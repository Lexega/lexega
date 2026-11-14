// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! The string literals of a lowered statement a report may print, each
//! shown safe by where its value goes: an operand of a comparison or a
//! predicate, an argument of a built-in function, at a place that takes no
//! key, passphrase, command or SQL text, whose result is one of those; a
//! value written into a column, only where it is known to hold no secret
//! (a literal of a type that holds no text, or one a catalog records as
//! written into a column holding none). A literal compared with, passed
//! beside, written into or paired with something that reads a secret is
//! never one of them.
//!
//! What reads a secret is decided once per column, through the columns of
//! the statement's plans, never by a name alone: a column of a source named
//! for a secret; a computed column whose expression reads one; a column a
//! CTE or a derived table lists, paired with a body column that reads one;
//! a set operation's or a merged column, one of whose inputs reads one. An
//! expression reads a secret where an operand does, where it reads a field
//! or a document key named for one, or a variable named for one.

use std::collections::{BTreeMap, BTreeSet};

use lexega_syntax::secrets::{is_secret_name, string_literal_content};

use crate::ast::{AstExpr, AstMysqlSetKind, AstStmt};
use crate::catalog::Resolution;
use crate::catalog::{CatalogIndex, CatalogTable, RelationsAt};
use crate::context::node_metadata::IdentKey;
use crate::context::node_metadata::TableRef;
use crate::dialect::{normalize_identifier_as, Dialect, NameKind};
use crate::dialect::{ArgumentUse, WrittenArgument, WrittenValue};
use crate::facts::literal::DataTypeKind;
use crate::ir::catalog::{ArgumentRoles, FunctionCatalog};
use crate::ir::column::{BindingTable, ColumnId, ColumnOrigin};
use crate::ir::lower::{lower_values_outside_query, AroundStatement};
use crate::ir::pairing::PairingSteps;
use crate::ir::plan::{
    AggregateCall, AssignedValue, Assignment, ConflictAction, GroupKey, GroupingSpec, InsertSource,
    MergeAction, MultiInsertTarget, ProjectItem, RelPlan, ResolvedFunc,
};
use crate::ir::scalar::{BinOpKind, ComparisonOp, FieldStep, Lit, QuantifiedRhs, ScalarExpr};
use crate::ir::visitor::{
    walk_rel_plan, walk_scalar_expr, walk_scalar_expr_standalone, RelPlanVisitor, ScalarExprVisitor,
};
use crate::ir::SessionContext;
use crate::lexer::token::Span;

/// The table columns each column of `query`, by position, is made of: a
/// column it copies, one its expression, aggregate or row reads, the body
/// column a CTE or a derived table pairs it with, an `UNPIVOT`'s source
/// columns, and a set operation's or a merge's inputs, followed to the
/// columns of the tables it scans,
/// each by its table and name. `None` where `query`'s columns are not all
/// known by position, or a column reads one no table it scans is known to
/// hold.
pub(crate) fn column_sources(
    query: &RelPlan,
    bindings: &BindingTable,
) -> Option<Vec<Vec<(TableRef, String)>>> {
    let positions = query.positional_columns();
    if positions.open {
        return None;
    }
    let mut gathered = Gathered::default();
    gathered.roots.push(query);
    gathered.visit_rel_plan(query);
    let steps = PairingSteps::of(query);
    let mut unattributed = false;
    let sources = positions
        .known
        .iter()
        .map(|column| {
            let mut found = Vec::new();
            let mut seen = BTreeSet::new();
            let mut pending = vec![*column];
            while let Some(column) = pending.pop() {
                if !seen.insert(column) {
                    continue;
                }
                let exprs: Vec<&ScalarExpr> = match gathered.definitions.get(&column) {
                    Some(Definition::Expr(expr)) => vec![expr],
                    Some(Definition::Call(args, named)) => args
                        .iter()
                        .chain(named.iter().map(|(_, expr)| expr))
                        .collect(),
                    Some(Definition::Row { rows, at }) => row_values(rows, *at),
                    None => Vec::new(),
                };
                for expr in exprs {
                    pending.extend(columns_read(expr));
                }
                pending.extend(gathered.unpivoted.get(&column).into_iter().flatten());
                pending.extend(steps.body_column(column));
                match bindings.get(column).map(|binding| &binding.origin) {
                    Some(ColumnOrigin::Table {
                        table_node,
                        column_name,
                        ..
                    }) => {
                        let table = gathered
                            .scanned
                            .get(&column)
                            .or_else(|| gathered.nodes.get(table_node));
                        if let Some(table) = table {
                            found.push(((*table).clone(), column_name.clone()));
                        }
                    }
                    Some(ColumnOrigin::SetOp { inputs }) => pending.extend(inputs),
                    Some(ColumnOrigin::Merged { value, .. }) => pending.extend(value.sides()),
                    Some(ColumnOrigin::OuterRef { outer_column, .. }) => {
                        pending.push(*outer_column)
                    }
                    Some(ColumnOrigin::Unattributed { .. }) => unattributed = true,
                    Some(ColumnOrigin::Computed { .. } | ColumnOrigin::RecursiveRef { .. })
                    | None => {}
                }
            }
            found
        })
        .collect();
    (!unattributed).then_some(sources)
}

/// Each table `query` scans, once, and whether it gives values of them
/// names of its own other than a select list's (an `UNPIVOT`'s value
/// columns).
pub(crate) fn tables_scanned(query: &RelPlan) -> (Vec<TableRef>, bool) {
    let mut gathered = Gathered::default();
    gathered.roots.push(query);
    gathered.visit_rel_plan(query);
    let mut tables: Vec<TableRef> = Vec::new();
    for table in gathered.nodes.into_values() {
        if !tables.contains(table) {
            tables.push(table.clone());
        }
    }
    (tables, !gathered.unpivoted.is_empty())
}

/// The columns `expr` reads outside a subquery, a scalar subquery's column
/// included.
fn columns_read(expr: &ScalarExpr) -> Vec<ColumnId> {
    struct Read(Vec<ColumnId>);
    impl<'e> ScalarExprVisitor<'e> for Read {
        fn visit_scalar_expr(&mut self, expr: &'e ScalarExpr) {
            match expr {
                ScalarExpr::Column { column, .. }
                | ScalarExpr::OuterRef { column, .. }
                | ScalarExpr::PatternVarRef { column, .. } => self.0.push(*column),
                ScalarExpr::ScalarSubquery { subquery, .. } => {
                    self.0.extend(subquery.positional_columns().at(0).column());
                    return;
                }
                ScalarExpr::Lit { .. }
                | ScalarExpr::BinOp { .. }
                | ScalarExpr::LogicalChain { .. }
                | ScalarExpr::OperatorChain { .. }
                | ScalarExpr::UnaryOp { .. }
                | ScalarExpr::FuncCall { .. }
                | ScalarExpr::Case { .. }
                | ScalarExpr::Cast { .. }
                | ScalarExpr::InList { .. }
                | ScalarExpr::Between { .. }
                | ScalarExpr::Like { .. }
                | ScalarExpr::Exists { .. }
                | ScalarExpr::QuantifiedCmp { .. }
                | ScalarExpr::RowCmp { .. }
                | ScalarExpr::WindowFn { .. }
                | ScalarExpr::FieldAccess { .. }
                | ScalarExpr::Lambda { .. }
                | ScalarExpr::Opaque { .. } => {}
            }
            walk_scalar_expr_standalone(self, expr);
        }
    }
    let mut read = Read(Vec::new());
    read.visit_scalar_expr(expr);
    read.0
}

/// What a statement's text is read with: the text, its dialect, the
/// function catalog in force at the statement, and, where a catalog is
/// given, the table it records under a name the statement writes.
#[derive(Clone, Copy)]
pub(crate) struct Reading<'a> {
    pub(crate) source: &'a str,
    pub(crate) dialect: &'a dyn Dialect,
    pub(crate) functions: &'a FunctionCatalog,
    pub(crate) tables: Option<CatalogTables<'a>>,
    /// The columns the script's statements write.
    pub(crate) written: &'a WrittenColumns,
    /// How a name the statement writes is resolved to a table.
    pub(crate) places: Places<'a>,
    /// The catalog tags the organization lists as marking a column that
    /// holds no secret ([`crate::rules::MaskingPolicy`]).
    pub(crate) shown_tags: &'a [crate::rules::ShownColumnTag],
}

/// Where the tables a statement names resolve: as the relations the
/// statements before it make and the catalog place a name under the
/// session the run states ([`RelationsAt::resolved`]); a schema the run
/// does not state is none, so the name meets a table of any schema.
#[derive(Clone, Copy)]
pub(crate) struct Places<'a> {
    pub(crate) relations: RelationsAt<'a>,
    pub(crate) catalog: Option<&'a CatalogIndex>,
    /// The session in force, the dialect's own path included.
    pub(crate) session: &'a SessionContext,
    /// The session as the run states it.
    pub(crate) stated: &'a SessionContext,
}

impl Places<'_> {
    /// The tables `table` may name under the session the run states.
    fn resolved(&self, table: &TableRef) -> Resolution {
        self.relations.resolution(self.catalog, table, self.stated)
    }

    /// The names of the columns of `table`, in order, where every one is
    /// known: from the statement that made it, or a catalog that lists
    /// every column.
    fn columns(&self, table: &TableRef) -> Option<Vec<&str>> {
        let held = self
            .relations
            .catalogued_table(self.catalog, table, self.session)?;
        let every = !held.columns.is_empty()
            && self.relations.lists_every_column(held)
            && self
                .catalog
                .is_none_or(|catalog| catalog.listed_columns(held).is_some());
        every.then(|| {
            held.columns
                .iter()
                .map(|column| column.name.name.as_str())
                .collect()
        })
    }
}

/// A table a run's statements write, by its name and the schema and
/// database the name resolves to. Each part is read as the dialect reads a
/// relation's name, its quotes stripped and a quoted path read as its parts
/// ([`crate::dialect::normalize_relation_name`]), and compared without
/// case: whether two spellings name one table rests on settings the run
/// does not state (MySQL's `lower_case_table_names`, a case-insensitive
/// BigQuery dataset), so two that may are taken to.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct WrittenTable {
    database: Option<IdentKey>,
    schema: Schemas,
    name: IdentKey,
}

/// The schemas a written table may be in ([`Resolution`]).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Schemas {
    /// Any schema.
    Any,
    /// One of these.
    Among(BTreeSet<IdentKey>),
}

impl WrittenTable {
    fn of(table: &TableRef) -> Self {
        // The parts one written part names, the last first.
        let parts = |written: &str| -> Vec<IdentKey> {
            crate::dialect::normalize_relation_name(&[written])
                .into_iter()
                .rev()
                .map(|part| IdentKey::from_normalized(part.to_lowercase()))
                .collect()
        };
        // A quoted path written as the name names the parts the reference
        // leaves out.
        let mut path = parts(&table.name).into_iter();
        let name = path
            .next()
            .unwrap_or_else(|| IdentKey::from_normalized(String::new()));
        let mut part = |written: &Option<String>| match written {
            Some(written) => parts(written).into_iter().next(),
            None => path.next(),
        };
        let schema = match part(&table.schema) {
            Some(schema) => Schemas::Among(BTreeSet::from([schema])),
            None => Schemas::Any,
        };
        let database = part(&table.db);
        Self {
            database,
            schema,
            name,
        }
    }

    /// The table, or the tables, `resolution` gives a name: any schema's
    /// where it may be any, each of a set's.
    fn resolved(resolution: &Resolution) -> Self {
        match resolution {
            Resolution::One(table) => Self::of(table),
            Resolution::Any(table) => Self {
                schema: Schemas::Any,
                ..Self::of(table)
            },
            Resolution::Among(tables) => {
                let mut each = tables.iter().map(Self::of);
                let Some(mut joined) = each.next() else {
                    return Self::of(&TableRef::new(String::new()));
                };
                for table in each {
                    joined.schema = match (joined.schema, table.schema) {
                        (Schemas::Among(mut a), Schemas::Among(b)) => {
                            a.extend(b);
                            Schemas::Among(a)
                        }
                        (Schemas::Any, _) | (_, Schemas::Any) => Schemas::Any,
                    };
                    if joined.database != table.database {
                        joined.database = None;
                    }
                }
                joined
            }
        }
    }

    /// Whether `self` and `other` may name the same table: the same name,
    /// a schema both may be in, and the same database where both resolve
    /// to one.
    fn meets(&self, other: &WrittenTable) -> bool {
        let database = match (&self.database, &other.database) {
            (Some(a), Some(b)) => a == b,
            (Some(_), None) | (None, Some(_)) | (None, None) => true,
        };
        let schema = match (&self.schema, &other.schema) {
            (Schemas::Among(a), Schemas::Among(b)) => !a.is_disjoint(b),
            (Schemas::Any, _) | (_, Schemas::Any) => true,
        };
        self.name == other.name && schema && database
    }
}

/// `name`, a column's name as written, as written columns are compared:
/// its quotes stripped and without case ([`WrittenTable`]).
fn column_key(name: &str) -> IdentKey {
    IdentKey::from_normalized(normalize_identifier_as(name, NameKind::Column).to_lowercase())
}

/// A column of a written table ([`WrittenTable`], [`column_key`]).
type WrittenColumn = (WrittenTable, IdentKey);

/// The columns a run's statements write values into, each by its table,
/// as the name resolves ([`WrittenTable`]), and its own name
/// ([`column_key`]): a value compared with one is read as a value written
/// into it is. A table or a column is met under each name the run gives
/// it: a rename, a synonym, a view's column.
#[derive(Debug, Default, Clone)]
pub(crate) struct WrittenColumns {
    columns: BTreeSet<WrittenColumn>,
    /// Tables written by position, or by a form naming no column, whose
    /// columns are not all known: every column of each is written.
    every_column_of: BTreeSet<WrittenTable>,
    /// Two names of one table whose columns keep their names: a rename, a
    /// synonym.
    same_tables: Vec<(WrittenTable, WrittenTable)>,
    /// Two names of one column, or a column and one it reads: a rename, a
    /// view's column and the column of the table it shows.
    same_columns: Vec<(WrittenColumn, WrittenColumn)>,
    /// A statement writes a table whose name the run cannot read: dynamic
    /// SQL whose text is not known. Every column may be written.
    anything: bool,
}

impl WrittenColumns {
    /// No column written.
    pub(crate) const NONE: WrittenColumns = WrittenColumns {
        columns: BTreeSet::new(),
        every_column_of: BTreeSet::new(),
        same_tables: Vec::new(),
        same_columns: Vec::new(),
        anything: false,
    };

    /// Record that a statement writes `column` of `table`, the name as it
    /// resolves, every column of it where `column` is `None`.
    pub(crate) fn record(&mut self, table: &Resolution, column: Option<&str>) {
        let table = WrittenTable::resolved(table);
        match column {
            Some(column) => {
                self.columns.insert((table, column_key(column)));
            }
            None => {
                self.every_column_of.insert(table);
            }
        }
    }

    /// Record that a statement writes a table whose name the run cannot
    /// read.
    pub(crate) fn record_anything(&mut self) {
        self.anything = true;
    }

    /// Record every write and name `other` records.
    pub(crate) fn merge(&mut self, other: &WrittenColumns) {
        self.columns.extend(other.columns.iter().cloned());
        self.every_column_of
            .extend(other.every_column_of.iter().cloned());
        self.same_tables.extend(other.same_tables.iter().cloned());
        self.same_columns.extend(other.same_columns.iter().cloned());
        self.anything |= other.anything;
    }

    /// Record that `a` and `b`, each as its name resolves, name one table.
    pub(crate) fn same_table(&mut self, a: &Resolution, b: &Resolution) {
        self.same_tables
            .push((WrittenTable::resolved(a), WrittenTable::resolved(b)));
    }

    /// Record that the column `a_column` of `a` is the column `b_column` of
    /// `b`, or reads it.
    pub(crate) fn same_column(
        &mut self,
        a: &Resolution,
        a_column: &str,
        b: &Resolution,
        b_column: &str,
    ) {
        self.same_columns.push((
            (WrittenTable::resolved(a), column_key(a_column)),
            (WrittenTable::resolved(b), column_key(b_column)),
        ));
    }

    /// The column `column` of `table`, and every column the run names it
    /// by: through each table and column it is recorded the same as.
    fn names_of(&self, table: &Resolution, column: &str) -> Vec<WrittenColumn> {
        let mut seen: Vec<WrittenColumn> = Vec::new();
        let mut pending = vec![(WrittenTable::resolved(table), column_key(column))];
        while let Some((table, column)) = pending.pop() {
            if seen.contains(&(table.clone(), column.clone())) {
                continue;
            }
            for (a, b) in &self.same_tables {
                for (from, to) in [(a, b), (b, a)] {
                    if from.meets(&table) {
                        pending.push((to.clone(), column.clone()));
                    }
                }
            }
            for (a, b) in &self.same_columns {
                for (from, to) in [(a, b), (b, a)] {
                    if from.1 == column && from.0.meets(&table) {
                        pending.push(to.clone());
                    }
                }
            }
            seen.push((table, column));
        }
        seen
    }

    /// Whether a statement writes the column `column` of `table`, the name
    /// as it resolves, under any name the run gives it.
    fn holds(&self, table: &Resolution, column: &str) -> bool {
        self.anything
            || self.names_of(table, column).iter().any(|(table, column)| {
                self.every_column_of.iter().any(|whole| whole.meets(table))
                    || self
                        .columns
                        .iter()
                        .any(|(written, name)| name == column && written.meets(table))
            })
    }

    /// Whether a statement writes a column named `column` of any table.
    fn names(&self, column: &str) -> bool {
        let column = column_key(column);
        let named = |column: &IdentKey| self.columns.iter().any(|(_, written)| written == column);
        self.anything
            || !self.every_column_of.is_empty()
            || named(&column)
            || self
                .same_columns
                .iter()
                .any(|(a, b)| (a.1 == column && named(&b.1)) || (b.1 == column && named(&a.1)))
    }

    /// The names, other than `column`, the run gives the column `column`
    /// of `table`.
    fn other_names(&self, table: &Resolution, column: &str) -> Vec<IdentKey> {
        let own = column_key(column);
        self.names_of(table, column)
            .into_iter()
            .map(|(_, name)| name)
            .filter(|name| *name != own)
            .collect()
    }
}

/// Where the tables a statement names are recorded: the catalog, and the
/// relations the statements before it make, under its session.
#[derive(Clone, Copy)]
pub(crate) struct CatalogTables<'a> {
    pub(crate) catalog: &'a CatalogIndex,
    pub(crate) relations: RelationsAt<'a>,
    pub(crate) session: &'a SessionContext,
}

impl<'a> CatalogTables<'a> {
    /// The table recorded under the name `table`.
    fn table(&self, table: &TableRef) -> Option<&'a CatalogTable> {
        self.relations
            .catalogued_table(Some(self.catalog), table, self.session)
    }
}

/// The string literals of one statement a report may print
/// ([`plan_literals`], [`script_literals`]).
#[derive(Debug, Default)]
pub(crate) struct ShownLiterals {
    /// The span of each, in order.
    pub(crate) spans: Vec<Span>,
    /// The span of each literal that is not a string (a number, a binary
    /// value) written into, or equated with, a value named for a secret:
    /// masked whole.
    pub(crate) vetoed: Vec<Span>,
}

/// The string literals of `plans` and `bodies`, one statement's plans and
/// a policy's body expressions lowered with `bindings`, that a report may
/// print. A body is a condition.
pub(crate) fn plan_literals(
    plans: &[&RelPlan],
    bodies: &[&ScalarExpr],
    bindings: &BindingTable,
    reading: Reading<'_>,
) -> ShownLiterals {
    let mut gathered = Gathered::default();
    for plan in plans {
        gathered.roots.push(plan);
        gathered.visit_rel_plan(plan);
    }
    for body in bodies {
        gathered.visit_scalar_expr(body);
    }
    let classifier = Classifier::new(gathered, bindings, reading);
    let mut masking = Masking::new(&classifier);
    for plan in plans {
        masking.visit_rel_plan(plan);
    }
    for body in bodies {
        masking.consume(body);
        masking.visit_scalar_expr(body);
    }
    let mut shown = masking.finish();
    shown
        .spans
        .extend(number_destinations(plans, bodies, reading));
    shown
}

/// The numbers of `plans` and `bodies`, one statement's plans and a
/// policy's body expressions, whose destination the walk knows: each a
/// value the statement compares, tests, computes with a function the
/// dialect builds in, returns, stores or counts rows by. A number passed to
/// a routine the dialect does not build in reaches what no walk follows,
/// and one the walk does not reach goes where it does not know: neither is
/// listed, so a report masks it ([`ReportedLiterals`]). A destination a
/// secret is at masks the number however it is listed
/// ([`ShownLiterals::vetoed`]).
pub(crate) fn number_destinations(
    plans: &[&RelPlan],
    bodies: &[&ScalarExpr],
    reading: Reading<'_>,
) -> Vec<Span> {
    let mut numbers = Numbers {
        reading,
        known: Vec::new(),
    };
    for plan in plans {
        numbers.visit_rel_plan(plan);
    }
    for body in bodies {
        numbers.visit_scalar_expr(body);
    }
    numbers.known
}

/// One walk of [`number_destinations`].
struct Numbers<'a> {
    reading: Reading<'a>,
    known: Vec<Span>,
}

impl Numbers<'_> {
    /// Whether the dialect builds in the function `func` calls: by its
    /// name in the dialect's own catalog, never one a script defines.
    fn builtin(&self, func: &ResolvedFunc) -> bool {
        let written = match func {
            ResolvedFunc::Resolved { id, .. } => match self.reading.functions.signature(*id) {
                Some(signature) => signature.display_name.clone(),
                None => return false,
            },
            ResolvedFunc::Unresolved {
                raw_name,
                namespace,
                ..
            } => match namespace {
                Some(namespace) => format!("{namespace}.{raw_name}"),
                None => raw_name.clone(),
            },
        };
        let dialect = crate::ir::CatalogDialect::from_dialect_name(self.reading.dialect.name());
        crate::names_builtin_function_in(
            &crate::ir::lower::routine_name(&written),
            self.reading.dialect,
            FunctionCatalog::dialect_defined(dialect),
        )
    }
}

impl<'e> RelPlanVisitor<'e> for Numbers<'_> {
    fn visit_scalar_expr(&mut self, expr: &'e ScalarExpr) {
        match expr {
            ScalarExpr::Lit { value, span } => match value {
                Lit::Integer(_) | Lit::Float(_) => self.known.push(*span),
                Lit::Null
                | Lit::Bool(_)
                | Lit::Str(_)
                | Lit::Bytes { .. }
                | Lit::Typed { .. }
                | Lit::Variant(_)
                | Lit::Variable { .. } => {}
            },
            // What a routine the dialect does not build in does with its
            // arguments is not read.
            ScalarExpr::FuncCall { func, span, .. }
                if func.span() != *span && !self.builtin(func) =>
            {
                return
            }
            // The type a value converts to: its length, precision and scale.
            ScalarExpr::Cast {
                expr: converted,
                span,
                ..
            } => self.known.push(Span {
                start: converted.span().end.min(span.end),
                end: span.end,
            }),
            ScalarExpr::FuncCall { .. }
            | ScalarExpr::Column { .. }
            | ScalarExpr::OuterRef { .. }
            | ScalarExpr::PatternVarRef { .. }
            | ScalarExpr::ScalarSubquery { .. }
            | ScalarExpr::BinOp { .. }
            | ScalarExpr::LogicalChain { .. }
            | ScalarExpr::OperatorChain { .. }
            | ScalarExpr::UnaryOp { .. }
            | ScalarExpr::Case { .. }
            | ScalarExpr::InList { .. }
            | ScalarExpr::Between { .. }
            | ScalarExpr::Like { .. }
            | ScalarExpr::Exists { .. }
            | ScalarExpr::QuantifiedCmp { .. }
            | ScalarExpr::RowCmp { .. }
            | ScalarExpr::WindowFn { .. }
            | ScalarExpr::FieldAccess { .. }
            | ScalarExpr::Lambda { .. }
            | ScalarExpr::Opaque { .. } => {}
        }
        walk_scalar_expr(self, expr);
    }
}

/// The string literals of the values and conditions `stmt`, a scripting
/// statement, holds outside any query that a report may print: each value
/// lowered in a scope with no source, a name the scopes `around` declare
/// read as its variable.
pub(crate) fn script_literals(
    stmt: &AstStmt,
    session: &SessionContext,
    around: AroundStatement<'_>,
    reading: Reading<'_>,
) -> ShownLiterals {
    let held = script_values(stmt);
    if held.is_empty() {
        return ShownLiterals::default();
    }
    let written: Vec<&AstExpr> = held.iter().flat_map(ScriptValue::exprs).collect();
    let (lowered, bindings) =
        lower_values_outside_query(&written, reading.source, reading.functions, session, around);
    let mut gathered = Gathered::default();
    for value in lowered.iter().flatten() {
        gathered.visit_scalar_expr(value);
    }
    let classifier = Classifier::new(gathered, &bindings, reading);
    let mut masking = Masking::new(&classifier);
    // Each held value's expressions, in the order they were lowered.
    let mut values = lowered.iter().map(Option::as_ref);
    // The arguments a routine of the dialect's reads as names.
    let mut named: Vec<&ScalarExpr> = Vec::new();
    for value in &held {
        match value {
            ScriptValue::Alone(_) => {
                if let Some(expr) = values.next().flatten() {
                    masking.visit_scalar_expr(expr);
                }
            }
            ScriptValue::Compared { values: whens, .. } => {
                let operand = values.next().flatten();
                let whens: Vec<&ScalarExpr> = whens
                    .iter()
                    .filter_map(|_| values.next().flatten())
                    .collect();
                for expr in operand.into_iter().chain(whens.iter().copied()) {
                    masking.visit_scalar_expr(expr);
                }
                if let Some(operand) = operand {
                    for when in whens {
                        masking.compared(operand, when);
                    }
                }
            }
            ScriptValue::Arguments { routine, arguments } => {
                // The use the dialect's routine of that name gives each
                // argument written, where the call names one.
                let uses = routine
                    .and_then(|routine| {
                        reading
                            .source
                            .get(routine.start as usize..routine.end as usize)
                    })
                    .and_then(|routine| {
                        let parts = crate::ir::lower::routine_name(routine);
                        let parts: Vec<&str> = parts.iter().map(IdentKey::as_str).collect();
                        let written: Vec<WrittenArgument<'_>> = arguments
                            .iter()
                            .map(|(name, expr)| WrittenArgument {
                                name: name.and_then(|name| {
                                    reading.source.get(name.start as usize..name.end as usize)
                                }),
                                value: WrittenValue::of(expr),
                            })
                            .collect();
                        Some(
                            reading
                                .dialect
                                .system_routine(&parts)?
                                .argument_uses(&written),
                        )
                    })
                    .unwrap_or_default();
                let arguments: Vec<(Option<&str>, Option<ArgumentUse>, &ScalarExpr)> = arguments
                    .iter()
                    .enumerate()
                    .filter_map(|(at, (name, _))| {
                        let name = name.and_then(|name| {
                            reading.source.get(name.start as usize..name.end as usize)
                        });
                        let reads = uses.get(at).copied().flatten();
                        values.next().flatten().map(|expr| (name, reads, expr))
                    })
                    .collect();
                for (_, reads, expr) in &arguments {
                    masking.visit_scalar_expr(expr);
                    if *reads == Some(ArgumentUse::Name) {
                        masking.consume(expr);
                        named.push(*expr);
                    }
                }
                masking.call(arguments.into_iter().map(|(name, _, expr)| (name, expr)));
            }
        }
    }
    let mut shown = masking.finish();
    // A number a routine of the dialect's reads as a name or a setting.
    shown
        .spans
        .extend(number_destinations(&[], &named, reading));
    shown
}

/// A value or a condition a scripting statement holds outside any query.
enum ScriptValue<'s> {
    /// Read on its own.
    Alone(&'s AstExpr),
    /// A simple `CASE` statement's operand and the values it is compared
    /// with.
    Compared {
        operand: &'s AstExpr,
        values: Vec<&'s AstExpr>,
    },
    /// A call's arguments, each with where the name written for it is,
    /// and where the routine it calls is named.
    Arguments {
        routine: Option<Span>,
        arguments: Vec<(Option<Span>, &'s AstExpr)>,
    },
}

impl<'s> ScriptValue<'s> {
    /// Each expression, in the order [`script_literals`] reads them.
    fn exprs(&self) -> Vec<&'s AstExpr> {
        match self {
            ScriptValue::Alone(expr) => vec![expr],
            ScriptValue::Compared { operand, values } => std::iter::once(*operand)
                .chain(values.iter().copied())
                .collect(),
            ScriptValue::Arguments { arguments, .. } => {
                arguments.iter().map(|(_, expr)| *expr).collect()
            }
        }
    }
}

/// The values and conditions `stmt` holds outside any query: a condition
/// of an `IF`, `CASE`, `WHILE` or `REPEAT`, the value a variable is
/// assigned or declared with, a returned value, a `CALL`'s arguments.
/// Statements a statement holds are read on their own.
fn script_values(stmt: &AstStmt) -> Vec<ScriptValue<'_>> {
    match stmt {
        AstStmt::If(s) => s
            .branches
            .iter()
            .map(|branch| ScriptValue::Alone(&branch.condition))
            .collect(),
        AstStmt::CaseStmt(s) => {
            let whens = s
                .branches
                .iter()
                .flat_map(|branch| std::iter::once(&*branch.condition).chain(&branch.more_values));
            match s.operand.as_deref() {
                Some(operand) => vec![ScriptValue::Compared {
                    operand,
                    values: whens.collect(),
                }],
                None => whens.map(ScriptValue::Alone).collect(),
            }
        }
        AstStmt::While(s) => vec![ScriptValue::Alone(&s.condition)],
        AstStmt::Repeat(s) => vec![ScriptValue::Alone(&s.until_condition)],
        AstStmt::MssqlIf(s) => vec![ScriptValue::Alone(&s.condition)],
        AstStmt::MssqlWhile(s) => vec![ScriptValue::Alone(&s.condition)],
        AstStmt::Assign { expr, .. } | AstStmt::Let { expr, .. } => {
            vec![ScriptValue::Alone(expr)]
        }
        AstStmt::Return { expr, .. } => expr
            .as_deref()
            .map(ScriptValue::Alone)
            .into_iter()
            .collect(),
        AstStmt::Declare { variables, .. } => variables
            .iter()
            .filter_map(|variable| variable.default_expr.as_deref())
            .map(ScriptValue::Alone)
            .collect(),
        AstStmt::SetVariable { values, .. } => values.iter().map(ScriptValue::Alone).collect(),
        AstStmt::MysqlSet(s) => match &s.kind {
            AstMysqlSetKind::Assignments(assignments) => assignments
                .iter()
                .map(|assignment| ScriptValue::Alone(&assignment.value))
                .collect(),
            AstMysqlSetKind::Names(_)
            | AstMysqlSetKind::CharacterSet(_)
            | AstMysqlSetKind::Password(_)
            | AstMysqlSetKind::Role(_)
            | AstMysqlSetKind::DefaultRole(_)
            | AstMysqlSetKind::Transaction(_) => Vec::new(),
        },
        AstStmt::Call {
            procedure_name_span,
            args,
            ..
        } => vec![ScriptValue::Arguments {
            routine: Some(*procedure_name_span),
            arguments: args
                .iter()
                .map(|arg| (arg.name.as_ref().map(|name| name.span), &arg.value))
                .collect(),
        }],
        AstStmt::MssqlExec(exec) if exec.procedure_name_span.is_some() => {
            vec![ScriptValue::Arguments {
                routine: exec.procedure_name_span,
                arguments: exec
                    .args
                    .iter()
                    .map(|arg| (arg.name.as_ref().map(|name| name.span), &arg.value))
                    .collect(),
            }]
        }
        AstStmt::CreateExternalTable(_)
        | AstStmt::Unload { .. }
        | AstStmt::Block(_)
        | AstStmt::DeclareHandler(_)
        | AstStmt::For(_)
        | AstStmt::ForEach(_)
        | AstStmt::Loop(_)
        | AstStmt::MssqlTryCatch(_)
        | AstStmt::CreateProcedure(_)
        | AstStmt::CreateFunction(_)
        | AstStmt::DoBlock(_)
        | AstStmt::CreateEvent(_)
        | AstStmt::AlterEvent(_)
        | AstStmt::CreateMysqlTrigger(_)
        | AstStmt::CreateTask(_)
        | AstStmt::CreateMssqlTrigger(_)
        | AstStmt::Insert(_)
        | AstStmt::Select(_)
        | AstStmt::Perform(_)
        | AstStmt::SetSelect(_)
        | AstStmt::ValuesQuery(_)
        | AstStmt::ReplaceInto(_)
        | AstStmt::MultiInsert(_)
        | AstStmt::Update(_)
        | AstStmt::Delete(_)
        | AstStmt::Merge(_)
        | AstStmt::Explain(_)
        | AstStmt::PsqlGexec(_)
        | AstStmt::ExecuteImmediate { .. }
        | AstStmt::ExecuteImmediateFrom(_)
        | AstStmt::OpaqueContent { .. }
        | AstStmt::ClauseFragment { .. }
        | AstStmt::JinjaPlaceholder { .. }
        | AstStmt::JinjaConditionalStmt(_)
        | AstStmt::Error { .. }
        | AstStmt::GoBatchSeparator { .. }
        | AstStmt::SqlcmdCommand { .. }
        | AstStmt::AlterAccount(_)
        | AstStmt::AlterAggregationPolicy(_)
        | AstStmt::AlterApiIntegration(_)
        | AstStmt::AlterNotificationIntegration(_)
        | AstStmt::CreateShare(_)
        | AstStmt::AlterShare(_)
        | AstStmt::CreateDatashare(_)
        | AstStmt::AlterDatashare(_)
        | AstStmt::CreateSecurityIntegration(_)
        | AstStmt::AlterSecurityIntegration(_)
        | AstStmt::AlterReplicationGroup(_)
        | AstStmt::AlterFailoverGroup(_)
        | AstStmt::AlterAuthenticationPolicy(_)
        | AstStmt::AlterCatalog(_)
        | AstStmt::AlterConnection(_)
        | AstStmt::AlterDatabase(_)
        | AstStmt::AlterDomain(_)
        | AstStmt::AlterDynamicTable(_)
        | AstStmt::AlterExternalAccessIntegration(_)
        | AstStmt::AlterExternalLocation(_)
        | AstStmt::AlterFunction(_)
        | AstStmt::AlterIndex(_)
        | AstStmt::AlterMaterializedView(_)
        | AstStmt::AlterMaskingPolicy(_)
        | AstStmt::AlterNetworkPolicy(_)
        | AstStmt::AlterPasswordPolicy(_)
        | AstStmt::AlterPgPolicy(_)
        | AstStmt::AlterPgTrigger(_)
        | AstStmt::AlterPipe(_)
        | AstStmt::AlterProcedure(_)
        | AstStmt::AlterProjectionPolicy(_)
        | AstStmt::AlterJoinPolicy(_)
        | AstStmt::AlterRowAccessPolicy(_)
        | AstStmt::AlterSchema(_)
        | AstStmt::AlterSequence(_)
        | AstStmt::AlterSessionPolicy(_)
        | AstStmt::AlterSession(_)
        | AstStmt::AlterStage(_)
        | AstStmt::AlterStorageCredential(_)
        | AstStmt::AlterStorageIntegration(_)
        | AstStmt::AlterStream(_)
        | AstStmt::AlterTable(_)
        | AstStmt::AlterTask(_)
        | AstStmt::AlterType(_)
        | AstStmt::AlterUser(_)
        | AstStmt::AlterView(_)
        | AstStmt::AlterVolume(_)
        | AstStmt::AlterWarehouse(_)
        | AstStmt::AnalyzeStmt(_)
        | AstStmt::Await { .. }
        | AstStmt::BeginTransaction { .. }
        | AstStmt::BqAlterModel(_)
        | AstStmt::BqAlterVectorIndex(_)
        | AstStmt::BqAssert(_)
        | AstStmt::BqCreateModel(_)
        | AstStmt::BqCreateSearchIndex(_)
        | AstStmt::BqCreateSnapshotTable(_)
        | AstStmt::BqCreateVectorIndex(_)
        | AstStmt::BqDropModel(_)
        | AstStmt::BqDropSearchIndex(_)
        | AstStmt::BqDropSnapshotTable(_)
        | AstStmt::BqDropVectorIndex(_)
        | AstStmt::BqExportData(_)
        | AstStmt::BqExportModel(_)
        | AstStmt::BqLoadData(_)
        | AstStmt::MysqlLoadData(_)
        | AstStmt::MysqlRenameTable(_)
        | AstStmt::Break { .. }
        | AstStmt::CacheTable(_)
        | AstStmt::Cancel { .. }
        | AstStmt::CloseCursor { .. }
        | AstStmt::CommentOn(_)
        | AstStmt::Commit { .. }
        | AstStmt::Continue { .. }
        | AstStmt::CopyIntoLocation { .. }
        | AstStmt::RedshiftCopy { .. }
        | AstStmt::CopyIntoTable { .. }
        | AstStmt::CreateAggregationPolicy(_)
        | AstStmt::CreateApiIntegration(_)
        | AstStmt::CreateNotificationIntegration(_)
        | AstStmt::CreateAuthenticationPolicy(_)
        | AstStmt::CreateCatalog(_)
        | AstStmt::AlterUserMapping(_)
        | AstStmt::DropUserMapping(_)
        | AstStmt::CreateUserMapping(_)
        | AstStmt::CreateForeignTable(_)
        | AstStmt::ImportForeignSchema(_)
        | AstStmt::CreateForeignServer(_)
        | AstStmt::AlterForeignServer(_)
        | AstStmt::MssqlAlterServerConfiguration(_)
        | AstStmt::MssqlCreateExternalDataSource(_)
        | AstStmt::MssqlAlterExternalDataSource(_)
        | AstStmt::CreateConnection(_)
        | AstStmt::CreateDatabase(_)
        | AstStmt::CreateDomain(_)
        | AstStmt::CreateDynamicTable(_)
        | AstStmt::CreateExtension(_)
        | AstStmt::CreateExternalAccessIntegration(_)
        | AstStmt::CreateExternalLocation(_)
        | AstStmt::CreateExternalSchema(_)
        | AstStmt::CreateFlow(_)
        | AstStmt::CreateIndex(_)
        | AstStmt::CreateSynonym(_)
        | AstStmt::CreateMaskingPolicy(_)
        | AstStmt::CreateNetworkPolicy(_)
        | AstStmt::CreatePasswordPolicy(_)
        | AstStmt::CreatePgPolicy(_)
        | AstStmt::CreatePgTrigger(_)
        | AstStmt::CreatePipe(_)
        | AstStmt::CreateProjectionPolicy(_)
        | AstStmt::CreateJoinPolicy(_)
        | AstStmt::CreateRowAccessPolicy(_)
        | AstStmt::CreateSchema(_)
        | AstStmt::CreateSequence(_)
        | AstStmt::CreateSessionPolicy(_)
        | AstStmt::CreateStage(_)
        | AstStmt::CreateStorageCredential(_)
        | AstStmt::CreateStorageIntegration(_)
        | AstStmt::CreateStream(_)
        | AstStmt::CreateTable(_)
        | AstStmt::CreateTableFunction(_)
        | AstStmt::CreateType(_)
        | AstStmt::CreateView(_)
        | AstStmt::CreateVolume(_)
        | AstStmt::CreateWarehouse(_)
        | AstStmt::DeclareCondition { .. }
        | AstStmt::DeclareCursor { .. }
        | AstStmt::DeclareTable { .. }
        | AstStmt::Deny(_)
        | AstStmt::AlterAuthorization(_)
        | AstStmt::MssqlExecuteAs(_)
        | AstStmt::MssqlRevert { .. }
        | AstStmt::MssqlAuditDdl(_)
        | AstStmt::MssqlSecurityObjectDdl(_)
        | AstStmt::Describe(_)
        | AstStmt::DescribeHistory(_)
        | AstStmt::Drop(_)
        | AstStmt::DropAggregationPolicy(_)
        | AstStmt::DropAllRowAccessPolicies(_)
        | AstStmt::DropApiIntegration(_)
        | AstStmt::DropNotificationIntegration(_)
        | AstStmt::DropAuthenticationPolicy(_)
        | AstStmt::DropCatalog(_)
        | AstStmt::DropConnection(_)
        | AstStmt::DropDatabase(_)
        | AstStmt::DropDomain(_)
        | AstStmt::DropExternalAccessIntegration(_)
        | AstStmt::DropExternalLocation(_)
        | AstStmt::DropMaskingPolicy(_)
        | AstStmt::DropMssqlTrigger(_)
        | AstStmt::MssqlTriggerState(_)
        | AstStmt::DropNetworkPolicy(_)
        | AstStmt::DropPasswordPolicy(_)
        | AstStmt::DropPgPolicy(_)
        | AstStmt::DropPgTrigger(_)
        | AstStmt::DropPipe(_)
        | AstStmt::DropProjectionPolicy(_)
        | AstStmt::DropJoinPolicy(_)
        | AstStmt::DropRowAccessPolicy(_)
        | AstStmt::DropSchema(_)
        | AstStmt::DropSessionPolicy(_)
        | AstStmt::DropStorageCredential(_)
        | AstStmt::DropStorageIntegration(_)
        | AstStmt::DropStream(_)
        | AstStmt::DropTask(_)
        | AstStmt::DropVolume(_)
        | AstStmt::DropWarehouse(_)
        | AstStmt::FetchCursor { .. }
        | AstStmt::GetDiagnostics { .. }
        | AstStmt::Grant(_)
        | AstStmt::LetCursor { .. }
        | AstStmt::MssqlAlterExternalModel(_)
        | AstStmt::MssqlBulkInsert(_)
        | AstStmt::MssqlCreateExternalModel(_)
        | AstStmt::MssqlCreateVectorIndex(_)
        | AstStmt::MssqlDropExternalModel(_)
        | AstStmt::MssqlExec(_)
        | AstStmt::MssqlGoto(_)
        | AstStmt::MssqlLabel(_)
        | AstStmt::MssqlPrint(_)
        | AstStmt::MssqlRaiserror(_)
        | AstStmt::MssqlSetOption(_)
        | AstStmt::Reconfigure { .. }
        | AstStmt::MssqlServerCommand { .. }
        | AstStmt::MysqlUnlockTables(_)
        | AstStmt::MssqlThrow(_)
        | AstStmt::MssqlWaitfor(_)
        | AstStmt::Null { .. }
        | AstStmt::OpenCursor { .. }
        | AstStmt::Optimize(_)
        | AstStmt::AlterPrincipal(_)
        | AstStmt::PgAlterRule(_)
        | AstStmt::PgAlterSystem(_)
        | AstStmt::PgAlterTableTriggerState(_)
        | AstStmt::PgAlterTablespace(_)
        | AstStmt::PgCluster(_)
        | AstStmt::PgCopy(_)
        | AstStmt::PgCreateAggregate(_)
        | AstStmt::PgCreateOperator(_)
        | AstStmt::CreatePrincipal(_)
        | AstStmt::PgCreateRule(_)
        | AstStmt::MssqlCreateRule(_)
        | AstStmt::MysqlDo(_)
        | AstStmt::ExecuteTask(_)
        | AstStmt::MysqlCreateLoadableFunction(_)
        | AstStmt::MysqlAdmin(_)
        | AstStmt::PgCreateTablespace(_)
        | AstStmt::PgDeallocate(_)
        | AstStmt::PgDiscard(_)
        | AstStmt::PgDropExtension(_)
        | AstStmt::PgDropIndex(_)
        | AstStmt::PgDropOwned(_)
        | AstStmt::DropPrincipal(_)
        | AstStmt::PgDropRule(_)
        | AstStmt::PgDropSequence(_)
        | AstStmt::PgDropTablespace(_)
        | AstStmt::PgDropType(_)
        | AstStmt::PgExecute(_)
        | AstStmt::PgListen(_)
        | AstStmt::PgLockTable(_)
        | AstStmt::PgNotify(_)
        | AstStmt::PgPrepare(_)
        | AstStmt::PgPublication(_)
        | AstStmt::PgReassignOwned(_)
        | AstStmt::PgRefreshMatview(_)
        | AstStmt::PgSet(_)
        | AstStmt::PgSubscription(_)
        | AstStmt::PgUnlisten(_)
        | AstStmt::PipeChain { .. }
        | AstStmt::Raise { .. }
        | AstStmt::Reindex(_)
        | AstStmt::RepairTable(_)
        | AstStmt::Resignal { .. }
        | AstStmt::Restore(_)
        | AstStmt::MssqlBackup(_)
        | AstStmt::MssqlRestore(_)
        | AstStmt::MssqlDbcc(_)
        | AstStmt::MssqlKeyManagement(_)
        | AstStmt::MssqlSecurityPolicy(_)
        | AstStmt::MssqlKeyBackup(_)
        | AstStmt::MssqlAssembly(_)
        | AstStmt::MssqlAddSignature(_)
        | AstStmt::MssqlSetuser(_)
        | AstStmt::MssqlAlterServiceMasterKey(_)
        | AstStmt::PgAlterDefaultPrivileges(_)
        | AstStmt::Revoke(_)
        | AstStmt::Rollback { .. }
        | AstStmt::Savepoint(_)
        | AstStmt::Show(_)
        | AstStmt::Signal { .. }
        | AstStmt::Truncate(_)
        | AstStmt::UncacheTable(_)
        | AstStmt::UndropDatabase(_)
        | AstStmt::UndropSchema(_)
        | AstStmt::UndropTable(_)
        | AstStmt::UndropType(_)
        | AstStmt::CreateTag(_)
        | AstStmt::AlterTag(_)
        | AstStmt::UndropTag(_)
        | AstStmt::CreateFileFormat(_)
        | AstStmt::AlterFileFormat(_)
        | AstStmt::CreateSecret(_)
        | AstStmt::AlterSecret(_)
        | AstStmt::CreateNetworkRule(_)
        | AstStmt::AlterNetworkRule(_)
        | AstStmt::CreateResourceMonitor(_)
        | AstStmt::AlterResourceMonitor(_)
        | AstStmt::CreateComputePool(_)
        | AstStmt::AlterComputePool(_)
        | AstStmt::CreateGitRepository(_)
        | AstStmt::CreateExternalFunction(_)
        | AstStmt::AlterGitRepository(_)
        | AstStmt::CreateImageRepository(_)
        | AstStmt::AlterImageRepository(_)
        | AstStmt::CreateStreamlit(_)
        | AstStmt::AlterStreamlit(_)
        | AstStmt::CreateService(_)
        | AstStmt::AlterService(_)
        | AstStmt::CreateNotebook(_)
        | AstStmt::AlterNotebook(_)
        | AstStmt::CreateSemanticView(_)
        | AstStmt::AlterSemanticView(_)
        | AstStmt::CreateCortexSearchService(_)
        | AstStmt::AlterCortexSearchService(_)
        | AstStmt::CreateApplication(_)
        | AstStmt::AlterApplication(_)
        | AstStmt::CreateApplicationPackage(_)
        | AstStmt::AlterApplicationPackage(_)
        | AstStmt::CreateListing(_)
        | AstStmt::AlterListing(_)
        | AstStmt::CreateManagedAccount(_)
        | AstStmt::CreateAccount(_)
        | AstStmt::StageFileCommand(_)
        | AstStmt::CreateAlert(_)
        | AstStmt::CreateDataMetricFunction(_)
        | AstStmt::CreateReplicationFailoverGroup(_)
        | AstStmt::AlterAlert(_)
        | AstStmt::Use(_)
        | AstStmt::Vacuum(_) => Vec::new(),
    }
}

/// How a computed column is defined.
enum Definition<'p> {
    /// By an expression.
    Expr(&'p ScalarExpr),
    /// By an aggregate's or a window function's arguments.
    Call(&'p [ScalarExpr], &'p [(IdentKey, ScalarExpr)]),
    /// By the values at its place in the rows of a `VALUES`.
    Row {
        rows: &'p [Vec<ScalarExpr>],
        at: usize,
    },
}

/// Where a value is written.
enum Target<'p> {
    /// A column of a table.
    Column(ColumnId),
    /// A column a statement creates, by the name it is given.
    Named(&'p IdentKey),
    /// A column a statement creates, named as the select list names it.
    Output(ColumnId),
}

/// What a write by position writes.
enum Positional<'p> {
    /// The columns of a query, in order.
    Query(&'p RelPlan),
    /// Rows of values, in order.
    Rows(&'p [Vec<ScalarExpr>]),
}

/// The value written.
enum Written<'p> {
    Value(&'p ScalarExpr),
    /// The value of a column of the query a statement writes from.
    Column(ColumnId),
}

/// An aggregate or window call's positional and named arguments.
type CallArgs<'p> = (&'p [ScalarExpr], &'p [(IdentKey, ScalarExpr)]);

/// What one walk of a statement's plans finds: how each computed column is
/// defined, the name a select list gives an output column, the arguments
/// of each aggregate and window call of a plan node, and each value
/// written into a column.
#[derive(Default)]
struct Gathered<'p> {
    definitions: BTreeMap<ColumnId, Definition<'p>>,
    aliases: BTreeMap<ColumnId, &'p IdentKey>,
    /// Where each select item that names its column writes the name: after
    /// its expression.
    item_names: Vec<Span>,
    calls: Vec<CallArgs<'p>>,
    writes: Vec<(Target<'p>, Written<'p>)>,
    /// The two sides of each equality.
    equalities: Vec<(&'p ScalarExpr, &'p ScalarExpr)>,
    /// The plans walked from outside any plan: a statement's, or a
    /// subquery a value outside a query holds.
    roots: Vec<&'p RelPlan>,
    /// The table each column a statement writes is of.
    written_tables: BTreeMap<ColumnId, &'p TableRef>,
    /// The tables a statement writes every column of, by position or by a
    /// form naming none.
    written_whole: Vec<&'p TableRef>,
    /// Each write by position: its table, and the query or the rows it
    /// writes.
    positional: Vec<(&'p TableRef, Positional<'p>)>,
    /// The columns of each `VALUES` the statement reads rows from.
    values_columns: Vec<ColumnId>,
    /// The span of each call a statement reads rows from, as a table.
    source_calls: BTreeSet<(u32, u32)>,
    /// The table each column a scan reads is of.
    scanned: BTreeMap<ColumnId, &'p TableRef>,
    /// The source columns each value column of an `UNPIVOT` takes its
    /// values from, one of each group.
    unpivoted: BTreeMap<ColumnId, Vec<ColumnId>>,
    /// The table each scan or write target reads, by the node its columns
    /// are allocated on.
    nodes: BTreeMap<crate::ast::NodeId, &'p TableRef>,
    /// The columns a write's own query defines at the places it writes:
    /// its select items, its `VALUES` rows and the branches of a set
    /// operation of them ([`own_columns`]).
    own_places: BTreeSet<ColumnId>,
    /// How many plans the walk is inside.
    depth: usize,
}

impl<'p> Gathered<'p> {
    fn record(&mut self, plan: &'p RelPlan) {
        match plan {
            RelPlan::Values { rows, columns, .. } => {
                for (at, column) in columns.iter().enumerate() {
                    self.definitions
                        .insert(*column, Definition::Row { rows, at });
                }
                self.values_columns.extend(columns);
            }
            RelPlan::Project { items, .. } => {
                for item in items {
                    match item {
                        ProjectItem::Expr(expr) => {
                            self.define(expr.output, &expr.expr);
                            if let Some(alias) = &expr.alias {
                                self.aliases.insert(expr.output, alias);
                                let after = expr.expr.span().end;
                                if after < expr.span.end {
                                    self.item_names.push(Span {
                                        start: after,
                                        end: expr.span.end,
                                    });
                                }
                            }
                        }
                        ProjectItem::Star(_) => {}
                    }
                }
            }
            RelPlan::Filter { computed, .. } => self.computed(computed),
            RelPlan::Aggregate {
                grouping,
                aggregates,
                computed,
                ..
            } => {
                let keys: &[GroupKey] = match grouping {
                    GroupingSpec::None => &[],
                    GroupingSpec::Standard(keys)
                    | GroupingSpec::Cube(keys)
                    | GroupingSpec::Rollup(keys)
                    | GroupingSpec::All { keys, .. } => keys,
                    GroupingSpec::GroupingSets(sets) => &sets.keys,
                };
                for key in keys {
                    self.define(key.output, &key.expr);
                }
                self.computed(computed);
                self.aggregates(aggregates);
            }
            RelPlan::Window {
                windows, computed, ..
            } => {
                self.computed(computed);
                for window in windows {
                    self.definitions
                        .insert(window.output, Definition::Call(&window.args, &[]));
                    self.calls.push((&window.args, &[]));
                }
            }
            RelPlan::Pivot { aggregates, .. } => {
                for aggregate in aggregates {
                    self.calls.push((&aggregate.args, &aggregate.named_args));
                }
            }
            RelPlan::Unnest {
                array,
                value_column,
                ..
            } => {
                self.define(*value_column, array);
            }
            RelPlan::Scan {
                table,
                columns,
                node_id,
                ..
            } => {
                self.nodes.insert(*node_id, table);
                self.scanned(columns, table);
            }
            RelPlan::Unpivot {
                value_columns,
                unpivoted_columns,
                ..
            } => {
                for (at, value) in value_columns.iter().enumerate() {
                    let sources = unpivoted_columns
                        .iter()
                        .filter_map(|group| group.columns.get(at).copied());
                    self.unpivoted.entry(*value).or_default().extend(sources);
                }
            }
            // A table function's columns are made of its call, which no
            // column of them copies.
            RelPlan::TableFunction {
                call,
                output_columns,
                ..
            } => {
                self.source_calls.insert(span_key(call));
                for column in output_columns {
                    self.definitions
                        .insert(*column, Definition::Call(std::slice::from_ref(call), &[]));
                }
            }
            RelPlan::Insert {
                target,
                target_columns,
                source,
                on_conflict,
                ..
            } => {
                if target_columns.is_empty() {
                    self.written_whole.push(target);
                    match source {
                        InsertSource::Values(query) | InsertSource::Query(query) => {
                            self.positional.push((target, Positional::Query(query)))
                        }
                        InsertSource::DefaultValues => {}
                    }
                }
                self.written_into(target_columns, target);
                match source {
                    InsertSource::Values(rows) | InsertSource::Query(rows) => {
                        self.write_query(target_columns.iter().map(|c| Target::Column(*c)), rows);
                    }
                    InsertSource::DefaultValues => {}
                }
                if let Some(conflict) = on_conflict {
                    match &conflict.action {
                        ConflictAction::DoNothing => {}
                        ConflictAction::DoUpdate { assignments, .. }
                        | ConflictAction::MySqlDuplicateKeyUpdate { assignments } => {
                            self.assignments(assignments, target);
                        }
                    }
                }
            }
            RelPlan::Update {
                target,
                target_node,
                target_read_columns,
                assignments,
                ..
            } => {
                self.nodes.insert(*target_node, target);
                self.scanned(target_read_columns, target);
                self.assignments(assignments, target);
            }
            RelPlan::Delete {
                target,
                target_node,
                target_read_columns,
                ..
            } => {
                self.nodes.insert(*target_node, target);
                self.scanned(target_read_columns, target);
            }
            RelPlan::Merge {
                target,
                target_node,
                target_read_columns,
                branches,
                ..
            } => {
                self.nodes.insert(*target_node, target);
                self.scanned(target_read_columns, target);
                for branch in branches {
                    match &branch.action {
                        MergeAction::Insert {
                            target_columns,
                            values,
                        } => {
                            self.written_into(target_columns, target);
                            self.write_values(target_columns, values);
                        }
                        MergeAction::Update { assignments } => {
                            self.assignments(assignments, target)
                        }
                        MergeAction::InsertStar { .. }
                        | MergeAction::InsertAllByName { .. }
                        | MergeAction::UpdateSetStar { .. }
                        | MergeAction::UpdateAllByName { .. } => self.written_whole.push(target),
                        MergeAction::Delete | MergeAction::DoNothing => {}
                    }
                }
            }
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
                for MultiInsertTarget {
                    target,
                    target_columns,
                    values,
                    ..
                } in targets
                {
                    if target_columns.is_empty() {
                        self.written_whole.push(target);
                        self.positional.push((target, Positional::Rows(values)));
                    }
                    self.written_into(target_columns, target);
                    for row in values {
                        self.write_values(target_columns, row);
                    }
                }
            }
            RelPlan::CreateAsQuery {
                columns,
                body: Some(body),
                ..
            } => match columns {
                Some(names) => self.write_query(names.iter().map(Target::Named), body),
                None => {
                    let outputs = body.positional_columns().known;
                    self.write_query(outputs.into_iter().map(Target::Output), body);
                }
            },
            RelPlan::CreateAsQuery { body: None, .. }
            | RelPlan::CteRef { .. }
            | RelPlan::ModelRef { .. }
            | RelPlan::Join { .. }
            | RelPlan::SetOp { .. }
            | RelPlan::Sort { .. }
            | RelPlan::Limit { .. }
            | RelPlan::Explain { .. }
            | RelPlan::CreateTableForm { .. }
            | RelPlan::WithScope { .. }
            | RelPlan::DerivedTable { .. }
            | RelPlan::MatchRecognize { .. }
            | RelPlan::ConnectBy { .. }
            | RelPlan::TableSample { .. }
            | RelPlan::InvalidInput { .. }
            | RelPlan::ParseRecovery { .. }
            | RelPlan::Opaque { .. } => {}
        }
    }

    /// Each of `columns` is a column of `table` the statement reads.
    fn scanned(&mut self, columns: &[ColumnId], table: &'p TableRef) {
        self.scanned
            .extend(columns.iter().map(|column| (*column, table)));
    }

    fn computed(&mut self, computed: &'p [crate::ir::plan::ComputedItem]) {
        for item in computed {
            self.define(item.output, &item.expr);
        }
    }

    /// `column` is defined by `expr`; a column whose expression is the
    /// column itself (a group key over its input) is the input column and
    /// defines nothing.
    fn define(&mut self, column: ColumnId, expr: &'p ScalarExpr) {
        if matches!(expr, ScalarExpr::Column { column: copied, .. } if *copied == column) {
            return;
        }
        self.definitions.insert(column, Definition::Expr(expr));
    }

    fn aggregates(&mut self, aggregates: &'p [AggregateCall]) {
        for aggregate in aggregates {
            self.definitions.insert(
                aggregate.output,
                Definition::Call(&aggregate.args, &aggregate.named_args),
            );
            self.calls.push((&aggregate.args, &aggregate.named_args));
        }
    }

    /// Each of `columns` is a column of `table` the statement writes.
    fn written_into(&mut self, columns: &[ColumnId], table: &'p TableRef) {
        self.written_tables
            .extend(columns.iter().map(|column| (*column, table)));
    }

    /// `assignments`, of columns of `table`.
    fn assignments(&mut self, assignments: &'p [Assignment], table: &'p TableRef) {
        for assignment in assignments {
            self.written_into(&assignment.columns, table);
            match &assignment.value {
                AssignedValue::Row(values) => self.write_values(&assignment.columns, values),
                AssignedValue::Query { subquery, .. } => self.write_query(
                    assignment.columns.iter().map(|c| Target::Column(*c)),
                    subquery,
                ),
            }
        }
    }

    /// Each of `targets` is written the value at its place in `values`; a
    /// row of another length (`(a, b) = f(…)`) places none.
    fn write_values(&mut self, targets: &[ColumnId], values: &'p [ScalarExpr]) {
        if targets.len() != values.len() {
            return;
        }
        for (target, value) in targets.iter().zip(values) {
            self.writes
                .push((Target::Column(*target), Written::Value(value)));
        }
    }

    /// Each of `targets` is written the column at its place in `query`.
    fn write_query(&mut self, targets: impl Iterator<Item = Target<'p>>, query: &RelPlan) {
        own_columns(query, &mut self.own_places);
        let positions = query.positional_columns();
        for (at, target) in targets.enumerate() {
            if let Some(column) = positions.at(at).column() {
                self.writes.push((target, Written::Column(column)));
            }
        }
    }
}

impl<'p> RelPlanVisitor<'p> for Gathered<'p> {
    fn visit_rel_plan(&mut self, plan: &'p RelPlan) {
        self.record(plan);
        self.depth += 1;
        walk_rel_plan(self, plan);
        self.depth -= 1;
    }

    fn visit_subquery(&mut self, plan: &'p RelPlan, _correlates_with: &'p [ColumnId]) {
        if self.depth == 0 {
            self.roots.push(plan);
        }
        self.visit_rel_plan(plan);
    }

    fn visit_scalar_expr(&mut self, expr: &'p ScalarExpr) {
        if let ScalarExpr::BinOp {
            op: BinOpKind::Cmp(ComparisonOp::Eq),
            left,
            right,
            ..
        } = expr
        {
            self.equalities.push((left, right));
        }
        walk_scalar_expr(self, expr);
    }
}

/// Onto `own`, the columns `query`, a query a statement writes from, defines
/// at the places it writes: its select items and its `VALUES` rows, through
/// ordering, a limit, the CTEs it is written with and the branches of a set
/// operation. A column it takes from a CTE, a derived table, a joined
/// source or a `VALUES` it reads from is not one of them.
fn own_columns(query: &RelPlan, own: &mut BTreeSet<ColumnId>) {
    match query {
        RelPlan::Project { items, .. } => {
            own.extend(items.iter().filter_map(|item| match item {
                ProjectItem::Expr(expr) => Some(expr.output),
                ProjectItem::Star(_) => None,
            }));
        }
        RelPlan::Values { columns, .. } => own.extend(columns),
        RelPlan::Sort { input, .. } | RelPlan::Limit { input, .. } => own_columns(input, own),
        RelPlan::WithScope { body, .. } => own_columns(body, own),
        RelPlan::SetOp {
            inputs,
            output_columns,
            ..
        } => {
            own.extend(output_columns);
            for input in inputs {
                own_columns(input, own);
            }
        }
        RelPlan::Filter { .. }
        | RelPlan::Aggregate { .. }
        | RelPlan::Window { .. }
        | RelPlan::Pivot { .. }
        | RelPlan::Unnest { .. }
        | RelPlan::Insert { .. }
        | RelPlan::Update { .. }
        | RelPlan::Delete { .. }
        | RelPlan::Merge { .. }
        | RelPlan::MultiInsert { .. }
        | RelPlan::CreateAsQuery { .. }
        | RelPlan::Scan { .. }
        | RelPlan::CteRef { .. }
        | RelPlan::ModelRef { .. }
        | RelPlan::Join { .. }
        | RelPlan::Explain { .. }
        | RelPlan::CreateTableForm { .. }
        | RelPlan::DerivedTable { .. }
        | RelPlan::TableFunction { .. }
        | RelPlan::Unpivot { .. }
        | RelPlan::MatchRecognize { .. }
        | RelPlan::ConnectBy { .. }
        | RelPlan::TableSample { .. }
        | RelPlan::InvalidInput { .. }
        | RelPlan::ParseRecovery { .. }
        | RelPlan::Opaque { .. } => {}
    }
}

/// Whether `expr` reads nothing a statement or a run gives a value: no
/// column, variable, parameter or query.
fn is_constant(expr: &ScalarExpr) -> bool {
    struct Constant(bool);
    impl<'e> ScalarExprVisitor<'e> for Constant {
        fn visit_scalar_expr(&mut self, expr: &'e ScalarExpr) {
            self.0 &= match expr {
                ScalarExpr::Lit { value, .. } => match value {
                    Lit::Variable { .. } | Lit::Variant(_) => false,
                    Lit::Null
                    | Lit::Bool(_)
                    | Lit::Integer(_)
                    | Lit::Float(_)
                    | Lit::Str(_)
                    | Lit::Bytes { .. }
                    | Lit::Typed { .. } => true,
                },
                ScalarExpr::Column { .. }
                | ScalarExpr::OuterRef { .. }
                | ScalarExpr::PatternVarRef { .. }
                | ScalarExpr::ScalarSubquery { .. }
                | ScalarExpr::Exists { .. }
                | ScalarExpr::QuantifiedCmp { .. }
                | ScalarExpr::RowCmp { .. }
                | ScalarExpr::WindowFn { .. }
                | ScalarExpr::FieldAccess { .. }
                | ScalarExpr::Lambda { .. }
                | ScalarExpr::Opaque { .. } => false,
                ScalarExpr::BinOp { .. }
                | ScalarExpr::LogicalChain { .. }
                | ScalarExpr::OperatorChain { .. }
                | ScalarExpr::UnaryOp { .. }
                | ScalarExpr::FuncCall { .. }
                | ScalarExpr::Case { .. }
                | ScalarExpr::Cast { .. }
                | ScalarExpr::InList { .. }
                | ScalarExpr::Between { .. }
                | ScalarExpr::Like { .. } => true,
            };
            if self.0 {
                walk_scalar_expr_standalone(self, expr);
            }
        }
    }
    let mut constant = Constant(true);
    constant.visit_scalar_expr(expr);
    constant.0
}

/// The column `expr` is, converted or not: a scalar subquery is its
/// column's.
fn equated_column(expr: &ScalarExpr) -> Option<ColumnId> {
    match expr {
        ScalarExpr::Column { column, .. } | ScalarExpr::OuterRef { column, .. } => Some(*column),
        ScalarExpr::Cast { expr, .. } => equated_column(expr),
        ScalarExpr::ScalarSubquery { subquery, .. } => subquery.positional_columns().at(0).column(),
        ScalarExpr::Lit { .. }
        | ScalarExpr::BinOp { .. }
        | ScalarExpr::LogicalChain { .. }
        | ScalarExpr::OperatorChain { .. }
        | ScalarExpr::UnaryOp { .. }
        | ScalarExpr::FuncCall { .. }
        | ScalarExpr::Case { .. }
        | ScalarExpr::InList { .. }
        | ScalarExpr::Between { .. }
        | ScalarExpr::Like { .. }
        | ScalarExpr::Exists { .. }
        | ScalarExpr::QuantifiedCmp { .. }
        | ScalarExpr::RowCmp { .. }
        | ScalarExpr::WindowFn { .. }
        | ScalarExpr::FieldAccess { .. }
        | ScalarExpr::Lambda { .. }
        | ScalarExpr::PatternVarRef { .. }
        | ScalarExpr::Opaque { .. } => None,
    }
}

/// Which columns of a statement read a secret.
struct Classifier<'p, 'a> {
    gathered: Gathered<'p>,
    bindings: &'a BindingTable,
    steps: Vec<PairingSteps<'p>>,
    reading: Reading<'a>,
    secret: BTreeSet<ColumnId>,
}

impl<'p, 'a> Classifier<'p, 'a> {
    fn new(gathered: Gathered<'p>, bindings: &'a BindingTable, reading: Reading<'a>) -> Self {
        let steps = gathered
            .roots
            .iter()
            .map(|root| PairingSteps::of(root))
            .collect();
        let mut classifier = Self {
            gathered,
            bindings,
            steps,
            reading,
            secret: BTreeSet::new(),
        };
        classifier.secret = classifier.secret_columns();
        classifier
    }

    /// Every column that reads a secret: those that read one directly,
    /// then, in one pass over the columns each column reads, every column
    /// reading one of them.
    fn secret_columns(&self) -> BTreeSet<ColumnId> {
        let columns: BTreeSet<ColumnId> = self
            .bindings
            .iter()
            .map(|(column, _)| *column)
            .chain(self.gathered.definitions.keys().copied())
            .collect();
        let mut readers: BTreeMap<ColumnId, Vec<ColumnId>> = BTreeMap::new();
        let mut pending = Vec::new();
        for column in columns {
            let reads = self.column_reads(column);
            if reads.direct {
                pending.push(column);
            }
            for read in reads.columns {
                readers.entry(read).or_default().push(column);
            }
        }
        // A column equated with one that reads a secret holds that secret.
        for (left, right) in &self.gathered.equalities {
            if let (Some(left), Some(right)) = (equated_column(left), equated_column(right)) {
                readers.entry(left).or_default().push(right);
                readers.entry(right).or_default().push(left);
            }
        }
        let mut secret = BTreeSet::new();
        while let Some(column) = pending.pop() {
            if secret.insert(column) {
                pending.extend(readers.get(&column).into_iter().flatten().copied());
            }
        }
        secret
    }

    /// What `column` reads: its own name, its definition, the body column
    /// it is paired with, the columns its value is made of.
    fn column_reads(&self, column: ColumnId) -> Reads {
        let mut reads = Reads::default();
        if let Some(binding) = self.bindings.get(column) {
            match &binding.origin {
                ColumnOrigin::Table { column_name, .. } => {
                    reads.direct |= names_a_secret(column_name);
                }
                ColumnOrigin::Unattributed { name, .. } => reads.direct |= names_a_secret(name),
                ColumnOrigin::SetOp { inputs } => reads.columns.extend(inputs),
                ColumnOrigin::Merged { value, .. } => reads.columns.extend(value.sides()),
                ColumnOrigin::OuterRef { outer_column, .. } => reads.columns.push(*outer_column),
                ColumnOrigin::Computed { .. } | ColumnOrigin::RecursiveRef { .. } => {}
            }
        }
        reads.columns.extend(self.body_column(column));
        match self.gathered.definitions.get(&column) {
            Some(Definition::Expr(expr)) => self.expr_reads(expr, &mut reads),
            Some(Definition::Call(args, named)) => {
                for expr in args.iter().chain(named.iter().map(|(_, expr)| expr)) {
                    self.expr_reads(expr, &mut reads);
                }
            }
            Some(Definition::Row { rows, at }) => {
                for expr in row_values(rows, *at) {
                    self.expr_reads(expr, &mut reads);
                }
            }
            None => {}
        }
        reads
    }

    /// The body column `column`, listed by a CTE or a derived table, is
    /// paired with.
    fn body_column(&self, column: ColumnId) -> Option<ColumnId> {
        self.steps
            .iter()
            .find_map(|steps| steps.body_column(column))
    }

    /// Adds to `reads` what `expr` reads outside a subquery, a scalar
    /// subquery's column included.
    fn expr_reads(&self, expr: &ScalarExpr, reads: &mut Reads) {
        let mut walk = ReadsOf {
            reading: self.reading,
            reads,
        };
        walk.visit_scalar_expr(expr);
    }

    /// Whether `expr` reads a secret.
    fn reads_secret(&self, expr: &ScalarExpr) -> bool {
        let mut reads = Reads::default();
        self.expr_reads(expr, &mut reads);
        reads.direct
            || reads
                .columns
                .iter()
                .any(|column| self.secret.contains(column))
    }

    /// Whether `expr` is a secret's own value: a column, converted or not,
    /// that reads one, or a variable named for one.
    fn is_secret_value(&self, expr: &ScalarExpr) -> bool {
        match expr {
            ScalarExpr::Lit {
                value: Lit::Variable { name, .. },
                ..
            } => is_secret_name(name.as_str()),
            ScalarExpr::Lit {
                value: Lit::Variant(name),
                ..
            } => is_secret_name(name),
            ScalarExpr::Cast { expr, .. } => self.is_secret_value(expr),
            ScalarExpr::Lit { .. }
            | ScalarExpr::Column { .. }
            | ScalarExpr::OuterRef { .. }
            | ScalarExpr::BinOp { .. }
            | ScalarExpr::LogicalChain { .. }
            | ScalarExpr::OperatorChain { .. }
            | ScalarExpr::UnaryOp { .. }
            | ScalarExpr::FuncCall { .. }
            | ScalarExpr::Case { .. }
            | ScalarExpr::InList { .. }
            | ScalarExpr::Between { .. }
            | ScalarExpr::Like { .. }
            | ScalarExpr::Exists { .. }
            | ScalarExpr::ScalarSubquery { .. }
            | ScalarExpr::QuantifiedCmp { .. }
            | ScalarExpr::RowCmp { .. }
            | ScalarExpr::WindowFn { .. }
            | ScalarExpr::FieldAccess { .. }
            | ScalarExpr::Lambda { .. }
            | ScalarExpr::PatternVarRef { .. }
            | ScalarExpr::Opaque { .. } => {
                equated_column(expr).is_some_and(|column| self.secret.contains(&column))
            }
        }
    }

    /// The table `column` is a column of, where the statement scans,
    /// writes or reads it from one.
    fn table_of(&self, column: ColumnId) -> Option<&'p TableRef> {
        let gathered = &self.gathered;
        gathered
            .written_tables
            .get(&column)
            .or_else(|| gathered.scanned.get(&column))
            .copied()
            .or_else(
                || match self.bindings.get(column).map(|binding| &binding.origin) {
                    Some(ColumnOrigin::Table { table_node, .. }) => {
                        gathered.nodes.get(table_node).copied()
                    }
                    Some(
                        ColumnOrigin::Computed { .. }
                        | ColumnOrigin::Merged { .. }
                        | ColumnOrigin::SetOp { .. }
                        | ColumnOrigin::OuterRef { .. }
                        | ColumnOrigin::RecursiveRef { .. }
                        | ColumnOrigin::Unattributed { .. },
                    )
                    | None => None,
                },
            )
    }

    /// Whether `column` is a bare column no statement of the run writes:
    /// followed through the columns it copies, is paired with, correlates
    /// with or is a set operation's input of, it reaches only columns of
    /// tables, none of which the statement or another statement of the
    /// run writes (by the column's name and its table's). A column a
    /// statement computes (an aggregate, an expression, a literal) is not
    /// bare, and neither is one the walk ties to no table it checks.
    fn is_bare_unwritten(&self, column: ColumnId) -> bool {
        let gathered = &self.gathered;
        let written = self.reading.written;
        let writes = |table: &TableRef, name: &str| {
            written.holds(&self.reading.places.resolved(table), name)
                || gathered
                    .written_whole
                    .iter()
                    .any(|whole| same_table(whole, table))
                || gathered.written_tables.iter().any(|(column, target)| {
                    same_table(target, table)
                        && self.bindings.get(*column).is_some_and(|binding| {
                            column_key(&binding.display_name) == column_key(name)
                        })
                })
        };
        // A column not tied to one table is a column of one the statement
        // reads or writes: written where a statement writes a column of
        // that name of one of them; of any table where it names none.
        let named = |name: &str| match gathered.nodes.is_empty() {
            false => gathered.nodes.values().any(|table| writes(table, name)),
            true => {
                written.names(name)
                    || !gathered.written_whole.is_empty()
                    || gathered.written_tables.keys().any(|column| {
                        self.bindings.get(*column).is_some_and(|binding| {
                            column_key(&binding.display_name) == column_key(name)
                        })
                    })
            }
        };
        let mut seen = BTreeSet::new();
        let mut pending = vec![column];
        // Whether a column of a table was checked.
        let mut checked = false;
        while let Some(column) = pending.pop() {
            if !seen.insert(column) {
                continue;
            }
            if gathered.written_tables.contains_key(&column) {
                return false;
            }
            match gathered.definitions.get(&column) {
                Some(Definition::Expr(ScalarExpr::Column { column, .. })) => {
                    pending.push(*column);
                    continue;
                }
                Some(Definition::Expr(_) | Definition::Call(..) | Definition::Row { .. }) => {
                    return false
                }
                None => {}
            }
            let paired = self.body_column(column);
            pending.extend(paired);
            match self.bindings.get(column).map(|binding| &binding.origin) {
                // A column of no table the statement names is read as one
                // not tied to one table.
                Some(ColumnOrigin::Table { column_name, .. }) => {
                    let written = match self.table_of(column) {
                        Some(table) => writes(table, column_name),
                        None => named(column_name),
                    };
                    if written {
                        return false;
                    }
                    checked = true;
                }
                Some(ColumnOrigin::Unattributed { name, .. }) => {
                    if named(name) {
                        return false;
                    }
                    checked = true;
                }
                Some(ColumnOrigin::OuterRef { outer_column, .. }) => pending.push(*outer_column),
                Some(ColumnOrigin::SetOp { inputs }) => pending.extend(inputs),
                Some(ColumnOrigin::Merged { value, .. }) => pending.extend(value.sides()),
                Some(ColumnOrigin::Computed { .. }) if paired.is_some() => {}
                Some(ColumnOrigin::Computed { .. } | ColumnOrigin::RecursiveRef { .. }) | None => {
                    return false
                }
            }
        }
        checked
    }

    /// Whether a number compared with `expr` is masked where a string
    /// would be: `expr` reads a secret, or reaches a column a statement of
    /// the run writes through what it is made of.
    fn ties_numbers(&self, expr: &ScalarExpr) -> bool {
        if self.reads_secret(expr) {
            return true;
        }
        let mut reads = Reads::default();
        self.expr_reads(expr, &mut reads);
        reads
            .columns
            .into_iter()
            .any(|column| self.reaches_written(column))
    }

    /// Whether `column` reaches a column a statement of the run writes:
    /// itself, or a column its definition reads, it copies, is paired
    /// with, correlates with or is a set operation's or a merge's input of.
    fn reaches_written(&self, column: ColumnId) -> bool {
        let gathered = &self.gathered;
        let mut seen = BTreeSet::new();
        let mut pending = vec![column];
        while let Some(column) = pending.pop() {
            if !seen.insert(column) {
                continue;
            }
            let exprs: Vec<&ScalarExpr> = match gathered.definitions.get(&column) {
                Some(Definition::Expr(expr)) => vec![expr],
                Some(Definition::Call(args, named)) => args
                    .iter()
                    .chain(named.iter().map(|(_, expr)| expr))
                    .collect(),
                Some(Definition::Row { rows, at }) => row_values(rows, *at),
                None => Vec::new(),
            };
            let computed = !exprs.is_empty();
            for expr in exprs {
                let mut reads = Reads::default();
                self.expr_reads(expr, &mut reads);
                pending.extend(reads.columns);
            }
            pending.extend(self.body_column(column));
            match self.bindings.get(column).map(|binding| &binding.origin) {
                Some(ColumnOrigin::SetOp { inputs }) => pending.extend(inputs),
                Some(ColumnOrigin::Merged { value, .. }) => pending.extend(value.sides()),
                Some(ColumnOrigin::OuterRef { outer_column, .. }) => pending.push(*outer_column),
                Some(ColumnOrigin::Table { .. } | ColumnOrigin::Unattributed { .. })
                    if !computed =>
                {
                    if !self.is_bare_unwritten(column) {
                        return true;
                    }
                }
                Some(
                    ColumnOrigin::Table { .. }
                    | ColumnOrigin::Unattributed { .. }
                    | ColumnOrigin::Computed { .. }
                    | ColumnOrigin::RecursiveRef { .. },
                )
                | None => {}
            }
        }
        false
    }

    /// Whether a literal compared with `other` may be printed: `other` is
    /// a bare column no statement of the run writes
    /// ([`Self::is_bare_unwritten`]) or one a tag the organization lists
    /// marks ([`ShownColumn::Listed`]), or a constant, which tells nothing
    /// a column holds.
    fn shows_compared(&self, other: &ScalarExpr) -> bool {
        match other {
            ScalarExpr::Column { column, .. } | ScalarExpr::OuterRef { column, .. } => {
                self.is_bare_unwritten(*column)
                    || matches!(self.column_shown(*column), Some(ShownColumn::Listed))
            }
            ScalarExpr::Lit { .. }
            | ScalarExpr::BinOp { .. }
            | ScalarExpr::LogicalChain { .. }
            | ScalarExpr::OperatorChain { .. }
            | ScalarExpr::UnaryOp { .. }
            | ScalarExpr::FuncCall { .. }
            | ScalarExpr::Case { .. }
            | ScalarExpr::Cast { .. }
            | ScalarExpr::InList { .. }
            | ScalarExpr::Between { .. }
            | ScalarExpr::Like { .. }
            | ScalarExpr::Exists { .. }
            | ScalarExpr::ScalarSubquery { .. }
            | ScalarExpr::QuantifiedCmp { .. }
            | ScalarExpr::RowCmp { .. }
            | ScalarExpr::WindowFn { .. }
            | ScalarExpr::FieldAccess { .. }
            | ScalarExpr::Lambda { .. }
            | ScalarExpr::PatternVarRef { .. }
            | ScalarExpr::Opaque { .. } => is_constant(other),
        }
    }

    /// What a catalog records of the column `target` that shows a string
    /// written into it ([`Self::column_shown`]).
    fn target_shown(&self, target: &Target<'_>) -> Option<ShownColumn> {
        match target {
            Target::Column(column) => self.column_shown(*column),
            Target::Named(_) | Target::Output(_) => None,
        }
    }

    /// What a catalog records of `column`, a column of a table a statement
    /// writes or reads, that shows a string written into it: a tag the
    /// organization lists ([`crate::rules::MaskingPolicy`]), where every
    /// tag of the column and of its table is listed; or, where neither is
    /// tagged, its type, as the script's own statements leave it, where it
    /// holds a number, a truth value or a time.
    fn column_shown(&self, column: ColumnId) -> Option<ShownColumn> {
        let catalogued = self.reading.tables?;
        let binding = self.bindings.get(column)?;
        let table = self
            .table_of(column)
            .and_then(|table| catalogued.table(table))?;
        let name = IdentKey::new_as(&binding.display_name, NameKind::Column);
        let recorded = table
            .columns
            .iter()
            .find(|recorded| IdentKey::new_as(&recorded.name.name, NameKind::Column) == name)?;
        let listed = |tag: &crate::catalog::CatalogTag| {
            self.reading.shown_tags.iter().any(|shown| shown.marks(tag))
        };
        if recorded.tags.iter().any(listed) && recorded.tags.iter().chain(&table.tags).all(listed) {
            return Some(ShownColumn::Listed);
        }
        if !(recorded.tags.is_empty() && table.tags.is_empty()) {
            return None;
        }
        let kind = super::extract::classify_catalog_data_type(recorded.data_type.as_deref()?).kind;
        kind_holds_no_text(&kind).then_some(ShownColumn::Typed(kind))
    }

    /// Whether the column `target` names a secret.
    fn names_a_secret(&self, target: &Target<'_>) -> bool {
        match target {
            // A written column is named as the statement writes it, and as
            // the run names it elsewhere: the table column a view's column
            // shows.
            Target::Column(column) => self.bindings.get(*column).is_some_and(|binding| {
                names_a_secret(&binding.display_name)
                    || self.table_of(*column).is_some_and(|table| {
                        self.reading
                            .written
                            .other_names(
                                &self.reading.places.resolved(table),
                                &binding.display_name,
                            )
                            .iter()
                            .any(|name| names_a_secret(name.as_str()))
                    })
            }),
            Target::Named(name) => is_secret_name(name.as_str()),
            Target::Output(column) => self
                .gathered
                .aliases
                .get(column)
                .is_some_and(|alias| is_secret_name(alias.as_str())),
        }
    }
}

/// Whether `a` and `b` may name the same table ([`WrittenTable::meets`]).
fn same_table(a: &TableRef, b: &TableRef) -> bool {
    WrittenTable::of(a).meets(&WrittenTable::of(b))
}

/// What an expression or a column reads: a secret, directly, and the
/// columns it reads.
#[derive(Default)]
struct Reads {
    direct: bool,
    columns: Vec<ColumnId>,
}

/// One walk of an expression for what it reads.
struct ReadsOf<'r, 'a> {
    reading: Reading<'a>,
    reads: &'r mut Reads,
}

impl<'e> ScalarExprVisitor<'e> for ReadsOf<'_, '_> {
    fn visit_scalar_expr(&mut self, expr: &'e ScalarExpr) {
        match expr {
            ScalarExpr::Column { column, .. }
            | ScalarExpr::OuterRef { column, .. }
            | ScalarExpr::PatternVarRef { column, .. } => self.reads.columns.push(*column),
            ScalarExpr::Lit { value, .. } => {
                self.reads.direct |= match value {
                    Lit::Variable { name, .. } => is_secret_name(name.as_str()),
                    // A reference to a variable no scope around declares
                    // (`$v`, `:v`), by its name as written.
                    Lit::Variant(name) => is_secret_name(name),
                    Lit::Null
                    | Lit::Bool(_)
                    | Lit::Integer(_)
                    | Lit::Float(_)
                    | Lit::Str(_)
                    | Lit::Bytes { .. }
                    | Lit::Typed { .. } => false,
                };
            }
            ScalarExpr::FieldAccess { path, .. } => {
                self.reads.direct |= path.iter().any(|step| match step {
                    FieldStep::Field(name) => names_a_secret(name),
                    FieldStep::Index(_) => false,
                    FieldStep::IndexExpr(key) => self.names_a_secret_key(key),
                });
            }
            ScalarExpr::BinOp { op, right, .. } => {
                self.reads.direct |= reads_a_key(*op) && self.names_a_secret_key(right);
            }
            ScalarExpr::FuncCall { func, args, .. } => {
                match self.reading.functions.argument_roles(func) {
                    Some(ArgumentRoles::Path { from }) => {
                        self.reads.direct |= args
                            .iter()
                            .skip(from)
                            .any(|key| self.names_a_secret_key(key));
                    }
                    Some(
                        ArgumentRoles::KeyValuePairs { .. } | ArgumentRoles::PathValuePairs { .. },
                    )
                    | None => {}
                }
            }
            // A scalar subquery's value is its column's.
            ScalarExpr::ScalarSubquery { subquery, .. } => {
                self.reads
                    .columns
                    .extend(subquery.positional_columns().at(0).column());
                return;
            }
            ScalarExpr::LogicalChain { .. }
            | ScalarExpr::OperatorChain { .. }
            | ScalarExpr::UnaryOp { .. }
            | ScalarExpr::Case { .. }
            | ScalarExpr::Cast { .. }
            | ScalarExpr::InList { .. }
            | ScalarExpr::Between { .. }
            | ScalarExpr::Like { .. }
            | ScalarExpr::Exists { .. }
            | ScalarExpr::QuantifiedCmp { .. }
            | ScalarExpr::RowCmp { .. }
            | ScalarExpr::WindowFn { .. }
            | ScalarExpr::Lambda { .. }
            | ScalarExpr::Opaque { .. } => {}
        }
        walk_scalar_expr_standalone(self, expr);
    }
}

impl ReadsOf<'_, '_> {
    /// Whether `key`, a string written as a key of or a path into a
    /// document, names a secret.
    fn names_a_secret_key(&self, key: &ScalarExpr) -> bool {
        string_text(key, self.reading).is_some_and(is_secret_name)
    }
}

/// Whether a column or field name, as written, names a secret: its words
/// are read as written (`userPw`), before the dialect folds its case.
fn names_a_secret(name: &str) -> bool {
    is_secret_name(name) || is_secret_name(&normalize_identifier_as(name, NameKind::Column))
}

/// The text between the quotes of `expr`, where it is a string literal.
fn string_text<'a>(expr: &ScalarExpr, reading: Reading<'a>) -> Option<&'a str> {
    let span = string_literal_span(expr)?;
    let content = string_literal_content(span, reading.source, reading.dialect);
    reading
        .source
        .get(content.start as usize..content.end as usize)
}

/// The span of `expr` where it is a string or a binary literal.
fn string_literal_span(expr: &ScalarExpr) -> Option<Span> {
    let ScalarExpr::Lit { value, span } = expr else {
        return None;
    };
    match value {
        Lit::Str(_) | Lit::Bytes { .. } => Some(*span),
        Lit::Null
        | Lit::Bool(_)
        | Lit::Integer(_)
        | Lit::Float(_)
        | Lit::Typed { .. }
        | Lit::Variant(_)
        | Lit::Variable { .. } => None,
    }
}

/// The values at place `at` of `rows`; every value of them where a row
/// has none there, as any of them may be the column's.
fn row_values(rows: &[Vec<ScalarExpr>], at: usize) -> Vec<&ScalarExpr> {
    match rows.iter().all(|row| at < row.len()) {
        true => rows.iter().filter_map(|row| row.get(at)).collect(),
        false => rows.iter().flatten().collect(),
    }
}

/// The conditions `plan`'s own node filters or matches rows by: a value
/// of each is only tested.
fn plan_conditions(plan: &RelPlan) -> Vec<&ScalarExpr> {
    match plan {
        RelPlan::Filter { predicate, .. } => vec![predicate],
        RelPlan::Join {
            on,
            match_condition,
            ..
        } => on.iter().chain(match_condition).collect(),
        RelPlan::Update { predicate, .. } | RelPlan::Delete { predicate, .. } => {
            predicate.iter().collect()
        }
        RelPlan::Merge { on, branches, .. } => std::iter::once(on)
            .chain(
                branches
                    .iter()
                    .filter_map(|branch| branch.predicate.as_ref()),
            )
            .collect(),
        RelPlan::Values { .. }
        | RelPlan::Project { .. }
        | RelPlan::Aggregate { .. }
        | RelPlan::Window { .. }
        | RelPlan::Pivot { .. }
        | RelPlan::Unnest { .. }
        | RelPlan::Insert { .. }
        | RelPlan::MultiInsert { .. }
        | RelPlan::CreateAsQuery { .. }
        | RelPlan::Scan { .. }
        | RelPlan::CteRef { .. }
        | RelPlan::ModelRef { .. }
        | RelPlan::SetOp { .. }
        | RelPlan::Sort { .. }
        | RelPlan::Limit { .. }
        | RelPlan::Explain { .. }
        | RelPlan::CreateTableForm { .. }
        | RelPlan::WithScope { .. }
        | RelPlan::DerivedTable { .. }
        | RelPlan::TableFunction { .. }
        | RelPlan::Unpivot { .. }
        | RelPlan::MatchRecognize { .. }
        | RelPlan::ConnectBy { .. }
        | RelPlan::TableSample { .. }
        | RelPlan::InvalidInput { .. }
        | RelPlan::ParseRecovery { .. }
        | RelPlan::Opaque { .. } => Vec::new(),
    }
}

/// The span of the literal `expr` writes: a string, binary or typed
/// literal, converted or not.
fn written_literal_span(expr: &ScalarExpr) -> Option<Span> {
    match expr {
        ScalarExpr::Lit { value, span } => match value {
            Lit::Str(_) | Lit::Bytes { .. } | Lit::Typed { .. } => Some(*span),
            Lit::Null
            | Lit::Bool(_)
            | Lit::Integer(_)
            | Lit::Float(_)
            | Lit::Variant(_)
            | Lit::Variable { .. } => None,
        },
        ScalarExpr::Cast { expr, .. } => written_literal_span(expr),
        ScalarExpr::Column { .. }
        | ScalarExpr::OuterRef { .. }
        | ScalarExpr::BinOp { .. }
        | ScalarExpr::LogicalChain { .. }
        | ScalarExpr::OperatorChain { .. }
        | ScalarExpr::UnaryOp { .. }
        | ScalarExpr::FuncCall { .. }
        | ScalarExpr::Case { .. }
        | ScalarExpr::InList { .. }
        | ScalarExpr::Between { .. }
        | ScalarExpr::Like { .. }
        | ScalarExpr::Exists { .. }
        | ScalarExpr::ScalarSubquery { .. }
        | ScalarExpr::QuantifiedCmp { .. }
        | ScalarExpr::RowCmp { .. }
        | ScalarExpr::WindowFn { .. }
        | ScalarExpr::FieldAccess { .. }
        | ScalarExpr::Lambda { .. }
        | ScalarExpr::PatternVarRef { .. }
        | ScalarExpr::Opaque { .. } => None,
    }
}

/// Whether the value `expr` is holds no text: a literal of a type that
/// holds a number, a truth value or a time (`DATE '…'`), or a literal
/// converted to one, whose text reads as a value of that type: `'42'::int`,
/// not `TRY_CAST('word' AS INT)`.
fn holds_no_text(expr: &ScalarExpr, reading: Reading<'_>) -> bool {
    match expr {
        ScalarExpr::Lit {
            value: Lit::Typed { type_name, value },
            ..
        } => {
            let kind = super::extract::classify_catalog_data_type(type_name).kind;
            kind_holds_no_text(&kind) && reads_as(value.trim_matches('\''), &kind)
        }
        ScalarExpr::Cast {
            expr: converted,
            target_type,
            ..
        } => {
            let kind = super::extract::classify_catalog_data_type(&target_type.repr).kind;
            kind_holds_no_text(&kind)
                && match converted.as_ref() {
                    ScalarExpr::Lit {
                        value: Lit::Str(_) | Lit::Bytes { .. },
                        ..
                    } => string_text(converted, reading).is_some_and(|text| reads_as(text, &kind)),
                    ScalarExpr::Lit {
                        value: Lit::Typed { .. },
                        ..
                    }
                    | ScalarExpr::Cast { .. } => holds_no_text(converted, reading),
                    ScalarExpr::Lit {
                        value:
                            Lit::Null
                            | Lit::Bool(_)
                            | Lit::Integer(_)
                            | Lit::Float(_)
                            | Lit::Variant(_)
                            | Lit::Variable { .. },
                        ..
                    } => true,
                    ScalarExpr::Column { .. }
                    | ScalarExpr::OuterRef { .. }
                    | ScalarExpr::BinOp { .. }
                    | ScalarExpr::LogicalChain { .. }
                    | ScalarExpr::OperatorChain { .. }
                    | ScalarExpr::UnaryOp { .. }
                    | ScalarExpr::FuncCall { .. }
                    | ScalarExpr::Case { .. }
                    | ScalarExpr::InList { .. }
                    | ScalarExpr::Between { .. }
                    | ScalarExpr::Like { .. }
                    | ScalarExpr::Exists { .. }
                    | ScalarExpr::ScalarSubquery { .. }
                    | ScalarExpr::QuantifiedCmp { .. }
                    | ScalarExpr::RowCmp { .. }
                    | ScalarExpr::WindowFn { .. }
                    | ScalarExpr::FieldAccess { .. }
                    | ScalarExpr::Lambda { .. }
                    | ScalarExpr::PatternVarRef { .. }
                    | ScalarExpr::Opaque { .. } => false,
                }
        }
        ScalarExpr::Lit { .. }
        | ScalarExpr::Column { .. }
        | ScalarExpr::OuterRef { .. }
        | ScalarExpr::BinOp { .. }
        | ScalarExpr::LogicalChain { .. }
        | ScalarExpr::OperatorChain { .. }
        | ScalarExpr::UnaryOp { .. }
        | ScalarExpr::FuncCall { .. }
        | ScalarExpr::Case { .. }
        | ScalarExpr::InList { .. }
        | ScalarExpr::Between { .. }
        | ScalarExpr::Like { .. }
        | ScalarExpr::Exists { .. }
        | ScalarExpr::ScalarSubquery { .. }
        | ScalarExpr::QuantifiedCmp { .. }
        | ScalarExpr::RowCmp { .. }
        | ScalarExpr::WindowFn { .. }
        | ScalarExpr::FieldAccess { .. }
        | ScalarExpr::Lambda { .. }
        | ScalarExpr::PatternVarRef { .. }
        | ScalarExpr::Opaque { .. } => false,
    }
}

/// Whether `text`, a literal's, reads as a value of `kind`, a type that
/// holds no text: a number, a truth value, a date, a time or an interval,
/// written as the dialects' input forms write one.
fn reads_as(text: &str, kind: &DataTypeKind) -> bool {
    let text = text.trim();
    let lower = text.to_ascii_lowercase();
    let number = |text: &str| {
        let unsigned = text.strip_prefix(['+', '-']).unwrap_or(text);
        let (mantissa, exponent) = match unsigned.find(['e', 'E']) {
            Some(at) => (&unsigned[..at], Some(&unsigned[at + 1..])),
            None => (unsigned, None),
        };
        let mut parts = mantissa.splitn(2, '.');
        let whole = parts.next().unwrap_or("");
        let fraction = parts.next().unwrap_or("");
        let digits = |part: &str| part.chars().all(|c| c.is_ascii_digit());
        (!whole.is_empty() || !fraction.is_empty())
            && digits(whole)
            && digits(fraction)
            && exponent.is_none_or(|exponent| {
                let exponent = exponent.strip_prefix(['+', '-']).unwrap_or(exponent);
                !exponent.is_empty() && digits(exponent)
            })
    };
    match kind {
        DataTypeKind::Boolean => matches!(
            lower.as_str(),
            "true" | "false" | "t" | "f" | "yes" | "no" | "y" | "n" | "on" | "off" | "1" | "0"
        ),
        DataTypeKind::TinyInt
        | DataTypeKind::SmallInt
        | DataTypeKind::Integer
        | DataTypeKind::BigInt
        | DataTypeKind::Real
        | DataTypeKind::Double
        | DataTypeKind::Numeric
        | DataTypeKind::Decimal => {
            number(text)
                || matches!(
                    lower.as_str(),
                    "nan" | "inf" | "+inf" | "-inf" | "infinity" | "+infinity" | "-infinity"
                )
        }
        DataTypeKind::Date
        | DataTypeKind::Time
        | DataTypeKind::Timestamp
        | DataTypeKind::TimestampTz
        | DataTypeKind::TimestampLtz
        | DataTypeKind::TimestampNtz => {
            matches!(
                lower.as_str(),
                "infinity"
                    | "-infinity"
                    | "epoch"
                    | "now"
                    | "today"
                    | "tomorrow"
                    | "yesterday"
                    | "allballs"
            ) || (text.chars().any(|c| c.is_ascii_digit())
                && text.chars().all(|c| {
                    c.is_ascii_digit()
                        || c.is_whitespace()
                        || matches!(c, '-' | ':' | '.' | '/' | '+' | ',' | 'T' | 't' | 'Z' | 'z')
                }))
        }
        DataTypeKind::Interval => {
            const UNITS: &[&str] = &[
                "microsecond",
                "millisecond",
                "second",
                "minute",
                "hour",
                "day",
                "week",
                "month",
                "year",
                "decade",
                "century",
                "centuries",
                "millennium",
                "millennia",
                "us",
                "ms",
                "s",
                "sec",
                "secs",
                "m",
                "min",
                "mins",
                "h",
                "hr",
                "hrs",
                "d",
                "w",
                "mon",
                "mons",
                "y",
                "yr",
                "yrs",
                "ago",
            ];
            let iso = lower
                .strip_prefix(['+', '-'])
                .unwrap_or(&lower)
                .strip_prefix('p')
                .is_some_and(|rest| {
                    !rest.is_empty()
                        && rest.chars().all(|c| {
                            c.is_ascii_digit()
                                || matches!(c, 'y' | 'm' | 'w' | 'd' | 't' | 'h' | 's' | '.')
                        })
                });
            iso || (lower.chars().any(|c| c.is_ascii_digit())
                && lower.split_whitespace().all(|word| {
                    let unit = word.trim_end_matches('s');
                    word.chars()
                        .all(|c| c.is_ascii_digit() || matches!(c, '-' | '+' | ':' | '.'))
                        || UNITS.contains(&word)
                        || UNITS.contains(&unit)
                }))
        }
        DataTypeKind::Char
        | DataTypeKind::Varchar
        | DataTypeKind::Text
        | DataTypeKind::NChar
        | DataTypeKind::NVarchar
        | DataTypeKind::Clob
        | DataTypeKind::Binary
        | DataTypeKind::Varbinary
        | DataTypeKind::Blob
        | DataTypeKind::Bytes
        | DataTypeKind::Array
        | DataTypeKind::Map
        | DataTypeKind::Object
        | DataTypeKind::Struct
        | DataTypeKind::Variant
        | DataTypeKind::Json
        | DataTypeKind::Jsonb
        | DataTypeKind::Uuid
        | DataTypeKind::Geography
        | DataTypeKind::Geometry
        | DataTypeKind::Vector
        | DataTypeKind::Inet
        | DataTypeKind::Cidr
        | DataTypeKind::MacAddr
        | DataTypeKind::Other(_) => false,
    }
}

/// Whether a value of `kind` holds no text: a number, a truth value, a
/// date, a time or an interval.
fn kind_holds_no_text(kind: &DataTypeKind) -> bool {
    match kind {
        DataTypeKind::Boolean
        | DataTypeKind::TinyInt
        | DataTypeKind::SmallInt
        | DataTypeKind::Integer
        | DataTypeKind::BigInt
        | DataTypeKind::Real
        | DataTypeKind::Double
        | DataTypeKind::Numeric
        | DataTypeKind::Decimal
        | DataTypeKind::Date
        | DataTypeKind::Time
        | DataTypeKind::Timestamp
        | DataTypeKind::TimestampTz
        | DataTypeKind::TimestampLtz
        | DataTypeKind::TimestampNtz
        | DataTypeKind::Interval => true,
        DataTypeKind::Char
        | DataTypeKind::Varchar
        | DataTypeKind::Text
        | DataTypeKind::NChar
        | DataTypeKind::NVarchar
        | DataTypeKind::Clob
        | DataTypeKind::Binary
        | DataTypeKind::Varbinary
        | DataTypeKind::Blob
        | DataTypeKind::Bytes
        | DataTypeKind::Array
        | DataTypeKind::Map
        | DataTypeKind::Object
        | DataTypeKind::Struct
        | DataTypeKind::Variant
        | DataTypeKind::Json
        | DataTypeKind::Jsonb
        | DataTypeKind::Uuid
        | DataTypeKind::Geography
        | DataTypeKind::Geometry
        | DataTypeKind::Vector
        | DataTypeKind::Inet
        | DataTypeKind::Cidr
        | DataTypeKind::MacAddr
        | DataTypeKind::Other(_) => false,
    }
}

/// What a catalog records of a column that shows a string written into it
/// ([`Classifier::column_shown`]).
#[derive(Clone)]
enum ShownColumn {
    /// A tag the organization lists marks it as holding no secret: any
    /// literal written into it is shown.
    Listed,
    /// Its type in force holds no text: a string is shown where its text
    /// reads as a value of the type.
    Typed(DataTypeKind),
}

/// How a value is taken where it goes.
#[derive(Clone)]
enum Taken {
    /// Whole, by a comparison or a condition: each literal it is made of
    /// is shown ([`Masking::consume`]).
    Compared,
    /// Written into a column: shown where it is a literal, converted or
    /// not, that holds no text, or where what the catalog records of the
    /// column shows it ([`ShownColumn`]).
    Written { column: Option<ShownColumn> },
}

/// What a call writes as the argument `expr`, as a routine's forms tell it
/// apart.
fn written_value(expr: &ScalarExpr) -> WrittenValue {
    match expr {
        ScalarExpr::Lit {
            value: Lit::Str(_), ..
        } => WrittenValue::Text,
        ScalarExpr::Lit {
            value: Lit::Bool(_),
            ..
        } => WrittenValue::Flag,
        ScalarExpr::Lit { .. }
        | ScalarExpr::Column { .. }
        | ScalarExpr::OuterRef { .. }
        | ScalarExpr::BinOp { .. }
        | ScalarExpr::LogicalChain { .. }
        | ScalarExpr::OperatorChain { .. }
        | ScalarExpr::UnaryOp { .. }
        | ScalarExpr::FuncCall { .. }
        | ScalarExpr::Case { .. }
        | ScalarExpr::Cast { .. }
        | ScalarExpr::InList { .. }
        | ScalarExpr::Between { .. }
        | ScalarExpr::Like { .. }
        | ScalarExpr::Exists { .. }
        | ScalarExpr::ScalarSubquery { .. }
        | ScalarExpr::QuantifiedCmp { .. }
        | ScalarExpr::RowCmp { .. }
        | ScalarExpr::WindowFn { .. }
        | ScalarExpr::FieldAccess { .. }
        | ScalarExpr::Lambda { .. }
        | ScalarExpr::PatternVarRef { .. }
        | ScalarExpr::Opaque { .. } => WrittenValue::Other,
    }
}

/// Whether `op` reads the value its right operand, a key or a path, names
/// in the document its left operand is.
fn reads_a_key(op: BinOpKind) -> bool {
    match op {
        BinOpKind::JsonField
        | BinOpKind::JsonFieldText
        | BinOpKind::JsonPath
        | BinOpKind::JsonPathText => true,
        BinOpKind::Add
        | BinOpKind::Sub
        | BinOpKind::Mul
        | BinOpKind::Div
        | BinOpKind::Mod
        | BinOpKind::IntDiv
        | BinOpKind::Cmp(_)
        | BinOpKind::IsDistinctFrom
        | BinOpKind::IsNotDistinctFrom
        | BinOpKind::And
        | BinOpKind::Or
        | BinOpKind::Xor
        | BinOpKind::Concat
        | BinOpKind::LogicalOr
        | BinOpKind::AtTimeZone
        | BinOpKind::Distance
        | BinOpKind::ArrayContains
        | BinOpKind::ArrayContainedBy
        | BinOpKind::ArrayOverlap
        | BinOpKind::JsonContains
        | BinOpKind::JsonExists
        | BinOpKind::RegexMatch
        | BinOpKind::RegexMatchI
        | BinOpKind::RegexNotMatch
        | BinOpKind::RegexNotMatchI
        | BinOpKind::Shl
        | BinOpKind::Shr
        | BinOpKind::BitXor
        | BinOpKind::BitXorPg
        | BinOpKind::BitAnd
        | BinOpKind::BitOr
        | BinOpKind::Exponent
        | BinOpKind::QueryMatch
        | BinOpKind::JsonExistsAny
        | BinOpKind::JsonExistsAll
        | BinOpKind::StartsWith
        | BinOpKind::Overlaps
        | BinOpKind::SoundsLike
        | BinOpKind::MemberOf => false,
    }
}

/// Whether `op` compares its operands' values, so that a value of either
/// side tells what the other holds.
fn compares(op: BinOpKind) -> bool {
    match op {
        BinOpKind::Cmp(_)
        | BinOpKind::IsDistinctFrom
        | BinOpKind::IsNotDistinctFrom
        | BinOpKind::RegexMatch
        | BinOpKind::RegexMatchI
        | BinOpKind::RegexNotMatch
        | BinOpKind::RegexNotMatchI
        | BinOpKind::StartsWith
        | BinOpKind::SoundsLike
        | BinOpKind::QueryMatch
        | BinOpKind::ArrayContains
        | BinOpKind::ArrayContainedBy
        | BinOpKind::ArrayOverlap
        | BinOpKind::JsonContains
        | BinOpKind::MemberOf => true,
        BinOpKind::Add
        | BinOpKind::Sub
        | BinOpKind::Mul
        | BinOpKind::Div
        | BinOpKind::Mod
        | BinOpKind::IntDiv
        | BinOpKind::And
        | BinOpKind::Or
        | BinOpKind::Xor
        | BinOpKind::Concat
        | BinOpKind::LogicalOr
        | BinOpKind::AtTimeZone
        | BinOpKind::Distance
        | BinOpKind::JsonField
        | BinOpKind::JsonFieldText
        | BinOpKind::JsonPath
        | BinOpKind::JsonPathText
        | BinOpKind::JsonExists
        | BinOpKind::JsonExistsAny
        | BinOpKind::JsonExistsAll
        | BinOpKind::Shl
        | BinOpKind::Shr
        | BinOpKind::BitXor
        | BinOpKind::BitXorPg
        | BinOpKind::BitAnd
        | BinOpKind::BitOr
        | BinOpKind::Exponent
        | BinOpKind::Overlaps => false,
    }
}

/// `expr`'s span, as a key.
fn span_key(expr: &ScalarExpr) -> (u32, u32) {
    let span = expr.span();
    (span.start, span.end)
}

/// Whether `op` makes a value of its operands' values: arithmetic,
/// concatenation and bitwise operators.
fn combines(op: BinOpKind) -> bool {
    match op {
        BinOpKind::Add
        | BinOpKind::Sub
        | BinOpKind::Mul
        | BinOpKind::Div
        | BinOpKind::Mod
        | BinOpKind::IntDiv
        | BinOpKind::Concat
        | BinOpKind::Shl
        | BinOpKind::Shr
        | BinOpKind::BitXor
        | BinOpKind::BitXorPg
        | BinOpKind::BitAnd
        | BinOpKind::BitOr
        | BinOpKind::Exponent => true,
        BinOpKind::Cmp(_)
        | BinOpKind::IsDistinctFrom
        | BinOpKind::IsNotDistinctFrom
        | BinOpKind::And
        | BinOpKind::Or
        | BinOpKind::Xor
        | BinOpKind::LogicalOr
        | BinOpKind::AtTimeZone
        | BinOpKind::Distance
        | BinOpKind::ArrayContains
        | BinOpKind::ArrayContainedBy
        | BinOpKind::ArrayOverlap
        | BinOpKind::JsonField
        | BinOpKind::JsonFieldText
        | BinOpKind::JsonPath
        | BinOpKind::JsonPathText
        | BinOpKind::JsonContains
        | BinOpKind::JsonExists
        | BinOpKind::JsonExistsAny
        | BinOpKind::JsonExistsAll
        | BinOpKind::RegexMatch
        | BinOpKind::RegexMatchI
        | BinOpKind::RegexNotMatch
        | BinOpKind::RegexNotMatchI
        | BinOpKind::QueryMatch
        | BinOpKind::StartsWith
        | BinOpKind::Overlaps
        | BinOpKind::SoundsLike
        | BinOpKind::MemberOf => false,
    }
}

/// One walk of a statement's expressions for the literals a report may
/// print: those shown safe, less those the classifier finds compared with,
/// passed beside, written into or paired with something that reads a
/// secret.
struct Masking<'c, 'p, 'a> {
    classifier: &'c Classifier<'p, 'a>,
    /// The content span of each literal that reaches a secret.
    masked: BTreeSet<(u32, u32)>,
    /// The span of each literal that is not a string and is a secret's
    /// value: written into or equated with one.
    vetoed: BTreeSet<(u32, u32)>,
    /// The span of each literal shown safe by where its value goes, and of
    /// each place a select item's name is written.
    shown: BTreeSet<(u32, u32)>,
    /// The span of each operation read as part of a value made of the
    /// operands of an operation holding it ([`Self::combined`]).
    combined: BTreeSet<(u32, u32)>,
}

impl<'c, 'p, 'a> Masking<'c, 'p, 'a> {
    /// The walk of a statement `classifier` reads.
    fn new(classifier: &'c Classifier<'p, 'a>) -> Self {
        let mut masking = Self {
            classifier,
            masked: BTreeSet::new(),
            vetoed: BTreeSet::new(),
            shown: BTreeSet::new(),
            combined: BTreeSet::new(),
        };
        // A string written as the name a select item gives its column is a
        // name.
        for name in &classifier.gathered.item_names {
            masking.shown.insert((name.start, name.end));
        }
        for (args, named) in &classifier.gathered.calls {
            masking.call(
                args.iter()
                    .map(|expr| (None, expr))
                    .chain(named.iter().map(|(name, expr)| (Some(name.as_str()), expr))),
            );
        }
        // A written value is shown only where it is known to hold no
        // secret: a literal that is no text, or one written into a column
        // a catalog records as holding no text. A column named for a
        // secret masks it, of any kind, whatever the catalog records.
        for (target, written) in &classifier.gathered.writes {
            if classifier.names_a_secret(target) {
                match written {
                    Written::Value(expr) => masking.mask_value(expr),
                    Written::Column(column) => masking.mask_column(*column, true),
                }
            } else {
                let taken = Taken::Written {
                    column: classifier.target_shown(target),
                };
                match written {
                    Written::Value(expr) => masking.take(expr, &taken),
                    Written::Column(column) => masking.show_column(*column, &taken),
                }
            }
            // A number is shown only where it is written at the column's
            // own place: one that reaches the column from a CTE, a derived
            // table, a `VALUES` read from, a joined or a `USING` source is
            // masked, as no name tells what it is.
            match written {
                Written::Value(expr) => masking.veto_beyond(expr),
                Written::Column(column) => masking.veto_beyond_own_place(*column),
            }
        }
        // A value written by position goes to the column of its place in
        // the table's columns, where every one is known: masked of any
        // kind where that column is named for a secret. Where they are not
        // known, or the place is past those the run knows, the place is
        // undecided, and a number is masked.
        for (table, written) in &classifier.gathered.positional {
            let names = classifier.reading.places.columns(table);
            let secret = |at: usize| {
                names
                    .as_ref()
                    .and_then(|names| names.get(at))
                    .map(|name| names_a_secret(name))
            };
            match written {
                Positional::Query(query) => {
                    let positions = query.positional_columns();
                    // Where the query's columns are not known by position,
                    // a number of it may go to any place: masked where any
                    // place may be a secret's.
                    if positions.open {
                        let any_secret = names
                            .as_ref()
                            .is_none_or(|names| names.iter().any(|name| names_a_secret(name)));
                        if any_secret {
                            masking.veto_plan_numbers(query);
                        }
                        continue;
                    }
                    for (at, column) in positions.known.iter().enumerate() {
                        match secret(at) {
                            Some(true) => masking.mask_column(*column, true),
                            Some(false) => {}
                            None => masking.veto_reached(*column),
                        }
                    }
                }
                Positional::Rows(rows) => {
                    for row in rows.iter() {
                        for (at, expr) in row.iter().enumerate() {
                            match secret(at) {
                                Some(true) => masking.mask_value(expr),
                                Some(false) => {}
                                None => masking.veto_numbers(expr),
                            }
                        }
                    }
                }
            }
        }
        // A value a select item names for a secret (`SELECT 4821 AS pin`)
        // is that secret's value.
        for (column, alias) in &classifier.gathered.aliases {
            if names_a_secret(alias.as_str()) {
                masking.mask_column(*column, true);
            }
        }
        masking
    }

    /// Masks each number the columns `expr` reads are made of
    /// ([`Self::veto_reached`]): `expr`'s own literals are left.
    fn veto_beyond(&mut self, expr: &ScalarExpr) {
        let mut reads = Reads::default();
        self.classifier.expr_reads(expr, &mut reads);
        for column in reads.columns {
            self.veto_reached(column);
        }
    }

    /// Masks each number that reaches `column`, a column of the query a
    /// statement writes from, other than at the query's own place
    /// ([`own_columns`]).
    fn veto_beyond_own_place(&mut self, column: ColumnId) {
        let classifier = self.classifier;
        if !classifier.gathered.own_places.contains(&column) {
            return self.veto_reached(column);
        }
        match classifier.gathered.definitions.get(&column) {
            Some(Definition::Expr(expr)) => self.veto_beyond(expr),
            Some(Definition::Row { rows, at }) => {
                for expr in row_values(rows, *at) {
                    self.veto_beyond(expr);
                }
            }
            Some(Definition::Call(..)) => self.veto_reached(column),
            None => match classifier
                .bindings
                .get(column)
                .map(|binding| &binding.origin)
            {
                Some(ColumnOrigin::SetOp { inputs }) => {
                    for input in inputs {
                        self.veto_beyond_own_place(*input);
                    }
                }
                Some(_) | None => self.veto_reached(column),
            },
        }
    }

    /// Masks each number `column` is made of: the literals of its
    /// definition and of every column it reads, copies, is paired with or
    /// is a set operation's or a merge's input of.
    /// Masks every number `plan` holds.
    fn veto_plan_numbers(&mut self, plan: &RelPlan) {
        let mut strings = BTreeSet::new();
        Literals {
            reading: self.classifier.reading,
            masked: &mut strings,
            vetoed: Some(&mut self.vetoed),
        }
        .visit_rel_plan(plan);
    }

    fn veto_reached(&mut self, column: ColumnId) {
        let classifier = self.classifier;
        let mut seen = BTreeSet::new();
        let mut pending = vec![column];
        while let Some(column) = pending.pop() {
            if !seen.insert(column) {
                continue;
            }
            let exprs: Vec<&ScalarExpr> = match classifier.gathered.definitions.get(&column) {
                Some(Definition::Expr(expr)) => vec![expr],
                Some(Definition::Call(args, named)) => args
                    .iter()
                    .chain(named.iter().map(|(_, expr)| expr))
                    .collect(),
                Some(Definition::Row { rows, at }) => row_values(rows, *at),
                None => Vec::new(),
            };
            for expr in exprs {
                self.veto_numbers(expr);
                let mut reads = Reads::default();
                classifier.expr_reads(expr, &mut reads);
                pending.extend(reads.columns);
            }
            pending.extend(classifier.body_column(column));
            match classifier
                .bindings
                .get(column)
                .map(|binding| &binding.origin)
            {
                Some(ColumnOrigin::SetOp { inputs }) => pending.extend(inputs),
                Some(ColumnOrigin::Merged { value, .. }) => pending.extend(value.sides()),
                Some(ColumnOrigin::OuterRef { outer_column, .. }) => pending.push(*outer_column),
                // A name no source lists may be a column of a `VALUES`
                // whose columns are not named (Snowflake's `column1`).
                Some(ColumnOrigin::Unattributed { .. }) => pending.extend(
                    classifier
                        .gathered
                        .values_columns
                        .iter()
                        .filter(|values| {
                            classifier
                                .bindings
                                .get(**values)
                                .is_none_or(|binding| binding.display_name.is_empty())
                        })
                        .copied(),
                ),
                Some(
                    ColumnOrigin::Table { .. }
                    | ColumnOrigin::Computed { .. }
                    | ColumnOrigin::RecursiveRef { .. },
                )
                | None => {}
            }
        }
    }

    /// Masks every number and binary value of `expr`, at any depth.
    fn veto_numbers(&mut self, expr: &ScalarExpr) {
        let mut unmasked = BTreeSet::new();
        let mut literals = Literals {
            reading: self.classifier.reading,
            masked: &mut unmasked,
            vetoed: Some(&mut self.vetoed),
        };
        literals.visit_scalar_expr(expr);
    }

    /// Shows the literals of `expr`, a value taken as `taken` says.
    fn take(&mut self, expr: &ScalarExpr, taken: &Taken) {
        match taken {
            Taken::Compared => self.consume(expr),
            Taken::Written { column } => {
                let reading = self.classifier.reading;
                let shown = holds_no_text(expr, reading)
                    || match column {
                        Some(ShownColumn::Listed) => true,
                        Some(ShownColumn::Typed(kind)) => {
                            matches!(
                                expr,
                                ScalarExpr::Lit {
                                    value: Lit::Str(_),
                                    ..
                                }
                            ) && string_text(expr, reading).is_some_and(|text| reads_as(text, kind))
                        }
                        None => false,
                    };
                if let Some(span) = written_literal_span(expr).filter(|_| shown) {
                    self.shown.insert((span.start, span.end));
                }
            }
        }
    }

    /// The literals shown safe that reach no secret.
    fn finish(self) -> ShownLiterals {
        let reading = self.classifier.reading;
        let spans = self
            .shown
            .iter()
            .map(|(start, end)| Span {
                start: *start,
                end: *end,
            })
            .filter(|span| {
                let content = string_literal_content(*span, reading.source, reading.dialect);
                !self.masked.contains(&(content.start, content.end))
            })
            .collect();
        let vetoed = self
            .vetoed
            .iter()
            .map(|(start, end)| Span {
                start: *start,
                end: *end,
            })
            .collect();
        ShownLiterals { spans, vetoed }
    }

    /// Shows each literal whose value goes no further than `expr`, a value
    /// a comparison, a condition or a column the statement names takes
    /// whole: `expr` itself where it is a literal, converted or not; each
    /// operand of a condition; each argument of a built-in call
    /// ([`Self::builtin_call`]).
    fn consume(&mut self, expr: &ScalarExpr) {
        match expr {
            ScalarExpr::Lit { .. } => {
                if let Some(span) = written_literal_span(expr) {
                    self.shown.insert((span.start, span.end));
                }
            }
            // A value converted is taken whole as it is.
            ScalarExpr::Cast {
                expr: converted, ..
            } => match written_literal_span(expr) {
                Some(span) => {
                    self.shown.insert((span.start, span.end));
                }
                None => self.consume(converted),
            },
            ScalarExpr::FuncCall {
                func,
                args,
                named_args,
                ..
            } => self.builtin_call(func, args, named_args),
            // A value made of its operands is taken whole where it is: a
            // condition's, a negation's, a concatenation's or a sum's.
            ScalarExpr::LogicalChain { operands, .. }
            | ScalarExpr::OperatorChain { operands, .. } => {
                for operand in operands {
                    self.consume(operand);
                }
            }
            ScalarExpr::BinOp {
                op, left, right, ..
            } if compares(*op) => self.compared_shown(left, right),
            ScalarExpr::BinOp { left, right, .. } => {
                self.consume(left);
                self.consume(right);
            }
            ScalarExpr::UnaryOp { arg, .. } => self.consume(arg),
            ScalarExpr::Column { .. }
            | ScalarExpr::OuterRef { .. }
            | ScalarExpr::Case { .. }
            | ScalarExpr::InList { .. }
            | ScalarExpr::Between { .. }
            | ScalarExpr::Like { .. }
            | ScalarExpr::Exists { .. }
            | ScalarExpr::ScalarSubquery { .. }
            | ScalarExpr::QuantifiedCmp { .. }
            | ScalarExpr::RowCmp { .. }
            | ScalarExpr::WindowFn { .. }
            | ScalarExpr::FieldAccess { .. }
            | ScalarExpr::Lambda { .. }
            | ScalarExpr::PatternVarRef { .. }
            | ScalarExpr::Opaque { .. } => {}
        }
    }

    /// Shows the literals the value of `column`, a column of a query taken
    /// as `taken` says, is written as ([`Self::take`]): the value at its
    /// place in a `VALUES` row or a select item, following a column it
    /// copies, the body column it is paired with and each input of a set
    /// operation.
    fn show_column(&mut self, column: ColumnId, taken: &Taken) {
        let classifier = self.classifier;
        let mut seen = BTreeSet::new();
        let mut pending = vec![column];
        while let Some(column) = pending.pop() {
            if !seen.insert(column) {
                continue;
            }
            match classifier.gathered.definitions.get(&column) {
                Some(Definition::Expr(ScalarExpr::Column { column, .. })) => pending.push(*column),
                Some(Definition::Expr(expr)) => self.take(expr, taken),
                Some(Definition::Row { rows, at }) => {
                    for expr in rows.iter().filter_map(|row| row.get(*at)) {
                        self.take(expr, taken);
                    }
                }
                Some(Definition::Call(..)) => {}
                None => {
                    pending.extend(classifier.body_column(column));
                    if let Some(ColumnOrigin::SetOp { inputs }) = classifier
                        .bindings
                        .get(column)
                        .map(|binding| &binding.origin)
                    {
                        pending.extend(inputs);
                    }
                }
            }
        }
    }

    /// The arguments of a call of `func`, whose result a comparison, a
    /// condition or a column takes whole ([`Self::consume`]): each taken
    /// whole too, where the dialect's own catalog states the function's
    /// signature, at a place where the dialect's routine table lists no
    /// key, passphrase, command or SQL text it takes. A function known by
    /// name alone, or one a script defines, states nothing of what it does
    /// with an argument: none is proven safe.
    fn builtin_call(
        &mut self,
        func: &ResolvedFunc,
        args: &[ScalarExpr],
        named: &[(IdentKey, ScalarExpr)],
    ) {
        let reading = self.classifier.reading;
        let name = match func {
            ResolvedFunc::Resolved { id, .. } => match reading.functions.signature(*id) {
                Some(signature) => signature.display_name.clone(),
                None => return,
            },
            ResolvedFunc::Unresolved { .. } => return,
        };
        let dialect = crate::ir::CatalogDialect::from_dialect_name(reading.dialect.name());
        if FunctionCatalog::dialect_defined(dialect)
            .lookup(&name)
            .is_none()
        {
            return;
        }
        let written: Vec<(Option<&str>, &ScalarExpr)> = args
            .iter()
            .map(|expr| (None, expr))
            .chain(named.iter().map(|(name, expr)| (Some(name.as_str()), expr)))
            .collect();
        // The routine table is read by the name folded as the dialect
        // compares a routine's.
        let name = crate::ir::lower::routine_name(&name);
        let parts: Vec<&str> = name.iter().map(IdentKey::as_str).collect();
        let uses: Vec<Option<ArgumentUse>> = match reading.dialect.system_routine(&parts) {
            Some(routine) => routine.argument_uses(
                &written
                    .iter()
                    .map(|(name, expr)| WrittenArgument {
                        name: *name,
                        value: written_value(expr),
                    })
                    .collect::<Vec<_>>(),
            ),
            None => vec![Some(ArgumentUse::Value); written.len()],
        };
        for ((_, expr), reads) in written.iter().zip(uses) {
            match reads {
                Some(ArgumentUse::Value | ArgumentUse::Name | ArgumentUse::Flag) => {
                    self.consume(expr)
                }
                Some(
                    ArgumentUse::RunsSql
                    | ArgumentUse::RunsSqlRemotely
                    | ArgumentUse::Command
                    | ArgumentUse::Credential
                    | ArgumentUse::ConnectionString,
                )
                | None => {}
            }
        }
    }

    /// Onto `operands`, the operands of the value `expr` makes with
    /// operations that make a value of their operands, each operation
    /// noted as read.
    fn combined_operands<'e>(&mut self, expr: &'e ScalarExpr, operands: &mut Vec<&'e ScalarExpr>) {
        match expr {
            ScalarExpr::BinOp {
                op, left, right, ..
            } if combines(*op) => {
                self.combined.insert(span_key(expr));
                self.combined_operands(left, operands);
                self.combined_operands(right, operands);
            }
            ScalarExpr::BinOp { .. }
            | ScalarExpr::Column { .. }
            | ScalarExpr::OuterRef { .. }
            | ScalarExpr::Lit { .. }
            | ScalarExpr::LogicalChain { .. }
            | ScalarExpr::OperatorChain { .. }
            | ScalarExpr::UnaryOp { .. }
            | ScalarExpr::Cast { .. }
            | ScalarExpr::FuncCall { .. }
            | ScalarExpr::Case { .. }
            | ScalarExpr::InList { .. }
            | ScalarExpr::Between { .. }
            | ScalarExpr::Like { .. }
            | ScalarExpr::Exists { .. }
            | ScalarExpr::ScalarSubquery { .. }
            | ScalarExpr::QuantifiedCmp { .. }
            | ScalarExpr::RowCmp { .. }
            | ScalarExpr::WindowFn { .. }
            | ScalarExpr::FieldAccess { .. }
            | ScalarExpr::Lambda { .. }
            | ScalarExpr::PatternVarRef { .. }
            | ScalarExpr::Opaque { .. } => operands.push(expr),
        }
    }

    /// `operands` make one value: where one reads a secret, every other
    /// one's literals are masked (a pepper or a salt joined with a
    /// password).
    fn combined(&mut self, operands: &[&ScalarExpr]) {
        let reading: Vec<bool> = operands
            .iter()
            .map(|operand| self.classifier.reads_secret(operand))
            .collect();
        if reading.iter().any(|reads| *reads) {
            for (operand, reads) in operands.iter().zip(reading) {
                if !reads {
                    self.mask(operand);
                }
            }
        }
    }

    /// Shows each argument of a call of `func`, a routine of the dialect,
    /// that the dialect's routine table gives as a name
    /// ([`ArgumentUse::Name`]), wherever the call is.
    fn shown_names(
        &mut self,
        func: &ResolvedFunc,
        args: &[ScalarExpr],
        named: &[(IdentKey, ScalarExpr)],
    ) {
        let reading = self.classifier.reading;
        let name = match func {
            ResolvedFunc::Resolved { id, .. } => match reading.functions.signature(*id) {
                Some(signature) => signature.display_name.clone(),
                None => return,
            },
            ResolvedFunc::Unresolved {
                raw_name,
                namespace: None,
                ..
            } => raw_name.clone(),
            ResolvedFunc::Unresolved { .. } => return,
        };
        let parts = crate::ir::lower::routine_name(&name);
        let parts: Vec<&str> = parts.iter().map(IdentKey::as_str).collect();
        let Some(routine) = reading.dialect.system_routine(&parts) else {
            return;
        };
        let written: Vec<(Option<&str>, &ScalarExpr)> = args
            .iter()
            .map(|expr| (None, expr))
            .chain(named.iter().map(|(name, expr)| (Some(name.as_str()), expr)))
            .collect();
        let uses = routine.argument_uses(
            &written
                .iter()
                .map(|(name, expr)| WrittenArgument {
                    name: *name,
                    value: written_value(expr),
                })
                .collect::<Vec<_>>(),
        );
        for ((_, expr), reads) in written.iter().zip(uses) {
            if reads == Some(ArgumentUse::Name) {
                self.consume(expr);
            }
        }
    }

    /// Shows each literal operand of a comparison of `left` and `right`
    /// where the other side shows it ([`Classifier::shows_compared`]);
    /// masks the numbers of one where the other side does not show it and
    /// reads a secret or a column the run writes
    /// ([`Classifier::ties_numbers`]).
    fn compared_shown(&mut self, left: &ScalarExpr, right: &ScalarExpr) {
        self.compared_operand(left, right);
        self.compared_operand(right, left);
    }

    /// `value` is compared with `other` ([`Self::compared_shown`]).
    fn compared_operand(&mut self, other: &ScalarExpr, value: &ScalarExpr) {
        if self.classifier.shows_compared(other) {
            self.consume(value);
        } else if self.classifier.ties_numbers(other) {
            self.veto_numbers(value);
        }
    }

    /// Masks every string literal of `expr`, at any depth.
    fn mask(&mut self, expr: &ScalarExpr) {
        let mut literals = Literals {
            reading: self.classifier.reading,
            masked: &mut self.masked,
            vetoed: None,
        };
        literals.visit_scalar_expr(expr);
    }

    /// Masks every literal of `expr` of any kind, at any depth: `expr` is a
    /// secret's value.
    fn mask_value(&mut self, expr: &ScalarExpr) {
        let mut literals = Literals {
            reading: self.classifier.reading,
            masked: &mut self.masked,
            vetoed: Some(&mut self.vetoed),
        };
        literals.visit_scalar_expr(expr);
    }

    /// Masks the string literals the value of `column`, a column of a
    /// query, is written with, those of any kind where it is a secret's
    /// value (`values`): its expression's, where it computes one, following
    /// a column it copies, the body column it is paired with, and each
    /// input of a set operation.
    fn mask_column(&mut self, column: ColumnId, values: bool) {
        let classifier = self.classifier;
        let mut seen = BTreeSet::new();
        let mut pending = vec![column];
        while let Some(column) = pending.pop() {
            if !seen.insert(column) {
                continue;
            }
            match classifier.gathered.definitions.get(&column) {
                Some(Definition::Expr(ScalarExpr::Column { column, .. })) => pending.push(*column),
                Some(Definition::Expr(expr)) => match values {
                    true => self.mask_value(expr),
                    false => self.mask(expr),
                },
                Some(Definition::Call(args, named)) => {
                    for expr in args.iter().chain(named.iter().map(|(_, expr)| expr)) {
                        self.mask(expr);
                    }
                }
                Some(Definition::Row { rows, at }) => {
                    for expr in row_values(rows, *at) {
                        match values {
                            true => self.mask_value(expr),
                            false => self.mask(expr),
                        }
                    }
                }
                None => {
                    pending.extend(classifier.body_column(column));
                    if let Some(ColumnOrigin::SetOp { inputs }) = classifier
                        .bindings
                        .get(column)
                        .map(|binding| &binding.origin)
                    {
                        pending.extend(inputs);
                    }
                }
            }
        }
    }

    /// `left` and `right` are compared: each literal of either is masked
    /// where the other reads a secret, of any kind where the other is the
    /// secret's value.
    fn compared(&mut self, left: &ScalarExpr, right: &ScalarExpr) {
        self.compared_with(left, right);
        self.compared_with(right, left);
    }

    /// `value` is compared with `other` ([`Self::compared`]).
    fn compared_with(&mut self, other: &ScalarExpr, value: &ScalarExpr) {
        if self.classifier.reads_secret(other) {
            match self.classifier.is_secret_value(other) {
                true => self.mask_value(value),
                false => self.mask(value),
            }
        }
    }

    /// `left` is compared with the column at `at` of `query`: each side's
    /// literals are shown where the other side shows them
    /// ([`Self::compared_shown`]), the query's column counting as bare
    /// where it is one no statement of the run writes.
    fn compared_with_query(&mut self, left: &ScalarExpr, query: &RelPlan, at: usize) {
        let Some(column) = query.positional_columns().at(at).column() else {
            return;
        };
        let classifier = self.classifier;
        if classifier.is_bare_unwritten(column) {
            self.consume(left);
        } else if classifier.reaches_written(column) || classifier.secret.contains(&column) {
            self.veto_numbers(left);
        }
        if classifier.shows_compared(left) {
            self.show_column(column, &Taken::Compared);
        } else if classifier.ties_numbers(left) {
            self.veto_reached(column);
        }
        if classifier.reads_secret(left) {
            self.mask_column(column, classifier.is_secret_value(left));
        }
        if classifier.secret.contains(&column) {
            self.mask_value(left);
        }
    }

    /// A call's arguments, each with its name where it has one: every
    /// argument beside one that reads a secret is masked, and so is an
    /// argument named for a secret.
    fn call<'e>(&mut self, arguments: impl Iterator<Item = (Option<&'e str>, &'e ScalarExpr)>) {
        let arguments: Vec<(Option<&str>, &ScalarExpr)> = arguments.collect();
        let reading: Vec<bool> = arguments
            .iter()
            .map(|(_, expr)| self.classifier.reads_secret(expr))
            .collect();
        let readers = reading.iter().filter(|reads| **reads).count();
        for ((name, expr), reads) in arguments.iter().zip(&reading) {
            if name.is_some_and(is_secret_name) {
                self.mask_value(expr);
            } else if readers > usize::from(*reads) {
                self.mask(expr);
            }
        }
    }

    /// The pairs of a call taking paths and the values set at them in turn
    /// from `from`: a value, of any kind, is masked where any key of its
    /// path names a secret, whatever follows it (`'$.pin[0]'`, `'{pin,0}'`),
    /// or the path is not written as text.
    fn path_pairs(&mut self, args: &[ScalarExpr], from: usize) {
        let reading = self.classifier.reading;
        for pair in args.get(from..).unwrap_or_default().chunks(2) {
            if let [path, value] = pair {
                let keyed = string_text(path, reading).map(|path| {
                    path.split(|c: char| !(c.is_alphanumeric() || c == '_'))
                        .any(|key| !key.is_empty() && is_secret_name(key))
                });
                if keyed != Some(false) {
                    self.mask_value(value);
                }
            }
        }
    }

    /// The pairs of a call taking keys and values in turn from `from`: a
    /// value, of any kind, is masked where its key names a secret.
    fn pairs(&mut self, args: &[ScalarExpr], from: usize) {
        let reading = self.classifier.reading;
        for pair in args.get(from..).unwrap_or_default().chunks(2) {
            if let [key, value] = pair {
                if string_text(key, reading).is_some_and(is_secret_name) {
                    self.mask_value(value);
                }
            }
        }
    }
}

impl<'e> RelPlanVisitor<'e> for Masking<'_, '_, '_> {
    fn visit_rel_plan(&mut self, plan: &'e RelPlan) {
        for condition in plan_conditions(plan) {
            self.consume(condition);
        }
        walk_rel_plan(self, plan);
    }

    fn visit_scalar_expr(&mut self, expr: &'e ScalarExpr) {
        match expr {
            ScalarExpr::BinOp {
                op, left, right, ..
            } => {
                if compares(*op) {
                    self.compared(left, right);
                    self.compared_shown(left, right);
                } else if combines(*op) && !self.combined.contains(&span_key(expr)) {
                    // The operands of every operation of the value at once.
                    let mut operands = Vec::new();
                    self.combined_operands(expr, &mut operands);
                    self.combined(&operands);
                }
            }
            ScalarExpr::OperatorChain {
                operands,
                operators,
                ..
            } => {
                if operators.iter().any(|op| combines(*op)) {
                    self.combined(&operands.iter().collect::<Vec<_>>());
                }
                // `operators[i]` joins the fold of `operands[..=i]` with
                // `operands[i + 1]`.
                let mut folded_reads = false;
                for (at, (op, right)) in operators.iter().zip(operands.iter().skip(1)).enumerate() {
                    folded_reads |= operands
                        .get(at)
                        .is_some_and(|left| self.classifier.reads_secret(left));
                    if !compares(*op) {
                        continue;
                    }
                    if let Some(left) = operands.get(at) {
                        self.compared_shown(left, right);
                    }
                    if folded_reads {
                        self.mask(right);
                    }
                    if self.classifier.reads_secret(right) {
                        for left in operands.iter().take(at + 1) {
                            self.mask(left);
                        }
                    }
                }
            }
            ScalarExpr::Like { expr, pattern, .. } => {
                self.compared(expr, pattern);
                self.compared_shown(expr, pattern);
            }
            ScalarExpr::InList { expr, list, .. }
            | ScalarExpr::QuantifiedCmp {
                left: expr,
                right: QuantifiedRhs::List(list),
                ..
            } => {
                for item in list {
                    self.compared(expr, item);
                    self.compared_shown(expr, item);
                }
            }
            ScalarExpr::QuantifiedCmp {
                left,
                right: QuantifiedRhs::Subquery(query, _),
                ..
            } => self.compared_with_query(left, query, 0),
            ScalarExpr::RowCmp { left, subquery, .. } => {
                for (at, element) in left.iter().enumerate() {
                    self.compared_with_query(element, subquery, at);
                }
            }
            ScalarExpr::Between {
                expr, low, high, ..
            } => {
                self.compared(expr, low);
                self.compared(expr, high);
                self.compared_shown(expr, low);
                self.compared_shown(expr, high);
            }
            ScalarExpr::Case {
                operand: Some(operand),
                branches,
                ..
            } => {
                for (when, _) in branches {
                    self.compared(operand, when);
                    self.compared_shown(operand, when);
                }
            }
            ScalarExpr::FuncCall {
                func,
                args,
                named_args,
                ..
            } => {
                self.call(
                    args.iter().map(|expr| (None, expr)).chain(
                        named_args
                            .iter()
                            .map(|(name, expr)| (Some(name.as_str()), expr)),
                    ),
                );
                self.constructed(func, args);
                self.shown_names(func, args, named_args);
            }
            ScalarExpr::WindowFn { call, .. } => {
                self.call(call.args.iter().map(|expr| (None, expr)));
            }
            ScalarExpr::Case {
                operand: None,
                branches,
                ..
            } => {
                for (when, _) in branches {
                    self.consume(when);
                }
            }
            ScalarExpr::LogicalChain { operands, .. } => {
                for operand in operands {
                    self.consume(operand);
                }
            }
            ScalarExpr::Column { .. }
            | ScalarExpr::OuterRef { .. }
            | ScalarExpr::Lit { .. }
            | ScalarExpr::UnaryOp { .. }
            | ScalarExpr::Cast { .. }
            | ScalarExpr::Exists { .. }
            | ScalarExpr::ScalarSubquery { .. }
            | ScalarExpr::FieldAccess { .. }
            | ScalarExpr::Lambda { .. }
            | ScalarExpr::PatternVarRef { .. }
            | ScalarExpr::Opaque { .. } => {}
        }
        walk_scalar_expr(self, expr);
    }
}

impl Masking<'_, '_, '_> {
    /// The pairs of a call of `func`, where the catalog says it takes keys
    /// and values in turn.
    fn constructed(&mut self, func: &ResolvedFunc, args: &[ScalarExpr]) {
        match self.classifier.reading.functions.argument_roles(func) {
            Some(ArgumentRoles::KeyValuePairs { from }) => self.pairs(args, from),
            Some(ArgumentRoles::PathValuePairs { from }) => self.path_pairs(args, from),
            Some(ArgumentRoles::Path { .. }) | None => {}
        }
    }
}

/// One walk of an expression, the plans it holds included, adding the
/// content span of each string literal to `masked`, and, where `vetoed` is
/// given, the span of each number and binary value to it.
struct Literals<'m, 'a> {
    reading: Reading<'a>,
    masked: &'m mut BTreeSet<(u32, u32)>,
    vetoed: Option<&'m mut BTreeSet<(u32, u32)>>,
}

impl<'e> RelPlanVisitor<'e> for Literals<'_, '_> {
    fn visit_scalar_expr(&mut self, expr: &'e ScalarExpr) {
        if let Some(span) = string_literal_span(expr) {
            let content = string_literal_content(span, self.reading.source, self.reading.dialect);
            self.masked.insert((content.start, content.end));
        }
        // A typed literal (`DATE '…'`) is a string under its type's name:
        // masked whole, as the span that shows it is.
        if let ScalarExpr::Lit {
            value: Lit::Typed { .. },
            span,
        } = expr
        {
            self.masked.insert((span.start, span.end));
        }
        if let (Some(vetoed), ScalarExpr::Lit { value, span }) = (self.vetoed.as_mut(), expr) {
            match value {
                Lit::Integer(_) | Lit::Float(_) | Lit::Bytes { .. } => {
                    vetoed.insert((span.start, span.end));
                }
                // A truth value or NULL holds no secret; a string is masked
                // by its content; a variable is a name.
                Lit::Null
                | Lit::Bool(_)
                | Lit::Str(_)
                | Lit::Typed { .. }
                | Lit::Variant(_)
                | Lit::Variable { .. } => {}
            }
        }
        walk_scalar_expr(self, expr);
    }
}

/// A string literal of a text, as the dialect's lexer reads it
/// ([`ReportedLiterals`]).
#[derive(Debug, Clone, Copy)]
pub(crate) struct TextLiteral {
    pub(crate) span: Span,
    /// Its text between its quotes or delimiters.
    pub(crate) content: Span,
    /// Whether it is template code, or text a template block holds or
    /// passes on, which nothing renders: no walk shows it.
    pub(crate) template: bool,
    /// Whether it is a number: a value, never a name's text.
    pub(crate) number: bool,
}

/// What a report prints of the string literals of one text: a literal is
/// printed only where its span is in the shown set, every other one is
/// masked, and so is each span masked whole (a secret the parser records
/// at a credential's place, a template block's held value). Every quote of
/// the text ([`Self::quote`]) and every fact string a literal fills
/// ([`printing`]) is read through it.
#[derive(Debug, Default)]
pub(crate) struct ReportedLiterals {
    /// In source order, none overlapping another.
    literals: Vec<TextLiteral>,
    /// The span of each literal shown safe ([`plan_literals`],
    /// [`script_literals`], the dialect's shown grammar slots). It grows
    /// as each statement is read.
    shown: std::cell::RefCell<BTreeSet<(u32, u32)>>,
    /// Masked whatever they hold, in source order.
    whole: Vec<Span>,
    /// The literals that are not strings a statement's walk finds to be a
    /// secret's value ([`ShownLiterals::vetoed`]), masked whole. It grows
    /// as each statement is read.
    vetoed: std::cell::RefCell<BTreeSet<(u32, u32)>>,
    /// Text a fact string made of is masked, though a quote prints it: a
    /// variable a statement takes a name from, whose value is masked.
    held: Vec<Span>,
    /// Whether the text is SQL a script runs, of which no literal is shown.
    run_text: bool,
    /// Whether the text masks anything, once asked. It stays true where
    /// literals shown later leave nothing masked, which only asks again.
    masks_any: std::cell::Cell<Option<bool>>,
}

impl ReportedLiterals {
    /// The literals `literals` of a text, `whole` masked whole; none of
    /// them shown where the text is SQL a script runs (`run_text`).
    pub(crate) fn new(literals: Vec<TextLiteral>, mut whole: Vec<Span>, run_text: bool) -> Self {
        whole.sort_by_key(|span| (span.start, span.end));
        Self {
            literals,
            shown: std::cell::RefCell::default(),
            whole,
            vetoed: std::cell::RefCell::default(),
            held: Vec::new(),
            run_text,
            masks_any: std::cell::Cell::new(None),
        }
    }

    /// These literals, `held` masked where a fact prints text made of it.
    pub(crate) fn holding(mut self, mut held: Vec<Span>) -> Self {
        held.sort_by_key(|span| (span.start, span.end));
        self.held = held;
        self
    }

    /// Mask each span of `spans` whole: literals that are not strings and
    /// are a secret's value.
    pub(crate) fn veto(&self, spans: &[Span]) {
        if spans.is_empty() {
            return;
        }
        self.vetoed
            .borrow_mut()
            .extend(spans.iter().map(|span| (span.start, span.end)));
        self.masks_any.set(Some(true));
    }

    /// Show each literal a span of `spans` holds.
    pub(crate) fn show(&self, spans: &[Span]) {
        if self.run_text || spans.is_empty() {
            return;
        }
        let mut shown = self.shown.borrow_mut();
        shown.extend(spans.iter().map(|span| (span.start, span.end)));
    }

    /// Whether `literal` is printed: a span shown holds it.
    fn is_shown(&self, literal: &TextLiteral, shown: &BTreeSet<(u32, u32)>) -> bool {
        !self.run_text
            && !literal.template
            && shown
                .range(..=(literal.span.start, u32::MAX))
                .next_back()
                .is_some_and(|(_, end)| literal.span.end <= *end)
    }

    /// Whether a report masks a name written at `span`: a string literal
    /// there is not shown, or a span masked whole meets it. A number is
    /// never a name's text (a project `proj-123`, a call's argument
    /// beside its name), so none masks one.
    pub(crate) fn masks_name(&self, span: Span) -> bool {
        let meets = |other: &Span| other.start < span.end && span.start < other.end;
        let first = self.whole.partition_point(|w| w.end <= span.start);
        if self.whole[first..]
            .iter()
            .take_while(|w| w.start < span.end)
            .any(meets)
            || self.held.iter().any(meets)
        {
            return true;
        }
        let shown = self.shown.borrow();
        let first = self.literals.partition_point(|l| l.span.end <= span.start);
        self.literals[first..]
            .iter()
            .take_while(|l| l.span.start < span.end)
            .any(|literal| {
                !literal.number && meets(&literal.span) && !self.is_shown(literal, &shown)
            })
    }

    /// Whether a report masks any of the text at `span`: a literal there
    /// is not shown, or a span masked whole meets it.
    pub(crate) fn masks(&self, span: Span) -> bool {
        let meets = |other: &Span| other.start < span.end && span.start < other.end;
        let first = self.whole.partition_point(|w| w.end <= span.start);
        if self.whole[first..]
            .iter()
            .take_while(|w| w.start < span.end)
            .any(meets)
        {
            return true;
        }
        if self
            .vetoed
            .borrow()
            .range(..(span.end, 0))
            .any(|(start, end)| *start < span.end && span.start < *end)
            || self.held.iter().any(meets)
        {
            return true;
        }
        let shown = self.shown.borrow();
        let first = self.literals.partition_point(|l| l.span.end <= span.start);
        self.literals[first..]
            .iter()
            .take_while(|l| l.span.start < span.end)
            .any(|literal| meets(&literal.span) && !self.is_shown(literal, &shown))
    }

    /// What [`Self::quote`] overwrites: the content of every literal not
    /// shown, and every span masked whole; none empty.
    pub(crate) fn masked_spans(&self) -> Vec<Span> {
        let shown = self.shown.borrow();
        let vetoed = self.vetoed.borrow();
        self.literals
            .iter()
            .filter(|literal| !self.is_shown(literal, &shown))
            .map(|literal| literal.content)
            .chain(self.whole.iter().copied())
            .chain(vetoed.iter().map(|(start, end)| Span {
                start: *start,
                end: *end,
            }))
            .filter(|span| span.start < span.end)
            .collect()
    }

    /// What [`Self::quote`] overwrites, in source order, a span meeting or
    /// touching another joined with it: each is printed as one mask
    /// ([`masked_fixed`]).
    pub(crate) fn masked_runs(&self) -> Vec<Span> {
        let mut spans = self.masked_spans();
        spans.sort_unstable_by_key(|span| (span.start, span.end));
        let mut runs: Vec<Span> = Vec::with_capacity(spans.len());
        for span in spans {
            match runs.last_mut() {
                Some(last) if span.start <= last.end => last.end = last.end.max(span.end),
                Some(_) | None => runs.push(span),
            }
        }
        runs
    }

    /// `src`, the text, as a report prints it whole: each run of what is
    /// masked printed as one mask whatever its length ([`masked_fixed`]).
    pub(crate) fn quote_fixed(&self, src: &str) -> String {
        masked_fixed(src, 0, src.len(), &self.masked_runs()).into_owned()
    }

    /// The span of each literal shown, in source order.
    pub(crate) fn shown_literals(&self) -> Vec<Span> {
        let shown = self.shown.borrow();
        self.literals
            .iter()
            .filter(|literal| self.is_shown(literal, &shown))
            .map(|literal| literal.span)
            .collect()
    }

    /// `src`, the text, as a report quotes it: the content of every literal
    /// not shown and every span masked whole overwritten with `*`, byte
    /// for byte, so each offset of the text is that of the quote. Borrowed
    /// where nothing is masked.
    pub(crate) fn quote<'a>(&self, src: &'a str) -> std::borrow::Cow<'a, str> {
        let masked = self.masked_spans();
        if masked.is_empty() {
            return std::borrow::Cow::Borrowed(src);
        }
        let mut bytes = src.as_bytes().to_vec();
        let len = bytes.len();
        for span in masked {
            let start = (span.start as usize).min(len);
            let end = (span.end as usize).min(len).max(start);
            for byte in &mut bytes[start..end] {
                *byte = b'*';
            }
        }
        // A masked range is all `*`; a span that splits a character
        // degrades to the replacement character, never to what it held.
        std::borrow::Cow::Owned(String::from_utf8_lossy(&bytes).into_owned())
    }

    /// `facts`, a statement's at `statement`, as a report prints them:
    /// each credential value masked
    /// ([`super::StatementFacts::mask_credential_values`]), and each string
    /// a literal of the text fills masked where that literal is not shown
    /// ([`printing`]). A key is never masked, and neither is a string the
    /// facts' types constrain.
    pub(crate) fn printed(
        self: &std::rc::Rc<Self>,
        statement: Span,
        facts: &super::StatementFacts,
    ) -> Result<super::StatementFacts, serde_json::Error> {
        self.printed_or_unchanged(statement, facts)
            .map(|(printed, _)| printed)
    }

    /// [`Self::printed`], and whether it may differ from `facts`: it is
    /// `facts` unchanged where the statement holds no literal that is not
    /// shown, writes no credential value, and its facts hold no string
    /// written elsewhere in the text that is masked (a name another
    /// statement or an expression's text gives).
    fn printed_or_unchanged(
        self: &std::rc::Rc<Self>,
        statement: Span,
        facts: &super::StatementFacts,
    ) -> Result<(super::StatementFacts, bool), serde_json::Error> {
        let mut printed = facts.clone();
        let values = printed.mask_credential_values();
        let holds = self.holds_a_secret(statement);
        // A constraint made of text outside the statement is masked
        // whatever this text masks.
        let elsewhere = facts.query.as_ref().is_some_and(|query| {
            query.scopes.iter().any(|scope| {
                scope
                    .where_predicates
                    .iter()
                    .chain(&scope.having_predicates)
                    .flat_map(|predicate| &predicate.cross_scope_effects)
                    .chain(
                        scope
                            .predicates
                            .iter()
                            .flat_map(|predicate| &predicate.cross_scope_effects),
                    )
                    .any(super::query::PredicateCrossScopeEffect::quotes_text_elsewhere)
            })
        });
        if !holds && !elsewhere && values.is_empty() && !self.masks_a_string_of(facts) {
            return Ok((printed, false));
        }
        if holds {
            printed.for_each_literal_text_mut(&mut |text| {
                *text = super::MASKED_VALUE.to_string();
            });
        }
        let written = printing(self, || serde_json::to_value(&printed))?;
        serde_json::from_value(written).map(|printed| (printed, true))
    }

    /// Whether printing `facts` masks a string: one whose origin holds a
    /// literal that is not shown. A fact that cannot be serialized is
    /// taken to.
    fn masks_a_string_of(self: &std::rc::Rc<Self>, facts: &super::StatementFacts) -> bool {
        // A text that masks nothing masks no string; showing more never
        // masks more.
        let whole_text = Span {
            start: 0,
            end: u32::MAX,
        };
        let masks_any = match self.masks_any.get() {
            Some(masks_any) => masks_any,
            None => {
                let masks_any = self.masks(whole_text);
                self.masks_any.set(Some(masks_any));
                masks_any
            }
        };
        if !masks_any {
            return false;
        }
        let before = MASKED_IN_PRINT.with(|masked| masked.replace(false));
        let written = printing(self, || serde_json::to_writer(std::io::sink(), facts));
        let masked = MASKED_IN_PRINT.with(|masked| masked.replace(before));
        masked || written.is_err()
    }

    /// Whether the statement at `statement` holds a literal a report does
    /// not show, or text it masks whole.
    pub(crate) fn holds_a_secret(&self, statement: Span) -> bool {
        self.masks(statement)
    }

    /// The strings of `written`, the serialized `facts` of the statement at
    /// `statement`, that a report masks where it prints `facts`
    /// ([`Self::printed`]), each by the value that holds it, with its
    /// masked text.
    pub(crate) fn quoting_strings(
        self: &std::rc::Rc<Self>,
        statement: Span,
        facts: &super::StatementFacts,
        written: &serde_json::Value,
    ) -> QuotingStrings {
        let mut by_node = std::collections::HashMap::new();
        let printed = match self.printed_or_unchanged(statement, facts) {
            // Printed as written: no string differs.
            Ok((_, false)) => return QuotingStrings { by_node },
            Ok((printed, true)) => {
                #[cfg(test)]
                MASKED_COPIES.with(|copies| copies.set(copies.get() + 1));
                serde_json::to_value(&printed)
            }
            Err(e) => Err(e),
        };
        match printed {
            Ok(printed) => differing_strings(written, &printed, &mut by_node),
            // Facts that cannot be printed are masked whole.
            Err(_) => mask_every_string(written, &mut by_node),
        }
        QuotingStrings { by_node }
    }
}

/// `text[from..to]`, `text` a text or a quote of it that keeps its offsets,
/// with what each of `runs` (in source order, none touching another) covers
/// of it printed as one mask, `****`, whatever its length: a masked value
/// tells nothing of its length. The line breaks a run covers are kept after
/// its mask, so every line after it keeps its number. Borrowed where no run
/// meets the range; a bound that is not a char boundary is moved back to
/// one.
pub(crate) fn masked_fixed<'a>(
    text: &'a str,
    from: usize,
    to: usize,
    runs: &[Span],
) -> std::borrow::Cow<'a, str> {
    let boundary = |at: usize| {
        let mut at = at.min(text.len());
        while !text.is_char_boundary(at) {
            at -= 1;
        }
        at
    };
    let (from, to) = (boundary(from), boundary(to));
    let to = to.max(from);
    let first = runs.partition_point(|run| run.end as usize <= from);
    let mut meeting = runs[first..]
        .iter()
        .take_while(|run| (run.start as usize) < to)
        .peekable();
    if meeting.peek().is_none() {
        return std::borrow::Cow::Borrowed(&text[from..to]);
    }
    let mut out = String::with_capacity(to - from);
    let mut at = from;
    for run in meeting {
        let start = boundary((run.start as usize).max(at));
        let end = boundary((run.end as usize).min(to)).max(start);
        out.push_str(&text[at..start]);
        out.push_str(super::MASKED_VALUE);
        out.extend(text[start..end].chars().filter(|c| *c == '\n'));
        at = end;
    }
    out.push_str(&text[at..to]);
    std::borrow::Cow::Owned(out)
}

/// Where a report prints a statement's facts from: the literals of the
/// text, and the statement's span in it.
#[derive(Clone, Copy)]
pub(crate) struct PrintedAt<'a> {
    pub(crate) literals: &'a std::rc::Rc<ReportedLiterals>,
    pub(crate) statement: Span,
}

impl PrintedAt<'_> {
    /// [`ReportedLiterals::quoting_strings`] of the statement.
    pub(crate) fn quoting_strings(
        self,
        facts: &super::StatementFacts,
        written: &serde_json::Value,
    ) -> QuotingStrings {
        self.literals
            .quoting_strings(self.statement, facts, written)
    }
}

std::thread_local! {
    /// The literals of the text whose facts this thread is printing
    /// ([`printing`]).
    static PRINTING: std::cell::RefCell<Option<std::rc::Rc<ReportedLiterals>>> =
        const { std::cell::RefCell::new(None) };
    /// Whether a string serialized inside [`printing`] was masked.
    static MASKED_IN_PRINT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Run `print` with `literals` the text its facts are printed from: a
/// string a literal of the text fills, serialized inside it, is masked
/// where that literal is not shown ([`masked_in_print`]).
pub(crate) fn printing<R>(
    literals: &std::rc::Rc<ReportedLiterals>,
    print: impl FnOnce() -> R,
) -> R {
    struct Restore(Option<std::rc::Rc<ReportedLiterals>>);
    impl Drop for Restore {
        fn drop(&mut self) {
            let before = self.0.take();
            PRINTING.with(|printing| *printing.borrow_mut() = before);
        }
    }
    let before = PRINTING.with(|printing| printing.borrow_mut().replace(literals.clone()));
    let _restore = Restore(before);
    print()
}

/// Whether a string the source writes at `origin` is masked where it is
/// serialized: inside [`printing`], where the text there holds a literal
/// that is not shown.
pub(crate) fn masked_in_print(origin: Option<Span>) -> bool {
    let Some(origin) = origin else {
        return false;
    };
    let masked = PRINTING.with(|printing| {
        printing
            .borrow()
            .as_ref()
            .is_some_and(|literals| literals.masks(origin))
    });
    if masked {
        MASKED_IN_PRINT.with(|any| any.set(true));
    }
    masked
}

/// Whether a name the source writes at `origin` is masked where it is
/// serialized: inside [`printing`], where its text holds a string literal
/// that is not shown ([`ReportedLiterals::masks_name`]).
pub(crate) fn name_masked_in_print(origin: Option<Span>) -> bool {
    let Some(origin) = origin else {
        return false;
    };
    let masked = PRINTING.with(|printing| {
        printing
            .borrow()
            .as_ref()
            .is_some_and(|literals| literals.masks_name(origin))
    });
    if masked {
        MASKED_IN_PRINT.with(|any| any.set(true));
    }
    masked
}

/// Whether a fact string made of text outside the statement is masked
/// where it is serialized: inside [`printing`], always.
pub(crate) fn masked_in_print_elsewhere() -> bool {
    let masked = PRINTING.with(|printing| printing.borrow().is_some());
    if masked {
        MASKED_IN_PRINT.with(|any| any.set(true));
    }
    masked
}

/// Each string of `written`, by the value that holds it, masked.
fn mask_every_string(
    written: &serde_json::Value,
    by_node: &mut std::collections::HashMap<*const serde_json::Value, String>,
) {
    use serde_json::Value;
    match written {
        Value::String(_) => {
            by_node.insert(written as *const Value, super::MASKED_VALUE.to_string());
        }
        Value::Array(items) => {
            for item in items {
                mask_every_string(item, by_node);
            }
        }
        Value::Object(fields) => {
            for field in fields.values() {
                mask_every_string(field, by_node);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// Each string of `written` whose place in `printed`, the same value with
/// strings masked, holds another string, by the value that holds it, with
/// that string.
fn differing_strings(
    written: &serde_json::Value,
    printed: &serde_json::Value,
    by_node: &mut std::collections::HashMap<*const serde_json::Value, String>,
) {
    use serde_json::Value;
    match (written, printed) {
        (Value::String(text), Value::String(masked)) => {
            if text != masked {
                by_node.insert(written as *const Value, masked.clone());
            }
        }
        (Value::Array(items), Value::Array(masked)) => {
            for (item, masked) in items.iter().zip(masked) {
                differing_strings(item, masked, by_node);
            }
        }
        (Value::Object(fields), Value::Object(masked)) => {
            for (key, field) in fields {
                match masked.get(key) {
                    Some(masked) => differing_strings(field, masked, by_node),
                    // A value the printed facts hold no more (a number
                    // masked whole) is masked.
                    None => {
                        by_node.insert(field as *const Value, super::MASKED_VALUE.to_string());
                    }
                }
            }
        }
        // A number printed as something else is masked.
        (Value::Number(_), printed) if printed != written => {
            by_node.insert(written as *const Value, super::MASKED_VALUE.to_string());
        }
        (Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_), _)
        | (Value::Array(_) | Value::Object(_), _) => {}
    }
}

#[cfg(test)]
std::thread_local! {
    /// How many masked copies of facts this thread has serialized.
    static MASKED_COPIES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// How many masked copies of facts this thread has serialized
/// ([`ReportedLiterals::quoting_strings`]).
#[cfg(test)]
pub(crate) fn masked_copies_serialized() -> usize {
    MASKED_COPIES.with(std::cell::Cell::get)
}

/// The strings of a statement's serialized facts that quote a secret, each
/// by the value that holds it ([`ReportedLiterals::quoting_strings`]), with
/// its masked text.
#[derive(Default)]
pub(crate) struct QuotingStrings {
    by_node: std::collections::HashMap<*const serde_json::Value, String>,
}

impl QuotingStrings {
    /// The masked text of `node`, a value of the serialized facts these
    /// strings were read from, where it is a string that quotes a secret.
    pub(crate) fn masked(&self, node: &serde_json::Value) -> Option<&str> {
        self.by_node
            .get(&(node as *const serde_json::Value))
            .map(String::as_str)
    }

    /// `node`, a value of the serialized facts these strings were read
    /// from, with each string under it that quotes a secret masked.
    pub(crate) fn masked_value(&self, node: &serde_json::Value) -> serde_json::Value {
        use serde_json::Value;
        if let Some(text) = self.masked(node) {
            return Value::String(text.to_string());
        }
        match node {
            Value::Array(items) => {
                Value::Array(items.iter().map(|item| self.masked_value(item)).collect())
            }
            Value::Object(fields) => Value::Object(
                fields
                    .iter()
                    .map(|(key, field)| (key.clone(), self.masked_value(field)))
                    .collect(),
            ),
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => node.clone(),
        }
    }
}
