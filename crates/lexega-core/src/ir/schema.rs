// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Per-node output schema derivation.
//!
//! Implements `RelPlan::output_schema()` — the list of [`ColumnId`]s produced
//! by a plan node, in positional order.
//!
//! **Returns `Vec<ColumnId>` only.** Full `Vec<ColumnBinding>`
//! resolution (display name + provenance + type) requires the side-table of
//! bindings that gets populated during lowering; that API can be
//! added without breaking this one.
//!
//! # Closed-enum discipline
//!
//! The match below is intentionally exhaustive with no `_ =>` arm. If a
//! new [`RelPlan`] variant is added, the compiler will force every
//! analysis that consumes schema to account for it.

use super::column::ColumnId;
use crate::ast::NodeId;
// `FilterKind` is re-exported to the in-file `#[cfg(test)]` module
// via `use super::*;`; it is unused in the lib-only build path.
#[cfg_attr(not(test), allow(unused_imports))]
use super::plan::{
    AggregateCall, CteBody, FilterKind, MergeAction, MergeBranch, PivotValues, RelPlan,
};
use super::scalar::{FieldStep, QuantifiedRhs, ScalarExpr};

impl RelPlan {
    /// Output schema of this plan node, in positional order.
    ///
    /// Allocates a fresh `Vec` per call.
    ///
    /// Semantics per variant:
    ///
    /// - **Leaf sources** (`Scan`, `Values`, `ModelRef`): the `columns`
    ///   field is the schema. **`CteRef`**: `columns` followed by the
    ///   columns demanded through the reference.
    /// - **`Project`**: one `ColumnId` per `ProjectItem::Expr` item.
    ///   `ProjectItem::Star` items contribute a catalog-dependent
    ///   schema resolved after lowering; only the explicit-item
    ///   columns are emitted here.
    /// - **`Filter`, `Sort`, `Limit`, `TableSample`**: pure pass-through of
    ///   the input's schema.
    /// - **`Aggregate`, `Window`, `SetOp`, `Pivot`, `MatchRecognize`,
    ///   `ConnectBy`**: the stored `output_columns` is the schema.
    /// - **`Join`**: `left.output_schema() ++ right.output_schema()`, then
    ///   the merged column of each `USING` entry: the join makes it. Where
    ///   the columns stand in a row is [`Self::positional_columns`]'s
    ///   answer, not this list's.
    /// - **`Unnest`**: input schema followed by `value_column`, and then
    ///   `ordinality_column` when present.
    /// - **`Unpivot`**: input schema minus the `unpivoted_columns`, followed
    ///   by `name_column` and `value_column`.
    /// - **`WithScope`**: schema of the body.
    /// - **DML roots** (`Insert`, `Update`, `Delete`, `Merge`): empty — these
    ///   are statement roots with no row output.
    /// - **`Opaque`**: empty. Downstream analyses must treat opaque subtrees
    ///   as producing no observable columns.
    pub fn output_schema(&self) -> Vec<ColumnId> {
        self.output_schema_with(&mut |_, own| own.to_vec())
    }

    /// As [`Self::output_schema`], with each source's list taken from
    /// `source_columns`, given the source's node id and the list it
    /// carries. Lowering uses it to read a source's columns before
    /// they are listed on the plan.
    pub(crate) fn output_schema_with(
        &self,
        source_columns: &mut dyn FnMut(NodeId, &[ColumnId]) -> Vec<ColumnId>,
    ) -> Vec<ColumnId> {
        match self {
            // ── Sources ─────────────────────────────────────────────────
            RelPlan::Scan {
                columns, node_id, ..
            }
            | RelPlan::Values {
                columns, node_id, ..
            }
            | RelPlan::ModelRef {
                columns, node_id, ..
            } => source_columns(*node_id, columns),
            RelPlan::CteRef {
                columns,
                demanded,
                node_id,
                ..
            } => {
                let mut out = source_columns(*node_id, columns);
                out.extend(demanded.iter().map(|d| d.column));
                out
            }

            // ── Unary ops ───────────────────────────────────────────────
            RelPlan::Project { items, .. } => items
                .iter()
                .filter_map(|it| match it {
                    // `Star` items contribute a catalog-dependent
                    // column list attached during lineage
                    // resolution; here the schema covers only the
                    // explicitly-computed items, with
                    // `star_projections` recorded separately from
                    // enumerated column refs.
                    super::plan::ProjectItem::Expr(e) => Some(e.output),
                    super::plan::ProjectItem::Star(_) => None,
                })
                .collect(),

            // What the filter computed before its predicate follows its
            // input's columns.
            RelPlan::Filter {
                input, computed, ..
            } => {
                let mut out = input.output_schema_with(source_columns);
                out.extend(computed.iter().map(|item| item.output));
                out
            }

            RelPlan::Sort { input, .. }
            | RelPlan::Limit { input, .. }
            | RelPlan::TableSample { input, .. } => input.output_schema_with(source_columns),

            RelPlan::SetOp { output_columns, .. }
            | RelPlan::MatchRecognize { output_columns, .. }
            | RelPlan::ConnectBy { output_columns, .. } => output_columns.clone(),

            // The select list above reads what the node computed
            // before its aggregates.
            RelPlan::Aggregate {
                output_columns,
                computed,
                ..
            } => {
                let mut out = output_columns.clone();
                out.extend(computed.iter().map(|item| item.output));
                out
            }

            // PIVOT semantics: the output schema is
            //   (input.output_schema()
            //     − {pivot_column}
            //     − {ColumnIds referenced as aggregate args})
            //   ++ output_columns (synthesized one-per-pivot-value).
            //
            // Treating `output_columns` alone as the schema would
            // drop pass-through cols and break CTE-binding slot
            // enumeration for SQL like
            // `WITH pvt AS (SELECT * FROM t PIVOT(...)) SELECT * FROM pvt`
            // — the binding's outward arity must include the
            // pass-through cols so downstream `pvt.col` references
            // resolve. `output_columns` keeps its narrow meaning
            // (synth value cols only).
            RelPlan::Pivot {
                input,
                pivot_column,
                aggregates,
                output_columns,
                ..
            } => {
                let mut drop: std::collections::HashSet<ColumnId> =
                    std::collections::HashSet::new();
                drop.insert(*pivot_column);
                for agg in aggregates {
                    collect_columns_from_aggregate_args(agg, &mut drop);
                }
                let mut out: Vec<ColumnId> = input
                    .output_schema_with(source_columns)
                    .into_iter()
                    .filter(|c| !drop.contains(c))
                    .collect();
                out.extend(output_columns.iter().copied());
                out
            }

            // A Window operator passes every input row through and
            // appends window-call outputs. `window_outputs` holds
            // ONLY the appended ids — the full schema is
            // `input.output_schema() ∪ window_outputs`. See the
            // schema doc on `RelPlan::Window` in `plan.rs`. What the
            // node computed before its calls follows.
            RelPlan::Window {
                input,
                window_outputs,
                computed,
                ..
            } => {
                let mut out = input.output_schema_with(source_columns);
                for c in window_outputs {
                    if !out.contains(c) {
                        out.push(*c);
                    }
                }
                out.extend(computed.iter().map(|item| item.output));
                out
            }

            // ── Binary op ───────────────────────────────────────────────
            // The merged columns come last: a side's column keeps its
            // place in the list.
            RelPlan::Join {
                left, right, using, ..
            } => {
                let mut out = left.output_schema_with(source_columns);
                out.extend(right.output_schema_with(source_columns));
                out.extend(using.iter().map(|column| column.merged));
                out
            }

            // ── Dialect-exotic unary ops with derived schema ────────────
            RelPlan::Unnest {
                input,
                value_column,
                ordinality_column,
                ..
            } => {
                let mut out = input.output_schema_with(source_columns);
                out.push(*value_column);
                if let Some(ord) = ordinality_column {
                    out.push(*ord);
                }
                out
            }

            RelPlan::Unpivot {
                input,
                value_columns,
                name_column,
                unpivoted_columns,
                ..
            } => {
                // Every source ColumnId referenced by any tuple in
                // the IN list is projected away; the rest pass through.
                let mut drop = std::collections::HashSet::new();
                for group in unpivoted_columns {
                    for c in &group.columns {
                        drop.insert(*c);
                    }
                }
                let mut out: Vec<ColumnId> = input
                    .output_schema_with(source_columns)
                    .into_iter()
                    .filter(|c| !drop.contains(c))
                    .collect();
                out.push(*name_column);
                for v in value_columns {
                    out.push(*v);
                }
                out
            }

            // ── Scope ───────────────────────────────────────────────────
            RelPlan::WithScope { body, .. } => body.output_schema_with(source_columns),

            // A derived table re-binds the inner plan's output under
            // outer-scope `columns`. Lineage analysis wires them back
            // to `input.output_schema()`; until then, surface the
            // fresh outer ids so join-column arithmetic sees a
            // consistent schema.
            RelPlan::DerivedTable {
                columns, node_id, ..
            } => source_columns(*node_id, columns),

            // A table-valued function's schema is the columns the
            // enclosing block reads from it; true arity is
            // catalog-dependent.
            RelPlan::TableFunction {
                output_columns,
                node_id,
                ..
            } => source_columns(*node_id, output_columns),

            // ── DML roots ───────────────────────────────────────────────
            RelPlan::Insert { .. }
            | RelPlan::Update { .. }
            | RelPlan::Delete { .. }
            | RelPlan::Merge { .. }
            | RelPlan::MultiInsert { .. } => Vec::new(),

            // ── EXPLAIN ────────────────────────────────────────────────
            // EXPLAIN is a plan-request wrapper; the executed body's
            // schema is not the user-visible result (the server returns
            // plan text/JSON). Model as empty so analyses don't
            // accidentally treat EXPLAIN as data-producing. The wrapped
            // body remains walkable for taint/lineage via the visitor.
            RelPlan::Explain { .. } => Vec::new(),

            // ── Create-as-query roots ───────────────────────────────────
            // CREATE VIEW / CTAS / CREATE DYNAMIC TABLE are DDL
            // statement roots: they produce a new named object
            // rather than a row-set the caller reads. The wrapped
            // `body` schema is what gets *materialized into* the new
            // object, which the visitor walks for lineage / taint.
            // Expose empty schema here so analyses don't treat the
            // DDL statement as data-producing.
            RelPlan::CreateAsQuery { .. } => Vec::new(),

            // Non-query-bearing DDL: no row output.
            RelPlan::CreateTableForm { .. } => Vec::new(),

            // ── Parser-recovery terminals ───────────────────────────────
            RelPlan::ParseRecovery { .. } => Vec::new(),
            RelPlan::Opaque { .. } => Vec::new(),
            RelPlan::InvalidInput { .. } => Vec::new(),
        }
    }

    /// Visible output slots for a CTE body.
    ///
    /// For ordinary plans this is just [`Self::output_schema()`]. For a
    /// pure `SELECT *` CTE body, the visible slots are the immediate
    /// input's schema: the `ProjectItem::Star` itself does not allocate
    /// explicit output ids, but it does re-export every visible input
    /// column in order. For an `INSERT`, `UPDATE` or `DELETE` with a
    /// `RETURNING` list they are the columns of the list's items, in
    /// order: the statement's own output schema is empty, and a binding
    /// over it hands those rows to its references.
    pub fn cte_visible_output_schema(&self) -> Vec<ColumnId> {
        self.cte_visible_output_schema_with(&mut |_, own| own.to_vec())
    }

    /// As [`Self::cte_visible_output_schema`], with each source's list
    /// taken from `source_columns` as in [`Self::output_schema_with`].
    pub(crate) fn cte_visible_output_schema_with(
        &self,
        source_columns: &mut dyn FnMut(NodeId, &[ColumnId]) -> Vec<ColumnId>,
    ) -> Vec<ColumnId> {
        // For any `SELECT *` over a Scan chain (direct or wrapped in
        // Filter / Sort / Limit / TableSample), the lowerer only knows the
        // referenced scan columns pre-catalog — not the full table width.
        // Re-exporting those as CTE output slots creates phantom surface
        // columns (e.g. a WHERE-referenced column like YEAR appearing as a
        // CTE slot even though the SELECT * didn't explicitly name it).
        // Return empty here and let catalog expansion realize the
        // full star width.
        if self.cte_body_star_passthrough_leaf_scan_node().is_some() {
            return Vec::new();
        }
        if let Some(returning) = self.returned_at_root() {
            return returning.columns();
        }
        match self.cte_body_star_passthrough_input() {
            Some(inner) => inner.output_schema_with(source_columns),
            None => self.output_schema_with(source_columns),
        }
    }
}

/// The columns of a plan by position.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ColumnPositions {
    /// The columns at the first positions, in order.
    pub known: Vec<ColumnId>,
    /// Whether the plan may hold columns after `known` that it does not
    /// place.
    pub open: bool,
}

/// What a plan says of one position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Position {
    /// The column at the position.
    Column(ColumnId),
    /// A column the plan does not know is, or may be, there.
    Unknown,
    /// The plan lists every column and has none there.
    Absent,
}

impl Position {
    /// The column, where the plan knows it.
    pub fn column(self) -> Option<ColumnId> {
        match self {
            Position::Column(column) => Some(column),
            Position::Unknown | Position::Absent => None,
        }
    }
}

impl ColumnPositions {
    /// Every column is `columns`, in order.
    fn closed(known: Vec<ColumnId>) -> Self {
        Self { known, open: false }
    }

    /// No column is placed.
    fn unknown() -> Self {
        Self {
            known: Vec::new(),
            open: true,
        }
    }

    /// What the plan says of the position `index`, from 0.
    pub fn at(&self, index: usize) -> Position {
        match self.known.get(index) {
            Some(column) => Position::Column(*column),
            None if self.open => Position::Unknown,
            None => Position::Absent,
        }
    }

    /// `more` after these columns; nothing after an open plan is placed.
    fn then(mut self, more: impl IntoIterator<Item = ColumnId>) -> Self {
        if !self.open {
            self.known.extend(more);
        }
        self
    }

    /// `after`'s columns after these.
    fn then_positions(self, after: ColumnPositions) -> Self {
        if self.open {
            return self;
        }
        let open = after.open;
        let mut joined = self.then(after.known);
        joined.open = open;
        joined
    }

    /// These columns less `dropped`, in the same order.
    fn without(mut self, dropped: &std::collections::HashSet<ColumnId>) -> Self {
        self.known.retain(|column| !dropped.contains(column));
        self
    }
}

/// The indices of `items` at known positions, in order, and whether
/// columns the items do not place may follow. A complete star is no
/// position of its own: its columns are the items before it, less the
/// ones it says are none of its columns. The first star that is not
/// complete ends the count, and the items it says it did not place are
/// dropped from it.
pub(crate) fn positioned_items(items: &[super::plan::ProjectItem]) -> (Vec<usize>, bool) {
    positioned(items.iter().map(|item| match item {
        super::plan::ProjectItem::Expr(_) => Listed::Item,
        super::plan::ProjectItem::Star(star) => Listed::Star {
            complete: star.complete,
            unplaced: star.unplaced,
        },
    }))
}

/// What an entry of a select list or of a `RETURNING` list is to the
/// positions of its list.
enum Listed {
    Item,
    Star { complete: bool, unplaced: usize },
}

/// [`positioned_items`] over the entries of any list that holds items
/// and stars.
fn positioned(entries: impl Iterator<Item = Listed>) -> (Vec<usize>, bool) {
    let mut placed = Vec::new();
    for (index, entry) in entries.enumerate() {
        match entry {
            Listed::Item => placed.push(index),
            Listed::Star { complete, unplaced } => {
                placed.truncate(placed.len().saturating_sub(unplaced));
                if !complete {
                    return (placed, true);
                }
            }
        }
    }
    (placed, false)
}

impl RelPlan {
    /// The columns of this plan by position: the ones it places, and
    /// whether it may hold more. Where it is not open they are every
    /// column of its rows: its [`Self::output_schema`], but for a `USING`
    /// join, which lists a merged column once. A `RETURNING` list is the
    /// columns of an `INSERT`, `UPDATE` or `DELETE`. A set operation is
    /// open where every one of its branches is.
    pub fn positional_columns(&self) -> ColumnPositions {
        self.positional_columns_with(&mut |_| None)
    }

    /// As [`Self::positional_columns`], with the columns of a `Scan` taken
    /// from `table`, given the scan's node id: every column of its table,
    /// in order, where `table` knows them. Lowering answers it for a table
    /// the catalog lists every column of.
    pub(crate) fn positional_columns_with(
        &self,
        table: &mut dyn FnMut(NodeId) -> Option<Vec<ColumnId>>,
    ) -> ColumnPositions {
        match self {
            RelPlan::Values { columns, .. } => ColumnPositions::closed(columns.clone()),
            // A source lists the columns read of it, in the order read; a
            // table `table` knows has every column it knows. A reference
            // does not say whether its body is open.
            RelPlan::Scan { node_id, .. } => {
                table(*node_id).map_or_else(ColumnPositions::unknown, ColumnPositions::closed)
            }
            RelPlan::ModelRef { .. } | RelPlan::TableFunction { .. } | RelPlan::CteRef { .. } => {
                ColumnPositions::unknown()
            }

            RelPlan::Project { items, .. } => {
                let (placed, open) = positioned_items(items);
                let known = placed
                    .into_iter()
                    .filter_map(|index| match &items[index] {
                        super::plan::ProjectItem::Expr(item) => Some(item.output),
                        super::plan::ProjectItem::Star(_) => None,
                    })
                    .collect();
                ColumnPositions { known, open }
            }

            RelPlan::Filter {
                input, computed, ..
            } => input
                .positional_columns_with(table)
                .then(computed.iter().map(|item| item.output)),
            RelPlan::Sort { input, .. }
            | RelPlan::Limit { input, .. }
            | RelPlan::TableSample { input, .. } => input.positional_columns_with(table),
            RelPlan::WithScope { body, .. } => body.positional_columns_with(table),

            RelPlan::SetOp {
                inputs,
                output_columns,
                ..
            } => ColumnPositions {
                known: output_columns.clone(),
                open: !inputs.is_empty()
                    && inputs
                        .iter()
                        .all(|branch| branch.positional_columns_with(table).open),
            },

            // The alias names and the body's known columns come first.
            RelPlan::DerivedTable {
                input,
                columns,
                alias_columns,
                ..
            } => {
                let body = input.positional_columns_with(table);
                let placed = alias_columns.len().max(body.known.len());
                ColumnPositions {
                    known: columns.iter().take(placed).copied().collect(),
                    open: body.open,
                }
            }

            RelPlan::Insert { returning, .. }
            | RelPlan::Update { returning, .. }
            | RelPlan::Delete { returning, .. }
            | RelPlan::Merge { returning, .. } => match returning {
                Some(returning) => returning.positional_columns(),
                None => ColumnPositions::default(),
            },

            // The block's columns, as the block places them.
            RelPlan::ConnectBy { input, .. } => input.positional_columns_with(table),
            // Every row of a match: the input's columns, then the
            // measures. One row a match: the partition keys that are
            // columns, as far as each key is one, then the measures.
            RelPlan::MatchRecognize { input, body, .. } => {
                let measures = body.measures.iter().map(|measure| measure.output);
                match body.rows_per_match {
                    super::plan::RowsPerMatch::AllRows(_) => {
                        input.positional_columns_with(table).then(measures)
                    }
                    // With neither, the node lists its input's columns
                    // in place of its own.
                    super::plan::RowsPerMatch::OneRow
                        if body.partition_by.is_empty() && body.measures.is_empty() =>
                    {
                        ColumnPositions::unknown()
                    }
                    super::plan::RowsPerMatch::OneRow => {
                        let keys: Vec<ColumnId> = body
                            .partition_by
                            .iter()
                            .map_while(|key| {
                                if let ScalarExpr::Column { column, .. } = key {
                                    Some(*column)
                                } else {
                                    None
                                }
                            })
                            .collect();
                        let open = keys.len() < body.partition_by.len();
                        ColumnPositions { known: keys, open }.then(measures)
                    }
                }
            }
            RelPlan::Aggregate {
                output_columns,
                computed,
                ..
            } => ColumnPositions::closed(output_columns.clone())
                .then(computed.iter().map(|item| item.output)),
            // The columns it passes, then one per listed value. A list
            // that names no values yields columns the plan cannot count.
            RelPlan::Pivot {
                input,
                pivot_column,
                aggregates,
                pivot_values,
                output_columns,
                ..
            } => {
                let mut dropped = std::collections::HashSet::new();
                dropped.insert(*pivot_column);
                for call in aggregates {
                    collect_columns_from_aggregate_args(call, &mut dropped);
                }
                let passed = input.positional_columns_with(table).without(&dropped);
                match pivot_values {
                    PivotValues::ValueList(_) => passed.then(output_columns.iter().copied()),
                    PivotValues::Any { .. }
                    | PivotValues::Subquery(_)
                    | PivotValues::Opaque { .. } => ColumnPositions {
                        known: passed.known,
                        open: true,
                    },
                }
            }
            RelPlan::Window {
                input,
                window_outputs,
                computed,
                ..
            } => {
                let below = input.positional_columns_with(table);
                let fresh: Vec<ColumnId> = window_outputs
                    .iter()
                    .copied()
                    .filter(|column| !below.known.contains(column))
                    .collect();
                below
                    .then(fresh)
                    .then(computed.iter().map(|item| item.output))
            }
            // A `USING` join lists its merged columns first, then what
            // is left of each side. The order of several merged columns,
            // and which columns a `NATURAL` join merges, the plan does
            // not know.
            RelPlan::Join {
                left,
                right,
                using,
                natural,
                ..
            } => match using.as_slice() {
                [] if *natural => ColumnPositions::unknown(),
                [] => left
                    .positional_columns_with(table)
                    .then_positions(right.positional_columns_with(table)),
                [column] => {
                    let sides = std::collections::HashSet::from([column.left, column.right]);
                    ColumnPositions::closed(vec![column.merged])
                        .then_positions(left.positional_columns_with(table).without(&sides))
                        .then_positions(right.positional_columns_with(table).without(&sides))
                }
                [_, _, ..] => ColumnPositions::unknown(),
            },
            RelPlan::Unnest {
                input,
                value_column,
                ordinality_column,
                ..
            } => input
                .positional_columns_with(table)
                .then([*value_column])
                .then(*ordinality_column),
            RelPlan::Unpivot {
                input,
                value_columns,
                name_column,
                unpivoted_columns,
                ..
            } => {
                let dropped = unpivoted_columns
                    .iter()
                    .flat_map(|group| group.columns.iter().copied())
                    .collect();
                input
                    .positional_columns_with(table)
                    .without(&dropped)
                    .then([*name_column])
                    .then(value_columns.iter().copied())
            }

            // These hand no positioned rows to a reader.
            RelPlan::MultiInsert { .. }
            | RelPlan::Explain { .. }
            | RelPlan::CreateAsQuery { .. }
            | RelPlan::CreateTableForm { .. } => ColumnPositions::default(),
            // Nobody knows the columns of what was not understood.
            RelPlan::ParseRecovery { .. }
            | RelPlan::Opaque { .. }
            | RelPlan::InvalidInput { .. } => ColumnPositions::unknown(),
        }
    }
}

impl super::plan::Returning {
    /// The columns of the list by position, as a select list places its
    /// items: a complete star's columns are the items before it, and the
    /// first star that is not complete ends the count.
    fn positional_columns(&self) -> ColumnPositions {
        use super::plan::ReturningItem;
        let (placed, open) = positioned(self.items.iter().map(|item| match item {
            ReturningItem::Expr { .. } => Listed::Item,
            ReturningItem::Star(star) => Listed::Star {
                complete: star.complete,
                unplaced: star.unplaced,
            },
        }));
        let known = placed
            .into_iter()
            .filter_map(|index| match &self.items[index] {
                ReturningItem::Expr { output, .. } => *output,
                ReturningItem::Star(_) => None,
            })
            .collect();
        ColumnPositions { known, open }
    }
}

// ────────────────────────────────────────────────────────────────────────
// Pivot pass-through helpers.
// ────────────────────────────────────────────────────────────────────────

/// Collect every [`ColumnId`] referenced (as `ScalarExpr::Column`) by
/// the positional and named arguments of an aggregate call. Used by
/// PIVOT to determine which input columns are *consumed* by the
/// aggregate (and therefore dropped from the pass-through output
/// schema). FILTER / ORDER BY / WITHIN GROUP refs are intentionally
/// not collected — those don't make a column "consumed", they only
/// influence the aggregate value, and dropping them from pass-through
/// would break SQL like
/// `PIVOT(sum(amt) FILTER (WHERE flag) FOR k IN (...))` where `flag`
/// must remain visible at the binding boundary.
pub fn collect_columns_from_aggregate_args(
    call: &AggregateCall,
    out: &mut std::collections::HashSet<ColumnId>,
) {
    for arg in &call.args {
        collect_columns_from_scalar(arg, out);
    }
    for (_, arg) in &call.named_args {
        collect_columns_from_scalar(arg, out);
    }
}

/// Recursive walk over [`ScalarExpr`] collecting every `Column`
/// reference. Exhaustive per closed-enum discipline.
fn collect_columns_from_scalar(expr: &ScalarExpr, out: &mut std::collections::HashSet<ColumnId>) {
    match expr {
        ScalarExpr::Column { column, .. } | ScalarExpr::PatternVarRef { column, .. } => {
            out.insert(*column);
        }
        // OuterRef / Lit / Opaque carry no in-scope ColumnId
        // referencing the current FROM tree. (OuterRef references
        // an outer scope's id; for PIVOT pass-through purposes the
        // current scope's column set is what matters.)
        ScalarExpr::OuterRef { .. } | ScalarExpr::Lit { .. } | ScalarExpr::Opaque { .. } => {}
        ScalarExpr::BinOp { left, right, .. } => {
            collect_columns_from_scalar(left, out);
            collect_columns_from_scalar(right, out);
        }
        ScalarExpr::LogicalChain { operands, .. } | ScalarExpr::OperatorChain { operands, .. } => {
            for operand in operands {
                collect_columns_from_scalar(operand, out);
            }
        }
        ScalarExpr::Like {
            expr,
            pattern,
            escape,
            ..
        } => {
            collect_columns_from_scalar(expr, out);
            collect_columns_from_scalar(pattern, out);
            if let Some(e) = escape {
                collect_columns_from_scalar(e, out);
            }
        }
        ScalarExpr::UnaryOp { arg, .. } => collect_columns_from_scalar(arg, out),
        ScalarExpr::FuncCall {
            args, named_args, ..
        } => {
            for a in args {
                collect_columns_from_scalar(a, out);
            }
            for (_, a) in named_args {
                collect_columns_from_scalar(a, out);
            }
        }
        ScalarExpr::Case {
            operand,
            branches,
            else_,
            ..
        } => {
            if let Some(o) = operand {
                collect_columns_from_scalar(o, out);
            }
            for (when, then) in branches {
                collect_columns_from_scalar(when, out);
                collect_columns_from_scalar(then, out);
            }
            if let Some(e) = else_ {
                collect_columns_from_scalar(e, out);
            }
        }
        ScalarExpr::Cast { expr, .. } => collect_columns_from_scalar(expr, out),
        ScalarExpr::InList { expr, list, .. } => {
            collect_columns_from_scalar(expr, out);
            for v in list {
                collect_columns_from_scalar(v, out);
            }
        }
        ScalarExpr::Between {
            expr, low, high, ..
        } => {
            collect_columns_from_scalar(expr, out);
            collect_columns_from_scalar(low, out);
            collect_columns_from_scalar(high, out);
        }
        // Subqueries: their inner-scope refs do not contribute to
        // the outer FROM column set; correlated outer refs land via
        // OuterRef which is handled by the dedicated arm above.
        ScalarExpr::Exists { .. } | ScalarExpr::ScalarSubquery { .. } => {}
        ScalarExpr::QuantifiedCmp { left, right, .. } => {
            collect_columns_from_scalar(left, out);
            match right {
                QuantifiedRhs::List(list) => {
                    for v in list {
                        collect_columns_from_scalar(v, out);
                    }
                }
                QuantifiedRhs::Subquery(_, _) => {}
            }
        }
        ScalarExpr::RowCmp { left, .. } => {
            for e in left {
                collect_columns_from_scalar(e, out);
            }
        }
        ScalarExpr::WindowFn { call, .. } => {
            for a in &call.args {
                collect_columns_from_scalar(a, out);
            }
            for p in &call.partition_by {
                collect_columns_from_scalar(p, out);
            }
            for k in &call.order_by {
                collect_columns_from_scalar(&k.expr, out);
            }
        }
        ScalarExpr::FieldAccess { base, path, .. } => {
            collect_columns_from_scalar(base, out);
            for step in path {
                if let FieldStep::IndexExpr(e) = step {
                    collect_columns_from_scalar(e, out);
                }
            }
        }
        // Lambda body refs the lambda's own bound params, which
        // are not in the outer scope.
        ScalarExpr::Lambda { .. } => {}
    }
}

// ────────────────────────────────────────────────────────────────────────
// Compile-time cross-check: every `CteBody` / `MergeBranch` / `MergeAction`
// variant is referenced here so touching those enums surfaces in this file
// during review, even though their schema contribution is indirect.
// ────────────────────────────────────────────────────────────────────────

#[allow(dead_code)] // Exhaustiveness guard only — never called.
fn _cte_body_exhaustive(body: &CteBody) {
    match body {
        CteBody::NonRecursive(_) | CteBody::Recursive { .. } => {}
    }
}

#[allow(dead_code)]
fn _merge_branch_exhaustive(branch: &MergeBranch) {
    match &branch.action {
        MergeAction::Insert { .. }
        | MergeAction::InsertStar { .. }
        | MergeAction::InsertAllByName { .. }
        | MergeAction::Update { .. }
        | MergeAction::UpdateSetStar { .. }
        | MergeAction::UpdateAllByName { .. }
        | MergeAction::Delete
        | MergeAction::DoNothing => {}
    }
}

// ────────────────────────────────────────────────────────────────────────
// Unit tests — hand-constructed plans, one per variant family.
// ────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::NodeId;
    use crate::context::node_metadata::{IdentKey, TableRef};
    use crate::ir::column::ColumnIdAllocator;
    use crate::ir::invalid_input::InvalidInputKind;
    use crate::ir::plan::{
        AfterMatchSkip, AggregateCall, AllRowsMode, AssignedValue, Assignment, CteBinding, CteBody,
        FrameBound, FrameExclusion, FrameMode, GroupingSpec, JoinKind, MatchRecognizeBody,
        MatchRecognizeMeasure, MergeAction, MergeBranch, MergeBranchKind, NullTreatment,
        PatternExpr, PivotValues, ProjectExpr, ProjectItem, ResolvedFunc, ResolvedModel,
        RowsPerMatch, SampleKeyword, SampleSize, ScanModifier, SetOpKind, SortKey, SymbolTable,
        TableSample, UnpivotColumn, UsingColumn, WindowCall, WindowFrame,
    };
    use crate::ir::scalar::{Lit, ScalarExpr, ScopeId};
    use crate::ir::strict::{GroupByOrdinalCategory, OpaqueReason};
    use crate::lexer::Span;

    fn sp() -> Span {
        Span { start: 0, end: 0 }
    }

    fn nid() -> NodeId {
        NodeId::new(0)
    }

    fn ident(s: &str) -> IdentKey {
        IdentKey::new(s)
    }

    fn tref(name: &str) -> TableRef {
        TableRef::new(name.to_string())
    }

    fn lit_int(n: i64) -> ScalarExpr {
        ScalarExpr::Lit {
            value: Lit::Integer(n.to_string()),
            span: sp(),
        }
    }

    fn scan(alloc: &mut ColumnIdAllocator, name: &str, ncols: usize) -> RelPlan {
        let columns: Vec<ColumnId> = (0..ncols).map(|_| alloc.fresh_test()).collect();
        RelPlan::Scan {
            table: tref(name),
            columns,
            modifier: ScanModifier::default(),
            alias: None,
            node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        }
    }

    #[test]
    fn scan_schema_equals_columns_field() {
        let mut alloc = ColumnIdAllocator::new();
        let s = scan(&mut alloc, "t", 3);
        let schema = s.output_schema();
        assert_eq!(schema.len(), 3);
        // Distinct, monotonically allocated.
        assert_eq!(schema[0].as_u32(), 0);
        assert_eq!(schema[2].as_u32(), 2);
    }

    #[test]
    fn values_schema_equals_columns_field() {
        let mut alloc = ColumnIdAllocator::new();
        let cols = vec![alloc.fresh_test(), alloc.fresh_test()];
        let plan = RelPlan::Values {
            rows: vec![vec![lit_int(1), lit_int(2)]],
            columns: cols.clone(),
            alias: None,
            node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        };
        assert_eq!(plan.output_schema(), cols);
    }

    #[test]
    fn cte_ref_and_model_ref_schemas_are_their_columns() {
        let _folding = crate::ir::normalize::default_folding();
        let mut alloc = ColumnIdAllocator::new();
        let cte_cols = vec![alloc.fresh_test()];
        let cte = RelPlan::CteRef {
            name: ident("c"),
            scope: ScopeId(0),
            columns: cte_cols.clone(),
            demanded: Vec::new(),
            alias: None,
            node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        };
        assert_eq!(cte.output_schema(), cte_cols);

        let m_cols = vec![alloc.fresh_test(), alloc.fresh_test()];
        let model = RelPlan::ModelRef {
            model: ResolvedModel {
                package: None,
                name: "m".into(),
                base_tables: Vec::new(),
                taint_labels: std::collections::HashMap::new(),
                nullable_columns: std::collections::HashSet::new(),
                constraint_set: Default::default(),
                column_lineage: None,
                has_filter: false,
                node_id: nid(),
            },
            columns: m_cols.clone(),
            alias: None,
            node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        };
        assert_eq!(model.output_schema(), m_cols);
    }

    #[test]
    fn project_schema_reflects_items() {
        let mut alloc = ColumnIdAllocator::new();
        let s = scan(&mut alloc, "t", 2);
        let p1 = alloc.fresh_test();
        let p2 = alloc.fresh_test();
        let plan = RelPlan::Project {
            input: Box::new(s),
            items: vec![
                ProjectItem::Expr(ProjectExpr {
                    output: p1,
                    expr: lit_int(1),
                    alias: None,
                    span: sp(),
                }),
                ProjectItem::Expr(ProjectExpr {
                    output: p2,
                    expr: lit_int(2),
                    alias: None,
                    span: sp(),
                }),
            ],
            distinct: false,
            distinct_on: Vec::new(),
            node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        };
        assert_eq!(plan.output_schema(), vec![p1, p2]);
    }

    #[test]
    fn filter_sort_limit_pass_through_input_schema() {
        let mut alloc = ColumnIdAllocator::new();
        let s = scan(&mut alloc, "t", 2);
        let expected = s.output_schema();

        let f = RelPlan::Filter {
            computed: Vec::new(),
            input: Box::new(s.clone()),
            predicate: lit_int(1),
            kind: FilterKind::Where,
            node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        };
        assert_eq!(f.output_schema(), expected);

        let sort = RelPlan::Sort {
            input: Box::new(s.clone()),
            keys: vec![SortKey {
                expr: lit_int(1),
                ascending: true,
                nulls_first: None,
                span: sp(),
            }],
            node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        };
        assert_eq!(sort.output_schema(), expected);

        let lim = RelPlan::Limit {
            input: Box::new(s.clone()),
            limit: Some(lit_int(10)),
            offset: None,
            kind: crate::ir::plan::LimitKind::Rows,
            with_ties: false,
            node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        };
        assert_eq!(lim.output_schema(), expected);

        let samp = RelPlan::TableSample {
            input: Box::new(s),
            sample: TableSample {
                method_keyword: Some(SampleKeyword::Bernoulli),
                size: SampleSize::Probability(lit_int(10)),
                seed: None,
                repeatable: None,
                span: sp(),
            },
            node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        };
        assert_eq!(samp.output_schema(), expected);
    }

    #[test]
    fn aggregate_window_setop_pivot_use_output_columns_field() {
        let mut alloc = ColumnIdAllocator::new();
        let s = scan(&mut alloc, "t", 2);
        let key_out = alloc.fresh_test();
        let agg_out = alloc.fresh_test();

        let agg = RelPlan::Aggregate {
            input: Box::new(s.clone()),
            grouping: GroupingSpec::None,
            aggregates: vec![AggregateCall {
                func: ResolvedFunc::unresolved("COUNT", None, sp()),
                args: vec![],
                named_args: vec![],
                distinct: false,
                approximate: false,
                filter: None,
                arg_order: vec![],
                within_group_order: vec![],
                null_treatment: NullTreatment::Default,
                output: agg_out,
                span: sp(),
            }],
            having: None,
            output_columns: vec![key_out, agg_out],
            computed: Vec::new(),
            node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        };
        assert_eq!(agg.output_schema(), vec![key_out, agg_out]);

        let win_out = alloc.fresh_test();
        let win = RelPlan::Window {
            input: Box::new(s.clone()),
            windows: vec![WindowCall {
                func: ResolvedFunc::unresolved("ROW_NUMBER", None, sp()),
                args: vec![],
                distinct: false,
                null_treatment: NullTreatment::Default,
                partition_by: vec![],
                order_by: vec![],
                frame: Some(WindowFrame {
                    mode: FrameMode::Rows,
                    start: FrameBound::UnboundedPreceding,
                    end: FrameBound::CurrentRow,
                    exclusion: FrameExclusion::NoOthers,
                }),
                named_window: None,
                output: win_out,
                span: sp(),
            }],
            window_outputs: vec![win_out],
            computed: Vec::new(),
            node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        };
        // Window's schema is `input.output_schema() \u222a window_outputs`
        // \u2014 every input row passes through and the window-call output
        // is appended.
        let mut expected_win = s.output_schema();
        expected_win.push(win_out);
        assert_eq!(win.output_schema(), expected_win);

        let u1 = alloc.fresh_test();
        let set_out = vec![alloc.fresh_test(), alloc.fresh_test()];
        let set = RelPlan::SetOp {
            op: SetOpKind::UnionAll,
            inputs: vec![
                Box::new(scan(&mut alloc, "a", 2)),
                Box::new(scan(&mut alloc, "b", 2)),
            ],
            corresponding: None,
            output_columns: set_out.clone(),
            node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        };
        assert_eq!(set.output_schema(), set_out);
        let _ = u1;

        let piv_out = vec![alloc.fresh_test(), alloc.fresh_test()];
        let piv = RelPlan::Pivot {
            input: Box::new(s.clone()),
            aggregates: vec![AggregateCall {
                func: ResolvedFunc::unresolved("SUM", None, sp()),
                args: vec![],
                named_args: vec![],
                distinct: false,
                approximate: false,
                filter: None,
                arg_order: vec![],
                within_group_order: vec![],
                null_treatment: NullTreatment::Default,
                output: alloc.fresh_test(),
                span: sp(),
            }],
            pivot_column: alloc.fresh_test(),
            pivot_values: PivotValues::ValueList(vec![lit_int(1), lit_int(2)]),
            output_columns: piv_out.clone(),
            default_on_null: None,
            node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        };
        // PIVOT output_schema = (input.output_schema − {pivot_column,
        // aggregate-arg cols}) ++ output_columns. Here `s` is a 2-col
        // Scan and the SUM call has no args (degenerate test shape),
        // so all input cols pass through and `pivot_column` is not
        // in the input schema (allocated separately above);
        // schema = [s.col0, s.col1, piv_out[0], piv_out[1]].
        let mut expected_piv = s.output_schema();
        expected_piv.extend(piv_out.iter().copied());
        assert_eq!(piv.output_schema(), expected_piv);

        let mr_out = vec![alloc.fresh_test()];
        let mr = RelPlan::MatchRecognize {
            input: Box::new(s.clone()),
            body: MatchRecognizeBody {
                partition_by: vec![],
                order_by: vec![],
                measures: vec![],
                rows_per_match: RowsPerMatch::OneRow,
                after_match_skip: AfterMatchSkip::PastLastRow,
                pattern: PatternExpr::Empty,
                define: vec![],
                symbols: SymbolTable::default(),
                raw_span: sp(),
            },
            output_columns: mr_out.clone(),
            node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        };
        assert_eq!(mr.output_schema(), mr_out);

        let cb_out = vec![alloc.fresh_test(), alloc.fresh_test()];
        let cb = RelPlan::ConnectBy {
            input: Box::new(s),
            start_with: None,
            connect: lit_int(1),
            nocycle: false,
            output_columns: cb_out.clone(),
            pseudo_columns: Vec::new(),
            node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        };
        assert_eq!(cb.output_schema(), cb_out);
    }

    #[test]
    fn join_schema_concatenates_branches() {
        let mut alloc = ColumnIdAllocator::new();
        let l = scan(&mut alloc, "l", 2);
        let r = scan(&mut alloc, "r", 3);
        let mut expected = l.output_schema();
        expected.extend(r.output_schema());

        let j = RelPlan::Join {
            left: Box::new(l),
            right: Box::new(r),
            kind: JoinKind::Inner,
            on: Some(lit_int(1)),
            match_condition: None,
            using: vec![],
            natural: false,
            directed: false,
            lateral: false,
            implicit: false,
            node_id: nid(),
            span: sp(),
            clause_span: sp(),
            hints: Vec::new(),
        };
        assert_eq!(j.output_schema(), expected);
    }

    #[test]
    fn unnest_schema_appends_value_and_optional_ordinality() {
        let mut alloc = ColumnIdAllocator::new();
        let s = scan(&mut alloc, "t", 1);
        let v = alloc.fresh_test();

        let un = RelPlan::Unnest {
            input: Box::new(s.clone()),
            array: lit_int(1),
            value_column: v,
            ordinality_column: None,
            with_offset: false,
            preserve_nulls: false,
            node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        };
        let mut expected = s.output_schema();
        expected.push(v);
        assert_eq!(un.output_schema(), expected);

        let ord = alloc.fresh_test();
        let un2 = RelPlan::Unnest {
            input: Box::new(s.clone()),
            array: lit_int(1),
            value_column: v,
            ordinality_column: Some(ord),
            with_offset: true,
            preserve_nulls: false,
            node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        };
        let mut expected2 = s.output_schema();
        expected2.push(v);
        expected2.push(ord);
        assert_eq!(un2.output_schema(), expected2);
    }

    #[test]
    fn unpivot_schema_removes_sources_and_appends_name_value() {
        let mut alloc = ColumnIdAllocator::new();
        // scan with 3 columns: [c0, c1, c2]
        let s = scan(&mut alloc, "t", 3);
        let in_cols = s.output_schema();
        let (c0, c1, c2) = (in_cols[0], in_cols[1], in_cols[2]);
        let name_col = alloc.fresh_test();
        let value_col = alloc.fresh_test();

        let up = RelPlan::Unpivot {
            input: Box::new(s),
            value_columns: vec![value_col],
            name_column: name_col,
            unpivoted_columns: vec![
                UnpivotColumn {
                    columns: vec![c1],
                    alias: None,
                    span: sp(),
                },
                UnpivotColumn {
                    columns: vec![c2],
                    alias: None,
                    span: sp(),
                },
            ],
            include_nulls: false,
            node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        };
        assert_eq!(up.output_schema(), vec![c0, name_col, value_col]);
    }

    #[test]
    fn with_scope_schema_delegates_to_body() {
        let _folding = crate::ir::normalize::default_folding();
        let mut alloc = ColumnIdAllocator::new();
        let body_scan = scan(&mut alloc, "t", 2);
        let expected = body_scan.output_schema();

        let cte_body_scan = scan(&mut alloc, "s", 1);
        let cte_cols = cte_body_scan.output_schema();
        let ws = RelPlan::WithScope {
            ctes: vec![CteBinding {
                name: ident("c"),
                scope: ScopeId(1),
                declared_columns: None,
                body: CteBody::NonRecursive(Box::new(cte_body_scan)),
                slot_columns: cte_cols.iter().copied().map(Some).collect(),
                output_columns: cte_cols,
                node_id: nid(),
                span: sp(),
            }],
            body: Box::new(body_scan),
            recursive: false,
            node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        };
        assert_eq!(ws.output_schema(), expected);
    }

    #[test]
    fn cte_visible_output_schema_realizes_star_over_pivot_surface() {
        let mut alloc = ColumnIdAllocator::new();
        let scan = scan(&mut alloc, "agg", 4);
        let input_cols = scan.output_schema();
        let col_parity = input_cols[0];
        let col_bucket = input_cols[1];
        let col_total = input_cols[2];
        let col_avg = input_cols[3];
        let piv_out = vec![alloc.fresh_test(), alloc.fresh_test()];

        let pivot = RelPlan::Pivot {
            input: Box::new(scan),
            aggregates: vec![AggregateCall {
                func: ResolvedFunc::unresolved("SUM", None, sp()),
                args: vec![ScalarExpr::Column {
                    column: col_total,
                    span: sp(),
                }],
                named_args: vec![],
                distinct: false,
                approximate: false,
                filter: None,
                arg_order: vec![],
                within_group_order: vec![],
                null_treatment: NullTreatment::Default,
                output: alloc.fresh_test(),
                span: sp(),
            }],
            pivot_column: col_bucket,
            pivot_values: PivotValues::ValueList(vec![lit_int(1), lit_int(2)]),
            output_columns: piv_out.clone(),
            default_on_null: None,
            node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        };

        let project = RelPlan::Project {
            input: Box::new(pivot),
            items: vec![ProjectItem::Star(crate::ir::plan::ProjectStar {
                qualifier: crate::ir::plan::StarQualifier::Unqualified,
                exclude: vec![],
                replace: vec![],
                rename: vec![],
                ilike: None,
                top_level_pure: true,
                enumerated: Vec::new(),
                itemized: Vec::new(),
                complete: false,
                unplaced: 0,
                span: sp(),
            })],
            distinct: false,
            distinct_on: Vec::new(),
            node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        };

        assert_eq!(
            project.cte_visible_output_schema(),
            vec![col_parity, col_avg, piv_out[0], piv_out[1]]
        );
    }

    #[test]
    fn cte_visible_output_schema_keeps_star_over_scan_unresolved() {
        let mut alloc = ColumnIdAllocator::new();
        let scan = scan(&mut alloc, "events", 1);
        let project = RelPlan::Project {
            input: Box::new(scan),
            items: vec![ProjectItem::Star(crate::ir::plan::ProjectStar {
                qualifier: crate::ir::plan::StarQualifier::Unqualified,
                exclude: vec![],
                replace: vec![],
                rename: vec![],
                ilike: None,
                top_level_pure: true,
                enumerated: Vec::new(),
                itemized: Vec::new(),
                complete: false,
                unplaced: 0,
                span: sp(),
            })],
            distinct: false,
            distinct_on: Vec::new(),
            node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        };

        // Star over a bare Scan is unresolved pre-catalog; do not expose
        // partial scan column knowledge as concrete CTE slots.
        assert!(project.output_schema().is_empty());
        assert!(project.cte_visible_output_schema().is_empty());
    }

    #[test]
    fn dml_roots_have_empty_schema() {
        let mut alloc = ColumnIdAllocator::new();
        let src = scan(&mut alloc, "src", 2);

        let ins = RelPlan::Insert {
            target: tref("tgt"),
            target_node: nid(),
            target_read_columns: Vec::new(),
            target_columns: vec![alloc.fresh_test(), alloc.fresh_test()],
            unplaced_columns: Vec::new(),
            defaulted_columns: Vec::new(),
            source: crate::ir::plan::InsertSource::Query(Box::new(src.clone())),
            on_conflict: None,
            overwrite: None,
            replace_into: false,
            overriding: None,
            returning: None,
            returned_merges: Vec::new(),
            output: None,
            target_hints: Vec::new(),
            node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        };
        assert!(ins.output_schema().is_empty());

        let upd = RelPlan::Update {
            target: tref("tgt"),
            target_node: nid(),
            target_read_columns: Vec::new(),
            only: None,
            assignments: vec![Assignment {
                written_node: nid(),
                columns: vec![alloc.fresh_test()],
                value: AssignedValue::Row(vec![lit_int(1)]),
            }],
            from: None,
            target_row: None,
            predicate: None,
            top: None,
            returning: None,
            output: None,
            node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        };
        assert!(upd.output_schema().is_empty());

        let del = RelPlan::Delete {
            target: tref("tgt"),
            target_node: nid(),
            target_read_columns: Vec::new(),
            using: None,
            target_row: None,
            deleted_sources: Vec::new(),
            predicate: None,
            top: None,
            returning: None,
            output: None,
            node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        };
        assert!(del.output_schema().is_empty());

        let mg = RelPlan::Merge {
            target: tref("tgt"),
            target_node: nid(),
            target_read_columns: Vec::new(),
            only: None,
            source: Box::new(src),
            on: lit_int(1),
            branches: vec![MergeBranch {
                kind: MergeBranchKind::WhenMatched,
                predicate: None,
                action: MergeAction::Delete,
                span: sp(),
            }],
            with_schema_evolution: false,
            output: None,
            returning: None,
            returned_merges: Vec::new(),
            node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        };
        assert!(mg.output_schema().is_empty());
        // A statement that returns no rows has no column at any position.
        for root in [ins, upd, del, mg] {
            assert_eq!(root.positional_columns().at(0), Position::Absent);
        }
    }

    #[test]
    fn opaque_has_empty_schema() {
        let o = RelPlan::Opaque {
            stmt_node_id: nid(),
            reason: OpaqueReason::NonSelectTopLevel,
            span: sp(),
            hints: Vec::new(),
        };
        assert!(o.output_schema().is_empty());
    }

    // The tests below call `positional_columns` on a node built by hand:
    // lowering puts a `Project` over each of these, so no statement
    // reaches their arm as a root.

    /// An input that places each of its `ncols` columns.
    fn placing(alloc: &mut ColumnIdAllocator, ncols: usize) -> RelPlan {
        RelPlan::Values {
            rows: vec![(0..ncols).map(|_| lit_int(1)).collect()],
            columns: (0..ncols).map(|_| alloc.fresh_test()).collect(),
            alias: None,
            node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        }
    }

    fn known(columns: &[ColumnId]) -> ColumnPositions {
        ColumnPositions {
            known: columns.to_vec(),
            open: false,
        }
    }

    fn open_after(columns: &[ColumnId]) -> ColumnPositions {
        ColumnPositions {
            known: columns.to_vec(),
            open: true,
        }
    }

    fn join(left: RelPlan, right: RelPlan, using: Vec<UsingColumn>, natural: bool) -> RelPlan {
        RelPlan::Join {
            left: Box::new(left),
            right: Box::new(right),
            kind: JoinKind::Inner,
            on: None,
            match_condition: None,
            using,
            natural,
            directed: false,
            lateral: false,
            implicit: false,
            node_id: nid(),
            span: sp(),
            clause_span: sp(),
            hints: Vec::new(),
        }
    }

    fn count_call(output: ColumnId) -> AggregateCall {
        AggregateCall {
            func: ResolvedFunc::unresolved("COUNT", None, sp()),
            args: vec![],
            named_args: vec![],
            distinct: false,
            approximate: false,
            filter: None,
            arg_order: vec![],
            within_group_order: vec![],
            null_treatment: NullTreatment::Default,
            output,
            span: sp(),
        }
    }

    fn column(column: ColumnId) -> ScalarExpr {
        ScalarExpr::Column { column, span: sp() }
    }

    #[test]
    fn a_source_that_is_no_values_places_no_column() {
        let _folding = crate::ir::normalize::default_folding();
        let mut alloc = ColumnIdAllocator::new();
        let reference = RelPlan::CteRef {
            name: ident("c"),
            scope: ScopeId(0),
            columns: vec![alloc.fresh_test()],
            demanded: Vec::new(),
            alias: None,
            node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        };
        let model = RelPlan::ModelRef {
            model: ResolvedModel {
                package: None,
                name: "m".into(),
                base_tables: Vec::new(),
                taint_labels: std::collections::HashMap::new(),
                nullable_columns: std::collections::HashSet::new(),
                constraint_set: Default::default(),
                column_lineage: None,
                has_filter: false,
                node_id: nid(),
            },
            columns: vec![alloc.fresh_test()],
            alias: None,
            node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        };
        let function = RelPlan::TableFunction {
            call: lit_int(1),
            alias: None,
            output_columns: vec![alloc.fresh_test()],
            lateral: false,
            modifier: ScanModifier::default(),
            node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        };
        for source in [reference, model, function, scan(&mut alloc, "t", 2)] {
            // A reference does not say whether its body places its
            // columns: a reader of it is told nothing, not "no column".
            assert_eq!(source.positional_columns(), open_after(&[]), "{source:?}");
            assert_eq!(source.positional_columns().at(0), Position::Unknown);
        }
        let values = placing(&mut alloc, 2);
        assert_eq!(values.positional_columns(), known(&values.output_schema()));
        assert_eq!(values.positional_columns().at(2), Position::Absent);
    }

    #[test]
    fn a_join_places_its_left_side_and_then_its_right() {
        let mut alloc = ColumnIdAllocator::new();
        let (l, r) = (placing(&mut alloc, 2), placing(&mut alloc, 2));
        let (lc, rc) = (l.output_schema(), r.output_schema());
        let both = [lc.clone(), rc.clone()].concat();
        let plain = join(l.clone(), r.clone(), vec![], false);
        assert_eq!(plain.positional_columns(), known(&both));
        // Nothing after an open side is placed.
        let open_left = join(scan(&mut alloc, "t", 1), r.clone(), vec![], false);
        assert_eq!(open_left.positional_columns(), open_after(&[]));
        let open_right = join(l.clone(), scan(&mut alloc, "t", 1), vec![], false);
        assert_eq!(open_right.positional_columns(), open_after(&lc));
        // One `USING` column: the merged column, then the rest of each side.
        let merged = alloc.fresh_test();
        let using = vec![UsingColumn {
            merged,
            left: lc[1],
            right: rc[0],
        }];
        let one = join(l.clone(), r.clone(), using.clone(), false);
        assert_eq!(one.positional_columns(), known(&[merged, lc[0], rc[1]]));
        // The join lists the column it makes, after its sides' columns.
        assert_eq!(
            one.output_schema(),
            vec![lc[0], lc[1], rc[0], rc[1], merged]
        );
        // Several, or a `NATURAL` join: the plan does not know the order.
        let second = UsingColumn {
            merged: alloc.fresh_test(),
            left: lc[0],
            right: rc[1],
        };
        let two = join(l.clone(), r.clone(), vec![using[0], second], false);
        assert_eq!(two.positional_columns(), open_after(&[]));
        let natural = join(l, r, vec![], true);
        assert_eq!(natural.positional_columns(), open_after(&[]));
    }

    #[test]
    fn an_aggregate_places_its_own_columns_whatever_its_input() {
        let mut alloc = ColumnIdAllocator::new();
        for input in [placing(&mut alloc, 2), scan(&mut alloc, "t", 2)] {
            let (key, counted) = (alloc.fresh_test(), alloc.fresh_test());
            let aggregate = RelPlan::Aggregate {
                input: Box::new(input),
                grouping: GroupingSpec::None,
                aggregates: vec![count_call(counted)],
                having: None,
                output_columns: vec![key, counted],
                computed: Vec::new(),
                node_id: nid(),
                span: sp(),
                hints: Vec::new(),
            };
            assert_eq!(aggregate.positional_columns(), known(&[key, counted]));
        }
    }

    fn window_over(input: RelPlan, output: ColumnId) -> RelPlan {
        RelPlan::Window {
            input: Box::new(input),
            windows: vec![WindowCall {
                func: ResolvedFunc::unresolved("ROW_NUMBER", None, sp()),
                args: vec![],
                distinct: false,
                null_treatment: NullTreatment::Default,
                partition_by: vec![],
                order_by: vec![],
                frame: Some(WindowFrame {
                    mode: FrameMode::Rows,
                    start: FrameBound::UnboundedPreceding,
                    end: FrameBound::CurrentRow,
                    exclusion: FrameExclusion::NoOthers,
                }),
                named_window: None,
                output,
                span: sp(),
            }],
            window_outputs: vec![output],
            computed: Vec::new(),
            node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        }
    }

    #[test]
    fn a_window_and_an_unnest_place_their_columns_after_their_inputs() {
        let mut alloc = ColumnIdAllocator::new();
        let closed = placing(&mut alloc, 2);
        let below = closed.output_schema();
        let (ranked, value, ordinal) = (alloc.fresh_test(), alloc.fresh_test(), alloc.fresh_test());
        let window = window_over(closed.clone(), ranked);
        assert_eq!(
            window.positional_columns(),
            known(&[below[0], below[1], ranked])
        );
        let window = window_over(scan(&mut alloc, "t", 2), ranked);
        assert_eq!(window.positional_columns(), open_after(&[]));

        let unnest = |input: RelPlan| RelPlan::Unnest {
            input: Box::new(input),
            array: lit_int(1),
            value_column: value,
            ordinality_column: Some(ordinal),
            with_offset: true,
            preserve_nulls: false,
            node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        };
        assert_eq!(
            unnest(closed).positional_columns(),
            known(&[below[0], below[1], value, ordinal])
        );
        let open = unnest(scan(&mut alloc, "t", 2));
        assert_eq!(open.positional_columns(), open_after(&[]));
    }

    #[test]
    fn a_pivot_and_an_unpivot_place_what_they_keep_of_their_inputs_first() {
        let mut alloc = ColumnIdAllocator::new();
        let closed = placing(&mut alloc, 3);
        let below = closed.output_schema();
        let values = vec![alloc.fresh_test(), alloc.fresh_test()];
        let summed = alloc.fresh_test();
        let pivot = |input: RelPlan| RelPlan::Pivot {
            input: Box::new(input),
            aggregates: vec![count_call(summed)],
            pivot_column: below[1],
            pivot_values: PivotValues::ValueList(vec![lit_int(1), lit_int(2)]),
            output_columns: values.clone(),
            default_on_null: None,
            node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        };
        assert_eq!(
            pivot(closed.clone()).positional_columns(),
            known(&[below[0], below[2], values[0], values[1]])
        );
        let open = pivot(scan(&mut alloc, "t", 2));
        assert_eq!(open.positional_columns(), open_after(&[]));

        let (name, value) = (alloc.fresh_test(), alloc.fresh_test());
        let unpivot = |input: RelPlan| RelPlan::Unpivot {
            input: Box::new(input),
            value_columns: vec![value],
            name_column: name,
            unpivoted_columns: vec![UnpivotColumn {
                columns: vec![below[1]],
                alias: None,
                span: sp(),
            }],
            include_nulls: false,
            node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        };
        assert_eq!(
            unpivot(closed).positional_columns(),
            known(&[below[0], below[2], name, value])
        );
        let open = unpivot(scan(&mut alloc, "t", 2));
        assert_eq!(open.positional_columns(), open_after(&[]));
    }

    fn match_recognize(
        input: RelPlan,
        partition_by: Vec<ScalarExpr>,
        measures: &[ColumnId],
        rows_per_match: RowsPerMatch,
    ) -> RelPlan {
        // What lowering lists: the input's columns or the keys that are
        // columns, then the measures.
        let mut output_columns = match rows_per_match {
            RowsPerMatch::AllRows(_) => input.output_schema(),
            RowsPerMatch::OneRow => partition_by
                .iter()
                .filter_map(|key| {
                    if let ScalarExpr::Column { column, .. } = key {
                        Some(*column)
                    } else {
                        None
                    }
                })
                .collect(),
        };
        output_columns.extend(measures);
        RelPlan::MatchRecognize {
            input: Box::new(input),
            body: MatchRecognizeBody {
                partition_by,
                order_by: vec![],
                measures: measures
                    .iter()
                    .map(|output| MatchRecognizeMeasure {
                        output: *output,
                        modifier: None,
                        expr: lit_int(1),
                        alias: ident("m"),
                        span: sp(),
                    })
                    .collect(),
                rows_per_match,
                after_match_skip: AfterMatchSkip::PastLastRow,
                pattern: PatternExpr::Empty,
                define: vec![],
                symbols: SymbolTable::default(),
                raw_span: sp(),
            },
            output_columns,
            node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        }
    }

    #[test]
    fn a_match_recognize_places_its_measures_after_what_precedes_them() {
        let _folding = crate::ir::normalize::default_folding();
        let mut alloc = ColumnIdAllocator::new();
        let closed = placing(&mut alloc, 2);
        let below = closed.output_schema();
        let measure = alloc.fresh_test();
        let all_rows = RowsPerMatch::AllRows(AllRowsMode::Default);
        // Every row of a match: the input's columns come first.
        let every = match_recognize(closed.clone(), vec![], &[measure], all_rows);
        assert_eq!(
            every.positional_columns(),
            known(&[below[0], below[1], measure])
        );
        assert_eq!(every.positional_columns().known, every.output_schema());
        let every = match_recognize(scan(&mut alloc, "t", 2), vec![], &[measure], all_rows);
        assert_eq!(every.positional_columns(), open_after(&[]));
        // One row a match: the keys and the measures are the node's own,
        // whatever the input places.
        for input in [closed.clone(), scan(&mut alloc, "t", 2)] {
            let one = match_recognize(
                input,
                vec![column(below[1])],
                &[measure],
                RowsPerMatch::OneRow,
            );
            assert_eq!(one.positional_columns(), known(&[below[1], measure]));
        }
        // A key that is no column is a column the node does not list.
        let computed = match_recognize(
            closed.clone(),
            vec![column(below[0]), lit_int(1), column(below[1])],
            &[measure],
            RowsPerMatch::OneRow,
        );
        assert_eq!(computed.positional_columns(), open_after(&[below[0]]));
        // With no key and no measure the node lists its input's columns.
        let bare = match_recognize(closed, vec![], &[], RowsPerMatch::OneRow);
        assert_eq!(bare.positional_columns(), open_after(&[]));
    }

    #[test]
    fn a_connect_by_places_what_its_block_places() {
        let mut alloc = ColumnIdAllocator::new();
        for (input, expected_open) in [
            (placing(&mut alloc, 2), false),
            (scan(&mut alloc, "t", 2), true),
        ] {
            let listed = input.output_schema();
            let expected = input.positional_columns();
            assert_eq!(expected.open, expected_open);
            let connect_by = RelPlan::ConnectBy {
                input: Box::new(input),
                start_with: None,
                connect: lit_int(1),
                nocycle: false,
                output_columns: listed,
                pseudo_columns: Vec::new(),
                node_id: nid(),
                span: sp(),
                hints: Vec::new(),
            };
            assert_eq!(connect_by.positional_columns(), expected);
        }
    }

    #[test]
    fn a_plan_that_was_not_understood_may_hold_any_column() {
        let opaque = RelPlan::Opaque {
            stmt_node_id: nid(),
            reason: OpaqueReason::NonSelectTopLevel,
            span: sp(),
            hints: Vec::new(),
        };
        let recovery = RelPlan::ParseRecovery {
            stmt_node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        };
        let invalid = RelPlan::InvalidInput {
            stmt_node_id: nid(),
            kind: InvalidInputKind::GroupByOrdinal(GroupByOrdinalCategory::OutOfRange),
            span: sp(),
            hints: Vec::new(),
        };
        for plan in [opaque, recovery, invalid] {
            assert_eq!(plan.positional_columns(), open_after(&[]), "{plan:?}");
            assert_eq!(plan.positional_columns().at(0), Position::Unknown);
        }
    }
}
