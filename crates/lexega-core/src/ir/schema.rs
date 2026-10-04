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
// `FilterKind` is re-exported to the in-file `#[cfg(test)]` module
// via `use super::*;`; it is unused in the lib-only build path.
#[cfg_attr(not(test), allow(unused_imports))]
use super::plan::{AggregateCall, CteBody, FilterKind, MergeAction, MergeBranch, RelPlan};
use super::scalar::{FieldStep, QuantifiedRhs, ScalarExpr};

impl RelPlan {
    /// Output schema of this plan node, in positional order.
    ///
    /// Allocates a fresh `Vec` per call.
    ///
    /// Semantics per variant:
    ///
    /// - **Leaf sources** (`Scan`, `Values`, `CteRef`, `ModelRef`): the
    ///   `columns` field is the schema.
    /// - **`Project`**: one `ColumnId` per `ProjectItem::Expr` item.
    ///   `ProjectItem::Star` items contribute a catalog-dependent
    ///   schema resolved after lowering; only the explicit-item
    ///   columns are emitted here.
    /// - **`Filter`, `Sort`, `Limit`, `TableSample`**: pure pass-through of
    ///   the input's schema.
    /// - **`Aggregate`, `Window`, `SetOp`, `Pivot`, `MatchRecognize`,
    ///   `ConnectBy`**: the stored `output_columns` is the schema.
    /// - **`Join`**: `left.output_schema() ++ right.output_schema()`.
    ///   `USING` / `NATURAL` column merging is handled by a wrapping
    ///   [`RelPlan::Project`] added during lowering, not by the `Join` node
    ///   itself.
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
        match self {
            // ── Sources ─────────────────────────────────────────────────
            RelPlan::Scan { columns, .. }
            | RelPlan::Values { columns, .. }
            | RelPlan::CteRef { columns, .. }
            | RelPlan::ModelRef { columns, .. } => columns.clone(),

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

            RelPlan::Filter { input, .. }
            | RelPlan::Sort { input, .. }
            | RelPlan::Limit { input, .. }
            | RelPlan::TableSample { input, .. } => input.output_schema(),

            RelPlan::Aggregate { output_columns, .. }
            | RelPlan::SetOp { output_columns, .. }
            | RelPlan::MatchRecognize { output_columns, .. }
            | RelPlan::ConnectBy { output_columns, .. } => output_columns.clone(),

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
                    .output_schema()
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
            // schema doc on `RelPlan::Window` in `plan.rs`.
            RelPlan::Window {
                input,
                window_outputs,
                ..
            } => {
                let mut out = input.output_schema();
                for c in window_outputs {
                    if !out.contains(c) {
                        out.push(*c);
                    }
                }
                out
            }

            // ── Binary op ───────────────────────────────────────────────
            RelPlan::Join { left, right, .. } => {
                let mut out = left.output_schema();
                out.extend(right.output_schema());
                out
            }

            // ── Dialect-exotic unary ops with derived schema ────────────
            RelPlan::Unnest {
                input,
                value_column,
                ordinality_column,
                ..
            } => {
                let mut out = input.output_schema();
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
                    .output_schema()
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
            RelPlan::WithScope { body, .. } => body.output_schema(),

            // A derived table re-binds the inner plan's output under
            // outer-scope `columns`. Lineage analysis wires them back
            // to `input.output_schema()`; until then, surface the
            // fresh outer ids so join-column arithmetic sees a
            // consistent schema.
            RelPlan::DerivedTable { columns, .. } => columns.clone(),

            // Table-valued functions produce a schema the outer
            // walk has bound via `scan_cols`; true arity is
            // catalog-dependent. Surface
            // whatever outer names were bound so column-arithmetic
            // downstream sees a consistent schema.
            RelPlan::TableFunction { output_columns, .. } => output_columns.clone(),

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
    /// column in order.
    pub fn cte_visible_output_schema(&self) -> Vec<ColumnId> {
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
        match self.cte_body_star_passthrough_input() {
            Some(inner) => inner.output_schema(),
            None => self.output_schema(),
        }
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
        ScalarExpr::LogicalChain { operands, .. } => {
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
        | MergeAction::InsertStar
        | MergeAction::InsertAllByName
        | MergeAction::Update { .. }
        | MergeAction::UpdateSetStar
        | MergeAction::UpdateAllByName
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
    use crate::ir::plan::{
        AfterMatchSkip, AggregateCall, CteBinding, CteBody, FrameBound, FrameExclusion, FrameMode,
        GroupingSpec, JoinKind, MatchRecognizeBody, MergeAction, MergeBranch, MergeBranchKind,
        NullTreatment, PatternExpr, PivotValues, ProjectExpr, ProjectItem, ResolvedFunc,
        ResolvedModel, RowsPerMatch, SampleKeyword, SampleSize, ScanModifier, SetOpKind, SortKey,
        SymbolTable, TableSample, UnpivotColumn, WindowCall, WindowFrame,
    };
    use crate::ir::scalar::{Lit, ScalarExpr, ScopeId};
    use crate::ir::strict::OpaqueReason;
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
        let mut alloc = ColumnIdAllocator::new();
        let cte_cols = vec![alloc.fresh_test()];
        let cte = RelPlan::CteRef {
            name: ident("c"),
            scope: ScopeId(0),
            columns: cte_cols.clone(),
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
            target_columns: vec![alloc.fresh_test(), alloc.fresh_test()],
            source: crate::ir::plan::InsertSource::Query(Box::new(src.clone())),
            on_conflict: None,
            overwrite: false,
            replace_into: false,
            overriding: None,
            returning: None,
            output: None,
            target_hints: Vec::new(),
            node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        };
        assert!(ins.output_schema().is_empty());

        let upd = RelPlan::Update {
            target: tref("tgt"),
            assignments: vec![(alloc.fresh_test(), lit_int(1))],
            from: None,
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
            using: None,
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
            node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        };
        assert!(mg.output_schema().is_empty());
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
}
