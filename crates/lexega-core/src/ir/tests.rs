// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Per-variant hand-constructed tests for the IR skeleton.
//!
//! Every variant has a hand-constructed test. The analytical modules
//! (`schema`, `visitor`, `pretty`) already exercise every variant
//! collectively via exhaustive matches; this module complements them with
//! **identity** tests:
//!
//! 1. Each [`RelPlan`] variant can be constructed with an arbitrary span,
//!    and [`RelPlan::span()`] returns exactly that span.
//! 2. Each [`ScalarExpr`] variant can be constructed with an arbitrary span,
//!    and [`ScalarExpr::span()`] returns exactly that span.
//! 3. [`ColumnIdAllocator`] allocates strictly increasing, distinct ids.
//! 4. Each [`ColumnOrigin`] and [`OpaqueReason`] variant is constructible.
//!
//! These tests fail-compile (not fail-run) the moment a variant is added
//! or its shape changes — that is the intended drift protection for the
//! closed-enum promise.

#![cfg(test)]

use crate::ast::NodeId;
use crate::context::node_metadata::{IdentKey, TableRef};
use crate::ir::column::{ColumnBinding, ColumnId, ColumnIdAllocator, ColumnOrigin};
use crate::ir::plan::{
    AfterMatchSkip, AggregateCall, CteBinding, CteBody, FilterKind, FrameBound, FrameExclusion,
    FrameMode, GroupingSpec, JoinKind, MatchRecognizeBody, MatchRecognizeDefine,
    MatchRecognizeMeasure, MergeAction, MergeBranch, MergeBranchKind, NullTreatment, PatternExpr,
    PatternQuantKind, ProjectExpr, ProjectItem, RelPlan, ResolvedFunc, ResolvedModel, RowsPerMatch,
    SampleKeyword, SampleSize, ScanModifier, SetOpKind, SortKey, SymbolId, SymbolTable,
    TableSample, WindowCall, WindowFrame,
};
use crate::ir::scalar::{
    ComparisonOp, FieldStep, Lit, QuantifiedRhs, Quantifier, ScalarExpr, ScopeId, SqlType,
    UnaryOpKind,
};
use crate::ir::strict::OpaqueReason;
use crate::lexer::Span;

// ─── small builders ─────────────────────────────────────────────────────

fn span(start: u32, end: u32) -> Span {
    Span { start, end }
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
        span: span(0, 0),
    }
}

fn col(id: u32) -> ScalarExpr {
    ScalarExpr::Column {
        column: ColumnId::new(id),
        span: span(0, 0),
    }
}

fn sort_key() -> SortKey {
    SortKey {
        expr: lit_int(1),
        ascending: true,
        nulls_first: None,
        span: span(0, 0),
    }
}

fn resolved_func() -> ResolvedFunc {
    // Tests that don't exercise catalog behavior use an unresolved
    // placeholder — it round-trips by raw name and treats the call as
    // plain scalar shape for analyses that don't look at aggregate /
    // window status.
    ResolvedFunc::unresolved("f", None, span(0, 0))
}

fn aggregate_call(out: ColumnId) -> AggregateCall {
    // Tests exercising aggregate-node construction don't need catalog
    // lookup — the aggregate "shape" here is determined by the node
    // containing the call, not by the function's catalog kind. Using
    // an unresolved placeholder keeps the helper catalog-free.
    AggregateCall {
        func: resolved_func(),
        args: vec![],
        named_args: vec![],
        distinct: false,
        approximate: false,
        filter: None,
        arg_order: vec![],
        within_group_order: vec![],
        null_treatment: NullTreatment::default(),
        output: out,
        span: span(0, 0),
    }
}

fn window_call(out: ColumnId) -> WindowCall {
    WindowCall {
        func: resolved_func(),
        args: vec![],
        distinct: false,
        null_treatment: NullTreatment::default(),
        partition_by: vec![],
        order_by: vec![],
        frame: Some(WindowFrame {
            mode: FrameMode::Rows,
            start: FrameBound::UnboundedPreceding,
            end: FrameBound::CurrentRow,
            exclusion: FrameExclusion::default(),
        }),
        named_window: None,
        output: out,
        span: span(0, 0),
    }
}

fn scan(alloc: &mut ColumnIdAllocator, n: usize, sp: Span) -> RelPlan {
    let columns: Vec<ColumnId> = (0..n).map(|_| alloc.fresh_test()).collect();
    RelPlan::Scan {
        table: tref("t"),
        columns,
        modifier: ScanModifier::default(),
        alias: None,
        node_id: nid(),
        span: sp,
        hints: Vec::new(),
    }
}

// ─── RelPlan: per-variant span round-trip ───────────────────────────────
//
// One test per variant. If the variant shape changes, only that test needs
// updating; a new variant forces adding a new test (the compile-time
// exhaustiveness check is in `schema.rs` / `pretty.rs` / `visitor.rs`).

#[test]
fn relplan_scan_span() {
    let mut alloc = ColumnIdAllocator::new();
    let s = span(10, 20);
    assert_eq!(scan(&mut alloc, 1, s).span(), s);
}

#[test]
fn relplan_values_span() {
    let s = span(5, 15);
    let plan = RelPlan::Values {
        rows: vec![vec![lit_int(1)]],
        columns: vec![ColumnId::new(0)],
        alias: None,
        node_id: nid(),
        span: s,
        hints: Vec::new(),
    };
    assert_eq!(plan.span(), s);
}

#[test]
fn relplan_cte_ref_span() {
    let s = span(1, 2);
    let plan = RelPlan::CteRef {
        name: ident("c"),
        scope: ScopeId(0),
        columns: vec![ColumnId::new(0)],
        alias: Some(ident("a")),
        node_id: nid(),
        span: s,
        hints: Vec::new(),
    };
    assert_eq!(plan.span(), s);
}

#[test]
fn relplan_model_ref_span() {
    let s = span(3, 4);
    let plan = RelPlan::ModelRef {
        model: ResolvedModel {
            package: Some("pkg".into()),
            name: "m".into(),
            base_tables: Vec::new(),
            taint_labels: std::collections::HashMap::new(),
            nullable_columns: std::collections::HashSet::new(),
            constraint_set: Default::default(),
            column_lineage: None,
            has_filter: false,
            node_id: nid(),
        },
        columns: vec![ColumnId::new(0)],
        alias: None,
        node_id: nid(),
        span: s,
        hints: Vec::new(),
    };
    assert_eq!(plan.span(), s);
}

#[test]
fn relplan_project_span() {
    let mut alloc = ColumnIdAllocator::new();
    let s = span(100, 200);
    let item = ProjectItem::Expr(ProjectExpr {
        output: alloc.fresh_test(),
        expr: lit_int(1),
        alias: None,
        span: span(0, 0),
    });
    let plan = RelPlan::Project {
        input: Box::new(scan(&mut alloc, 1, span(0, 0))),
        items: vec![item],
        distinct: false,
        distinct_on: Vec::new(),
        node_id: nid(),
        span: s,
        hints: Vec::new(),
    };
    assert_eq!(plan.span(), s);
}

#[test]
fn relplan_filter_span() {
    let mut alloc = ColumnIdAllocator::new();
    let s = span(7, 8);
    let plan = RelPlan::Filter {
        input: Box::new(scan(&mut alloc, 1, span(0, 0))),
        predicate: lit_int(1),
        kind: FilterKind::Where,
        node_id: nid(),
        span: s,
        hints: Vec::new(),
    };
    assert_eq!(plan.span(), s);
}

#[test]
fn relplan_aggregate_span() {
    let mut alloc = ColumnIdAllocator::new();
    let s = span(9, 10);
    let out = alloc.fresh_test();
    let plan = RelPlan::Aggregate {
        input: Box::new(scan(&mut alloc, 1, span(0, 0))),
        grouping: GroupingSpec::None,
        aggregates: vec![aggregate_call(out)],
        having: None,
        output_columns: vec![out],
        node_id: nid(),
        span: s,
        hints: Vec::new(),
    };
    assert_eq!(plan.span(), s);
}

#[test]
fn relplan_window_span() {
    let mut alloc = ColumnIdAllocator::new();
    let s = span(11, 12);
    let out = alloc.fresh_test();
    let plan = RelPlan::Window {
        input: Box::new(scan(&mut alloc, 1, span(0, 0))),
        windows: vec![window_call(out)],
        window_outputs: vec![out],
        node_id: nid(),
        span: s,
        hints: Vec::new(),
    };
    assert_eq!(plan.span(), s);
}

#[test]
fn relplan_join_span() {
    let mut alloc = ColumnIdAllocator::new();
    let s = span(13, 14);
    let plan = RelPlan::Join {
        left: Box::new(scan(&mut alloc, 1, span(0, 0))),
        right: Box::new(scan(&mut alloc, 1, span(0, 0))),
        kind: JoinKind::Inner,
        on: Some(lit_int(1)),
        match_condition: None,
        using: vec![],
        natural: false,
        directed: false,
        lateral: false,
        implicit: false,
        node_id: nid(),
        span: s,
        clause_span: s,
        hints: Vec::new(),
    };
    assert_eq!(plan.span(), s);
}

#[test]
fn relplan_setop_span() {
    let mut alloc = ColumnIdAllocator::new();
    let out = alloc.fresh_test();
    let s = span(15, 16);
    let plan = RelPlan::SetOp {
        op: SetOpKind::UnionAll,
        inputs: vec![
            Box::new(scan(&mut alloc, 1, span(0, 0))),
            Box::new(scan(&mut alloc, 1, span(0, 0))),
        ],
        corresponding: None,
        output_columns: vec![out],
        node_id: nid(),
        span: s,
        hints: Vec::new(),
    };
    assert_eq!(plan.span(), s);
}

#[test]
fn relplan_sort_span() {
    let mut alloc = ColumnIdAllocator::new();
    let s = span(17, 18);
    let plan = RelPlan::Sort {
        input: Box::new(scan(&mut alloc, 1, span(0, 0))),
        keys: vec![sort_key()],
        node_id: nid(),
        span: s,
        hints: Vec::new(),
    };
    assert_eq!(plan.span(), s);
}

#[test]
fn relplan_limit_span() {
    let mut alloc = ColumnIdAllocator::new();
    let s = span(19, 20);
    let plan = RelPlan::Limit {
        input: Box::new(scan(&mut alloc, 1, span(0, 0))),
        limit: Some(lit_int(10)),
        offset: Some(lit_int(0)),
        kind: crate::ir::plan::LimitKind::Rows,
        with_ties: false,
        node_id: nid(),
        span: s,
        hints: Vec::new(),
    };
    assert_eq!(plan.span(), s);
}

#[test]
fn relplan_insert_span() {
    let mut alloc = ColumnIdAllocator::new();
    let s = span(21, 22);
    let plan = RelPlan::Insert {
        target: tref("t"),
        target_columns: vec![alloc.fresh_test()],
        source: crate::ir::plan::InsertSource::Query(Box::new(scan(&mut alloc, 1, span(0, 0)))),
        on_conflict: None,
        overwrite: false,
        replace_into: false,
        overriding: None,
        returning: None,
        output: None,
        target_hints: Vec::new(),
        node_id: nid(),
        span: s,
        hints: Vec::new(),
    };
    assert_eq!(plan.span(), s);
}

#[test]
fn relplan_update_span() {
    let mut alloc = ColumnIdAllocator::new();
    let s = span(23, 24);
    let plan = RelPlan::Update {
        target: tref("t"),
        assignments: vec![(alloc.fresh_test(), lit_int(1))],
        from: None,
        predicate: None,
        top: None,
        returning: None,
        output: None,
        node_id: nid(),
        span: s,
        hints: Vec::new(),
    };
    assert_eq!(plan.span(), s);
}

#[test]
fn relplan_delete_span() {
    let s = span(25, 26);
    let plan = RelPlan::Delete {
        target: tref("t"),
        using: None,
        predicate: None,
        top: None,
        returning: None,
        output: None,
        node_id: nid(),
        span: s,
        hints: Vec::new(),
    };
    assert_eq!(plan.span(), s);
}

#[test]
fn relplan_merge_span() {
    let mut alloc = ColumnIdAllocator::new();
    let s = span(27, 28);
    let plan = RelPlan::Merge {
        target: tref("t"),
        source: Box::new(scan(&mut alloc, 1, span(0, 0))),
        on: lit_int(1),
        branches: vec![MergeBranch {
            kind: MergeBranchKind::WhenMatched,
            predicate: None,
            action: MergeAction::Delete,
            span: span(0, 0),
        }],
        with_schema_evolution: false,
        output: None,
        node_id: nid(),
        span: s,
        hints: Vec::new(),
    };
    assert_eq!(plan.span(), s);
}

#[test]
fn relplan_with_scope_span() {
    let mut alloc = ColumnIdAllocator::new();
    let s = span(29, 30);
    let cte_cols = vec![alloc.fresh_test()];
    let cte_inner = scan(&mut alloc, 1, span(0, 0));
    let plan = RelPlan::WithScope {
        ctes: vec![CteBinding {
            name: ident("c"),
            scope: ScopeId(0),
            declared_columns: None,
            body: CteBody::NonRecursive(Box::new(cte_inner)),
            output_columns: cte_cols,
            node_id: nid(),
            span: span(0, 0),
        }],
        body: Box::new(scan(&mut alloc, 1, span(0, 0))),
        recursive: false,
        node_id: nid(),
        span: s,
        hints: Vec::new(),
    };
    assert_eq!(plan.span(), s);
}

#[test]
fn relplan_unnest_span() {
    let mut alloc = ColumnIdAllocator::new();
    let s = span(31, 32);
    let value_col = alloc.fresh_test();
    let plan = RelPlan::Unnest {
        input: Box::new(scan(&mut alloc, 1, span(0, 0))),
        array: lit_int(1),
        value_column: value_col,
        ordinality_column: None,
        with_offset: false,
        preserve_nulls: false,
        node_id: nid(),
        span: s,
        hints: Vec::new(),
    };
    assert_eq!(plan.span(), s);
}

#[test]
fn relplan_pivot_span() {
    let mut alloc = ColumnIdAllocator::new();
    let s = span(33, 34);
    let pivot_col = alloc.fresh_test();
    let out = alloc.fresh_test();
    let plan = RelPlan::Pivot {
        input: Box::new(scan(&mut alloc, 1, span(0, 0))),
        aggregates: vec![aggregate_call(out)],
        pivot_column: pivot_col,
        pivot_values: crate::ir::PivotValues::ValueList(vec![lit_int(1)]),
        output_columns: vec![out],
        default_on_null: None,
        node_id: nid(),
        span: s,
        hints: Vec::new(),
    };
    assert_eq!(plan.span(), s);
}

#[test]
fn relplan_unpivot_span() {
    let mut alloc = ColumnIdAllocator::new();
    let s = span(35, 36);
    let name_col = alloc.fresh_test();
    let value_col = alloc.fresh_test();
    let src_col = alloc.fresh_test();
    let plan = RelPlan::Unpivot {
        input: Box::new(scan(&mut alloc, 1, span(0, 0))),
        value_columns: vec![value_col],
        name_column: name_col,
        unpivoted_columns: vec![crate::ir::UnpivotColumn {
            columns: vec![src_col],
            alias: None,
            span: span(0, 0),
        }],
        include_nulls: false,
        node_id: nid(),
        span: s,
        hints: Vec::new(),
    };
    assert_eq!(plan.span(), s);
}

#[test]
fn relplan_match_recognize_span() {
    let mut alloc = ColumnIdAllocator::new();
    let s = span(37, 38);
    let plan = RelPlan::MatchRecognize {
        input: Box::new(scan(&mut alloc, 1, span(0, 0))),
        body: MatchRecognizeBody {
            partition_by: vec![],
            order_by: vec![],
            measures: vec![],
            rows_per_match: RowsPerMatch::OneRow,
            after_match_skip: AfterMatchSkip::PastLastRow,
            pattern: PatternExpr::Empty,
            define: vec![],
            symbols: SymbolTable::default(),
            raw_span: span(0, 0),
        },
        output_columns: vec![alloc.fresh_test()],
        node_id: nid(),
        span: s,
        hints: Vec::new(),
    };
    assert_eq!(plan.span(), s);
}

/// A non-trivial MATCH_RECOGNIZE body exercises every typed
/// sub-field, including `ScalarExpr::PatternVarRef` inside a
/// MEASURES expression and a quantified pattern referencing the
/// interned symbols. Verifies span round-trip, output_columns
/// shape, and that the visitor walks every leaf in the body.
#[test]
fn relplan_match_recognize_typed_body_full_shape() {
    use crate::ir::visitor::{walk_rel_plan, walk_scalar_expr, RelPlanVisitor};

    let mut alloc = ColumnIdAllocator::new();
    let inner = scan(&mut alloc, 2, span(0, 10));
    let inner_cols = inner.output_schema();
    let partition_col = inner_cols[0];
    let order_col = inner_cols[1];

    // Symbols A, B (B is also pattern-quantified).
    let mut symbols = SymbolTable::default();
    let a_sym = symbols.intern(IdentKey::new("A"), "A".into(), span(20, 21));
    let b_sym = symbols.intern(IdentKey::new("B"), "B".into(), span(22, 23));

    // MEASURES output ColumnId (allocated computed).
    let measure_out = alloc.fresh_test();

    // MEASURES expr: PatternVarRef(B, order_col) — `B.event_ts`-style.
    let measure_expr = ScalarExpr::PatternVarRef {
        symbol: b_sym,
        column: order_col,
        span: span(24, 30),
    };

    // DEFINE B AS B.order_col > 0 (use PatternVarRef again).
    let define_predicate = ScalarExpr::BinOp {
        op: crate::ir::scalar::BinOpKind::Cmp(crate::ir::scalar::ComparisonOp::Gt),
        left: Box::new(ScalarExpr::PatternVarRef {
            symbol: b_sym,
            column: order_col,
            span: span(40, 46),
        }),
        right: Box::new(lit_int(0)),
        span: span(40, 50),
    };

    let body = MatchRecognizeBody {
        partition_by: vec![ScalarExpr::Column {
            column: partition_col,
            span: span(11, 18),
        }],
        order_by: vec![SortKey {
            expr: ScalarExpr::Column {
                column: order_col,
                span: span(19, 27),
            },
            ascending: true,
            nulls_first: None,
            span: span(19, 27),
        }],
        measures: vec![MatchRecognizeMeasure {
            output: measure_out,
            modifier: None,
            expr: measure_expr,
            alias: IdentKey::new("first_b"),
            span: span(24, 35),
        }],
        rows_per_match: RowsPerMatch::OneRow,
        after_match_skip: AfterMatchSkip::ToLast(b_sym),
        pattern: PatternExpr::Concat(vec![
            PatternExpr::Symbol(a_sym),
            PatternExpr::Quantified {
                inner: Box::new(PatternExpr::Symbol(b_sym)),
                kind: PatternQuantKind::OneOrMore,
                greedy: true,
            },
        ]),
        define: vec![MatchRecognizeDefine {
            symbol: b_sym,
            predicate: define_predicate,
            span: span(40, 50),
        }],
        symbols,
        raw_span: span(0, 60),
    };

    // OneRow: partition column id + measure outputs.
    let s = span(0, 60);
    let plan = RelPlan::MatchRecognize {
        input: Box::new(inner),
        body,
        output_columns: vec![partition_col, measure_out],
        node_id: nid(),
        span: s,
        hints: Vec::new(),
    };

    assert_eq!(plan.span(), s);
    assert_eq!(plan.output_schema(), vec![partition_col, measure_out]);

    // Visitor walks every ScalarExpr leaf inside the body. The
    // partition_by Column, order_by SortKey expr, MEASURES expr
    // (PatternVarRef), and DEFINE predicate (BinOp containing
    // PatternVarRef + Lit) together produce: 2 Column refs +
    // 2 PatternVarRef + 1 Lit + 1 BinOp = 6 ScalarExpr nodes
    // visible to the visitor's pre-order callback for the body's
    // top-level expressions. The visitor descends into BinOp's
    // operands, so PatternVarRef + Lit are also counted.
    #[derive(Default)]
    struct Counter {
        columns: usize,
        pvars: usize,
        lits: usize,
    }
    impl<'a> RelPlanVisitor<'a> for Counter {
        fn visit_scalar_expr(&mut self, expr: &'a ScalarExpr) {
            match expr {
                ScalarExpr::Column { .. } => self.columns += 1,
                ScalarExpr::PatternVarRef { .. } => self.pvars += 1,
                ScalarExpr::Lit { .. } => self.lits += 1,
                _ => {}
            }
            walk_scalar_expr(self, expr);
        }
    }
    let mut c = Counter::default();
    walk_rel_plan(&mut c, &plan);
    // partition_by Column (1) + order_by SortKey Column (1) → 2.
    assert_eq!(c.columns, 2);
    // MEASURES PatternVarRef (1) + DEFINE BinOp's lhs PatternVarRef (1) → 2.
    assert_eq!(c.pvars, 2);
    // DEFINE BinOp's rhs Lit (1) → 1.
    assert_eq!(c.lits, 1);

    // Sanity: SymbolTable accessors.
    if let RelPlan::MatchRecognize { body, .. } = &plan {
        assert_eq!(body.symbols.len(), 2);
        assert_eq!(body.symbols.lookup(&IdentKey::new("A")), Some(SymbolId(0)));
        assert_eq!(body.symbols.lookup(&IdentKey::new("B")), Some(SymbolId(1)));
    } else {
        panic!("expected MatchRecognize");
    }
}

#[test]
fn relplan_connect_by_span() {
    let mut alloc = ColumnIdAllocator::new();
    let s = span(39, 40);
    let plan = RelPlan::ConnectBy {
        input: Box::new(scan(&mut alloc, 1, span(0, 0))),
        start_with: Some(lit_int(1)),
        connect: lit_int(1),
        nocycle: false,
        output_columns: vec![alloc.fresh_test()],
        node_id: nid(),
        span: s,
        hints: Vec::new(),
    };
    assert_eq!(plan.span(), s);
}

#[test]
fn relplan_tablesample_span() {
    let mut alloc = ColumnIdAllocator::new();
    let s = span(41, 42);
    let plan = RelPlan::TableSample {
        input: Box::new(scan(&mut alloc, 1, span(0, 0))),
        sample: TableSample {
            method_keyword: Some(SampleKeyword::Bernoulli),
            size: SampleSize::Probability(lit_int(10)),
            seed: None,
            repeatable: None,
            span: span(0, 0),
        },
        node_id: nid(),
        span: s,
        hints: Vec::new(),
    };
    assert_eq!(plan.span(), s);
}

#[test]
fn relplan_opaque_span() {
    let s = span(43, 44);
    let plan = RelPlan::Opaque {
        stmt_node_id: nid(),
        reason: OpaqueReason::NonSelectTopLevel,
        span: s,
        hints: Vec::new(),
    };
    assert_eq!(plan.span(), s);
}

#[test]
fn relplan_parse_recovery_span() {
    let s = span(43, 44);
    let plan = RelPlan::ParseRecovery {
        stmt_node_id: nid(),
        span: s,
        hints: Vec::new(),
    };
    assert_eq!(plan.span(), s);
}

#[test]
fn relplan_derived_table_span_and_schema() {
    let mut alloc = ColumnIdAllocator::new();
    let s = span(45, 46);
    let c = alloc.fresh_test();
    let plan = RelPlan::DerivedTable {
        input: Box::new(scan(&mut alloc, 1, span(0, 0))),
        alias: None,
        columns: vec![c],
        alias_columns: Vec::new(),
        node_id: nid(),
        span: s,
        hints: Vec::new(),
    };
    assert_eq!(plan.span(), s);
    // Schema surfaces the fresh outer-scope columns, not the
    // inner scan's ids.
    assert_eq!(plan.output_schema(), vec![c]);
}

// ─── ScalarExpr: per-variant span round-trip ────────────────────────────

#[test]
fn scalar_column_span() {
    let s = span(1, 2);
    let e = ScalarExpr::Column {
        column: ColumnId::new(0),
        span: s,
    };
    assert_eq!(e.span(), s);
}

#[test]
fn scalar_outer_ref_span() {
    let s = span(3, 4);
    let e = ScalarExpr::OuterRef {
        scope: ScopeId(0),
        column: ColumnId::new(0),
        span: s,
    };
    assert_eq!(e.span(), s);
}

#[test]
fn scalar_lit_span() {
    let s = span(5, 6);
    let e = ScalarExpr::Lit {
        value: Lit::Null,
        span: s,
    };
    assert_eq!(e.span(), s);
}

#[test]
fn scalar_binop_span() {
    let s = span(7, 8);
    let e = ScalarExpr::BinOp {
        op: crate::ir::scalar::BinOpKind::Cmp(crate::ir::scalar::ComparisonOp::Eq),
        left: Box::new(lit_int(1)),
        right: Box::new(lit_int(2)),
        span: s,
    };
    assert_eq!(e.span(), s);
}

#[test]
fn scalar_unaryop_span() {
    let s = span(9, 10);
    let e = ScalarExpr::UnaryOp {
        op: UnaryOpKind::Neg,
        arg: Box::new(lit_int(1)),
        span: s,
    };
    assert_eq!(e.span(), s);
}

#[test]
fn scalar_funccall_span() {
    let s = span(11, 12);
    let e = ScalarExpr::FuncCall {
        func: resolved_func(),
        args: vec![lit_int(1)],
        named_args: vec![(
            crate::context::node_metadata::IdentKey::new("k"),
            lit_int(2),
        )],
        distinct: false,
        span: s,
    };
    assert_eq!(e.span(), s);
}

#[test]
fn scalar_case_span() {
    let s = span(13, 14);
    let e = ScalarExpr::Case {
        operand: Some(Box::new(lit_int(1))),
        branches: vec![(lit_int(1), lit_int(2))],
        else_: Some(Box::new(lit_int(3))),
        span: s,
    };
    assert_eq!(e.span(), s);
}

#[test]
fn scalar_cast_span() {
    let s = span(15, 16);
    let e = ScalarExpr::Cast {
        expr: Box::new(lit_int(1)),
        target_type: SqlType { repr: "INT".into() },
        try_cast: false,
        span: s,
    };
    assert_eq!(e.span(), s);
}

#[test]
fn scalar_inlist_span() {
    let s = span(17, 18);
    let e = ScalarExpr::InList {
        expr: Box::new(lit_int(1)),
        list: vec![lit_int(2), lit_int(3)],
        negated: false,
        span: s,
    };
    assert_eq!(e.span(), s);
}

#[test]
fn scalar_between_span() {
    let s = span(19, 20);
    let e = ScalarExpr::Between {
        expr: Box::new(lit_int(1)),
        low: Box::new(lit_int(0)),
        high: Box::new(lit_int(2)),
        negated: false,
        span: s,
    };
    assert_eq!(e.span(), s);
}

#[test]
fn scalar_exists_span() {
    let mut alloc = ColumnIdAllocator::new();
    let s = span(21, 22);
    let e = ScalarExpr::Exists {
        subquery: Box::new(scan(&mut alloc, 1, span(0, 0))),
        correlates_with: vec![],
        negated: false,
        span: s,
    };
    assert_eq!(e.span(), s);
}

#[test]
fn scalar_scalar_subquery_span() {
    let mut alloc = ColumnIdAllocator::new();
    let s = span(23, 24);
    let e = ScalarExpr::ScalarSubquery {
        subquery: Box::new(scan(&mut alloc, 1, span(0, 0))),
        correlates_with: vec![ColumnId::new(9)],
        span: s,
    };
    assert_eq!(e.span(), s);
}

#[test]
fn scalar_quantified_cmp_span() {
    let s = span(25, 26);
    let e = ScalarExpr::QuantifiedCmp {
        op: ComparisonOp::Eq,
        quantifier: Quantifier::Any,
        negated: false,
        left: Box::new(lit_int(1)),
        right: QuantifiedRhs::List(vec![lit_int(1), lit_int(2)]),
        span: s,
    };
    assert_eq!(e.span(), s);
}

#[test]
fn scalar_window_fn_span() {
    let mut alloc = ColumnIdAllocator::new();
    let s = span(27, 28);
    let out = alloc.fresh_test();
    let e = ScalarExpr::WindowFn {
        call: Box::new(window_call(out)),
        span: s,
    };
    assert_eq!(e.span(), s);
}

#[test]
fn scalar_field_access_span() {
    let s = span(29, 30);
    let e = ScalarExpr::FieldAccess {
        base: Box::new(col(0)),
        path: vec![
            FieldStep::Field("a".into()),
            FieldStep::Index(2),
            FieldStep::IndexExpr(Box::new(lit_int(1))),
        ],
        cast: Some(SqlType { repr: "INT".into() }),
        span: s,
    };
    assert_eq!(e.span(), s);
}

#[test]
fn scalar_opaque_span() {
    let s = span(31, 32);
    let e = ScalarExpr::Opaque {
        span: s,
        reason: "unresolved".into(),
    };
    assert_eq!(e.span(), s);
}

// ─── ColumnId / allocator / bindings ────────────────────────────────────

#[test]
fn column_id_allocator_is_monotonic_and_distinct() {
    let mut alloc = ColumnIdAllocator::new();
    let a = alloc.fresh_test();
    let b = alloc.fresh_test();
    let c = alloc.fresh_test();
    assert_eq!(a.as_u32(), 0);
    assert_eq!(b.as_u32(), 1);
    assert_eq!(c.as_u32(), 2);
    assert_ne!(a, b);
    assert_ne!(b, c);
    assert_eq!(alloc.count(), 3);
}

#[test]
fn column_origin_table_binding() {
    let b = ColumnBinding {
        id: ColumnId::new(0),
        display_name: "name".into(),
        origin: ColumnOrigin::Table {
            table_node: nid(),
            column_name: "name".into(),
            span: span(1, 5),
        },
        ty: None,
        explicit_alias: None,
    };
    match &b.origin {
        ColumnOrigin::Table { column_name, .. } => assert_eq!(column_name, "name"),
        _ => panic!("expected Table origin"),
    }
}

#[test]
fn column_origin_computed_binding() {
    let b = ColumnBinding {
        id: ColumnId::new(1),
        display_name: "expr".into(),
        origin: ColumnOrigin::Computed {
            producing_node: nid(),
            expr_span: span(10, 20),
        },
        ty: None,
        explicit_alias: None,
    };
    assert!(matches!(b.origin, ColumnOrigin::Computed { .. }));
}

#[test]
fn column_origin_setop_binding() {
    let b = ColumnBinding {
        id: ColumnId::new(2),
        display_name: "u".into(),
        origin: ColumnOrigin::SetOp {
            inputs: vec![ColumnId::new(0), ColumnId::new(1)],
        },
        ty: None,
        explicit_alias: None,
    };
    match &b.origin {
        ColumnOrigin::SetOp { inputs } => assert_eq!(inputs.len(), 2),
        _ => panic!("expected SetOp origin"),
    }
}

#[test]
fn column_origin_outer_ref_binding() {
    let b = ColumnBinding {
        id: ColumnId::new(3),
        display_name: "outer".into(),
        origin: ColumnOrigin::OuterRef {
            scope: ScopeId(7),
            outer_column: ColumnId::new(0),
        },
        ty: None,
        explicit_alias: None,
    };
    match &b.origin {
        ColumnOrigin::OuterRef { scope, .. } => assert_eq!(*scope, ScopeId(7)),
        _ => panic!("expected OuterRef origin"),
    }
}

#[test]
fn column_origin_recursive_ref_binding() {
    let b = ColumnBinding {
        id: ColumnId::new(4),
        display_name: "rec".into(),
        origin: ColumnOrigin::RecursiveRef { binding_index: 2 },
        ty: None,
        explicit_alias: None,
    };
    match &b.origin {
        ColumnOrigin::RecursiveRef { binding_index } => assert_eq!(*binding_index, 2),
        _ => panic!("expected RecursiveRef origin"),
    }
}

// ─── OpaqueReason: exhaustive construction ──────────────────────────────

#[test]
fn opaque_reason_all_variants_constructible() {
    let variants = [
        OpaqueReason::UnresolvedJinja {
            macro_name: Some("m".into()),
        },
        OpaqueReason::UnknownFunction {
            raw_name: "NOT_A_FUNC".into(),
        },
        OpaqueReason::NonSelectTopLevel,
        OpaqueReason::CatalogMissing {
            kind: crate::ir::strict::CatalogLookupKind::MergeInsertStar,
        },
    ];
    // Tags are non-empty and unique.
    let tags: Vec<&'static str> = variants.iter().map(OpaqueReason::tag).collect();
    let unique: std::collections::BTreeSet<&&str> = tags.iter().collect();
    assert_eq!(unique.len(), tags.len());
    for t in tags {
        assert!(!t.is_empty());
    }
}

// ─── GroupingSpec / FrameBound: auxiliary enum exhaustiveness ──────────

#[test]
fn grouping_spec_all_shapes_constructible() {
    let g0 = GroupingSpec::None;
    let g1 = GroupingSpec::Standard(vec![]);
    let g2 = GroupingSpec::Cube(vec![]);
    let g3 = GroupingSpec::Rollup(vec![]);
    let g4 = GroupingSpec::GroupingSets(vec![]);
    let g5 = GroupingSpec::All(vec![]);
    // Compile-time exhaustiveness: exercise a match with all five arms.
    for g in [g0, g1, g2, g3, g4, g5] {
        match g {
            GroupingSpec::None
            | GroupingSpec::Standard(_)
            | GroupingSpec::Cube(_)
            | GroupingSpec::Rollup(_)
            | GroupingSpec::GroupingSets(_)
            | GroupingSpec::All(_) => {}
        }
    }
}

#[test]
fn frame_bound_all_shapes_constructible() {
    for fb in [
        FrameBound::UnboundedPreceding,
        FrameBound::Preceding(lit_int(1)),
        FrameBound::CurrentRow,
        FrameBound::Following(lit_int(1)),
        FrameBound::UnboundedFollowing,
    ] {
        match fb {
            FrameBound::UnboundedPreceding
            | FrameBound::Preceding(_)
            | FrameBound::CurrentRow
            | FrameBound::Following(_)
            | FrameBound::UnboundedFollowing => {}
        }
    }
}

// ─── Scalar-expr round-trip ─────────────────────────────────────────────
//
// "Round-trip" here means: a scalar tree preserves its shape and
// payload through `Clone`, and a visitor observes the same sequence of
// columns/outer-refs/literals traversing either copy. There is no
// serialization; `Clone`-equivalence is the operational round-trip.
//
// Covers scalar exprs including FieldAccess / OuterRef.

#[derive(Default)]
struct Collector {
    columns: Vec<ColumnId>,
    outers: Vec<(ScopeId, ColumnId)>,
    lits: Vec<String>,
    fields: Vec<String>,
    indexes: Vec<i64>,
}

impl<'a> crate::ir::visitor::ScalarExprVisitor<'a> for Collector {
    fn visit_scalar_expr(&mut self, expr: &'a ScalarExpr) {
        match expr {
            ScalarExpr::Column { column, .. } => self.columns.push(*column),
            ScalarExpr::OuterRef { scope, column, .. } => self.outers.push((*scope, *column)),
            ScalarExpr::Lit { value, .. } => self.lits.push(format!("{value:?}")),
            ScalarExpr::FieldAccess { path, .. } => {
                for step in path {
                    match step {
                        FieldStep::Field(n) => self.fields.push(n.clone()),
                        FieldStep::Index(i) => self.indexes.push(*i),
                        FieldStep::IndexExpr(_) => {}
                    }
                }
            }
            _ => {}
        }
        crate::ir::visitor::walk_scalar_expr_standalone(self, expr);
    }
}

fn collect(e: &ScalarExpr) -> Collector {
    let mut c = Collector::default();
    use crate::ir::visitor::ScalarExprVisitor;
    c.visit_scalar_expr(e);
    c
}

fn assert_roundtrip(e: &ScalarExpr) {
    let cloned = e.clone();
    // Spans survive clone.
    assert_eq!(e.span(), cloned.span());
    // Visitor-observed payload is identical.
    let a = collect(e);
    let b = collect(&cloned);
    assert_eq!(a.columns, b.columns);
    assert_eq!(a.outers, b.outers);
    assert_eq!(a.lits, b.lits);
    assert_eq!(a.fields, b.fields);
    assert_eq!(a.indexes, b.indexes);
}

#[test]
fn roundtrip_outer_ref_preserves_scope_and_column() {
    let e = ScalarExpr::OuterRef {
        scope: ScopeId(4),
        column: ColumnId::new(9),
        span: span(1, 2),
    };
    assert_roundtrip(&e);
    let c = collect(&e);
    assert_eq!(c.outers, vec![(ScopeId(4), ColumnId::new(9))]);
    assert!(c.columns.is_empty(), "OuterRef must not count as Column");
}

#[test]
fn roundtrip_field_access_preserves_path_shape() {
    // payload:a.b[2][expr]::INT
    let e = ScalarExpr::FieldAccess {
        base: Box::new(col(7)),
        path: vec![
            FieldStep::Field("a".into()),
            FieldStep::Field("b".into()),
            FieldStep::Index(2),
            FieldStep::IndexExpr(Box::new(lit_int(42))),
        ],
        cast: Some(SqlType { repr: "INT".into() }),
        span: span(3, 4),
    };
    assert_roundtrip(&e);
    let c = collect(&e);
    assert_eq!(c.fields, vec!["a".to_string(), "b".to_string()]);
    assert_eq!(c.indexes, vec![2]);
    // The base column reference is observed.
    assert_eq!(c.columns, vec![ColumnId::new(7)]);
    // IndexExpr's literal is reached via recursive walk.
    assert_eq!(c.lits.len(), 1);
}

#[test]
fn roundtrip_nested_mixing_column_outerref_fieldaccess() {
    // fn( c_0 + outer(2, 3), payload:x[1] )
    let e = ScalarExpr::FuncCall {
        func: resolved_func(),
        args: vec![
            ScalarExpr::BinOp {
                op: crate::ir::scalar::BinOpKind::Add,
                left: Box::new(col(0)),
                right: Box::new(ScalarExpr::OuterRef {
                    scope: ScopeId(2),
                    column: ColumnId::new(3),
                    span: span(0, 0),
                }),
                span: span(0, 0),
            },
            ScalarExpr::FieldAccess {
                base: Box::new(col(5)),
                path: vec![FieldStep::Field("x".into()), FieldStep::Index(1)],
                cast: None,
                span: span(0, 0),
            },
        ],
        named_args: vec![],
        distinct: false,
        span: span(10, 20),
    };
    assert_roundtrip(&e);
    let c = collect(&e);
    assert_eq!(c.columns, vec![ColumnId::new(0), ColumnId::new(5)]);
    assert_eq!(c.outers, vec![(ScopeId(2), ColumnId::new(3))]);
    assert_eq!(c.fields, vec!["x".to_string()]);
    assert_eq!(c.indexes, vec![1]);
}

// ─── FieldPath projection (path-aware analysis) ─────────────────────────
//
// These tests pin the closed `FieldPath` / `FieldPathSegment` projection
// derived from source-faithful `FieldStep` sequences. They exercise:
//   * empty path (whole-base equivalence),
//   * static field + index segments (case-folding via `IdentKey`),
//   * dynamic-index collapse to `Dynamic`,
//   * prefix semantics (whole-base covers sub-paths; concrete vs.
//     dynamic widening; rejection of disjoint paths).
// A new `FieldPathSegment` variant or `FieldStep` variant fails
// compilation in `from_field_steps` and `is_prefix_of`.

#[test]
fn field_path_empty_is_prefix_of_everything() {
    use crate::ir::scalar::{FieldPath, FieldPathSegment};

    let empty = FieldPath::empty();
    assert!(empty.is_empty());
    assert_eq!(empty.len(), 0);

    let nonempty =
        FieldPath::from_field_steps(&[FieldStep::Field("a".into()), FieldStep::Index(2)]);
    assert!(empty.is_prefix_of(&nonempty));
    assert!(empty.is_prefix_of(&empty));
    assert!(!nonempty.is_prefix_of(&empty));

    // Sanity on segment types.
    match &nonempty.segments()[0] {
        FieldPathSegment::Field(k) => {
            assert_eq!(k, &IdentKey::new("a"));
        }
        FieldPathSegment::Index(_) | FieldPathSegment::Dynamic => panic!("wrong segment"),
    }
    match &nonempty.segments()[1] {
        FieldPathSegment::Index(i) => assert_eq!(*i, 2),
        FieldPathSegment::Field(_) | FieldPathSegment::Dynamic => panic!("wrong segment"),
    }
}

#[test]
fn field_path_field_segment_normalizes_case() {
    use crate::ir::scalar::FieldPath;

    // Unquoted identifiers fold case via `IdentKey::new`.
    let lower = FieldPath::from_field_steps(&[FieldStep::Field("payload".into())]);
    let upper = FieldPath::from_field_steps(&[FieldStep::Field("PAYLOAD".into())]);
    assert_eq!(lower, upper);
    assert!(lower.is_prefix_of(&upper));
    assert!(upper.is_prefix_of(&lower));
}

#[test]
fn field_path_dynamic_index_collapses() {
    use crate::ir::scalar::{FieldPath, FieldPathSegment};

    let dyn_path = FieldPath::from_field_steps(&[
        FieldStep::Field("payload".into()),
        FieldStep::IndexExpr(Box::new(lit_int(1))),
        FieldStep::Field("id".into()),
    ]);
    assert_eq!(dyn_path.len(), 3);
    assert!(dyn_path.has_dynamic());
    match &dyn_path.segments()[1] {
        FieldPathSegment::Dynamic => {}
        FieldPathSegment::Field(_) | FieldPathSegment::Index(_) => panic!("expected Dynamic"),
    }
}

#[test]
fn field_path_prefix_dynamic_widens_match() {
    use crate::ir::scalar::FieldPath;

    // Constraint over `payload[expr]` covers `payload[5]` (dynamic
    // could have selected it).
    let dyn_idx = FieldPath::from_field_steps(&[
        FieldStep::Field("payload".into()),
        FieldStep::IndexExpr(Box::new(lit_int(0))),
    ]);
    let concrete =
        FieldPath::from_field_steps(&[FieldStep::Field("payload".into()), FieldStep::Index(5)]);
    assert!(dyn_idx.is_prefix_of(&concrete));
    // Symmetric: a fact about `payload[5]` is also treated as
    // applicable when the lookup is the dynamic one.
    assert!(concrete.is_prefix_of(&dyn_idx));
}

#[test]
fn field_path_disjoint_paths_are_not_prefixes() {
    use crate::ir::scalar::FieldPath;

    let id = FieldPath::from_field_steps(&[
        FieldStep::Field("payload".into()),
        FieldStep::Field("id".into()),
    ]);
    let name = FieldPath::from_field_steps(&[
        FieldStep::Field("payload".into()),
        FieldStep::Field("name".into()),
    ]);
    assert!(!id.is_prefix_of(&name));
    assert!(!name.is_prefix_of(&id));
}

#[test]
fn field_path_static_prefix_covers_descendants() {
    use crate::ir::scalar::FieldPath;

    // `payload` covers `payload.id` and `payload.id[3]`.
    let base = FieldPath::from_field_steps(&[FieldStep::Field("payload".into())]);
    let mid = FieldPath::from_field_steps(&[
        FieldStep::Field("payload".into()),
        FieldStep::Field("id".into()),
    ]);
    let leaf = FieldPath::from_field_steps(&[
        FieldStep::Field("payload".into()),
        FieldStep::Field("id".into()),
        FieldStep::Index(3),
    ]);
    assert!(base.is_prefix_of(&mid));
    assert!(base.is_prefix_of(&leaf));
    assert!(mid.is_prefix_of(&leaf));
    // And not in the reverse direction (sub-fact does not cover whole).
    assert!(!leaf.is_prefix_of(&base));
    assert!(!mid.is_prefix_of(&base));
}

// ─── ScanModifier projection ────────────────────────────────────────────
//
// These tests pin the canonical typed projection of `ScanModifier`
// into `ScanModifierFact`. They exercise every sub-field — `time_travel`,
// `changes`, `hints`, `stage_options`, `origin` — so a future addition
// to any of those (or to the underlying closed enums `TimeTravel` /
// `OriginHint`) fails compilation here until the projection is
// updated. The walk is also exercised across enclosing wrappers so a
// new `RelPlan` variant that hides scan reachability surfaces.

#[test]
fn scan_modifier_default_projects_to_minimal_fact() {
    use crate::ir::derived_facts::{derive_scan_modifier_facts, OriginTag, ScanModifierFact};

    let mut alloc = ColumnIdAllocator::new();
    let plan = scan(&mut alloc, 1, span(10, 20));
    let facts = derive_scan_modifier_facts(&plan);

    assert_eq!(
        facts,
        vec![ScanModifierFact {
            table: tref("t"),
            alias: None,
            time_travel: None,
            changes: None,
            hint_count: 0,
            has_stage_options: false,
            origin: OriginTag::Direct,
            span: span(10, 20),
        }]
    );
}

#[test]
fn scan_modifier_every_field_round_trips() {
    use crate::ir::derived_facts::{
        derive_scan_modifier_facts, ChangesTag, OriginTag, TimeTravelTag,
    };
    use crate::ir::plan::{ChangesClause, ChangesInformation, Hint, OriginHint, TimeTravel};

    let columns = vec![ColumnId::new(0), ColumnId::new(1)];
    let modifier = ScanModifier {
        time_travel: Some(TimeTravel::AtOffset(lit_int(-60))),
        changes: Some(ChangesClause {
            information: ChangesInformation::AppendOnly,
            at: Some(TimeTravel::AtTimestamp(lit_int(0))),
            end: Some(TimeTravel::BeforeStatement(lit_int(0))),
        }),
        hints: vec![
            Hint {
                text: "/*+ NOLOCK */".into(),
                span: span(0, 0),
            },
            Hint {
                text: "/*+ INDEX(t pk) */".into(),
                span: span(0, 0),
            },
        ],
        stage_options: Some(span(40, 60)),
        origin: OriginHint::DbtRef {
            macro_span: span(0, 5),
            target: "orders".into(),
        },
        ..Default::default()
    };
    let plan = RelPlan::Scan {
        table: tref("orders"),
        columns,
        modifier,
        alias: Some(ident("o")),
        node_id: nid(),
        span: span(100, 200),
        hints: Vec::new(),
    };

    let facts = derive_scan_modifier_facts(&plan);
    assert_eq!(facts.len(), 1);
    let f = &facts[0];
    assert_eq!(f.table, tref("orders"));
    assert_eq!(f.alias, Some(ident("o")));
    assert_eq!(f.time_travel, Some(TimeTravelTag::AtOffset));
    assert_eq!(
        f.changes,
        Some(ChangesTag {
            information: ChangesInformation::AppendOnly,
            at: Some(TimeTravelTag::AtTimestamp),
            end: Some(TimeTravelTag::BeforeStatement),
        })
    );
    assert_eq!(f.hint_count, 2);
    assert!(f.has_stage_options);
    assert_eq!(f.origin, OriginTag::DbtRef);
    assert_eq!(f.span, span(100, 200));
}

#[test]
fn scan_modifier_walk_descends_through_wrappers() {
    use crate::ir::derived_facts::derive_scan_modifier_facts;

    // `WithScope { ctes: [..], body: Project(Filter(Join(Scan, Scan))) }`
    // — every wrapper on the path must surface both leaf scans.
    let mut alloc = ColumnIdAllocator::new();
    let left = scan(&mut alloc, 1, span(1, 2));
    let right = scan(&mut alloc, 1, span(3, 4));
    let join = RelPlan::Join {
        left: Box::new(left),
        right: Box::new(right),
        kind: JoinKind::Inner,
        on: None,
        match_condition: None,
        using: vec![],
        natural: false,
        directed: false,
        lateral: false,
        implicit: false,
        node_id: nid(),
        span: span(5, 6),
        clause_span: span(5, 6),
        hints: Vec::new(),
    };
    let filter = RelPlan::Filter {
        input: Box::new(join),
        kind: FilterKind::Where,
        predicate: lit_int(1),
        node_id: nid(),
        span: span(7, 8),
        hints: Vec::new(),
    };
    let project = RelPlan::Project {
        input: Box::new(filter),
        items: vec![],
        distinct: false,
        distinct_on: Vec::new(),
        node_id: nid(),
        span: span(9, 10),
        hints: Vec::new(),
    };
    let cte_inner = scan(&mut alloc, 1, span(11, 12));
    let with_scope = RelPlan::WithScope {
        ctes: vec![CteBinding {
            name: ident("cte"),
            scope: ScopeId(1),
            declared_columns: None,
            body: CteBody::NonRecursive(Box::new(cte_inner)),
            output_columns: vec![],
            node_id: nid(),
            span: span(13, 14),
        }],
        body: Box::new(project),
        recursive: false,
        node_id: nid(),
        span: span(15, 16),
        hints: Vec::new(),
    };

    let facts = derive_scan_modifier_facts(&with_scope);
    assert_eq!(facts.len(), 3, "expected three Scan leaves, got {facts:?}");
}
