// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Free outer references for a [`RelPlan`] subtree.
//!
//! `free_outer_refs: Set<(ScopeId, ColumnId)>` is a derived property of
//! every `RelPlan` subtree, computed by walking the plan
//! tree (including subqueries) and collecting every
//! [`ScalarExpr::OuterRef`]. No local scope shadowing is subtracted —
//! any `OuterRef` appearing inside the tree is free.
//!
//! The result is a `BTreeSet<(ScopeId, ColumnId)>` so iteration order is
//! deterministic for snapshot-based tests.

use std::collections::BTreeSet;

use super::column::ColumnId;
// `FilterKind` is re-exported to the in-file `#[cfg(test)]` module
// via `use super::*;`; it is unused in the lib-only build path.
#[cfg_attr(not(test), allow(unused_imports))]
use super::plan::{FilterKind, RelPlan};
use super::scalar::{ScalarExpr, ScopeId};
use super::visitor::{walk_rel_plan, RelPlanVisitor};

impl RelPlan {
    /// Free outer references in this subtree.
    ///
    /// Returns the set of `(scope, column)` pairs that appear as
    /// [`ScalarExpr::OuterRef`] anywhere inside `self`, recursing through
    /// subqueries.
    ///
    /// No shadowing subtraction (see module docs).
    pub fn free_outer_refs(&self) -> BTreeSet<(ScopeId, ColumnId)> {
        let mut v = FreeOuterRefs {
            out: BTreeSet::new(),
        };
        v.visit_rel_plan(self);
        v.out
    }
}

struct FreeOuterRefs {
    out: BTreeSet<(ScopeId, ColumnId)>,
}

impl<'a> RelPlanVisitor<'a> for FreeOuterRefs {
    fn visit_rel_plan(&mut self, plan: &'a RelPlan) {
        walk_rel_plan(self, plan);
    }

    fn visit_scalar_expr(&mut self, expr: &'a ScalarExpr) {
        if let ScalarExpr::OuterRef { scope, column, .. } = expr {
            self.out.insert((*scope, *column));
        }
        // Recurse into the scalar tree — critical so outer refs inside
        // nested expressions (function args, CASE branches, subqueries)
        // are collected too.
        super::visitor::walk_scalar_expr(self, expr);
    }

    fn visit_subquery(&mut self, plan: &'a RelPlan, _correlates_with: &'a [ColumnId]) {
        // Outer refs inside a subquery are still free with respect to this
        // subtree.
        self.visit_rel_plan(plan);
    }
}

// ────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::NodeId;
    use crate::context::node_metadata::TableRef;
    use crate::ir::column::ColumnIdAllocator;
    use crate::ir::plan::{ProjectExpr, ProjectItem, ScanModifier};
    use crate::ir::scalar::{Lit, ScalarExpr, ScopeId};
    use crate::lexer::Span;

    fn sp() -> Span {
        Span { start: 0, end: 0 }
    }
    fn nid() -> NodeId {
        NodeId::new(0)
    }

    fn scan(alloc: &mut ColumnIdAllocator, n: usize) -> RelPlan {
        let columns: Vec<ColumnId> = (0..n).map(|_| alloc.fresh_test()).collect();
        RelPlan::Scan {
            table: TableRef::new("t".to_string()),
            columns,
            modifier: ScanModifier::default(),
            alias: None,
            node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        }
    }

    fn outer(scope: u32, col: u32) -> ScalarExpr {
        ScalarExpr::OuterRef {
            scope: ScopeId(scope),
            column: ColumnId::new(col),
            span: sp(),
        }
    }

    #[test]
    fn no_outer_refs_empty() {
        let mut alloc = ColumnIdAllocator::new();
        let s = scan(&mut alloc, 2);
        assert!(s.free_outer_refs().is_empty());
    }

    #[test]
    fn outer_ref_in_filter_is_collected() {
        let mut alloc = ColumnIdAllocator::new();
        let s = scan(&mut alloc, 1);
        let plan = RelPlan::Filter {
            input: Box::new(s),
            predicate: ScalarExpr::BinOp {
                op: crate::ir::scalar::BinOpKind::Cmp(crate::ir::scalar::ComparisonOp::Eq),
                left: Box::new(outer(3, 7)),
                right: Box::new(ScalarExpr::Lit {
                    value: Lit::Integer("1".into()),
                    span: sp(),
                }),
                span: sp(),
            },
            kind: FilterKind::Where,
            node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        };
        let refs = plan.free_outer_refs();
        assert_eq!(refs.len(), 1);
        assert!(refs.contains(&(ScopeId(3), ColumnId::new(7))));
    }

    #[test]
    fn outer_ref_inside_exists_subquery_is_collected() {
        let mut alloc = ColumnIdAllocator::new();
        let outer_scan = scan(&mut alloc, 1);
        let inner_scan = scan(&mut alloc, 1);
        // EXISTS ( SELECT 1 FROM t WHERE outer_col = 42 ) — outer_col is
        // really an OuterRef with scope 1.
        let subquery = RelPlan::Filter {
            input: Box::new(inner_scan),
            predicate: outer(1, 99),
            kind: FilterKind::Where,
            node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        };
        let plan = RelPlan::Filter {
            input: Box::new(outer_scan),
            predicate: ScalarExpr::Exists {
                subquery: Box::new(subquery),
                correlates_with: vec![ColumnId::new(99)],
                negated: false,
                span: sp(),
            },
            kind: FilterKind::Where,
            node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        };
        let refs = plan.free_outer_refs();
        assert_eq!(refs.len(), 1);
        assert!(refs.contains(&(ScopeId(1), ColumnId::new(99))));
    }

    #[test]
    fn duplicate_outer_refs_deduplicate() {
        let mut alloc = ColumnIdAllocator::new();
        let s = scan(&mut alloc, 1);
        // Two references to the same (scope, column) — set dedupes.
        let plan = RelPlan::Project {
            input: Box::new(s),
            items: vec![
                ProjectItem::Expr(ProjectExpr {
                    output: alloc.fresh_test(),
                    expr: outer(5, 11),
                    alias: None,
                    span: sp(),
                }),
                ProjectItem::Expr(ProjectExpr {
                    output: alloc.fresh_test(),
                    expr: outer(5, 11),
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
        assert_eq!(plan.free_outer_refs().len(), 1);
    }

    #[test]
    fn multiple_distinct_outer_refs_preserved() {
        let mut alloc = ColumnIdAllocator::new();
        let s = scan(&mut alloc, 1);
        let plan = RelPlan::Project {
            input: Box::new(s),
            items: vec![
                ProjectItem::Expr(ProjectExpr {
                    output: alloc.fresh_test(),
                    expr: outer(1, 10),
                    alias: None,
                    span: sp(),
                }),
                ProjectItem::Expr(ProjectExpr {
                    output: alloc.fresh_test(),
                    expr: outer(2, 10),
                    alias: None,
                    span: sp(),
                }),
                ProjectItem::Expr(ProjectExpr {
                    output: alloc.fresh_test(),
                    expr: outer(1, 11),
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
        let refs = plan.free_outer_refs();
        assert_eq!(refs.len(), 3);
    }

    #[test]
    fn btreeset_ordering_is_deterministic() {
        let mut alloc = ColumnIdAllocator::new();
        let s = scan(&mut alloc, 1);
        let plan = RelPlan::Project {
            input: Box::new(s),
            items: vec![
                ProjectItem::Expr(ProjectExpr {
                    output: alloc.fresh_test(),
                    expr: outer(2, 1),
                    alias: None,
                    span: sp(),
                }),
                ProjectItem::Expr(ProjectExpr {
                    output: alloc.fresh_test(),
                    expr: outer(1, 2),
                    alias: None,
                    span: sp(),
                }),
                ProjectItem::Expr(ProjectExpr {
                    output: alloc.fresh_test(),
                    expr: outer(1, 1),
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
        let refs: Vec<_> = plan.free_outer_refs().into_iter().collect();
        assert_eq!(
            refs,
            vec![
                (ScopeId(1), ColumnId::new(1)),
                (ScopeId(1), ColumnId::new(2)),
                (ScopeId(2), ColumnId::new(1)),
            ]
        );
    }
}
