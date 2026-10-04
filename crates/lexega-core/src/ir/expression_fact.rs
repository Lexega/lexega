// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! `ScalarExpr → ExpressionFact` bridge.
//!
//! Projects an IR-level [`crate::ir::ScalarExpr`] tree onto the
//! [`crate::context::node_metadata::ExpressionFact`]
//! surface used by `JoinEdge::on_clause`, `WherePredicate`, and the
//! projection-item facts. Lives in
//! `src/ir/` because it is part of the IR-derived projection
//! pipeline (`derive_facts_from_plan`).
//!
//! ## Closed-enum discipline
//!
//! [`scalar_to_expression_fact`] matches every [`ScalarExpr`] variant
//! exhaustively. There is no `_ =>` catch-all; new variants must be
//! added explicitly. The same rule applies to [`Lit`], [`FieldStep`],
//! [`QuantifiedRhs`], [`QuantifiedCmpKind`], and the
//! [`ResolvedFunc`] inspection — all are exhaustive.
//!
//! ## Resolution model
//!
//! Two side-tables are required to project a scalar:
//!
//! - [`BindingTable`] — maps each [`ColumnId`] to its
//!   [`ColumnBinding`] (display name + origin). Built by the
//!   `ColumnIdAllocator` during lowering and returned with the plan.
//! - [`ScanIndex`] — maps the [`crate::ast::NodeId`] held in
//!   [`ColumnOrigin::Table`] to the [`TableRef`] of the producing
//!   `Scan` or `CteRef`. Built once per plan via
//!   [`build_scan_index`] (linear walk).
//!
//! With both side-tables, a `ScalarExpr::Column { column }` resolves
//! to an [`ExpressionFact::Column`] carrying the column's display
//! name and (where determinable) `resolved_table`. The
//! `resolved_table` is what makes `qualifier`-keyed semantic
//! diff (`a.id == u.id`) work — `ColumnRef::PartialEq` ignores
//! qualifier when both sides have a `resolved_table`.
//!
//! ## Opaque fallback policy
//!
//! Three classes of `ScalarExpr` carry no `ExpressionFact`-shaped
//! analog and project to [`ExpressionFact::Opaque`] with a
//! diagnostic text:
//!
//! - [`ScalarExpr::OuterRef`] — correlation references.
//! - [`ScalarExpr::Lambda`] — higher-order function bodies;
//!   surfaced as opaque text.
//! - [`ScalarExpr::Opaque`] — parser recovery placeholder; carries
//!   its own `reason` string.
//!
//! [`Lit`]: crate::ir::scalar::Lit
//! [`FieldStep`]: crate::ir::scalar::FieldStep
//! [`QuantifiedRhs`]: crate::ir::scalar::QuantifiedRhs
//! [`QuantifiedCmpKind`]: crate::ir::scalar::Quantifier
//! [`ResolvedFunc`]: crate::ir::plan::ResolvedFunc
//! [`ColumnId`]: crate::ir::column::ColumnId
//! [`ColumnBinding`]: crate::ir::column::ColumnBinding
//! [`ColumnOrigin::Table`]: crate::ir::column::ColumnOrigin

use std::collections::HashMap;

use crate::ast::NodeId;
use crate::context::node_metadata::{CaseWhenFact, ColumnRef, ExpressionFact, TableRef};
use crate::ir::column::{BindingTable, ColumnOrigin};
use crate::ir::plan::{RelPlan, ResolvedFunc};
use crate::ir::scalar::{FieldStep, Lit, QuantifiedRhs, Quantifier, ScalarExpr};

/// Map from the `NodeId` carried in [`ColumnOrigin::Table`] to the
/// [`TableRef`] of the `Scan` (or `CteRef`) that produced the
/// column. Built once per plan by [`build_scan_index`].
pub type ScanIndex = HashMap<NodeId, TableRef>;

/// Walk the plan once, recording every base-table `Scan`, every
/// `CteRef`, and every `ModelRef` keyed by their `node_id`. All three
/// kinds can appear as the `table_node` in [`ColumnOrigin::Table`]
/// (CTE references to single-scan bodies redirect column allocation
/// through the leaf scan's `NodeId`; references to general CTE
/// bodies allocate against the `CteRef`'s own `NodeId`; cross-model
/// `ModelRef`s carry their own `NodeId` for cross-scope resolution).
///
/// Descent uses the standard `RelPlanVisitor` framework: relational
/// descent via [`walk_rel_plan`](crate::ir::visitor::walk_rel_plan) is closed-enum exhaustive over
/// [`RelPlan`], and the default `walk_scalar_expr` follows
/// `ScalarExpr::Exists` / `ScalarSubquery` / `QuantifiedCmp::Subquery`
/// into their nested plans via `visit_subquery`. This ensures every
/// Scan/CteRef/ModelRef the column-refs walker can reach is
/// resolvable through this index.
pub fn build_scan_index(plan: &RelPlan) -> ScanIndex {
    use super::visitor::{walk_rel_plan, RelPlanVisitor};

    struct Builder {
        index: ScanIndex,
    }
    impl<'a> RelPlanVisitor<'a> for Builder {
        fn visit_rel_plan(&mut self, plan: &'a RelPlan) {
            match plan {
                RelPlan::Scan { table, node_id, .. } => {
                    self.index.insert(*node_id, table.clone());
                }
                RelPlan::CteRef { name, node_id, .. } => {
                    self.index
                        .insert(*node_id, TableRef::new(name.as_str().to_string()));
                }
                RelPlan::ModelRef { model, node_id, .. } => {
                    self.index.insert(*node_id, model_ref_to_table_ref(model));
                }
                RelPlan::Values { .. }
                | RelPlan::TableFunction { .. }
                | RelPlan::CreateTableForm { .. }
                | RelPlan::ParseRecovery { .. }
                | RelPlan::Opaque { .. }
                | RelPlan::InvalidInput { .. }
                | RelPlan::Filter { .. }
                | RelPlan::Project { .. }
                | RelPlan::Aggregate { .. }
                | RelPlan::Window { .. }
                | RelPlan::Sort { .. }
                | RelPlan::Limit { .. }
                | RelPlan::TableSample { .. }
                | RelPlan::Pivot { .. }
                | RelPlan::Unpivot { .. }
                | RelPlan::MatchRecognize { .. }
                | RelPlan::ConnectBy { .. }
                | RelPlan::Unnest { .. }
                | RelPlan::DerivedTable { .. }
                | RelPlan::Join { .. }
                | RelPlan::SetOp { .. }
                | RelPlan::WithScope { .. }
                | RelPlan::Explain { .. }
                | RelPlan::CreateAsQuery { .. }
                | RelPlan::Insert { .. }
                | RelPlan::Update { .. }
                | RelPlan::Delete { .. }
                | RelPlan::Merge { .. }
                | RelPlan::MultiInsert { .. } => {}
            }
            walk_rel_plan(self, plan);
        }
    }

    let mut b = Builder {
        index: ScanIndex::new(),
    };
    b.visit_rel_plan(plan);
    b.index
}

/// Reconstruct a [`TableRef`] for a `ResolvedModel` boundary from
/// the model's resolved relation name. The lowerer stores the
/// original `scan_table.canonical()` blob in `model.name` (e.g.
/// `"analytics.staging.stg_orders"`) along with `model.package =
/// scan_table.schema`. We split the canonical form back into the
/// `(db, schema, name)` triple that downstream consumers expect:
/// 3-segment → `db.schema.name`, 2-segment → `schema.name` (or
/// `package.name` when canonical didn't include a db), 1-segment
/// → bare `name`.
fn model_ref_to_table_ref(model: &super::plan::ResolvedModel) -> TableRef {
    let parts: Vec<&str> = model.name.splitn(3, '.').collect();
    match parts.as_slice() {
        [db, schema, name] => TableRef {
            server: None,
            db: Some((*db).to_string()),
            schema: Some((*schema).to_string()),
            name: (*name).to_string(),
            span: None,
        },
        [schema, name] => TableRef {
            server: None,
            db: None,
            schema: Some((*schema).to_string()),
            name: (*name).to_string(),
            span: None,
        },
        [name] => TableRef {
            server: None,
            db: None,
            schema: model.package.clone(),
            name: (*name).to_string(),
            span: None,
        },
        _ => TableRef::new(model.name.clone()),
    }
}

/// Project an IR `ScalarExpr` tree onto an [`ExpressionFact`] tree.
///
/// Exhaustive, closed-enum match over every [`ScalarExpr`] variant.
/// See module docs for the resolution model and opaque-fallback
/// policy.
pub fn scalar_to_expression_fact(
    expr: &ScalarExpr,
    bindings: &BindingTable,
    scan_index: &ScanIndex,
) -> ExpressionFact {
    match expr {
        ScalarExpr::Column { column, .. } => {
            let (display_name, resolved_table) = match bindings.get(*column) {
                Some(binding) => {
                    let table = match &binding.origin {
                        ColumnOrigin::Table { table_node, .. } => {
                            scan_index.get(table_node).cloned()
                        }
                        ColumnOrigin::Computed { .. }
                        | ColumnOrigin::SetOp { .. }
                        | ColumnOrigin::OuterRef { .. }
                        | ColumnOrigin::RecursiveRef { .. } => None,
                    };
                    (binding.display_name.clone(), table)
                }
                None => (String::new(), None),
            };
            let mut col = ColumnRef::new(display_name);
            if let Some(t) = resolved_table {
                col = col.with_resolved_table(t);
            }
            ExpressionFact::Column(col)
        }
        // Pattern-variable-qualified reference: projected
        // as a plain column reference; the symbol qualifier is
        // metadata that the projection surface does not preserve.
        ScalarExpr::PatternVarRef { column, .. } => {
            let display_name = bindings
                .get(*column)
                .map(|b| b.display_name.clone())
                .unwrap_or_default();
            ExpressionFact::Column(ColumnRef::new(display_name))
        }
        ScalarExpr::OuterRef { .. } => ExpressionFact::Opaque {
            text: "<outer-ref>".to_string(),
        },
        ScalarExpr::Lit { value, .. } => lit_to_expression_fact(value),
        ScalarExpr::BinOp {
            op, left, right, ..
        } => ExpressionFact::BinaryOp {
            left: Box::new(scalar_to_expression_fact(left, bindings, scan_index)),
            operator: op.as_sql_str().to_string(),
            right: Box::new(scalar_to_expression_fact(right, bindings, scan_index)),
        },
        ScalarExpr::LogicalChain { op, operands, .. } => ExpressionFact::LogicalChain {
            operator: op.as_sql_str().to_string(),
            operands: operands
                .iter()
                .map(|o| scalar_to_expression_fact(o, bindings, scan_index))
                .collect(),
        },
        // Pattern matches project to a dedicated typed
        // `ExpressionFact::Like` (negation and ESCAPE are first-class), not
        // a nested `BinaryOp { operator: "NOT LIKE" }` +
        // `BinaryOp { operator: "ESCAPE" }` wrapper.
        ScalarExpr::Like {
            kind,
            negated,
            expr,
            pattern,
            escape,
            ..
        } => ExpressionFact::Like {
            kind: kind.as_sql_str().to_string(),
            negated: *negated,
            expr: Box::new(scalar_to_expression_fact(expr, bindings, scan_index)),
            pattern: Box::new(scalar_to_expression_fact(pattern, bindings, scan_index)),
            escape: escape
                .as_deref()
                .map(|e| Box::new(scalar_to_expression_fact(e, bindings, scan_index))),
        },
        ScalarExpr::UnaryOp { op, arg, .. } => ExpressionFact::UnaryOp {
            operator: op.as_sql_str().to_string(),
            operand: Box::new(scalar_to_expression_fact(arg, bindings, scan_index)),
        },
        ScalarExpr::FuncCall {
            func,
            args,
            named_args,
            distinct,
            ..
        } => {
            let name = resolved_func_display_name(func);
            // Positional and named arguments project
            // into a single flat `args` list (named
            // args contribute their value, the name is dropped). Lambda
            // arguments ride inside `args` as `ScalarExpr::Lambda`
            // values and are handled by the recursive call.
            let mut arg_facts: Vec<ExpressionFact> =
                Vec::with_capacity(args.len() + named_args.len());
            for a in args {
                arg_facts.push(scalar_to_expression_fact(a, bindings, scan_index));
            }
            for (_name, value) in named_args {
                arg_facts.push(scalar_to_expression_fact(value, bindings, scan_index));
            }
            ExpressionFact::Function {
                name,
                args: arg_facts,
                is_distinct: *distinct,
            }
        }
        ScalarExpr::Case {
            operand,
            branches,
            else_,
            ..
        } => {
            // Simple-CASE form (`CASE x WHEN v THEN …`) is desugared
            // into searched-CASE form for fact projection by rewriting
            // each `WHEN v` branch to `WHEN x = v`, since the
            // `ExpressionFact::Case` shape has no operand slot.
            let when_branches: Vec<CaseWhenFact> = branches
                .iter()
                .map(|(cond, result)| {
                    let cond_fact = match operand {
                        Some(op_expr) => ExpressionFact::BinaryOp {
                            left: Box::new(scalar_to_expression_fact(
                                op_expr, bindings, scan_index,
                            )),
                            operator: "=".to_string(),
                            right: Box::new(scalar_to_expression_fact(cond, bindings, scan_index)),
                        },
                        None => scalar_to_expression_fact(cond, bindings, scan_index),
                    };
                    CaseWhenFact {
                        condition: Box::new(cond_fact),
                        result: Box::new(scalar_to_expression_fact(result, bindings, scan_index)),
                    }
                })
                .collect();
            let else_fact = else_
                .as_ref()
                .map(|e| Box::new(scalar_to_expression_fact(e, bindings, scan_index)));
            ExpressionFact::Case {
                when_branches,
                else_expr: else_fact,
            }
        }
        ScalarExpr::Cast {
            expr, target_type, ..
        } => ExpressionFact::Cast {
            expr: Box::new(scalar_to_expression_fact(expr, bindings, scan_index)),
            target_type: target_type.repr.clone(),
        },
        ScalarExpr::InList {
            expr,
            list,
            negated,
            ..
        } => ExpressionFact::InList {
            expr: Box::new(scalar_to_expression_fact(expr, bindings, scan_index)),
            values: list
                .iter()
                .map(|v| scalar_to_expression_fact(v, bindings, scan_index))
                .collect(),
            negated: *negated,
        },
        ScalarExpr::Between {
            expr,
            low,
            high,
            negated,
            ..
        } => {
            // BETWEEN projection:
            //   x BETWEEN lo AND hi   →   x BETWEEN (lo AND hi)
            //   x NOT BETWEEN lo AND hi → x NOT BETWEEN (lo AND hi)
            // The operator string carries the NOT marker; the inner
            // `AND` is a plain `BinaryOp`.
            let operator = if *negated { "NOT BETWEEN" } else { "BETWEEN" };
            ExpressionFact::BinaryOp {
                left: Box::new(scalar_to_expression_fact(expr, bindings, scan_index)),
                operator: operator.to_string(),
                right: Box::new(ExpressionFact::BinaryOp {
                    left: Box::new(scalar_to_expression_fact(low, bindings, scan_index)),
                    operator: "AND".to_string(),
                    right: Box::new(scalar_to_expression_fact(high, bindings, scan_index)),
                }),
            }
        }
        ScalarExpr::Exists {
            subquery, negated, ..
        } => {
            let tables = collect_subquery_table_names(subquery);
            let kind = if *negated { "not_exists" } else { "exists" };
            ExpressionFact::Subquery {
                tables_referenced: tables,
                kind: kind.to_string(),
            }
        }
        ScalarExpr::ScalarSubquery { subquery, .. } => {
            let tables = collect_subquery_table_names(subquery);
            ExpressionFact::Subquery {
                tables_referenced: tables,
                kind: "scalar".to_string(),
            }
        }
        ScalarExpr::QuantifiedCmp {
            op,
            quantifier,
            negated,
            left,
            right,
            ..
        } => {
            let q_str = match quantifier {
                Quantifier::Any => "ANY",
                Quantifier::All => "ALL",
            };
            let right_fact = match right {
                QuantifiedRhs::Subquery(subquery, _) => {
                    let tables = collect_subquery_table_names(subquery);
                    ExpressionFact::Subquery {
                        tables_referenced: tables,
                        kind: "quantified".to_string(),
                    }
                }
                QuantifiedRhs::List(values) => ExpressionFact::InList {
                    expr: Box::new(scalar_to_expression_fact(left, bindings, scan_index)),
                    values: values
                        .iter()
                        .map(|v| scalar_to_expression_fact(v, bindings, scan_index))
                        .collect(),
                    negated: *negated,
                },
            };
            let cmp = ExpressionFact::BinaryOp {
                left: Box::new(scalar_to_expression_fact(left, bindings, scan_index)),
                operator: format!("{} {}", op.as_sql_str(), q_str),
                right: Box::new(right_fact),
            };
            // Preserve the `UnaryOp("NOT", ...)` wrapper shape
            // for negated quantified comparisons. The IR canonicalized
            // the NOT into the typed `negated` field, but downstream
            // consumers expect the wrap.
            if *negated {
                ExpressionFact::UnaryOp {
                    operator: "NOT".to_string(),
                    operand: Box::new(cmp),
                }
            } else {
                cmp
            }
        }
        ScalarExpr::WindowFn { call, .. } => {
            let name = resolved_func_display_name(&call.func);
            let arg_facts: Vec<ExpressionFact> = call
                .args
                .iter()
                .map(|a| scalar_to_expression_fact(a, bindings, scan_index))
                .collect();
            ExpressionFact::Function {
                name,
                args: arg_facts,
                is_distinct: call.distinct,
            }
        }
        ScalarExpr::FieldAccess {
            base, path, cast, ..
        } => {
            let base_fact = scalar_to_expression_fact(base, bindings, scan_index);
            let mut accessor_parts: Vec<String> = Vec::with_capacity(path.len());
            for step in path {
                match step {
                    FieldStep::Field(name) => accessor_parts.push(name.clone()),
                    FieldStep::Index(i) => accessor_parts.push(i.to_string()),
                    FieldStep::IndexExpr(_) => {
                        // The expression-fact surface has no slot for
                        // a recursive index expression; mark the step
                        // with a placeholder so the accessor string
                        // remains structurally faithful.
                        accessor_parts.push("<expr>".to_string());
                    }
                }
            }
            let access = ExpressionFact::Access {
                base: Box::new(base_fact),
                accessor: accessor_parts.join("."),
            };
            match cast {
                Some(t) => ExpressionFact::Cast {
                    expr: Box::new(access),
                    target_type: t.repr.clone(),
                },
                None => access,
            }
        }
        ScalarExpr::Lambda { .. } => ExpressionFact::Opaque {
            text: "<lambda>".to_string(),
        },
        ScalarExpr::Opaque { reason, .. } => ExpressionFact::Opaque {
            text: reason.clone(),
        },
    }
}

fn lit_to_expression_fact(value: &Lit) -> ExpressionFact {
    let (text, kind) = match value {
        Lit::Null => ("NULL".to_string(), "null"),
        Lit::Bool(true) => ("TRUE".to_string(), "boolean"),
        Lit::Bool(false) => ("FALSE".to_string(), "boolean"),
        Lit::Integer(s) | Lit::Float(s) => (s.clone(), "number"),
        Lit::Str(s) => (s.clone(), "string"),
        Lit::Bytes { tag, value } => (format!("{}'{}'", tag, value), "string"),
        Lit::Typed { type_name, value } => (format!("{} '{}'", type_name, value), "string"),
        Lit::Variant(s) => (s.clone(), "string"),
    };
    ExpressionFact::Literal {
        value: text,
        kind: kind.to_string(),
    }
}

fn resolved_func_display_name(func: &ResolvedFunc) -> String {
    match func {
        ResolvedFunc::Resolved { id, .. } => format!("{}", id).to_uppercase(),
        ResolvedFunc::Unresolved { raw_name, .. } => raw_name.to_uppercase(),
    }
}

/// Collect the principal-table names from a subquery plan for
/// `ExpressionFact::Subquery.tables_referenced`. This is a flat
/// list of `TableRef::canonical` strings keyed by appearance.
fn collect_subquery_table_names(plan: &RelPlan) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    walk_for_subquery_tables(plan, &mut out);
    out
}

fn walk_for_subquery_tables(plan: &RelPlan, out: &mut Vec<String>) {
    match plan {
        RelPlan::Scan { table, .. } => {
            let s = table.canonical();
            if !out.iter().any(|x| x == &s) {
                out.push(s);
            }
        }
        RelPlan::CteRef { name, .. } => {
            let s = name.as_str().to_string();
            if !out.iter().any(|x| x == &s) {
                out.push(s);
            }
        }
        RelPlan::Values { .. }
        | RelPlan::ModelRef { .. }
        | RelPlan::TableFunction { .. }
        | RelPlan::CreateTableForm { .. }
        | RelPlan::ParseRecovery { .. }
        | RelPlan::Opaque { .. }
        | RelPlan::InvalidInput { .. } => {}
        RelPlan::Filter { input, .. }
        | RelPlan::Project { input, .. }
        | RelPlan::Aggregate { input, .. }
        | RelPlan::Window { input, .. }
        | RelPlan::Sort { input, .. }
        | RelPlan::Limit { input, .. }
        | RelPlan::TableSample { input, .. }
        | RelPlan::Pivot { input, .. }
        | RelPlan::Unpivot { input, .. }
        | RelPlan::MatchRecognize { input, .. }
        | RelPlan::ConnectBy { input, .. }
        | RelPlan::Unnest { input, .. }
        | RelPlan::DerivedTable { input, .. } => walk_for_subquery_tables(input, out),
        RelPlan::Join { left, right, .. } => {
            walk_for_subquery_tables(left, out);
            walk_for_subquery_tables(right, out);
        }
        RelPlan::SetOp { inputs, .. } => {
            for branch in inputs {
                walk_for_subquery_tables(branch, out);
            }
        }
        RelPlan::WithScope { body, ctes, .. } => {
            for cte in ctes {
                match &cte.body {
                    super::plan::CteBody::NonRecursive(p) => walk_for_subquery_tables(p, out),
                    super::plan::CteBody::Recursive { anchor, step, .. } => {
                        walk_for_subquery_tables(anchor, out);
                        walk_for_subquery_tables(step, out);
                    }
                }
            }
            walk_for_subquery_tables(body, out);
        }
        RelPlan::Explain { body, .. } => walk_for_subquery_tables(body, out),
        RelPlan::CreateAsQuery { body, .. } => {
            if let Some(body) = body.as_deref() {
                walk_for_subquery_tables(body, out)
            }
        }
        RelPlan::Insert { source, .. } => match source {
            super::plan::InsertSource::Values(p) | super::plan::InsertSource::Query(p) => {
                walk_for_subquery_tables(p, out)
            }
            super::plan::InsertSource::DefaultValues => {}
        },
        RelPlan::Merge { source, .. } | RelPlan::MultiInsert { source, .. } => {
            walk_for_subquery_tables(source, out)
        }
        RelPlan::Update { from, .. } => {
            if let Some(f) = from {
                walk_for_subquery_tables(f, out);
            }
        }
        RelPlan::Delete { using, .. } => {
            if let Some(u) = using {
                walk_for_subquery_tables(u, out);
            }
        }
    }
}
