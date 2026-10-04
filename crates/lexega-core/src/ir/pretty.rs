// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Pretty-printer for [`RelPlan`] / [`ScalarExpr`]: an indented,
//! multi-line rendering of a plan tree.
//!
//! # Closed-enum discipline
//!
//! Both the plan and scalar match tables are exhaustive with no `_ =>` arm.
//! Adding a [`RelPlan`] or [`ScalarExpr`] variant will fail to compile here
//! until the new case is handled.

use std::fmt;

use super::plan::{
    CteBody, FilterKind, GroupingSpec, JoinKind, MergeAction, MergeBranch, MergeBranchKind,
    RelPlan, SetOpKind,
};
use super::scalar::{FieldStep, QuantifiedRhs, ScalarExpr};

// ────────────────────────────────────────────────────────────────────────
// Public API
// ────────────────────────────────────────────────────────────────────────

/// Display wrapper around a borrowed [`RelPlan`]. The output is indented
/// and multi-line.
pub struct PrettyPlan<'a> {
    plan: &'a RelPlan,
}

impl<'a> PrettyPlan<'a> {
    pub fn new(plan: &'a RelPlan) -> Self {
        Self { plan }
    }
}

impl<'a> fmt::Display for PrettyPlan<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_plan(f, self.plan, 0)
    }
}

impl RelPlan {
    /// Borrowed pretty-printer.
    pub fn pretty(&self) -> PrettyPlan<'_> {
        PrettyPlan::new(self)
    }
}

// ────────────────────────────────────────────────────────────────────────
// Internal formatting
// ────────────────────────────────────────────────────────────────────────

fn indent(f: &mut fmt::Formatter<'_>, depth: usize) -> fmt::Result {
    for _ in 0..depth {
        f.write_str("  ")?;
    }
    Ok(())
}

fn write_plan(f: &mut fmt::Formatter<'_>, plan: &RelPlan, depth: usize) -> fmt::Result {
    indent(f, depth)?;
    match plan {
        // ── Sources ─────────────────────────────────────────────────────
        RelPlan::Scan {
            table,
            columns,
            alias,
            ..
        } => {
            f.write_str("Scan")?;
            write!(f, "[{}]", table.name)?;
            if let Some(a) = alias {
                write!(f, " as {}", a.as_str())?;
            }
            write!(f, " <{} cols>", columns.len())?;
            writeln!(f)
        }

        RelPlan::Values { rows, columns, .. } => {
            f.write_str("Values")?;
            write!(f, " <{} rows, {} cols>", rows.len(), columns.len())?;
            writeln!(f)
        }

        RelPlan::CteRef { name, columns, .. } => {
            f.write_str("CteRef")?;
            write!(f, "[{}]", name.as_str())?;
            write!(f, " <{} cols>", columns.len())?;
            writeln!(f)
        }

        RelPlan::ModelRef { model, columns, .. } => {
            f.write_str("ModelRef")?;
            write!(f, "[{}]", model.name)?;
            write!(f, " <{} cols>", columns.len())?;
            writeln!(f)
        }

        // ── Unary ops ───────────────────────────────────────────────────
        RelPlan::Project {
            input,
            items,
            distinct,
            distinct_on,
            ..
        } => {
            f.write_str("Project")?;
            if *distinct {
                f.write_str(" ")?;
                f.write_str("distinct")?;
            }
            if !distinct_on.is_empty() {
                // Render the ON-key arity only; full key expressions
                // appear in the scalar tree above this level via the
                // visitor's descent. Keeping it terse preserves
                // snapshot stability for fixtures that don't use
                // `DISTINCT ON`.
                f.write_str(" ")?;
                f.write_str("on")?;
                write!(f, "({})", distinct_on.len())?;
            }
            write!(f, " <{} items>", items.len())?;
            writeln!(f)?;
            write_plan(f, input, depth + 1)
        }

        RelPlan::Filter {
            input,
            predicate,
            kind,
            ..
        } => {
            f.write_str("Filter")?;
            let kind_tag = match kind {
                FilterKind::Where => "where",
                FilterKind::Qualify => "qualify",
                FilterKind::Having => "having",
            };
            write!(f, "[{}] ", kind_tag)?;
            write_scalar(f, predicate)?;
            writeln!(f)?;
            write_plan(f, input, depth + 1)
        }

        RelPlan::Aggregate {
            input,
            grouping,
            aggregates,
            having,
            output_columns,
            ..
        } => {
            f.write_str("Aggregate")?;
            write!(f, " ")?;
            write_grouping_tag(f, grouping)?;
            write!(
                f,
                " <{} aggs, {} out>",
                aggregates.len(),
                output_columns.len()
            )?;
            if having.is_some() {
                f.write_str(" ")?;
                f.write_str("having")?;
            }
            writeln!(f)?;
            write_plan(f, input, depth + 1)
        }

        RelPlan::Window {
            input,
            windows,
            window_outputs,
            ..
        } => {
            f.write_str("Window")?;
            write!(
                f,
                " <{} calls, {} out>",
                windows.len(),
                window_outputs.len()
            )?;
            writeln!(f)?;
            write_plan(f, input, depth + 1)
        }

        // ── Binary ops ──────────────────────────────────────────────────
        RelPlan::Join {
            left,
            right,
            kind,
            on,
            using,
            natural,
            lateral,
            implicit,
            ..
        } => {
            f.write_str("Join")?;
            f.write_str(" ")?;
            write_join_kind(f, *kind)?;
            if *natural {
                f.write_str(" ")?;
                f.write_str("natural")?;
            }
            if *lateral {
                f.write_str(" ")?;
                f.write_str("lateral")?;
            }
            if *implicit {
                f.write_str(" ")?;
                f.write_str("implicit")?;
            }
            if !using.is_empty() {
                write!(f, " <using {} cols>", using.len())?;
            }
            if on.is_some() {
                f.write_str(" ")?;
                f.write_str("on")?;
            }
            writeln!(f)?;
            write_plan(f, left, depth + 1)?;
            write_plan(f, right, depth + 1)
        }

        RelPlan::SetOp {
            op,
            inputs,
            output_columns,
            ..
        } => {
            f.write_str("SetOp")?;
            f.write_str(" ")?;
            write_setop_kind(f, *op)?;
            write!(
                f,
                " <{} branches, {} out>",
                inputs.len(),
                output_columns.len()
            )?;
            writeln!(f)?;
            for branch in inputs {
                write_plan(f, branch, depth + 1)?;
            }
            Ok(())
        }

        // ── Ordering / limiting ─────────────────────────────────────────
        RelPlan::Sort { input, keys, .. } => {
            f.write_str("Sort")?;
            write!(f, " <{} keys>", keys.len())?;
            writeln!(f)?;
            write_plan(f, input, depth + 1)
        }

        RelPlan::Limit {
            input,
            limit,
            offset,
            kind,
            with_ties,
            ..
        } => {
            f.write_str("Limit")?;
            if matches!(kind, crate::ir::plan::LimitKind::Percent) {
                f.write_str(" ")?;
                f.write_str("pct")?;
            }
            if limit.is_some() {
                f.write_str(" ")?;
                f.write_str("limit")?;
            }
            if offset.is_some() {
                f.write_str(" ")?;
                f.write_str("offset")?;
            }
            if *with_ties {
                f.write_str(" ")?;
                f.write_str("ties")?;
            }
            writeln!(f)?;
            write_plan(f, input, depth + 1)
        }

        // ── DML ─────────────────────────────────────────────────────────
        RelPlan::Insert {
            target,
            source,
            overwrite,
            replace_into,
            on_conflict,
            returning,
            output,
            ..
        } => {
            f.write_str("Insert")?;
            write!(f, "[{}]", target.name)?;
            if *overwrite {
                f.write_str(" ")?;
                f.write_str("ovwr")?;
            }
            if *replace_into {
                f.write_str(" ")?;
                f.write_str("repl")?;
            }
            if on_conflict.is_some() {
                f.write_str(" ")?;
                f.write_str("conflict")?;
            }
            if returning.is_some() {
                f.write_str(" ")?;
                f.write_str("ret")?;
            }
            if output.is_some() {
                f.write_str(" ")?;
                f.write_str("out")?;
            }
            writeln!(f)?;
            match source {
                crate::ir::plan::InsertSource::Values(p)
                | crate::ir::plan::InsertSource::Query(p) => write_plan(f, p, depth + 1),
                crate::ir::plan::InsertSource::DefaultValues => {
                    indent(f, depth + 1)?;
                    f.write_str("default_values")?;
                    writeln!(f)
                }
            }
        }

        RelPlan::Update {
            target,
            assignments,
            from,
            predicate,
            ..
        } => {
            f.write_str("Update")?;
            write!(f, "[{}]", target.name)?;
            write!(f, " <{} sets>", assignments.len())?;
            if predicate.is_some() {
                f.write_str(" ")?;
                f.write_str("where")?;
            }
            writeln!(f)?;
            if let Some(fr) = from {
                write_plan(f, fr, depth + 1)?;
            }
            Ok(())
        }

        RelPlan::Delete {
            target,
            using,
            predicate,
            ..
        } => {
            f.write_str("Delete")?;
            write!(f, "[{}]", target.name)?;
            if predicate.is_some() {
                f.write_str(" ")?;
                f.write_str("where")?;
            }
            writeln!(f)?;
            if let Some(u) = using {
                write_plan(f, u, depth + 1)?;
            }
            Ok(())
        }

        RelPlan::Merge {
            target,
            source,
            branches,
            ..
        } => {
            f.write_str("Merge")?;
            write!(f, "[{}]", target.name)?;
            write!(f, " <{} branches>", branches.len())?;
            writeln!(f)?;
            write_plan(f, source, depth + 1)?;
            for b in branches {
                indent(f, depth + 1)?;
                write_merge_branch_tag(f, b)?;
                writeln!(f)?;
            }
            Ok(())
        }

        RelPlan::MultiInsert {
            mode,
            unconditional_clauses,
            when_clauses,
            else_clauses,
            source,
            ..
        } => {
            f.write_str("MultiInsert")?;
            f.write_str(" ")?;
            match mode {
                crate::ir::plan::MultiInsertMode::UnconditionalAll => f.write_str("all")?,
                crate::ir::plan::MultiInsertMode::ConditionalFirst => f.write_str("cfirst")?,
                crate::ir::plan::MultiInsertMode::ConditionalAll => f.write_str("call")?,
            }
            write!(
                f,
                " <{} uncond, {} when, {} else>",
                unconditional_clauses.len(),
                when_clauses.len(),
                else_clauses.len(),
            )?;
            writeln!(f)?;
            write_plan(f, source, depth + 1)
        }

        RelPlan::Explain { body, options, .. } => {
            f.write_str("Explain")?;
            if options.analyze {
                f.write_str(" ")?;
                f.write_str("analyze")?;
            }
            writeln!(f)?;
            write_plan(f, body, depth + 1)
        }

        RelPlan::CreateAsQuery {
            target,
            kind,
            body,
            or_replace,
            or_alter,
            side_options,
            ..
        } => {
            f.write_str("CreateAsQuery")?;
            f.write_str(" ")?;
            match kind {
                crate::ir::plan::CreateAsKind::View { materialized, .. } => {
                    if *materialized {
                        f.write_str("mview")?;
                    } else {
                        f.write_str("view")?;
                    }
                }
                crate::ir::plan::CreateAsKind::Table { .. } => f.write_str("ctas")?,
                crate::ir::plan::CreateAsKind::DynamicTable { iceberg, .. } => {
                    if *iceberg {
                        f.write_str("dyn_iceberg")?;
                    } else {
                        f.write_str("dyn")?;
                    }
                }
            }
            write!(f, "[{}]", target.name)?;
            if *or_replace {
                f.write_str(" ")?;
                f.write_str("replace")?;
            }
            if *or_alter {
                f.write_str(" ")?;
                f.write_str("alter")?;
            }
            if !side_options.is_empty() {
                write!(f, " <{} opts>", side_options.len())?;
            }
            if body.is_none() {
                f.write_str(" nobody")?;
            }
            writeln!(f)?;
            if let Some(body) = body.as_deref() {
                write_plan(f, body, depth + 1)
            } else {
                Ok(())
            }
        }

        // ── Non-query-bearing DDL ────────────────────────────────────────
        RelPlan::CreateTableForm {
            target,
            kind,
            or_replace,
            if_not_exists,
            ..
        } => {
            f.write_str("CreateTableForm")?;
            write!(f, "/{}", kind.as_str())?;
            write!(f, "[{}]", target.name)?;
            if *or_replace {
                f.write_str(" ")?;
                f.write_str("replace")?;
            }
            if *if_not_exists {
                f.write_str(" ")?;
                f.write_str("ifnotexists")?;
            }
            writeln!(f)
        }

        // ── CTE scoping ─────────────────────────────────────────────────
        RelPlan::WithScope {
            ctes,
            body,
            recursive,
            ..
        } => {
            f.write_str("WithScope")?;
            if *recursive {
                f.write_str(" ")?;
                f.write_str("recursive")?;
            }
            write!(f, " <{} ctes>", ctes.len())?;
            writeln!(f)?;
            for c in ctes {
                indent(f, depth + 1)?;
                f.write_str("cte")?;
                write!(f, "[{}]", c.name.as_str())?;
                writeln!(f)?;
                match &c.body {
                    CteBody::NonRecursive(p) => write_plan(f, p, depth + 2)?,
                    CteBody::Recursive { anchor, step, .. } => {
                        indent(f, depth + 2)?;
                        f.write_str("anchor")?;
                        writeln!(f)?;
                        write_plan(f, anchor, depth + 3)?;
                        indent(f, depth + 2)?;
                        f.write_str("step")?;
                        writeln!(f)?;
                        write_plan(f, step, depth + 3)?;
                    }
                }
            }
            write_plan(f, body, depth + 1)
        }

        RelPlan::DerivedTable { input, columns, .. } => {
            f.write_str("DerivedTable")?;
            write!(f, " <{} out>", columns.len())?;
            writeln!(f)?;
            write_plan(f, input, depth + 1)
        }

        RelPlan::TableFunction {
            output_columns,
            lateral,
            modifier,
            ..
        } => {
            f.write_str("TableFunction")?;
            if *lateral {
                f.write_str(" ")?;
                f.write_str("lateral")?;
            }
            write!(f, " <{} out>", output_columns.len())?;
            if modifier.with_offset.is_some() {
                f.write_str(" ")?;
                f.write_str("+with_offset")?;
            }
            if modifier.tvf_schema.is_some() {
                f.write_str(" ")?;
                f.write_str("+tvf_schema")?;
            }
            if modifier.time_travel.is_some() {
                f.write_str(" ")?;
                f.write_str("+time_travel")?;
            }
            if modifier.changes.is_some() {
                f.write_str(" ")?;
                f.write_str("+changes")?;
            }
            writeln!(f)
        }

        // ── Dialect-exotic ──────────────────────────────────────────────
        RelPlan::Unnest {
            input,
            ordinality_column,
            with_offset,
            preserve_nulls,
            ..
        } => {
            f.write_str("Unnest")?;
            if ordinality_column.is_some() {
                f.write_str(" ")?;
                f.write_str("ordinality")?;
            }
            if *with_offset {
                f.write_str(" ")?;
                f.write_str("offset")?;
            }
            if *preserve_nulls {
                f.write_str(" ")?;
                f.write_str("outer")?;
            }
            writeln!(f)?;
            write_plan(f, input, depth + 1)
        }

        RelPlan::Pivot {
            input,
            pivot_values,
            output_columns,
            ..
        } => {
            f.write_str("Pivot")?;
            write!(
                f,
                " <{} values, {} out>",
                pivot_values.len(),
                output_columns.len()
            )?;
            writeln!(f)?;
            write_plan(f, input, depth + 1)
        }

        RelPlan::Unpivot {
            input,
            unpivoted_columns,
            include_nulls,
            ..
        } => {
            f.write_str("Unpivot")?;
            write!(f, " <{} cols>", unpivoted_columns.len())?;
            if *include_nulls {
                f.write_str(" ")?;
                f.write_str("nulls")?;
            }
            writeln!(f)?;
            write_plan(f, input, depth + 1)
        }

        RelPlan::MatchRecognize {
            input,
            body,
            output_columns,
            ..
        } => {
            f.write_str("MatchRecognize")?;
            write!(
                f,
                " <{} out, {} part, {} meas, {} def, {} sym>",
                output_columns.len(),
                body.partition_by.len(),
                body.measures.len(),
                body.define.len(),
                body.symbols.len(),
            )?;
            writeln!(f)?;
            write_plan(f, input, depth + 1)
        }

        RelPlan::ConnectBy {
            input,
            start_with,
            nocycle,
            output_columns,
            ..
        } => {
            f.write_str("ConnectBy")?;
            if start_with.is_some() {
                f.write_str(" ")?;
                f.write_str("start")?;
            }
            if *nocycle {
                f.write_str(" ")?;
                f.write_str("nocycle")?;
            }
            write!(f, " <{} out>", output_columns.len())?;
            writeln!(f)?;
            write_plan(f, input, depth + 1)
        }

        RelPlan::TableSample { input, .. } => {
            f.write_str("TableSample")?;
            writeln!(f)?;
            write_plan(f, input, depth + 1)
        }

        // ── Parser recovery ─────────────────────────────────────────────
        RelPlan::ParseRecovery { .. } => {
            f.write_str("ParseRecovery")?;
            writeln!(f)
        }
        RelPlan::Opaque { reason, .. } => {
            f.write_str("Opaque")?;
            f.write_str(" ")?;
            write_opaque_reason(f, reason)?;
            writeln!(f)
        }
        RelPlan::InvalidInput { kind, .. } => {
            f.write_str("InvalidInput")?;
            f.write_str(" ")?;
            write_invalid_input_kind(f, kind)?;
            writeln!(f)
        }
    }
}

// ── Scalar pretty (shallow: just variant tag) ───────────────────────────

fn write_scalar(f: &mut fmt::Formatter<'_>, expr: &ScalarExpr) -> fmt::Result {
    match expr {
        ScalarExpr::Column { column, .. } => {
            f.write_str("col")?;
            write!(f, "({})", column)
        }
        ScalarExpr::PatternVarRef { symbol, column, .. } => {
            f.write_str("pvar")?;
            write!(f, "(s{}, {})", symbol.0, column)
        }
        ScalarExpr::OuterRef { scope, column, .. } => {
            f.write_str("outer")?;
            write!(f, "(s{}, {})", scope.0, column)
        }
        ScalarExpr::Lit { .. } => f.write_str("lit"),
        ScalarExpr::BinOp { op, .. } => {
            f.write_str("binop")?;
            write!(f, "[{}]", op)
        }
        ScalarExpr::LogicalChain { op, operands, .. } => {
            f.write_str("chain")?;
            write!(f, "[{}]/{}", op, operands.len())
        }
        ScalarExpr::Like { kind, negated, .. } => {
            f.write_str("like")?;
            write!(f, "[{}{}]", if *negated { "NOT " } else { "" }, kind)
        }
        ScalarExpr::UnaryOp { op, .. } => {
            f.write_str("unop")?;
            write!(f, "[{}]", op)
        }
        ScalarExpr::FuncCall { func, args, .. } => {
            f.write_str("func")?;
            write!(f, "[{}]/{}", func.display_hint(), args.len())
        }
        ScalarExpr::Case { branches, .. } => {
            f.write_str("case")?;
            write!(f, "/{}", branches.len())
        }
        ScalarExpr::Cast { try_cast, .. } => {
            if *try_cast {
                f.write_str("trycast")
            } else {
                f.write_str("cast")
            }
        }
        ScalarExpr::InList { negated, list, .. } => {
            if *negated {
                f.write_str("notin")?;
            } else {
                f.write_str("in")?;
            }
            write!(f, "/{}", list.len())
        }
        ScalarExpr::Between { negated, .. } => {
            if *negated {
                f.write_str("notbetween")
            } else {
                f.write_str("between")
            }
        }
        ScalarExpr::Exists { negated, .. } => {
            if *negated {
                f.write_str("notexists")
            } else {
                f.write_str("exists")
            }
        }
        ScalarExpr::ScalarSubquery { .. } => f.write_str("subquery"),
        ScalarExpr::QuantifiedCmp { op, right, .. } => {
            f.write_str("quant")?;
            write!(f, "[{}]", op)?;
            match right {
                QuantifiedRhs::Subquery(_, _) => {
                    f.write_str(" ")?;
                    f.write_str("subq")
                }
                QuantifiedRhs::List(items) => write!(f, " /{}", items.len()),
            }
        }
        ScalarExpr::WindowFn { .. } => f.write_str("winfn"),
        ScalarExpr::FieldAccess { path, cast, .. } => {
            f.write_str("field")?;
            write!(f, "/{}", path.len())?;
            // Reach every FieldStep variant exhaustively so adding a new
            // one surfaces here.
            for step in path {
                match step {
                    FieldStep::Field(_) | FieldStep::Index(_) | FieldStep::IndexExpr(_) => {}
                }
            }
            if cast.is_some() {
                f.write_str(" ")?;
                f.write_str("cast")?;
            }
            Ok(())
        }
        ScalarExpr::Opaque { .. } => f.write_str("opaque"),
        ScalarExpr::Lambda { params, .. } => {
            f.write_str("lambda")?;
            write!(f, "/{}", params.len())
        }
    }
}

// ── Tag writers for closed sub-enums ────────────────────────────────────

fn write_grouping_tag(f: &mut fmt::Formatter<'_>, g: &GroupingSpec) -> fmt::Result {
    match g {
        GroupingSpec::None => f.write_str("none"),
        GroupingSpec::Standard(_) => f.write_str("group"),
        GroupingSpec::Cube(_) => f.write_str("cube"),
        GroupingSpec::Rollup(_) => f.write_str("rollup"),
        GroupingSpec::GroupingSets(_) => f.write_str("sets"),
        GroupingSpec::All(_) => f.write_str("all"),
    }
}

fn write_join_kind(f: &mut fmt::Formatter<'_>, k: JoinKind) -> fmt::Result {
    match k {
        JoinKind::Inner => f.write_str("inner"),
        JoinKind::LeftOuter => f.write_str("left"),
        JoinKind::RightOuter => f.write_str("right"),
        JoinKind::FullOuter => f.write_str("full"),
        JoinKind::Cross => f.write_str("cross"),
        JoinKind::Asof => f.write_str("asof"),
        JoinKind::LeftSemi => f.write_str("lsemi"),
        JoinKind::RightSemi => f.write_str("rsemi"),
        JoinKind::LeftAnti => f.write_str("lanti"),
        JoinKind::RightAnti => f.write_str("ranti"),
    }
}

fn write_setop_kind(f: &mut fmt::Formatter<'_>, k: SetOpKind) -> fmt::Result {
    match k {
        SetOpKind::UnionAll => f.write_str("ua"),
        SetOpKind::UnionDistinct => f.write_str("ud"),
        SetOpKind::IntersectAll => f.write_str("ia"),
        SetOpKind::IntersectDistinct => f.write_str("id"),
        SetOpKind::ExceptAll => f.write_str("ea"),
        SetOpKind::ExceptDistinct => f.write_str("ed"),
    }
}

fn write_merge_branch_tag(f: &mut fmt::Formatter<'_>, b: &MergeBranch) -> fmt::Result {
    match b.kind {
        MergeBranchKind::WhenMatched => f.write_str("matched")?,
        MergeBranchKind::WhenNotMatched => f.write_str("nomatch")?,
        MergeBranchKind::WhenNotMatchedBySource => f.write_str("nomatchsrc")?,
    }
    f.write_str(" ")?;
    match &b.action {
        MergeAction::Insert { .. } => f.write_str("ins"),
        MergeAction::InsertStar => f.write_str("insstar"),
        MergeAction::InsertAllByName => f.write_str("insname"),
        MergeAction::Update { .. } => f.write_str("upd"),
        MergeAction::UpdateSetStar => f.write_str("updstar"),
        MergeAction::UpdateAllByName => f.write_str("updname"),
        MergeAction::Delete => f.write_str("del"),
        MergeAction::DoNothing => f.write_str("nop"),
    }
}

fn write_opaque_reason(f: &mut fmt::Formatter<'_>, r: &super::strict::OpaqueReason) -> fmt::Result {
    use super::strict::OpaqueReason as R;
    match r {
        R::UnresolvedJinja { .. } => f.write_str("jinja"),
        R::UnknownFunction { .. } => f.write_str("unkfn"),
        R::NonSelectTopLevel => f.write_str("nonselecttop"),
        R::CatalogMissing { .. } => f.write_str("catmiss"),
        R::ExpressionTooDeep { .. } => f.write_str("exprdepth"),
    }
}

fn write_invalid_input_kind(
    f: &mut fmt::Formatter<'_>,
    k: &super::invalid_input::InvalidInputKind,
) -> fmt::Result {
    use super::invalid_input::InvalidInputKind as K;
    match k {
        K::Dml(_) => f.write_str("dmlerr"),
        K::WindowContext(_) => f.write_str("winctxerr"),
        K::AggregateContext(_) => f.write_str("aggctxerr"),
        K::GroupByOrdinal(_) => f.write_str("gbyordinalerr"),
        K::ConflictingAggregateOrderings => f.write_str("conflictord"),
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
    use crate::ir::column::{ColumnId, ColumnIdAllocator};
    use crate::ir::plan::{ProjectExpr, ProjectItem, ScanModifier};
    use crate::ir::scalar::Lit;
    use crate::ir::strict::OpaqueReason;
    use crate::lexer::token::Span;

    fn sp() -> Span {
        Span { start: 0, end: 0 }
    }
    fn nid() -> NodeId {
        NodeId::new(0)
    }
    fn tref(name: &str) -> TableRef {
        TableRef::new(name.to_string())
    }
    fn col(id: ColumnId) -> ScalarExpr {
        ScalarExpr::Column {
            column: id,
            span: sp(),
        }
    }
    fn lit(n: i64) -> ScalarExpr {
        ScalarExpr::Lit {
            value: Lit::Integer(n.to_string()),
            span: sp(),
        }
    }

    fn scan(alloc: &mut ColumnIdAllocator, name: &str, n: usize) -> RelPlan {
        let columns: Vec<ColumnId> = (0..n).map(|_| alloc.fresh_test()).collect();
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
    fn pretty_emits_labels() {
        let mut alloc = ColumnIdAllocator::new();
        let s = scan(&mut alloc, "t", 2);
        let f = RelPlan::Filter {
            input: Box::new(s),
            predicate: ScalarExpr::BinOp {
                op: crate::ir::scalar::BinOpKind::Cmp(crate::ir::scalar::ComparisonOp::Eq),
                left: Box::new(col(ColumnId::new(0))),
                right: Box::new(lit(1)),
                span: sp(),
            },
            kind: FilterKind::Where,
            node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        };
        let out = format!("{}", f.pretty());
        assert!(out.contains("Filter"), "got: {out}");
        assert!(out.contains("Scan"), "got: {out}");
        assert!(out.contains("binop"), "got: {out}");
        // Nesting: Scan line is indented relative to Filter.
        let lines: Vec<&str> = out.lines().collect();
        assert!(lines[0].starts_with("Filter"));
        assert!(lines[1].starts_with("  Scan"));
    }

    #[test]
    fn pretty_handles_every_top_level_tag_without_panic() {
        let mut alloc = ColumnIdAllocator::new();
        let plans = [
            scan(&mut alloc, "t", 1),
            RelPlan::ParseRecovery {
                stmt_node_id: nid(),
                span: sp(),
                hints: Vec::new(),
            },
            RelPlan::Opaque {
                stmt_node_id: nid(),
                reason: OpaqueReason::NonSelectTopLevel,
                span: sp(),
                hints: Vec::new(),
            },
            RelPlan::Project {
                input: Box::new(scan(&mut alloc, "p", 1)),
                items: vec![ProjectItem::Expr(ProjectExpr {
                    output: alloc.fresh_test(),
                    expr: lit(0),
                    alias: None,
                    span: sp(),
                })],
                distinct: true,
                distinct_on: Vec::new(),
                node_id: nid(),
                span: sp(),
                hints: Vec::new(),
            },
        ];
        for p in &plans {
            let _ = format!("{}", p.pretty());
        }
    }
}
