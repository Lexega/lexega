// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Closed enumeration of *ill-formed-input* shapes the lowerer
//! detects.
//!
//! Distinct from [`super::strict::OpaqueReason`]: ill-formed input is
//! not a *gap* in IR coverage — it is the typed answer the IR gives
//! for SQL that survived the parser but is semantically invalid in
//! its enclosing context (e.g. DML missing target, GROUP BY ordinal
//! out of range, aggregate in WHERE). The lowerer captures the
//! failure shape as a typed terminal [`super::plan::RelPlan::InvalidInput`]
//! so every analysis still walks the surrounding plan and the
//! ill-formedness is visible to rules.

use super::strict::{
    AggregateContextCategory, DmlShapeCategory, GroupByOrdinalCategory, WindowContextCategory,
};

/// Closed enumeration of ill-formed-input shapes detected during
/// lowering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidInputKind {
    /// DML input shape that survived parsing but cannot be lowered.
    /// Carries the closed [`DmlShapeCategory`] sub-enum.
    Dml(DmlShapeCategory),
    /// Window-function context violation. Carries the
    /// closed [`WindowContextCategory`] sub-enum.
    WindowContext(WindowContextCategory),
    /// Aggregate-context violation. Carries the closed
    /// [`AggregateContextCategory`] sub-enum.
    AggregateContext(AggregateContextCategory),
    /// `GROUP BY` ordinal error. Carries the closed
    /// [`GroupByOrdinalCategory`] sub-enum.
    GroupByOrdinal(GroupByOrdinalCategory),
    /// Aggregate call specifying both an inline `ORDER BY` inside
    /// its argument list and a SQL-standard `WITHIN GROUP (ORDER BY
    /// …)` clause. These are distinct operators;
    /// specifying both is a SQL shape error.
    ConflictingAggregateOrderings,
}

impl InvalidInputKind {
    /// Stable snake_case label for harness histograms / pretty
    /// output. Format: `"<bucket>::<category>"` so the bucket is
    /// always readable. Exhaustive — adding a variant fails
    /// compilation here.
    pub fn as_str(self) -> &'static str {
        match self {
            InvalidInputKind::Dml(cat) => match cat {
                DmlShapeCategory::InsertQueryWithoutBody => "dml::insert_query_without_body",
                DmlShapeCategory::InsertUnknownSource => "dml::insert_unknown_source",
                DmlShapeCategory::MultiInsertWithoutSource => "dml::multi_insert_without_source",
                DmlShapeCategory::UpdateWithoutTarget => "dml::update_without_target",
                DmlShapeCategory::DeleteWithoutTarget => "dml::delete_without_target",
                DmlShapeCategory::MergeWithoutSource => "dml::merge_without_source",
                DmlShapeCategory::MergeWithoutOn => "dml::merge_without_on",
                DmlShapeCategory::DmlWithoutTargetTable => "dml::dml_without_target_table",
                DmlShapeCategory::CreateTableCtasWithoutQuery => {
                    "dml::create_table_ctas_without_query"
                }
            },
            InvalidInputKind::WindowContext(cat) => match cat {
                WindowContextCategory::FunctionOutsideWindowContext => {
                    "window_context::function_outside_window_context"
                }
                WindowContextCategory::FunctionInDisallowedContext => {
                    "window_context::function_in_disallowed_context"
                }
                WindowContextCategory::FrameBoundMissingValue => {
                    "window_context::frame_bound_missing_value"
                }
                WindowContextCategory::NamedReferenceOutOfCurrentScope => {
                    "window_context::named_reference_out_of_current_scope"
                }
                WindowContextCategory::WithinGroupOutOfCurrentScope => {
                    "window_context::within_group_out_of_current_scope"
                }
                WindowContextCategory::FilterClauseOutOfCurrentScope => {
                    "window_context::filter_clause_out_of_current_scope"
                }
                WindowContextCategory::NamedArgsOnWindowCall => {
                    "window_context::named_args_on_window_call"
                }
                WindowContextCategory::LambdaOnWindowCallOutOfCurrentScope => {
                    "window_context::lambda_on_window_call_out_of_current_scope"
                }
            },
            InvalidInputKind::AggregateContext(cat) => match cat {
                AggregateContextCategory::InDisallowedContext => {
                    "aggregate_context::in_disallowed_context"
                }
                AggregateContextCategory::ModifierOutsideAggregateContext => {
                    "aggregate_context::modifier_outside_aggregate_context"
                }
            },
            InvalidInputKind::GroupByOrdinal(cat) => match cat {
                GroupByOrdinalCategory::OutOfRange => "group_by_ordinal::out_of_range",
                GroupByOrdinalCategory::NonInteger => "group_by_ordinal::non_integer",
                GroupByOrdinalCategory::QualifiedPositionRef => {
                    "group_by_ordinal::qualified_position_ref"
                }
            },
            InvalidInputKind::ConflictingAggregateOrderings => "conflicting_aggregate_orderings",
        }
    }

    /// High-level bucket label (one of `"dml"`, `"window_context"`,
    /// `"aggregate_context"`, `"group_by_ordinal"`,
    /// `"conflicting_aggregate_orderings"`). Useful for harness
    /// histograms that want the bucket without the sub-category.
    pub fn bucket(self) -> &'static str {
        match self {
            InvalidInputKind::Dml(_) => "dml",
            InvalidInputKind::WindowContext(_) => "window_context",
            InvalidInputKind::AggregateContext(_) => "aggregate_context",
            InvalidInputKind::GroupByOrdinal(_) => "group_by_ordinal",
            InvalidInputKind::ConflictingAggregateOrderings => "conflicting_aggregate_orderings",
        }
    }
}
