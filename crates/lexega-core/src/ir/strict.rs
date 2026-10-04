// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Strictness plumbing for the Relational IR pipeline.

use crate::lexer::Span;

/// How strictly the IR pipeline treats fallbacks.
///
/// - `Permissive`: `RelPlan::Opaque` nodes are allowed; analyses skip them.
///   Default for LSP and interactive CLI use.
/// - `Strict`: Lowering must produce a fully-typed plan with no
///   `Opaque` fallbacks. Intended for CI (`LEXEGA_STRICT=1`).
/// - `Pedantic`: `Strict` plus a violation for every statement whose
///   analysis could not be completed. Intended for release validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StrictMode {
    #[default]
    Permissive,
    Strict,
    Pedantic,
}

impl StrictMode {
    /// User-facing label for this mode. Kept deliberately generic.
    pub fn as_str(self) -> &'static str {
        match self {
            StrictMode::Permissive => "off",
            StrictMode::Strict => "strict",
            StrictMode::Pedantic => "pedantic",
        }
    }

    /// True if opaque fallbacks should cause an error.
    pub fn forbids_opaque(self) -> bool {
        !matches!(self, StrictMode::Permissive)
    }
}

/// Why a node was lowered to [`super::plan::RelPlan::Opaque`].
///
/// Discriminated so reporting is precise and so `Strict` can distinguish
/// "known-limitation" opacity (accept-listed in CI) from real regressions.
///
/// # Closed-enum discipline
///
/// This enum is **closed** alongside `RelPlan` and `ScalarExpr`. The
/// same discipline applies to the nested sub-enums below
/// (`SelectClauseFeature`, `WindowContextCategory`,
/// `AggregateContextCategory`, `DmlShapeCategory`,
/// `GroupByOrdinalCategory`): they are the secondary granularity, and
/// a new lowering site must pick the variant whose meaning matches —
/// never widen a variant's meaning to accommodate a new site.
#[derive(Debug, Clone)]
pub enum OpaqueReason {
    /// Jinja template fragment the renderer could not resolve.
    UnresolvedJinja { macro_name: Option<String> },
    // Parser failures are not a variant here: they route through
    // LowerError::ParseUpstream → RelPlan::ParseRecovery.
    /// A function call whose name was not found in the active
    /// [`crate::ir::FunctionCatalog`]. Permissive mode stores the
    /// call as [`crate::ir::ResolvedFunc::Unresolved`] and continues;
    /// strict-IR mode surfaces this reason so the caller knows the
    /// catalog is incomplete for the input.
    UnknownFunction { raw_name: String },

    // Shapes that are not variants here because they lower to typed
    // nodes: bare `SELECT` (`Project` over a synthetic one-row
    // `Values`), star projections (`ProjectItem::Star`), every
    // `AstExpr` discriminant (a concrete `ScalarExpr`), `ConnectBy`
    // (`RelPlan::ConnectBy` in `lower_select_body`), and all subquery
    // shapes (`ScalarSubquery`, `Exists`, `InSubquery`,
    // `QuantifiedSubquery`).
    //
    // Conflicting aggregate orderings and window-context,
    // aggregate-context, DML-shape and `GROUP BY`-ordinal errors
    // route through [`crate::ir::invalid_input::InvalidInputKind`]
    // attached to a typed [`super::plan::RelPlan::InvalidInput`]
    // terminal. Ill-formed input is the typed answer, not a coverage
    // gap, so this conversion is unconditional under every
    // [`StrictMode`].
    /// A top-level statement that isn't query-bearing. The IR is
    /// not invoked on these; the variant exists for harness
    /// bookkeeping when the dispatcher is asked to lower one anyway.
    NonSelectTopLevel,
    /// An expression nested deeper than the analyzer walks.
    /// The input is valid SQL — this bounds the fixed stack shared by
    /// every consumer of the lowered tree, so it is a coverage limit
    /// rather than a modelling gap. Permanent: no future lowering makes
    /// a fixed stack unbounded.
    ///
    /// `AND` / `OR` runs do not reach this bound; the parser flattens
    /// them and [`crate::ir::scalar::ScalarExpr::LogicalChain`] keeps
    /// them flat. It is the non-associative chains (`a - b - c …`,
    /// `a / b / c …`), which cannot be re-associated, that can.
    ExpressionTooDeep { depth: usize },
    /// A lookup the current analysis needs from the attached
    /// [`crate::ir::CatalogContext`] could not be satisfied.
    ///
    /// Permissive mode silently falls back to empty results. Strict-IR
    /// mode surfaces this reason so callers know the catalog is
    /// incomplete for the input.
    ///
    /// `kind` identifies the lookup that failed; the set is closed by
    /// [`CatalogLookupKind`].
    CatalogMissing { kind: CatalogLookupKind },
}

/// Closed enumeration of catalog lookups that an IR analysis can
/// require. Each variant maps to a specific lowering context
/// (currently: MERGE star / by-name actions).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogLookupKind {
    /// A MERGE `INSERT *` / `INSERT ALL` action whose target column
    /// list could not be resolved against the catalog.
    MergeInsertStar,
    /// A MERGE `UPDATE SET *` action whose target column list could
    /// not be resolved against the catalog.
    MergeUpdateStar,
    /// A MERGE `INSERT ALL BY NAME` action whose target column list
    /// could not be resolved against the catalog.
    MergeInsertByName,
    /// A MERGE `UPDATE ALL BY NAME` action whose target column list
    /// could not be resolved against the catalog.
    MergeUpdateByName,
    /// A `PIVOT … IN (ANY [ORDER BY …])` clause whose distinct-value
    /// set could not be resolved against the catalog. The lookup is
    /// against the input scan's `pivot_column`; a complete catalog
    /// supplies the distinct-values list, after which the lowering
    /// would synthesize one output `ColumnId` per (aggregate, value)
    /// pair as in the `PivotValues::ValueList` case.
    PivotAnyDistinctValues,
}

impl CatalogLookupKind {
    pub fn as_str(self) -> &'static str {
        match self {
            CatalogLookupKind::MergeInsertStar => "merge_insert_star",
            CatalogLookupKind::MergeUpdateStar => "merge_update_star",
            CatalogLookupKind::MergeInsertByName => "merge_insert_by_name",
            CatalogLookupKind::MergeUpdateByName => "merge_update_by_name",
            CatalogLookupKind::PivotAnyDistinctValues => "pivot_any_distinct_values",
        }
    }
}

/// Window-context violations detected during lowering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowContextCategory {
    FunctionOutsideWindowContext,
    FunctionInDisallowedContext,
    FrameBoundMissingValue,
    NamedReferenceOutOfCurrentScope,
    WithinGroupOutOfCurrentScope,
    FilterClauseOutOfCurrentScope,
    NamedArgsOnWindowCall,
    LambdaOnWindowCallOutOfCurrentScope,
}

/// Aggregate-context violations detected during lowering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AggregateContextCategory {
    InDisallowedContext,
    ModifierOutsideAggregateContext,
}

/// DML input shapes that survived parsing but cannot be lowered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmlShapeCategory {
    InsertQueryWithoutBody,
    InsertUnknownSource,
    MultiInsertWithoutSource,
    UpdateWithoutTarget,
    DeleteWithoutTarget,
    MergeWithoutSource,
    MergeWithoutOn,
    DmlWithoutTargetTable,
    CreateTableCtasWithoutQuery,
}

/// `GROUP BY` ordinal errors detected during lowering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupByOrdinalCategory {
    OutOfRange,
    NonInteger,
    QualifiedPositionRef,
}

impl WindowContextCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            WindowContextCategory::FunctionOutsideWindowContext => {
                "function_outside_window_context"
            }
            WindowContextCategory::FunctionInDisallowedContext => "function_in_disallowed_context",
            WindowContextCategory::FrameBoundMissingValue => "frame_bound_missing_value",
            WindowContextCategory::NamedReferenceOutOfCurrentScope => {
                "named_reference_out_of_current_scope"
            }
            WindowContextCategory::WithinGroupOutOfCurrentScope => {
                "within_group_out_of_current_scope"
            }
            WindowContextCategory::FilterClauseOutOfCurrentScope => {
                "filter_clause_out_of_current_scope"
            }
            WindowContextCategory::NamedArgsOnWindowCall => "named_args_on_window_call",
            WindowContextCategory::LambdaOnWindowCallOutOfCurrentScope => {
                "lambda_on_window_call_out_of_current_scope"
            }
        }
    }
}

impl AggregateContextCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            AggregateContextCategory::InDisallowedContext => "in_disallowed_context",
            AggregateContextCategory::ModifierOutsideAggregateContext => {
                "modifier_outside_aggregate_context"
            }
        }
    }
}

impl DmlShapeCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            DmlShapeCategory::InsertQueryWithoutBody => "insert_query_without_body",
            DmlShapeCategory::InsertUnknownSource => "insert_unknown_source",
            DmlShapeCategory::MultiInsertWithoutSource => "multi_insert_without_source",
            DmlShapeCategory::UpdateWithoutTarget => "update_without_target",
            DmlShapeCategory::DeleteWithoutTarget => "delete_without_target",
            DmlShapeCategory::MergeWithoutSource => "merge_without_source",
            DmlShapeCategory::MergeWithoutOn => "merge_without_on",
            DmlShapeCategory::DmlWithoutTargetTable => "dml_without_target_table",
            DmlShapeCategory::CreateTableCtasWithoutQuery => "create_table_ctas_without_query",
        }
    }
}

impl GroupByOrdinalCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            GroupByOrdinalCategory::OutOfRange => "out_of_range",
            GroupByOrdinalCategory::NonInteger => "non_integer",
            GroupByOrdinalCategory::QualifiedPositionRef => "qualified_position_ref",
        }
    }
}

impl OpaqueReason {
    pub fn tag(&self) -> &'static str {
        match self {
            OpaqueReason::UnresolvedJinja { .. } => "unresolved_jinja",
            OpaqueReason::UnknownFunction { .. } => "unknown_function",
            OpaqueReason::NonSelectTopLevel => "non_select_top_level",
            OpaqueReason::CatalogMissing { .. } => "catalog_missing",
            OpaqueReason::ExpressionTooDeep { .. } => "expression_too_deep",
        }
    }

    /// Whether an [`super::plan::RelPlan::Opaque`] carrying this reason
    /// means analysis of the statement was *lost* — findings that would
    /// otherwise have been produced were not — as opposed to never
    /// having applied to the statement in the first place.
    ///
    /// This drives the report's confidence level only. It deliberately
    /// does not feed the statement-coverage counts: those are defined in
    /// terms of what the parser achieved (`statements_skipped` renders
    /// as "could not parse, no analysis"), and these statements parse.
    ///
    /// It must stay a discriminator, not a synonym for "is opaque".
    /// The bar is: *we would have produced findings here and did not*.
    /// Each `false` arm below clears that bar for its own reason — one
    /// shared justification would paper over the differences — so read
    /// them individually before changing one.
    pub fn indicates_lost_analysis(&self) -> bool {
        match self {
            // The statement was never query-bearing; the query lowering
            // correctly declined it and another family modelled it.
            // ~40% of statements in the fixture corpus (every `USE
            // ROLE`, `CREATE STAGE`, `ALTER TABLE` …).
            OpaqueReason::NonSelectTopLevel => false,
            // Has a dedicated channel (`jinja_blocks`,
            // `render_completeness`, `placeholders.top_sources` names
            // the macro) and does not suppress findings anyway — a
            // predicate beside an unresolvable `FROM` macro still fires.
            OpaqueReason::UnresolvedJinja { .. } => false,
            // Optional enrichment, not loss: the catalog is
            // user-supplied and absent by choice. A rule needing it
            // yields no verdict by design rather than a wrong one —
            // this engine never guesses.
            OpaqueReason::CatalogMissing { .. } => false,
            // Not loss: the function catalog is ours and finite, so an
            // unrecognized name is our gap, not missing user input.
            // Permissive lowering continues with
            // `ResolvedFunc::Unresolved` inside a typed plan — findings
            // in the statement still fire.
            OpaqueReason::UnknownFunction { .. } => false,
            // The input is valid SQL we declined to walk, so the whole
            // statement's plan collapses and every finding in it is
            // lost.
            OpaqueReason::ExpressionTooDeep { .. } => true,
        }
    }
}

#[cfg(test)]
mod lost_analysis_tests {
    use super::{CatalogLookupKind, OpaqueReason};

    #[test]
    fn only_genuine_loss_degrades_confidence() {
        // Absent optional enrichment is not loss. This engine never
        // guesses: a rule needing a catalog it was not given yields no
        // verdict by design, and reporting that as reduced confidence
        // would tell users a correct run was unreliable.
        assert!(!OpaqueReason::CatalogMissing {
            kind: CatalogLookupKind::PivotAnyDistinctValues,
        }
        .indicates_lost_analysis());

        // Separate rationale: the function catalog is ours and finite,
        // so this is our gap rather than missing user input — and
        // permissive lowering continues with a typed plan, so findings
        // in the statement still fire. Nothing is lost to report.
        assert!(!OpaqueReason::UnknownFunction {
            raw_name: "some_udf".to_string(),
        }
        .indicates_lost_analysis());

        // Not query-bearing — another fact family models these.
        assert!(!OpaqueReason::NonSelectTopLevel.indicates_lost_analysis());

        // Reported through the render/placeholder channel, and does not
        // suppress findings.
        assert!(!OpaqueReason::UnresolvedJinja { macro_name: None }.indicates_lost_analysis());

        // Valid SQL we declined to walk: the plan collapses and every
        // finding in the statement is lost.
        assert!(OpaqueReason::ExpressionTooDeep { depth: 500 }.indicates_lost_analysis());
    }
}

/// Analysis options threaded from the CLI / LSP down to the analyzer.
///
/// Carries the IR-relevant fields only; other options (dialect, catalog,
/// rule filters) are passed alongside this.
#[derive(Debug, Clone, Default)]
pub struct AnalysisOptions {
    pub strict: StrictMode,
    /// Optional explicit source-span override for diagnostics emitted from
    /// the IR pipeline when the span cannot be inferred.
    pub default_span: Option<Span>,
}

impl AnalysisOptions {
    pub fn permissive() -> Self {
        Self::default()
    }

    pub fn strict() -> Self {
        Self {
            strict: StrictMode::Strict,
            default_span: None,
        }
    }

    pub fn pedantic() -> Self {
        Self {
            strict: StrictMode::Pedantic,
            default_span: None,
        }
    }
}
