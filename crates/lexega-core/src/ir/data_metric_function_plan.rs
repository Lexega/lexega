// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for Snowflake `CREATE / DROP DATA METRIC FUNCTION`.
//!
//! A data metric function (DMF) is a SQL function returning a NUMBER that
//! measures table data (e.g. null counts); it is attached to tables via
//! `ALTER TABLE … ADD DATA METRIC FUNCTION` (handled separately on the
//! table-alter side). This carrier covers the function's own lifecycle.
//! `SECURE` hides the function definition — the only governance-relevant
//! recognition primitive at the CREATE site.

use crate::ast::types::AstCreateDataMetricFunction;
use crate::ast::{AstDrop, NodeId};
use crate::ir::utils::slice_span;
use crate::lexer::token::Span;

#[derive(Debug, Clone)]
pub struct DataMetricFunctionPlan {
    pub action: DataMetricFunctionAction,
    pub target: Option<DataMetricFunctionTarget>,
    /// `SECURE` modifier present (definition hidden).
    pub is_secure: bool,
    pub options: DataMetricFunctionOptions,
    pub node_id: NodeId,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DataMetricFunctionAction {
    Create,
    Drop,
}

#[derive(Debug, Clone)]
pub struct DataMetricFunctionTarget {
    pub name: String,
    pub span: Span,
}

#[derive(Debug, Clone, Default)]
pub struct DataMetricFunctionOptions {
    pub or_replace: bool,
    pub if_not_exists: bool,
    pub if_exists: bool,
}

/// Lower a typed [`AstCreateDataMetricFunction`] into a plan.
pub fn lower_create_data_metric_function_to_plan(
    s: &AstCreateDataMetricFunction,
    source: &str,
) -> DataMetricFunctionPlan {
    DataMetricFunctionPlan {
        action: DataMetricFunctionAction::Create,
        target: Some(target_from_span(source, s.name_span)),
        is_secure: s.secure_span.is_some(),
        options: DataMetricFunctionOptions {
            or_replace: s.or_replace_span.is_some(),
            if_not_exists: s.if_not_exists_span.is_some(),
            if_exists: false,
        },
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a generic [`AstDrop`] whose object type is DATA METRIC FUNCTION.
/// The caller gates on the object type.
pub fn lower_drop_data_metric_function_to_plan(
    s: &AstDrop,
    source: &str,
) -> DataMetricFunctionPlan {
    DataMetricFunctionPlan {
        action: DataMetricFunctionAction::Drop,
        target: s
            .target_name_span
            .map(|span| target_from_span(source, span)),
        is_secure: false,
        options: DataMetricFunctionOptions {
            or_replace: false,
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
        },
        node_id: s.node_id,
        span: s.span,
    }
}

fn target_from_span(source: &str, span: Span) -> DataMetricFunctionTarget {
    DataMetricFunctionTarget {
        name: slice_span(source, span).unwrap_or("").trim().to_string(),
        span,
    }
}
