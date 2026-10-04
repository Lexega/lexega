// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Sibling carrier for non-query DDL policy facts.
//!
//! `PolicyStatementFacts` is the home for facts (`PasswordPolicyFact`
//! / `SessionPolicyFact` / etc.) that are populated only when the
//! AST is a
//! `CREATE/ALTER PASSWORD POLICY`, `CREATE/ALTER SESSION POLICY`,
//! `CREATE/ALTER NETWORK POLICY`, etc.
//!
//! # Where this fits
//!
//! These statements are **not** query-shaped — they have no
//! [`super::plan::RelPlan`] body, no column flow, no analytical
//! projections. They are typed structured data attached to specific
//! DDL statement variants. They do not belong:
//!
//! - on `RelPlan` (no relational shape)
//! - on `StatementFacts` (not non-relational sibling-tier of a query)
//!
//! They form their own carrier — this enum — lowered beside the plan
//! for the relevant DDL statements.
//!
//! # Closed enum
//!
//! Consumers match exhaustively (no `_ =>` arms, no string blobs).

use crate::context::node_metadata::{
    AggregationPolicyFact, ApiIntegrationFact, AuthenticationPolicyFact, IdentKey,
    NetworkPolicyFact, PasswordPolicyFact, ProjectionPolicyFact, SessionPolicyFact, TableRef,
};
use crate::lexer::Span;

use super::column::ColumnId;
use super::scalar::ScalarExpr;

/// Closed enum of non-query DDL policy facts.
///
/// Exactly one variant matches a `CREATE/ALTER POLICY` statement;
/// the variant carries the policy-specific structured data.
/// Consumers (rule matchers, CLI output) dispatch on the variant
/// via exhaustive match.
#[derive(Debug, Clone)]
pub enum PolicyStatementFacts {
    /// `CREATE/ALTER PASSWORD POLICY`.
    Password(PasswordPolicyFact),
    /// `CREATE/ALTER SESSION POLICY`.
    Session(SessionPolicyFact),
    /// `CREATE/ALTER AUTHENTICATION POLICY`.
    Authentication(AuthenticationPolicyFact),
    /// `CREATE/ALTER NETWORK POLICY`.
    Network(NetworkPolicyFact),
    /// `CREATE/ALTER AGGREGATION POLICY`.
    Aggregation(AggregationPolicyFact),
    /// `CREATE/ALTER PROJECTION POLICY`.
    Projection(ProjectionPolicyFact),
    /// `CREATE/ALTER API INTEGRATION`.
    ApiIntegration(ApiIntegrationFact),
    /// `CREATE/ALTER ROW ACCESS POLICY` (Snowflake / BigQuery).
    /// Carries the lowered RLS body predicate.
    RowAccess(RowAccessPolicyFact),
    /// `CREATE/ALTER MASKING POLICY` (Snowflake). Carries the
    /// lowered body expression.
    Masking(MaskingPolicyFact),
    /// `CREATE/ALTER POLICY ... ON <table>` (PostgreSQL row-level
    /// security). Carries the lowered `USING` and `WITH CHECK`
    /// predicates.
    PgPolicy(PgPolicyFact),
}

impl PolicyStatementFacts {
    /// Stable label for diagnostics / signal emission. Closed-enum
    /// exhaustive — adding a variant fails compilation here.
    pub fn kind_label(&self) -> &'static str {
        match self {
            PolicyStatementFacts::Password(_) => "password_policy",
            PolicyStatementFacts::Session(_) => "session_policy",
            PolicyStatementFacts::Authentication(_) => "authentication_policy",
            PolicyStatementFacts::Network(_) => "network_policy",
            PolicyStatementFacts::Aggregation(_) => "aggregation_policy",
            PolicyStatementFacts::Projection(_) => "projection_policy",
            PolicyStatementFacts::ApiIntegration(_) => "api_integration",
            PolicyStatementFacts::RowAccess(_) => "row_access_policy",
            PolicyStatementFacts::Masking(_) => "masking_policy",
            PolicyStatementFacts::PgPolicy(_) => "pg_policy",
        }
    }
}

/// `CREATE/ALTER ROW ACCESS POLICY` fact carrier.
///
/// Snowflake form: `CREATE ROW ACCESS POLICY p AS (params)
/// RETURNS BOOLEAN -> <body>`. BigQuery form: `CREATE ROW
/// ACCESS POLICY p ON t [GRANT TO (...)] FILTER USING
/// (<body>)`. Both shapes lower their boolean predicate into
/// the `body` slot.
#[derive(Debug, Clone)]
pub struct RowAccessPolicyFact {
    /// Span covering the entire policy DDL statement.
    pub span: Span,
    /// Normalized policy name.
    pub policy_name: IdentKey,
    /// Lowered RLS body predicate. `None` when the AST has no
    /// parsed body (parser recovery, or BigQuery-shape policies
    /// without a `FILTER USING` clause).
    pub body: Option<ScalarExpr>,
    /// Per-parameter `ColumnId`s allocated during lowering,
    /// position-aligned with the AST signature parameter list.
    /// Empty for BigQuery-shape policies (no parameters).
    pub parameters: Vec<ColumnId>,
}

/// `CREATE/ALTER MASKING POLICY` fact carrier.
///
/// Snowflake form: `CREATE MASKING POLICY p AS (val T)
/// RETURNS T -> <body>`. The body is a value-typed expression
/// (not boolean), but the same predicate-query infrastructure
/// applies for tautology detection (e.g. masking policies that
/// reduce to a constant).
#[derive(Debug, Clone)]
pub struct MaskingPolicyFact {
    /// Span covering the entire policy DDL statement.
    pub span: Span,
    /// Normalized policy name.
    pub policy_name: IdentKey,
    /// Lowered body expression. `None` when the AST has no
    /// parsed body (parser recovery).
    pub body: Option<ScalarExpr>,
    /// Per-parameter `ColumnId`s allocated during lowering,
    /// position-aligned with the AST signature parameter list.
    pub parameters: Vec<ColumnId>,
}

/// `CREATE/ALTER POLICY ... ON <table>` fact carrier
/// (PostgreSQL row-level security policies).
#[derive(Debug, Clone)]
pub struct PgPolicyFact {
    /// Span covering the entire policy DDL statement.
    pub span: Span,
    /// Normalized policy name.
    pub policy_name: IdentKey,
    /// Target table from `... ON <table>`.
    pub table_ref: TableRef,
    /// Lowered `USING (...)` predicate. `None` when omitted.
    pub using: Option<ScalarExpr>,
    /// Lowered `WITH CHECK (...)` predicate. `None` when
    /// omitted.
    pub with_check: Option<ScalarExpr>,
    /// Per-target-column `ColumnId`s allocated during lowering
    /// when the catalog supplied the table's schema. Empty
    /// when the catalog is absent or the target table is
    /// unresolved — predicates referencing unbound columns
    /// lower to `ScalarExpr::Opaque`.
    pub target_columns: Vec<ColumnId>,
}
