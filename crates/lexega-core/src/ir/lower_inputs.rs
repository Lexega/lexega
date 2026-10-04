// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Explicit input bundle and unified return
//! shape for [`super::lower_dispatch::lower_stmt`] — the single
//! closed-enum dispatch over [`crate::ast::types::AstStmt`] that
//! collapses the split between
//! [`super::lower::lower_query_full_with_bindings_models_and_policy_facts`]
//! and [`super::lower_ddl::lower_ddl_stmt`].
//!
//! - [`IrLowerInputs`] carries source, catalogs, session, model
//!   catalog, function catalog, and strict mode. Lowering is a free
//!   function over an explicit bundle.
//! - [`LoweredStatement`] is the unified output: a closed enum whose
//!   `Rel` arm carries the lowering side-band (bindings, indexed
//!   catalog context, IR-side sibling-tier facts, optional policy
//!   facts) the query-bearing entry point produces, and whose `Ddl`
//!   arm carries only the [`super::DdlPlan`] that `lower_ddl_stmt`
//!   produces. Owned values throughout — a caller that stores the plan
//!   wraps it in a [`super::statement_plan::StatementPlan`], which
//!   `Rc`-shares each arm.

use super::catalog::FunctionCatalog;
use super::catalog_context::IndexedCatalogContext;
use super::column::BindingTable;
use super::ddl_plan::DdlPlan;
use super::model_catalog::ModelCatalog;
use super::plan::RelPlan;
use super::policy_facts::PolicyStatementFacts;
use super::privilege_plan::PrivilegePlan;
use super::statement_facts::StatementFacts;
use super::strict::StrictMode;
use super::types::SessionContext;
use crate::catalog::CatalogIndex;

/// Explicit input bundle for [`super::lower_dispatch::lower_stmt`].
///
/// Holds borrows; callers own the underlying values.
pub struct IrLowerInputs<'a> {
    /// Original SQL source — used for span resolution and identifier
    /// extraction during lowering.
    pub source: &'a str,
    /// Strict-mode policy. Permissive permits opaque fall-through to
    /// [`super::plan::RelPlan::Opaque`] / typed
    /// [`super::error::LowerError`](crate::ir::lower::LowerError) terminals; strict modes refuse
    /// opaques.
    pub strict: StrictMode,
    /// Function catalog used to resolve scalar / table function
    /// signatures. Borrowed; outlives the call.
    pub func_catalog: &'a FunctionCatalog,
    /// Session context (current database / schema, search path).
    pub session: &'a SessionContext,
    /// Optional indexed catalog snapshot — when `Some`, the lowerer
    /// seeds [`IndexedCatalogContext`] with column / table tags and
    /// downstream analyses can resolve table-qualified references.
    pub catalog: Option<&'a CatalogIndex>,
    /// Optional dbt model injection catalog — when `Some` and a
    /// FROM-clause `TableRef` matches an entry, the lowerer emits
    /// [`super::plan::RelPlan::ModelRef`] with the upstream
    /// `ResolvedModel.base_tables` populated.
    pub model_catalog: Option<&'a ModelCatalog>,
    /// Reasoning consulted when derived facts are computed for a
    /// lowered body statement.
    pub reasoning: &'a dyn crate::facts::reasoning::Reasoning,
    /// Optional sink for inner statements lowered inside a DDL body.
    /// When `Some`, `super::lower_ddl::lower_body` hands every inner
    /// statement to it as it lowers them. Recurses naturally: an inner
    /// DDL's body likewise emits its own inner statements (a procedure
    /// that contains `BEGIN SELECT … END` yields the block + the
    /// SELECT, not just the block). The DDL itself is still handled by
    /// the caller; the sink only receives statements found *inside* a
    /// body slot, so order is depth-first body-then-parent.
    ///
    /// `None` for entry points that evaluate each top-level statement
    /// against its dedicated projection and don't need body statements
    /// as standalone inputs.
    pub flatten_body_into: Option<&'a dyn LoweredBodySink>,
}

/// Receives the statements lowered inside a DDL body.
pub trait LoweredBodySink {
    /// A query-bearing (or policy-with-predicates) inner statement.
    fn rel(
        &self,
        plan: &RelPlan,
        bindings: &BindingTable,
        catalog_ctx: &IndexedCatalogContext,
        facts: &StatementFacts,
        derived: super::derived_facts::DerivedFacts,
        policy_facts: Option<&PolicyStatementFacts>,
    );

    /// A non-query inner DDL statement.
    fn ddl(&self, plan: &DdlPlan, privilege_plan: Option<&PrivilegePlan>);
}

/// Unified return shape from [`super::lower_dispatch::lower_stmt`].
///
/// Closed sum: query-bearing and policy-DDL-with-predicates statements
/// produce [`Self::Rel`] with the full lowering side-band; non-query
/// DDL statements produce [`Self::Ddl`] with just the lowered plan
/// (`lower_ddl_stmt` does not allocate column ids or seed the catalog
/// context). Both arms carry owned values; a caller that stores the
/// plan wraps it in a [`super::statement_plan::StatementPlan`], which
/// `Rc`-shares it.
pub enum LoweredStatement {
    /// Query-bearing or policy-DDL-with-predicates statement.
    /// `policy_facts` is `Some` exactly for the six policy DDL arms
    /// (`CREATE/ALTER ROW ACCESS POLICY`, `CREATE/ALTER MASKING
    /// POLICY`, `CREATE/ALTER POLICY ... ON <table>`); `None` for
    /// pure query-bearing arms.
    Rel {
        plan: RelPlan,
        bindings: BindingTable,
        catalog_ctx: IndexedCatalogContext,
        facts: StatementFacts,
        policy_facts: Option<PolicyStatementFacts>,
    },
    /// Non-query DDL statement. Produced by
    /// [`super::lower_ddl::lower_ddl_stmt`] which does not allocate
    /// column ids or seed catalog state, so there are no bindings,
    /// catalog context or sibling facts to carry.
    ///
    /// `privilege_plan` is `Some` exactly when the source statement is
    /// `AstStmt::Grant` / `AstStmt::Revoke`; lowered alongside `plan`
    /// by [`super::lower_dispatch::lower_stmt`].
    Ddl {
        plan: DdlPlan,
        privilege_plan: Option<super::PrivilegePlan>,
    },
}
