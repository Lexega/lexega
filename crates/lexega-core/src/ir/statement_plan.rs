// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Top-level statement plan.
//!
//! [`StatementPlan`] is the plan of one lowered statement: the disjoint
//! union of the two statement-kind plans:
//!
//! - [`super::plan::RelPlan`] — query-bearing statements
//!   (`SELECT` / `INSERT` / `UPDATE` / `DELETE` / `MERGE`).
//! - [`super::ddl_plan::DdlPlan`] — every non-query statement
//!   (DDL, session/option statements, procedural wrappers, etc.).
//!
//! Each arm wraps its plan in `Rc` so callers that want shared
//! ownership of the tree can clone a refcount without deep-cloning the
//! plan. The sum is **closed** — no `_` arms permitted in match
//! sites.

use std::rc::Rc;

use crate::lexer::Span;

use super::ddl_plan::DdlPlan;
use super::plan::RelPlan;

/// IR plan for any statement.
#[derive(Debug, Clone)]
pub enum StatementPlan {
    /// Query-bearing statement lowered to a relational tree.
    Rel(Rc<RelPlan>),
    /// Non-query statement (DDL / session / procedural wrapper).
    Ddl(Rc<DdlPlan>),
}

impl StatementPlan {
    /// Source span of the statement this plan represents.
    pub fn span(&self) -> Span {
        match self {
            StatementPlan::Rel(p) => p.span(),
            StatementPlan::Ddl(p) => p.span(),
        }
    }

    /// Project to the relational arm. Returns `None` for DDL.
    /// Used by callers that only operate on the relational shape
    /// (lineage, nullability, taint, query analyses).
    pub fn as_rel(&self) -> Option<&RelPlan> {
        match self {
            StatementPlan::Rel(p) => Some(p.as_ref()),
            StatementPlan::Ddl(_) => None,
        }
    }

    /// Project to the DDL arm. Returns `None` for relational
    /// plans.
    pub fn as_ddl(&self) -> Option<&DdlPlan> {
        match self {
            StatementPlan::Rel(_) => None,
            StatementPlan::Ddl(p) => Some(p.as_ref()),
        }
    }

    /// True iff the relational arm has a `WHERE` filter. False for
    /// DDL — non-query statements have no `WHERE` clause.
    pub fn has_where(&self) -> bool {
        match self {
            StatementPlan::Rel(p) => p.has_where(),
            StatementPlan::Ddl(_) => false,
        }
    }

    /// True iff the relational arm has any filter (`WHERE` or
    /// `QUALIFY`). False for DDL.
    pub fn has_any_filter(&self) -> bool {
        match self {
            StatementPlan::Rel(p) => p.has_any_filter(),
            StatementPlan::Ddl(_) => false,
        }
    }

    /// True iff the relational arm has a `LIMIT`. False for DDL.
    pub fn has_limit(&self) -> bool {
        match self {
            StatementPlan::Rel(p) => p.has_limit(),
            StatementPlan::Ddl(_) => false,
        }
    }

    /// True iff the relational arm has a `QUALIFY`. False for DDL.
    pub fn has_qualify(&self) -> bool {
        match self {
            StatementPlan::Rel(p) => p.has_qualify(),
            StatementPlan::Ddl(_) => false,
        }
    }

    /// True iff the relational arm contains an implicit cross-join
    /// (comma-joined `FROM`). False for DDL.
    pub fn has_implicit_cross_join(&self) -> bool {
        match self {
            StatementPlan::Rel(p) => p.has_implicit_cross_join(),
            StatementPlan::Ddl(_) => false,
        }
    }
}
