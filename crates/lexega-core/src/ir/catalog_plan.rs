// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for `CREATE / ALTER / DROP CATALOG` (Databricks
//! Unity Catalog).
//!
//! Sibling-tier fact analogous to [`super::SchemaPlan`] and
//! [`super::DatabasePlan`]: typed projection of the AST that
//! downstream `derive_facts_from_catalog_plan` folds into a public
//! `StatementFacts.ddl.catalog` carrier.
//!
//! The carrier exposes the `foreign` CREATE-time flag and a single
//! `IrCatalogAlterAction` per ALTER statement (catalog ALTER takes
//! exactly one action). Each variant maps 1:1 to a SQL action shape;
//! DBX-CAT-* rules compose against `ddl.catalog.actions: { exists:
//! { kind: <variant> } }` rather than per-verdict booleans. The DROP
//! cascade vs restrict discriminator is plumbed through the existing
//! `DdlOptions.cascade` flag — no catalog-specific field is required.

use crate::ast::{
    AlterCatalogActionKind, AstAlterCatalog, AstCreateCatalog, AstDropCatalog, NodeId,
};
use crate::lexer::token::Span;

#[derive(Debug, Clone)]
pub struct CatalogPlan {
    pub action: CatalogAction,
    pub target: Option<CatalogTarget>,
    pub options: CatalogOptions,
    /// True for `CREATE FOREIGN CATALOG …`. Always `false` on `ALTER`
    /// and `DROP`. Names the SQL keyword's presence.
    pub foreign: bool,
    /// Typed list of `ALTER CATALOG` action variants present in source
    /// order. Empty on `Create` and `Drop`. ALTER CATALOG carries
    /// exactly one action per statement; the `Vec` shape parallels
    /// [`super::SchemaPlan::actions`] for uniform projection.
    pub(crate) actions: Vec<IrCatalogAlterAction>,
    pub node_id: NodeId,
    pub span: Span,
}

/// IR-internal mirror of [`crate::ast::AlterCatalogActionKind`]. The
/// public-facts equivalent in `src/facts/ddl.rs::CatalogAlterAction`
/// is projected from this enum at the single boundary point in
/// `src/facts/extract.rs::project_catalog_alter_action`. The two
/// shapes are 1:1 today; the IR-side type stays `pub(crate)` so
/// future engine-internal divergence (carrying source spans,
/// principal references, etc.) does not leak into the public schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum IrCatalogAlterAction {
    OwnerTo,
    SetTags,
    UnsetTags,
    EnablePredictiveOptimization,
    DisablePredictiveOptimization,
    InheritPredictiveOptimization,
    DefaultCollation,
    Options,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CatalogAction {
    Create,
    Alter,
    Drop,
}

#[derive(Debug, Clone)]
pub struct CatalogTarget {
    pub name: String,
    pub schema: Option<String>,
    pub db: Option<String>,
    pub span: Span,
}

#[derive(Debug, Clone, Default)]
pub struct CatalogOptions {
    pub if_not_exists: bool,
    pub if_exists: bool,
    pub cascade: bool,
    pub restrict: bool,
}

/// Lower a typed [`AstCreateCatalog`] into a [`CatalogPlan`].
pub fn lower_create_catalog_to_catalog_plan(s: &AstCreateCatalog, source: &str) -> CatalogPlan {
    CatalogPlan {
        action: CatalogAction::Create,
        target: Some(target_from_span(source, s.catalog_name_span)),
        options: CatalogOptions {
            if_not_exists: s.if_not_exists,
            if_exists: false,
            cascade: false,
            restrict: false,
        },
        foreign: s.is_foreign,
        actions: Vec::new(),
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a typed [`AstAlterCatalog`] into a [`CatalogPlan`].
///
/// Exhaustively matches every [`AlterCatalogActionKind`] variant —
/// no `_ =>` arm — so introducing a new variant in the AST closed
/// enum produces a compile-time gap.
pub fn lower_alter_catalog_to_catalog_plan(s: &AstAlterCatalog, source: &str) -> CatalogPlan {
    let action = classify_alter_action(&s.action_kind);
    CatalogPlan {
        action: CatalogAction::Alter,
        target: s
            .catalog_name_span
            .map(|span| target_from_span(source, span)),
        options: CatalogOptions::default(),
        foreign: false,
        actions: vec![action],
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a typed [`AstDropCatalog`] into a [`CatalogPlan`].
pub fn lower_drop_catalog_to_catalog_plan(s: &AstDropCatalog, source: &str) -> CatalogPlan {
    CatalogPlan {
        action: CatalogAction::Drop,
        target: Some(target_from_span(source, s.catalog_name_span)),
        options: CatalogOptions {
            if_not_exists: false,
            if_exists: s.if_exists,
            cascade: s.cascade,
            restrict: s.restrict,
        },
        foreign: false,
        actions: Vec::new(),
        node_id: s.node_id,
        span: s.span,
    }
}

/// Project one [`AlterCatalogActionKind`] onto its typed IR mirror.
/// Exhaustive — no `_ =>` arm.
fn classify_alter_action(kind: &AlterCatalogActionKind) -> IrCatalogAlterAction {
    use AlterCatalogActionKind as K;
    use IrCatalogAlterAction as A;
    match kind {
        K::OwnerTo => A::OwnerTo,
        K::SetTags => A::SetTags,
        K::UnsetTags => A::UnsetTags,
        K::EnablePredictiveOptimization => A::EnablePredictiveOptimization,
        K::DisablePredictiveOptimization => A::DisablePredictiveOptimization,
        K::InheritPredictiveOptimization => A::InheritPredictiveOptimization,
        K::DefaultCollation => A::DefaultCollation,
        K::Options => A::Options,
    }
}

fn target_from_span(source: &str, span: Span) -> CatalogTarget {
    let raw = source
        .get(span.start as usize..span.end as usize)
        .unwrap_or("")
        .trim();
    let parts: Vec<&str> = raw.split('.').collect();
    let (db, schema, name) = match parts.as_slice() {
        [n] => (None, None, (*n).to_string()),
        [s, n] => (None, Some((*s).to_string()), (*n).to_string()),
        [d, s, n] => (
            Some((*d).to_string()),
            Some((*s).to_string()),
            (*n).to_string(),
        ),
        _ => (None, None, raw.to_string()),
    };
    CatalogTarget {
        name,
        schema,
        db,
        span,
    }
}
