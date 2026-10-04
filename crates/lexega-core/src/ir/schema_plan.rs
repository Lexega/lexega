// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for `CREATE / ALTER / DROP SCHEMA`.
//!
//! Sibling-tier fact analogous to [`super::DatabasePlan`] and
//! [`super::PipePlan`]: typed projection of the AST that downstream
//! `derive_facts_from_schema_plan` folds into a public
//! `StatementFacts.ddl.schema` carrier.
//!
//! The carrier collects per-property typed flags by classifying
//! `AstCreateSchema.with_managed_access_span` for CREATE and by
//! exhaustively matching the `AstAlterSchemaActionKind` for ALTER.
//! Each flag corresponds 1:1 with a SNW-SCHEMA-* rule condition so
//! YAML rules predicate against the flag directly.
//!
//! `retention_changed` is decoded by scanning the `SetProperties`
//! action's `properties_span` text for the
//! `DATA_RETENTION_TIME_IN_DAYS` identifier — a
//! case-insensitive `contains("DATA_RETENTION_TIME_IN_DAYS")`
//! check on that span. The parser captures the property clause as
//! a single span (it has no per-pair typed AST yet); the IR-lowering
//! layer is the legitimate place to convert span content into the
//! typed flag, the same way [`super::stage_plan`] decodes
//! `ENCRYPTION = (TYPE = 'NONE')`.

use crate::ast::{
    AstAlterSchema, AstAlterSchemaActionKind, AstCreateSchema, AstDropSchema, NodeId,
};
use crate::lexer::token::Span;

#[derive(Debug, Clone)]
pub struct SchemaPlan {
    pub action: SchemaAction,
    pub target: Option<SchemaTarget>,
    pub options: SchemaOptions,
    /// True when the statement enables managed access — either
    /// `CREATE SCHEMA … WITH MANAGED ACCESS` or
    /// `ALTER SCHEMA … ENABLE MANAGED ACCESS`. Both surfaces set
    /// the same flag. The rule
    /// predicate scopes the firing via `kind: create_schema` or
    /// `kind: alter_schema`.
    pub managed_access_enabled: bool,
    /// True only for `ALTER SCHEMA … DISABLE MANAGED ACCESS`. There
    /// is no CREATE-time form for disabling managed access.
    pub managed_access_disabled: bool,
    /// True for `ALTER SCHEMA … SET PROPERTIES (…)` whose property
    /// clause text contains `DATA_RETENTION_TIME_IN_DAYS`. Always
    /// `false` on `Create` and `Drop` actions.
    pub retention_changed: bool,
    /// `DATA_RETENTION_TIME_IN_DAYS = <n>` value resolved from the
    /// `SET PROPERTIES` clause. `None` when the parameter is absent or
    /// its value is not a plain integer. `Some(0)` disables Time Travel
    /// for every object in the schema that uses the schema default.
    /// Whether a value is dangerous is YAML policy, not recognition.
    pub data_retention_days: Option<i64>,
    /// True for `ALTER SCHEMA … SWAP WITH …`. Always `false` on
    /// `Create` and `Drop` actions.
    pub swapped: bool,
    /// True for `CREATE SCHEMA … MANAGED LOCATION '…'` (Databricks
    /// Unity Catalog). Always `false` on `Alter` and `Drop`. The
    /// rule (DBX-SCHEMA-MGLOC) composes this with `kind: create_schema`
    /// in YAML; the name describes the SQL clause's presence.
    pub managed_location_present: bool,
    /// True for `CREATE SCHEMA … LOCATION '…'` (Databricks Hive
    /// metastore). Always `false` on `Alter` and `Drop`. Names the
    /// SQL clause; drives the predicate composition for DBX-SCHEMA-LOC.
    pub location_present: bool,
    /// Typed list of `ALTER SCHEMA` action variants, in source order.
    /// Empty on `Create` and `Drop`. Rules predicate via
    /// `ddl.schema.actions: { exists: { kind: <variant> } }` — the
    /// substrate exposes structural inputs (which AST variants were
    /// matched) rather than per-rule verdict booleans.
    pub(crate) actions: Vec<IrSchemaAlterAction>,
    /// Origin of a `CREATE SCHEMA` statement: standard (no source)
    /// or a CLONE of an existing schema. `None` on `Alter` and `Drop`.
    /// Drives SCHEMA-CLONE. The public mirror in
    /// `crate::facts::ddl::SchemaCreateOrigin` is a curated 2-variant
    /// closed enum; future expansion (e.g. clone source name, time
    /// travel) is additive on either side.
    pub(crate) create_origin: Option<IrSchemaCreateOrigin>,
    pub node_id: NodeId,
    pub span: Span,
}

/// IR-internal mirror of the origin variants on `AstCreateSchemaVariant`.
/// Today maps 1:1 to the AST's structural variants; the public mirror in
/// `crate::facts::ddl::SchemaCreateOrigin` stays narrower because no rule
/// composes against clone-source detail. The IR-side type is
/// `pub(crate)` so future divergence (carrying source span, time travel
/// detail) does not leak into the public schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum IrSchemaCreateOrigin {
    /// `CREATE SCHEMA name` with no upstream source.
    Standard,
    /// `CREATE SCHEMA name CLONE source [AT|BEFORE (...)]`.
    Clone,
}

/// IR-internal mirror of [`crate::ast::AstAlterSchemaActionKind`]. The
/// public-facts equivalent in `src/facts/ddl.rs::SchemaAlterAction` is
/// projected from this enum at the single boundary point in
/// `src/facts/extract.rs::project_schema_alter_action`. The IR-side
/// type stays `pub(crate)` so engine-internal divergence (e.g.
/// carrying source spans, principal references) does not leak into the
/// public schema.
///
/// **Collapse policy**: syntactic alternatives that are exactly
/// semantically equivalent map to the same IR variant. Today the only
/// such collapse is:
///
/// - `ALTER SCHEMA … ENABLE MANAGED ACCESS` and
///   `ALTER SCHEMA … SET MANAGED ACCESS` both lower to
///   [`IrSchemaAlterAction::EnableManagedAccess`].
/// - Mirrored for DISABLE / UNSET → [`IrSchemaAlterAction::DisableManagedAccess`].
///
/// This collapse is intentional: the two spellings produce identical
/// account-level state changes in Snowflake. Customer rules that
/// predicate on `actions: enable_managed_access` therefore fire on
/// both spellings without per-rule disjunctions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum IrSchemaAlterAction {
    EnableManagedAccess,
    DisableManagedAccess,
    SwapWith,
    /// `ALTER SCHEMA … SET PROPERTIES (…)`. The
    /// DATA_RETENTION_TIME_IN_DAYS sub-property is exposed
    /// separately via [`SchemaPlan::retention_changed`].
    SetProperties,
    UnsetProperties,
    SetDbProperties,
    OwnerTo,
    PredictiveOptimization,
    DefaultCollation,
    RenameTo,
    SetTag,
    UnsetTag,
    SetComment,
    UnsetComment,
    SetTags,
    UnsetTags,
    /// `Unknown` variant from the AST — clause the parser preserved but
    /// did not structurally recognize.
    Opaque,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SchemaAction {
    /// `CREATE SCHEMA`
    Create,
    /// `ALTER SCHEMA`
    Alter,
    /// `DROP SCHEMA`
    Drop,
}

#[derive(Debug, Clone)]
pub struct SchemaTarget {
    pub name: String,
    pub schema: Option<String>,
    pub db: Option<String>,
    pub span: Span,
}

#[derive(Debug, Clone, Default)]
pub struct SchemaOptions {
    pub or_replace: bool,
    pub if_not_exists: bool,
    pub if_exists: bool,
}

/// Lower a typed [`AstCreateSchema`] into a [`SchemaPlan`].
pub fn lower_create_schema_to_schema_plan(s: &AstCreateSchema, source: &str) -> SchemaPlan {
    let create_origin = Some(match &s.variant {
        crate::ast::AstCreateSchemaVariant::Standard => IrSchemaCreateOrigin::Standard,
        crate::ast::AstCreateSchemaVariant::Clone { .. } => IrSchemaCreateOrigin::Clone,
    });
    SchemaPlan {
        action: SchemaAction::Create,
        target: Some(target_from_span(source, s.name_span)),
        options: SchemaOptions {
            or_replace: s.or_replace_span.is_some(),
            if_not_exists: s.if_not_exists_span.is_some(),
            if_exists: false,
        },
        managed_access_enabled: s.with_managed_access_span.is_some(),
        managed_access_disabled: false,
        retention_changed: false,
        data_retention_days: None,
        swapped: false,
        managed_location_present: s.managed_location_span.is_some(),
        location_present: s.location_span.is_some(),
        actions: Vec::new(),
        create_origin,
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a typed [`AstAlterSchema`] into a [`SchemaPlan`].
///
/// Exhaustively matches every [`AstAlterSchemaActionKind`] variant —
/// no `_ =>` arm. Variants whose semantics map to none of the
/// SNW-SCHEMA-* flag set leave every flag at its default
/// `false`; downstream rules that key on those actions need to land
/// alongside their corresponding flag extension.
pub fn lower_alter_schema_to_schema_plan(s: &AstAlterSchema, source: &str) -> SchemaPlan {
    let action = classify_alter_action(&s.action.kind);

    // Pre-existing SNW-* signals continue to use per-condition booleans
    // because their existing rule_ids predicate against them. New
    // DBX-SCHEMA-* rules predicate against `actions` directly. The
    // booleans below are an additional projection of the typed action,
    // computed via an exhaustive match — no `_ =>` arm.
    let (retention_changed, data_retention_days) = match &s.action.kind {
        AstAlterSchemaActionKind::SetProperties {
            properties_span, ..
        } => (
            properties_clause_changes_retention(source, *properties_span),
            super::table_plan::resolve_data_retention_days(source, *properties_span),
        ),
        AstAlterSchemaActionKind::EnableManagedAccess { .. }
        | AstAlterSchemaActionKind::DisableManagedAccess { .. }
        | AstAlterSchemaActionKind::SetManagedAccess { .. }
        | AstAlterSchemaActionKind::UnsetManagedAccess { .. }
        | AstAlterSchemaActionKind::SwapWith { .. }
        | AstAlterSchemaActionKind::UnsetProperties { .. }
        | AstAlterSchemaActionKind::SetTag { .. }
        | AstAlterSchemaActionKind::UnsetTag { .. }
        | AstAlterSchemaActionKind::SetComment { .. }
        | AstAlterSchemaActionKind::UnsetComment { .. }
        | AstAlterSchemaActionKind::SetDbProperties { .. }
        | AstAlterSchemaActionKind::OwnerTo { .. }
        | AstAlterSchemaActionKind::PredictiveOptimization { .. }
        | AstAlterSchemaActionKind::DefaultCollation { .. }
        | AstAlterSchemaActionKind::SetTags { .. }
        | AstAlterSchemaActionKind::UnsetTags { .. }
        | AstAlterSchemaActionKind::RenameTo { .. }
        | AstAlterSchemaActionKind::Unknown(_) => (false, None),
    };
    let managed_access_enabled = matches!(action, IrSchemaAlterAction::EnableManagedAccess);
    let managed_access_disabled = matches!(action, IrSchemaAlterAction::DisableManagedAccess);
    let swapped = matches!(action, IrSchemaAlterAction::SwapWith);

    SchemaPlan {
        action: SchemaAction::Alter,
        target: Some(target_from_span(source, s.name_span)),
        options: SchemaOptions {
            or_replace: false,
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
        },
        managed_access_enabled,
        managed_access_disabled,
        retention_changed,
        data_retention_days,
        swapped,
        managed_location_present: false,
        location_present: false,
        actions: vec![action],
        create_origin: None,
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a typed [`AstDropSchema`] into a [`SchemaPlan`].
pub fn lower_drop_schema_to_schema_plan(s: &AstDropSchema, source: &str) -> SchemaPlan {
    SchemaPlan {
        action: SchemaAction::Drop,
        target: Some(target_from_span(source, s.name_span)),
        options: SchemaOptions {
            or_replace: false,
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
        },
        managed_access_enabled: false,
        managed_access_disabled: false,
        retention_changed: false,
        data_retention_days: None,
        swapped: false,
        managed_location_present: false,
        location_present: false,
        actions: Vec::new(),
        create_origin: None,
        node_id: s.node_id,
        span: s.span,
    }
}

/// Project one [`AstAlterSchemaActionKind`] onto its typed IR mirror.
/// Exhaustive — no `_ =>` arm — so introducing a new variant in the
/// AST closed enum produces a compile-time gap rather than a silent
/// miss.
fn classify_alter_action(kind: &AstAlterSchemaActionKind) -> IrSchemaAlterAction {
    use AstAlterSchemaActionKind as K;
    use IrSchemaAlterAction as A;
    match kind {
        K::EnableManagedAccess { .. } | K::SetManagedAccess { .. } => A::EnableManagedAccess,
        K::DisableManagedAccess { .. } | K::UnsetManagedAccess { .. } => A::DisableManagedAccess,
        K::SwapWith { .. } => A::SwapWith,
        K::SetProperties { .. } => A::SetProperties,
        K::UnsetProperties { .. } => A::UnsetProperties,
        K::SetDbProperties { .. } => A::SetDbProperties,
        K::OwnerTo { .. } => A::OwnerTo,
        K::PredictiveOptimization { .. } => A::PredictiveOptimization,
        K::DefaultCollation { .. } => A::DefaultCollation,
        K::RenameTo { .. } => A::RenameTo,
        K::SetTag { .. } => A::SetTag,
        K::UnsetTag { .. } => A::UnsetTag,
        K::SetComment { .. } => A::SetComment,
        K::UnsetComment { .. } => A::UnsetComment,
        K::SetTags { .. } => A::SetTags,
        K::UnsetTags { .. } => A::UnsetTags,
        K::Unknown(_) => A::Opaque,
    }
}

/// True iff the upper-cased properties clause text contains
/// `DATA_RETENTION_TIME_IN_DAYS`. Returns `false` for an
/// unreadable span.
fn properties_clause_changes_retention(source: &str, span: Span) -> bool {
    let Some(text) = source.get(span.start as usize..span.end as usize) else {
        return false;
    };
    text.to_ascii_uppercase()
        .contains("DATA_RETENTION_TIME_IN_DAYS")
}

fn target_from_span(source: &str, span: Span) -> SchemaTarget {
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
    SchemaTarget {
        name,
        schema,
        db,
        span,
    }
}
