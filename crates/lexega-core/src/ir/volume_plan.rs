// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for `CREATE / ALTER / DROP VOLUME` (Databricks Unity
//! Catalog managed-or-external volume lifecycle).
//!
//! Sibling-tier fact analogous to [`super::CatalogPlan`]: typed
//! projection of the AST that downstream
//! `derive_facts_from_volume_plan` folds into a public
//! `StatementFacts.ddl.volume` carrier.
//!
//! The carrier exposes the CREATE-time keyword presence flags
//! (`is_external`, `location_present`, `comment_present`) and a single
//! `IrVolumeAlterAction` per ALTER statement (volume ALTER takes
//! exactly one action). Each variant maps 1:1 to a SQL action shape;
//! DBX-VOL-* rules compose against `ddl.volume.actions: { exists:
//! { kind: <variant> } }` rather than per-verdict booleans. The DROP
//! `IF EXISTS` flag is plumbed through the existing
//! `DdlOptions.if_exists` slot — no volume-specific field required.

use crate::ast::{
    types::AlterVolumeActionKind, types::AstStorageLocation, AstAlterVolume, AstCreateVolume,
    AstDropVolume, NodeId,
};
use crate::lexer::token::Span;

/// Strip surrounding quotes and upper-case a property value span (used for
/// the normalized recognition values carried on [`IrStorageLocation`]).
fn unquote_upper(source: &str, span: Span) -> Option<String> {
    let raw = source.get(span.start as usize..span.end as usize)?;
    let out = raw
        .trim()
        .trim_matches(|c| c == '\'' || c == '"')
        .trim()
        .to_ascii_uppercase();
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn lower_storage_location(s: &AstStorageLocation, source: &str) -> IrStorageLocation {
    IrStorageLocation {
        provider: s.provider_span.and_then(|sp| unquote_upper(source, sp)),
        has_role_arn: s.role_arn_span.is_some(),
        has_external_id: s.external_id_span.is_some(),
        encryption_type: s
            .encryption_type_span
            .and_then(|sp| unquote_upper(source, sp)),
    }
}

#[derive(Debug, Clone)]
pub struct VolumePlan {
    pub action: VolumeAction,
    pub target: Option<VolumeTarget>,
    pub options: VolumeOptions,
    /// True for `CREATE EXTERNAL VOLUME …`. Always `false` on ALTER and
    /// DROP. Names the SQL keyword's presence.
    pub is_external: bool,
    /// True when the CREATE statement carries `LOCATION '<path>'`.
    pub location_present: bool,
    /// True when the CREATE statement carries `COMMENT '<text>'`.
    pub comment_present: bool,
    /// Snowflake `ALLOW_WRITES = { TRUE | FALSE }`. `None` when absent
    /// (and on ALTER / DROP).
    pub allow_writes: Option<bool>,
    /// Per-location cloud-storage config from the Snowflake
    /// `STORAGE_LOCATIONS` clause. Empty for Databricks volumes and on
    /// ALTER / DROP.
    pub(crate) storage_locations: Vec<IrStorageLocation>,
    /// Typed list of `ALTER VOLUME` action variants present in source
    /// order. Empty on `Create` and `Drop`. ALTER VOLUME carries
    /// exactly one action per statement; the `Vec` shape parallels
    /// [`super::CatalogPlan::actions`] for uniform projection.
    pub(crate) actions: Vec<IrVolumeAlterAction>,
    pub node_id: NodeId,
    pub span: Span,
}

/// IR-internal recognition of one Snowflake external-volume storage
/// location. Values are normalized (dequoted, upper-cased). Public-facts
/// mirror: `src/facts/ddl.rs::StorageLocationFacts`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IrStorageLocation {
    /// `STORAGE_PROVIDER` value, normalized (e.g. `S3`, `GCS`, `AZURE`).
    pub provider: Option<String>,
    /// `STORAGE_AWS_ROLE_ARN` present — the volume assumes a cloud IAM role.
    pub has_role_arn: bool,
    /// `STORAGE_AWS_EXTERNAL_ID` present.
    pub has_external_id: bool,
    /// `ENCRYPTION ( TYPE = … )` value, normalized (e.g. `NONE`,
    /// `AWS_SSE_S3`, `AWS_SSE_KMS`).
    pub encryption_type: Option<String>,
}

/// IR-internal mirror of [`crate::ast::types::AlterVolumeActionKind`].
/// The public-facts equivalent in
/// `src/facts/ddl.rs::VolumeAlterAction` is projected from this enum at
/// the single boundary point in
/// `src/facts/extract.rs::project_volume_alter_action`. The two shapes
/// are 1:1 today; the IR-side type stays `pub(crate)` so future
/// engine-internal divergence does not leak into the public schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum IrVolumeAlterAction {
    RenameTo,
    OwnerTo,
    SetTags,
    UnsetTags,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VolumeAction {
    Create,
    Alter,
    Drop,
}

#[derive(Debug, Clone)]
pub struct VolumeTarget {
    pub name: String,
    pub schema: Option<String>,
    pub catalog: Option<String>,
    pub span: Span,
}

#[derive(Debug, Clone, Default)]
pub struct VolumeOptions {
    pub if_not_exists: bool,
    pub if_exists: bool,
    /// `OR REPLACE` present (CREATE only).
    pub or_replace: bool,
}

pub fn lower_create_volume_to_volume_plan(s: &AstCreateVolume, source: &str) -> VolumePlan {
    VolumePlan {
        action: VolumeAction::Create,
        target: Some(target_from_span(source, s.volume_name_span)),
        options: VolumeOptions {
            if_not_exists: s.if_not_exists,
            if_exists: false,
            or_replace: s.or_replace_span.is_some(),
        },
        is_external: s.is_external,
        location_present: s.location_span.is_some(),
        comment_present: s.comment_span.is_some(),
        allow_writes: s.allow_writes,
        storage_locations: s
            .storage_locations
            .iter()
            .map(|loc| lower_storage_location(loc, source))
            .collect(),
        actions: Vec::new(),
        node_id: s.node_id,
        span: s.span,
    }
}

pub fn lower_alter_volume_to_volume_plan(s: &AstAlterVolume, source: &str) -> VolumePlan {
    let action = classify_alter_action(&s.action_kind);
    VolumePlan {
        action: VolumeAction::Alter,
        target: Some(target_from_span(source, s.volume_name_span)),
        options: VolumeOptions::default(),
        is_external: false,
        location_present: false,
        comment_present: false,
        allow_writes: None,
        storage_locations: Vec::new(),
        actions: vec![action],
        node_id: s.node_id,
        span: s.span,
    }
}

pub fn lower_drop_volume_to_volume_plan(s: &AstDropVolume, source: &str) -> VolumePlan {
    VolumePlan {
        action: VolumeAction::Drop,
        target: Some(target_from_span(source, s.volume_name_span)),
        options: VolumeOptions {
            if_not_exists: false,
            if_exists: s.if_exists,
            or_replace: false,
        },
        is_external: false,
        location_present: false,
        comment_present: false,
        allow_writes: None,
        storage_locations: Vec::new(),
        actions: Vec::new(),
        node_id: s.node_id,
        span: s.span,
    }
}

/// Project one [`AlterVolumeActionKind`] onto its typed IR mirror.
/// Exhaustive — no `_ =>` arm.
fn classify_alter_action(kind: &AlterVolumeActionKind) -> IrVolumeAlterAction {
    use AlterVolumeActionKind as K;
    use IrVolumeAlterAction as A;
    match kind {
        K::RenameTo => A::RenameTo,
        K::OwnerTo => A::OwnerTo,
        K::SetTags => A::SetTags,
        K::UnsetTags => A::UnsetTags,
    }
}

fn target_from_span(source: &str, span: Span) -> VolumeTarget {
    let raw = source
        .get(span.start as usize..span.end as usize)
        .unwrap_or("")
        .trim();
    let parts: Vec<&str> = raw.split('.').collect();
    let (catalog, schema, name) = match parts.as_slice() {
        [n] => (None, None, (*n).to_string()),
        [s, n] => (None, Some((*s).to_string()), (*n).to_string()),
        [d, s, n] => (
            Some((*d).to_string()),
            Some((*s).to_string()),
            (*n).to_string(),
        ),
        _ => (None, None, raw.to_string()),
    };
    VolumeTarget {
        name,
        schema,
        catalog,
        span,
    }
}
