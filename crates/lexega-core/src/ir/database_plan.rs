// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for Snowflake `CREATE / ALTER / DROP DATABASE`.
//!
//! Sibling-tier fact analogous to [`super::SchemaPlan`] and
//! [`super::ProcedurePlan`]: typed projection of the AST that downstream
//! `derive_facts_from_database_plan` folds into a public
//! `StatementFacts.ddl.database` carrier.
//!
//! The carrier exposes **structural primitives**:
//!
//! * `create_origin: Option<IrDatabaseCreateOrigin>` — typed origin of a
//!   `CREATE DATABASE` (Standard / Clone / FromShare / FromListing /
//!   AsReplica / FromBackup). `None` on ALTER / DROP.
//! * `actions: Vec<IrDatabaseAlterActionDetail>` — typed list of
//!   `ALTER DATABASE` actions in source order. Each entry carries a
//!   discriminator (`kind`) plus per-kind sub-facts (today only
//!   `properties` for `SetProperties`). Length 0 on CREATE / DROP;
//!   length 1 for every ALTER (Snowflake permits one action per
//!   statement).
//!
//! Adjacent SNW-DB-* rules and new DB-* rules compose against the same
//! structural surface from different angles instead of each demanding
//! a new boolean.

use crate::ast::{
    AstAlterDatabase, AstAlterDatabaseActionKind, AstCreateDatabase, AstCreateDatabaseVariant,
    AstDropDatabase, NodeId,
};
use crate::lexer::token::Span;

#[derive(Debug, Clone)]
pub struct DatabasePlan {
    pub action: DatabaseAction,
    pub target: Option<DatabaseTarget>,
    pub options: DatabaseOptions,
    /// `CREATE DATABASE` origin — `Some` only when `action == Create`.
    pub(crate) create_origin: Option<IrDatabaseCreateOrigin>,
    /// Typed `ALTER DATABASE` actions in source order. Empty for
    /// CREATE / DROP. Length 1 for every ALTER (one action per
    /// statement).
    pub(crate) actions: Vec<IrDatabaseAlterActionDetail>,
    pub node_id: NodeId,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DatabaseAction {
    Create,
    Alter,
    Drop,
}

#[derive(Debug, Clone)]
pub struct DatabaseTarget {
    pub name: String,
    pub schema: Option<String>,
    pub db: Option<String>,
    pub span: Span,
}

#[derive(Debug, Clone, Default)]
pub struct DatabaseOptions {
    pub or_replace: bool,
    pub if_not_exists: bool,
    pub if_exists: bool,
    pub transient: bool,
}

/// IR-internal mirror of [`AstCreateDatabaseVariant`]. The public-facts
/// equivalent in [`crate::facts::ddl::DatabaseCreateOrigin`] is
/// projected from this enum at the single boundary point in
/// [`crate::facts::extract::project_database_create_origin`]. The
/// IR-side type stays `pub(crate)` so future engine-internal divergence
/// (e.g. carrying clone source name / time travel / replication source
/// account) does not leak into the public schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum IrDatabaseCreateOrigin {
    /// `CREATE DATABASE name` with no upstream source.
    Standard,
    /// `CREATE DATABASE name CLONE source [AT|BEFORE (...)]`.
    Clone,
    /// `CREATE DATABASE name FROM SHARE provider.share`.
    FromShare,
    /// `CREATE DATABASE name FROM LISTING listing_name`.
    FromListing,
    /// `CREATE DATABASE name AS REPLICA OF account.db`.
    AsReplica,
    /// `CREATE DATABASE name FROM BACKUP SET ...`.
    FromBackup,
}

/// IR-internal mirror of [`AstAlterDatabaseActionKind`]. The public
/// equivalent in [`crate::facts::ddl::DatabaseAlterActionKind`] is
/// projected at [`crate::facts::extract::project_database_alter_action`].
/// Exhaustive — adding a new AST variant produces a compile-time gap
/// rather than a silent miss.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum IrDatabaseAlterAction {
    RenameTo,
    SwapWith,
    SetProperties,
    UnsetProperties,
    SetTag,
    UnsetTag,
    SetComment,
    UnsetComment,
    EnableReplication,
    DisableReplication,
    EnableFailover,
    DisableFailover,
    Primary,
    Refresh,
    /// `Unknown` variant from the AST — clause the parser preserved but
    /// did not structurally recognize.
    Opaque,
}

/// One `ALTER DATABASE` action with kind discriminator and per-kind
/// sub-facts. Today only `SetProperties` carries a `properties`
/// payload; other variants have no rule-relevant sub-fact today, so
/// the field is `None`. New per-kind structural data is additive on
/// this carrier.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct IrDatabaseAlterActionDetail {
    pub kind: IrDatabaseAlterAction,
    /// `SET <properties…>`-specific structural facts. `Some` iff
    /// `kind == SetProperties` (the AST captures the properties clause
    /// span only on that variant).
    pub properties: Option<Vec<IrDatabaseProperty>>,
    /// T-SQL `SET <KEY> { ON | OFF }` switch options recognized in the
    /// same clause (`TRUSTWORTHY ON`, `ENCRYPTION OFF`, …). Empty for
    /// `KEY = value` (Snowflake-shaped) clauses.
    pub switches: Vec<IrDatabasePropertySwitch>,
    /// `DATA_RETENTION_TIME_IN_DAYS = <n>` value resolved from the
    /// `SET <properties>` clause. `None` when the parameter is absent or
    /// its value is not a plain integer. `Some(0)` disables Time Travel
    /// for every object in the database that uses the database default.
    /// Whether a value is dangerous is YAML policy, not recognition.
    pub data_retention_days: Option<i64>,
}

/// Closed enum of `SET <properties…>` keys exposed at the IR boundary.
/// Variants chosen for current rule-relevance; widening is additive.
/// Mirrored 1:1 by [`crate::facts::ddl::DatabasePropertyKey`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum IrDatabaseProperty {
    /// `DATA_RETENTION_TIME_IN_DAYS = <n>` key presence. Drives
    /// SNW-DB-RETENTION-CHG; the value (see
    /// [`IrDatabaseAlterActionDetail::data_retention_days`]) drives
    /// SNW-DB-RETENTION-ZERO.
    DataRetentionTimeInDays,
    /// T-SQL `TRUSTWORTHY { ON | OFF }`.
    Trustworthy,
    /// T-SQL `ENCRYPTION { ON | OFF }` — transparent data encryption.
    Encryption,
    /// T-SQL `DB_CHAINING { ON | OFF }` — cross-database ownership
    /// chaining for this database.
    DbChaining,
    /// Property key not enumerated above. Surfaced so rules that gate
    /// on absence of known keys can still discriminate.
    Other,
}

/// One T-SQL `SET <KEY> { ON | OFF }` switch from an ALTER DATABASE
/// properties clause.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct IrDatabasePropertySwitch {
    pub key: IrDatabaseProperty,
    pub value: IrDatabaseSwitchValue,
}

/// The ON / OFF half of a T-SQL database switch option.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum IrDatabaseSwitchValue {
    On,
    Off,
}

/// Lower a typed [`AstCreateDatabase`] into a [`DatabasePlan`].
///
/// Walks the single `variant` to set the typed `create_origin`. Closed
/// exhaustive `match` — every [`AstCreateDatabaseVariant`] variant is
/// enumerated explicitly.
pub fn lower_create_database_to_database_plan(s: &AstCreateDatabase, source: &str) -> DatabasePlan {
    DatabasePlan {
        action: DatabaseAction::Create,
        target: Some(target_from_span(source, s.name_span)),
        options: DatabaseOptions {
            or_replace: s.or_replace_span.is_some(),
            if_not_exists: s.if_not_exists_span.is_some(),
            if_exists: false,
            transient: s.transient_span.is_some(),
        },
        create_origin: Some(classify_create_variant(&s.variant)),
        actions: Vec::new(),
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a typed [`AstAlterDatabase`] into a [`DatabasePlan`].
///
/// Walks the single `action.kind` to produce one
/// `IrDatabaseAlterActionDetail` entry. Closed exhaustive `match` —
/// every [`AstAlterDatabaseActionKind`] variant is enumerated.
pub fn lower_alter_database_to_database_plan(s: &AstAlterDatabase, source: &str) -> DatabasePlan {
    let detail = classify_alter_action(&s.action.kind, source);

    DatabasePlan {
        action: DatabaseAction::Alter,
        target: Some(target_from_span(source, s.name_span)),
        options: DatabaseOptions {
            or_replace: false,
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
            transient: false,
        },
        create_origin: None,
        actions: vec![detail],
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a typed [`AstDropDatabase`] into a [`DatabasePlan`].
pub fn lower_drop_database_to_database_plan(s: &AstDropDatabase, source: &str) -> DatabasePlan {
    DatabasePlan {
        action: DatabaseAction::Drop,
        target: Some(target_from_span(source, s.name_span)),
        options: DatabaseOptions {
            or_replace: false,
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
            transient: false,
        },
        create_origin: None,
        actions: Vec::new(),
        node_id: s.node_id,
        span: s.span,
    }
}

fn classify_create_variant(variant: &AstCreateDatabaseVariant) -> IrDatabaseCreateOrigin {
    use AstCreateDatabaseVariant as V;
    use IrDatabaseCreateOrigin as O;
    match variant {
        V::Standard => O::Standard,
        V::Clone { .. } => O::Clone,
        V::FromShare { .. } => O::FromShare,
        V::FromListing { .. } => O::FromListing,
        V::AsReplica { .. } => O::AsReplica,
        V::FromBackup { .. } => O::FromBackup,
    }
}

fn classify_alter_action(
    kind: &AstAlterDatabaseActionKind,
    source: &str,
) -> IrDatabaseAlterActionDetail {
    use AstAlterDatabaseActionKind as K;
    use IrDatabaseAlterAction as A;
    match kind {
        K::RenameTo { .. } => detail_simple(A::RenameTo),
        K::SwapWith { .. } => detail_simple(A::SwapWith),
        K::SetProperties {
            properties_span, ..
        } => {
            let (keys, switches) = extract_property_keys(source, *properties_span);
            IrDatabaseAlterActionDetail {
                kind: A::SetProperties,
                properties: Some(keys),
                switches,
                data_retention_days: super::table_plan::resolve_data_retention_days(
                    source,
                    *properties_span,
                ),
            }
        }
        K::UnsetProperties { .. } => detail_simple(A::UnsetProperties),
        K::SetTag { .. } => detail_simple(A::SetTag),
        K::UnsetTag { .. } => detail_simple(A::UnsetTag),
        K::SetComment { .. } => detail_simple(A::SetComment),
        K::UnsetComment { .. } => detail_simple(A::UnsetComment),
        K::EnableReplication { .. } => detail_simple(A::EnableReplication),
        K::DisableReplication { .. } => detail_simple(A::DisableReplication),
        K::EnableFailover { .. } => detail_simple(A::EnableFailover),
        K::DisableFailover { .. } => detail_simple(A::DisableFailover),
        K::Primary { .. } => detail_simple(A::Primary),
        K::Refresh { .. } => detail_simple(A::Refresh),
        K::Unknown(_) => detail_simple(A::Opaque),
    }
}

fn detail_simple(kind: IrDatabaseAlterAction) -> IrDatabaseAlterActionDetail {
    IrDatabaseAlterActionDetail {
        kind,
        properties: None,
        switches: Vec::new(),
        data_retention_days: None,
    }
}

/// Extract the set of recognized property keys from the
/// `ALTER DATABASE … SET <properties>` clause text. Splits on `,` at
/// the top level, takes the identifier before `=`, normalises to
/// uppercase, and maps to [`IrDatabaseProperty`]. Unrecognized names
/// fold to [`IrDatabaseProperty::Other`].
///
/// Conservative parser: does not handle nested parens, string literals
/// containing `,`, or escapes. Snowflake property clauses use
/// `KEY = value` pairs separated by commas; values are scalars or
/// single-quoted strings.
fn extract_property_keys(
    source: &str,
    span: Span,
) -> (Vec<IrDatabaseProperty>, Vec<IrDatabasePropertySwitch>) {
    let Some(text) = source.get(span.start as usize..span.end as usize) else {
        return (Vec::new(), Vec::new());
    };
    let mut keys = Vec::new();
    let mut switches = Vec::new();
    for part in text.split(',') {
        let (key, value) = if let Some(eq_idx) = part.find('=') {
            // Snowflake-shaped `KEY = value` pair.
            (part[..eq_idx].trim(), None)
        } else {
            // T-SQL-shaped `KEY ON|OFF` switch (`TRUSTWORTHY ON`).
            let mut words = part.split_whitespace();
            let Some(k) = words.next() else {
                continue;
            };
            let v = words.next().and_then(|w| {
                if w.eq_ignore_ascii_case("ON") {
                    Some(IrDatabaseSwitchValue::On)
                } else if w.eq_ignore_ascii_case("OFF") {
                    Some(IrDatabaseSwitchValue::Off)
                } else {
                    None
                }
            });
            // Without a recognizable ON/OFF this is not a switch pair —
            // skip rather than mislabel arbitrary clause text as a key.
            if v.is_none() {
                continue;
            }
            (k, v)
        };
        if key.is_empty() {
            continue;
        }
        let key = match key.to_ascii_uppercase().as_str() {
            "DATA_RETENTION_TIME_IN_DAYS" => IrDatabaseProperty::DataRetentionTimeInDays,
            "TRUSTWORTHY" => IrDatabaseProperty::Trustworthy,
            "ENCRYPTION" => IrDatabaseProperty::Encryption,
            "DB_CHAINING" => IrDatabaseProperty::DbChaining,
            _ => IrDatabaseProperty::Other,
        };
        if !keys.contains(&key) {
            keys.push(key);
        }
        if let Some(value) = value {
            let sw = IrDatabasePropertySwitch { key, value };
            if !switches.contains(&sw) {
                switches.push(sw);
            }
        }
    }
    (keys, switches)
}

fn target_from_span(source: &str, span: Span) -> DatabaseTarget {
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
    DatabaseTarget {
        name,
        schema,
        db,
        span,
    }
}
