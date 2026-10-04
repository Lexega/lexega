// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Privilege change facts: GRANT / REVOKE / DENY with typed privileges,
//! grantees, and target objects.

use serde::{Deserialize, Serialize};

#[cfg(feature = "schema")]
use schemars::JsonSchema;

use super::identity::{IdentName, ObjectRef, PrincipalRef};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct PrivilegeFacts {
    pub kind: PrivilegeChangeKind,
    pub privileges: Vec<Privilege>,
    /// Omitted for `GRANT … ON FUTURE …` without an explicit target.
    pub target: Option<ObjectRef>,
    pub grantees: Vec<PrincipalRef>,
    pub with_grant_option: bool,
    pub on_future: bool,
    pub on_all: bool,
    pub all_privileges: bool,
    pub copy_current_grants: bool,
    /// `DENY ... CASCADE` flag — propagates the denial through any
    /// principals that received the privilege via the target principal.
    /// T-SQL only; always `false` for GRANT / REVOKE.
    #[serde(default)]
    pub cascade: bool,
    /// `DENY ... AS <principal>` delegation clause — executes the denial
    /// on behalf of another principal. MSSQL T-SQL only; always
    /// omitted for GRANT / REVOKE.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub as_principal: Option<PrincipalRef>,
    /// Effective-access impact of a `GRANT ROLE <parent> TO ROLE
    /// <child>` statement, computed from the catalog's grant graph.
    /// Omitted for non-role grants or when no catalog is attached.
    pub role_grant_impact: Option<RoleGrantImpactFacts>,
    /// Effective-access impact of an object-privilege grant
    /// `GRANT <privs> ON <object> TO ROLE <r>`, computed from the
    /// catalog's grant graph downstream of the grantee. Omitted for
    /// role-to-role grants, non-role grantees, or when no catalog is
    /// attached.
    pub object_grant_impact: Option<ObjectGrantImpactFacts>,
    /// For `GRANT … ON {ALL | FUTURE} <plural> IN <scope>`, the
    /// singular object kind that the grant operates on (`Tables` →
    /// `Table`, `Schemas` → `Schema`, …). `target.kind` separately
    /// carries the scope kind (Database / Schema / Catalog). Omitted
    /// for single-object grants and unmapped plurals.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_plural_kind: Option<super::identity::ObjectKind>,
}

/// Effective-access expansion produced by a `GRANT ROLE <parent> TO
/// ROLE <child>`. Populated when a catalog is attached and the grant
/// graph contains role-hierarchy and object-privilege edges.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct RoleGrantImpactFacts {
    /// Role being granted (privilege source). Privileges flow from this
    /// role to the grantee.
    pub parent_role: IdentName,
    /// Role receiving the grant.
    pub child_role: IdentName,
    /// Privileges the child inherits as a direct result of this grant.
    pub inherited_privileges: u64,
    /// Downstream roles (transitive children of `child_role`) that gain
    /// access via this grant.
    pub downstream_roles: u64,
    /// Users who gain effective access via this grant.
    pub affected_users: u64,
}

/// Effective-access expansion produced by an object-privilege grant.
/// Computed from the catalog's grant graph downstream of the grantee
/// role and surfaces the "how broad is the grantee?" axis (the
/// privilege list and target object are already on the parent
/// `privilege` fact).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct ObjectGrantImpactFacts {
    /// The role receiving the object privilege.
    pub grantee_role: IdentName,
    /// Distinct roles that effectively hold the granted privilege after
    /// this statement: the grantee role plus all transitive downstream
    /// roles in the role hierarchy.
    pub total_roles_with_access: u64,
    /// Distinct users who effectively gain the granted privilege — the
    /// transitive user count of the grantee role.
    pub affected_users: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "PrivilegeChangeType"))]
pub enum PrivilegeChangeKind {
    Grant,
    Revoke,
    Deny,
    /// SQL Server `ALTER AUTHORIZATION` — ownership transfer of a
    /// securable. The privilege list always contains `ownership`.
    OwnershipTransfer,
}

/// A SQL privilege. `Other(IdentName)` covers dialect-specific
/// privileges not listed below.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum Privilege {
    // ───────────── Data-level ─────────────
    Select,
    Insert,
    Update,
    Delete,
    Truncate,
    References,
    Trigger,

    // ───────────── Definition-level ─────────────
    Create,
    CreateTable,
    CreateView,
    CreateSchema,
    CreateDatabase,
    CreateRole,
    CreateUser,
    CreateFunction,
    CreateProcedure,
    CreateMaskingPolicy,
    CreateRowAccessPolicy,
    CreateNetworkPolicy,
    CreateSessionPolicy,
    CreatePasswordPolicy,
    CreateStage,
    CreateWarehouse,
    CreateTask,
    CreatePipe,
    CreateExternalTable,

    // ───────────── Schema / object-level ─────────────
    Modify,
    Monitor,
    Operate,
    Usage,
    Apply,
    Execute,
    Read,
    Write,

    // ───────────── Snowflake-special ─────────────
    Ownership,
    ManageGrants,
    ApplyMaskingPolicy,
    ApplyRowAccessPolicy,
    ApplyTag,
    ApplyAggregationPolicy,
    ApplyProjectionPolicy,
    ImportShare,
    ImportedPrivileges,

    // ───────────── PG-specific ─────────────
    Connect,
    TemporaryTable,
    ForeignServer,

    // ───────────── Databricks Unity Catalog ─────────────
    /// `MANAGE` — broad administrative privilege on a UC object.
    Manage,
    /// `EXTERNAL USE LOCATION` — temporary-credential vending for
    /// external engines on an external location.
    ExternalUseLocation,
    /// `EXTERNAL USE SCHEMA` — temporary-credential vending for
    /// external engines on a schema (Iceberg REST).
    ExternalUseSchema,
    /// `READ FILES` — direct reads from cloud object storage backing
    /// an external location.
    ReadFiles,
    /// `WRITE FILES` — direct writes to cloud object storage backing
    /// an external location.
    WriteFiles,
    /// `CREATE STORAGE CREDENTIAL` — metastore-tier privilege.
    CreateStorageCredential,
    /// `CREATE EXTERNAL LOCATION` — metastore-tier privilege.
    CreateExternalLocation,
    /// `SET SHARE PERMISSION` — Delta Sharing administrative privilege.
    SetSharePermission,

    /// `ALL` / `ALL PRIVILEGES`.
    All,

    /// Dialect-specific privilege. Predicates can match against
    /// `kind: other` + `other.raw: { matches: ... }`.
    Other(IdentName),
}
