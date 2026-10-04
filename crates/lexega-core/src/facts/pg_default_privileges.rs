// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Customer-facing facts for the PostgreSQL `ALTER DEFAULT PRIVILEGES`
//! statement.
//!
//! Populated on [`crate::facts::StatementFacts::pg_default_privileges`].
//! Projected from
//! [`crate::ir::pg_default_privileges_plan::PgDefaultPrivilegesPlan`] via
//! `derive_facts_from_pg_default_privileges_plan`.
//!
//! `ALTER DEFAULT PRIVILEGES` sets the privileges automatically applied to
//! objects *created in the future* — a standing policy, not a one-time grant.
//! Recognition surfaces the neutral primitives: whether it grants or revokes,
//! the object class, the privileges (and whether `ALL`), the grantees (a
//! `PUBLIC` grantee appears as a role named `public`), and the role/schema
//! scope. Which combination is dangerous is a YAML verdict — a default grant
//! to `PUBLIC` exposes every future object; an unscoped (`global_scope`)
//! default reaches every schema.
//!
//! Predicate example:
//! ```yaml
//! triggers:
//!   all_of:
//!     - kind: pg_default_privileges
//!     - pg_default_privileges.action: grant
//!     - pg_default_privileges.grantees:
//!         exists:
//!           name.normalized: public
//! ```

use serde::{Deserialize, Serialize};

#[cfg(feature = "schema")]
use schemars::JsonSchema;

use super::identity::{IdentName, PrincipalRef};
use super::privilege::Privilege;

/// Whether an `ALTER DEFAULT PRIVILEGES` grants or revokes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum DefaultPrivilegesAction {
    Grant,
    Revoke,
}

/// The object class a default-privileges policy applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum PgDefaultPrivObjectClass {
    Tables,
    Sequences,
    Functions,
    Routines,
    Types,
    Schemas,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct PgDefaultPrivilegesFacts {
    /// Whether the policy grants or revokes default privileges.
    pub action: DefaultPrivilegesAction,
    /// The object class the default applies to (`TABLES`, `FUNCTIONS`, …).
    pub object_class: PgDefaultPrivObjectClass,
    /// The privileges granted/revoked by default. `ALL` appears as a single
    /// `all` entry; see `all_privileges`.
    pub privileges: Vec<Privilege>,
    /// `true` when the source spelled `ALL [PRIVILEGES]`.
    pub all_privileges: bool,
    /// The grantees the default applies to. A `PUBLIC` target appears as a
    /// role named `public`.
    pub grantees: Vec<PrincipalRef>,
    /// `FOR { ROLE | USER } target [, …]` — the roles whose future objects
    /// are affected. Empty when the clause is omitted (the current role).
    pub for_roles: Vec<IdentName>,
    /// `IN SCHEMA schema [, …]` — the schemas the default is confined to.
    /// Empty when omitted (applies to every schema).
    pub in_schemas: Vec<IdentName>,
    /// `true` when no `IN SCHEMA` clause is present, so the default reaches
    /// objects created in *all* schemas — the broad form.
    pub global_scope: bool,
    /// `WITH GRANT OPTION` — grantees may re-grant the default privilege.
    pub with_grant_option: bool,
    /// `GRANT OPTION FOR` on a REVOKE — revokes only the grant option.
    pub grant_option_for: bool,
}
