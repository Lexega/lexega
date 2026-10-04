// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side privilege carrier for `GRANT` / `REVOKE` statements.
//!
//! Sibling-tier fact (analogous to
//! [`super::policy_facts::PolicyStatementFacts`]) lowered beside the
//! statement plan when the statement is a typed [`AstGrant`] /
//! [`AstRevoke`].
//!
//! The shape mirrors the public-facing
//! [`crate::facts::privilege::PrivilegeFacts`] but reuses the AST-side
//! closed enums ([`crate::ast::AstObjectKind`],
//! [`crate::ast::AstPrivilegeKind`], [`crate::ast::AstPluralObjectKind`])
//! as the typed leaf surface — the parser is the only legitimate
//! text→typed conversion site, so re-projecting them at the IR layer
//! would be redundant.
//! Fact extraction projects these closed enums to the public
//! `Privilege` / `ObjectKind` / `PrincipalKind` taxonomy.

use crate::ast::{
    AstCascadeMode, AstDeny, AstGrant, AstGrantObject, AstGrantShape, AstGrantee, AstObjectKind,
    AstObjectScope, AstOwnershipDisposition, AstPluralObjectKind, AstPrivilegeKind, AstRevoke,
    AstRevokeShape, NodeId,
};
use crate::lexer::token::Span;

/// Typed projection of `GRANT` / `REVOKE` for downstream IR consumers.
#[derive(Debug, Clone)]
pub struct PrivilegePlan {
    pub action: PrivilegeAction,
    pub shape: PrivilegeShape,
    pub options: PrivilegeOptions,
    pub node_id: NodeId,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PrivilegeAction {
    Grant,
    Revoke,
    /// MSSQL `DENY` — explicit privilege denial. Overrides any existing
    /// GRANT and blocks access. Drives the DNY-* rule family.
    Deny,
    /// T-SQL `ALTER AUTHORIZATION` — ownership transfer of a securable.
    /// Distinct from `Grant` so statement identity stays honest in the
    /// public `kind` fact; always paired with [`PrivilegeShape::Ownership`].
    OwnershipTransfer,
}

/// Top-level shape of the privilege change.
#[derive(Debug, Clone)]
pub enum PrivilegeShape {
    /// `GRANT/REVOKE <privilege list> [ON <object>[, <object>...]] TO/FROM <grantee>[, ...]`.
    ///
    /// `objects` cardinality encodes the source shape:
    /// - **empty** — server/account-tier MSSQL permission (`GRANT CONTROL
    ///   SERVER TO ...`) with no `ON` clause.
    /// - **single** — standard form across Snowflake / Databricks / MSSQL /
    ///   MySQL / BigQuery.
    /// - **multi** — PostgreSQL `ON TABLE t1, t2, t3` multi-object form.
    ///
    /// `grantees` carries one element on Snowflake/Databricks and multiple
    /// on MSSQL / BigQuery / MySQL.
    Privilege {
        privileges: PrivilegeSet,
        objects: Vec<PrivilegeObject>,
        grantees: Vec<PrivilegeGrantee>,
    },
    /// `GRANT/REVOKE ROLE <name> TO/FROM <grantee>`
    Role {
        role_name_span: Span,
        grantee: PrivilegeGrantee,
    },
    /// `GRANT/REVOKE DATABASE ROLE <name> TO/FROM <grantee>`
    DatabaseRole {
        role_name_span: Span,
        grantee: PrivilegeGrantee,
    },
    /// `GRANT OWNERSHIP ON <object> TO <grantee> [COPY|REVOKE CURRENT GRANTS]`.
    /// Always paired with `PrivilegeAction::Grant` (OWNERSHIP cannot be
    /// revoked per Snowflake semantics — it is transferred).
    Ownership {
        object: PrivilegeObject,
        grantee: PrivilegeGrantee,
        disposition: Option<AstOwnershipDisposition>,
    },
    /// AST-side parsing fell through to the span-only `Unparsed`
    /// placeholder — the body could not be lifted into typed shapes.
    /// IR consumers can detect this and skip typed predicates.
    Unparsed { body_span: Span },
    /// MSSQL `DENY <privs> [ON <object>] TO <p1>[, p2, ...]
    /// [CASCADE] [AS <principal>]`. Distinct from `Privilege` because
    /// DENY admits multiple grantees in a single statement, an optional
    /// (rather than required) object clause, and the DENY-specific
    /// `CASCADE` / `AS` modifiers. The latter two are carried on
    /// [`PrivilegeOptions`].
    Deny {
        privileges: PrivilegeSet,
        object: Option<PrivilegeObject>,
        grantees: Vec<PrivilegeGrantee>,
    },
}

/// The privilege list — either `ALL [PRIVILEGES]` or a named list.
#[derive(Debug, Clone)]
pub enum PrivilegeSet {
    /// `ALL` or `ALL PRIVILEGES` (the boolean records whether the
    /// `PRIVILEGES` keyword was spelled).
    All { privileges_keyword: bool },
    /// Named privileges in source order.
    Listed { privileges: Vec<AstPrivilegeKind> },
}

/// What the privilege change operates on.
#[derive(Debug, Clone)]
pub enum PrivilegeObject {
    /// `ON ACCOUNT` — global-tier privileges.
    Account,
    /// `ON METASTORE` — Databricks Unity Catalog metastore-tier singleton.
    Metastore,
    /// `ON <object_kind> <name>[(<arg-types>)]`.
    Single {
        kind: AstObjectKind,
        name_span: Span,
        /// `Some` exactly when the object is FUNCTION / PROCEDURE /
        /// DATA METRIC FUNCTION and the source spelled an arg-type
        /// list (possibly empty `()`).
        function_signature_present: bool,
    },
    /// `ON ALL <plural> IN { DATABASE <db> | SCHEMA <sch> }`.
    AllInScope {
        plural: AstPluralObjectKind,
        scope: PrivilegeObjectScope,
    },
    /// `ON FUTURE <plural> IN { DATABASE <db> | SCHEMA <sch> }`.
    FutureInScope {
        plural: AstPluralObjectKind,
        scope: PrivilegeObjectScope,
    },
}

#[derive(Debug, Clone)]
pub enum PrivilegeObjectScope {
    Database { name_span: Span },
    Schema { name_span: Span },
    Catalog { name_span: Span },
}

#[derive(Debug, Clone)]
pub enum PrivilegeGrantee {
    Role {
        name_span: Span,
    },
    User {
        name_span: Span,
    },
    Share {
        name_span: Span,
    },
    DatabaseRole {
        name_span: Span,
    },
    Application {
        name_span: Span,
    },
    ApplicationRole {
        name_span: Span,
    },
    /// `GROUP <name>` — Redshift permission group. Kept distinct from
    /// `Role` so role-targeted policy never misfires on a group.
    Group {
        name_span: Span,
    },
    /// T-SQL `ALTER AUTHORIZATION ... TO SCHEMA OWNER` — ownership
    /// reverts to the containing schema's owner (no principal name).
    SchemaOwner {
        keyword_span: Span,
    },
}

/// Optional clauses (some are GRANT-only, some REVOKE-only, some
/// DENY-only).
#[derive(Debug, Clone, Default)]
pub struct PrivilegeOptions {
    /// `WITH GRANT OPTION` — GRANT only.
    pub with_grant_option: bool,
    /// `GRANT OPTION FOR` — REVOKE only.
    pub grant_option_for: bool,
    /// `RESTRICT` / `CASCADE` — REVOKE only.
    pub cascade_mode: Option<AstCascadeMode>,
    /// `CASCADE` keyword present — DENY only.
    pub deny_cascade: bool,
    /// `AS <principal>` delegation clause — DENY only. The span covers
    /// the principal name; the projection translates it into a
    /// `PrincipalRef` at the facts boundary.
    pub deny_as_principal: Option<Span>,
}

// ---------------------------------------------------------------------------
// Lowering: AstGrant / AstRevoke → PrivilegePlan.
// ---------------------------------------------------------------------------

/// Project a typed `AstGrant` into the IR-side `PrivilegePlan`.
pub fn lower_grant_to_privilege_plan(g: &AstGrant) -> PrivilegePlan {
    let (shape, options) = match &g.shape {
        AstGrantShape::Privilege(body) => {
            let shape = PrivilegeShape::Privilege {
                privileges: lower_privilege_list(&body.privileges),
                objects: body.objects.iter().map(lower_grant_object).collect(),
                grantees: body.grantees.iter().map(lower_grantee).collect(),
            };
            let options = PrivilegeOptions {
                with_grant_option: body.with_grant_option.is_some(),
                grant_option_for: false,
                cascade_mode: None,
                deny_cascade: false,
                deny_as_principal: None,
            };
            (shape, options)
        }
        AstGrantShape::Role(body) => (
            PrivilegeShape::Role {
                role_name_span: body.role_name_span,
                grantee: lower_grantee(&body.grantee),
            },
            PrivilegeOptions::default(),
        ),
        AstGrantShape::DatabaseRole(body) => (
            PrivilegeShape::DatabaseRole {
                role_name_span: body.role_name_span,
                grantee: lower_grantee(&body.grantee),
            },
            PrivilegeOptions::default(),
        ),
        AstGrantShape::Ownership(body) => (
            PrivilegeShape::Ownership {
                object: lower_grant_object(&body.object),
                grantee: lower_grantee(&body.grantee),
                disposition: body.disposition,
            },
            PrivilegeOptions::default(),
        ),
        AstGrantShape::Unparsed { body_span } => (
            PrivilegeShape::Unparsed {
                body_span: *body_span,
            },
            PrivilegeOptions::default(),
        ),
    };

    PrivilegePlan {
        action: PrivilegeAction::Grant,
        shape,
        options,
        node_id: g.node_id,
        span: g.span,
    }
}

/// Project a typed `AstRevoke` into the IR-side `PrivilegePlan`.
pub fn lower_revoke_to_privilege_plan(r: &AstRevoke) -> PrivilegePlan {
    let shape = match &r.shape {
        AstRevokeShape::Privilege(body) => PrivilegeShape::Privilege {
            privileges: lower_privilege_list(&body.privileges),
            objects: body.objects.iter().map(lower_grant_object).collect(),
            grantees: body.grantees.iter().map(lower_grantee).collect(),
        },
        AstRevokeShape::Role(body) => PrivilegeShape::Role {
            role_name_span: body.role_name_span,
            grantee: lower_grantee(&body.grantee),
        },
        AstRevokeShape::DatabaseRole(body) => PrivilegeShape::DatabaseRole {
            role_name_span: body.role_name_span,
            grantee: lower_grantee(&body.grantee),
        },
        AstRevokeShape::Unparsed { body_span } => PrivilegeShape::Unparsed {
            body_span: *body_span,
        },
    };

    let options = PrivilegeOptions {
        with_grant_option: false,
        grant_option_for: r.grant_option_for.is_some(),
        cascade_mode: r.cascade_mode,
        deny_cascade: false,
        deny_as_principal: None,
    };

    PrivilegePlan {
        action: PrivilegeAction::Revoke,
        shape,
        options,
        node_id: r.node_id,
        span: r.span,
    }
}

// ---------------------------------------------------------------------------
// Sub-folds.
// ---------------------------------------------------------------------------

pub(crate) fn lower_privilege_list(list: &crate::ast::AstPrivilegeList) -> PrivilegeSet {
    if let Some(all) = &list.all {
        PrivilegeSet::All {
            privileges_keyword: all.privileges_keyword,
        }
    } else {
        PrivilegeSet::Listed {
            privileges: list.privileges.iter().map(|p| p.kind.clone()).collect(),
        }
    }
}

fn lower_grant_object(obj: &AstGrantObject) -> PrivilegeObject {
    match obj {
        AstGrantObject::Account { .. } => PrivilegeObject::Account,
        AstGrantObject::Metastore { .. } => PrivilegeObject::Metastore,
        AstGrantObject::Single {
            object_kind,
            name_span,
            function_signature,
            ..
        } => PrivilegeObject::Single {
            kind: object_kind.clone(),
            name_span: *name_span,
            function_signature_present: function_signature.is_some(),
        },
        AstGrantObject::AllInScope {
            plural_kind, scope, ..
        } => PrivilegeObject::AllInScope {
            plural: plural_kind.clone(),
            scope: lower_object_scope(scope),
        },
        AstGrantObject::FutureInScope {
            plural_kind, scope, ..
        } => PrivilegeObject::FutureInScope {
            plural: plural_kind.clone(),
            scope: lower_object_scope(scope),
        },
    }
}

fn lower_object_scope(scope: &AstObjectScope) -> PrivilegeObjectScope {
    match scope {
        AstObjectScope::Database { name_span, .. } => PrivilegeObjectScope::Database {
            name_span: *name_span,
        },
        AstObjectScope::Schema { name_span, .. } => PrivilegeObjectScope::Schema {
            name_span: *name_span,
        },
        AstObjectScope::Catalog { name_span, .. } => PrivilegeObjectScope::Catalog {
            name_span: *name_span,
        },
    }
}

/// Project a typed `AstDeny` into the IR-side `PrivilegePlan`. Maps to
/// the dedicated `PrivilegeShape::Deny` variant so the multiple-
/// grantees / optional-object / cascade / as-principal shape stays
/// distinct from `PrivilegeShape::Privilege`.
pub fn lower_deny_to_privilege_plan(d: &AstDeny) -> PrivilegePlan {
    let privileges = lower_privilege_list(&d.privileges);
    let object = d.object_span.as_ref().map(|_| {
        // No DNY-* rule currently predicates on the securable's class
        // or name; surface a placeholder `Account` to signal that some
        // ON clause was present. Promote to a typed shape when the
        // first rule needs it (see [`AstDeny::object_span`]).
        PrivilegeObject::Account
    });
    let grantees = d.grantees.iter().map(lower_grantee).collect();
    let options = PrivilegeOptions {
        with_grant_option: false,
        grant_option_for: false,
        cascade_mode: None,
        deny_cascade: d.cascade.is_some(),
        deny_as_principal: d.as_principal.as_ref().map(|a| a.principal_name_span),
    };
    PrivilegePlan {
        action: PrivilegeAction::Deny,
        shape: PrivilegeShape::Deny {
            privileges,
            object,
            grantees,
        },
        options,
        node_id: d.node_id,
        span: d.span,
    }
}

/// Project a typed `AstAlterAuthorization` into the IR-side
/// `PrivilegePlan`. T-SQL ownership transfer maps onto the existing
/// `Ownership` shape (the construct is semantically `GRANT OWNERSHIP`)
/// under the dedicated `OwnershipTransfer` action so the public
/// statement kind stays `alter_authorization`.
pub fn lower_alter_authorization_to_privilege_plan(
    a: &crate::ast::types::AstAlterAuthorization,
) -> PrivilegePlan {
    let grantee = match &a.new_owner {
        crate::ast::types::AstAuthorizationOwner::Principal { name_span } => {
            // T-SQL grants ownership to a user or role; the statement
            // does not spell which. `User` is the securable-owner default
            // the facts projection maps to a neutral PrincipalRef.
            PrivilegeGrantee::User {
                name_span: *name_span,
            }
        }
        crate::ast::types::AstAuthorizationOwner::SchemaOwner { keyword_span } => {
            PrivilegeGrantee::SchemaOwner {
                keyword_span: *keyword_span,
            }
        }
    };
    PrivilegePlan {
        action: PrivilegeAction::OwnershipTransfer,
        shape: PrivilegeShape::Ownership {
            object: lower_grant_object(&a.object),
            grantee,
            disposition: None,
        },
        options: PrivilegeOptions::default(),
        node_id: a.node_id,
        span: a.span,
    }
}

pub(crate) fn lower_grantee(g: &AstGrantee) -> PrivilegeGrantee {
    match g {
        AstGrantee::Role { name_span, .. } => PrivilegeGrantee::Role {
            name_span: *name_span,
        },
        AstGrantee::User { name_span, .. } => PrivilegeGrantee::User {
            name_span: *name_span,
        },
        AstGrantee::Share { name_span, .. } => PrivilegeGrantee::Share {
            name_span: *name_span,
        },
        AstGrantee::DatabaseRole { name_span, .. } => PrivilegeGrantee::DatabaseRole {
            name_span: *name_span,
        },
        AstGrantee::Application { name_span, .. } => PrivilegeGrantee::Application {
            name_span: *name_span,
        },
        AstGrantee::ApplicationRole { name_span, .. } => PrivilegeGrantee::ApplicationRole {
            name_span: *name_span,
        },
        AstGrantee::Group { name_span, .. } => PrivilegeGrantee::Group {
            name_span: *name_span,
        },
    }
}
