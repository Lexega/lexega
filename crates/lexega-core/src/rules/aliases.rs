// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Statement-kind aliases. Compiled to `kind: { in: [...] }` at parse time.
//!
//! Customer DSL can write `kind: any_dml` and the parser expands to the
//! concrete variant set. Adding new aliases is a v1.x non-breaking
//! minor change.

use crate::facts::StatementKind;

/// Resolve an alias to its concrete `StatementKind` set. Returns `None`
/// when the identifier is not a registered alias (callers should treat
/// it as a concrete `StatementKind` token instead).
pub fn resolve_alias(name: &str) -> Option<&'static [StatementKind]> {
    use StatementKind::*;
    Some(match name {
        // Query-bearing
        "any_query" => &[Select, SetSelect],
        "any_dml_write" => &[Insert, Update, Delete, Merge, MultiInsert],
        "any_dml" => &[
            Select,
            SetSelect,
            Insert,
            Update,
            Delete,
            Merge,
            MultiInsert,
        ],

        // Table DDL
        "any_table_ddl" => &[
            CreateTable,
            AlterTable,
            DropTable,
            Truncate,
            RenameTable,
            CloneTable,
            DropAllRowAccessPolicies,
        ],

        // View DDL (regular + materialized)
        "any_view_ddl" => &[
            CreateView,
            AlterView,
            DropView,
            CreateMaterializedView,
            AlterMaterializedView,
            DropMaterializedView,
        ],

        // Policy DDL — all 24 (3 actions × 8 policy kinds)
        "any_policy_ddl" => &[
            CreateMaskingPolicy,
            AlterMaskingPolicy,
            DropMaskingPolicy,
            CreateRowAccessPolicy,
            AlterRowAccessPolicy,
            DropRowAccessPolicy,
            CreateNetworkPolicy,
            AlterNetworkPolicy,
            DropNetworkPolicy,
            CreateSessionPolicy,
            AlterSessionPolicy,
            DropSessionPolicy,
            CreatePasswordPolicy,
            AlterPasswordPolicy,
            DropPasswordPolicy,
            CreateAggregationPolicy,
            AlterAggregationPolicy,
            DropAggregationPolicy,
            CreateProjectionPolicy,
            AlterProjectionPolicy,
            DropProjectionPolicy,
            CreateJoinPolicy,
            AlterJoinPolicy,
            DropJoinPolicy,
            CreateAuthenticationPolicy,
            AlterAuthenticationPolicy,
            DropAuthenticationPolicy,
        ],

        // Privilege
        "any_grant" => &[Grant, Revoke, Deny],

        // Stage / integration
        "any_stage_ddl" => &[CreateStage, AlterStage, DropStage],
        "any_integration_ddl" => &[
            CreateApiIntegration,
            AlterApiIntegration,
            DropApiIntegration,
            CreateStorageIntegration,
            AlterStorageIntegration,
            DropStorageIntegration,
            CreateNotificationIntegration,
            AlterNotificationIntegration,
            DropNotificationIntegration,
            CreateExternalAccessIntegration,
            AlterExternalAccessIntegration,
            DropExternalAccessIntegration,
        ],

        // Bulk load
        "any_copy" => &[
            CopyIntoTable,
            CopyIntoLocation,
            BulkInsert,
            BqLoadData,
            BqExportData,
        ],

        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_alias_returns_none() {
        assert!(resolve_alias("not_an_alias").is_none());
    }

    #[test]
    fn any_dml_includes_select_and_insert() {
        let resolved = resolve_alias("any_dml").expect("alias resolves");
        assert!(resolved.contains(&StatementKind::Select));
        assert!(resolved.contains(&StatementKind::Insert));
        assert!(resolved.contains(&StatementKind::Merge));
    }

    #[test]
    fn any_policy_ddl_has_27_variants() {
        let resolved = resolve_alias("any_policy_ddl").expect("alias resolves");
        assert_eq!(resolved.len(), 27);
    }
}
