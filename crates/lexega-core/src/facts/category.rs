// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Rule category — a derived recognition projection.
//!
//! A rule's category is *derived* from the recognition surface it reasons
//! over (the statement kind it gates on, and — see `category_of_rule`,
//! built on top of this — the fact families its predicate reads). It is
//! never authored on the rule itself, so the rule corpus carries no
//! grouping metadata: categories are the stable vocabulary anything that
//! groups rules refers to.

use super::statement::StatementKind;
use serde::{Deserialize, Serialize};

/// The concern a rule reasons about, derived from recognition.
///
/// A closed, additive vocabulary. Each variant names a property of the SQL
/// surface — *what the rule recognizes* — not a verdict, a severity, or an
/// audience.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuleCategory {
    /// Privileges, roles, users, logins, ownership, and identity / auth /
    /// network / session / password policies.
    AccessControl,
    /// Masking, row-access, aggregation, projection, and join policies —
    /// the confidentiality of data values and rows.
    DataProtection,
    /// Secrets, storage credentials, encryption keys, and code-signing material.
    CredentialsKeys,
    /// Dynamic SQL assembly and execution.
    DynamicSql,
    /// Data leaving the warehouse — unload, export, backup, and sharing.
    DataEgress,
    /// Bulk data entering or relocating — load, ingest, restore, and staging.
    DataMovement,
    /// Connections to external systems — integrations, foreign data, and replication.
    Integration,
    /// Differences between two versions of a statement — breaking-change safety.
    ChangeSafety,
    /// Databases, schemas, warehouses, catalogs, accounts, and resource governance.
    LifecycleGovernance,
    /// Scheduled and automated objects — tasks, streams, pipes, dynamic tables, alerts.
    Orchestration,
    /// Maintenance and optimization operations.
    Maintenance,
    /// Session, transaction, and scripting control-flow mechanics.
    Operations,
    /// Classification labels, comments, audit configuration, and data-quality metadata.
    GovernanceMetadata,
    /// Query and DML shape — correctness, performance, and result semantics.
    Query,
    /// Table, view, index, sequence, and type design and change.
    SchemaDesign,
    /// Functions, procedures, triggers, and stored logic.
    Code,
    /// Provider apps, marketplace listings, container services, and extensions.
    Extensibility,
    /// Cross-script downstream impact — lineage and blast radius.
    LineageImpact,
    /// Recognition incomplete — the statement could not be analyzed.
    Unclassified,
}

impl RuleCategory {
    /// Every category, in declaration order.
    pub const ALL: [RuleCategory; 19] = [
        RuleCategory::AccessControl,
        RuleCategory::DataProtection,
        RuleCategory::CredentialsKeys,
        RuleCategory::DynamicSql,
        RuleCategory::DataEgress,
        RuleCategory::DataMovement,
        RuleCategory::Integration,
        RuleCategory::ChangeSafety,
        RuleCategory::LifecycleGovernance,
        RuleCategory::Orchestration,
        RuleCategory::Maintenance,
        RuleCategory::Operations,
        RuleCategory::GovernanceMetadata,
        RuleCategory::Query,
        RuleCategory::SchemaDesign,
        RuleCategory::Code,
        RuleCategory::Extensibility,
        RuleCategory::LineageImpact,
        RuleCategory::Unclassified,
    ];

    /// Stable kebab-case identifier (matches the serialized form): the
    /// token a category is referenced by.
    pub fn as_str(&self) -> &'static str {
        match self {
            RuleCategory::AccessControl => "access-control",
            RuleCategory::DataProtection => "data-protection",
            RuleCategory::CredentialsKeys => "credentials-keys",
            RuleCategory::DynamicSql => "dynamic-sql",
            RuleCategory::DataEgress => "data-egress",
            RuleCategory::DataMovement => "data-movement",
            RuleCategory::Integration => "integration",
            RuleCategory::ChangeSafety => "change-safety",
            RuleCategory::LifecycleGovernance => "lifecycle-governance",
            RuleCategory::Orchestration => "orchestration",
            RuleCategory::Maintenance => "maintenance",
            RuleCategory::Operations => "operations",
            RuleCategory::GovernanceMetadata => "governance-metadata",
            RuleCategory::Query => "query",
            RuleCategory::SchemaDesign => "schema-design",
            RuleCategory::Code => "code",
            RuleCategory::Extensibility => "extensibility",
            RuleCategory::LineageImpact => "lineage-impact",
            RuleCategory::Unclassified => "unclassified",
        }
    }
}

impl std::fmt::Display for RuleCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Derive a category from a statement kind.
///
/// This is the kind-keyed half of category derivation: it covers every rule
/// whose recognition surface is its statement kind. Rules that gate on a fact
/// family instead of (or in addition to) a kind — `ChangeSafety` (the diff
/// family) and `LineageImpact` (cross-script lineage) — are resolved by the
/// fact-family-aware `category_of_rule` layered on top; this function never
/// returns those two.
///
/// **No `_ =>` arm**: every `StatementKind` is classified explicitly, so a new
/// kind cannot silently fall into a default category — the compiler forces the
/// decision here.
pub fn category_of_kind(kind: StatementKind) -> RuleCategory {
    use RuleCategory as C;
    use StatementKind as K;
    match kind {
        // Query & DML shape (reads and row-level writes).
        K::Select
        | K::SetSelect
        | K::Explain
        | K::Insert
        | K::Update
        | K::Delete
        | K::Merge
        | K::MultiInsert
        | K::BqAssert => C::Query,

        // Data leaving the warehouse.
        K::BqExportData
        | K::BqExportModel
        | K::CopyIntoLocation
        | K::RedshiftUnload
        | K::CreateShare
        | K::AlterShare
        | K::DropShare
        | K::CreateDatashare
        | K::AlterDatashare
        | K::StageGet
        | K::MssqlBackup => C::DataEgress,

        // Bulk data entering / relocating.
        K::BulkInsert
        | K::CopyIntoTable
        | K::PgCopy
        | K::MssqlBulkInsert
        | K::BqLoadData
        | K::MysqlLoadData
        | K::DbxRestore
        | K::RedshiftCopy
        | K::CreateExternalLocation
        | K::AlterExternalLocation
        | K::DropExternalLocation
        | K::CreateStage
        | K::AlterStage
        | K::DropStage
        | K::CreateFileFormat
        | K::AlterFileFormat
        | K::DropFileFormat
        | K::StagePut
        | K::MssqlRestore
        | K::DbxClone => C::DataMovement,

        // Who can do / connect as what.
        K::Grant
        | K::Revoke
        | K::Deny
        | K::PgDefaultPrivileges
        | K::AlterAuthorization
        | K::MssqlAlterLogin
        | K::MssqlDropLogin
        | K::MssqlCreateLogin
        | K::MssqlCreateUser
        | K::MssqlExecuteAs
        | K::MssqlRevert
        | K::MssqlSetuser
        | K::MssqlCreateSecurityObject
        | K::MssqlAlterSecurityObject
        | K::MssqlDropSecurityObject
        | K::CreateNetworkPolicy
        | K::AlterNetworkPolicy
        | K::DropNetworkPolicy
        | K::CreateSessionPolicy
        | K::AlterSessionPolicy
        | K::DropSessionPolicy
        | K::CreatePasswordPolicy
        | K::AlterPasswordPolicy
        | K::DropPasswordPolicy
        | K::CreateAuthenticationPolicy
        | K::AlterAuthenticationPolicy
        | K::DropAuthenticationPolicy
        | K::CreateRole
        | K::AlterRole
        | K::DropRole
        | K::CreateUser
        | K::AlterUser
        | K::DropUser
        | K::PgCreateRole
        | K::PgAlterRole
        | K::PgDropRole
        | K::PgDropOwned
        | K::PgReassignOwned
        | K::CreateGroup
        | K::AlterGroup
        | K::CreateNetworkRule
        | K::AlterNetworkRule
        | K::DropNetworkRule => C::AccessControl,

        // Confidentiality of values and rows.
        K::CreateMaskingPolicy
        | K::AlterMaskingPolicy
        | K::DropMaskingPolicy
        | K::CreateRowAccessPolicy
        | K::AlterRowAccessPolicy
        | K::DropRowAccessPolicy
        | K::CreateAggregationPolicy
        | K::AlterAggregationPolicy
        | K::DropAggregationPolicy
        | K::CreateProjectionPolicy
        | K::CreateJoinPolicy
        | K::AlterProjectionPolicy
        | K::AlterJoinPolicy
        | K::DropProjectionPolicy
        | K::DropJoinPolicy
        | K::PgCreatePolicy
        | K::PgAlterPolicy
        | K::PgDropPolicy
        | K::DropAllRowAccessPolicies
        | K::MssqlSecurityPolicy => C::DataProtection,

        // Secrets, credentials, keys, signing material.
        K::CreateStorageCredential
        | K::AlterStorageCredential
        | K::DropStorageCredential
        | K::CreateSecret
        | K::AlterSecret
        | K::DropSecret
        | K::MssqlKeyManagement
        | K::MssqlKeyBackup
        | K::MssqlServiceMasterKey
        | K::MssqlAddSignature => C::CredentialsKeys,

        // Dynamic SQL.
        K::ExecuteImmediate | K::ExecuteImmediateFrom | K::Exec | K::MssqlExec => C::DynamicSql,

        // External-system connections, foreign data, replication.
        K::CreateSecurityIntegration
        | K::AlterSecurityIntegration
        | K::DropSecurityIntegration
        | K::CreateConnection
        | K::AlterConnection
        | K::DropConnection
        | K::CreateExternalDataSource
        | K::AlterExternalDataSource
        | K::CreateForeignServer
        | K::AlterForeignServer
        | K::CreateUserMapping
        | K::AlterUserMapping
        | K::DropUserMapping
        | K::CreateForeignTable
        | K::ImportForeignSchema
        | K::CreateApiIntegration
        | K::AlterApiIntegration
        | K::DropApiIntegration
        | K::CreateStorageIntegration
        | K::AlterStorageIntegration
        | K::DropStorageIntegration
        | K::CreateNotificationIntegration
        | K::AlterNotificationIntegration
        | K::DropNotificationIntegration
        | K::CreateExternalAccessIntegration
        | K::AlterExternalAccessIntegration
        | K::DropExternalAccessIntegration
        | K::PgPublication
        | K::PgSubscription
        | K::PgCreateSubscription
        | K::PgAlterSubscription
        | K::PgDropSubscription
        | K::PgCreatePublication
        | K::PgAlterPublication
        | K::PgDropPublication => C::Integration,

        // Account / database / schema / warehouse / resource governance.
        K::AlterAccount
        | K::CreateAccount
        | K::DropAccount
        | K::CreateSchema
        | K::AlterSchema
        | K::DropSchema
        | K::RenameSchema
        | K::CloneSchema
        | K::UndropSchema
        | K::CreateDatabase
        | K::AlterDatabase
        | K::DropDatabase
        | K::RenameDatabase
        | K::CloneDatabase
        | K::UndropDatabase
        | K::CreateCatalog
        | K::AlterCatalog
        | K::DropCatalog
        | K::CreateVolume
        | K::AlterVolume
        | K::DropVolume
        | K::CreateWarehouse
        | K::AlterWarehouse
        | K::DropWarehouse
        | K::CreateResourceMonitor
        | K::AlterResourceMonitor
        | K::DropResourceMonitor
        | K::AlterReplicationGroup
        | K::AlterFailoverGroup
        | K::CreateReplicationGroup
        | K::DropReplicationGroup
        | K::CreateFailoverGroup
        | K::DropFailoverGroup
        | K::PgAlterSystem
        | K::AlterServerConfiguration
        | K::PgCreateTablespace
        | K::PgAlterTablespace
        | K::PgDropTablespace => C::LifecycleGovernance,

        // Scheduled / automated objects.
        K::CreateTask
        | K::AlterTask
        | K::DropTask
        | K::CreateEvent
        | K::AlterEvent
        | K::CreateDynamicTable
        | K::AlterDynamicTable
        | K::DropDynamicTable
        | K::CreatePipe
        | K::AlterPipe
        | K::DropPipe
        | K::CreateStream
        | K::AlterStream
        | K::DropStream
        | K::CreateAlert
        | K::AlterAlert
        | K::DropAlert
        | K::CreateFlow => C::Orchestration,

        // Maintenance / optimization.
        K::PgRefreshMatview
        | K::PgReindex
        | K::PgCluster
        | K::MssqlDbcc
        | K::AnalyzeStmt
        | K::DbxOptimize
        | K::DbxVacuum
        | K::DbxDescribeHistory
        | K::DbxRepairTable
        | K::DbxCacheTable
        | K::DbxUncacheTable => C::Maintenance,

        // Session / transaction / scripting control-flow mechanics.
        K::Use
        | K::Show
        | K::Set
        | K::Reset
        | K::BeginTransaction
        | K::Commit
        | K::Rollback
        | K::Savepoint
        | K::If
        | K::Case
        | K::While
        | K::For
        | K::Loop
        | K::Repeat
        | K::TryCatch
        | K::Block
        | K::Declare
        | K::DeclareTable
        | K::DeclareCursor
        | K::OpenCursor
        | K::FetchCursor
        | K::CloseCursor
        | K::DeclareHandler
        | K::DoBlock
        | K::PgLockTable
        | K::PgSet
        | K::PgDiscard
        | K::PgListen
        | K::PgNotify
        | K::PgUnlisten
        | K::PgPrepare
        | K::PgExecute
        | K::PgDeallocate
        | K::MssqlSetOption
        | K::Reconfigure
        | K::AlterSession
        | K::StageRemove
        | K::StageList => C::Operations,

        // Classification, comments, audit, data-quality metadata.
        K::CreateTag
        | K::AlterTag
        | K::DropTag
        | K::UndropTag
        | K::Comment
        | K::CreateDataMetricFunction
        | K::DropDataMetricFunction
        | K::MssqlCreateAudit
        | K::MssqlAlterAudit
        | K::MssqlDropAudit => C::GovernanceMetadata,

        // Table / view / index / sequence / type design.
        K::CreateTable
        | K::AlterTable
        | K::DropTable
        | K::Truncate
        | K::RenameTable
        | K::CloneTable
        | K::UndropTable
        | K::CreateView
        | K::AlterView
        | K::DropView
        | K::CreateMaterializedView
        | K::AlterMaterializedView
        | K::DropMaterializedView
        | K::CreateIndex
        | K::AlterIndex
        | K::PgDropIndex
        | K::CreateSynonym
        | K::CreateSequence
        | K::AlterSequence
        | K::DropSequence
        | K::PgDropSequence
        | K::PgCreateDomain
        | K::PgAlterDomain
        | K::PgDropDomain
        | K::PgCreateType
        | K::PgAlterType
        | K::PgDropType
        | K::UndropType
        | K::CreateExternalTable
        | K::AlterExternalTable
        | K::DropExternalTable
        | K::CreateExternalSchema
        | K::MssqlCreateVectorIndex
        | K::BqCreateSnapshotTable
        | K::BqDropSnapshotTable
        | K::BqCreateSearchIndex
        | K::BqDropSearchIndex
        | K::BqCreateVectorIndex
        | K::BqAlterVectorIndex
        | K::BqDropVectorIndex => C::SchemaDesign,

        // Stored logic.
        K::CreateProcedure
        | K::AlterProcedure
        | K::DropProcedure
        | K::CreateFunction
        | K::AlterFunction
        | K::DropFunction
        | K::CreateExternalFunction
        | K::CreateTrigger
        | K::AlterTrigger
        | K::DropTrigger
        | K::PgCreateTrigger
        | K::PgAlterTrigger
        | K::PgDropTrigger
        | K::PgAlterTableTriggerState
        | K::CreateMysqlTrigger
        | K::MssqlDropTrigger
        | K::PgCreateRule
        | K::PgAlterRule
        | K::PgDropRule
        | K::PgCreateAggregate
        | K::PgCreateOperator
        | K::MssqlCreateExternalModel
        | K::MssqlAlterExternalModel
        | K::MssqlDropExternalModel
        | K::BqCreateModel
        | K::BqAlterModel
        | K::BqDropModel
        | K::Call => C::Code,

        // Provider apps, marketplace, container surfaces, extensions.
        K::CreateComputePool
        | K::AlterComputePool
        | K::DropComputePool
        | K::CreateGitRepository
        | K::AlterGitRepository
        | K::DropGitRepository
        | K::CreateImageRepository
        | K::AlterImageRepository
        | K::DropImageRepository
        | K::CreateStreamlit
        | K::AlterStreamlit
        | K::DropStreamlit
        | K::CreateService
        | K::AlterService
        | K::DropService
        | K::CreateNotebook
        | K::AlterNotebook
        | K::DropNotebook
        | K::CreateSemanticView
        | K::AlterSemanticView
        | K::DropSemanticView
        | K::CreateCortexSearchService
        | K::AlterCortexSearchService
        | K::DropCortexSearchService
        | K::CreateApplication
        | K::AlterApplication
        | K::DropApplication
        | K::CreateApplicationPackage
        | K::AlterApplicationPackage
        | K::DropApplicationPackage
        | K::CreateListing
        | K::AlterListing
        | K::DropListing
        | K::CreateManagedAccount
        | K::DropManagedAccount
        | K::PgCreateExtension
        | K::PgAlterExtension
        | K::PgDropExtension
        | K::MssqlAssembly => C::Extensibility,

        // Recognition incomplete.
        K::Opaque => C::Unclassified,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn representative_kinds_classify_as_expected() {
        assert_eq!(
            category_of_kind(StatementKind::Grant),
            RuleCategory::AccessControl
        );
        assert_eq!(
            category_of_kind(StatementKind::CreateMaskingPolicy),
            RuleCategory::DataProtection
        );
        assert_eq!(
            category_of_kind(StatementKind::CopyIntoLocation),
            RuleCategory::DataEgress
        );
        assert_eq!(
            category_of_kind(StatementKind::MssqlExec),
            RuleCategory::DynamicSql
        );
        assert_eq!(
            category_of_kind(StatementKind::CreateWarehouse),
            RuleCategory::LifecycleGovernance
        );
        assert_eq!(
            category_of_kind(StatementKind::CreateTask),
            RuleCategory::Orchestration
        );
        assert_eq!(category_of_kind(StatementKind::Select), RuleCategory::Query);
        assert_eq!(
            category_of_kind(StatementKind::CreateProcedure),
            RuleCategory::Code
        );
        // Extensibility is reachable from a statement kind — not a recognition gap.
        assert_eq!(
            category_of_kind(StatementKind::CreateApplication),
            RuleCategory::Extensibility
        );
        assert_eq!(
            category_of_kind(StatementKind::Opaque),
            RuleCategory::Unclassified
        );
    }

    #[test]
    fn as_str_matches_serialized_form() {
        // Stable identifiers a category is referenced by.
        assert_eq!(RuleCategory::AccessControl.as_str(), "access-control");
        assert_eq!(RuleCategory::LineageImpact.as_str(), "lineage-impact");
        for c in RuleCategory::ALL {
            // round-trips through serde with the same token.
            let json = serde_json::to_string(&c).expect("serialize");
            assert_eq!(json, format!("\"{}\"", c.as_str()));
        }
    }

    #[test]
    fn all_array_covers_every_variant_once() {
        // Length guard: ALL must list each variant exactly once. If a variant
        // is added, bump the array and this stays honest.
        let mut seen = std::collections::HashSet::new();
        for c in RuleCategory::ALL {
            assert!(seen.insert(c), "duplicate in ALL: {c}");
        }
        assert_eq!(seen.len(), 19);
    }
}
