// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Per-statement semantic ledger for risk analysis
//!
//! This module implements the single source of truth for statement semantics.
//! All metrics are derived from the ledger, never pushed directly.

use crate::ast::NodeId;
use crate::context::node_metadata::TableRef;
use crate::facts::statement::{StatementFacts, StatementKind};
use crate::facts::ObjectKind;
use crate::lexer::Span;
use std::collections::{BTreeMap, HashSet};

/// Statement classification (exactly one per statement)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatementClassification {
    /// SELECT, WITH ... SELECT, VALUES (as query), SHOW (if treated as query)
    DmlRead,
    /// INSERT / UPDATE / DELETE / MERGE
    DmlWrite,
    /// CREATE / ALTER / DROP / REPLACE / TRUNCATE / COMMENT / RENAME / UNDROP
    Ddl,
    /// GRANT / REVOKE (including GRANT OWNERSHIP)
    Security,
    /// USE ROLE, USE WAREHOUSE, USE DATABASE/SCHEMA, CALL, BEGIN/COMMIT/ROLLBACK,
    /// DECLARE, RETURN, SET, EXECUTE IMMEDIATE, SHOW (if not query), DESCRIBE
    Control,
    /// Jinja/template constructs: {{ config() }}, {% set %}, {% if %} blocks
    /// These are NOT SQL statements but template directives
    Jinja,
    /// Unimplemented or skipped (OpaqueContent, ClauseFragment, expressions)
    Unknown,
}

/// Classify a [`StatementKind`] into a [`StatementClassification`].
///
/// This is the single source of truth for statement classification on
/// the IR-native (facts) path.
///
/// **NO WILDCARD CATCH-ALL**: Every `StatementKind` variant is listed
/// explicitly. When a new kind is added, the compiler forces you to
/// classify it here. This prevents the silent "Unknown" fallthrough bug.
pub fn classify_statement_kind(kind: StatementKind) -> StatementClassification {
    use StatementKind as K;
    match kind {
        // DmlRead: SELECT, set-operations, EXPLAIN
        K::Select | K::SetSelect | K::Explain => StatementClassification::DmlRead,

        // DmlWrite: writes that produce table state changes.
        // `DbxRestore` rolls the table back to a prior snapshot —
        // semantically a write (it mutates current state) even though
        // its surface is Delta-table maintenance.
        K::Insert
        | K::Update
        | K::Delete
        | K::Merge
        | K::MultiInsert
        | K::BulkInsert
        | K::CopyIntoTable
        | K::PgCopy
        | K::MssqlBulkInsert
        | K::BqLoadData
        | K::MysqlLoadData
        | K::DbxRestore => StatementClassification::DmlWrite,

        // BqExportData reads a table and writes to external storage;
        // classifies as DmlRead for read-set attribution. The
        // destination (GCS / file) is not tracked as a table.
        K::BqExportData => StatementClassification::DmlRead,

        // Security: privileges, policies, principals, server config
        K::Grant
        | K::Revoke
        | K::Deny
        | K::PgDefaultPrivileges
        | K::AlterAuthorization
        | K::MssqlAlterLogin
        | K::MssqlDropLogin
        | K::MssqlExecuteAs
        | K::MssqlRevert
        | K::MssqlCreateAudit
        | K::MssqlAlterAudit
        | K::MssqlDropAudit
        | K::MssqlCreateSecurityObject
        | K::MssqlAlterSecurityObject
        | K::MssqlDropSecurityObject
        | K::CreateMaskingPolicy
        | K::AlterMaskingPolicy
        | K::DropMaskingPolicy
        | K::CreateRowAccessPolicy
        | K::AlterRowAccessPolicy
        | K::DropRowAccessPolicy
        | K::CreateNetworkPolicy
        | K::AlterNetworkPolicy
        | K::DropNetworkPolicy
        | K::CreateSessionPolicy
        | K::AlterSessionPolicy
        | K::DropSessionPolicy
        | K::CreatePasswordPolicy
        | K::AlterPasswordPolicy
        | K::DropPasswordPolicy
        | K::CreateAggregationPolicy
        | K::AlterAggregationPolicy
        | K::DropAggregationPolicy
        | K::CreateProjectionPolicy
        | K::CreateJoinPolicy
        | K::AlterProjectionPolicy
        | K::AlterJoinPolicy
        | K::DropProjectionPolicy
        | K::DropJoinPolicy
        | K::CreateAuthenticationPolicy
        | K::AlterAuthenticationPolicy
        | K::DropAuthenticationPolicy
        | K::PgCreatePolicy
        | K::PgAlterPolicy
        | K::PgDropPolicy
        | K::CreateRole
        | K::AlterRole
        | K::DropRole
        | K::CreateUser
        | K::AlterUser
        | K::RenameUser
        | K::DropUser
        | K::AlterAccount
        | K::CreateShare
        | K::AlterShare
        | K::DropShare
        | K::CreateDatashare
        | K::AlterDatashare
        | K::CreateSecurityIntegration
        | K::AlterSecurityIntegration
        | K::DropSecurityIntegration
        | K::AlterReplicationGroup
        | K::AlterFailoverGroup
        | K::CreateReplicationGroup
        | K::DropReplicationGroup
        | K::CreateFailoverGroup
        | K::DropFailoverGroup
        | K::PgCreateRole
        | K::PgAlterRole
        | K::PgDropRole
        | K::PgDropOwned
        | K::PgReassignOwned
        | K::PgAlterSystem
        | K::MssqlCreateLogin
        | K::MssqlCreateUser => StatementClassification::Security,

        // DDL: schema-shape changes
        K::CreateTable
        | K::AlterTable
        | K::DropTable
        | K::Truncate
        | K::RenameTable
        | K::CloneTable
        | K::UndropTable
        | K::DropAllRowAccessPolicies
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
        | K::CreateExternalLocation
        | K::AlterExternalLocation
        | K::DropExternalLocation
        | K::CreateConnection
        | K::AlterConnection
        | K::DropConnection
        | K::CreateExternalDataSource
        | K::AlterExternalDataSource
        | K::CreateForeignServer
        | K::AlterForeignServer
        | K::AlterServerConfiguration
        | K::CreateUserMapping
        | K::AlterUserMapping
        | K::DropUserMapping
        | K::CreateForeignTable
        | K::ImportForeignSchema
        | K::CreateFlow
        | K::CreateProcedure
        | K::AlterProcedure
        | K::DropProcedure
        | K::CreateFunction
        | K::AlterFunction
        | K::DropFunction
        | K::CreateExternalFunction
        | K::CreateDataMetricFunction
        | K::DropDataMetricFunction
        | K::CreateTrigger
        | K::AlterTrigger
        | K::DropTrigger
        | K::PgCreateTrigger
        | K::PgAlterTrigger
        | K::PgDropTrigger
        | K::PgAlterTableTriggerState
        | K::CreateStage
        | K::AlterStage
        | K::DropStage
        | K::CreateApiIntegration
        | K::AlterApiIntegration
        | K::DropApiIntegration
        | K::CreateStorageIntegration
        | K::AlterStorageIntegration
        | K::DropStorageIntegration
        | K::CreateStorageCredential
        | K::AlterStorageCredential
        | K::DropStorageCredential
        | K::CreateWarehouse
        | K::AlterWarehouse
        | K::DropWarehouse
        | K::CreateTask
        | K::AlterTask
        | K::DropTask
        | K::CreateEvent
        | K::AlterEvent
        | K::CreateMysqlTrigger
        | K::CreateDynamicTable
        | K::AlterDynamicTable
        | K::DropDynamicTable
        | K::CreateNotificationIntegration
        | K::AlterNotificationIntegration
        | K::DropNotificationIntegration
        | K::CreateExternalTable
        | K::AlterExternalTable
        | K::DropExternalTable
        | K::CreateExternalSchema
        | K::CreateExternalAccessIntegration
        | K::AlterExternalAccessIntegration
        | K::DropExternalAccessIntegration
        | K::CreateNetworkRule
        | K::AlterNetworkRule
        | K::DropNetworkRule
        | K::CreateResourceMonitor
        | K::AlterResourceMonitor
        | K::DropResourceMonitor
        | K::CreateComputePool
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
        | K::CreateAccount
        | K::DropAccount
        | K::StagePut
        | K::StageGet
        | K::StageRemove
        | K::StageList
        | K::CreateAlert
        | K::AlterAlert
        | K::DropAlert
        | K::CreateTag
        | K::AlterTag
        | K::DropTag
        | K::UndropTag
        | K::CreateFileFormat
        | K::AlterFileFormat
        | K::DropFileFormat
        | K::CreateSecret
        | K::AlterSecret
        | K::DropSecret
        | K::CreateSequence
        | K::AlterSequence
        | K::DropSequence
        | K::CreatePipe
        | K::AlterPipe
        | K::DropPipe
        | K::CreateStream
        | K::AlterStream
        | K::DropStream
        | K::CopyIntoLocation
        | K::RedshiftUnload
        | K::RedshiftCopy
        | K::CreateGroup
        | K::AlterGroup
        | K::Comment
        | K::PgCreateExtension
        | K::PgAlterExtension
        | K::PgDropExtension
        | K::PgCreateDomain
        | K::PgAlterDomain
        | K::PgDropDomain
        | K::PgCreateType
        | K::PgAlterType
        | K::PgDropType
        | K::UndropType
        | K::PgDropSequence
        | K::PgCreateRule
        | K::PgAlterRule
        | K::PgDropRule
        | K::PgCreateTablespace
        | K::PgAlterTablespace
        | K::PgDropTablespace
        | K::PgPublication
        | K::PgSubscription
        | K::PgCreateSubscription
        | K::PgAlterSubscription
        | K::PgDropSubscription
        | K::PgCreatePublication
        | K::PgAlterPublication
        | K::PgDropPublication
        | K::PgRefreshMatview
        | K::PgReindex
        | K::PgCluster
        | K::PgCreateAggregate
        | K::PgCreateOperator
        | K::MssqlCreateExternalModel
        | K::MssqlAlterExternalModel
        | K::MssqlDropExternalModel
        | K::MssqlCreateVectorIndex
        | K::MssqlDropTrigger
        | K::MssqlTriggerState
        | K::BqCreateModel
        | K::BqAlterModel
        | K::BqDropModel
        | K::BqCreateSnapshotTable
        | K::BqDropSnapshotTable
        | K::BqCreateSearchIndex
        | K::BqDropSearchIndex
        | K::BqCreateVectorIndex
        | K::BqAlterVectorIndex
        | K::BqDropVectorIndex => StatementClassification::Ddl,

        // Control: session state, scripting, transactions, dynamic SQL,
        // observability statements (EXPORT / ASSERT / OPTIMIZE / VACUUM)
        K::Use
        | K::Show
        | K::Describe
        | K::MssqlBackup
        | K::MssqlRestore
        | K::MssqlDbcc
        | K::MssqlKeyManagement
        | K::MssqlSecurityPolicy
        | K::MssqlKeyBackup
        | K::MssqlAssembly
        | K::MssqlAddSignature
        | K::MssqlSetuser
        | K::MssqlServiceMasterKey
        | K::Set
        | K::Reset
        | K::BeginTransaction
        | K::Commit
        | K::Rollback
        | K::Savepoint
        | K::ExecuteImmediate
        | K::ExecuteImmediateFrom
        | K::Exec
        | K::If
        | K::Case
        | K::While
        | K::For
        | K::Loop
        | K::Repeat
        | K::TryCatch
        | K::Block
        | K::PipeChain
        | K::MssqlWaitfor
        | K::MssqlPrint
        | K::MssqlThrow
        | K::MssqlRaiserror
        | K::MysqlDo
        | K::Declare
        | K::DeclareTable
        | K::DeclareCursor
        | K::OpenCursor
        | K::FetchCursor
        | K::CloseCursor
        | K::DeclareHandler
        | K::PgLockTable
        | K::PgSet
        | K::PgDiscard
        | K::PgListen
        | K::PgNotify
        | K::PgUnlisten
        | K::PgPrepare
        | K::PgExecute
        | K::PgDeallocate
        | K::DoBlock
        | K::AnalyzeStmt
        | K::Call
        | K::ExecuteTask
        | K::MssqlExec
        | K::MssqlSetOption
        | K::Reconfigure
        | K::MssqlServerCommand
        | K::OptimizeTable
        | K::CheckTable
        | K::ChecksumTable
        | K::RepairTable
        | K::Flush
        | K::Kill
        | K::AlterInstance
        | K::XaTransaction
        | K::AlterSession
        | K::BqAssert
        | K::Assert
        | K::BqExportModel
        | K::DbxOptimize
        | K::DbxVacuum
        | K::DbxClone
        | K::DbxDescribeHistory
        | K::DbxRepairTable
        | K::DbxCacheTable
        | K::DbxUncacheTable => StatementClassification::Control,

        // Unknown: lowering failure
        K::Opaque => StatementClassification::Unknown,
    }
}

/// Semantic information for a single statement (immutable after creation).
///
/// Sourced from IR-native [`StatementFacts`] via
/// [`StatementLedger::populate_from_facts`].
#[derive(Debug, Clone)]
pub struct StatementSemantics {
    /// Exactly one classification per statement
    pub classification: StatementClassification,

    /// The statement's kind.
    pub(crate) kind: StatementKind,

    /// Source span
    pub span: Span,

    /// Whether the statement's outer scope has a WHERE clause
    pub has_where: bool,

    /// Whether the outer-scope WHERE clause contains at least one
    /// tautology subexpression (e.g. `1=1`, `TRUE`). Drives
    /// `has_unbounded_write` in [`StatementLedger::derive_metrics`].
    pub has_tautology_where: bool,

    /// Tables referenced (SELECT / JOIN / subqueries / read side of MERGE).
    /// Populated for DmlRead, DmlWrite, Security, Control.
    pub tables_read: Vec<TableRef>,

    /// Tables written by DML (only populated when classification == DmlWrite).
    /// Empty for non-DML-WRITE statements.
    pub tables_written: Vec<TableRef>,

    /// Tables modified by DDL: the statement's DDL target where that is a
    /// table, a view, a materialized view, a dynamic table or an external
    /// table. Empty for a statement with no such target.
    pub tables_modified_ddl: Vec<TableRef>,

    /// The object a DDL statement targets, of whatever kind.
    pub(crate) ddl_target: Option<TableRef>,

    /// The statement is in the body of a routine, trigger, event, task or
    /// rule, which the statement creating it defines and does not run.
    pub defined: bool,
    /// The kind of `ddl_target`, where the statement changes it: none
    /// for a target the statement only reads.
    pub(crate) changed_object_kind: Option<ObjectKind>,

    /// The object whose privileges a GRANT, REVOKE or DENY changes, and
    /// its kind.
    pub(crate) privilege_target: Option<(ObjectKind, TableRef)>,

    /// The objects after the first of a list the statement changes, with
    /// their kinds (`DROP TABLE a, b`, `GRANT … ON a, b`).
    pub(crate) further_objects: Vec<(ObjectKind, TableRef)>,

    /// The routine, task or prepared statement the statement runs, and its
    /// kind.
    pub(crate) run_target: Option<(ObjectKind, TableRef)>,

    /// The tables of the three lists that an attached catalog is asked
    /// for, from every fact of the statement.
    pub(crate) catalog_subjects: Vec<CatalogSubject>,
}

/// A table a statement names, for the question whether an attached
/// catalog has it.
#[derive(Debug, Clone)]
pub(crate) struct CatalogSubject {
    /// Source offset the statement names the table at.
    pub(crate) at: u32,
    pub(crate) table: TableRef,
    /// The catalog's answer where lowering asked it for this table; `None`
    /// where it did not.
    pub(crate) in_catalog: Option<bool>,
    /// Whether a query of the statement reads or writes the table. Lowering
    /// asks the catalog for every such table but a session's own and a
    /// stage, so where it has no answer the catalog is not asked again.
    pub(crate) queried: bool,
    /// Whether the statement creates the table.
    pub(crate) created: bool,
    /// The statement naming it.
    pub(crate) statement: Span,
}

impl CatalogSubject {
    /// Its place in script order. A statement reads before it creates: a
    /// created table falls where its statement ends, after everything that
    /// statement names and before the statement that follows.
    pub(crate) fn script_order(&self) -> (u32, u32, bool) {
        let place = if self.created {
            self.statement.end
        } else {
            self.at
        };
        (place, self.statement.start, self.created)
    }
}

impl StatementSemantics {
    /// Tables referenced (SELECT / JOIN / subqueries / read side of MERGE).
    pub fn tables_read(&self) -> &[TableRef] {
        &self.tables_read
    }

    /// Tables written by DML (only if classification == DmlWrite).
    pub fn tables_written_dml(&self) -> &[TableRef] {
        if self.classification == StatementClassification::DmlWrite {
            &self.tables_written
        } else {
            &[]
        }
    }

    /// Tables modified by DDL (only if classification == Ddl).
    pub fn tables_modified_ddl(&self) -> &[TableRef] {
        if self.classification == StatementClassification::Ddl {
            &self.tables_modified_ddl
        } else {
            &[]
        }
    }

    /// The object a DDL statement targets, of whatever kind (only if
    /// classification == Ddl).
    fn ddl_object(&self) -> Option<&TableRef> {
        if self.classification == StatementClassification::Ddl {
            self.ddl_target.as_ref()
        } else {
            None
        }
    }
}

/// Single source of truth: StatementId → StatementSemantics
///
/// INVARIANT: statements_parsed() == entries.len() (by definition)
/// INVARIANT: statements_analyzed + statements_skipped == statements_parsed (always)
///
/// Note: statements_parsed is derived from entries.len() to guarantee the invariant.
#[derive(Debug, Clone, Default)]
pub struct StatementLedger {
    // Keyed by the offset a statement starts at, so iteration is in script order.
    pub(crate) entries: BTreeMap<NodeId, StatementSemantics>,
    /// Tracks span starts that have been added (for dedup)
    span_starts: std::collections::HashSet<u32>,
    /// Whether ledger has been finalized (invariant check)
    finalized: bool,
    /// Span starts of the statements whose DDL target the parser read as a
    /// session's own table or a stage: no catalog holds it.
    uncatalogued_ddl_targets: std::collections::BTreeSet<u32>,
}

impl StatementLedger {
    /// Record that the DDL target of the statement starting at
    /// `statement_start` is a session's own table or a stage, so an
    /// attached catalog is not asked for it.
    pub(crate) fn record_uncatalogued_ddl_target(&mut self, statement_start: u32) {
        self.uncatalogued_ddl_targets.insert(statement_start);
    }

    /// Create empty ledger
    pub fn new() -> Self {
        Self::default()
    }

    /// Reopen the ledger for recording. The argument is unused: the
    /// parsed count is derived from the recorded entries.
    #[allow(unused_variables)]
    pub fn initialize(&mut self, _statements_parsed: usize) {
        self.finalized = false;
    }

    /// Get number of top-level statements from parser.
    ///
    /// This is now derived from ledger entries to ensure the invariant
    /// `statements_parsed == analyzed + skipped` always holds.
    pub fn statements_parsed(&self) -> usize {
        // Derive from entries to guarantee invariant
        self.entries.len()
    }

    /// Get number of actual SQL statements (excludes Jinja and Unknown).
    /// This is what users care about - real executable SQL.
    pub fn sql_statements(&self) -> usize {
        self.entries
            .values()
            .filter(|s| {
                !matches!(
                    s.classification,
                    StatementClassification::Jinja | StatementClassification::Unknown
                )
            })
            .count()
    }

    /// Get number of Jinja/template blocks (not SQL statements).
    /// These are {{ config() }}, {% set %}, {% if %} etc.
    pub fn jinja_blocks(&self) -> usize {
        self.entries
            .values()
            .filter(|s| s.classification == StatementClassification::Jinja)
            .count()
    }

    /// Get number of statements analyzed (entries in ledger, excluding Unknown and Jinja)
    /// These are SQL statements we successfully classified.
    pub fn statements_analyzed(&self) -> usize {
        self.sql_statements()
    }

    /// Get number of statements skipped (Unknown classification)
    /// These are entries we couldn't classify (OpaqueContent, ClauseFragment, etc.)
    pub fn statements_skipped(&self) -> usize {
        self.entries
            .values()
            .filter(|s| s.classification == StatementClassification::Unknown)
            .count()
    }

    /// Get total entries in ledger (equals statements_parsed by definition)
    pub fn total_entries(&self) -> usize {
        self.entries.len()
    }

    /// Verify invariant: analyzed + skipped + jinja == total_entries
    ///
    /// This invariant is now guaranteed by construction since all values
    /// are derived from entries.len(). Kept for defensive checks.
    pub fn verify_invariant(&self) -> Result<(), String> {
        let analyzed = self.statements_analyzed();
        let skipped = self.statements_skipped();
        let jinja = self.jinja_blocks();
        let total = self.total_entries();

        if analyzed + skipped + jinja != total {
            return Err(format!(
                "LEDGER INVARIANT VIOLATED: analyzed({}) + skipped({}) + jinja({}) = {} != total_entries({})",
                analyzed, skipped, jinja, analyzed + skipped + jinja, total
            ));
        }

        Ok(())
    }

    /// Add statement to ledger. Only adds if span_start is new (no duplicates);
    /// a later statement at a recorded start adds its catalog subjects to
    /// the entry already there.
    pub fn add_statement(&mut self, node_id: NodeId, semantics: StatementSemantics) {
        let span_start = semantics.span.start;

        // Only add if this span_start hasn't been seen
        // (prevents triple-counting from blast_radius, cost_risk, policy analyzers)
        if self.span_starts.insert(span_start) {
            self.entries.insert(node_id, semantics);
        } else if let Some(first) = self.entries.get_mut(&node_id) {
            first.catalog_subjects.extend(semantics.catalog_subjects);
        }
    }

    /// Fold one statement of the IR-native [`StatementFacts`] stream
    /// produced by the v1 fact pipeline into the ledger. Called once
    /// per statement as facts are derived, so the stream is never
    /// retained whole — its carrier is large and scripts can run to
    /// thousands of statements.
    ///
    /// One ledger entry is created per [`StatementFacts`]. The entry's
    /// classification is derived from [`classify_statement_kind`], and
    /// `tables_read` / `tables_written` / `tables_modified_ddl` are
    /// projected from `query.reads_table[]` / `query.writes_table[]` /
    /// `ddl.target` respectively.
    ///
    /// `body_regions` carries the source spans of every procedure /
    /// function body in the script. The DDL and query rule evaluators
    /// flatten each body depth-first so inner statements are rule-
    /// evaluated, which pushes the body's control-flow scaffolding
    /// (the BEGIN/END wrapper, `RETURN`, `IF`/`WHILE`/loops) into the
    /// same fact stream. That scaffolding lowers to
    /// [`StatementKind::Opaque`] — it is not unrecognized top-level SQL,
    /// and it is accounted separately via `statements_in_bodies`. A fact
    /// that classifies Unknown and whose span is contained in a body
    /// region is therefore skipped so it does not inflate
    /// `statements_skipped`. Body-nested statements with a real
    /// classification (inner DML/DDL) still create entries, preserving
    /// their table-access projection; genuine top-level Opaque is never
    /// contained in a body region and still counts as skipped.
    ///
    /// `defined_regions` are the bodies whose statements the script defines
    /// and does not run: those of routines, triggers, events, tasks and
    /// rules, not of a `DO` block.
    pub fn populate_from_fact(
        &mut self,
        fact: &StatementFacts,
        body_regions: &[Span],
        defined_regions: &[Span],
    ) {
        self.finalized = true;
        let classification = classify_statement_kind(fact.kind);
        let span = fact.source_span.unwrap_or(Span { start: 0, end: 0 });

        if classification == StatementClassification::Unknown
            && body_regions
                .iter()
                .any(|r| span.start >= r.start && span.end <= r.end)
        {
            return;
        }

        let (has_where, has_tautology_where, mut tables_read, mut tables_written) =
            if let Some(q) = fact.query.as_ref() {
                let reads: Vec<TableRef> = q
                    .reads_table
                    .iter()
                    .map(|te| facts_tableref_to_metadata(&te.table))
                    .collect();
                let writes: Vec<TableRef> = q
                    .writes_table
                    .iter()
                    .map(|te| facts_tableref_to_metadata(&te.table))
                    .collect();
                (q.has_where, q.has_tautology_where, reads, writes)
            } else {
                (false, false, Vec::new(), Vec::new())
            };

        // DDL target → tables_modified_ddl. Only project when the
        // target's object kind is a table-shaped surface (Table,
        // View, MaterializedView, DynamicTable, ExternalTable). Other
        // ObjectKinds (Stage, Pipe, Procedure, etc.) are not tracked
        // as table modifications.
        let ddl_object = fact.ddl.as_ref().and_then(|d| d.target.as_ref());
        let ddl_target: Option<TableRef> =
            ddl_object.map(|obj| facts_tableref_to_metadata(&obj.name));
        let table_shaped = ddl_object.is_some_and(|obj| {
            matches!(
                obj.kind,
                crate::facts::ObjectKind::Table
                    | crate::facts::ObjectKind::View
                    | crate::facts::ObjectKind::MaterializedView
                    | crate::facts::ObjectKind::DynamicTable
                    | crate::facts::ObjectKind::ExternalTable
            )
        });
        // The objects after the first of a list (`DROP TABLE a, b`).
        let further_ddl: Vec<TableRef> = fact
            .ddl
            .iter()
            .flat_map(|d| d.targets.iter().skip(1))
            .map(|obj| facts_tableref_to_metadata(&obj.name))
            .collect();
        let tables_modified_ddl: Vec<TableRef> = ddl_target
            .iter()
            .chain(&further_ddl)
            .filter(|_| table_shaped)
            .cloned()
            .collect();
        // Whether one of the three lists holds the DDL target.
        let mut target_listed = table_shaped;

        // Statements classified as DmlWrite that carry their target
        // table on `ddl.target` rather than `query.{reads,writes}_table[]`
        // (PgCopy table-subject, COPY INTO TABLE, MSSQL BULK INSERT)
        // must contribute their target to the appropriate ledger
        // entry so `summary.tables_{read,written}` and the
        // `derive_metrics` aggregate count them.
        //
        // Directionality: `COPY <table> FROM <source>` writes the
        // table; `COPY <table> TO <sink>` reads the table.
        // `pg_copy.direction` is the typed discriminator.
        if classification == StatementClassification::DmlWrite
            && tables_written.is_empty()
            && tables_read.is_empty()
        {
            if let Some(target) = &ddl_target {
                if matches!(
                    fact.pg_copy.as_ref().map(|p| p.direction),
                    Some(crate::facts::PgCopyDirection::To)
                ) {
                    tables_read.push(target.clone());
                } else {
                    tables_written.push(target.clone());
                }
                target_listed = true;
            }
        }

        // Maintenance statements (REPAIR / OPTIMIZE / VACUUM /
        // RESTORE / DESCRIBE HISTORY / CACHE / UNCACHE) touch their
        // target table — `query: None` on the maintenance projection
        // means the ledger has no other path to record the access.
        // `RESTORE` is a write (it rewrites the table state to a
        // prior version); every other maintenance form is read-only
        // metadata / partition reorganization.
        if matches!(
            fact.ddl.as_ref().map(|d| d.action),
            Some(crate::facts::DdlAction::Maintenance)
        ) && tables_read.is_empty()
            && tables_written.is_empty()
        {
            if let Some(target) = &ddl_target {
                if matches!(fact.kind, crate::facts::StatementKind::DbxRestore) {
                    tables_written.push(target.clone());
                } else {
                    tables_read.push(target.clone());
                }
                target_listed = true;
            }
        }

        // The tables an attached catalog is asked for are the ones the
        // three lists hold: a table read where lowering asked the catalog
        // for it (a CTE or a derived table is never asked for), a table
        // written, and the DDL target where a list holds it and it is no
        // session's own table or a stage.
        let mut catalog_subjects: Vec<CatalogSubject> = Vec::new();
        if let Some(q) = fact.query.as_ref() {
            // The statement's read and write lists name each table once
            // and carry no place; its scans do. A table read only inside
            // an expression's subquery has no scan here: it is placed
            // after the tables that have one.
            let mut first_scan: BTreeMap<&str, u32> = BTreeMap::new();
            for scan in q.scopes.iter().flat_map(|scope| &scope.tables) {
                if let Some(scanned) = scan.source_span {
                    let at = first_scan
                        .entry(scan.table.canonical.as_str())
                        .or_insert(scanned.start);
                    *at = (*at).min(scanned.start);
                }
            }
            let subject = |te: &crate::facts::query::TableEvent, unplaced: u32| CatalogSubject {
                at: first_scan
                    .get(te.table.canonical.as_str())
                    .copied()
                    .or(te.source_span.map(|s| s.start))
                    .unwrap_or(unplaced),
                table: facts_tableref_to_metadata(&te.table),
                in_catalog: te.in_catalog,
                queried: true,
                created: false,
                statement: span,
            };
            catalog_subjects.extend(
                q.reads_table
                    .iter()
                    .filter(|te| te.in_catalog.is_some())
                    .map(|te| subject(te, span.end)),
            );
            catalog_subjects.extend(q.writes_table.iter().map(|te| subject(te, span.start)));
        }
        if let Some(target) = ddl_target
            .as_ref()
            .filter(|_| target_listed && !self.uncatalogued_ddl_targets.contains(&span.start))
        {
            catalog_subjects.push(CatalogSubject {
                at: span.start,
                table: target.clone(),
                in_catalog: None,
                queried: false,
                created: matches!(
                    fact.ddl.as_ref().map(|d| d.action),
                    Some(crate::facts::DdlAction::Create)
                ),
                statement: span,
            });
        }

        // Whether the target is changed follows from what the statement
        // does to it, whatever else it reads.
        let changes_target = fact.ddl.as_ref().is_some_and(|ddl| {
            use crate::facts::DdlAction;
            match ddl.action {
                DdlAction::Create
                | DdlAction::Alter
                | DdlAction::Drop
                | DdlAction::Rename
                | DdlAction::Truncate
                | DdlAction::Comment
                | DdlAction::Refresh
                // Vacuum, optimize, restore and repair rewrite a table;
                // the few that only read it are counted with them.
                | DdlAction::Maintenance
                | DdlAction::BulkLoad
                | DdlAction::Restore
                | DdlAction::Grant
                | DdlAction::Revoke => true,
                DdlAction::Configure
                | DdlAction::ControlFlow
                | DdlAction::Transaction
                | DdlAction::Backup
                | DdlAction::Execute => false,
            }
        });
        let changed_object_kind = ddl_object.map(|obj| obj.kind).filter(|_| changes_target);
        // The routine, task or prepared statement it runs.
        let run_target = fact
            .ddl
            .as_ref()
            .filter(|ddl| ddl.action == crate::facts::DdlAction::Execute)
            .and_then(|ddl| ddl.target.as_ref())
            .map(|obj| (obj.kind, facts_tableref_to_metadata(&obj.name)));
        let privilege_target = fact
            .privilege
            .as_ref()
            .and_then(|p| p.target.as_ref())
            .map(|obj| (obj.kind, facts_tableref_to_metadata(&obj.name)));
        let changed_further = fact
            .ddl
            .iter()
            .filter(|_| changes_target)
            .flat_map(|d| d.targets.iter().skip(1));
        let granted_further = fact.privilege.iter().flat_map(|p| p.targets.iter().skip(1));
        let further_objects: Vec<(ObjectKind, TableRef)> = changed_further
            .chain(granted_further)
            .map(|obj| (obj.kind, facts_tableref_to_metadata(&obj.name)))
            .collect();

        let semantics = StatementSemantics {
            classification,
            kind: fact.kind,
            span,
            defined: defined_regions
                .iter()
                .any(|r| span.start >= r.start && span.end <= r.end),
            has_where,
            has_tautology_where,
            tables_read,
            tables_written,
            tables_modified_ddl,
            ddl_target,
            changed_object_kind,
            privilege_target,
            further_objects,
            run_target,
            catalog_subjects,
        };

        // Synthesize a stable NodeId from the span start. The ledger
        // uses NodeId for keying.
        //
        // Each statement is one fact record, so one entry. Where two
        // statements start at the same offset the first entry is kept
        // and a later one adds only the tables it names for the catalog
        // question (add_statement, first-wins by span start).
        let nid = NodeId::new(span.start);
        self.add_statement(nid, semantics);
    }

    /// Derive all metrics from ledger (never store derived values)
    pub fn derive_metrics(&self) -> DerivedMetrics {
        self.derive_metrics_masking(&|_| false)
    }

    /// [`Self::derive_metrics`], each table whose text `masked` says a
    /// report masks named masked whole: the source writes a string literal
    /// the report does not show in it (`IDENTIFIER('…')`, template code).
    pub fn derive_metrics_masking(&self, masked: &dyn Fn(Span) -> bool) -> DerivedMetrics {
        let shown = |t: &TableRef| -> TableRef {
            match t.span.is_some_and(masked) {
                true => {
                    let part = |p: &Option<String>| {
                        p.as_ref().map(|_| crate::facts::MASKED_VALUE.to_string())
                    };
                    TableRef {
                        server: part(&t.server),
                        db: part(&t.db),
                        schema: part(&t.schema),
                        name: crate::facts::MASKED_VALUE.to_string(),
                        span: t.span,
                    }
                }
                false => t.clone(),
            }
        };
        // Tables Written (DML) = unique set of DmlWrite targets
        let tables_written: HashSet<String> = self
            .entries
            .values()
            .filter(|s| s.classification == StatementClassification::DmlWrite)
            .flat_map(|s| s.tables_written_dml())
            .map(|t| shown(t).canonical())
            .collect();

        // Tables Read = tables from:
        // - DmlRead (SELECT/CTEs/subqueries)
        // - DmlWrite (read-side of MERGE, INSERT...SELECT)
        // - Security (policies with subqueries)
        // - Control (cursor queries like DECLARE CURSOR FOR SELECT...)
        // - Ddl (the query of a CREATE TABLE … AS or of a view)
        let tables_read: HashSet<String> = self
            .entries
            .values()
            .filter(|s| {
                matches!(
                    s.classification,
                    StatementClassification::DmlRead
                        | StatementClassification::DmlWrite
                        | StatementClassification::Security
                        | StatementClassification::Control
                        | StatementClassification::Ddl
                )
            })
            .flat_map(|s| s.tables_read())
            .map(|t| shown(t).canonical())
            .collect();

        // DDL Operations = count of statements with classification == Ddl
        let ddl_operations = self
            .entries
            .values()
            .filter(|s| s.classification == StatementClassification::Ddl)
            .count();

        // Security Operations = count of statements with classification == Security
        let security_operations = self
            .entries
            .values()
            .filter(|s| s.classification == StatementClassification::Security)
            .count();

        // Control Operations = count of statements with classification == Control
        let control_operations = self
            .entries
            .values()
            .filter(|s| s.classification == StatementClassification::Control)
            .count();

        // Databases accessed
        let databases: HashSet<String> = self
            .entries
            .values()
            .flat_map(|s| {
                s.tables_read()
                    .iter()
                    .chain(s.tables_written_dml().iter())
                    .chain(s.ddl_object())
                    .map(shown)
                    .filter_map(|t| t.db)
                    .map(|db| db.to_uppercase())
            })
            .collect();

        // Schemas accessed
        let schemas: HashSet<String> = self
            .entries
            .values()
            .flat_map(|s| {
                s.tables_read()
                    .iter()
                    .chain(s.tables_written_dml().iter())
                    .chain(s.ddl_object())
                    .map(shown)
                    .filter_map(|t| {
                        t.schema.as_ref().map(|schema| {
                            if let Some(db) = &t.db {
                                format!("{}.{}", db.to_uppercase(), schema.to_uppercase())
                            } else {
                                schema.to_uppercase()
                            }
                        })
                    })
            })
            .collect();

        // Cross-database and cross-schema flags
        let cross_database = databases.len() > 1;
        let cross_schema = schemas.len() > 1;

        // Unbounded writes (DmlWrite only). A write is unbounded if
        // it has no WHERE clause OR the outer WHERE is tautological
        // (`1=1`, `TRUE`, ...). Both flags are projected directly from
        // `StatementFacts.query` at ledger-population time.
        let has_unbounded_write = self
            .entries
            .values()
            .filter(|s| s.classification == StatementClassification::DmlWrite)
            .filter(|s| !s.tables_written_dml().is_empty())
            .any(|s| !s.has_where || s.has_tautology_where);

        // Tables modified (for blast radius analysis - DmlWrite only)
        let tables_modified: Vec<String> = self
            .entries
            .values()
            .filter(|s| s.classification == StatementClassification::DmlWrite)
            .flat_map(|s| s.tables_written_dml())
            .map(|t| shown(t).canonical())
            .collect();

        // One subject per statement, in script order: the tables its DML
        // writes, then the object its DDL changes and the object whose
        // privileges it changes, each unless already named.
        let subjects: Vec<StatementSubject> = self
            .entries
            .values()
            .map(|s| {
                let mut objects: Vec<SubjectObject> = s
                    .tables_written_dml()
                    .iter()
                    .map(|t| SubjectObject {
                        kind: ObjectKind::Table,
                        name: crate::context::node_metadata::TableKey::of(&shown(t)).to_string(),
                    })
                    .collect();
                let changed = s.changed_object_kind.zip(s.ddl_target.as_ref());
                let granted = s
                    .privilege_target
                    .as_ref()
                    .map(|(kind, target)| (*kind, target));
                let further = s
                    .further_objects
                    .iter()
                    .map(|(kind, target)| (*kind, target));
                let run = s.run_target.as_ref().map(|(kind, target)| (*kind, target));
                for (kind, target) in changed.into_iter().chain(granted).chain(further).chain(run) {
                    let name =
                        crate::context::node_metadata::TableKey::of(&shown(target)).to_string();
                    if !objects.iter().any(|o| o.name == name) {
                        objects.push(SubjectObject { kind, name });
                    }
                }
                StatementSubject {
                    kind: s.kind,
                    objects,
                    defined: s.defined,
                    runs: Vec::new(),
                    span: s.span,
                }
            })
            .collect();

        DerivedMetrics {
            subjects,
            tables_written,
            tables_read,
            ddl_operations,
            security_operations,
            control_operations,
            databases_accessed: databases,
            schemas_accessed: schemas,
            cross_database,
            cross_schema,
            has_unbounded_write,
            tables_modified,
        }
    }
}

/// What one statement acts on: its kind and the objects it changes.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(rename = "StatementSubject"))]
pub struct StatementSubject {
    pub kind: StatementKind,
    /// The objects the statement writes, creates, alters or drops, whose
    /// privileges it grants, revokes or denies, or which it runs (a
    /// procedure it calls, a task it executes). Empty for a statement that
    /// acts on none, or none it names.
    pub objects: Vec<SubjectObject>,
    /// The statement is in the body of a procedure, function, trigger,
    /// event, task or rule: the statement that creates that defines it,
    /// and it runs only when that is called or fires.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub defined: bool,
    /// The statements of the SQL text this statement runs, where the text
    /// is known: the body of an `EXECUTE IMMEDIATE` or of a procedure's
    /// dynamic SQL.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub runs: Vec<StatementSubject>,
    /// Where the statement is in the analyzed text.
    #[serde(skip)]
    #[cfg_attr(feature = "schema", schemars(skip))]
    pub span: Span,
}

/// An object a statement changes.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(rename = "SubjectObject"))]
pub struct SubjectObject {
    pub kind: ObjectKind,
    /// The name, each part folded as the dialect folds identifiers
    /// (quotes removed, unquoted case folded), so two spellings of one
    /// object name it alike; masked where a report masks it.
    pub name: String,
}

/// All metrics derived from ledger (never stored in ledger)
#[derive(Debug, Clone)]
pub struct DerivedMetrics {
    /// What each statement acts on, in script order.
    pub subjects: Vec<StatementSubject>,
    pub tables_written: HashSet<String>,
    pub tables_read: HashSet<String>,
    pub ddl_operations: usize,
    pub security_operations: usize,
    pub control_operations: usize,
    pub databases_accessed: HashSet<String>,
    pub schemas_accessed: HashSet<String>,
    pub cross_database: bool,
    pub cross_schema: bool,
    pub has_unbounded_write: bool,
    pub tables_modified: Vec<String>,
}

/// Convert an IR-native [`crate::facts::identity::TableRef`] to the
/// report-shaped [`crate::context::node_metadata::TableRef`] consumed by
/// downstream summary metrics. The two types differ only in their
/// identifier representation: facts use `IdentName` (raw + normalized),
/// the report shape uses bare `String`. We forward `raw` to preserve
/// the source spelling on the rendered report.
fn facts_tableref_to_metadata(t: &crate::facts::identity::TableRef) -> TableRef {
    TableRef {
        server: t.server.as_ref().map(|id| id.raw.clone()),
        db: t.database.as_ref().map(|id| id.raw.clone()),
        schema: t.schema.as_ref().map(|id| id.raw.clone()),
        name: t.name.raw.clone(),
        span: t.source_span,
    }
}

/// The ledger under the name the analysis pipeline uses.
pub type MetricsCollector = StatementLedger;

impl MetricsCollector {
    /// No-op: metrics are derived, not stored.
    pub fn finalize(&mut self) {}
}

#[cfg(test)]
mod tests {
    use super::{
        classify_statement_kind, CatalogSubject, StatementLedger, StatementSemantics,
        StatementSubject, SubjectObject,
    };
    use crate::ast::NodeId;
    use crate::context::node_metadata::TableRef;
    use crate::facts::{ObjectKind, StatementKind};
    use crate::lexer::Span;

    fn subject(at: u32, created: bool, statement: Span) -> CatalogSubject {
        CatalogSubject {
            at,
            table: TableRef {
                server: None,
                db: None,
                schema: None,
                name: "t".to_string(),
                span: None,
            },
            in_catalog: None,
            queried: false,
            created,
            statement,
        }
    }

    #[test]
    fn a_created_table_follows_what_its_statement_names_and_precedes_the_next_statement() {
        let creating = Span { start: 0, end: 20 };
        let following = Span { start: 20, end: 30 };
        let read_inside = subject(12, false, creating);
        // A read with no place of its own is put at its statement's end.
        let read_at_the_end = subject(20, false, creating);
        let created = subject(0, true, creating);
        let next_target = subject(20, false, following);

        let mut order = [&next_target, &created, &read_at_the_end, &read_inside];
        order.sort_by_key(|s| s.script_order());
        let expected = [&read_inside, &read_at_the_end, &created, &next_target];
        assert!(order
            .iter()
            .zip(expected)
            .all(|(got, want)| std::ptr::eq(*got, want)));
    }

    /// A ledger of one statement of `kind` at `span` that writes `written`
    /// and whose DDL changes `changed`.
    fn ledger_of(
        kind: StatementKind,
        span: Span,
        written: Vec<TableRef>,
        changed: Option<(ObjectKind, TableRef)>,
    ) -> StatementLedger {
        let mut ledger = StatementLedger::new();
        ledger.add_statement(
            NodeId::new(span.start),
            StatementSemantics {
                classification: classify_statement_kind(kind),
                kind,
                span,
                defined: false,
                has_where: true,
                has_tautology_where: false,
                tables_read: Vec::new(),
                tables_written: written,
                tables_modified_ddl: Vec::new(),
                changed_object_kind: changed.as_ref().map(|(kind, _)| *kind),
                ddl_target: changed.map(|(_, target)| target),
                privilege_target: None,
                further_objects: Vec::new(),
                run_target: None,
                catalog_subjects: Vec::new(),
            },
        );
        ledger
    }

    fn table_at(name: &str, span: Span) -> TableRef {
        TableRef {
            server: None,
            db: Some("db".to_string()),
            schema: None,
            name: name.to_string(),
            span: Some(span),
        }
    }

    #[test]
    fn a_subject_names_a_masked_object_masked() {
        let _folding = crate::ir::normalize::default_folding();
        let statement = Span { start: 0, end: 40 };
        let name = Span { start: 12, end: 20 };
        let ledger = ledger_of(
            StatementKind::Delete,
            statement,
            vec![table_at("orders", name)],
            None,
        );
        let subject = |masked: bool| ledger.derive_metrics_masking(&|_| masked).subjects;
        assert_eq!(
            subject(false),
            vec![StatementSubject {
                kind: StatementKind::Delete,
                objects: vec![SubjectObject {
                    kind: ObjectKind::Table,
                    name: "DB.ORDERS".to_string(),
                }],
                defined: false,
                runs: Vec::new(),
                span: statement,
            }]
        );
        // Each part is masked.
        assert_eq!(
            subject(true)[0].objects[0].name,
            format!("{0}.{0}", crate::facts::MASKED_VALUE)
        );
    }

    #[test]
    fn a_subject_names_an_object_once_and_a_changed_ddl_target_by_its_kind() {
        let _folding = crate::ir::normalize::default_folding();
        let statement = Span { start: 0, end: 40 };
        let name = Span { start: 12, end: 20 };
        let both = ledger_of(
            StatementKind::Insert,
            statement,
            vec![table_at("t", name)],
            Some((ObjectKind::Table, table_at("t", name))),
        );
        assert_eq!(both.derive_metrics().subjects[0].objects.len(), 1);

        let dropped = ledger_of(
            StatementKind::DropView,
            statement,
            Vec::new(),
            Some((ObjectKind::View, table_at("v", name))),
        );
        assert_eq!(
            dropped.derive_metrics().subjects[0].objects,
            vec![SubjectObject {
                kind: ObjectKind::View,
                name: "DB.V".to_string(),
            }]
        );
    }

    #[test]
    fn test_metrics_collector_single_db() {
        // This test would require a real RenderContext
        // Left as placeholder for integration tests
    }
}
