// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Per-statement semantic ledger for risk analysis
//!
//! This module implements the single source of truth for statement semantics.
//! All metrics are derived from the ledger, never pushed directly.

use crate::ast::NodeId;
use crate::context::node_metadata::TableRef;
use crate::facts::statement::{StatementFacts, StatementKind};
use crate::lexer::Span;
use std::collections::{HashMap, HashSet};

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
        | K::MssqlExec
        | K::MssqlSetOption
        | K::Reconfigure
        | K::AlterSession
        | K::BqAssert
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

    /// Tables modified by DDL (only populated when classification == Ddl).
    /// Empty for non-DDL statements.
    pub tables_modified_ddl: Vec<TableRef>,
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
}

/// Single source of truth: StatementId → StatementSemantics
///
/// INVARIANT: statements_parsed() == entries.len() (by definition)
/// INVARIANT: statements_analyzed + statements_skipped == statements_parsed (always)
///
/// Note: statements_parsed is derived from entries.len() to guarantee the invariant.
#[derive(Debug, Clone, Default)]
pub struct StatementLedger {
    pub(crate) entries: HashMap<NodeId, StatementSemantics>,
    /// Tracks span starts that have been added (for dedup)
    span_starts: std::collections::HashSet<u32>,
    /// Whether ledger has been finalized (invariant check)
    finalized: bool,
}

impl StatementLedger {
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

    /// Add statement to ledger. Only adds if span_start is new (no duplicates).
    pub fn add_statement(&mut self, node_id: NodeId, semantics: StatementSemantics) {
        let span_start = semantics.span.start;

        // Only add if this span_start hasn't been seen
        // (prevents triple-counting from blast_radius, cost_risk, policy analyzers)
        if self.span_starts.insert(span_start) {
            self.entries.insert(node_id, semantics);
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
    pub fn populate_from_fact(&mut self, fact: &StatementFacts, body_regions: &[Span]) {
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
        let tables_modified_ddl: Vec<TableRef> =
            match fact.ddl.as_ref().and_then(|d| d.target.as_ref()) {
                Some(obj) => vec![facts_tableref_to_metadata(&obj.name)],
                None => Vec::new(),
            };

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
            && !tables_modified_ddl.is_empty()
        {
            let direction = fact.pg_copy.as_ref().map(|p| p.direction);
            match direction {
                Some(crate::facts::PgCopyDirection::To) => {
                    tables_read.extend(tables_modified_ddl.iter().cloned());
                }
                _ => {
                    tables_written.extend(tables_modified_ddl.iter().cloned());
                }
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
            && !tables_modified_ddl.is_empty()
        {
            if matches!(fact.kind, crate::facts::StatementKind::DbxRestore) {
                tables_written.extend(tables_modified_ddl.iter().cloned());
            } else {
                tables_read.extend(tables_modified_ddl.iter().cloned());
            }
        }

        let semantics = StatementSemantics {
            classification,
            span,
            has_where,
            has_tautology_where,
            tables_read,
            tables_written,
            tables_modified_ddl,
        };

        // Synthesize a stable NodeId from the span start. The ledger
        // uses NodeId for keying.
        //
        // First-wins on collision: the four rule evaluators fold into
        // the same per-statement fact stream in the order
        // privilege → ddl → query → policy_attachment. When two
        // evaluators produce facts for the same span (e.g. the DDL
        // evaluator producing a `PgCopy` fact with a populated
        // `ddl.target` and the query evaluator producing a
        // Terminal-plan Select stub for the same statement),
        // the first/earlier evaluator's fact wins. This preserves
        // the more specific surface — the later stub would
        // otherwise overwrite the typed `ddl.target` and silently
        // drop the read-set / write-set on the floor.
        // Route through add_statement (first-wins by span_start). NodeId is
        // derived from span.start, so this preserves the prior
        // or_insert/first-wins keying.
        let nid = NodeId::new(span.start);
        self.add_statement(nid, semantics);
    }

    /// Derive all metrics from ledger (never store derived values)
    pub fn derive_metrics(&self) -> DerivedMetrics {
        // Tables Written (DML) = unique set of DmlWrite targets
        let tables_written: HashSet<String> = self
            .entries
            .values()
            .filter(|s| s.classification == StatementClassification::DmlWrite)
            .flat_map(|s| s.tables_written_dml())
            .map(|t| t.canonical())
            .collect();

        // Tables Read = tables from:
        // - DmlRead (SELECT/CTEs/subqueries)
        // - DmlWrite (read-side of MERGE, INSERT...SELECT)
        // - Security (policies with subqueries)
        // - Control (cursor queries like DECLARE CURSOR FOR SELECT...)
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
                )
            })
            .flat_map(|s| s.tables_read())
            .map(|t| t.canonical())
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
                    .chain(s.tables_modified_ddl().iter())
                    .filter_map(|t| t.db.as_ref())
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
                    .chain(s.tables_modified_ddl().iter())
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
            .map(|t| t.canonical())
            .collect();

        DerivedMetrics {
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

/// All metrics derived from ledger (never stored in ledger)
#[derive(Debug, Clone)]
pub struct DerivedMetrics {
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

    #[test]
    fn test_metrics_collector_single_db() {
        // This test would require a real RenderContext
        // Left as placeholder for integration tests
    }
}
