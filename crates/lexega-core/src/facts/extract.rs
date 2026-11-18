// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! The single fact-extraction entry point.

use super::identity::TextOrigin;
use std::error::Error;
use std::fmt;

use crate::ast::{
    AstExpr, AstFunctionArg, AstIsPredicate, AstLiteral, AstObjectKind, AstPluralObjectKind,
    AstPrivilegeKind, BinaryOperator, LogicalChainOperator,
};
use crate::ir::normalize::NameKind;
use crate::ir::policy_attachment_plan::{
    PolicyAttachmentPlan, PolicyAttachmentPrincipal as IrPolicyAttachmentPrincipal,
    PolicyAttachmentTarget as IrPolicyAttachmentTarget,
    PolicyAttachmentVerb as IrPolicyAttachmentVerb,
};
use crate::ir::span_extract::{literal_value_or_name, literal_value_or_text, string_literal_value};
use crate::ir::{
    AccountPlan, AccountProvisioningAction, AggregationPolicyShape, AlertAction, AlertPlan,
    ApiIntegrationShape, ApplicationAction, ApplicationAlterActionIr, ApplicationPackagePlan,
    ApplicationPlan, AuthenticationPolicyShape, CatalogAction, CatalogPlan, ComputePoolAction,
    ComputePoolAlterActionIr, ComputePoolPlan, ConnectionAction, ConnectionPlan,
    CortexSearchServiceAction, CortexSearchServiceAlterActionIr, CortexSearchServicePlan,
    DataMetricFunctionAction, DataMetricFunctionPlan, DatabaseAction, DatabasePlan,
    DatashareAction, DatashareObjectKind as IrDatashareObjectKind, DatasharePlan,
    DefinerLowered as IrDefinerLowered, DynamicTableAction, DynamicTablePlan,
    EventAction as IrEventAction, EventPlan, ExternalAccessIntegrationShape,
    ExternalDataSourceAction, ExternalDataSourcePlan, ExternalDataSourceTypeKind,
    ExternalLocationAction, ExternalLocationPlan, FileFormatAction, FileFormatPlan, FlowAction,
    FlowPlan, ForeignServerAction, ForeignServerPlan, ForeignTablePlan, FunctionAction,
    FunctionPlan, GitRepositoryAction, GitRepositoryAlterActionIr, GitRepositoryPlan,
    HandlerBodyShapeIr, HandlerBodyStatementKindIr, HandlerConditionIr, HandlerPlan, HandlerTypeIr,
    ImageRepositoryAction, ImageRepositoryAlterActionIr, ImageRepositoryPlan,
    ImportFilterMode as IrImportFilterMode, ImportForeignSchemaPlan, IntegrationAction,
    IntegrationKindIr, IntegrationPlan, IntegrationPlanVariant, IrBackupMode, IrCatalogAlterAction,
    IrCloneShape, IrConnectionAlterAction, IrCreateTableKind, IrDatabaseAlterAction,
    IrDatabaseAlterActionDetail, IrDatabaseCreateOrigin, IrDatabaseProperty, IrDistStyle,
    IrExternalLocationAlterAction, IrSchemaAlterAction, IrSchemaCreateOrigin, IrSortKeySpec,
    IrStorageCredentialAlterAction, IrStorageLocation, IrTableAlterAction, IrVolumeAlterAction,
    ListingAction, ListingAlterActionIr, ListingPlan, ManagedAccountPlan, MaskingPolicyShape,
    MysqlLoadDataPlan, NetworkPolicyShape, NetworkRuleAction, NetworkRulePlan, NotebookAction,
    NotebookAlterActionIr, NotebookPlan, OrgAccountPlan, PasswordPolicyFieldIr,
    PasswordPolicyShape, PgPolicyCommandIr, PgPolicyPermissivenessIr, PipeAction, PipePlan,
    PolicyAction, PolicyCommentAction, PolicyKindIr, PolicyPlan, PolicyPlanVariant,
    PrivilegeAction, PrivilegeGrantee, PrivilegeObject, PrivilegeObjectScope, PrivilegePlan,
    PrivilegeSet, PrivilegeShape, ProcedureAction, ProcedureAlterActionKindIr,
    ProcedureAlterActionShape, ProcedureBodyShape, ProcedureBodyStatementKindIr, ProcedurePlan,
    ProcedurePropertiesShape, ProcedurePropertyKeyIr, ProjectionPolicyShape,
    ReplicationFailoverGroupAction, ReplicationFailoverGroupPlan, ReplicationGroupType,
    ResourceMonitorAction, ResourceMonitorPlan, RowAccessPolicyShape, SchemaAction, SchemaPlan,
    SecretAction, SecretPlan, SemanticViewAction, SemanticViewAlterActionIr, SemanticViewPlan,
    ServerConfigurationPlan, ServiceAction, ServiceAlterActionIr, ServicePlan, SessionAction,
    SessionPlan, SessionPolicyFieldIr, SessionPolicyShape, ShareAction, SharePlan, StageAction,
    StageCredentialValue, StageCredentials, StageFileCommandPlan, StageFileOperation, StagePlan,
    StorageCredentialAction, StorageCredentialKindIr, StorageCredentialPlan,
    StorageCredentialProvider, StorageCredentialProviderVariant, StorageIntegrationShape,
    StreamAction, StreamPlan, StreamlitAction, StreamlitAlterActionIr, StreamlitPlan, TableAction,
    TableMaintenanceKind as IrTableMaintenanceKind, TableMaintenancePlan, TablePlan, TagAction,
    TagAlterActionIr, TagPlan, TagPolicyRefIr, TaskAction, TaskPlan, TriggerCreatePlan, UseKind,
    UsePlan, UserMappingAction, UserMappingOptionIr, UserMappingPlan, VolumeAction, VolumePlan,
    WarehouseAction, WarehousePlan,
};
use crate::lexer::token::Span;

use super::algebra::AlgebraFacts;
use super::catalog::CatalogTag;
use super::ddl::{
    AccountFacts, AccountParameter, AlertAlterAction, AlertAlterActionKind, AlertBodyFacts,
    AlertBodyParseStatus, AlertCreateOptions, AlertFacts, ApplicationAlterAction, ApplicationFacts,
    ApplicationPackageFacts, BackupMode, CacheOptions, CatalogAlterAction, CatalogFacts,
    CloneShape, ComputePoolAlterAction, ComputePoolFacts, ConnectionAlterAction, ConnectionFacts,
    CopyOption, CortexSearchServiceAlterAction, CortexSearchServiceFacts, CreateTableKind,
    CreateTriggerFacts, DataMetricFunctionFacts, DatabaseAlterAction, DatabaseAlterActionKind,
    DatabaseCreateOrigin, DatabaseFacts, DatabasePropertiesFacts, DatabasePropertyKey,
    DatashareFacts, DatashareObjectKindFacts, DatashareObjectRef, DdlAction, DdlFacts, DdlOptions,
    DefinerFacts, DistStyle, DynamicSqlArg, DynamicSqlCall, DynamicSqlParameterization,
    DynamicSqlSurface, DynamicTableFacts, EventAction, EventEnableState as EventEnableStateFacts,
    EventFacts, EventScheduleKind as EventScheduleKindFacts, ExternalDataSourceFacts,
    ExternalDataSourceType, ExternalLocationAlterAction, ExternalLocationFacts, FileFormatFacts,
    FlowFacts, ForeignServerFacts, ForeignTableFacts, FunctionAlterAction, FunctionAlterActionKind,
    FunctionBodyFacts, FunctionBodyStatementKind, FunctionFacts, FunctionPropertiesFacts,
    FunctionPropertyKey, GitRepositoryAlterAction, GitRepositoryFacts, ImageRepositoryAlterAction,
    ImageRepositoryFacts, ImportFilterMode, ImportForeignSchemaFacts, ListingAlterAction,
    ListingFacts, ManagedAccountFacts, MysqlLoadDataFacts, NetworkRuleFacts, NotebookAlterAction,
    NotebookFacts, PipeFacts, ProcedureAlterAction, ProcedureAlterActionKind, ProcedureBodyFacts,
    ProcedureBodyStatementKind, ProcedureExecuteAsMode, ProcedureFacts, ProcedurePropertiesFacts,
    ProcedurePropertyKey, RepairMode, RepairOptions, ReplicationFailoverGroupFacts,
    ReplicationGroupKind, ResourceMonitorFacts, ResourceMonitorTriggerFacts, SchemaAlterAction,
    SchemaCreateOrigin, SchemaFacts, SecretFacts, SemanticViewAlterAction, SemanticViewFacts,
    ServerConfigurationFacts, ServiceAlterAction, ServiceFacts, SessionFacts, SessionParam,
    ShareFacts, SortKeySpec, StageCredentialOption, StageDdlFacts, StorageCredentialAlterAction,
    StorageCredentialChangeKind, StorageCredentialFacts, StorageCredentialKindFacts,
    StorageCredentialLiteral, StorageCredentialProviderFacts,
    StorageCredentialProviderVariantFacts, StorageLocationFacts, StreamFacts, StreamlitAlterAction,
    StreamlitFacts, TableAlterAction, TableFacts, TableMaintenanceFacts, TableMaintenanceKind,
    TableRenamePair, TagFacts, TaskAlterAction, TaskAlterActionKind, TaskBodyFacts,
    TaskBodyParseStatus, TaskCreateOptions, TaskExecuteAsClause, TaskFacts, TaskOverlapPolicy,
    TriggerEvent as TriggerEventFacts, TriggerTiming as TriggerTimingFacts, UserMappingFacts,
    UserMappingOption, VacuumOptions, ViewAlterActionKind, ViewCheckOption, ViewFacts,
    ViewSqlSecurity, VolumeAlterAction, VolumeFacts, WarehouseFacts,
};
use super::handler::{
    HandlerBody, HandlerBodyStatementKind, HandlerCondition, HandlerFacts, HandlerType,
};
use super::identity::{IdentName, ObjectKind, ObjectRef, PrincipalKind, PrincipalRef, TableRef};
use super::integration::{
    ApiIntegrationVariantFacts, ExternalAccessIntegrationVariantFacts, IntegrationFacts,
    IntegrationKind, IntegrationVariantFacts, NotificationIntegrationVariantFacts,
    SecurityIntegrationProperty, SecurityIntegrationVariantFacts, StorageIntegrationVariantFacts,
};
use super::policy::{
    AggregationPolicyFacts, AuthenticationPolicyFacts, IpListEntry, JoinPolicyFacts,
    MaskTerminalFlow, MaskingPolicyFacts, NetworkPolicyFacts, PasswordPolicyComplexityClass,
    PasswordPolicyFacts, PasswordPolicyField, PolicyBodySemantics, PolicyCommentChange,
    PolicyFacts, PolicyKind, PolicyPredicate, PolicyVariantFacts, ProjectionPolicyFacts,
    RowAccessPolicyFacts, SessionPolicyFacts, SessionPolicyField,
};
use super::policy_attachment::{
    PolicyAttachmentFacts, PolicyAttachmentPrincipalKind, PolicyAttachmentTargetKind,
    PolicyAttachmentVerb,
};
use super::privilege::{Privilege, PrivilegeChangeKind, PrivilegeFacts};
use super::script_context::ScriptContext;
use super::statement::{StatementFacts, StatementKind};
use super::use_stmt::{UseFacts, UseStatementKind, UseTargetFacts};

/// Catalog and IR-side context required by fact extraction. Wraps the
/// existing IR catalog plumbing without re-exposing IR types in the
/// public surface.
pub struct CatalogCtx<'a> {
    /// Catalog index for tag / row-count / column-count lookups.
    pub catalog: Option<&'a crate::ir::IndexedCatalogContext>,
    /// What lowering learned of the tables the statement reads, from the
    /// catalog where one is attached and from the relations the script's
    /// statements made: what reasoning reads. `catalog` where `None`.
    pub known: Option<&'a crate::ir::IndexedCatalogContext>,
    /// Function catalog for temporal / deterministic / aggregate flags.
    pub function_catalog: &'a crate::ir::FunctionCatalog,
    /// Source text for span resolution.
    pub source: &'a str,
    /// Plan-derived `NodeId → TableRef` map for resolving the
    /// `binding.origin.table_node` of every scan-bound column to its
    /// authoritative table identity. Built once per statement by
    /// [`crate::ir::expression_fact::build_scan_index`]; threaded
    /// alongside `catalog` so column-identity resolution is
    /// independent of whether an external catalog is attached
    /// (catalog augments with `in_catalog` / `is_ambiguous` bits, but
    /// the table identity itself is IR-derived). `None` for
    /// callers that don't construct one (e.g. plan-less DDL
    /// projections); column-identity resolution silently falls back
    /// to the catalog cache in that case.
    pub scan_index: Option<&'a crate::ir::expression_fact::ScanIndex>,
    /// Semantic analyses the projection consults.
    pub reasoning: &'a dyn super::reasoning::Reasoning,
    /// The placeholder spans `source` was parsed with: where a render or a
    /// substitution wrote text for a value it could not resolve. A
    /// credential value overlapping one is no literal. Empty for text
    /// parsed without any.
    pub placeholders: &'a [Span],
    /// Whether to state the columns of the relation the statement returns
    /// or makes ([`super::query::QueryFacts::output_columns`]), which
    /// comparing two versions of a statement reads. Off elsewhere: the
    /// analyses they need are not run for nothing.
    pub output_columns: bool,
}

/// Typed error for fact-extraction failures.
/// `Debug` is unconditional because `std::error::Error` requires it as
/// a supertrait.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FactsError {
    /// No fact projection exists for this statement.
    Unimplemented(String),
    /// IR-side state could not produce a typed projection.
    Opaque(String),
}

impl fmt::Display for FactsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unimplemented(msg) => write!(f, "facts derivation unimplemented: {}", msg),
            Self::Opaque(msg) => write!(f, "facts derivation opaque: {}", msg),
        }
    }
}

impl Error for FactsError {}

/// Project a lower-time `INTO OUTFILE / DUMPFILE` file-export target
/// onto the public `QueryFacts.file_exports` surface. No-op when the
/// statement has no file target. The file target binds the whole
/// statement, not any relational scope, so it rides
/// [`crate::ir::statement_facts::StatementFacts`] rather than the plan
/// walk.
pub fn project_file_export_into(
    query: &mut crate::facts::query::QueryFacts,
    file_export: Option<&crate::ir::statement_facts::FileExportFact>,
) {
    let Some(export) = file_export else {
        return;
    };
    let kind = match export.kind {
        crate::ir::statement_facts::FileExportKind::Outfile => {
            crate::facts::query::FileExportTargetKind::Outfile
        }
        crate::ir::statement_facts::FileExportKind::Dumpfile => {
            crate::facts::query::FileExportTargetKind::Dumpfile
        }
    };
    query
        .file_exports
        .push(crate::facts::query::FileExportFacts {
            kind,
            file_path: export.file_path.clone(),
        });
}

/// Build a minimal [`StatementFacts`] carrier for a DDL plan whose
/// typed `(action, object)` projects to a known
/// [`StatementKind`]. The carrier is intentionally sparse — `kind` and
/// `source_span` are populated, every other family slot
/// (`query`/`ddl`/`privilege`/…) is `None`. The diff dispatcher
/// attaches the `diff` slot at projection time; the rule engine
/// evaluates against `diff.events.kind: statement_kind_changed` and
/// the read-set-driven `table_added` / `table_removed` events without
/// needing the per-family DDL projections (those continue to flow
/// through the dedicated `analyze_<family>_facts` entry points).
/// Project the IR-side [`crate::ir::ddl_plan::DdlAction`] onto the public
/// facts [`DdlAction`] — 1:1; every IR verb has a facts counterpart.
fn project_ir_ddl_action(action: crate::ir::ddl_plan::DdlAction) -> DdlAction {
    use crate::ir::ddl_plan::DdlAction as I;
    match action {
        I::Create => DdlAction::Create,
        I::Alter => DdlAction::Alter,
        I::Drop => DdlAction::Drop,
        I::Rename => DdlAction::Rename,
        I::Truncate => DdlAction::Truncate,
        I::Comment => DdlAction::Comment,
        I::Refresh => DdlAction::Refresh,
        I::Grant => DdlAction::Grant,
        I::Revoke => DdlAction::Revoke,
        I::Execute => DdlAction::Execute,
        I::Configure => DdlAction::Configure,
        I::ControlFlow => DdlAction::ControlFlow,
        I::Transaction => DdlAction::Transaction,
        I::BulkLoad => DdlAction::BulkLoad,
        I::Backup => DdlAction::Backup,
        I::Restore => DdlAction::Restore,
    }
}

/// Project a `SHOW` [`crate::ir::DdlPlan`] to public [`StatementFacts`]
/// (`kind = show`, populated `ddl.show`). `None` if the plan carries no
/// recognized statement kind. Generic DDL projection — the typed
/// recognition rides the `show` sibling.
pub(crate) fn derive_facts_from_show_plan(plan: &crate::ir::DdlPlan) -> Option<StatementFacts> {
    plan.statement_kind()
        .map(|kind| minimal_ddl_statement(kind, plan))
}

/// Project a T-SQL trigger's definition plan to public [`StatementFacts`]:
/// kind `create_trigger` or `alter_trigger` with `ddl.action`, the trigger
/// as `ddl.target`, `or_alter` for `CREATE OR ALTER` (published as a
/// creation as a procedure's is), and its `body` as `ddl.trigger_body`.
pub(crate) fn derive_facts_from_mssql_trigger_plan(
    plan: &crate::ir::DdlPlan,
    or_alter: bool,
    body: Option<&ProcedureBodyShape>,
) -> Option<StatementFacts> {
    let kind = plan.statement_kind()?;
    let mut facts = minimal_ddl_statement(kind, plan);
    if let Some(ddl) = facts.ddl.as_mut() {
        ddl.object_kind = ObjectKind::Trigger;
        if let Some(target) = ddl.target.as_mut() {
            target.kind = ObjectKind::Trigger;
        }
        ddl.options.or_alter = or_alter;
        ddl.trigger_body = body.map(project_procedure_body);
    }
    Some(facts)
}

pub(crate) fn minimal_ddl_statement(
    kind: StatementKind,
    plan: &crate::ir::DdlPlan,
) -> StatementFacts {
    // Generic DDL statements without a richer dedicated facts projection still
    // surface their recognition options (OR REPLACE, IF [NOT] EXISTS,
    // CASCADE / RESTRICT) so rules can predicate on them — e.g.
    // `CREATE OR REPLACE STAGE` / `EXTERNAL TABLE`.
    let target = plan.target.as_ref().map(|t| ObjectRef {
        kind: ObjectKind::Generic,
        name: TableRef::new(
            IdentName::new(t.name.clone()),
            t.schema.clone().map(IdentName::new),
            t.db.clone().map(IdentName::new),
            Some(t.span),
        ),
    });
    let ddl = DdlFacts {
        targets: Vec::new(),
        action: project_ir_ddl_action(plan.action),
        object_kind: ObjectKind::Generic,
        target,
        options: DdlOptions {
            if_exists: plan.options.if_exists,
            if_not_exists: plan.options.if_not_exists,
            or_replace: plan.options.or_replace,
            cascade: plan.options.cascade,
            restrict: plan.options.restrict,
            ..DdlOptions::default()
        },
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: None,
        database: None,
        warehouse: None,
        stream: None,
        schema: None,
        function: None,
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: None,
        session: None,
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: None,
        managed_account: None,
        show: plan.show.as_ref().map(|sh| crate::facts::ddl::ShowFacts {
            object_class: sh.object_class.clone(),
            terse: sh.terse,
            history: sh.history,
            grants: sh
                .grants
                .as_ref()
                .map(|g| crate::facts::ddl::ShowGrantsFacts {
                    future: g.future,
                    relation: g.relation.clone(),
                    on_account: g.on_account,
                    target_kind: g.target_kind.clone(),
                    // Normalize the principal/target name so rule predicates
                    // match it case-insensitively (unquoted folds to upper;
                    // quoted identifiers keep their case), matching how the
                    // privilege facts expose `*.normalized` names.
                    name: g
                        .name
                        .as_ref()
                        .map(|n| crate::ir::normalize::normalize_identifier(n)),
                }),
            scope: sh
                .scope
                .as_ref()
                .map(|sc| crate::facts::ddl::ShowScopeFacts {
                    kind: sc.kind.clone(),
                    name: sc.name.clone(),
                }),
        }),
        synonym: plan
            .synonym
            .as_ref()
            .map(|sp| crate::facts::ddl::SynonymFacts {
                referent: (!sp.referent.is_empty()).then(|| sp.referent.clone()),
                // Four-part `server.database.schema.object` ⇒ the referent lives on a
                // linked/remote server. Recognition only; the verdict is in YAML.
                referent_server_qualified: sp.referent_part_count >= 4,
            }),
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

// ---------------------------------------------------------------------------
// Privilege projection.
// ---------------------------------------------------------------------------

pub fn project_privilege_statement(plan: &PrivilegePlan, ctx: &CatalogCtx<'_>) -> StatementFacts {
    let kind = match plan.action {
        PrivilegeAction::Grant => StatementKind::Grant,
        PrivilegeAction::Revoke => StatementKind::Revoke,
        PrivilegeAction::Deny => StatementKind::Deny,
        PrivilegeAction::OwnershipTransfer => StatementKind::AlterAuthorization,
    };
    let privilege = project_privilege_facts(plan, ctx);
    StatementFacts {
        declare: None,
        call: None,
        kind,
        source_span: Some(plan.span),
        query: None,
        ddl: None,
        privilege: Some(privilege),
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

fn project_privilege_facts(plan: &PrivilegePlan, ctx: &CatalogCtx<'_>) -> PrivilegeFacts {
    let kind = match plan.action {
        PrivilegeAction::Grant => PrivilegeChangeKind::Grant,
        PrivilegeAction::Revoke => PrivilegeChangeKind::Revoke,
        PrivilegeAction::Deny => PrivilegeChangeKind::Deny,
        PrivilegeAction::OwnershipTransfer => PrivilegeChangeKind::OwnershipTransfer,
    };

    let deny_cascade = plan.options.deny_cascade;
    let deny_as_principal = plan.options.deny_as_principal.map(|span| PrincipalRef {
        kind: PrincipalKind::Role,
        name: span_to_ident_name(span, ctx.source),
        source_span: Some(span),
    });

    match &plan.shape {
        PrivilegeShape::Privilege {
            privileges,
            objects,
            grantees,
        } => {
            let (privs, all_privileges) = project_privilege_set(privileges);
            // `target` is the first object, `targets` every one (PostgreSQL
            // `ON TABLE a, b`). Empty `objects` (MSSQL `GRANT CONTROL
            // SERVER`) yields neither.
            let (target, on_future, on_all, target_plural_kind) = match objects.first() {
                Some(obj) => project_object_target(obj, ctx.source),
                None => (None, false, false, None),
            };
            let targets: Vec<ObjectRef> = objects
                .iter()
                .filter_map(|obj| project_object_target(obj, ctx.source).0)
                .collect();
            PrivilegeFacts {
                targets,
                kind,
                privileges: privs,
                target,
                grantees: grantees
                    .iter()
                    .map(|g| project_grantee(g, ctx.source))
                    .collect(),
                with_grant_option: plan.options.with_grant_option,
                on_future,
                on_all,
                all_privileges,
                copy_current_grants: false,
                cascade: false,
                as_principal: None,
                role_grant_impact: None,
                object_grant_impact: None,
                target_plural_kind,
            }
        }
        PrivilegeShape::Role {
            role_name_span,
            grantee,
        } => PrivilegeFacts {
            targets: Vec::new(),
            kind,
            privileges: Vec::new(),
            target: Some(role_target(*role_name_span, ctx.source)),
            grantees: vec![project_grantee(grantee, ctx.source)],
            with_grant_option: false,
            on_future: false,
            on_all: false,
            all_privileges: false,
            copy_current_grants: false,
            cascade: false,
            as_principal: None,
            role_grant_impact: None,
            object_grant_impact: None,
            target_plural_kind: None,
        },
        PrivilegeShape::DatabaseRole {
            role_name_span,
            grantee,
        } => PrivilegeFacts {
            targets: Vec::new(),
            kind,
            privileges: Vec::new(),
            target: Some(database_role_target(*role_name_span, ctx.source)),
            grantees: vec![project_grantee(grantee, ctx.source)],
            with_grant_option: false,
            on_future: false,
            on_all: false,
            all_privileges: false,
            copy_current_grants: false,
            cascade: false,
            as_principal: None,
            role_grant_impact: None,
            object_grant_impact: None,
            target_plural_kind: None,
        },
        PrivilegeShape::Ownership {
            object,
            grantee,
            disposition,
        } => {
            let (target, on_future, on_all, target_plural_kind) =
                project_object_target(object, ctx.source);
            PrivilegeFacts {
                targets: Vec::new(),
                kind,
                privileges: vec![Privilege::Ownership],
                target,
                grantees: vec![project_grantee(grantee, ctx.source)],
                with_grant_option: false,
                on_future,
                on_all,
                all_privileges: false,
                copy_current_grants: matches!(
                    disposition,
                    Some(crate::ast::AstOwnershipDisposition::Copy)
                ),
                cascade: false,
                as_principal: None,
                role_grant_impact: None,
                object_grant_impact: None,
                target_plural_kind,
            }
        }
        PrivilegeShape::Unparsed { .. } => PrivilegeFacts {
            targets: Vec::new(),
            kind,
            privileges: Vec::new(),
            target: None,
            grantees: Vec::new(),
            with_grant_option: false,
            on_future: false,
            on_all: false,
            all_privileges: false,
            copy_current_grants: false,
            cascade: false,
            as_principal: None,
            role_grant_impact: None,
            object_grant_impact: None,
            target_plural_kind: None,
        },
        PrivilegeShape::Deny {
            privileges,
            object,
            grantees,
        } => {
            let (privs, all_privileges) = project_privilege_set(privileges);
            let target = object
                .as_ref()
                .and_then(|object| project_object_target(object, ctx.source).0);
            PrivilegeFacts {
                targets: Vec::new(),
                kind,
                privileges: privs,
                target,
                grantees: grantees
                    .iter()
                    .map(|g| project_grantee(g, ctx.source))
                    .collect(),
                with_grant_option: false,
                on_future: false,
                on_all: false,
                all_privileges,
                copy_current_grants: false,
                cascade: deny_cascade,
                as_principal: deny_as_principal,
                role_grant_impact: None,
                object_grant_impact: None,
                target_plural_kind: None,
            }
        }
    }
}

fn project_privilege_set(set: &PrivilegeSet) -> (Vec<Privilege>, bool) {
    match set {
        PrivilegeSet::All { .. } => (vec![Privilege::All], true),
        PrivilegeSet::Listed { privileges } => (
            privileges.iter().map(project_ast_privilege_kind).collect(),
            false,
        ),
    }
}

fn project_ast_privilege_kind(kind: &AstPrivilegeKind) -> Privilege {
    use AstPrivilegeKind as A;
    match kind {
        A::Select => Privilege::Select,
        A::Insert => Privilege::Insert,
        A::Update => Privilege::Update,
        A::Delete => Privilege::Delete,
        A::Truncate => Privilege::Truncate,
        A::References => Privilege::References,
        A::Modify => Privilege::Modify,
        A::Monitor => Privilege::Monitor,
        A::Operate => Privilege::Operate,
        A::Usage => Privilege::Usage,
        A::Apply => Privilege::Apply,
        A::Execute => Privilege::Execute,
        A::Read => Privilege::Read,
        A::Write => Privilege::Write,
        A::Ownership => Privilege::Ownership,
        A::ManageGrants => Privilege::ManageGrants,
        A::ApplyMaskingPolicy => Privilege::ApplyMaskingPolicy,
        A::ApplyRowAccessPolicy => Privilege::ApplyRowAccessPolicy,
        A::ApplyTag => Privilege::ApplyTag,
        A::ApplyAggregationPolicy => Privilege::ApplyAggregationPolicy,
        A::ApplyProjectionPolicy => Privilege::ApplyProjectionPolicy,
        A::ImportShare => Privilege::ImportShare,
        A::ImportedPrivileges => Privilege::ImportedPrivileges,
        A::CreateTable => Privilege::CreateTable,
        A::CreateView => Privilege::CreateView,
        A::CreateSchema => Privilege::CreateSchema,
        A::CreateDatabase => Privilege::CreateDatabase,
        A::CreateRole => Privilege::CreateRole,
        A::CreateUser => Privilege::CreateUser,
        A::CreateFunction => Privilege::CreateFunction,
        A::CreateProcedure => Privilege::CreateProcedure,
        A::CreateMaskingPolicy => Privilege::CreateMaskingPolicy,
        A::CreateRowAccessPolicy => Privilege::CreateRowAccessPolicy,
        A::CreateNetworkPolicy => Privilege::CreateNetworkPolicy,
        A::CreateSessionPolicy => Privilege::CreateSessionPolicy,
        A::CreatePasswordPolicy => Privilege::CreatePasswordPolicy,
        A::CreateStage => Privilege::CreateStage,
        A::CreateWarehouse => Privilege::CreateWarehouse,
        A::CreateTask => Privilege::CreateTask,
        A::CreatePipe => Privilege::CreatePipe,
        A::CreateExternalTable => Privilege::CreateExternalTable,
        A::Create => Privilege::Create,
        A::Manage => Privilege::Manage,
        A::ExternalUseLocation => Privilege::ExternalUseLocation,
        A::ExternalUseSchema => Privilege::ExternalUseSchema,
        A::ReadFiles => Privilege::ReadFiles,
        A::WriteFiles => Privilege::WriteFiles,
        A::CreateStorageCredential => Privilege::CreateStorageCredential,
        A::CreateExternalLocation => Privilege::CreateExternalLocation,
        A::SetSharePermission => Privilege::SetSharePermission,
        A::Other { lexemes } => Privilege::Other(IdentName::new(lexemes.join(" "))),
    }
}

fn project_object_target(
    obj: &PrivilegeObject,
    source: &str,
) -> (Option<ObjectRef>, bool, bool, Option<ObjectKind>) {
    match obj {
        PrivilegeObject::Account => (None, false, false, None),
        PrivilegeObject::Metastore => (None, false, false, None),
        PrivilegeObject::Single {
            kind, name_span, ..
        } => {
            let object_ref = ObjectRef {
                kind: project_object_kind(kind),
                name: parse_table_ref(*name_span, source),
            };
            (Some(object_ref), false, false, None)
        }
        PrivilegeObject::AllInScope { scope, plural } => (
            Some(scope_target(scope, source)),
            false,
            true,
            project_plural_object_kind(plural),
        ),
        PrivilegeObject::FutureInScope { scope, plural } => (
            Some(scope_target(scope, source)),
            true,
            false,
            project_plural_object_kind(plural),
        ),
    }
}

fn scope_target(scope: &PrivilegeObjectScope, source: &str) -> ObjectRef {
    match scope {
        PrivilegeObjectScope::Database { name_span } => ObjectRef {
            kind: ObjectKind::Database,
            name: parse_table_ref(*name_span, source),
        },
        PrivilegeObjectScope::Schema { name_span } => ObjectRef {
            kind: ObjectKind::Schema,
            name: parse_table_ref(*name_span, source),
        },
        PrivilegeObjectScope::Catalog { name_span } => ObjectRef {
            kind: ObjectKind::Catalog,
            name: parse_table_ref(*name_span, source),
        },
    }
}

fn role_target(name_span: Span, source: &str) -> ObjectRef {
    ObjectRef {
        kind: ObjectKind::Role,
        name: parse_table_ref(name_span, source),
    }
}

fn database_role_target(name_span: Span, source: &str) -> ObjectRef {
    // `ObjectKind` does not yet have a dedicated `DatabaseRole` variant;
    // project to the closest sibling `Role` and let downstream rules
    // disambiguate via the qualified `name` (`<db>.<role>`).
    ObjectRef {
        kind: ObjectKind::Role,
        name: parse_table_ref(name_span, source),
    }
}

fn project_object_kind(kind: &AstObjectKind) -> ObjectKind {
    use AstObjectKind as A;
    match kind {
        A::Table => ObjectKind::Table,
        A::View => ObjectKind::View,
        A::MaterializedView => ObjectKind::MaterializedView,
        A::DynamicTable => ObjectKind::DynamicTable,
        A::ExternalTable => ObjectKind::ExternalTable,
        A::Schema => ObjectKind::Schema,
        A::Database => ObjectKind::Database,
        A::Warehouse => ObjectKind::Warehouse,
        A::User => ObjectKind::User,
        A::Role => ObjectKind::Role,
        A::Share => ObjectKind::Share,
        A::Account => ObjectKind::Account,
        A::Integration => ObjectKind::ApiIntegration,
        A::Stage => ObjectKind::Stage,
        A::Function => ObjectKind::Function,
        A::Procedure => ObjectKind::Procedure,
        A::Sequence => ObjectKind::Sequence,
        A::Stream => ObjectKind::Stream,
        A::Task => ObjectKind::Task,
        A::Pipe => ObjectKind::Pipe,
        A::Tag => ObjectKind::Tag,
        A::NetworkRule => ObjectKind::NetworkRule,
        A::Alert => ObjectKind::Alert,
        A::MaskingPolicy => ObjectKind::MaskingPolicy,
        A::RowAccessPolicy => ObjectKind::RowAccessPolicy,
        A::AggregationPolicy => ObjectKind::AggregationPolicy,
        A::AuthenticationPolicy => ObjectKind::AuthenticationPolicy,
        A::PasswordPolicy => ObjectKind::PasswordPolicy,
        A::NetworkPolicy => ObjectKind::NetworkPolicy,
        A::SessionPolicy => ObjectKind::SessionPolicy,
        A::ProjectionPolicy => ObjectKind::ProjectionPolicy,
        A::Catalog => ObjectKind::Catalog,
        A::Volume => ObjectKind::Volume,
        A::ExternalLocation => ObjectKind::ExternalLocation,
        A::StorageCredential => ObjectKind::StorageCredential,
        A::Metastore => ObjectKind::Metastore,
        // Snowflake kinds without a dedicated `ObjectKind` variant fall
        // back to `Generic`.
        A::IcebergTable
        | A::HybridTable
        | A::Application
        | A::ApplicationPackage
        | A::ResourceMonitor
        | A::ComputePool
        | A::ExternalVolume
        | A::Connection
        | A::FailoverGroup
        | A::ReplicationGroup
        | A::FileFormat
        | A::DataMetricFunction
        | A::Secret
        | A::Service
        | A::Streamlit
        | A::SemanticView
        | A::Other { .. } => ObjectKind::Generic,
    }
}

/// Map an `AstPluralObjectKind` (the `<plural>` in
/// `GRANT … ON {ALL | FUTURE} <plural> IN <scope>`) to its singular
/// [`ObjectKind`] for `PrivilegeFacts.target_plural_kind`. Returns
/// `None` for plurals that have no typed singular counterpart so
/// rules predicate only on recognised forms rather than a `Generic`
/// fallback.
fn project_plural_object_kind(plural: &AstPluralObjectKind) -> Option<ObjectKind> {
    use AstPluralObjectKind as P;
    match plural {
        P::Tables => Some(ObjectKind::Table),
        P::Views => Some(ObjectKind::View),
        P::MaterializedViews => Some(ObjectKind::MaterializedView),
        P::DynamicTables => Some(ObjectKind::DynamicTable),
        P::ExternalTables => Some(ObjectKind::ExternalTable),
        P::Schemas => Some(ObjectKind::Schema),
        P::Functions => Some(ObjectKind::Function),
        P::Procedures => Some(ObjectKind::Procedure),
        P::Sequences => Some(ObjectKind::Sequence),
        P::Stages => Some(ObjectKind::Stage),
        P::Streams => Some(ObjectKind::Stream),
        P::Tasks => Some(ObjectKind::Task),
        P::Pipes => Some(ObjectKind::Pipe),
        P::Tags => Some(ObjectKind::Tag),
        P::MaskingPolicies => Some(ObjectKind::MaskingPolicy),
        P::RowAccessPolicies => Some(ObjectKind::RowAccessPolicy),
        P::AggregationPolicies => Some(ObjectKind::AggregationPolicy),
        P::AuthenticationPolicies => Some(ObjectKind::AuthenticationPolicy),
        P::PasswordPolicies => Some(ObjectKind::PasswordPolicy),
        P::NetworkPolicies => Some(ObjectKind::NetworkPolicy),
        P::SessionPolicies => Some(ObjectKind::SessionPolicy),
        P::ProjectionPolicies => Some(ObjectKind::ProjectionPolicy),
        P::IcebergTables
        | P::HybridTables
        | P::FileFormats
        | P::DataMetricFunctions
        | P::SemanticViews
        | P::Other { .. } => None,
    }
}

fn project_grantee(grantee: &PrivilegeGrantee, source: &str) -> PrincipalRef {
    match grantee {
        PrivilegeGrantee::Role { name_span } => PrincipalRef {
            kind: PrincipalKind::Role,
            name: span_to_ident_name(*name_span, source),
            source_span: Some(*name_span),
        },
        PrivilegeGrantee::User { name_span } => PrincipalRef {
            kind: PrincipalKind::User,
            name: span_to_ident_name(*name_span, source),
            source_span: Some(*name_span),
        },
        PrivilegeGrantee::Share { name_span } => PrincipalRef {
            kind: PrincipalKind::Share,
            name: span_to_ident_name(*name_span, source),
            source_span: Some(*name_span),
        },
        PrivilegeGrantee::DatabaseRole { name_span } => PrincipalRef {
            kind: PrincipalKind::Other(IdentName::new("database_role")),
            name: span_to_ident_name(*name_span, source),
            source_span: Some(*name_span),
        },
        PrivilegeGrantee::Application { name_span } => PrincipalRef {
            kind: PrincipalKind::Application,
            name: span_to_ident_name(*name_span, source),
            source_span: Some(*name_span),
        },
        PrivilegeGrantee::ApplicationRole { name_span } => PrincipalRef {
            kind: PrincipalKind::ApplicationRole,
            name: span_to_ident_name(*name_span, source),
            source_span: Some(*name_span),
        },
        PrivilegeGrantee::Group { name_span } => PrincipalRef {
            kind: PrincipalKind::Other(IdentName::new("group")),
            name: span_to_ident_name(*name_span, source),
            source_span: Some(*name_span),
        },
        PrivilegeGrantee::SchemaOwner { keyword_span } => PrincipalRef {
            kind: PrincipalKind::Other(IdentName::new("schema_owner")),
            name: span_to_ident_name(*keyword_span, source),
            source_span: Some(*keyword_span),
        },
    }
}

// ---------------------------------------------------------------------------
// Span / identifier helpers.
// ---------------------------------------------------------------------------

pub fn span_slice(span: Span, source: &str) -> &str {
    let start = span.start as usize;
    let end = span.end as usize;
    if start <= end && end <= source.len() {
        &source[start..end]
    } else {
        ""
    }
}

fn span_to_ident_name(span: Span, source: &str) -> IdentName {
    // For grantee names we take the last component (most-specific) so
    // the `IdentName` carries a single-segment identity. Multi-component
    // grantee names (e.g., `DATABASE ROLE db.dbr`) preserve their full
    // qualifier in `target.name.canonical` instead.
    let raw = span_slice(span, source).trim();
    let name = match crate::ir::lower_ddl::split_qualified(raw).pop() {
        Some(last) => IdentName::new(last),
        None => IdentName::new(raw),
    };
    name.written_at(span)
}

fn parse_table_ref(span: Span, source: &str) -> TableRef {
    qualified_name_to_table_ref(span_slice(span, source).trim(), Some(span))
}

/// Build a public `StatementFacts` directly from a lowered
/// [`PrivilegePlan`] and the original source text — the catalog is
/// not consulted (privilege projection is fully closed-enum-driven).
///
/// For callers that only need privilege-shaped facts (e.g. the
/// `analyze_privilege_facts` entry point).
pub fn derive_facts_from_privilege_plan(plan: &PrivilegePlan, source: &str) -> StatementFacts {
    let func_catalog = crate::ir::FunctionCatalog::empty();
    // Privilege projection reads the plan alone; no analysis is consulted.
    let ctx = CatalogCtx {
        catalog: None,
        known: None,
        function_catalog: &func_catalog,
        source,
        scan_index: None,
        reasoning: &super::reasoning::RecognitionOnly,
        placeholders: &[],
        output_columns: false,
    };
    project_privilege_statement(plan, &ctx)
}

/// [`derive_facts_from_privilege_plan`] plus the reach the reasoning
/// provider reports for the grant: `privilege.role_grant_impact` and
/// `privilege.object_grant_impact` when the statement is a `GRANT ROLE
/// <parent> TO ROLE <child>` or object-level GRANT whose role-hierarchy
/// traversal yields non-zero privilege inheritance.
pub fn derive_facts_from_privilege_plan_with_reasoning(
    plan: &PrivilegePlan,
    source: &str,
    reasoning: &dyn super::reasoning::Reasoning,
) -> StatementFacts {
    let mut facts = derive_facts_from_privilege_plan(plan, source);
    let impacts = reasoning.grant_impacts(plan, source);
    if let Some(p) = facts.privilege.as_mut() {
        if impacts.role.is_some() {
            p.role_grant_impact = impacts.role;
        }
        if impacts.object.is_some() {
            p.object_grant_impact = impacts.object;
        }
    }
    facts
}

/// Build a public `StatementFacts` directly from a lowered [`StagePlan`]
/// and the original source text — the catalog is not consulted.
///
/// the `analyze_ddl_facts` pipeline. Produces facts for both
/// `CREATE STAGE` and `ALTER STAGE`; further stage-DDL families plug
/// in here.
pub fn derive_facts_from_stage_plan(plan: &StagePlan, source: &str) -> StatementFacts {
    project_stage_statement(plan, source)
}

fn project_stage_statement(plan: &StagePlan, source: &str) -> StatementFacts {
    let kind = match plan.action {
        StageAction::Create => StatementKind::CreateStage,
        StageAction::Alter => StatementKind::AlterStage,
        StageAction::Drop => StatementKind::DropStage,
        StageAction::CopyToLocation => StatementKind::CopyIntoLocation,
        StageAction::Unload => StatementKind::RedshiftUnload,
        StageAction::Load => StatementKind::RedshiftCopy,
        StageAction::CopyToTable => StatementKind::CopyIntoTable,
    };
    let stage = StageDdlFacts {
        credentials: project_stage_credentials(&plan.credentials, source),
        url_literal: plan.url_literal.clone().map(|url| match plan.url_span {
            Some(span) => super::identity::WrittenText::at(url, span),
            None => super::identity::WrittenText {
                text: url,
                origin: super::identity::TextOrigin::default(),
            },
        }),
        url_password_literals: password_literals(&plan.url_password_literals),
        encryption_disabled: plan.encryption_disabled,
        encryption_enabled: plan.encryption_enabled,
        set_tag: plan.set_tag,
        unset_tag: plan.unset_tag,
        set_storage_integration: plan.set_storage_integration,
        unbounded_export: plan.unbounded_export,
        has_unknown_clauses: plan.has_unknown_clauses,
        copy_options: project_copy_options(&plan.copy_options, source),
        // Populated by the COPY INTO <location> dispatch, which has the
        // catalog / cross-script registry needed to resolve the source's taint.
        exported_columns: Vec::new(),
        path: None,
    };
    // COPY INTO LOCATION moves data rather than altering schema; emit
    // `DdlAction::BulkLoad` (the same variant as the inverse
    // `COPY INTO TABLE` direction). Predicates target
    // `kind: copy_into_location` for statement-type filtering, not
    // `ddl.action`, so this stays consistent with rule authoring.
    let ddl = DdlFacts {
        targets: Vec::new(),
        action: match plan.action {
            StageAction::Create => DdlAction::Create,
            StageAction::Alter => DdlAction::Alter,
            StageAction::Drop => DdlAction::Drop,
            StageAction::CopyToLocation => DdlAction::BulkLoad,
            StageAction::Unload => DdlAction::BulkLoad,
            StageAction::Load => DdlAction::BulkLoad,
            StageAction::CopyToTable => DdlAction::BulkLoad,
        },
        object_kind: ObjectKind::Stage,
        // The stage a CREATE, ALTER or DROP STAGE names or `COPY INTO @stage`
        // unloads to; the table a COPY loads.
        target: plan.target.as_ref().map(|t| ObjectRef {
            kind: match plan.action {
                StageAction::Create
                | StageAction::Alter
                | StageAction::Drop
                | StageAction::CopyToLocation => ObjectKind::Stage,
                StageAction::Load | StageAction::CopyToTable => ObjectKind::Table,
                StageAction::Unload => ObjectKind::Generic,
            },
            name: ddl_target_name(t),
        }),
        options: DdlOptions {
            or_replace: plan.or_replace,
            ..DdlOptions::default()
        },
        alter_changes: Vec::new(),
        stage: Some(stage),
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: None,
        database: None,
        warehouse: None,
        stream: None,
        schema: None,
        function: None,
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: None,
        session: None,
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: None,
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

fn project_stage_credentials(creds: &StageCredentials, source: &str) -> Vec<StageCredentialOption> {
    match creds {
        StageCredentials::None | StageCredentials::StorageIntegration { .. } => Vec::new(),
        StageCredentials::Inline { options } => options
            .iter()
            .map(|opt| {
                let raw = slice_span_text(source, opt.name_span);
                StageCredentialOption {
                    key: IdentName::new(raw),
                    value_literal: match &opt.value {
                        StageCredentialValue::StringLiteral { text, .. } => Some(text.clone()),
                        StageCredentialValue::Other { .. } => None,
                    },
                }
            })
            .collect(),
    }
}

/// Project the AST copy options of a COPY INTO statement onto their public
/// `CopyOption` facts. Name and (scalar) value are normalized via
/// `IdentName`; a parenthesized value (e.g. `FILE_FORMAT = (...)`) yields
/// `value: None` — its presence is recognized, its body is not decomposed.
fn project_copy_options(opts: &[crate::ast::AstCopyOption], source: &str) -> Vec<CopyOption> {
    opts.iter()
        .map(|o| {
            let key = IdentName::new(slice_span_text(source, o.name_span)).written_at(o.name_span);
            let raw = slice_span_text(source, o.value_span);
            let value = if raw.starts_with('(') {
                None
            } else {
                Some(IdentName::new(literal_value_or_name(raw)))
            };
            CopyOption { key, value }
        })
        .collect()
}

/// Build a public `StatementFacts` directly from a lowered
/// [`StorageCredentialPlan`]. Catalog is not consulted — the typed
/// provider taxonomy already carries all the structural data needed
/// downstream.
pub fn derive_facts_from_storage_credential_plan(
    plan: &StorageCredentialPlan,
    source: &str,
) -> StatementFacts {
    project_storage_credential_statement(plan, source)
}

/// Project one `IrStorageCredentialAlterAction` onto its public mirror.
/// Single boundary point — the public closed enum is curated in
/// `src/facts/ddl.rs::StorageCredentialAlterAction`.
fn project_storage_credential_alter_action(
    a: IrStorageCredentialAlterAction,
) -> StorageCredentialAlterAction {
    match a {
        IrStorageCredentialAlterAction::RenameTo => StorageCredentialAlterAction::RenameTo,
        IrStorageCredentialAlterAction::OwnerTo => StorageCredentialAlterAction::OwnerTo,
        IrStorageCredentialAlterAction::SetProvider => StorageCredentialAlterAction::SetProvider,
    }
}

fn project_storage_credential_statement(
    plan: &StorageCredentialPlan,
    source: &str,
) -> StatementFacts {
    let kind = match plan.action {
        StorageCredentialAction::Create => StatementKind::CreateStorageCredential,
        StorageCredentialAction::Alter => StatementKind::AlterStorageCredential,
        StorageCredentialAction::Drop => StatementKind::DropStorageCredential,
    };
    let comment = plan
        .comment_value_span
        .and_then(|sp| crate::ir::policy_plan::comment_text_from_value_span(sp, source));
    let storage_credential = StorageCredentialFacts {
        action: match plan.action {
            StorageCredentialAction::Create => StorageCredentialChangeKind::Create,
            StorageCredentialAction::Alter => StorageCredentialChangeKind::Alter,
            StorageCredentialAction::Drop => StorageCredentialChangeKind::Drop,
        },
        credential_kind: match plan.credential_kind {
            StorageCredentialKindIr::Storage => StorageCredentialKindFacts::Storage,
            StorageCredentialKindIr::Service => StorageCredentialKindFacts::Service,
            StorageCredentialKindIr::Bare => StorageCredentialKindFacts::Bare,
        },
        if_not_exists: plan.if_not_exists,
        provider: plan.provider.as_ref().map(project_provider),
        actions: plan
            .actions
            .iter()
            .copied()
            .map(project_storage_credential_alter_action)
            .collect(),
        comment,
        comment_url_password_literals: password_literals(&plan.comment_url_password_literals),
    };
    let ddl = DdlFacts {
        targets: Vec::new(),
        action: match plan.action {
            StorageCredentialAction::Create => DdlAction::Create,
            StorageCredentialAction::Alter => DdlAction::Alter,
            StorageCredentialAction::Drop => DdlAction::Drop,
        },
        object_kind: ObjectKind::StorageCredential,
        target: plan.target.as_ref().map(|t| ObjectRef {
            kind: ObjectKind::StorageCredential,
            name: ddl_target_name(t),
        }),
        options: DdlOptions::default(),
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: Some(storage_credential),
        dynamic_table: None,
        pipe: None,
        task: None,
        database: None,
        warehouse: None,
        stream: None,
        schema: None,
        function: None,
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: None,
        session: None,
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: None,
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

fn project_provider(p: &StorageCredentialProvider) -> StorageCredentialProviderFacts {
    let variant = match &p.variant {
        StorageCredentialProviderVariant::AwsIamRole { role_arn } => {
            StorageCredentialProviderVariantFacts::AwsIamRole {
                role_arn: role_arn.clone(),
            }
        }
        StorageCredentialProviderVariant::AzureManagedIdentity {
            managed_identity_id,
            access_connector_id,
        } => StorageCredentialProviderVariantFacts::AzureManagedIdentity {
            managed_identity_id: managed_identity_id.clone(),
            access_connector_id: access_connector_id.clone(),
        },
        StorageCredentialProviderVariant::AzureServicePrincipal {
            directory_id,
            application_id,
            client_secret,
        } => StorageCredentialProviderVariantFacts::AzureServicePrincipal {
            directory_id: directory_id.clone(),
            application_id: application_id.clone(),
            client_secret: client_secret.clone(),
        },
        StorageCredentialProviderVariant::DatabricksGcpServiceAccount => {
            StorageCredentialProviderVariantFacts::DatabricksGcpServiceAccount
        }
        StorageCredentialProviderVariant::CloudflareApiToken {
            account_id,
            access_key_id,
            secret_access_key,
        } => StorageCredentialProviderVariantFacts::CloudflareApiToken {
            account_id: account_id.clone(),
            access_key_id: access_key_id.clone(),
            secret_access_key: secret_access_key.clone(),
        },
        StorageCredentialProviderVariant::Unparsed => {
            StorageCredentialProviderVariantFacts::Unparsed
        }
    };
    StorageCredentialProviderFacts {
        variant,
        all_literal_values: p
            .all_literal_values
            .iter()
            .map(|s| StorageCredentialLiteral { value: s.clone() })
            .collect(),
        url_password_literals: password_literals(&p.url_password_literals),
    }
}

fn slice_span_text(source: &str, span: Span) -> &str {
    let start = span.start as usize;
    let end = (span.end as usize).min(source.len());
    if start >= end {
        ""
    } else {
        &source[start..end]
    }
}

// ---------------------------------------------------------------------------
// Dynamic-table projection.
// ---------------------------------------------------------------------------

/// Build a public `StatementFacts` directly from a lowered
/// [`DynamicTablePlan`]. Catalog is not consulted — the typed plan
/// already carries the required structural data.
pub fn derive_facts_from_dynamic_table_plan(
    plan: &DynamicTablePlan,
    _source: &str,
) -> StatementFacts {
    project_dynamic_table_statement(plan)
}

fn project_dynamic_table_statement(plan: &DynamicTablePlan) -> StatementFacts {
    let kind = match plan.action {
        DynamicTableAction::Create => StatementKind::CreateDynamicTable,
        DynamicTableAction::Alter => StatementKind::AlterDynamicTable,
        DynamicTableAction::Drop => StatementKind::DropDynamicTable,
    };
    let dynamic_table = DynamicTableFacts {
        query_unparseable: plan.query_unparseable,
        suspended: plan.alter_flags.suspended,
        resumed: plan.alter_flags.resumed,
        renamed: plan.alter_flags.renamed,
        swapped: plan.alter_flags.swapped,
        tag_set: plan.alter_flags.tag_set,
        tag_unset: plan.alter_flags.tag_unset,
        row_access_policy_added: plan.alter_flags.row_access_policy_added,
        row_access_policy_removed: plan.alter_flags.row_access_policy_removed,
        masking_policy_added: plan.alter_flags.masking_policy_added,
        masking_policy_removed: plan.alter_flags.masking_policy_removed,
    };
    let ddl = DdlFacts {
        targets: Vec::new(),
        action: match plan.action {
            DynamicTableAction::Create => DdlAction::Create,
            DynamicTableAction::Alter => DdlAction::Alter,
            DynamicTableAction::Drop => DdlAction::Drop,
        },
        object_kind: ObjectKind::DynamicTable,
        target: plan.target.as_ref().map(|t| ObjectRef {
            kind: ObjectKind::DynamicTable,
            name: TableRef::new(
                IdentName::new(t.name.clone()),
                t.schema.clone().map(IdentName::new),
                t.db.clone().map(IdentName::new),
                Some(t.span),
            ),
        }),
        options: DdlOptions {
            or_replace: plan.options.or_replace,
            or_alter: plan.options.or_alter,
            if_exists: plan.options.if_exists,
            if_not_exists: plan.options.if_not_exists,
            transient: plan.options.transient,
            cascade: plan.options.cascade,
            restrict: plan.options.restrict,
            ..DdlOptions::default()
        },
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: Some(dynamic_table),
        pipe: None,
        task: None,
        database: None,
        warehouse: None,
        stream: None,
        schema: None,
        function: None,
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: None,
        session: None,
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: None,
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

// ---------------------------------------------------------------------------
// Table projection.
// ---------------------------------------------------------------------------

/// Build a public `StatementFacts` directly from a lowered
/// [`TablePlan`]. Catalog is not consulted — the typed plan already
/// carries the required structural data.
pub fn derive_facts_from_table_plan(plan: &TablePlan, _source: &str) -> StatementFacts {
    project_table_statement(plan)
}

/// Project one `IrTableAlterAction` onto its public mirror. Single
/// boundary point — the public closed enum is curated in
/// `src/facts/ddl.rs::TableAlterAction`.
fn project_table_alter_action(a: IrTableAlterAction) -> TableAlterAction {
    match a {
        IrTableAlterAction::SetTblProperties => TableAlterAction::SetTblProperties,
        IrTableAlterAction::UnsetTblProperties => TableAlterAction::UnsetTblProperties,
        IrTableAlterAction::ClusterBy { disabled } => TableAlterAction::ClusterBy { disabled },
        IrTableAlterAction::SetJoinPolicy => TableAlterAction::SetJoinPolicy,
        IrTableAlterAction::SetAggregationPolicy => TableAlterAction::SetAggregationPolicy,
        IrTableAlterAction::AddDataMetricFunction => TableAlterAction::AddDataMetricFunction,
        IrTableAlterAction::DropDataMetricFunction => TableAlterAction::DropDataMetricFunction,
        IrTableAlterAction::RowLevelSecurity { mode } => {
            use crate::facts::ddl::RowLevelSecurityMode as F;
            use crate::ir::table_plan::IrRowLevelSecurityMode as M;
            let mode = match mode {
                M::Enable => F::Enable,
                M::Disable => F::Disable,
                M::Force => F::Force,
                M::NoForce => F::NoForce,
            };
            TableAlterAction::RowLevelSecurity { mode }
        }
        IrTableAlterAction::SwapWith => TableAlterAction::SwapWith,
    }
}

fn project_clone_shape(s: IrCloneShape) -> CloneShape {
    match s {
        IrCloneShape::Shallow => CloneShape::Shallow,
        IrCloneShape::Deep => CloneShape::Deep,
        IrCloneShape::Standard => CloneShape::Standard,
    }
}

fn project_create_table_kind(k: IrCreateTableKind) -> CreateTableKind {
    match k {
        IrCreateTableKind::Iceberg => CreateTableKind::Iceberg,
        IrCreateTableKind::Hybrid => CreateTableKind::Hybrid,
        IrCreateTableKind::Event => CreateTableKind::Event,
    }
}

fn project_dist_style(s: IrDistStyle) -> DistStyle {
    match s {
        IrDistStyle::Even => DistStyle::Even,
        IrDistStyle::Key => DistStyle::Key,
        IrDistStyle::All => DistStyle::All,
        IrDistStyle::Auto => DistStyle::Auto,
    }
}

fn project_sort_key_spec(s: IrSortKeySpec) -> SortKeySpec {
    match s {
        IrSortKeySpec::Compound => SortKeySpec::Compound,
        IrSortKeySpec::Interleaved => SortKeySpec::Interleaved,
    }
}

fn project_backup_mode(s: IrBackupMode) -> BackupMode {
    match s {
        IrBackupMode::Yes => BackupMode::Yes,
        IrBackupMode::No => BackupMode::No,
    }
}

fn table_target_to_ref(t: &crate::ir::table_plan::TableTarget) -> TableRef {
    TableRef::new(
        IdentName::new(t.name.clone()),
        t.schema.clone().map(IdentName::new),
        t.db.clone().map(IdentName::new),
        Some(t.span),
    )
}

fn project_table_statement(plan: &TablePlan) -> StatementFacts {
    let kind = match plan.action {
        TableAction::Create => StatementKind::CreateTable,
        TableAction::Alter => StatementKind::AlterTable,
        TableAction::Drop => StatementKind::DropTable,
        TableAction::Truncate => StatementKind::Truncate,
        TableAction::Rename => StatementKind::RenameTable,
        TableAction::DropAllRowAccessPolicies => StatementKind::DropAllRowAccessPolicies,
    };
    let table = TableFacts {
        or_replace: plan.options.or_replace,
        temporary: plan.options.temporary || plan.target.as_ref().is_some_and(|t| t.temporary),
        column_added: plan.alter_flags.column_added,
        column_dropped: plan.alter_flags.column_dropped,
        renamed: plan.alter_flags.renamed,
        row_access_policy_added: plan.alter_flags.row_access_policy_added,
        row_access_policy_removed: plan.alter_flags.row_access_policy_removed,
        masking_policy_added: plan.alter_flags.masking_policy_added,
        masking_policy_removed: plan.alter_flags.masking_policy_removed,
        aggregation_policy_removed: plan.alter_flags.aggregation_policy_removed,
        tag_set: plan.alter_flags.tag_set,
        tag_unset: plan.alter_flags.tag_unset,
        drop_all_row_access_policies: matches!(plan.action, TableAction::DropAllRowAccessPolicies),
        actions: plan
            .actions
            .iter()
            .copied()
            .map(project_table_alter_action)
            .collect(),
        clone: plan.clone.map(project_clone_shape),
        dist_style: plan.physical.dist_style.map(project_dist_style),
        dist_key_present: plan.physical.dist_key_present,
        sort_key: plan.physical.sort_key.map(project_sort_key_spec),
        backup: plan.physical.backup.map(project_backup_mode),
        variant: plan.kind.map(project_create_table_kind),
        data_retention_days: plan.data_retention_days,
        renames: plan
            .renames
            .iter()
            .map(|p| TableRenamePair {
                from: table_target_to_ref(&p.from),
                to: table_target_to_ref(&p.to),
            })
            .collect(),
    };
    let ddl = DdlFacts {
        targets: Vec::new(),
        action: match plan.action {
            TableAction::Create => DdlAction::Create,
            TableAction::Alter => DdlAction::Alter,
            TableAction::Drop => DdlAction::Drop,
            TableAction::Truncate => DdlAction::Truncate,
            TableAction::Rename => DdlAction::Rename,
            // Top-level `DROP ALL ROW ACCESS POLICIES <table>` is a
            // policy-detach action; surfaces as `DdlAction::Drop` in
            // the public DDL action axis (predicates that need to
            // distinguish use `kind: drop_all_row_access_policies`).
            TableAction::DropAllRowAccessPolicies => DdlAction::Drop,
        },
        object_kind: ObjectKind::Table,
        target: plan.target.as_ref().map(|t| ObjectRef {
            kind: ObjectKind::Table,
            name: table_target_to_ref(t),
        }),
        options: DdlOptions {
            or_replace: plan.options.or_replace,
            or_alter: false,
            if_exists: plan.options.if_exists,
            if_not_exists: plan.options.if_not_exists,
            temporary: plan.options.temporary,
            transient: plan.options.transient,
            scoped: plan.options.scoped,
            cascade: plan.options.cascade,
            restrict: plan.options.restrict,
            ..DdlOptions::default()
        },
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: None,
        database: None,
        warehouse: None,
        stream: None,
        schema: None,
        function: None,
        procedure: None,
        table: Some(table),
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: None,
        session: None,
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: None,
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

// ---------------------------------------------------------------------------
// Table-maintenance projection (Databricks / Delta / SparkSQL).
// ---------------------------------------------------------------------------

/// Project a [`TableMaintenancePlan`] onto public [`StatementFacts`].
/// Catalog is not consulted — the plan already carries the required
/// structural data.
pub fn derive_facts_from_table_maintenance_plan(
    plan: &TableMaintenancePlan,
    _source: &str,
) -> StatementFacts {
    let kind = match plan.kind {
        IrTableMaintenanceKind::Vacuum => StatementKind::DbxVacuum,
        IrTableMaintenanceKind::Optimize => StatementKind::DbxOptimize,
        IrTableMaintenanceKind::Restore => StatementKind::DbxRestore,
        IrTableMaintenanceKind::DescribeHistory => StatementKind::DbxDescribeHistory,
        IrTableMaintenanceKind::RepairTable => StatementKind::DbxRepairTable,
        IrTableMaintenanceKind::CacheTable => StatementKind::DbxCacheTable,
        IrTableMaintenanceKind::UncacheTable => StatementKind::DbxUncacheTable,
    };
    let public_kind = match plan.kind {
        IrTableMaintenanceKind::Vacuum => TableMaintenanceKind::Vacuum,
        IrTableMaintenanceKind::Optimize => TableMaintenanceKind::Optimize,
        IrTableMaintenanceKind::Restore => TableMaintenanceKind::Restore,
        IrTableMaintenanceKind::DescribeHistory => TableMaintenanceKind::DescribeHistory,
        IrTableMaintenanceKind::RepairTable => TableMaintenanceKind::RepairTable,
        IrTableMaintenanceKind::CacheTable => TableMaintenanceKind::CacheTable,
        IrTableMaintenanceKind::UncacheTable => TableMaintenanceKind::UncacheTable,
    };
    let target_ref = plan.target.as_ref().map(|t| {
        TableRef::new(
            IdentName::new(t.name.clone()),
            t.schema.clone().map(IdentName::new),
            t.db.clone().map(IdentName::new),
            Some(t.span),
        )
    });
    let maintenance = TableMaintenanceFacts {
        kind: public_kind,
        target: target_ref.clone(),
        vacuum: plan.vacuum.map(|v| VacuumOptions {
            retain_hours: v.retain_hours,
        }),
        cache: plan.cache.map(|c| CacheOptions { lazy: c.lazy }),
        repair: plan.repair.map(|r| RepairOptions {
            mode: r.mode.map(project_repair_mode),
        }),
    };
    let ddl = DdlFacts {
        targets: Vec::new(),
        action: DdlAction::Maintenance,
        object_kind: ObjectKind::Table,
        target: target_ref.map(|name| ObjectRef {
            kind: ObjectKind::Table,
            name,
        }),
        options: DdlOptions::default(),
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: None,
        database: None,
        warehouse: None,
        stream: None,
        schema: None,
        function: None,
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: Some(maintenance),
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: None,
        session: None,
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: None,
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

fn project_repair_mode(m: crate::ast::types::RepairPartitionsMode) -> RepairMode {
    use crate::ast::types::RepairPartitionsMode as A;
    match m {
        A::Add => RepairMode::Add,
        A::Drop => RepairMode::Drop,
        A::Sync => RepairMode::Sync,
    }
}

// ---------------------------------------------------------------------------
// Pipe projection.
// ---------------------------------------------------------------------------

/// Build a public `StatementFacts` directly from a lowered
/// [`PipePlan`]. Catalog is not consulted — the typed plan already
/// carries the required structural data.
pub fn derive_facts_from_pipe_plan(plan: &PipePlan, _source: &str) -> StatementFacts {
    project_pipe_statement(plan)
}

fn project_pipe_statement(plan: &PipePlan) -> StatementFacts {
    let kind = match plan.action {
        PipeAction::Create => StatementKind::CreatePipe,
        PipeAction::Alter => StatementKind::AlterPipe,
        PipeAction::Drop => StatementKind::DropPipe,
    };
    let pipe = PipeFacts {
        auto_ingest_enabled: plan.create_flags.auto_ingest_enabled,
        error_integration_set: plan.create_flags.error_integration_set,
        set: plan.alter_flags.set,
        tag_set: plan.alter_flags.tag_set,
        tag_unset: plan.alter_flags.tag_unset,
        refreshed: plan.alter_flags.refreshed,
    };
    let ddl = DdlFacts {
        targets: Vec::new(),
        action: match plan.action {
            PipeAction::Create => DdlAction::Create,
            PipeAction::Alter => DdlAction::Alter,
            PipeAction::Drop => DdlAction::Drop,
        },
        object_kind: ObjectKind::Pipe,
        target: plan.target.as_ref().map(|t| ObjectRef {
            kind: ObjectKind::Pipe,
            name: TableRef::new(
                IdentName::new(t.name.clone()),
                t.schema.clone().map(IdentName::new),
                t.db.clone().map(IdentName::new),
                Some(t.span),
            ),
        }),
        options: DdlOptions {
            or_replace: plan.options.or_replace,
            if_exists: plan.options.if_exists,
            if_not_exists: plan.options.if_not_exists,
            ..DdlOptions::default()
        },
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: Some(pipe),
        task: None,
        database: None,
        warehouse: None,
        stream: None,
        schema: None,
        function: None,
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: None,
        session: None,
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: None,
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

// ---------------------------------------------------------------------------
// Network-rule projection.
// ---------------------------------------------------------------------------

/// Build a public `StatementFacts` directly from a lowered
/// [`NetworkRulePlan`].
pub fn derive_facts_from_network_rule_plan(plan: &NetworkRulePlan, source: &str) -> StatementFacts {
    let kind = match plan.action {
        NetworkRuleAction::Create => StatementKind::CreateNetworkRule,
        NetworkRuleAction::Alter => StatementKind::AlterNetworkRule,
        NetworkRuleAction::Drop => StatementKind::DropNetworkRule,
    };
    let network_rule = NetworkRuleFacts {
        rule_type: plan.rule_type.clone(),
        mode: plan.mode.clone(),
        value_entries: plan
            .value_list
            .iter()
            .map(|v| {
                let (cidr_prefix, is_private_range, is_zero_route) = classify_ip_entry(v);
                crate::facts::policy::IpListEntry {
                    raw: v.clone(),
                    cidr_prefix,
                    is_private_range,
                    is_zero_route,
                }
            })
            .collect(),
        value_list: plan.value_list.clone(),
        value_list_set: plan.had_set_value_list,
        properties_set: plan.set_property_names.clone(),
        properties_unset: plan.unset_property_names.clone(),
    };
    let ddl = DdlFacts {
        targets: Vec::new(),
        action: match plan.action {
            NetworkRuleAction::Create => DdlAction::Create,
            NetworkRuleAction::Alter => DdlAction::Alter,
            NetworkRuleAction::Drop => DdlAction::Drop,
        },
        object_kind: ObjectKind::NetworkRule,
        target: plan.target.as_ref().map(|t| ObjectRef {
            kind: ObjectKind::NetworkRule,
            name: parse_table_ref(t.span, source),
        }),
        options: DdlOptions {
            or_replace: plan.options.or_replace,
            if_exists: plan.options.if_exists,
            if_not_exists: plan.options.if_not_exists,
            ..DdlOptions::default()
        },
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: None,
        database: None,
        warehouse: None,
        stream: None,
        schema: None,
        function: None,
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: None,
        session: None,
        share: None,
        secret: None,
        network_rule: Some(network_rule),
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: None,
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

// ---------------------------------------------------------------------------
// Resource-monitor projection.
// ---------------------------------------------------------------------------

/// Build a public `StatementFacts` directly from a lowered
/// [`ResourceMonitorPlan`].
pub fn derive_facts_from_resource_monitor_plan(
    plan: &ResourceMonitorPlan,
    source: &str,
) -> StatementFacts {
    let kind = match plan.action {
        ResourceMonitorAction::Create => StatementKind::CreateResourceMonitor,
        ResourceMonitorAction::Alter => StatementKind::AlterResourceMonitor,
        ResourceMonitorAction::Drop => StatementKind::DropResourceMonitor,
    };
    // SUSPEND / SUSPEND_IMMEDIATE are the actions that structurally halt
    // compute; a CREATE without one of them defines no automatic cap.
    let has_suspend = plan
        .triggers
        .iter()
        .any(|t| matches!(t.action.as_str(), "SUSPEND" | "SUSPEND_IMMEDIATE"));
    let no_suspend_trigger = matches!(plan.action, ResourceMonitorAction::Create) && !has_suspend;
    let resource_monitor = ResourceMonitorFacts {
        credit_quota_set: plan.credit_quota_set,
        frequency: plan.frequency.clone(),
        notify_users: plan.notify_users.clone(),
        triggers: plan
            .triggers
            .iter()
            .map(|t| ResourceMonitorTriggerFacts {
                threshold: t.threshold.clone(),
                action: t.action.clone(),
            })
            .collect(),
        triggers_changed: plan.triggers_present,
        no_suspend_trigger,
    };
    let ddl = DdlFacts {
        targets: Vec::new(),
        action: match plan.action {
            ResourceMonitorAction::Create => DdlAction::Create,
            ResourceMonitorAction::Alter => DdlAction::Alter,
            ResourceMonitorAction::Drop => DdlAction::Drop,
        },
        object_kind: ObjectKind::ResourceMonitor,
        target: plan.target.as_ref().map(|t| ObjectRef {
            kind: ObjectKind::ResourceMonitor,
            name: parse_table_ref(t.span, source),
        }),
        options: DdlOptions {
            or_replace: plan.options.or_replace,
            if_exists: plan.options.if_exists,
            if_not_exists: plan.options.if_not_exists,
            ..DdlOptions::default()
        },
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: None,
        database: None,
        warehouse: None,
        stream: None,
        schema: None,
        function: None,
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: None,
        session: None,
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: Some(resource_monitor),
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: None,
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

// ---------------------------------------------------------------------------
// Compute-pool projection.
// ---------------------------------------------------------------------------

fn project_compute_pool_alter_action(a: ComputePoolAlterActionIr) -> ComputePoolAlterAction {
    use ComputePoolAlterAction as P;
    use ComputePoolAlterActionIr as I;
    match a {
        I::Set => P::Set,
        I::Unset => P::Unset,
        I::Suspend => P::Suspend,
        I::Resume => P::Resume,
        I::StopAll => P::StopAll,
    }
}

/// Build a public `StatementFacts` from a lowered [`ComputePoolPlan`].
pub fn derive_facts_from_compute_pool_plan(plan: &ComputePoolPlan, source: &str) -> StatementFacts {
    let kind = match plan.action {
        ComputePoolAction::Create => StatementKind::CreateComputePool,
        ComputePoolAction::Alter => StatementKind::AlterComputePool,
        ComputePoolAction::Drop => StatementKind::DropComputePool,
    };
    let compute_pool = ComputePoolFacts {
        instance_family: plan.instance_family.clone(),
        auto_resume: plan.auto_resume,
        min_nodes: plan.min_nodes.clone(),
        max_nodes: plan.max_nodes.clone(),
        actions: plan
            .actions
            .iter()
            .copied()
            .map(project_compute_pool_alter_action)
            .collect(),
    };
    let ddl = DdlFacts {
        targets: Vec::new(),
        action: match plan.action {
            ComputePoolAction::Create => DdlAction::Create,
            ComputePoolAction::Alter => DdlAction::Alter,
            ComputePoolAction::Drop => DdlAction::Drop,
        },
        // No `ObjectKind::ComputePool` in the public identity taxonomy yet —
        // use `Generic` and let the typed `compute_pool` projection carry the
        // family identity.
        object_kind: ObjectKind::Generic,
        target: plan.target.as_ref().map(|t| ObjectRef {
            kind: ObjectKind::Generic,
            name: parse_table_ref(t.span, source),
        }),
        options: DdlOptions {
            if_exists: plan.options.if_exists,
            if_not_exists: plan.options.if_not_exists,
            or_replace: plan.options.or_replace,
            ..DdlOptions::default()
        },
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: None,
        database: None,
        warehouse: None,
        stream: None,
        schema: None,
        function: None,
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: None,
        session: None,
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: Some(compute_pool),
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: None,
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

// ---------------------------------------------------------------------------
// Git-repository projection.
// ---------------------------------------------------------------------------

fn project_git_repository_alter_action(a: GitRepositoryAlterActionIr) -> GitRepositoryAlterAction {
    use GitRepositoryAlterAction as P;
    use GitRepositoryAlterActionIr as I;
    match a {
        I::Set => P::Set,
        I::Unset => P::Unset,
        I::Fetch => P::Fetch,
    }
}

/// Build a public `StatementFacts` from a lowered [`GitRepositoryPlan`].
pub fn derive_facts_from_git_repository_plan(
    plan: &GitRepositoryPlan,
    source: &str,
) -> StatementFacts {
    let kind = match plan.action {
        GitRepositoryAction::Create => StatementKind::CreateGitRepository,
        GitRepositoryAction::Alter => StatementKind::AlterGitRepository,
        GitRepositoryAction::Drop => StatementKind::DropGitRepository,
    };
    let git_repository = GitRepositoryFacts {
        api_integration: plan.api_integration.clone(),
        origin: plan.origin.clone(),
        has_git_credentials: plan.has_git_credentials,
        actions: plan
            .actions
            .iter()
            .copied()
            .map(project_git_repository_alter_action)
            .collect(),
    };
    let ddl = DdlFacts {
        targets: Vec::new(),
        action: match plan.action {
            GitRepositoryAction::Create => DdlAction::Create,
            GitRepositoryAction::Alter => DdlAction::Alter,
            GitRepositoryAction::Drop => DdlAction::Drop,
        },
        // No `ObjectKind::GitRepository` in the public taxonomy yet — use
        // `Generic` and let the typed `git_repository` projection carry the
        // family identity.
        object_kind: ObjectKind::Generic,
        target: plan.target.as_ref().map(|t| ObjectRef {
            kind: ObjectKind::Generic,
            name: parse_table_ref(t.span, source),
        }),
        options: DdlOptions {
            or_replace: plan.options.or_replace,
            if_exists: plan.options.if_exists,
            if_not_exists: plan.options.if_not_exists,
            ..DdlOptions::default()
        },
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: None,
        database: None,
        warehouse: None,
        stream: None,
        schema: None,
        function: None,
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: None,
        session: None,
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: Some(git_repository),
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: None,
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

// ---------------------------------------------------------------------------
// External-function projection.
// ---------------------------------------------------------------------------

/// Build a public [`StatementFacts`] from a lowered [`ExternalFunctionPlan`](crate::ir::external_function_plan::ExternalFunctionPlan).
/// Recognition only — which endpoints are trusted, and at what severity, is YAML.
pub fn derive_facts_from_external_function_plan(
    plan: &crate::ir::ExternalFunctionPlan,
    source: &str,
) -> StatementFacts {
    let external_function = crate::facts::ddl::ExternalFunctionFacts {
        api_integration: plan.api_integration.clone(),
        endpoint_url: plan.endpoint_url.clone(),
        endpoint_scheme: plan.endpoint_scheme.clone(),
        secure: plan.secure,
        has_headers: plan.has_headers,
        has_context_headers: plan.has_context_headers,
        request_translator: plan.request_translator.clone(),
        response_translator: plan.response_translator.clone(),
    };
    let ddl = DdlFacts {
        targets: Vec::new(),
        action: DdlAction::Create,
        object_kind: ObjectKind::Function,
        target: plan.target.as_ref().map(|t| ObjectRef {
            kind: ObjectKind::Function,
            name: parse_table_ref(t.span, source),
        }),
        options: DdlOptions {
            or_replace: plan.or_replace,
            ..DdlOptions::default()
        },
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: None,
        database: None,
        warehouse: None,
        stream: None,
        schema: None,
        function: None,
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: None,
        session: None,
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: None,
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: Some(external_function),
        trigger_body: None,
    };
    let mut facts = derive_facts_stmt_kind_only(StatementKind::CreateExternalFunction, plan.span);
    facts.ddl = Some(ddl);
    facts
}

// ---------------------------------------------------------------------------
// Image-repository projection.
// ---------------------------------------------------------------------------

fn project_image_repository_alter_action(
    a: ImageRepositoryAlterActionIr,
) -> ImageRepositoryAlterAction {
    use ImageRepositoryAlterAction as P;
    use ImageRepositoryAlterActionIr as I;
    match a {
        I::Set => P::Set,
        I::Unset => P::Unset,
    }
}

/// Build a public `StatementFacts` from a lowered [`ImageRepositoryPlan`].
pub fn derive_facts_from_image_repository_plan(
    plan: &ImageRepositoryPlan,
    source: &str,
) -> StatementFacts {
    let kind = match plan.action {
        ImageRepositoryAction::Create => StatementKind::CreateImageRepository,
        ImageRepositoryAction::Alter => StatementKind::AlterImageRepository,
        ImageRepositoryAction::Drop => StatementKind::DropImageRepository,
    };
    let image_repository = ImageRepositoryFacts {
        actions: plan
            .actions
            .iter()
            .copied()
            .map(project_image_repository_alter_action)
            .collect(),
    };
    let ddl = DdlFacts {
        targets: Vec::new(),
        action: match plan.action {
            ImageRepositoryAction::Create => DdlAction::Create,
            ImageRepositoryAction::Alter => DdlAction::Alter,
            ImageRepositoryAction::Drop => DdlAction::Drop,
        },
        // No `ObjectKind::ImageRepository` in the public taxonomy yet — use
        // `Generic` and let the typed `image_repository` projection carry the
        // family identity.
        object_kind: ObjectKind::Generic,
        target: plan.target.as_ref().map(|t| ObjectRef {
            kind: ObjectKind::Generic,
            name: parse_table_ref(t.span, source),
        }),
        options: DdlOptions {
            or_replace: plan.options.or_replace,
            if_exists: plan.options.if_exists,
            if_not_exists: plan.options.if_not_exists,
            ..DdlOptions::default()
        },
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: None,
        database: None,
        warehouse: None,
        stream: None,
        schema: None,
        function: None,
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: None,
        session: None,
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: Some(image_repository),
        streamlit: None,
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: None,
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

// ---------------------------------------------------------------------------
// Streamlit projection.
// ---------------------------------------------------------------------------

fn project_streamlit_alter_action(a: StreamlitAlterActionIr) -> StreamlitAlterAction {
    use StreamlitAlterAction as P;
    use StreamlitAlterActionIr as I;
    match a {
        I::Set => P::Set,
        I::Unset => P::Unset,
    }
}

/// Build a public `StatementFacts` from a lowered [`StreamlitPlan`].
pub fn derive_facts_from_streamlit_plan(plan: &StreamlitPlan, source: &str) -> StatementFacts {
    let kind = match plan.action {
        StreamlitAction::Create => StatementKind::CreateStreamlit,
        StreamlitAction::Alter => StatementKind::AlterStreamlit,
        StreamlitAction::Drop => StatementKind::DropStreamlit,
    };
    let streamlit = StreamlitFacts {
        has_external_access_integrations: plan.has_external_access_integrations,
        actions: plan
            .actions
            .iter()
            .copied()
            .map(project_streamlit_alter_action)
            .collect(),
    };
    let ddl = DdlFacts {
        targets: Vec::new(),
        action: match plan.action {
            StreamlitAction::Create => DdlAction::Create,
            StreamlitAction::Alter => DdlAction::Alter,
            StreamlitAction::Drop => DdlAction::Drop,
        },
        // No `ObjectKind::Streamlit` in the public taxonomy yet — use `Generic`
        // and let the typed `streamlit` projection carry the family identity.
        object_kind: ObjectKind::Generic,
        target: plan.target.as_ref().map(|t| ObjectRef {
            kind: ObjectKind::Generic,
            name: parse_table_ref(t.span, source),
        }),
        options: DdlOptions {
            or_replace: plan.options.or_replace,
            if_exists: plan.options.if_exists,
            if_not_exists: plan.options.if_not_exists,
            ..DdlOptions::default()
        },
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: None,
        database: None,
        warehouse: None,
        stream: None,
        schema: None,
        function: None,
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: None,
        session: None,
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: Some(streamlit),
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: None,
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

// ---------------------------------------------------------------------------
// Service projection.
// ---------------------------------------------------------------------------

fn project_service_alter_action(a: ServiceAlterActionIr) -> ServiceAlterAction {
    use ServiceAlterAction as P;
    use ServiceAlterActionIr as I;
    match a {
        I::Set => P::Set,
        I::Unset => P::Unset,
        I::Resume => P::Resume,
        I::Suspend => P::Suspend,
    }
}

/// Build a public `StatementFacts` from a lowered [`ServicePlan`].
pub fn derive_facts_from_service_plan(plan: &ServicePlan, source: &str) -> StatementFacts {
    let kind = match plan.action {
        ServiceAction::Create => StatementKind::CreateService,
        ServiceAction::Alter => StatementKind::AlterService,
        ServiceAction::Drop => StatementKind::DropService,
    };
    let service = ServiceFacts {
        in_compute_pool: plan.in_compute_pool.clone(),
        has_external_access_integrations: plan.has_external_access_integrations,
        actions: plan
            .actions
            .iter()
            .copied()
            .map(project_service_alter_action)
            .collect(),
    };
    let ddl = DdlFacts {
        targets: Vec::new(),
        action: match plan.action {
            ServiceAction::Create => DdlAction::Create,
            ServiceAction::Alter => DdlAction::Alter,
            ServiceAction::Drop => DdlAction::Drop,
        },
        // No `ObjectKind::Service` in the public taxonomy yet — use `Generic`
        // and let the typed `service` projection carry the family identity.
        object_kind: ObjectKind::Generic,
        target: plan.target.as_ref().map(|t| ObjectRef {
            kind: ObjectKind::Generic,
            name: parse_table_ref(t.span, source),
        }),
        options: DdlOptions {
            or_replace: plan.options.or_replace,
            if_exists: plan.options.if_exists,
            if_not_exists: plan.options.if_not_exists,
            ..DdlOptions::default()
        },
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: None,
        database: None,
        warehouse: None,
        stream: None,
        schema: None,
        function: None,
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: None,
        session: None,
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: Some(service),
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: None,
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

// ---------------------------------------------------------------------------
// Notebook projection.
// ---------------------------------------------------------------------------

fn project_notebook_alter_action(a: NotebookAlterActionIr) -> NotebookAlterAction {
    use NotebookAlterAction as P;
    use NotebookAlterActionIr as I;
    match a {
        I::Set => P::Set,
        I::Unset => P::Unset,
    }
}

/// Build a public `StatementFacts` from a lowered [`NotebookPlan`].
pub fn derive_facts_from_notebook_plan(plan: &NotebookPlan, source: &str) -> StatementFacts {
    let kind = match plan.action {
        NotebookAction::Create => StatementKind::CreateNotebook,
        NotebookAction::Alter => StatementKind::AlterNotebook,
        NotebookAction::Drop => StatementKind::DropNotebook,
    };
    let notebook = NotebookFacts {
        has_external_access_integrations: plan.has_external_access_integrations,
        actions: plan
            .actions
            .iter()
            .copied()
            .map(project_notebook_alter_action)
            .collect(),
    };
    let ddl = DdlFacts {
        targets: Vec::new(),
        action: match plan.action {
            NotebookAction::Create => DdlAction::Create,
            NotebookAction::Alter => DdlAction::Alter,
            NotebookAction::Drop => DdlAction::Drop,
        },
        // No `ObjectKind::Notebook` in the public taxonomy yet — use `Generic`
        // and let the typed `notebook` projection carry the family identity.
        object_kind: ObjectKind::Generic,
        target: plan.target.as_ref().map(|t| ObjectRef {
            kind: ObjectKind::Generic,
            name: parse_table_ref(t.span, source),
        }),
        options: DdlOptions {
            or_replace: plan.options.or_replace,
            if_exists: plan.options.if_exists,
            if_not_exists: plan.options.if_not_exists,
            ..DdlOptions::default()
        },
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: None,
        database: None,
        warehouse: None,
        stream: None,
        schema: None,
        function: None,
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: None,
        session: None,
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: Some(notebook),
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: None,
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

fn project_semantic_view_alter_action(a: SemanticViewAlterActionIr) -> SemanticViewAlterAction {
    use SemanticViewAlterAction as P;
    use SemanticViewAlterActionIr as I;
    match a {
        I::Set => P::Set,
        I::Unset => P::Unset,
        I::Rename => P::Rename,
    }
}

/// Build a public `StatementFacts` from a lowered [`SemanticViewPlan`].
pub fn derive_facts_from_semantic_view_plan(
    plan: &SemanticViewPlan,
    source: &str,
) -> StatementFacts {
    let kind = match plan.action {
        SemanticViewAction::Create => StatementKind::CreateSemanticView,
        SemanticViewAction::Alter => StatementKind::AlterSemanticView,
        SemanticViewAction::Drop => StatementKind::DropSemanticView,
    };
    let semantic_view = SemanticViewFacts {
        base_tables: plan
            .base_tables
            .iter()
            .map(|t| qualified_name_to_table_ref(&t.name, Some(t.span)))
            .collect(),
        has_relationships: plan.has_relationships,
        has_facts: plan.has_facts,
        has_dimensions: plan.has_dimensions,
        has_metrics: plan.has_metrics,
        actions: plan
            .actions
            .iter()
            .copied()
            .map(project_semantic_view_alter_action)
            .collect(),
    };
    let ddl = DdlFacts {
        targets: Vec::new(),
        action: match plan.action {
            SemanticViewAction::Create => DdlAction::Create,
            SemanticViewAction::Alter => DdlAction::Alter,
            SemanticViewAction::Drop => DdlAction::Drop,
        },
        // No `ObjectKind::SemanticView` in the public taxonomy yet — use
        // `Generic` and let the typed `semantic_view` projection carry identity.
        object_kind: ObjectKind::Generic,
        target: plan.target.as_ref().map(|t| ObjectRef {
            kind: ObjectKind::Generic,
            name: parse_table_ref(t.span, source),
        }),
        options: DdlOptions {
            or_replace: plan.options.or_replace,
            if_exists: plan.options.if_exists,
            if_not_exists: plan.options.if_not_exists,
            ..DdlOptions::default()
        },
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: None,
        database: None,
        warehouse: None,
        stream: None,
        schema: None,
        function: None,
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: None,
        session: None,
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: Some(semantic_view),
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: None,
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

fn project_cortex_search_service_alter_action(
    a: CortexSearchServiceAlterActionIr,
) -> CortexSearchServiceAlterAction {
    use CortexSearchServiceAlterAction as P;
    use CortexSearchServiceAlterActionIr as I;
    match a {
        I::Set => P::Set,
        I::Unset => P::Unset,
        I::Resume => P::Resume,
        I::Suspend => P::Suspend,
    }
}

/// Build a public `StatementFacts` from a lowered [`CortexSearchServicePlan`].
pub fn derive_facts_from_cortex_search_service_plan(
    plan: &CortexSearchServicePlan,
    source: &str,
) -> StatementFacts {
    let kind = match plan.action {
        CortexSearchServiceAction::Create => StatementKind::CreateCortexSearchService,
        CortexSearchServiceAction::Alter => StatementKind::AlterCortexSearchService,
        CortexSearchServiceAction::Drop => StatementKind::DropCortexSearchService,
    };
    let cortex = CortexSearchServiceFacts {
        embedding_model: plan.embedding_model.clone(),
        has_source_query: plan.has_source_query,
        actions: plan
            .actions
            .iter()
            .copied()
            .map(project_cortex_search_service_alter_action)
            .collect(),
    };
    let ddl = DdlFacts {
        targets: Vec::new(),
        action: match plan.action {
            CortexSearchServiceAction::Create => DdlAction::Create,
            CortexSearchServiceAction::Alter => DdlAction::Alter,
            CortexSearchServiceAction::Drop => DdlAction::Drop,
        },
        // No `ObjectKind::CortexSearchService` in the public taxonomy yet — use
        // `Generic` and let the typed `cortex_search_service` projection carry
        // identity.
        object_kind: ObjectKind::Generic,
        target: plan.target.as_ref().map(|t| ObjectRef {
            kind: ObjectKind::Generic,
            name: parse_table_ref(t.span, source),
        }),
        options: DdlOptions {
            or_replace: plan.options.or_replace,
            if_exists: plan.options.if_exists,
            if_not_exists: plan.options.if_not_exists,
            ..DdlOptions::default()
        },
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: None,
        database: None,
        warehouse: None,
        stream: None,
        schema: None,
        function: None,
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: None,
        session: None,
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: Some(cortex),
        application: None,
        application_package: None,
        listing: None,
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

fn project_application_alter_action(a: ApplicationAlterActionIr) -> ApplicationAlterAction {
    use ApplicationAlterAction as P;
    use ApplicationAlterActionIr as I;
    match a {
        I::Set => P::Set,
        I::Unset => P::Unset,
        I::Other => P::Other,
    }
}

/// Build a public `StatementFacts` from a lowered [`ApplicationPlan`].
pub fn derive_facts_from_application_plan(plan: &ApplicationPlan, source: &str) -> StatementFacts {
    let kind = match plan.action {
        ApplicationAction::Create => StatementKind::CreateApplication,
        ApplicationAction::Alter => StatementKind::AlterApplication,
        ApplicationAction::Drop => StatementKind::DropApplication,
    };
    let application = ApplicationFacts {
        from_listing: plan.from_listing,
        source_name: plan.source_name.clone(),
        debug_mode: plan.debug_mode,
        actions: plan
            .actions
            .iter()
            .copied()
            .map(project_application_alter_action)
            .collect(),
    };
    let ddl = DdlFacts {
        targets: Vec::new(),
        action: match plan.action {
            ApplicationAction::Create => DdlAction::Create,
            ApplicationAction::Alter => DdlAction::Alter,
            ApplicationAction::Drop => DdlAction::Drop,
        },
        object_kind: ObjectKind::Generic,
        target: plan.target.as_ref().map(|t| ObjectRef {
            kind: ObjectKind::Generic,
            name: parse_table_ref(t.span, source),
        }),
        options: DdlOptions {
            or_replace: plan.options.or_replace,
            if_exists: plan.options.if_exists,
            if_not_exists: plan.options.if_not_exists,
            ..DdlOptions::default()
        },
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: None,
        database: None,
        warehouse: None,
        stream: None,
        schema: None,
        function: None,
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: None,
        session: None,
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: Some(application),
        application_package: None,
        listing: None,
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

/// Build a public `StatementFacts` from a lowered [`ApplicationPackagePlan`].
pub fn derive_facts_from_application_package_plan(
    plan: &ApplicationPackagePlan,
    source: &str,
) -> StatementFacts {
    let kind = match plan.action {
        ApplicationAction::Create => StatementKind::CreateApplicationPackage,
        ApplicationAction::Alter => StatementKind::AlterApplicationPackage,
        ApplicationAction::Drop => StatementKind::DropApplicationPackage,
    };
    let application_package = ApplicationPackageFacts {
        distribution: plan.distribution.clone(),
        actions: plan
            .actions
            .iter()
            .copied()
            .map(project_application_alter_action)
            .collect(),
    };
    let ddl = DdlFacts {
        targets: Vec::new(),
        action: match plan.action {
            ApplicationAction::Create => DdlAction::Create,
            ApplicationAction::Alter => DdlAction::Alter,
            ApplicationAction::Drop => DdlAction::Drop,
        },
        object_kind: ObjectKind::Generic,
        target: plan.target.as_ref().map(|t| ObjectRef {
            kind: ObjectKind::Generic,
            name: parse_table_ref(t.span, source),
        }),
        options: DdlOptions {
            or_replace: plan.options.or_replace,
            if_exists: plan.options.if_exists,
            if_not_exists: plan.options.if_not_exists,
            ..DdlOptions::default()
        },
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: None,
        database: None,
        warehouse: None,
        stream: None,
        schema: None,
        function: None,
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: None,
        session: None,
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: Some(application_package),
        listing: None,
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

fn project_listing_alter_action(a: ListingAlterActionIr) -> ListingAlterAction {
    use ListingAlterAction as P;
    use ListingAlterActionIr as I;
    match a {
        I::Set => P::Set,
        I::Unset => P::Unset,
        I::Other => P::Other,
    }
}

/// Build a public `StatementFacts` from a lowered [`ListingPlan`].
pub fn derive_facts_from_listing_plan(plan: &ListingPlan, source: &str) -> StatementFacts {
    let kind = match plan.action {
        ListingAction::Create => StatementKind::CreateListing,
        ListingAction::Alter => StatementKind::AlterListing,
        ListingAction::Drop => StatementKind::DropListing,
    };
    let listing = ListingFacts {
        is_external: plan.is_external,
        publish: plan.publish,
        shared_object: plan.shared_object.clone(),
        actions: plan
            .actions
            .iter()
            .copied()
            .map(project_listing_alter_action)
            .collect(),
    };
    let ddl = DdlFacts {
        targets: Vec::new(),
        action: match plan.action {
            ListingAction::Create => DdlAction::Create,
            ListingAction::Alter => DdlAction::Alter,
            ListingAction::Drop => DdlAction::Drop,
        },
        object_kind: ObjectKind::Generic,
        target: plan.target.as_ref().map(|t| ObjectRef {
            kind: ObjectKind::Generic,
            name: parse_table_ref(t.span, source),
        }),
        options: DdlOptions {
            or_replace: plan.options.or_replace,
            if_exists: plan.options.if_exists,
            if_not_exists: plan.options.if_not_exists,
            ..DdlOptions::default()
        },
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: None,
        database: None,
        warehouse: None,
        stream: None,
        schema: None,
        function: None,
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: None,
        session: None,
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: Some(listing),
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

/// Build a public `StatementFacts` from a lowered [`ManagedAccountPlan`]. The
/// account's admin credentials are deliberately not carried (least-leak).
pub fn derive_facts_from_managed_account_plan(
    plan: &ManagedAccountPlan,
    source: &str,
) -> StatementFacts {
    let kind = match plan.action {
        AccountProvisioningAction::Create => StatementKind::CreateManagedAccount,
        AccountProvisioningAction::Drop => StatementKind::DropManagedAccount,
    };
    let managed_account = ManagedAccountFacts {
        account_type: plan.account_type.clone(),
    };
    let ddl = account_provisioning_ddl(
        plan.action,
        plan.target.as_ref(),
        &plan.options,
        Some(managed_account),
        source,
    );
    statement_facts_with_ddl(kind, plan.span, Some(ddl))
}

/// Build a public `StatementFacts` from a lowered [`OrgAccountPlan`] (org-level
/// CREATE / DROP ACCOUNT). Recognition only; credentials are not carried.
pub fn derive_facts_from_org_account_plan(plan: &OrgAccountPlan, source: &str) -> StatementFacts {
    let kind = match plan.action {
        AccountProvisioningAction::Create => StatementKind::CreateAccount,
        AccountProvisioningAction::Drop => StatementKind::DropAccount,
    };
    let ddl = account_provisioning_ddl(
        plan.action,
        plan.target.as_ref(),
        &plan.options,
        None,
        source,
    );
    statement_facts_with_ddl(kind, plan.span, Some(ddl))
}

/// Build a public `StatementFacts` from a lowered [`StageFileCommandPlan`]:
/// the stage a `PUT`, `GET`, `REMOVE` or `LIST` names as `ddl.target`, and
/// the path within it as `ddl.stage.path`. `PUT` and `GET` move files in
/// and out (`bulk_load`, as `COPY` does), `REMOVE` deletes files and keeps
/// the stage (`truncate`), `LIST` reads its listing (`configure`, as `SHOW`
/// does).
pub fn derive_facts_from_stage_file_command_plan(
    plan: &StageFileCommandPlan,
    source: &str,
) -> StatementFacts {
    let (kind, action) = match plan.operation {
        StageFileOperation::Put => (StatementKind::StagePut, DdlAction::BulkLoad),
        StageFileOperation::Get => (StatementKind::StageGet, DdlAction::BulkLoad),
        StageFileOperation::Remove => (StatementKind::StageRemove, DdlAction::Truncate),
        StageFileOperation::List => (StatementKind::StageList, DdlAction::Configure),
    };
    let target = plan.target.as_ref().map(|t| ObjectRef {
        kind: ObjectKind::Stage,
        name: ddl_target_name(t),
    });
    let mut ddl = DdlFacts::bare(action, ObjectKind::Stage, target);
    ddl.stage = Some(StageDdlFacts {
        path: plan.path.and_then(|span| {
            source
                .get(span.start as usize..span.end as usize)
                .map(|text| super::identity::WrittenText::at(text.to_string(), span))
        }),
        ..StageDdlFacts::default()
    });
    statement_facts_with_ddl(kind, plan.span, Some(ddl))
}

/// Shared DdlFacts builder for account-provisioning statements.
fn account_provisioning_ddl(
    action: AccountProvisioningAction,
    target: Option<&crate::ir::AccountProvisioningTarget>,
    options: &crate::ir::AccountProvisioningOptions,
    managed_account: Option<ManagedAccountFacts>,
    source: &str,
) -> DdlFacts {
    DdlFacts {
        targets: Vec::new(),
        action: match action {
            AccountProvisioningAction::Create => DdlAction::Create,
            AccountProvisioningAction::Drop => DdlAction::Drop,
        },
        object_kind: ObjectKind::Generic,
        target: target.map(|t| ObjectRef {
            kind: ObjectKind::Generic,
            name: parse_table_ref(t.span, source),
        }),
        options: DdlOptions {
            or_replace: options.or_replace,
            if_exists: options.if_exists,
            if_not_exists: options.if_not_exists,
            ..DdlOptions::default()
        },
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: None,
        database: None,
        warehouse: None,
        stream: None,
        schema: None,
        function: None,
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: None,
        session: None,
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: None,
        managed_account,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    }
}

/// Wrap a `DdlFacts` into a `StatementFacts` for a DDL-only statement.
fn statement_facts_with_ddl(
    kind: StatementKind,
    span: Span,
    ddl: Option<DdlFacts>,
) -> StatementFacts {
    StatementFacts {
        declare: None,
        call: None,
        kind,
        source_span: Some(span),
        query: None,
        ddl,
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

// ---------------------------------------------------------------------------
// Secret projection.
// ---------------------------------------------------------------------------

/// Build a public `StatementFacts` directly from a lowered
/// [`SecretPlan`]. Secret values are never carried (see the plan's
/// least-leak invariant).
pub fn derive_facts_from_secret_plan(plan: &SecretPlan, source: &str) -> StatementFacts {
    let kind = match plan.action {
        SecretAction::Create => StatementKind::CreateSecret,
        SecretAction::Alter => StatementKind::AlterSecret,
        SecretAction::Drop => StatementKind::DropSecret,
    };
    let secret = SecretFacts {
        secret_type: plan.secret_type.clone(),
        api_authentication: plan.api_authentication.clone(),
        enabled: plan.enabled,
        properties_set: plan.set_property_names.clone(),
        properties_unset: plan.unset_property_names.clone(),
    };
    let ddl = DdlFacts {
        targets: Vec::new(),
        action: match plan.action {
            SecretAction::Create => DdlAction::Create,
            SecretAction::Alter => DdlAction::Alter,
            SecretAction::Drop => DdlAction::Drop,
        },
        object_kind: ObjectKind::Secret,
        target: plan.target.as_ref().map(|t| ObjectRef {
            kind: ObjectKind::Secret,
            name: parse_table_ref(t.span, source),
        }),
        options: DdlOptions {
            or_replace: plan.options.or_replace,
            if_exists: plan.options.if_exists,
            if_not_exists: plan.options.if_not_exists,
            ..DdlOptions::default()
        },
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: None,
        database: None,
        warehouse: None,
        stream: None,
        schema: None,
        function: None,
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: None,
        session: None,
        share: None,
        secret: Some(secret),
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: None,
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

// ---------------------------------------------------------------------------
// Share projection.
// ---------------------------------------------------------------------------

/// Build a public `StatementFacts` directly from a lowered
/// [`SharePlan`]. Catalog is not consulted — the typed plan already
/// carries the required structural data.
pub fn derive_facts_from_share_plan(plan: &SharePlan, source: &str) -> StatementFacts {
    let kind = match plan.action {
        ShareAction::Create => StatementKind::CreateShare,
        ShareAction::Alter => StatementKind::AlterShare,
        ShareAction::Drop => StatementKind::DropShare,
    };
    let share = ShareFacts {
        accounts_added: plan.accounts_added.clone(),
        accounts_removed: plan.accounts_removed.clone(),
        accounts_set: plan.accounts_set.clone(),
        had_set_properties: plan.had_set_properties,
        had_unset_properties: plan.had_unset_properties,
        has_unknown_clauses: plan.has_unknown_clauses,
    };
    let ddl = DdlFacts {
        targets: Vec::new(),
        action: match plan.action {
            ShareAction::Create => DdlAction::Create,
            ShareAction::Alter => DdlAction::Alter,
            ShareAction::Drop => DdlAction::Drop,
        },
        object_kind: ObjectKind::Share,
        target: plan.target.as_ref().map(|t| ObjectRef {
            kind: ObjectKind::Share,
            name: parse_table_ref(t.span, source),
        }),
        options: DdlOptions {
            or_replace: plan.options.or_replace,
            if_exists: plan.options.if_exists,
            if_not_exists: plan.options.if_not_exists,
            ..DdlOptions::default()
        },
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: None,
        database: None,
        warehouse: None,
        stream: None,
        schema: None,
        function: None,
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: None,
        session: None,
        share: Some(share),
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: None,
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

// ---------------------------------------------------------------------------
// Tag projection.
// ---------------------------------------------------------------------------

/// Build a public `StatementFacts` directly from a lowered
/// [`TagPlan`]. Catalog is not consulted — the typed plan already
/// carries the required structural data.
pub fn derive_facts_from_tag_plan(plan: &TagPlan, _source: &str) -> StatementFacts {
    project_tag_statement(plan)
}

fn project_tag_statement(plan: &TagPlan) -> StatementFacts {
    let kind = match plan.action {
        TagAction::Create => StatementKind::CreateTag,
        TagAction::Alter => StatementKind::AlterTag,
        TagAction::Drop => StatementKind::DropTag,
        TagAction::Undrop => StatementKind::UndropTag,
    };

    let to_policy_refs = |policies: &[TagPolicyRefIr]| -> Vec<ObjectRef> {
        policies
            .iter()
            .map(|p| ObjectRef {
                kind: ObjectKind::MaskingPolicy,
                name: qualified_name_to_table_ref(&p.name, Some(p.span)),
            })
            .collect()
    };

    let mut tag = TagFacts::default();
    for action in &plan.alter_actions {
        match action {
            TagAlterActionIr::RenameTo { new_name } => {
                tag.renamed_to = Some(ObjectRef {
                    kind: ObjectKind::Tag,
                    name: qualified_name_to_table_ref(new_name, None),
                });
            }
            TagAlterActionIr::SetAllowedValues { values }
            | TagAlterActionIr::AddAllowedValues { values } => {
                tag.allowed_values.extend(values.iter().cloned());
            }
            TagAlterActionIr::DropAllowedValues { values } => {
                tag.allowed_values_removed.extend(values.iter().cloned());
            }
            TagAlterActionIr::UnsetAllowedValues => tag.allowed_values_unset = true,
            TagAlterActionIr::SetPropagate { mode } => tag.propagate = Some(mode.clone()),
            TagAlterActionIr::UnsetPropagate => tag.propagate_unset = true,
            TagAlterActionIr::SetMaskingPolicies { policies, force } => {
                tag.masking_policies_set.extend(to_policy_refs(policies));
                tag.masking_policy_force |= *force;
            }
            TagAlterActionIr::UnsetMaskingPolicies { policies } => {
                tag.masking_policies_unset.extend(to_policy_refs(policies));
            }
            TagAlterActionIr::SetOnConflict
            | TagAlterActionIr::UnsetOnConflict
            | TagAlterActionIr::SetComment
            | TagAlterActionIr::UnsetComment
            | TagAlterActionIr::UnsetDcmProject => {}
        }
    }

    let ddl = DdlFacts {
        targets: Vec::new(),
        action: match plan.action {
            TagAction::Create | TagAction::Undrop => DdlAction::Create,
            TagAction::Alter => DdlAction::Alter,
            TagAction::Drop => DdlAction::Drop,
        },
        object_kind: ObjectKind::Tag,
        target: plan.target.as_ref().map(|t| ObjectRef {
            kind: ObjectKind::Tag,
            name: TableRef::new(
                IdentName::new(t.name.clone()),
                t.schema.clone().map(IdentName::new),
                t.db.clone().map(IdentName::new),
                Some(t.span),
            ),
        }),
        options: DdlOptions {
            or_replace: plan.options.or_replace,
            if_exists: plan.options.if_exists,
            if_not_exists: plan.options.if_not_exists,
            ..DdlOptions::default()
        },
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: None,
        database: None,
        warehouse: None,
        stream: None,
        schema: None,
        function: None,
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: Some(tag),
        file_format: None,
        session: None,
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: None,
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

// ---------------------------------------------------------------------------
// File format projection (CREATE / ALTER / DROP FILE FORMAT).
// ---------------------------------------------------------------------------

/// Build a public `StatementFacts` from a lowered [`FileFormatPlan`].
pub fn derive_facts_from_file_format_plan(plan: &FileFormatPlan, _source: &str) -> StatementFacts {
    project_file_format_statement(plan)
}

fn project_file_format_statement(plan: &FileFormatPlan) -> StatementFacts {
    let kind = match plan.action {
        FileFormatAction::Create => StatementKind::CreateFileFormat,
        FileFormatAction::Alter => StatementKind::AlterFileFormat,
        FileFormatAction::Drop => StatementKind::DropFileFormat,
    };

    let file_format = FileFormatFacts {
        format_type: plan.format_type.clone(),
        renamed_to: plan.renamed_to.as_ref().map(|name| ObjectRef {
            kind: ObjectKind::FileFormat,
            name: qualified_name_to_table_ref(name, None),
        }),
        temporary: plan.options.temporary,
    };

    let ddl = DdlFacts {
        targets: Vec::new(),
        action: match plan.action {
            FileFormatAction::Create => DdlAction::Create,
            FileFormatAction::Alter => DdlAction::Alter,
            FileFormatAction::Drop => DdlAction::Drop,
        },
        object_kind: ObjectKind::FileFormat,
        target: plan.target.as_ref().map(|t| ObjectRef {
            kind: ObjectKind::FileFormat,
            name: TableRef::new(
                IdentName::new(t.name.clone()),
                t.schema.clone().map(IdentName::new),
                t.db.clone().map(IdentName::new),
                Some(t.span),
            ),
        }),
        options: DdlOptions {
            or_replace: plan.options.or_replace,
            if_exists: plan.options.if_exists,
            if_not_exists: plan.options.if_not_exists,
            ..DdlOptions::default()
        },
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: None,
        database: None,
        warehouse: None,
        stream: None,
        schema: None,
        function: None,
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: Some(file_format),
        session: None,
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: None,
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

// ---------------------------------------------------------------------------
// Session projection (ALTER SESSION SET/UNSET).
// ---------------------------------------------------------------------------

/// Build a public `StatementFacts` from a lowered [`SessionPlan`]. The typed
/// plan already carries resolved parameter names and values.
pub fn derive_facts_from_session_plan(plan: &SessionPlan, _source: &str) -> StatementFacts {
    project_session_statement(plan)
}

fn project_session_statement(plan: &SessionPlan) -> StatementFacts {
    let session = match &plan.action {
        SessionAction::Set { params } => SessionFacts {
            set_params: params
                .iter()
                .map(|p| SessionParam {
                    name: p.name.clone(),
                    value: p.value.clone(),
                    value_kind: p.value_kind,
                })
                .collect(),
            unset_params: Vec::new(),
        },
        SessionAction::Unset { params } => SessionFacts {
            set_params: Vec::new(),
            unset_params: params.clone(),
        },
    };

    let ddl = DdlFacts {
        targets: Vec::new(),
        action: DdlAction::Alter,
        object_kind: ObjectKind::Session,
        target: None,
        options: DdlOptions::default(),
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: None,
        database: None,
        warehouse: None,
        stream: None,
        schema: None,
        function: None,
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: None,
        session: Some(session),
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: None,
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };

    StatementFacts {
        declare: None,
        call: None,
        kind: StatementKind::AlterSession,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

/// The [`TableRef`] a dotted `[server.]db.schema.name` string names, each
/// part as written: a dot inside quotes separates nothing, and a quoted
/// path is read as its parts where the dialect reads it so (BigQuery).
fn qualified_name_to_table_ref(raw: &str, span: Option<Span>) -> TableRef {
    let parts = crate::ir::lower_ddl::relation_parts_written(raw);
    let mut qualifiers = parts.iter().rev().map(|part| IdentName::new(part.as_str()));
    let name = qualifiers.next().unwrap_or_else(|| IdentName::new(raw));
    let schema = qualifiers.next();
    let database = qualifiers.next();
    let server = qualifiers.next();
    TableRef::new(name, schema, database, span).with_server(server)
}

// ---------------------------------------------------------------------------
// Stream projection.
// ---------------------------------------------------------------------------

/// Build a public `StatementFacts` directly from a lowered
/// [`StreamPlan`]. Catalog is not consulted — the typed plan already
/// carries the required structural data.
pub fn derive_facts_from_stream_plan(plan: &StreamPlan, _source: &str) -> StatementFacts {
    project_stream_statement(plan)
}

fn project_stream_statement(plan: &StreamPlan) -> StatementFacts {
    let kind = match plan.action {
        StreamAction::Create => StatementKind::CreateStream,
        StreamAction::Drop => StatementKind::DropStream,
    };
    let stream = StreamFacts {
        append_only: plan.create_flags.append_only,
        insert_only: plan.create_flags.insert_only,
    };
    let ddl = DdlFacts {
        targets: Vec::new(),
        action: match plan.action {
            StreamAction::Create => DdlAction::Create,
            StreamAction::Drop => DdlAction::Drop,
        },
        object_kind: ObjectKind::Stream,
        target: plan.target.as_ref().map(|t| ObjectRef {
            kind: ObjectKind::Stream,
            name: TableRef::new(
                IdentName::new(t.name.clone()),
                t.schema.clone().map(IdentName::new),
                t.db.clone().map(IdentName::new),
                Some(t.span),
            ),
        }),
        options: DdlOptions {
            or_replace: plan.options.or_replace,
            if_exists: plan.options.if_exists,
            if_not_exists: plan.options.if_not_exists,
            ..DdlOptions::default()
        },
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: None,
        database: None,
        warehouse: None,
        stream: Some(stream),
        schema: None,
        function: None,
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: None,
        session: None,
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: None,
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

// ---------------------------------------------------------------------------
// Datashare projection.
// ---------------------------------------------------------------------------

/// Build a public `StatementFacts` directly from a lowered [`DatasharePlan`].
/// The typed plan already carries the cross-account exposure primitives; the
/// catalog is not consulted. Distinct from the Snowflake SHARE path (which
/// yields `ddl: None`): a datashare surfaces typed `ddl.datashare.*` facts.
pub fn derive_facts_from_datashare_plan(plan: &DatasharePlan, _source: &str) -> StatementFacts {
    project_datashare_statement(plan)
}

fn project_datashare_statement(plan: &DatasharePlan) -> StatementFacts {
    let kind = match plan.action {
        DatashareAction::Create => StatementKind::CreateDatashare,
        DatashareAction::Alter => StatementKind::AlterDatashare,
    };

    let mut added_objects = Vec::new();
    let mut removed_objects = Vec::new();
    for change in &plan.object_changes {
        let object_kind = match change.object_kind {
            IrDatashareObjectKind::Table => DatashareObjectKindFacts::Table,
            IrDatashareObjectKind::Schema => DatashareObjectKindFacts::Schema,
        };
        let name = if change.name.is_empty() {
            None
        } else {
            Some(change.name.clone())
        };
        let obj = DatashareObjectRef { object_kind, name };
        if change.added {
            added_objects.push(obj);
        } else {
            removed_objects.push(obj);
        }
    }

    let datashare = DatashareFacts {
        publicly_accessible: plan.publicly_accessible == Some(true),
        publicly_inaccessible: plan.publicly_accessible == Some(false),
        includenew_set: plan.includenew_set,
        added_objects,
        removed_objects,
        has_unknown_clauses: plan.has_unknown_clauses,
    };

    let ddl = DdlFacts {
        targets: Vec::new(),
        action: match plan.action {
            DatashareAction::Create => DdlAction::Create,
            DatashareAction::Alter => DdlAction::Alter,
        },
        object_kind: ObjectKind::Datashare,
        target: plan.target.as_ref().map(|t| ObjectRef {
            kind: ObjectKind::Datashare,
            name: TableRef::new(
                IdentName::new(t.name.clone()),
                t.schema.clone().map(IdentName::new),
                t.db.clone().map(IdentName::new),
                Some(t.span),
            ),
        }),
        options: DdlOptions {
            or_replace: plan.options.or_replace,
            if_exists: false,
            if_not_exists: plan.options.if_not_exists,
            ..DdlOptions::default()
        },
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: None,
        database: None,
        warehouse: None,
        stream: None,
        schema: None,
        function: None,
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: Some(datashare),
        tag: None,
        file_format: None,
        session: None,
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: None,
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };

    StatementFacts {
        declare: None,
        call: None,
        kind,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

// ---------------------------------------------------------------------------
// Schema projection.
// ---------------------------------------------------------------------------

/// Build a public `StatementFacts` directly from a lowered
/// [`SchemaPlan`]. Catalog is not consulted — the typed plan already
/// carries the required structural data.
pub fn derive_facts_from_schema_plan(plan: &SchemaPlan, _source: &str) -> StatementFacts {
    project_schema_statement(plan)
}

/// Project one `IrSchemaCreateOrigin` onto its public mirror. Single
/// boundary point — the public closed enum is curated in
/// `src/facts/ddl.rs::SchemaCreateOrigin`.
fn project_schema_create_origin(o: IrSchemaCreateOrigin) -> SchemaCreateOrigin {
    use IrSchemaCreateOrigin as I;
    use SchemaCreateOrigin as P;
    match o {
        I::Standard => P::Standard,
        I::Clone => P::Clone,
    }
}

/// Project one `IrSchemaAlterAction` onto its public mirror. Single
/// boundary point — the public closed enum is curated in
/// `src/facts/ddl.rs::SchemaAlterAction`.
fn project_schema_alter_action(a: IrSchemaAlterAction) -> SchemaAlterAction {
    use IrSchemaAlterAction as I;
    use SchemaAlterAction as P;
    match a {
        I::EnableManagedAccess => P::EnableManagedAccess,
        I::DisableManagedAccess => P::DisableManagedAccess,
        I::SwapWith => P::SwapWith,
        I::SetProperties => P::SetProperties,
        I::UnsetProperties => P::UnsetProperties,
        I::SetDbProperties => P::SetDbProperties,
        I::OwnerTo => P::OwnerTo,
        I::PredictiveOptimization => P::PredictiveOptimization,
        I::DefaultCollation => P::DefaultCollation,
        I::RenameTo => P::RenameTo,
        I::SetTag => P::SetTag,
        I::UnsetTag => P::UnsetTag,
        I::SetComment => P::SetComment,
        I::UnsetComment => P::UnsetComment,
        I::SetTags => P::SetTags,
        I::UnsetTags => P::UnsetTags,
        I::Opaque => P::Opaque,
    }
}

fn project_schema_statement(plan: &SchemaPlan) -> StatementFacts {
    let kind = match plan.action {
        SchemaAction::Create => StatementKind::CreateSchema,
        SchemaAction::Alter => StatementKind::AlterSchema,
        SchemaAction::Drop => StatementKind::DropSchema,
    };
    let schema = SchemaFacts {
        managed_access_enabled: plan.managed_access_enabled,
        managed_access_disabled: plan.managed_access_disabled,
        retention_changed: plan.retention_changed,
        data_retention_days: plan.data_retention_days,
        swapped: plan.swapped,
        managed_location_present: plan.managed_location_present,
        location_present: plan.location_present,
        actions: plan
            .actions
            .iter()
            .copied()
            .map(project_schema_alter_action)
            .collect(),
        create_origin: plan.create_origin.map(project_schema_create_origin),
        drops_contents: plan.action == SchemaAction::Drop
            && (plan.options.cascade
                || (!plan.options.restrict
                    && crate::ir::normalize::dialect_in_force().drop_schema_drops_contents())),
    };
    let ddl = DdlFacts {
        targets: Vec::new(),
        action: match plan.action {
            SchemaAction::Create => DdlAction::Create,
            SchemaAction::Alter => DdlAction::Alter,
            SchemaAction::Drop => DdlAction::Drop,
        },
        object_kind: ObjectKind::Schema,
        target: plan.target.as_ref().map(|t| ObjectRef {
            kind: ObjectKind::Schema,
            name: TableRef::new(
                IdentName::new(t.name.clone()),
                t.schema.clone().map(IdentName::new),
                t.db.clone().map(IdentName::new),
                Some(t.span),
            ),
        }),
        options: DdlOptions {
            or_replace: plan.options.or_replace,
            if_exists: plan.options.if_exists,
            if_not_exists: plan.options.if_not_exists,
            cascade: plan.options.cascade,
            restrict: plan.options.restrict,
            ..DdlOptions::default()
        },
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: None,
        database: None,
        warehouse: None,
        stream: None,
        schema: Some(schema),
        function: None,
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: None,
        session: None,
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: None,
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

// ---------------------------------------------------------------------------
// Catalog projection (Databricks Unity Catalog).
// ---------------------------------------------------------------------------

/// Build a public `StatementFacts` directly from a lowered
/// [`CatalogPlan`]. Catalog is not consulted — the typed plan already
/// carries the required structural data (the action discriminator,
/// `foreign` CREATE flag, typed ALTER action list, and `cascade` /
/// `restrict` DROP flags on `DdlOptions`).
pub fn derive_facts_from_catalog_plan(plan: &CatalogPlan, _source: &str) -> StatementFacts {
    project_catalog_statement(plan)
}

/// Project one `IrCatalogAlterAction` onto its public mirror. Single
/// boundary point — the public closed enum is curated in
/// `src/facts/ddl.rs::CatalogAlterAction`. The public type is
/// narrower than the IR: `DefaultCollation` and `Options` collapse
/// into [`CatalogAlterAction::Other`]. Exhaustive — no `_ =>` arm.
fn project_catalog_alter_action(a: IrCatalogAlterAction) -> CatalogAlterAction {
    use CatalogAlterAction as P;
    use IrCatalogAlterAction as I;
    match a {
        I::OwnerTo => P::OwnerTo,
        I::SetTags => P::SetTags,
        I::UnsetTags => P::UnsetTags,
        I::EnablePredictiveOptimization => P::EnablePredictiveOptimization,
        I::DisablePredictiveOptimization => P::DisablePredictiveOptimization,
        I::InheritPredictiveOptimization => P::InheritPredictiveOptimization,
        I::DefaultCollation | I::Options => P::Other,
    }
}

fn project_catalog_statement(plan: &CatalogPlan) -> StatementFacts {
    let kind = match plan.action {
        CatalogAction::Create => StatementKind::CreateCatalog,
        CatalogAction::Alter => StatementKind::AlterCatalog,
        CatalogAction::Drop => StatementKind::DropCatalog,
    };
    let catalog = CatalogFacts {
        foreign: plan.foreign,
        actions: plan
            .actions
            .iter()
            .copied()
            .map(project_catalog_alter_action)
            .collect(),
    };
    let ddl = DdlFacts {
        targets: Vec::new(),
        action: match plan.action {
            CatalogAction::Create => DdlAction::Create,
            CatalogAction::Alter => DdlAction::Alter,
            CatalogAction::Drop => DdlAction::Drop,
        },
        object_kind: ObjectKind::Catalog,
        target: plan.target.as_ref().map(|t| ObjectRef {
            kind: ObjectKind::Catalog,
            name: TableRef::new(
                IdentName::new(t.name.clone()),
                t.schema.clone().map(IdentName::new),
                t.db.clone().map(IdentName::new),
                Some(t.span),
            ),
        }),
        options: DdlOptions {
            if_not_exists: plan.options.if_not_exists,
            if_exists: plan.options.if_exists,
            cascade: plan.options.cascade,
            restrict: plan.options.restrict,
            ..DdlOptions::default()
        },
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: None,
        database: None,
        warehouse: None,
        stream: None,
        schema: None,
        function: None,
        procedure: None,
        table: None,
        catalog: Some(catalog),
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: None,
        session: None,
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: None,
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

// ---------------------------------------------------------------------------
// Volume projection (Databricks Unity Catalog).
// ---------------------------------------------------------------------------

/// Build a public `StatementFacts` directly from a lowered
/// [`VolumePlan`]. Catalog is not consulted — the typed plan already
/// carries the required structural data.
pub fn derive_facts_from_volume_plan(plan: &VolumePlan, _source: &str) -> StatementFacts {
    project_volume_statement(plan)
}

/// Project one `IrVolumeAlterAction` onto its public mirror. Single
/// boundary point — the public closed enum is curated in
/// `src/facts/ddl.rs::VolumeAlterAction`. Exhaustive.
fn project_volume_alter_action(a: IrVolumeAlterAction) -> VolumeAlterAction {
    use IrVolumeAlterAction as I;
    use VolumeAlterAction as P;
    match a {
        I::RenameTo => P::RenameTo,
        I::OwnerTo => P::OwnerTo,
        I::SetTags => P::SetTags,
        I::UnsetTags => P::UnsetTags,
    }
}

fn project_storage_location(loc: &IrStorageLocation) -> StorageLocationFacts {
    StorageLocationFacts {
        provider: loc.provider.clone(),
        has_role_arn: loc.has_role_arn,
        has_external_id: loc.has_external_id,
        encryption_type: loc.encryption_type.clone(),
    }
}

fn project_volume_statement(plan: &VolumePlan) -> StatementFacts {
    let kind = match plan.action {
        VolumeAction::Create => StatementKind::CreateVolume,
        VolumeAction::Alter => StatementKind::AlterVolume,
        VolumeAction::Drop => StatementKind::DropVolume,
    };
    let volume = VolumeFacts {
        is_external: plan.is_external,
        location_present: plan.location_present,
        comment_present: plan.comment_present,
        allow_writes: plan.allow_writes,
        storage_locations: plan
            .storage_locations
            .iter()
            .map(project_storage_location)
            .collect(),
        actions: plan
            .actions
            .iter()
            .copied()
            .map(project_volume_alter_action)
            .collect(),
    };
    let ddl = DdlFacts {
        targets: Vec::new(),
        action: match plan.action {
            VolumeAction::Create => DdlAction::Create,
            VolumeAction::Alter => DdlAction::Alter,
            VolumeAction::Drop => DdlAction::Drop,
        },
        // No `ObjectKind::Volume` exists yet in the public identity
        // taxonomy — use `Generic` and let the typed `volume`
        // projection carry the family identity.
        object_kind: ObjectKind::Generic,
        target: plan.target.as_ref().map(|t| ObjectRef {
            kind: ObjectKind::Generic,
            name: TableRef::new(
                IdentName::new(t.name.clone()),
                t.schema.clone().map(IdentName::new),
                t.catalog.clone().map(IdentName::new),
                Some(t.span),
            ),
        }),
        options: DdlOptions {
            if_not_exists: plan.options.if_not_exists,
            if_exists: plan.options.if_exists,
            or_replace: plan.options.or_replace,
            ..DdlOptions::default()
        },
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: None,
        database: None,
        warehouse: None,
        stream: None,
        schema: None,
        function: None,
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: Some(volume),
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: None,
        session: None,
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: None,
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

// ---------------------------------------------------------------------------
// External-location projection (Databricks Unity Catalog).
// ---------------------------------------------------------------------------

pub fn derive_facts_from_external_location_plan(
    plan: &ExternalLocationPlan,
    source: &str,
) -> StatementFacts {
    project_external_location_statement(plan, source)
}

fn project_external_location_alter_action(
    a: IrExternalLocationAlterAction,
) -> ExternalLocationAlterAction {
    use ExternalLocationAlterAction as P;
    use IrExternalLocationAlterAction as I;
    match a {
        I::RenameTo => P::RenameTo,
        I::SetUrl => P::SetUrl,
        I::SetStorageCredential => P::SetStorageCredential,
        I::OwnerTo => P::OwnerTo,
    }
}

fn project_external_location_statement(
    plan: &ExternalLocationPlan,
    source: &str,
) -> StatementFacts {
    let kind = match plan.action {
        ExternalLocationAction::Create => StatementKind::CreateExternalLocation,
        ExternalLocationAction::Alter => StatementKind::AlterExternalLocation,
        ExternalLocationAction::Drop => StatementKind::DropExternalLocation,
    };
    let external_location = ExternalLocationFacts {
        url_present: plan.url_present,
        storage_credential_present: plan.storage_credential_present,
        comment_present: plan.comment_present,
        actions: plan
            .actions
            .iter()
            .copied()
            .map(project_external_location_alter_action)
            .collect(),
    };
    let ddl = DdlFacts {
        targets: Vec::new(),
        action: match plan.action {
            ExternalLocationAction::Create => DdlAction::Create,
            ExternalLocationAction::Alter => DdlAction::Alter,
            ExternalLocationAction::Drop => DdlAction::Drop,
        },
        object_kind: ObjectKind::Generic,
        target: plan.target.as_ref().map(|t| ObjectRef {
            kind: ObjectKind::Generic,
            name: parse_table_ref(t.span, source),
        }),
        options: DdlOptions {
            if_not_exists: plan.options.if_not_exists,
            if_exists: plan.options.if_exists,
            ..DdlOptions::default()
        },
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: None,
        database: None,
        warehouse: None,
        stream: None,
        schema: None,
        function: None,
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: Some(external_location),
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: None,
        session: None,
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: None,
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

// ---------------------------------------------------------------------------
// Connection projection (Databricks Unity Catalog foreign connection).
// ---------------------------------------------------------------------------

pub fn derive_facts_from_connection_plan(plan: &ConnectionPlan, source: &str) -> StatementFacts {
    project_connection_statement(plan, source)
}

fn project_connection_alter_action(a: IrConnectionAlterAction) -> ConnectionAlterAction {
    use ConnectionAlterAction as P;
    use IrConnectionAlterAction as I;
    match a {
        I::OwnerTo => P::OwnerTo,
        I::RenameTo => P::RenameTo,
        I::Options => P::Options,
        I::EnableFailover => P::EnableFailover,
        I::DisableFailover => P::DisableFailover,
        I::Primary => P::Primary,
    }
}

fn project_connection_statement(plan: &ConnectionPlan, source: &str) -> StatementFacts {
    let kind = match plan.action {
        ConnectionAction::Create => StatementKind::CreateConnection,
        ConnectionAction::Alter => StatementKind::AlterConnection,
        ConnectionAction::Drop => StatementKind::DropConnection,
    };
    let connection = ConnectionFacts {
        type_present: plan.type_present,
        options_present: plan.options_present,
        comment_present: plan.comment_present,
        is_replica: plan.is_replica,
        actions: plan
            .actions
            .iter()
            .copied()
            .map(project_connection_alter_action)
            .collect(),
    };
    let ddl = DdlFacts {
        targets: Vec::new(),
        action: match plan.action {
            ConnectionAction::Create => DdlAction::Create,
            ConnectionAction::Alter => DdlAction::Alter,
            ConnectionAction::Drop => DdlAction::Drop,
        },
        object_kind: ObjectKind::Generic,
        target: plan.target.as_ref().map(|t| ObjectRef {
            kind: ObjectKind::Generic,
            name: parse_table_ref(t.span, source),
        }),
        options: DdlOptions {
            if_not_exists: plan.options.if_not_exists,
            if_exists: plan.options.if_exists,
            or_replace: plan.options.or_replace,
            ..DdlOptions::default()
        },
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: None,
        database: None,
        warehouse: None,
        stream: None,
        schema: None,
        function: None,
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: Some(connection),
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: None,
        session: None,
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: None,
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

// ---------------------------------------------------------------------------
// External data source projection (T-SQL / PolyBase CREATE EXTERNAL DATA
// SOURCE). Recognition primitives only — danger verdicts live in YAML.

pub fn derive_facts_from_external_data_source_plan(
    plan: &ExternalDataSourcePlan,
    _source: &str,
) -> StatementFacts {
    project_external_data_source_statement(plan)
}

fn project_external_data_source_type(kind: ExternalDataSourceTypeKind) -> ExternalDataSourceType {
    use ExternalDataSourceType as P;
    use ExternalDataSourceTypeKind as I;
    match kind {
        I::Hadoop => P::Hadoop,
        I::BlobStorage => P::BlobStorage,
        I::Rdbms => P::Rdbms,
        I::ShardMapManager => P::ShardMapManager,
    }
}

fn project_external_data_source_statement(plan: &ExternalDataSourcePlan) -> StatementFacts {
    let (ddl_action, stmt_kind) = match plan.action {
        ExternalDataSourceAction::Create => {
            (DdlAction::Create, StatementKind::CreateExternalDataSource)
        }
        ExternalDataSourceAction::Alter => {
            (DdlAction::Alter, StatementKind::AlterExternalDataSource)
        }
    };
    let external_data_source = ExternalDataSourceFacts {
        location_present: plan.location_present,
        location_scheme: plan.location_scheme.clone(),
        source_type: plan.source_type.map(project_external_data_source_type),
        credential_referenced: plan.credential_present,
        pushdown: plan.pushdown,
    };
    let ddl = DdlFacts {
        targets: Vec::new(),
        action: ddl_action,
        object_kind: ObjectKind::Generic,
        target: Some(ObjectRef {
            kind: ObjectKind::Generic,
            name: TableRef::new(
                IdentName::new(plan.name.clone()),
                None,
                None,
                Some(plan.name_span),
            ),
        }),
        options: DdlOptions {
            or_replace: plan.or_replace,
            if_not_exists: plan.if_not_exists,
            ..DdlOptions::default()
        },
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: None,
        database: None,
        warehouse: None,
        stream: None,
        schema: None,
        function: None,
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: Some(external_data_source),
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: None,
        session: None,
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: None,
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind: stmt_kind,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,
        mssql_backup: None,
        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

// ---------------------------------------------------------------------------
// Foreign server projection (SQL/MED CREATE SERVER … FOREIGN DATA WRAPPER).
// Recognition primitives only — danger verdicts (which wrappers reach the
// network / filesystem) live in YAML.

pub fn derive_facts_from_foreign_server_plan(
    plan: &ForeignServerPlan,
    _source: &str,
) -> StatementFacts {
    project_foreign_server_statement(plan)
}

fn project_foreign_server_statement(plan: &ForeignServerPlan) -> StatementFacts {
    let foreign_server = ForeignServerFacts {
        wrapper: plan.wrapper.clone(),
        type_present: plan.type_present,
        options_present: plan.options_present,
    };
    let (kind, ddl_action) = match plan.action {
        ForeignServerAction::Create => (StatementKind::CreateForeignServer, DdlAction::Create),
        ForeignServerAction::Alter => (StatementKind::AlterForeignServer, DdlAction::Alter),
    };
    let ddl = DdlFacts {
        targets: Vec::new(),
        action: ddl_action,
        object_kind: ObjectKind::Generic,
        target: Some(ObjectRef {
            kind: ObjectKind::Generic,
            name: TableRef::new(
                IdentName::new(plan.name.clone()),
                None,
                None,
                Some(plan.name_span),
            ),
        }),
        options: DdlOptions {
            if_not_exists: plan.if_not_exists,
            ..DdlOptions::default()
        },
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: None,
        database: None,
        warehouse: None,
        stream: None,
        schema: None,
        function: None,
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: Some(foreign_server),
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: None,
        session: None,
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: None,
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,
        mssql_backup: None,
        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

// ---------------------------------------------------------------------------
// Server configuration projection (T-SQL ALTER SERVER CONFIGURATION). An
// instance-level engine reconfiguration — surfaced with the subsystem changed.

pub fn derive_facts_from_server_configuration_plan(
    plan: &ServerConfigurationPlan,
    _source: &str,
) -> StatementFacts {
    project_server_configuration_statement(plan)
}

fn project_server_configuration_statement(plan: &ServerConfigurationPlan) -> StatementFacts {
    let server_configuration = ServerConfigurationFacts {
        subsystem: plan.subsystem.clone(),
    };
    let ddl = DdlFacts {
        targets: Vec::new(),
        action: DdlAction::Alter,
        object_kind: ObjectKind::Generic,
        target: None,
        options: DdlOptions::default(),
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: None,
        database: None,
        warehouse: None,
        stream: None,
        schema: None,
        function: None,
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: None,
        session: None,
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: None,
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: Some(server_configuration),
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind: StatementKind::AlterServerConfiguration,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,
        mssql_backup: None,
        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

// ---------------------------------------------------------------------------
// MySQL CREATE EVENT / ALTER EVENT projection. A scheduled SQL job — surfaced
// with the schedule kind (one-time vs recurring), the completion-preserve
// flag, and the enable state. The DO body is analyzed independently via the
// rule-engine flatten, so dangerous scheduled SQL fires through the corpus.

/// Map a lowered `DEFINER =` clause to its public facts (shared by every
/// routine that carries one — event, trigger, …).
fn definer_to_facts(d: &IrDefinerLowered) -> DefinerFacts {
    DefinerFacts {
        explicit: d.explicit,
        user: d.user.clone(),
        host: d.host.clone(),
    }
}

pub fn derive_facts_from_event_plan(plan: &EventPlan, _source: &str) -> StatementFacts {
    project_event_statement(plan)
}

fn project_event_statement(plan: &EventPlan) -> StatementFacts {
    use crate::ast::types::{EventEnableState as AstEnable, EventScheduleKind as AstSched};

    let (action, ddl_action, kind) = match plan.action {
        IrEventAction::Create => (
            EventAction::Create,
            DdlAction::Create,
            StatementKind::CreateEvent,
        ),
        IrEventAction::Alter => (
            EventAction::Alter,
            DdlAction::Alter,
            StatementKind::AlterEvent,
        ),
    };
    let schedule_kind = plan.schedule_kind.map(|k| match k {
        AstSched::OneTime => EventScheduleKindFacts::OneTime,
        AstSched::Recurring => EventScheduleKindFacts::Recurring,
    });
    let enable_state = plan.enable_state.map(|e| match e {
        AstEnable::Enable => EventEnableStateFacts::Enable,
        AstEnable::Disable => EventEnableStateFacts::Disable,
        AstEnable::DisableOnSlave => EventEnableStateFacts::DisableOnSlave,
    });
    let definer = plan.definer.as_ref().map(definer_to_facts);
    let event = EventFacts {
        action,
        definer,
        schedule_kind,
        schedule_present: plan.schedule_present,
        on_completion_preserve: plan.on_completion_preserve,
        enable_state,
        rename: plan.rename_present,
        body_present: plan.body_present,
    };
    let target = plan.name.as_ref().map(|name| ObjectRef {
        kind: ObjectKind::Generic,
        name: qualified_name_to_table_ref(name, Some(plan.name_span)),
    });
    let ddl = DdlFacts {
        targets: Vec::new(),
        action: ddl_action,
        object_kind: ObjectKind::Generic,
        target,
        options: DdlOptions::default(),
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: None,
        database: None,
        warehouse: None,
        stream: None,
        schema: None,
        function: None,
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: None,
        session: None,
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: None,
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: None,
        event: Some(event),
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,
        mssql_backup: None,
        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

// ---------------------------------------------------------------------------
// MySQL CREATE TRIGGER projection. An inline-body trigger that runs on a row
// event under the definer's privileges — surfaced with the timing, the event,
// and the definer. The body is analyzed independently via the rule-engine
// flatten, so a trigger that grants / drops on write fires through the corpus.

pub fn derive_facts_from_trigger_create_plan(
    plan: &TriggerCreatePlan,
    _source: &str,
) -> StatementFacts {
    project_trigger_create_statement(plan)
}

fn project_trigger_create_statement(plan: &TriggerCreatePlan) -> StatementFacts {
    use crate::ast::types::{TriggerEvent as AstEvent, TriggerTiming as AstTiming};

    let timing = match plan.timing {
        AstTiming::Before => TriggerTimingFacts::Before,
        AstTiming::After => TriggerTimingFacts::After,
    };
    let event = match plan.event {
        AstEvent::Insert => TriggerEventFacts::Insert,
        AstEvent::Update => TriggerEventFacts::Update,
        AstEvent::Delete => TriggerEventFacts::Delete,
    };
    let create_trigger = CreateTriggerFacts {
        timing,
        event,
        definer: plan.definer.as_ref().map(definer_to_facts),
        body_present: plan.body_present,
    };
    // The trigger fires on writes to the target table — model the target as the
    // DDL object so name-scoped rules see it.
    let target = plan.target_table.as_ref().map(|name| ObjectRef {
        kind: ObjectKind::Trigger,
        name: qualified_name_to_table_ref(name, Some(plan.target_table_span)),
    });
    let ddl = DdlFacts {
        targets: Vec::new(),
        action: DdlAction::Create,
        object_kind: ObjectKind::Trigger,
        target,
        options: DdlOptions::default(),
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: None,
        database: None,
        warehouse: None,
        stream: None,
        schema: None,
        function: None,
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: None,
        session: None,
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: None,
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: Some(create_trigger),
        view: None,
        external_function: None,
        trigger_body: None,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind: StatementKind::CreateMysqlTrigger,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,
        mssql_backup: None,
        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

// ---------------------------------------------------------------------------
// MySQL LOAD DATA INFILE projection. A bulk file-ingestion surface — surfaced
// with the LOCAL modifier (client vs server read) and the (optionally
// cloud-classified) path.

pub fn derive_facts_from_mysql_load_data_plan(
    plan: &MysqlLoadDataPlan,
    _source: &str,
) -> StatementFacts {
    project_mysql_load_data_statement(plan)
}

fn project_mysql_load_data_statement(plan: &MysqlLoadDataPlan) -> StatementFacts {
    let cloud_scheme = plan
        .infile_path
        .as_deref()
        .and_then(classify_cloud_storage_uri);
    let mysql_load_data = MysqlLoadDataFacts {
        local: plan.local,
        infile_path: plan.infile_path.clone(),
        cloud_scheme,
    };
    let target = plan.target_table.as_ref().map(|name| ObjectRef {
        kind: ObjectKind::Table,
        name: qualified_name_to_table_ref(name, plan.target_table_span),
    });
    let ddl = DdlFacts {
        targets: Vec::new(),
        action: DdlAction::BulkLoad,
        object_kind: ObjectKind::Table,
        target,
        options: DdlOptions::default(),
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: None,
        database: None,
        warehouse: None,
        stream: None,
        schema: None,
        function: None,
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: None,
        session: None,
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: None,
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: Some(mysql_load_data),
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind: StatementKind::MysqlLoadData,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,
        mssql_backup: None,
        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

// ---------------------------------------------------------------------------
// Foreign table projection (SQL/MED CREATE FOREIGN TABLE). A foreign table is
// the local handle for a remote relation — surfaced as a federated-data fact.

pub fn derive_facts_from_foreign_table_plan(
    plan: &ForeignTablePlan,
    _source: &str,
) -> StatementFacts {
    let foreign_table = ForeignTableFacts {
        server: if plan.server.is_empty() {
            None
        } else {
            Some(plan.server.clone())
        },
        is_partition: plan.is_partition,
        options_present: plan.options_present,
    };
    // A foreign table is a table a later statement reads, named by its
    // `[[db.]schema.]name` parts.
    let parts = crate::ir::lower::split_object_ref(&plan.name);
    let (db, schema, name) = match parts.as_slice() {
        _ if parts.iter().any(String::is_empty) => (None, None, plan.name.clone()),
        [n] => (None, None, n.clone()),
        [s, n] => (None, Some(s.clone()), n.clone()),
        [d, s, n] => (Some(d.clone()), Some(s.clone()), n.clone()),
        _ => (None, None, plan.name.clone()),
    };
    let ddl = DdlFacts {
        targets: Vec::new(),
        action: DdlAction::Create,
        object_kind: ObjectKind::ExternalTable,
        target: Some(ObjectRef {
            kind: ObjectKind::ExternalTable,
            name: TableRef::new(
                IdentName::new(name),
                schema.map(IdentName::new),
                db.map(IdentName::new),
                Some(plan.name_span),
            ),
        }),
        options: DdlOptions {
            if_not_exists: plan.if_not_exists,
            ..DdlOptions::default()
        },
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: None,
        database: None,
        warehouse: None,
        stream: None,
        schema: None,
        function: None,
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: Some(foreign_table),
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: None,
        session: None,
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: None,
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind: StatementKind::CreateForeignTable,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,
        mssql_backup: None,
        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

// ---------------------------------------------------------------------------
// Import foreign schema projection (SQL/MED IMPORT FOREIGN SCHEMA). Bulk-exposes
// a remote schema's tables locally — the filter mode (all / except / limit_to)
// is the recognition primitive that determines how much of the remote surface
// is exposed; the broad/scoped verdict is YAML.

pub fn derive_facts_from_import_foreign_schema_plan(
    plan: &ImportForeignSchemaPlan,
    _source: &str,
) -> StatementFacts {
    let opt = |s: &str| {
        if s.is_empty() {
            None
        } else {
            Some(s.to_string())
        }
    };
    let filter_mode = match plan.filter_mode {
        IrImportFilterMode::All => ImportFilterMode::All,
        IrImportFilterMode::LimitTo => ImportFilterMode::LimitTo,
        IrImportFilterMode::Except => ImportFilterMode::Except,
    };
    let import_foreign_schema = ImportForeignSchemaFacts {
        server: opt(&plan.server),
        remote_schema: opt(&plan.remote_schema),
        local_schema: opt(&plan.local_schema),
        filter_mode,
        options_present: plan.options_present,
    };
    let ddl = DdlFacts {
        targets: Vec::new(),
        action: DdlAction::Create,
        object_kind: ObjectKind::Generic,
        target: Some(ObjectRef {
            kind: ObjectKind::Generic,
            name: TableRef::new(
                IdentName::new(plan.local_schema.clone()),
                None,
                None,
                Some(plan.local_schema_span),
            ),
        }),
        options: DdlOptions::default(),
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: None,
        database: None,
        warehouse: None,
        stream: None,
        schema: None,
        function: None,
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: Some(import_foreign_schema),
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: None,
        session: None,
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: None,
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind: StatementKind::ImportForeignSchema,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,
        mssql_backup: None,
        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

// ---------------------------------------------------------------------------
// User mapping projection (SQL/MED CREATE USER MAPPING). Surfaces the OPTIONS
// as a typed key / value-literal list so the credential-leak rules match on a
// `create_user_mapping` kind rather than the old CREATE USER mislabel.

pub fn derive_facts_from_user_mapping_plan(
    plan: &UserMappingPlan,
    _source: &str,
) -> StatementFacts {
    project_user_mapping_statement(plan)
}

fn project_user_mapping_option(o: &UserMappingOptionIr) -> UserMappingOption {
    UserMappingOption {
        key: IdentName::new(o.key.clone()).written_at(o.key_span),
        value_literal: o.value_literal.clone(),
    }
}

fn project_user_mapping_statement(plan: &UserMappingPlan) -> StatementFacts {
    let user_mapping = UserMappingFacts {
        server: if plan.server.is_empty() {
            None
        } else {
            Some(plan.server.clone())
        },
        is_public: plan.is_public,
        options: plan
            .options
            .iter()
            .map(project_user_mapping_option)
            .collect(),
    };
    let (kind, ddl_action) = match plan.action {
        UserMappingAction::Create => (StatementKind::CreateUserMapping, DdlAction::Create),
        UserMappingAction::Alter => (StatementKind::AlterUserMapping, DdlAction::Alter),
        UserMappingAction::Drop => (StatementKind::DropUserMapping, DdlAction::Drop),
    };
    let ddl = DdlFacts {
        targets: Vec::new(),
        action: ddl_action,
        object_kind: ObjectKind::Generic,
        target: Some(ObjectRef {
            kind: ObjectKind::Generic,
            name: TableRef::new(
                IdentName::new(plan.server.clone()),
                None,
                None,
                Some(plan.server_span),
            ),
        }),
        options: DdlOptions {
            if_not_exists: plan.if_not_exists,
            if_exists: plan.if_exists,
            ..DdlOptions::default()
        },
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: None,
        database: None,
        warehouse: None,
        stream: None,
        schema: None,
        function: None,
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: Some(user_mapping),
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: None,
        session: None,
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: None,
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,
        mssql_backup: None,
        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

// ---------------------------------------------------------------------------
// Flow projection (Databricks Lakeflow CDC pipeline).
// ---------------------------------------------------------------------------

pub fn derive_facts_from_flow_plan(plan: &FlowPlan, _source: &str) -> StatementFacts {
    project_flow_statement(plan)
}

fn project_flow_statement(plan: &FlowPlan) -> StatementFacts {
    let kind = match plan.action {
        FlowAction::Create => StatementKind::CreateFlow,
    };
    let ddl = DdlFacts {
        targets: Vec::new(),
        action: match plan.action {
            FlowAction::Create => DdlAction::Create,
        },
        object_kind: ObjectKind::Generic,
        target: None,
        options: DdlOptions::default(),
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: None,
        database: None,
        warehouse: None,
        stream: None,
        schema: None,
        function: None,
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: Some(FlowFacts {}),
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: None,
        session: None,
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: None,
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

// ---------------------------------------------------------------------------
// Use projection.
// ---------------------------------------------------------------------------

/// Build a public `StatementFacts` directly from a lowered
/// [`UsePlan`]. Catalog is not consulted — the typed plan already
/// carries the required structural data (the closed `UseKind`
/// discriminator and a single normalized identifier).
pub fn derive_facts_from_use_plan(plan: &UsePlan, _source: &str) -> StatementFacts {
    project_use_statement(plan)
}

fn project_use_statement(plan: &UsePlan) -> StatementFacts {
    let kind = match plan.kind {
        UseKind::Role => UseStatementKind::Role,
        UseKind::Database => UseStatementKind::Database,
        UseKind::Catalog => UseStatementKind::Catalog,
        UseKind::Schema => UseStatementKind::Schema,
        UseKind::Warehouse => UseStatementKind::Warehouse,
        UseKind::SecondaryRoles => UseStatementKind::SecondaryRoles,
    };
    let target = plan.target.as_ref().map(|t| UseTargetFacts {
        raw: t.raw.clone(),
        normalized: t.normalized.clone(),
    });
    let use_facts = UseFacts { kind, target };
    StatementFacts {
        declare: None,
        call: None,
        kind: StatementKind::Use,
        source_span: Some(plan.span),
        query: None,
        ddl: None,
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: Some(use_facts),
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

// ---------------------------------------------------------------------------
// Statement-kind-only projection (no per-element detail surface).
// ---------------------------------------------------------------------------

/// Build a public [`StatementFacts`] for a `COMMENT ON <target-kind>
/// <name> IS <value>` statement. Classifies the parser-validated
/// `object_kind` keyword span into the curated public closed enum.
/// The keyword set is closed: every unrecognized keyword folds to
/// [`CommentTargetKind::Other`](crate::facts::comment::CommentTargetKind::Other).
pub fn derive_facts_from_comment_on(
    stmt: &crate::ast::AstCommentOn,
    source: &str,
) -> StatementFacts {
    use crate::facts::CommentTargetKind;
    let kw_start = stmt.object_kind.start as usize;
    let kw_end = std::cmp::min(stmt.object_kind.end as usize, source.len());
    let kw = source.get(kw_start..kw_end).unwrap_or("");
    let target_kind = match kw.trim().to_ascii_uppercase().as_str() {
        "TABLE" => CommentTargetKind::Table,
        "COLUMN" => CommentTargetKind::Column,
        "SCHEMA" => CommentTargetKind::Schema,
        "DATABASE" => CommentTargetKind::Database,
        "CATALOG" => CommentTargetKind::Catalog,
        "VOLUME" => CommentTargetKind::Volume,
        "CONNECTION" => CommentTargetKind::Connection,
        "INDEX" => CommentTargetKind::Index,
        "FUNCTION" => CommentTargetKind::Function,
        "PROCEDURE" => CommentTargetKind::Procedure,
        "VIEW" => CommentTargetKind::View,
        "SEQUENCE" => CommentTargetKind::Sequence,
        _ => CommentTargetKind::Other,
    };
    // The object commented on; for a column, its table.
    let (object_kind, of_column) = match target_kind {
        CommentTargetKind::Column => (ObjectKind::Table, true),
        CommentTargetKind::Table => (ObjectKind::Table, false),
        CommentTargetKind::Schema => (ObjectKind::Schema, false),
        CommentTargetKind::Database => (ObjectKind::Database, false),
        CommentTargetKind::Catalog => (ObjectKind::Catalog, false),
        CommentTargetKind::Volume => (ObjectKind::Volume, false),
        CommentTargetKind::Index => (ObjectKind::Index, false),
        CommentTargetKind::Function => (ObjectKind::Function, false),
        CommentTargetKind::Procedure => (ObjectKind::Procedure, false),
        CommentTargetKind::View => (ObjectKind::View, false),
        CommentTargetKind::Sequence => (ObjectKind::Sequence, false),
        CommentTargetKind::Connection | CommentTargetKind::Other => (ObjectKind::Generic, false),
    };
    let target = match of_column {
        true => crate::ir::lower_ddl::column_table_target(stmt.object_name, source),
        false => crate::ir::lower_ddl::target_from(stmt.object_name, source),
    };
    let ddl = DdlFacts::bare(
        DdlAction::Comment,
        object_kind,
        target.as_ref().map(|t| ObjectRef {
            kind: object_kind,
            name: ddl_target_name(t),
        }),
    );
    let comment = crate::facts::CommentOnFacts { target_kind };
    StatementFacts {
        declare: None,
        call: None,
        kind: StatementKind::Comment,
        source_span: Some(stmt.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: Some(comment),
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

/// A statement that runs, restores, maintains, prepares or alters an object
/// it names, read by [`derive_facts_from_command`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandKind {
    /// `CALL p(…)`.
    Call,
    UndropTable,
    UndropSchema,
    UndropDatabase,
    UndropType,
    /// PostgreSQL `ANALYZE [t]`, MySQL `ANALYZE TABLE t, …`.
    Analyze,
    /// PostgreSQL `CLUSTER [t]`.
    Cluster,
    /// MySQL `OPTIMIZE TABLE t, …`.
    OptimizeTable,
    /// MySQL `CHECK TABLE t, …`.
    CheckTable,
    /// MySQL `CHECKSUM TABLE t, …`.
    ChecksumTable,
    /// MySQL `REPAIR TABLE t, …`.
    RepairTable,
    /// `PREPARE name …`: a prepared statement made.
    Prepare,
    /// `EXECUTE name`: a prepared statement run.
    Execute,
    /// `DEALLOCATE [PREPARE] name`.
    Deallocate,
    /// T-SQL `CREATE VECTOR INDEX`.
    CreateVectorIndex,
    /// Snowflake `ALTER STREAM`.
    AlterStream,
    /// Snowflake `ALTER REPLICATION GROUP`.
    AlterReplicationGroup,
    /// Snowflake `ALTER FAILOVER GROUP`.
    AlterFailoverGroup,
    /// T-SQL `EXEC p …`.
    MssqlExec,
    /// `DESCRIBE <object>`: the object, of the kind its plan names.
    Describe,
    /// `OPEN`, `FETCH` or `CLOSE` of a cursor: the cursor.
    OpenCursor,
    FetchCursor,
    CloseCursor,
    /// PostgreSQL `LISTEN`, `NOTIFY` or `UNLISTEN`: the channel.
    Listen,
    Notify,
    Unlisten,
    /// `SAVEPOINT` or `RELEASE`: the savepoint.
    Savepoint,
}

/// The facts of the statement of `kind` at `span`: what it does to the
/// object it names, its DDL `plan`'s target.
pub fn derive_facts_from_command(
    kind: CommandKind,
    span: Span,
    plan: Option<&crate::ir::DdlPlan>,
) -> StatementFacts {
    let (stmt_kind, action, object_kind) = match kind {
        CommandKind::Call => (
            StatementKind::Call,
            DdlAction::Execute,
            ObjectKind::Procedure,
        ),
        CommandKind::UndropTable => (
            StatementKind::UndropTable,
            DdlAction::Restore,
            ObjectKind::Table,
        ),
        CommandKind::UndropSchema => (
            StatementKind::UndropSchema,
            DdlAction::Restore,
            ObjectKind::Schema,
        ),
        CommandKind::UndropDatabase => (
            StatementKind::UndropDatabase,
            DdlAction::Restore,
            ObjectKind::Database,
        ),
        CommandKind::UndropType => (
            StatementKind::UndropType,
            DdlAction::Restore,
            ObjectKind::PgType,
        ),
        CommandKind::Analyze => (
            StatementKind::AnalyzeStmt,
            DdlAction::Maintenance,
            ObjectKind::Table,
        ),
        CommandKind::Cluster => (
            StatementKind::PgCluster,
            DdlAction::Maintenance,
            ObjectKind::Table,
        ),
        CommandKind::OptimizeTable => (
            StatementKind::OptimizeTable,
            DdlAction::Maintenance,
            ObjectKind::Table,
        ),
        CommandKind::CheckTable => (
            StatementKind::CheckTable,
            DdlAction::Maintenance,
            ObjectKind::Table,
        ),
        CommandKind::ChecksumTable => (
            StatementKind::ChecksumTable,
            DdlAction::Maintenance,
            ObjectKind::Table,
        ),
        CommandKind::RepairTable => (
            StatementKind::RepairTable,
            DdlAction::Maintenance,
            ObjectKind::Table,
        ),
        CommandKind::Prepare => (
            StatementKind::PgPrepare,
            DdlAction::Create,
            ObjectKind::Generic,
        ),
        CommandKind::Execute => (
            StatementKind::PgExecute,
            DdlAction::Execute,
            ObjectKind::Generic,
        ),
        CommandKind::Deallocate => (
            StatementKind::PgDeallocate,
            DdlAction::Drop,
            ObjectKind::Generic,
        ),
        CommandKind::CreateVectorIndex => (
            StatementKind::MssqlCreateVectorIndex,
            DdlAction::Create,
            ObjectKind::Index,
        ),
        CommandKind::AlterStream => (
            StatementKind::AlterStream,
            DdlAction::Alter,
            ObjectKind::Stream,
        ),
        CommandKind::AlterReplicationGroup => (
            StatementKind::AlterReplicationGroup,
            DdlAction::Alter,
            ObjectKind::ReplicationGroup,
        ),
        CommandKind::AlterFailoverGroup => (
            StatementKind::AlterFailoverGroup,
            DdlAction::Alter,
            ObjectKind::FailoverGroup,
        ),
        CommandKind::MssqlExec => (
            StatementKind::MssqlExec,
            DdlAction::Execute,
            ObjectKind::Procedure,
        ),
        CommandKind::OpenCursor => (
            StatementKind::OpenCursor,
            DdlAction::ControlFlow,
            ObjectKind::Generic,
        ),
        CommandKind::FetchCursor => (
            StatementKind::FetchCursor,
            DdlAction::ControlFlow,
            ObjectKind::Generic,
        ),
        CommandKind::CloseCursor => (
            StatementKind::CloseCursor,
            DdlAction::ControlFlow,
            ObjectKind::Generic,
        ),
        CommandKind::Listen => (
            StatementKind::PgListen,
            DdlAction::Configure,
            ObjectKind::Generic,
        ),
        CommandKind::Notify => (
            StatementKind::PgNotify,
            DdlAction::Configure,
            ObjectKind::Generic,
        ),
        CommandKind::Unlisten => (
            StatementKind::PgUnlisten,
            DdlAction::Configure,
            ObjectKind::Generic,
        ),
        CommandKind::Savepoint => (
            StatementKind::Savepoint,
            DdlAction::Transaction,
            ObjectKind::Generic,
        ),
        CommandKind::Describe => (
            StatementKind::Describe,
            DdlAction::Configure,
            plan.map_or(ObjectKind::Generic, |plan| plan.object_kind),
        ),
    };
    let target = plan
        .and_then(|plan| plan.target.as_ref())
        .map(|target| ObjectRef {
            kind: object_kind,
            name: ddl_target_name(target),
        });
    let mut facts = derive_facts_stmt_kind_only(stmt_kind, span);
    facts.ddl = Some(DdlFacts::bare(action, object_kind, target));
    facts
}

/// The DDL facts `plan` names: its action, `object_kind`, and its target as
/// an object of that kind. For a family whose own facts name no object.
pub(crate) fn ddl_of_plan(plan: &crate::ir::DdlPlan, object_kind: ObjectKind) -> DdlFacts {
    let target = plan.target.as_ref().map(|target| ObjectRef {
        kind: object_kind,
        name: ddl_target_name(target),
    });
    DdlFacts::bare(project_ir_ddl_action(plan.action), object_kind, target)
}

/// The name a DDL target gives an object, as facts name it.
pub(crate) fn ddl_target_name(target: &crate::ir::ddl_plan::DdlTarget) -> TableRef {
    TableRef::new(
        IdentName::new(target.name.clone()),
        target.schema.clone().map(IdentName::new),
        target.db.clone().map(IdentName::new),
        Some(target.span),
    )
}

pub fn derive_facts_stmt_kind_only(kind: StatementKind, span: Span) -> StatementFacts {
    StatementFacts {
        declare: None,
        call: None,
        kind,
        source_span: Some(span),
        query: None,
        ddl: None,
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

/// Derive a [`StatementFacts`] for a dynamic-SQL surface statement
/// (top-level Snowflake/BQ/Databricks `EXECUTE IMMEDIATE`, T-SQL
/// `EXEC`/`sp_executesql`, PG/MySQL `PREPARE`). Mirrors
/// [`derive_facts_stmt_kind_only`] but additionally attaches the typed
/// [`DynamicSqlCall`] so DYNSQL-* rules can predicate on argument
/// shape and parameterization at the statement level.
pub fn derive_facts_dynamic_sql_stmt(
    kind: StatementKind,
    span: Span,
    call: DynamicSqlCall,
) -> StatementFacts {
    StatementFacts {
        declare: None,
        call: None,
        kind,
        source_span: Some(span),
        query: None,
        ddl: None,
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: vec![call],
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

/// Project a lowered [`crate::ir::dynamic_sql::ExecuteImmediateFromIr`] into
/// the public [`crate::facts::ddl::ExecuteImmediateFromFacts`] recognition
/// carrier. Recognition only — the trust/severity verdict is YAML.
pub fn project_execute_immediate_from(
    ir: &crate::ir::dynamic_sql::ExecuteImmediateFromIr,
) -> crate::facts::ddl::ExecuteImmediateFromFacts {
    use crate::facts::ddl::{EifLocationKind, ExecuteImmediateFromFacts};
    use crate::ir::dynamic_sql::EifLocationKindIr;
    ExecuteImmediateFromFacts {
        location_kind: match ir.location_kind {
            EifLocationKindIr::StagePath => EifLocationKind::StagePath,
            EifLocationKindIr::RelativePath => EifLocationKind::RelativePath,
        },
        location: ir.location.clone(),
        executes: ir.executes,
        dry_run: ir.dry_run,
        using_keys: ir.using_keys.clone(),
    }
}

/// Build a public [`StatementFacts`] for a Snowflake `EXECUTE IMMEDIATE
/// FROM <file>` statement, attaching the typed
/// [`crate::facts::ddl::ExecuteImmediateFromFacts`].
pub fn derive_facts_execute_immediate_from(
    span: Span,
    eif: crate::facts::ddl::ExecuteImmediateFromFacts,
) -> StatementFacts {
    let mut facts = derive_facts_stmt_kind_only(StatementKind::ExecuteImmediateFrom, span);
    facts.execute_immediate_from = Some(eif);
    facts
}

/// Build a public [`StatementFacts`] for the T-SQL audit DDL
/// statements (`CREATE/ALTER/DROP { SERVER AUDIT [SPECIFICATION] |
/// DATABASE AUDIT SPECIFICATION }`).
pub fn derive_facts_mssql_audit(
    kind: StatementKind,
    span: Span,
    audit: crate::facts::ddl::AuditFacts,
) -> StatementFacts {
    let mut facts = derive_facts_mssql_impersonation(kind, span, None);
    facts.audit = Some(audit);
    facts
}

/// Build a public [`StatementFacts`] for the T-SQL security-object DDL
/// statements (`CREATE/ALTER/DROP { MASTER KEY | SYMMETRIC KEY |
/// ASYMMETRIC KEY | CERTIFICATE | [DATABASE SCOPED] CREDENTIAL }`).
pub fn derive_facts_mssql_security_object(
    kind: StatementKind,
    span: Span,
    security_object: crate::facts::ddl::SecurityObjectFacts,
) -> StatementFacts {
    let mut facts = derive_facts_mssql_impersonation(kind, span, None);
    facts.security_object = Some(security_object);
    facts
}

/// Build a public [`StatementFacts`] for the T-SQL impersonation
/// statements: `EXECUTE AS LOGIN/USER = …` (with typed
/// [`crate::facts::ddl::ImpersonationFacts`]) and `REVERT` (kind only,
/// `impersonation: None`).
pub fn derive_facts_mssql_impersonation(
    kind: StatementKind,
    span: Span,
    impersonation: Option<crate::facts::ddl::ImpersonationFacts>,
) -> StatementFacts {
    StatementFacts {
        declare: None,
        call: None,
        kind,
        source_span: Some(span),
        query: None,
        ddl: None,
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

// ---------------------------------------------------------------------------
// PG COPY projection.
// ---------------------------------------------------------------------------

/// Build a public [`StatementFacts`] directly from a lowered
/// [`PgCopyPlan`](crate::ir::pg_copy_plan::PgCopyPlan). Catalog is not consulted — the typed plan already
/// carries the required structural data (the closed direction +
/// target-kind discriminators).
pub fn derive_facts_from_pg_copy_plan(
    plan: &crate::ir::PgCopyPlan,
    _source: &str,
) -> StatementFacts {
    let direction = match plan.direction {
        crate::ir::PgCopyDirection::From => crate::facts::PgCopyDirection::From,
        crate::ir::PgCopyDirection::To => crate::facts::PgCopyDirection::To,
    };
    let target = match plan.target {
        crate::ir::PgCopyTargetKind::File => crate::facts::PgCopyTargetKind::File,
        crate::ir::PgCopyTargetKind::Program => crate::facts::PgCopyTargetKind::Program,
        crate::ir::PgCopyTargetKind::Stdin => crate::facts::PgCopyTargetKind::Stdin,
        crate::ir::PgCopyTargetKind::Stdout => crate::facts::PgCopyTargetKind::Stdout,
        crate::ir::PgCopyTargetKind::Placeholder => crate::facts::PgCopyTargetKind::Placeholder,
    };
    let pg_copy = crate::facts::PgCopyFacts { direction, target };
    // `COPY <table> FROM/TO …` — surface the table identity on the
    // standard DDL-target surface so downstream consumers see the
    // table involved in the bulk load / unload, pinned to a typed
    // `DdlFacts.target`. Query-subject form
    // (`COPY (<query>) TO …`) lowers via the Rel path and surfaces
    // tables in `query.reads_table` instead.
    let ddl = plan.subject_table.as_ref().map(|t| {
        let action = match plan.direction {
            crate::ir::PgCopyDirection::From => DdlAction::BulkLoad,
            crate::ir::PgCopyDirection::To => DdlAction::BulkLoad,
        };
        let table_ref = crate::facts::identity::TableRef::new(
            crate::facts::IdentName::new(&t.name),
            t.schema.as_deref().map(crate::facts::IdentName::new),
            t.db.as_deref().map(crate::facts::IdentName::new),
            Some(t.span),
        );
        let target_ref = crate::facts::ObjectRef {
            kind: ObjectKind::Table,
            name: table_ref,
        };
        DdlFacts {
            targets: Vec::new(),
            action,
            object_kind: ObjectKind::Table,
            target: Some(target_ref),
            options: DdlOptions::default(),
            alter_changes: Vec::new(),
            stage: None,
            storage_credential: None,
            dynamic_table: None,
            pipe: None,
            task: None,
            database: None,
            warehouse: None,
            stream: None,
            schema: None,
            function: None,
            procedure: None,
            table: None,
            catalog: None,
            table_maintenance: None,
            volume: None,
            external_location: None,
            connection: None,
            external_data_source: None,
            foreign_server: None,
            user_mapping: None,
            foreign_table: None,
            import_foreign_schema: None,
            flow: None,
            mssql_set_option: None,
            mssql_principal: None,
            principal: None,
            domain: None,
            index: None,
            trigger: None,
            trigger_state: None,
            pg_session: None,
            bq_assert: None,
            bq_create_model: None,
            bq_export_data: None,
            bq_options: None,
            datashare: None,
            tag: None,
            file_format: None,
            session: None,
            share: None,
            secret: None,
            network_rule: None,
            resource_monitor: None,
            compute_pool: None,
            git_repository: None,
            image_repository: None,
            streamlit: None,
            service: None,
            notebook: None,
            alert: None,
            data_metric_function: None,
            replication_failover_group: None,
            account: None,
            semantic_view: None,
            cortex_search_service: None,
            application: None,
            application_package: None,
            listing: None,
            managed_account: None,
            show: None,
            synonym: None,
            server_configuration: None,
            mysql_load_data: None,
            event: None,
            create_trigger: None,
            view: None,
            external_function: None,
            trigger_body: None,
        }
    });
    StatementFacts {
        declare: None,
        call: None,
        kind: StatementKind::PgCopy,
        source_span: Some(plan.span),
        query: None,
        ddl,
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: Some(pg_copy),

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

// ---------------------------------------------------------------------------
// BACKUP projection.
// ---------------------------------------------------------------------------

/// Build a public `StatementFacts` from a lowered [`MssqlBackupPlan`](crate::ir::backup_plan::MssqlBackupPlan).
///
/// `BACKUP` is a top-level utility statement (not DDL), so the payload sits
/// on `StatementFacts.mssql_backup` alongside `pg_copy`. Recognition only —
/// the destination device class and encryption flag are structural; which
/// destination is dangerous is a YAML verdict.
pub fn derive_facts_from_backup_plan(
    plan: &crate::ir::MssqlBackupPlan,
    _source: &str,
) -> StatementFacts {
    let target = match plan.target {
        crate::ir::BackupTargetKind::Database => crate::facts::BackupTarget::Database,
        crate::ir::BackupTargetKind::Log => crate::facts::BackupTarget::Log,
    };
    let destination = match plan.destination {
        crate::ir::BackupDestinationKind::Disk => crate::facts::BackupDestination::Disk,
        crate::ir::BackupDestinationKind::Url => crate::facts::BackupDestination::Url,
        crate::ir::BackupDestinationKind::Tape => crate::facts::BackupDestination::Tape,
    };
    let mssql_backup = crate::facts::MssqlBackupFacts {
        target,
        destination,
        encryption: plan.encryption,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind: StatementKind::MssqlBackup,
        source_span: Some(plan.span),
        query: None,
        ddl: None,
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,
        mssql_backup: Some(mssql_backup),
        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

// ---------------------------------------------------------------------------
// DBCC projection.
// ---------------------------------------------------------------------------

/// Build a public `StatementFacts` from a lowered [`crate::ir::MssqlDbccPlan`].
///
/// `DBCC` is a top-level maintenance utility (not DDL), so the payload sits on
/// `StatementFacts.mssql_dbcc` alongside `mssql_backup`. Recognition only — the
/// command verb is the single primitive; which command is dangerous is a YAML
/// verdict.
pub fn derive_facts_from_dbcc_plan(
    plan: &crate::ir::MssqlDbccPlan,
    _source: &str,
) -> StatementFacts {
    let mssql_dbcc = crate::facts::MssqlDbccFacts {
        command: plan.command.clone(),
    };
    StatementFacts {
        declare: None,
        call: None,
        kind: StatementKind::MssqlDbcc,
        source_span: Some(plan.span),
        query: None,
        ddl: None,
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,
        mssql_backup: None,
        mssql_restore: None,
        mssql_dbcc: Some(mssql_dbcc),
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

// ---------------------------------------------------------------------------
// Password literals: a T-SQL key statement's (OPEN / CLOSE KEY, BACKUP /
// RESTORE KEY, ADD SIGNATURE, ALTER SERVICE MASTER KEY) and a URL's.
// ---------------------------------------------------------------------------

/// Decoded password literals as facts.
fn password_literals(values: &[String]) -> Vec<crate::facts::PasswordLiteral> {
    values
        .iter()
        .cloned()
        .map(|value| crate::facts::PasswordLiteral { value })
        .collect()
}

// ---------------------------------------------------------------------------
// Encryption-key activation (OPEN / CLOSE KEY) projection.
// ---------------------------------------------------------------------------

/// Build a public `StatementFacts` from a lowered
/// [`crate::ir::MssqlKeyManagementPlan`].
///
/// Key activation is a session-scoped context switch (not DDL), so the payload
/// sits on `StatementFacts.mssql_key_management` alongside `mssql_dbcc`.
/// Recognition only — verb, key kind and inline-password presence are
/// structural; which combination is dangerous is a YAML verdict.
pub fn derive_facts_from_key_management_plan(
    plan: &crate::ir::MssqlKeyManagementPlan,
    _source: &str,
) -> StatementFacts {
    use crate::ast::types::{KeyMgmtAction, KeyMgmtKind};
    let action = match plan.action {
        KeyMgmtAction::Open => crate::facts::KeyManagementAction::Open,
        KeyMgmtAction::Close => crate::facts::KeyManagementAction::Close,
    };
    let key_kind = match plan.key_kind {
        KeyMgmtKind::Master => crate::facts::KeyManagementKind::Master,
        KeyMgmtKind::Symmetric => crate::facts::KeyManagementKind::Symmetric,
        KeyMgmtKind::AllSymmetric => crate::facts::KeyManagementKind::AllSymmetric,
    };
    let mssql_key_management = crate::facts::MssqlKeyManagementFacts {
        action,
        key_kind,
        password_present: !plan.password_literals.is_empty(),
        password_literals: password_literals(&plan.password_literals),
    };
    StatementFacts {
        declare: None,
        call: None,
        kind: StatementKind::MssqlKeyManagement,
        source_span: Some(plan.span),
        query: None,
        ddl: None,
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,
        mssql_backup: None,
        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: Some(mssql_key_management),
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

// ---------------------------------------------------------------------------
// Row-Level Security (CREATE / ALTER SECURITY POLICY) projection.
// ---------------------------------------------------------------------------

/// Build a public `StatementFacts` from a lowered
/// [`crate::ir::MssqlSecurityPolicyPlan`].
///
/// A security policy is the row-level-security control; the payload sits on
/// `StatementFacts.mssql_security_policy` alongside the other dedicated MSSQL
/// families. Recognition only — verb, state and predicate presence are
/// structural; which combination is dangerous (a disabled control) is a YAML
/// verdict.
pub fn derive_facts_from_security_policy_plan(
    plan: &crate::ir::MssqlSecurityPolicyPlan,
    _source: &str,
) -> StatementFacts {
    use crate::ast::types::{PolicyState as AstState, SecurityPolicyAction as AstAction};
    let action = match plan.action {
        AstAction::Create => crate::facts::security_policy::SecurityPolicyAction::Create,
        AstAction::Alter => crate::facts::security_policy::SecurityPolicyAction::Alter,
    };
    let state = match plan.state {
        AstState::On => crate::facts::security_policy::PolicyState::On,
        AstState::Off => crate::facts::security_policy::PolicyState::Off,
        AstState::Unset => crate::facts::security_policy::PolicyState::Unset,
    };
    let mssql_security_policy = crate::facts::MssqlSecurityPolicyFacts {
        action,
        state,
        has_filter_predicate: plan.has_filter_predicate,
        has_block_predicate: plan.has_block_predicate,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind: StatementKind::MssqlSecurityPolicy,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(DdlFacts::bare(
            match plan.action {
                AstAction::Create => DdlAction::Create,
                AstAction::Alter => DdlAction::Alter,
            },
            ObjectKind::RowAccessPolicy,
            plan.target.as_ref().map(|t| ObjectRef {
                kind: ObjectKind::RowAccessPolicy,
                name: ddl_target_name(t),
            }),
        )),
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,
        mssql_backup: None,
        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: Some(mssql_security_policy),
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

// ---------------------------------------------------------------------------
// Key-material protection (BACKUP / RESTORE key objects) projection.
// ---------------------------------------------------------------------------

/// Build a public `StatementFacts` from a lowered
/// [`crate::ir::MssqlKeyBackupPlan`].
///
/// These statements move root key material across the filesystem boundary; the
/// payload sits on `StatementFacts.mssql_key_backup` alongside the other
/// dedicated MSSQL families. Recognition only — verb, key object and inline-
/// password presence are structural; which combination is dangerous is a YAML
/// verdict.
pub fn derive_facts_from_key_backup_plan(
    plan: &crate::ir::MssqlKeyBackupPlan,
    _source: &str,
) -> StatementFacts {
    use crate::ast::types::{BackupKeyObject as AstObj, KeyBackupAction as AstAction};
    let action = match plan.action {
        AstAction::Backup => crate::facts::key_backup::KeyBackupAction::Backup,
        AstAction::Restore => crate::facts::key_backup::KeyBackupAction::Restore,
    };
    let key_object = match plan.key_object {
        AstObj::ServiceMasterKey => crate::facts::key_backup::BackupKeyObject::ServiceMasterKey,
        AstObj::MasterKey => crate::facts::key_backup::BackupKeyObject::MasterKey,
        AstObj::Certificate => crate::facts::key_backup::BackupKeyObject::Certificate,
        AstObj::AsymmetricKey => crate::facts::key_backup::BackupKeyObject::AsymmetricKey,
    };
    let mssql_key_backup = crate::facts::MssqlKeyBackupFacts {
        action,
        key_object,
        password_present: !plan.password_literals.is_empty(),
        password_literals: password_literals(&plan.password_literals),
    };
    StatementFacts {
        declare: None,
        call: None,
        kind: StatementKind::MssqlKeyBackup,
        source_span: Some(plan.span),
        query: None,
        ddl: None,
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,
        mssql_backup: None,
        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: Some(mssql_key_backup),
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

// ---------------------------------------------------------------------------
// CLR assembly (CREATE / ALTER ASSEMBLY) projection.
// ---------------------------------------------------------------------------

/// Build a public `StatementFacts` from a lowered
/// [`crate::ir::MssqlAssemblyPlan`].
///
/// A CLR assembly registers .NET code that runs inside the SQL Server process;
/// the payload sits on `StatementFacts.mssql_assembly` alongside the other
/// dedicated MSSQL families. Recognition only — verb, permission set and
/// filesystem-source flag are structural; which permission is dangerous is a
/// YAML verdict.
pub fn derive_facts_from_assembly_plan(
    plan: &crate::ir::MssqlAssemblyPlan,
    _source: &str,
) -> StatementFacts {
    use crate::ast::types::{AssemblyAction as AstAction, AssemblyPermissionSet as AstPerm};
    let action = match plan.action {
        AstAction::Create => crate::facts::assembly::AssemblyAction::Create,
        AstAction::Alter => crate::facts::assembly::AssemblyAction::Alter,
    };
    let permission_set = match plan.permission_set {
        AstPerm::Safe => crate::facts::assembly::AssemblyPermissionSet::Safe,
        AstPerm::ExternalAccess => crate::facts::assembly::AssemblyPermissionSet::ExternalAccess,
        AstPerm::Unsafe => crate::facts::assembly::AssemblyPermissionSet::Unsafe,
        AstPerm::Unset => crate::facts::assembly::AssemblyPermissionSet::Unset,
    };
    let mssql_assembly = crate::facts::MssqlAssemblyFacts {
        action,
        permission_set,
        from_file: plan.from_file,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind: StatementKind::MssqlAssembly,
        source_span: Some(plan.span),
        query: None,
        ddl: None,
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,
        mssql_backup: None,
        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: Some(mssql_assembly),
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

// ---------------------------------------------------------------------------
// Module signing (ADD [COUNTER] SIGNATURE) projection.
// ---------------------------------------------------------------------------

/// Build a public `StatementFacts` from a lowered
/// [`crate::ir::MssqlAddSignaturePlan`].
///
/// Signing a module delegates the signer's privileges to it; the payload sits
/// on `StatementFacts.mssql_add_signature` alongside the other dedicated MSSQL
/// families. Recognition only — counter, signer kind and inline-password
/// presence are structural; which combination is dangerous is a YAML verdict.
pub fn derive_facts_from_add_signature_plan(
    plan: &crate::ir::MssqlAddSignaturePlan,
    _source: &str,
) -> StatementFacts {
    use crate::ast::types::SignerKind as AstSigner;
    let signer_kind = match plan.signer_kind {
        AstSigner::Certificate => crate::facts::add_signature::SignerKind::Certificate,
        AstSigner::AsymmetricKey => crate::facts::add_signature::SignerKind::AsymmetricKey,
    };
    let mssql_add_signature = crate::facts::MssqlAddSignatureFacts {
        counter: plan.counter,
        signer_kind,
        password_present: !plan.password_literals.is_empty(),
        password_literals: password_literals(&plan.password_literals),
    };
    StatementFacts {
        declare: None,
        call: None,
        kind: StatementKind::MssqlAddSignature,
        source_span: Some(plan.span),
        query: None,
        // Signing a module changes what it may do.
        ddl: Some(DdlFacts::bare(
            DdlAction::Alter,
            ObjectKind::Generic,
            plan.target.as_ref().map(|t| ObjectRef {
                kind: ObjectKind::Generic,
                name: ddl_target_name(t),
            }),
        )),
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,
        mssql_backup: None,
        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: Some(mssql_add_signature),
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

// ---------------------------------------------------------------------------
// Service Master Key rotation (ALTER SERVICE MASTER KEY) projection.
// ---------------------------------------------------------------------------

/// Build a public `StatementFacts` from a lowered
/// [`crate::ir::MssqlServiceMasterKeyPlan`].
///
/// The Service Master Key is the encryption-hierarchy root; the payload sits on
/// `StatementFacts.mssql_service_master_key` alongside the other dedicated MSSQL
/// families. Recognition only — operation, force and inline-password presence
/// are structural; which combination is dangerous is a YAML verdict.
pub fn derive_facts_from_service_master_key_plan(
    plan: &crate::ir::MssqlServiceMasterKeyPlan,
    _source: &str,
) -> StatementFacts {
    use crate::ast::types::ServiceMasterKeyOperation as AstOp;
    let operation = match plan.operation {
        AstOp::Regenerate => {
            crate::facts::service_master_key::ServiceMasterKeyOperation::Regenerate
        }
        AstOp::AccountChange => {
            crate::facts::service_master_key::ServiceMasterKeyOperation::AccountChange
        }
    };
    let mssql_service_master_key = crate::facts::MssqlServiceMasterKeyFacts {
        operation,
        force: plan.force,
        password_present: !plan.password_literals.is_empty(),
        password_literals: password_literals(&plan.password_literals),
    };
    StatementFacts {
        declare: None,
        call: None,
        kind: StatementKind::MssqlServiceMasterKey,
        source_span: Some(plan.span),
        query: None,
        ddl: None,
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,
        mssql_backup: None,
        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: Some(mssql_service_master_key),
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

// ---------------------------------------------------------------------------
// ALTER DEFAULT PRIVILEGES (PostgreSQL default-grant policy) projection.
// ---------------------------------------------------------------------------

/// Build a public `StatementFacts` from a lowered
/// [`crate::ir::PgDefaultPrivilegesPlan`].
///
/// Reuses the shared privilege/grantee projections (`project_privilege_set`,
/// `project_grantee`) so a `PUBLIC` grantee and an `ALL` privilege surface
/// identically to a plain GRANT. The role/schema scope and the grant/revoke
/// action are the additional recognition primitives; the danger verdict (a
/// default grant to `PUBLIC`, an unscoped global default) is a YAML rule.
pub fn derive_facts_from_pg_default_privileges_plan(
    plan: &crate::ir::PgDefaultPrivilegesPlan,
    source: &str,
) -> StatementFacts {
    use crate::ast::types::DefaultPrivilegesAction as AstAction;
    use crate::ast::types::PgDefaultPrivObjectClass as AstClass;

    let action = match plan.action {
        AstAction::Grant => crate::facts::pg_default_privileges::DefaultPrivilegesAction::Grant,
        AstAction::Revoke => crate::facts::pg_default_privileges::DefaultPrivilegesAction::Revoke,
    };
    let object_class = match plan.object_class {
        AstClass::Tables => crate::facts::pg_default_privileges::PgDefaultPrivObjectClass::Tables,
        AstClass::Sequences => {
            crate::facts::pg_default_privileges::PgDefaultPrivObjectClass::Sequences
        }
        AstClass::Functions => {
            crate::facts::pg_default_privileges::PgDefaultPrivObjectClass::Functions
        }
        AstClass::Routines => {
            crate::facts::pg_default_privileges::PgDefaultPrivObjectClass::Routines
        }
        AstClass::Types => crate::facts::pg_default_privileges::PgDefaultPrivObjectClass::Types,
        AstClass::Schemas => crate::facts::pg_default_privileges::PgDefaultPrivObjectClass::Schemas,
    };
    let (privileges, all_privileges) = project_privilege_set(&plan.privileges);
    let grantees = plan
        .grantees
        .iter()
        .map(|g| project_grantee(g, source))
        .collect();
    let for_roles = plan
        .for_roles
        .iter()
        .map(|s| span_to_ident_name(*s, source))
        .collect();
    let in_schemas: Vec<_> = plan
        .in_schemas
        .iter()
        .map(|s| span_to_ident_name(*s, source))
        .collect();
    let global_scope = in_schemas.is_empty();

    let pg_default_privileges = crate::facts::PgDefaultPrivilegesFacts {
        action,
        object_class,
        privileges,
        all_privileges,
        grantees,
        for_roles,
        in_schemas,
        global_scope,
        with_grant_option: plan.with_grant_option,
        grant_option_for: plan.grant_option_for,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind: StatementKind::PgDefaultPrivileges,
        source_span: Some(plan.span),
        query: None,
        ddl: None,
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,
        mssql_backup: None,
        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: Some(pg_default_privileges),
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

// ---------------------------------------------------------------------------
// RESTORE projection.
// ---------------------------------------------------------------------------

/// Build a public `StatementFacts` from a lowered [`MssqlRestorePlan`](crate::ir::restore_plan::MssqlRestorePlan).
///
/// `RESTORE` is a top-level utility statement (not DDL), so the payload sits
/// on `StatementFacts.mssql_restore` alongside `mssql_backup`. Recognition
/// only — the source device class and the `WITH REPLACE` flag are structural;
/// which source is dangerous is a YAML verdict.
pub fn derive_facts_from_restore_plan(
    plan: &crate::ir::MssqlRestorePlan,
    _source: &str,
) -> StatementFacts {
    let target = match plan.target {
        crate::ir::RestoreTargetKind::Database => crate::facts::RestoreTarget::Database,
        crate::ir::RestoreTargetKind::Log => crate::facts::RestoreTarget::Log,
    };
    let source = plan.source.map(|src| match src {
        crate::ir::RestoreSourceKind::Disk => crate::facts::RestoreSource::Disk,
        crate::ir::RestoreSourceKind::Url => crate::facts::RestoreSource::Url,
        crate::ir::RestoreSourceKind::Tape => crate::facts::RestoreSource::Tape,
    });
    let mssql_restore = crate::facts::MssqlRestoreFacts {
        target,
        source,
        replace: plan.replace,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind: StatementKind::MssqlRestore,
        source_span: Some(plan.span),
        query: None,
        ddl: None,
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,
        mssql_backup: None,
        mssql_restore: Some(mssql_restore),
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

// ---------------------------------------------------------------------------
// Task projection.
// ---------------------------------------------------------------------------

/// Build a public `StatementFacts` directly from a lowered [`TaskPlan`].
/// Catalog is not consulted — the typed plan already carries the
/// required structural data.
pub fn derive_facts_from_task_plan(plan: &TaskPlan, _source: &str) -> StatementFacts {
    project_task_statement(plan)
}

fn project_task_statement(plan: &TaskPlan) -> StatementFacts {
    let kind = match plan.action {
        TaskAction::Create => StatementKind::CreateTask,
        TaskAction::Alter => StatementKind::AlterTask,
        TaskAction::Drop => StatementKind::DropTask,
        TaskAction::Execute => StatementKind::ExecuteTask,
    };
    let create_options = plan
        .create_options
        .as_ref()
        .map(project_task_create_options);
    let actions: Vec<TaskAlterAction> = plan
        .alter_actions
        .iter()
        .map(project_task_alter_action)
        .collect();
    let task = TaskFacts {
        create_options,
        actions,
    };
    let ddl = DdlFacts {
        targets: Vec::new(),
        action: match plan.action {
            TaskAction::Create => DdlAction::Create,
            TaskAction::Alter => DdlAction::Alter,
            TaskAction::Drop => DdlAction::Drop,
            TaskAction::Execute => DdlAction::Execute,
        },
        object_kind: ObjectKind::Task,
        target: plan.target.as_ref().map(|t| ObjectRef {
            kind: ObjectKind::Task,
            name: TableRef::new(
                IdentName::new(t.name.clone()),
                t.schema.clone().map(IdentName::new),
                t.db.clone().map(IdentName::new),
                Some(t.span),
            ),
        }),
        options: DdlOptions {
            or_replace: plan.options.or_replace,
            or_alter: plan.options.or_alter,
            if_exists: plan.options.if_exists,
            if_not_exists: plan.options.if_not_exists,
            ..DdlOptions::default()
        },
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: Some(task),
        database: None,
        warehouse: None,
        stream: None,
        schema: None,
        function: None,
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: None,
        session: None,
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: None,
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

fn project_task_create_options(shape: &crate::ir::TaskCreateOptionsShape) -> TaskCreateOptions {
    use crate::ir::TaskBodyParseStatusIr as BodyIr;
    use crate::ir::TaskOverlapPolicyIr as OvIr;
    TaskCreateOptions {
        execute_as: if shape.execute_as_present {
            Some(TaskExecuteAsClause {})
        } else {
            None
        },
        body: TaskBodyFacts {
            parse: match shape.body_parse {
                BodyIr::Parsed => TaskBodyParseStatus::Parsed,
                BodyIr::Unparseable => TaskBodyParseStatus::Unparseable,
            },
        },
        overlap_policy: shape.overlap_policy.map(|v| match v {
            OvIr::NoOverlap => TaskOverlapPolicy::NoOverlap,
            OvIr::AllowChildOverlap => TaskOverlapPolicy::AllowChildOverlap,
            OvIr::AllowAllOverlap => TaskOverlapPolicy::AllowAllOverlap,
        }),
        allow_overlapping_execution: shape.allow_overlapping_execution,
    }
}

fn project_task_alter_action(shape: &crate::ir::TaskAlterActionShape) -> TaskAlterAction {
    use crate::ir::TaskAlterActionKindIr as Ir;
    TaskAlterAction {
        kind: match shape.kind {
            Ir::Resume => TaskAlterActionKind::Resume,
            Ir::Suspend => TaskAlterActionKind::Suspend,
            Ir::AddAfter => TaskAlterActionKind::AddAfter,
            Ir::RemoveAfter => TaskAlterActionKind::RemoveAfter,
            Ir::Set => TaskAlterActionKind::Set,
            Ir::SetTag => TaskAlterActionKind::SetTag,
            Ir::SetFinalize => TaskAlterActionKind::SetFinalize,
            Ir::Unset => TaskAlterActionKind::Unset,
            Ir::UnsetTag => TaskAlterActionKind::UnsetTag,
            Ir::UnsetFinalize => TaskAlterActionKind::UnsetFinalize,
            Ir::ModifyAs => TaskAlterActionKind::ModifyAs,
            Ir::ModifyWhen => TaskAlterActionKind::ModifyWhen,
            Ir::RemoveWhen => TaskAlterActionKind::RemoveWhen,
        },
    }
}

// ---------------------------------------------------------------------------
// Alert projection.
// ---------------------------------------------------------------------------

/// Build a public `StatementFacts` directly from a lowered [`AlertPlan`].
pub fn derive_facts_from_alert_plan(plan: &AlertPlan, _source: &str) -> StatementFacts {
    let kind = match plan.action {
        AlertAction::Create => StatementKind::CreateAlert,
        AlertAction::Alter => StatementKind::AlterAlert,
        AlertAction::Drop => StatementKind::DropAlert,
    };
    let create_options = plan
        .create_options
        .as_ref()
        .map(project_alert_create_options);
    let actions: Vec<AlertAlterAction> = plan
        .alter_actions
        .iter()
        .map(project_alert_alter_action)
        .collect();
    let alert = AlertFacts {
        create_options,
        actions,
    };
    let ddl = DdlFacts {
        targets: Vec::new(),
        action: match plan.action {
            AlertAction::Create => DdlAction::Create,
            AlertAction::Alter => DdlAction::Alter,
            AlertAction::Drop => DdlAction::Drop,
        },
        object_kind: ObjectKind::Alert,
        target: plan.target.as_ref().map(|t| ObjectRef {
            kind: ObjectKind::Alert,
            name: TableRef::new(
                IdentName::new(t.name.clone()),
                t.schema.clone().map(IdentName::new),
                t.db.clone().map(IdentName::new),
                Some(t.span),
            ),
        }),
        options: DdlOptions {
            or_replace: plan.options.or_replace,
            if_exists: plan.options.if_exists,
            if_not_exists: plan.options.if_not_exists,
            ..DdlOptions::default()
        },
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: None,
        database: None,
        warehouse: None,
        stream: None,
        schema: None,
        function: None,
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: None,
        session: None,
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: None,
        alert: Some(alert),
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: None,
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

/// Build a public `StatementFacts` from a lowered [`DataMetricFunctionPlan`].
pub fn derive_facts_from_data_metric_function_plan(
    plan: &DataMetricFunctionPlan,
    source: &str,
) -> StatementFacts {
    let kind = match plan.action {
        DataMetricFunctionAction::Create => StatementKind::CreateDataMetricFunction,
        DataMetricFunctionAction::Drop => StatementKind::DropDataMetricFunction,
    };
    let dmf = DataMetricFunctionFacts {
        secure: plan.is_secure,
    };
    let ddl = DdlFacts {
        targets: Vec::new(),
        action: match plan.action {
            DataMetricFunctionAction::Create => DdlAction::Create,
            DataMetricFunctionAction::Drop => DdlAction::Drop,
        },
        object_kind: ObjectKind::DataMetricFunction,
        target: plan.target.as_ref().map(|t| ObjectRef {
            kind: ObjectKind::DataMetricFunction,
            name: parse_table_ref(t.span, source),
        }),
        options: DdlOptions {
            or_replace: plan.options.or_replace,
            if_exists: plan.options.if_exists,
            if_not_exists: plan.options.if_not_exists,
            ..DdlOptions::default()
        },
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: None,
        database: None,
        warehouse: None,
        stream: None,
        schema: None,
        function: None,
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: None,
        session: None,
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: Some(dmf),
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: None,
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

/// Build a public `StatementFacts` from a lowered
/// [`ReplicationFailoverGroupPlan`].
pub fn derive_facts_from_replication_failover_group_plan(
    plan: &ReplicationFailoverGroupPlan,
    source: &str,
) -> StatementFacts {
    let group_kind = match plan.group_type {
        ReplicationGroupType::Replication => ReplicationGroupKind::Replication,
        ReplicationGroupType::Failover => ReplicationGroupKind::Failover,
    };
    let kind = match (plan.group_type, plan.action) {
        (ReplicationGroupType::Replication, ReplicationFailoverGroupAction::Create) => {
            StatementKind::CreateReplicationGroup
        }
        (ReplicationGroupType::Replication, ReplicationFailoverGroupAction::Drop) => {
            StatementKind::DropReplicationGroup
        }
        (ReplicationGroupType::Failover, ReplicationFailoverGroupAction::Create) => {
            StatementKind::CreateFailoverGroup
        }
        (ReplicationGroupType::Failover, ReplicationFailoverGroupAction::Drop) => {
            StatementKind::DropFailoverGroup
        }
    };
    let group = ReplicationFailoverGroupFacts {
        group_kind,
        allowed_accounts: plan.allowed_accounts.clone(),
        object_types: plan.object_types.clone(),
        allowed_databases: plan.allowed_databases.clone(),
        allowed_shares: plan.allowed_shares.clone(),
        is_replica: plan.is_replica,
        has_replication_schedule: plan.has_replication_schedule,
    };
    let ddl = DdlFacts {
        targets: Vec::new(),
        action: match plan.action {
            ReplicationFailoverGroupAction::Create => DdlAction::Create,
            ReplicationFailoverGroupAction::Drop => DdlAction::Drop,
        },
        object_kind: ObjectKind::ReplicationGroup,
        target: plan.target.as_ref().map(|t| ObjectRef {
            kind: ObjectKind::ReplicationGroup,
            name: parse_table_ref(t.span, source),
        }),
        options: DdlOptions {
            if_exists: plan.options.if_exists,
            if_not_exists: plan.options.if_not_exists,
            or_replace: plan.options.or_replace,
            ..DdlOptions::default()
        },
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: None,
        database: None,
        warehouse: None,
        stream: None,
        schema: None,
        function: None,
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: None,
        session: None,
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: Some(group),
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: None,
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

/// Build a public `StatementFacts` from a lowered [`AccountPlan`]
/// (generic `ALTER ACCOUNT SET/UNSET <param>`).
pub fn derive_facts_from_account_plan(plan: &AccountPlan, _source: &str) -> StatementFacts {
    let to_param = |p: &crate::ir::AccountParameterIr| AccountParameter {
        name: p.name.clone(),
        value: p.value.clone(),
    };
    let account = AccountFacts {
        parameters_set: plan.parameters_set.iter().map(to_param).collect(),
        parameters_unset: plan.parameters_unset.iter().map(to_param).collect(),
    };
    let ddl = DdlFacts {
        targets: Vec::new(),
        action: DdlAction::Alter,
        object_kind: ObjectKind::Account,
        target: None,
        options: DdlOptions::default(),
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: None,
        database: None,
        warehouse: None,
        stream: None,
        schema: None,
        function: None,
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: None,
        session: None,
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: Some(account),
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: None,
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind: StatementKind::AlterAccount,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

fn project_alert_create_options(shape: &crate::ir::AlertCreateOptionsShape) -> AlertCreateOptions {
    use crate::ir::AlertBodyParseStatusIr as BodyIr;
    AlertCreateOptions {
        warehouse_set: shape.warehouse_present,
        schedule_set: shape.schedule_present,
        has_condition: shape.condition_present,
        action: AlertBodyFacts {
            parse: match shape.action_parse {
                BodyIr::Parsed => AlertBodyParseStatus::Parsed,
                BodyIr::Unparseable => AlertBodyParseStatus::Unparseable,
            },
        },
    }
}

fn project_alert_alter_action(shape: &crate::ir::AlertAlterActionShape) -> AlertAlterAction {
    use crate::ir::AlertAlterActionKindIr as Ir;
    AlertAlterAction {
        kind: match shape.kind {
            Ir::Resume => AlertAlterActionKind::Resume,
            Ir::Suspend => AlertAlterActionKind::Suspend,
            Ir::Set => AlertAlterActionKind::Set,
            Ir::Unset => AlertAlterActionKind::Unset,
            Ir::ModifyCondition => AlertAlterActionKind::ModifyCondition,
            Ir::ModifyAction => AlertAlterActionKind::ModifyAction,
        },
    }
}

// ---------------------------------------------------------------------------
// Function projection.
// ---------------------------------------------------------------------------

/// Build a public `StatementFacts` directly from a lowered
/// [`FunctionPlan`]. Catalog is not consulted — the typed plan already
/// carries the required structural data.
pub fn derive_facts_from_function_plan(plan: &FunctionPlan, _source: &str) -> StatementFacts {
    project_function_statement(plan)
}

fn project_function_statement(plan: &FunctionPlan) -> StatementFacts {
    let kind = match plan.action {
        FunctionAction::Create => StatementKind::CreateFunction,
        FunctionAction::Alter => StatementKind::AlterFunction,
        FunctionAction::Drop => StatementKind::DropFunction,
    };
    let body = plan.create_body.as_ref().map(project_function_body);
    let actions: Vec<FunctionAlterAction> = plan
        .alter_actions
        .iter()
        .map(project_function_alter_action)
        .collect();
    let function = FunctionFacts {
        body,
        actions,
        definer: plan.definer.as_ref().map(definer_to_facts),
        loadable_library: plan.loadable_library.clone(),
    };
    let ddl = DdlFacts {
        targets: Vec::new(),
        action: match plan.action {
            FunctionAction::Create => DdlAction::Create,
            FunctionAction::Alter => DdlAction::Alter,
            FunctionAction::Drop => DdlAction::Drop,
        },
        object_kind: ObjectKind::Function,
        target: plan.target.as_ref().map(|t| ObjectRef {
            kind: ObjectKind::Function,
            name: TableRef::new(
                IdentName::new(t.name.clone()),
                t.schema.clone().map(IdentName::new),
                t.db.clone().map(IdentName::new),
                Some(t.span),
            ),
        }),
        options: DdlOptions {
            or_replace: plan.options.or_replace,
            or_alter: plan.options.or_alter,
            if_exists: plan.options.if_exists,
            if_not_exists: plan.options.if_not_exists,
            ..DdlOptions::default()
        },
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: None,
        database: None,
        warehouse: None,
        stream: None,
        schema: None,
        function: Some(function),
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: None,
        session: None,
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: None,
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

fn project_function_body(body: &crate::ir::FunctionBodyShape) -> FunctionBodyFacts {
    FunctionBodyFacts {
        statement_kinds: body
            .statement_kinds
            .iter()
            .map(|k| match k {
                crate::ir::FunctionBodyStatementKindIr::ExecuteImmediate => {
                    FunctionBodyStatementKind::ExecuteImmediate
                }
            })
            .collect(),
        statements_count: body.statements_count,
        dynamic_sql_calls: body
            .dynamic_sql_calls
            .iter()
            .map(project_dynamic_sql_call)
            .collect(),
    }
}

fn project_function_alter_action(
    shape: &crate::ir::FunctionAlterActionShape,
) -> FunctionAlterAction {
    use crate::ir::FunctionAlterActionKindIr as Ir;
    FunctionAlterAction {
        kind: match shape.kind {
            Ir::Rename => FunctionAlterActionKind::Rename,
            Ir::SetSecure => FunctionAlterActionKind::SetSecure,
            Ir::UnsetSecure => FunctionAlterActionKind::UnsetSecure,
            Ir::SetProperties => FunctionAlterActionKind::SetProperties,
            Ir::UnsetProperties => FunctionAlterActionKind::UnsetProperties,
            Ir::SetTag => FunctionAlterActionKind::SetTag,
            Ir::UnsetTag => FunctionAlterActionKind::UnsetTag,
            Ir::SetApiIntegration => FunctionAlterActionKind::SetApiIntegration,
            Ir::SetHeaders => FunctionAlterActionKind::SetHeaders,
            Ir::SetContextHeaders => FunctionAlterActionKind::SetContextHeaders,
            Ir::SetMaxBatchRows => FunctionAlterActionKind::SetMaxBatchRows,
            Ir::SetCompression => FunctionAlterActionKind::SetCompression,
            Ir::SetRequestTranslator => FunctionAlterActionKind::SetRequestTranslator,
            Ir::SetResponseTranslator => FunctionAlterActionKind::SetResponseTranslator,
            Ir::Unknown => FunctionAlterActionKind::Unknown,
        },
        properties: shape.properties.as_ref().map(project_function_properties),
    }
}

fn project_function_properties(
    shape: &crate::ir::FunctionPropertiesShape,
) -> FunctionPropertiesFacts {
    use crate::ir::FunctionPropertyKeyIr as Ir;
    FunctionPropertiesFacts {
        keys: shape
            .keys
            .iter()
            .map(|k| match k {
                Ir::ExternalAccessIntegrations => FunctionPropertyKey::ExternalAccessIntegrations,
                Ir::Secrets => FunctionPropertyKey::Secrets,
                Ir::LogLevel => FunctionPropertyKey::LogLevel,
                Ir::TraceLevel => FunctionPropertyKey::TraceLevel,
                Ir::Comment => FunctionPropertyKey::Comment,
                Ir::Other => FunctionPropertyKey::Other,
            })
            .collect(),
    }
}

// ---------------------------------------------------------------------------
// Procedure projection.
// ---------------------------------------------------------------------------

/// Build a public `StatementFacts` directly from a lowered
/// [`HandlerPlan`]. Catalog is not consulted — the typed plan already
/// carries the required structural data.
pub fn derive_facts_from_handler_plan(plan: &HandlerPlan, _source: &str) -> StatementFacts {
    project_handler_statement(plan)
}

fn project_handler_statement(plan: &HandlerPlan) -> StatementFacts {
    let handler = HandlerFacts {
        handler_type: match plan.handler_type {
            HandlerTypeIr::Simple => HandlerType::Simple,
            HandlerTypeIr::Exit => HandlerType::Exit,
            HandlerTypeIr::Continue => HandlerType::Continue,
        },
        conditions: plan
            .conditions
            .iter()
            .map(|c| match c {
                HandlerConditionIr::SqlException => HandlerCondition::SqlException,
                HandlerConditionIr::SqlWarning => HandlerCondition::SqlWarning,
                HandlerConditionIr::NotFound => HandlerCondition::NotFound,
                HandlerConditionIr::SqlState => HandlerCondition::SqlState,
                HandlerConditionIr::NamedCondition => HandlerCondition::NamedCondition,
            })
            .collect(),
        body: project_handler_body(&plan.body),
    };
    StatementFacts {
        declare: None,
        call: None,
        kind: StatementKind::DeclareHandler,
        source_span: Some(plan.span),
        query: None,
        ddl: None,
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: Some(handler),
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

fn project_handler_body(body: &HandlerBodyShapeIr) -> HandlerBody {
    HandlerBody {
        statement_kinds: body
            .statement_kinds_transitive
            .iter()
            .map(|k| match k {
                HandlerBodyStatementKindIr::Resignal => HandlerBodyStatementKind::Resignal,
                HandlerBodyStatementKindIr::Signal => HandlerBodyStatementKind::Signal,
                HandlerBodyStatementKindIr::GetDiagnostics => {
                    HandlerBodyStatementKind::GetDiagnostics
                }
            })
            .collect(),
    }
}

/// Build a public `StatementFacts` directly from a lowered
/// [`ProcedurePlan`]. Catalog is not consulted — the typed plan
/// already carries the required structural data.
pub fn derive_facts_from_procedure_plan(plan: &ProcedurePlan, _source: &str) -> StatementFacts {
    project_procedure_statement(plan)
}

fn project_procedure_statement(plan: &ProcedurePlan) -> StatementFacts {
    let kind = match plan.action {
        ProcedureAction::Create => StatementKind::CreateProcedure,
        ProcedureAction::Alter => StatementKind::AlterProcedure,
        ProcedureAction::Drop => StatementKind::DropProcedure,
    };
    let body = plan.create_body.as_ref().map(project_procedure_body);
    let actions: Vec<ProcedureAlterAction> = plan
        .alter_actions
        .iter()
        .map(project_procedure_alter_action)
        .collect();
    let procedure = ProcedureFacts {
        body,
        actions,
        definer: plan.definer.as_ref().map(definer_to_facts),
        runs_as: plan.runs_as.map(project_execute_as_mode),
    };
    let ddl = DdlFacts {
        targets: Vec::new(),
        action: match plan.action {
            ProcedureAction::Create => DdlAction::Create,
            ProcedureAction::Alter => DdlAction::Alter,
            ProcedureAction::Drop => DdlAction::Drop,
        },
        object_kind: ObjectKind::Procedure,
        target: plan.target.as_ref().map(|t| ObjectRef {
            kind: ObjectKind::Procedure,
            name: TableRef::new(
                IdentName::new(t.name.clone()),
                t.schema.clone().map(IdentName::new),
                t.db.clone().map(IdentName::new),
                Some(t.span),
            ),
        }),
        options: DdlOptions {
            or_replace: plan.options.or_replace,
            or_alter: plan.options.or_alter,
            if_exists: plan.options.if_exists,
            if_not_exists: plan.options.if_not_exists,
            ..DdlOptions::default()
        },
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: None,
        database: None,
        warehouse: None,
        stream: None,
        schema: None,
        function: None,
        procedure: Some(procedure),
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: None,
        session: None,
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: None,
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

pub(crate) fn project_procedure_body(body: &ProcedureBodyShape) -> ProcedureBodyFacts {
    ProcedureBodyFacts {
        statement_kinds: body
            .statement_kinds
            .iter()
            .map(|k| match k {
                ProcedureBodyStatementKindIr::ExecuteImmediate => {
                    ProcedureBodyStatementKind::ExecuteImmediate
                }
            })
            .collect(),
        statements_count: body.statements_count,
        dynamic_sql_calls: body
            .dynamic_sql_calls
            .iter()
            .map(project_dynamic_sql_call)
            .collect(),
        execute_as_mode: body.execute_as_mode.map(project_execute_as_mode),
    }
}

pub(crate) fn project_dynamic_sql_call(
    call: &crate::ir::dynamic_sql::DynamicSqlCallIr,
) -> DynamicSqlCall {
    use crate::facts::ddl::{
        DynamicSqlSplice, DynamicSqlSplicePosition, DynamicSqlSpliceQuoting, TaintWitnessRoleFact,
        TaintWitnessSpanFact,
    };
    use crate::ir::dynamic_sql::TaintWitnessRole;
    use crate::ir::dynamic_sql::{
        DynamicSqlArgIr, DynamicSqlParameterizationIr, DynamicSqlSurfaceIr, HoleQuoting,
        SplicePosition,
    };
    DynamicSqlCall {
        surface: match call.surface {
            DynamicSqlSurfaceIr::ExecuteImmediate => DynamicSqlSurface::ExecuteImmediate,
            DynamicSqlSurfaceIr::MssqlExecDynamic => DynamicSqlSurface::MssqlExecDynamic,
            DynamicSqlSurfaceIr::MssqlSpExecutesql => DynamicSqlSurface::MssqlSpExecutesql,
            DynamicSqlSurfaceIr::Prepare => DynamicSqlSurface::Prepare,
            DynamicSqlSurfaceIr::DblinkExec => DynamicSqlSurface::DblinkExec,
            DynamicSqlSurfaceIr::MssqlExecProcCall => DynamicSqlSurface::MssqlExecProcCall,
            DynamicSqlSurfaceIr::CallProcCall => DynamicSqlSurface::CallProcCall,
            DynamicSqlSurfaceIr::PsqlGexec => DynamicSqlSurface::PsqlGexec,
        },
        argument: match call.argument {
            DynamicSqlArgIr::Literal => DynamicSqlArg::Literal,
            DynamicSqlArgIr::Variable => DynamicSqlArg::Variable,
            DynamicSqlArgIr::Concat => DynamicSqlArg::Concat,
            DynamicSqlArgIr::ConcatQuoted => DynamicSqlArg::ConcatQuoted,
            DynamicSqlArgIr::Format => DynamicSqlArg::Format,
            DynamicSqlArgIr::FormatQuoted => DynamicSqlArg::FormatQuoted,
            DynamicSqlArgIr::Unknown => DynamicSqlArg::Unknown,
        },
        parameterization: match call.parameterization {
            DynamicSqlParameterizationIr::None => DynamicSqlParameterization::None,
            DynamicSqlParameterizationIr::PositionalUsing => {
                DynamicSqlParameterization::PositionalUsing
            }
            DynamicSqlParameterizationIr::NamedParams => DynamicSqlParameterization::NamedParams,
            DynamicSqlParameterizationIr::NotApplicable => {
                DynamicSqlParameterization::NotApplicable
            }
        },
        argument_parameter: call.argument_parameter.as_deref().map(IdentName::new),
        provenance: call
            .provenance
            .iter()
            .map(|w| TaintWitnessSpanFact {
                start: w.span.start,
                end: w.span.end,
                role: match w.role {
                    TaintWitnessRole::Assignment => TaintWitnessRoleFact::Assignment,
                    TaintWitnessRole::CallSite => TaintWitnessRoleFact::CallSite,
                    TaintWitnessRole::Sink => TaintWitnessRoleFact::Sink,
                },
            })
            .collect(),
        taint_splices: call
            .splices
            .iter()
            .map(|s| DynamicSqlSplice {
                position: match s.position {
                    SplicePosition::StringLiteral => DynamicSqlSplicePosition::StringLiteral,
                    SplicePosition::Identifier => DynamicSqlSplicePosition::Identifier,
                    SplicePosition::Bare => DynamicSqlSplicePosition::Bare,
                    SplicePosition::Unknown => DynamicSqlSplicePosition::Unknown,
                },
                quoting: match s.quoting {
                    HoleQuoting::Raw => DynamicSqlSpliceQuoting::Raw,
                    HoleQuoting::IdentQuoter => DynamicSqlSpliceQuoting::IdentifierQuoted,
                    HoleQuoting::LitQuoter => DynamicSqlSpliceQuoting::LiteralQuoted,
                },
            })
            .collect(),
    }
}

fn project_procedure_alter_action(shape: &ProcedureAlterActionShape) -> ProcedureAlterAction {
    ProcedureAlterAction {
        kind: match shape.kind {
            ProcedureAlterActionKindIr::Rename => ProcedureAlterActionKind::Rename,
            ProcedureAlterActionKindIr::SetSecure => ProcedureAlterActionKind::SetSecure,
            ProcedureAlterActionKindIr::UnsetSecure => ProcedureAlterActionKind::UnsetSecure,
            ProcedureAlterActionKindIr::SetProperties => ProcedureAlterActionKind::SetProperties,
            ProcedureAlterActionKindIr::UnsetComment => ProcedureAlterActionKind::UnsetComment,
            ProcedureAlterActionKindIr::SetTag => ProcedureAlterActionKind::SetTag,
            ProcedureAlterActionKindIr::UnsetTag => ProcedureAlterActionKind::UnsetTag,
            ProcedureAlterActionKindIr::ExecuteAs => ProcedureAlterActionKind::ExecuteAs,
            ProcedureAlterActionKindIr::Unknown => ProcedureAlterActionKind::Unknown,
        },
        properties: shape.properties.as_ref().map(project_procedure_properties),
        execute_as_mode: shape.execute_as_mode.map(project_execute_as_mode),
    }
}

fn project_procedure_properties(shape: &ProcedurePropertiesShape) -> ProcedurePropertiesFacts {
    ProcedurePropertiesFacts {
        keys: shape
            .keys
            .iter()
            .map(|k| match k {
                ProcedurePropertyKeyIr::ExternalAccessIntegrations => {
                    ProcedurePropertyKey::ExternalAccessIntegrations
                }
                ProcedurePropertyKeyIr::Secrets => ProcedurePropertyKey::Secrets,
                ProcedurePropertyKeyIr::LogLevel => ProcedurePropertyKey::LogLevel,
                ProcedurePropertyKeyIr::TraceLevel => ProcedurePropertyKey::TraceLevel,
                ProcedurePropertyKeyIr::Comment => ProcedurePropertyKey::Comment,
                ProcedurePropertyKeyIr::AutoEventLogging => ProcedurePropertyKey::AutoEventLogging,
                ProcedurePropertyKeyIr::Other => ProcedurePropertyKey::Other,
            })
            .collect(),
    }
}

fn project_execute_as_mode(mode: crate::ast::ExecuteAsMode) -> ProcedureExecuteAsMode {
    use crate::ast::ExecuteAsMode as M;
    match mode {
        M::Owner => ProcedureExecuteAsMode::Owner,
        M::Caller => ProcedureExecuteAsMode::Caller,
        M::RestrictedCaller => ProcedureExecuteAsMode::RestrictedCaller,
    }
}

// ---------------------------------------------------------------------------
// Database projection.
// ---------------------------------------------------------------------------

/// Build a public `StatementFacts` directly from a lowered
/// [`DatabasePlan`]. Catalog is not consulted — the typed plan already
/// carries the required structural data.
pub fn derive_facts_from_database_plan(plan: &DatabasePlan, _source: &str) -> StatementFacts {
    project_database_statement(plan)
}

/// Project one `IrDatabaseCreateOrigin` onto its public mirror. Single
/// boundary point — the public closed enum is curated in
/// `src/facts/ddl.rs::DatabaseCreateOrigin`.
fn project_database_create_origin(o: IrDatabaseCreateOrigin) -> DatabaseCreateOrigin {
    use DatabaseCreateOrigin as P;
    use IrDatabaseCreateOrigin as I;
    match o {
        I::Standard => P::Standard,
        I::Clone => P::Clone,
        I::FromShare => P::FromShare,
        I::FromListing => P::FromListing,
        I::AsReplica => P::AsReplica,
        I::FromBackup => P::FromBackup,
    }
}

/// Project one [`IrDatabaseAlterActionDetail`] onto its public mirror.
/// Single boundary point. The public type
/// [`DatabaseAlterAction`] is a struct (not an enum) with a `kind`
/// discriminator + optional per-kind sub-facts; see
/// `src/facts/ddl.rs::DatabaseAlterAction`.
fn project_database_alter_action(detail: &IrDatabaseAlterActionDetail) -> DatabaseAlterAction {
    let kind = project_database_alter_action_kind(detail.kind);
    let properties = detail
        .properties
        .as_ref()
        .map(|keys| DatabasePropertiesFacts {
            keys: keys
                .iter()
                .copied()
                .map(project_database_property_key)
                .collect(),
            switches: detail
                .switches
                .iter()
                .map(|s| crate::facts::ddl::DatabasePropertySwitch {
                    key: project_database_property_key(s.key),
                    value: match s.value {
                        crate::ir::database_plan::IrDatabaseSwitchValue::On => {
                            crate::facts::ddl::DatabaseSwitchValue::On
                        }
                        crate::ir::database_plan::IrDatabaseSwitchValue::Off => {
                            crate::facts::ddl::DatabaseSwitchValue::Off
                        }
                    },
                })
                .collect(),
            data_retention_days: detail.data_retention_days,
        });
    DatabaseAlterAction { kind, properties }
}

fn project_database_alter_action_kind(a: IrDatabaseAlterAction) -> DatabaseAlterActionKind {
    use DatabaseAlterActionKind as P;
    use IrDatabaseAlterAction as I;
    match a {
        I::RenameTo => P::RenameTo,
        I::SwapWith => P::SwapWith,
        I::SetProperties => P::SetProperties,
        I::UnsetProperties => P::UnsetProperties,
        I::SetTag => P::SetTag,
        I::UnsetTag => P::UnsetTag,
        I::SetComment => P::SetComment,
        I::UnsetComment => P::UnsetComment,
        I::EnableReplication => P::EnableReplication,
        I::DisableReplication => P::DisableReplication,
        I::EnableFailover => P::EnableFailover,
        I::DisableFailover => P::DisableFailover,
        I::Primary => P::Primary,
        I::Refresh => P::Refresh,
        I::Opaque => P::Opaque,
    }
}

fn project_database_property_key(p: IrDatabaseProperty) -> DatabasePropertyKey {
    use DatabasePropertyKey as P;
    use IrDatabaseProperty as I;
    match p {
        I::DataRetentionTimeInDays => P::DataRetentionTimeInDays,
        I::Trustworthy => P::Trustworthy,
        I::Encryption => P::Encryption,
        I::DbChaining => P::DbChaining,
        I::Other => P::Other,
    }
}

fn project_database_statement(plan: &DatabasePlan) -> StatementFacts {
    let kind = match plan.action {
        DatabaseAction::Create => StatementKind::CreateDatabase,
        DatabaseAction::Alter => StatementKind::AlterDatabase,
        DatabaseAction::Drop => StatementKind::DropDatabase,
    };
    let database = DatabaseFacts {
        create_origin: plan.create_origin.map(project_database_create_origin),
        actions: plan
            .actions
            .iter()
            .map(project_database_alter_action)
            .collect(),
    };
    let ddl = DdlFacts {
        targets: Vec::new(),
        action: match plan.action {
            DatabaseAction::Create => DdlAction::Create,
            DatabaseAction::Alter => DdlAction::Alter,
            DatabaseAction::Drop => DdlAction::Drop,
        },
        object_kind: ObjectKind::Database,
        target: plan.target.as_ref().map(|t| ObjectRef {
            kind: ObjectKind::Database,
            name: TableRef::new(
                IdentName::new(t.name.clone()),
                t.schema.clone().map(IdentName::new),
                t.db.clone().map(IdentName::new),
                Some(t.span),
            ),
        }),
        options: DdlOptions {
            or_replace: plan.options.or_replace,
            if_exists: plan.options.if_exists,
            if_not_exists: plan.options.if_not_exists,
            transient: plan.options.transient,
            ..DdlOptions::default()
        },
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: None,
        database: Some(database),
        warehouse: None,
        stream: None,
        schema: None,
        function: None,
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: None,
        session: None,
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: None,
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

// ---------------------------------------------------------------------------
// Warehouse projection.
// ---------------------------------------------------------------------------

/// Build a public `StatementFacts` directly from a lowered
/// [`WarehousePlan`]. Catalog is not consulted — the typed plan
/// already carries the required structural data.
pub fn derive_facts_from_warehouse_plan(plan: &WarehousePlan, _source: &str) -> StatementFacts {
    project_warehouse_statement(plan)
}

fn project_warehouse_statement(plan: &WarehousePlan) -> StatementFacts {
    let kind = match plan.action {
        WarehouseAction::Create => StatementKind::CreateWarehouse,
        WarehouseAction::Alter => StatementKind::AlterWarehouse,
        WarehouseAction::Drop => StatementKind::DropWarehouse,
    };
    let warehouse = WarehouseFacts {
        large_size: plan.create_flags.large_size,
        snowpark_optimized: plan.create_flags.snowpark_optimized,
        auto_suspend_zero: plan.create_flags.auto_suspend_zero,
        resource_monitor_set: plan.create_flags.resource_monitor_set,
        multi_cluster: plan.create_flags.multi_cluster,
        suspended: plan.alter_flags.suspended,
        resumed: plan.alter_flags.resumed,
        queries_aborted: plan.alter_flags.queries_aborted,
        renamed: plan.alter_flags.renamed,
        set: plan.alter_flags.set,
        set_changes_size: plan.alter_flags.set_changes_size,
        tag_set: plan.alter_flags.tag_set,
        tag_unset: plan.alter_flags.tag_unset,
    };
    let ddl = DdlFacts {
        targets: Vec::new(),
        action: match plan.action {
            WarehouseAction::Create => DdlAction::Create,
            WarehouseAction::Alter => DdlAction::Alter,
            WarehouseAction::Drop => DdlAction::Drop,
        },
        object_kind: ObjectKind::Warehouse,
        target: plan.target.as_ref().map(|t| ObjectRef {
            kind: ObjectKind::Warehouse,
            name: TableRef::new(
                IdentName::new(t.name.clone()),
                t.schema.clone().map(IdentName::new),
                t.db.clone().map(IdentName::new),
                Some(t.span),
            ),
        }),
        options: DdlOptions {
            or_replace: plan.options.or_replace,
            if_exists: plan.options.if_exists,
            if_not_exists: plan.options.if_not_exists,
            ..DdlOptions::default()
        },
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: None,
        database: None,
        warehouse: Some(warehouse),
        stream: None,
        schema: None,
        function: None,
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: None,
        session: None,
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: None,
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

// ---------------------------------------------------------------------------
// Policy-attachment projection.
// ---------------------------------------------------------------------------

/// Build a public `StatementFacts` directly from a lowered
/// [`PolicyAttachmentPlan`]. Catalog is not consulted — the closed-enum
/// AST already carries the full structural data the AUTHPOL-attachment
/// rules need.
///
/// Standalone entry point used by the `analyze_policy_attachment_facts`
/// pipeline.
pub fn derive_facts_from_policy_attachment_plan(
    plan: &PolicyAttachmentPlan,
    source: &str,
) -> StatementFacts {
    project_policy_attachment_statement(plan, source)
}

fn project_policy_attachment_statement(
    plan: &PolicyAttachmentPlan,
    source: &str,
) -> StatementFacts {
    let kind = match plan.principal {
        IrPolicyAttachmentPrincipal::User { .. } => StatementKind::AlterUser,
        IrPolicyAttachmentPrincipal::Account => StatementKind::AlterAccount,
    };
    let attachment = project_policy_attachment_facts(plan, source);
    StatementFacts {
        declare: None,
        call: None,
        kind,
        source_span: Some(plan.span),
        query: None,
        ddl: None,
        privilege: None,
        policy: None,
        integration: None,
        policy_attachment: Some(attachment),
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        diff: None,
    }
}

fn project_policy_attachment_facts(
    plan: &PolicyAttachmentPlan,
    source: &str,
) -> PolicyAttachmentFacts {
    let verb = match plan.verb {
        IrPolicyAttachmentVerb::Set => PolicyAttachmentVerb::Set,
        IrPolicyAttachmentVerb::Unset => PolicyAttachmentVerb::Unset,
    };
    let (principal_kind, principal_name) = match &plan.principal {
        IrPolicyAttachmentPrincipal::User { name_span } => (
            PolicyAttachmentPrincipalKind::User,
            Some(span_to_ident_name(*name_span, source)),
        ),
        IrPolicyAttachmentPrincipal::Account => (PolicyAttachmentPrincipalKind::Account, None),
    };
    let (target_kind, policy) = match &plan.target {
        IrPolicyAttachmentTarget::AuthenticationPolicy { policy_name_span } => (
            PolicyAttachmentTargetKind::AuthenticationPolicy,
            policy_name_span.map(|sp| parse_table_ref(sp, source)),
        ),
    };
    PolicyAttachmentFacts {
        verb,
        principal_kind,
        principal_name,
        target_kind,
        policy,
    }
}

// ---------------------------------------------------------------------------
// Policy DDL dialect-origin tag.
// ---------------------------------------------------------------------------

/// Dialect-of-origin discriminator for [`crate::ir::PolicyPlan`].
///
/// Most policy DDL statements (CREATE/ALTER/DROP MASKING / NETWORK /
/// SESSION / PASSWORD / AUTHENTICATION / AGGREGATION / PROJECTION /
/// ROW ACCESS POLICY) project 1:1 from `PolicyKindIr` to a single
/// `StatementKind`. Row-access policy is the exception: PostgreSQL
/// `CREATE/ALTER/DROP POLICY name ON table` and Snowflake / BigQuery
/// `CREATE/ALTER/DROP ROW ACCESS POLICY name` both share
/// `PolicyKindIr::RowAccess` in the IR (correctly — they are the same
/// concept) but project to **different** `StatementKind`s
/// (`Pg{Create,Alter,Drop}Policy` vs `{Create,Alter,Drop}RowAccessPolicy`)
/// so the right family of rules fires.
///
/// The IR plan itself stays dialect-clean. The dialect is
/// recovered at the `analyze_ddl_facts` dispatch site (which knows the
/// dialect via the originating `AstStmt` variant — `CreatePgPolicy` is
/// constructed only by the PG parser) and passed explicitly to
/// [`derive_facts_from_policy_plan`]. Same pattern as [`PgDdlKind`] /
/// [`MssqlDdlKind`] for DDL statements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PolicyDialectOrigin {
    /// Snowflake / BigQuery policy DDL. The default for every policy
    /// kind except PG row-level security.
    Standard,
    /// PostgreSQL `CREATE/ALTER/DROP POLICY name ON table` row-level
    /// security. Routes through `PolicyKindIr::RowAccess` in the IR
    /// but projects to `Pg{Create,Alter,Drop}Policy` StatementKind.
    Postgres,
}

// ---------------------------------------------------------------------------
// MSSQL DDL projection (T-SQL Login / User / External Model / Bulk Insert).
// ---------------------------------------------------------------------------

/// Narrow closed enum naming the MSSQL DDL statement kinds that
/// [`derive_facts_from_mssql_ddl_plan`] dispatches on. Authoring this
/// as a separate enum (rather than matching the wide
/// [`StatementKind`] taxonomy) lets the projection enumerate every
/// supported kind without a `_ =>` catch-all on a domain enum.
///
/// Callers ([`crate::Engine::analyze_ddl_facts`]) resolve the variant
/// from the originating `AstStmt` and pass it explicitly; the
/// projection then maps to the public `StatementKind` + `DdlAction`
/// exhaustively.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MssqlDdlKind {
    BulkInsert,
    CreateExternalModel,
    AlterExternalModel,
    DropExternalModel,
    CreateLogin,
    CreateUser,
    /// T-SQL `ALTER LOGIN` — password / default-schema / enable / disable.
    AlterLogin,
    /// T-SQL `DROP LOGIN`.
    DropLogin,
    SetOption,
    /// T-SQL `DROP TRIGGER` — DML / DDL / logon trigger removal.
    DropTrigger,
    /// T-SQL `{ ENABLE | DISABLE } TRIGGER … ON …`.
    TriggerState,
}

/// Build a public `StatementFacts` directly from a lowered
/// [`crate::ir::DdlPlan`] for one of the MSSQL DDL statements:
/// `BULK INSERT`, `CREATE/ALTER/DROP EXTERNAL MODEL`, `CREATE LOGIN`,
/// `CREATE USER`, `SET <option>`. The caller selects the
/// [`MssqlDdlKind`] from the originating `AstStmt` variant.
///
/// Standalone entry point used by [`crate::Engine::analyze_ddl_facts`].
pub fn derive_facts_from_mssql_ddl_plan(
    plan: &crate::ir::DdlPlan,
    kind: MssqlDdlKind,
    _source: &str,
) -> StatementFacts {
    let stmt_kind = match kind {
        MssqlDdlKind::BulkInsert => StatementKind::MssqlBulkInsert,
        MssqlDdlKind::CreateExternalModel => StatementKind::MssqlCreateExternalModel,
        MssqlDdlKind::AlterExternalModel => StatementKind::MssqlAlterExternalModel,
        MssqlDdlKind::DropExternalModel => StatementKind::MssqlDropExternalModel,
        MssqlDdlKind::CreateLogin => StatementKind::MssqlCreateLogin,
        MssqlDdlKind::CreateUser => StatementKind::MssqlCreateUser,
        MssqlDdlKind::AlterLogin => StatementKind::MssqlAlterLogin,
        MssqlDdlKind::DropLogin => StatementKind::MssqlDropLogin,
        MssqlDdlKind::SetOption => StatementKind::MssqlSetOption,
        MssqlDdlKind::DropTrigger => StatementKind::MssqlDropTrigger,
        MssqlDdlKind::TriggerState => StatementKind::MssqlTriggerState,
    };
    let object_kind = match kind {
        MssqlDdlKind::CreateUser => ObjectKind::User,
        MssqlDdlKind::DropTrigger | MssqlDdlKind::TriggerState => ObjectKind::Trigger,
        MssqlDdlKind::BulkInsert
        | MssqlDdlKind::CreateExternalModel
        | MssqlDdlKind::AlterExternalModel
        | MssqlDdlKind::DropExternalModel
        | MssqlDdlKind::CreateLogin
        | MssqlDdlKind::AlterLogin
        | MssqlDdlKind::DropLogin
        | MssqlDdlKind::SetOption => ObjectKind::Generic,
    };
    let action = match kind {
        MssqlDdlKind::CreateExternalModel
        | MssqlDdlKind::CreateLogin
        | MssqlDdlKind::CreateUser => DdlAction::Create,
        MssqlDdlKind::AlterExternalModel
        | MssqlDdlKind::AlterLogin
        | MssqlDdlKind::TriggerState => DdlAction::Alter,
        MssqlDdlKind::DropExternalModel | MssqlDdlKind::DropTrigger | MssqlDdlKind::DropLogin => {
            DdlAction::Drop
        }
        MssqlDdlKind::BulkInsert => DdlAction::BulkLoad,
        MssqlDdlKind::SetOption => DdlAction::Configure,
    };
    // A trigger-state statement's target is the table or view its triggers
    // are on, as for PostgreSQL's `ALTER TABLE … TRIGGER`.
    let target_kind = match kind {
        MssqlDdlKind::TriggerState => ObjectKind::Generic,
        MssqlDdlKind::BulkInsert
        | MssqlDdlKind::CreateExternalModel
        | MssqlDdlKind::AlterExternalModel
        | MssqlDdlKind::DropExternalModel
        | MssqlDdlKind::CreateLogin
        | MssqlDdlKind::CreateUser
        | MssqlDdlKind::AlterLogin
        | MssqlDdlKind::DropLogin
        | MssqlDdlKind::SetOption
        | MssqlDdlKind::DropTrigger => object_kind,
    };
    let target = plan.target.as_ref().map(|t| ObjectRef {
        kind: target_kind,
        name: TableRef::new(
            IdentName::new(t.name.clone()),
            t.schema.clone().map(IdentName::new),
            t.db.clone().map(IdentName::new),
            Some(t.span),
        ),
    });
    let mssql_set_option =
        plan.mssql_set_option
            .map(|detail| crate::facts::ddl::MssqlSetOptionFacts {
                option_kind: project_ir_set_option_kind(detail.option_kind),
                value: project_ir_set_option_value(detail.value),
                isolation_level: detail.isolation_level.map(project_ir_isolation_level),
            });
    let mssql_principal =
        plan.mssql_principal_source
            .map(|source| crate::facts::ddl::MssqlPrincipalFacts {
                source: project_ir_principal_source(source),
            });
    let principal = plan
        .principal_options
        .as_ref()
        .map(project_principal_options);
    let ddl = DdlFacts {
        targets: Vec::new(),
        action,
        object_kind,
        target,
        options: DdlOptions {
            or_replace: plan.options.or_replace,
            if_exists: plan.options.if_exists,
            if_not_exists: plan.options.if_not_exists,
            ..DdlOptions::default()
        },
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: None,
        database: None,
        warehouse: None,
        stream: None,
        schema: None,
        function: None,
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option,
        mssql_principal,
        principal,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: plan.pg_trigger_state.as_ref().map(|detail| {
            crate::facts::ddl::TriggerStateFacts {
                action: project_ir_trigger_state_action(detail.action),
            }
        }),
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: None,
        session: None,
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: None,
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind: stmt_kind,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        diff: None,
    }
}

/// IR → public projection for MSSQL `SET <option>` keyword identity.
/// Closed-enum exhaustive translation at the facts boundary.
fn project_ir_set_option_kind(
    k: crate::ir::ddl_plan::MssqlSetOptionKindIr,
) -> crate::facts::ddl::MssqlSetOptionKind {
    use crate::facts::ddl::MssqlSetOptionKind as P;
    use crate::ir::ddl_plan::MssqlSetOptionKindIr as I;
    match k {
        I::IdentityInsert => P::IdentityInsert,
        I::NoCount => P::NoCount,
        I::XactAbort => P::XactAbort,
        I::AnsiNulls => P::AnsiNulls,
        I::QuotedIdentifier => P::QuotedIdentifier,
        I::ArithAbort => P::ArithAbort,
        I::ConcatNullYieldsNull => P::ConcatNullYieldsNull,
        I::LockTimeout => P::LockTimeout,
        I::DeadlockPriority => P::DeadlockPriority,
        I::RowCount => P::RowCount,
        I::TransactionIsolationLevel => P::TransactionIsolationLevel,
        I::Other => P::Other,
    }
}

fn project_ir_set_option_value(
    v: crate::ir::ddl_plan::MssqlSetOptionValueIr,
) -> crate::facts::ddl::MssqlSetOptionValue {
    use crate::facts::ddl::MssqlSetOptionValue as P;
    use crate::ir::ddl_plan::MssqlSetOptionValueIr as I;
    match v {
        I::On => P::On,
        I::Off => P::Off,
        I::NumericLiteral => P::NumericLiteral,
        I::Identifier => P::Identifier,
        I::Unparsed => P::Unparsed,
    }
}

fn project_ir_isolation_level(
    level: crate::ir::ddl_plan::MssqlIsolationLevelIr,
) -> crate::facts::ddl::MssqlIsolationLevel {
    use crate::facts::ddl::MssqlIsolationLevel as P;
    use crate::ir::ddl_plan::MssqlIsolationLevelIr as I;
    match level {
        I::ReadUncommitted => P::ReadUncommitted,
        I::ReadCommitted => P::ReadCommitted,
        I::RepeatableRead => P::RepeatableRead,
        I::Snapshot => P::Snapshot,
        I::Serializable => P::Serializable,
    }
}

fn project_ir_principal_source(
    s: crate::ir::ddl_plan::MssqlPrincipalSourceIr,
) -> crate::facts::ddl::MssqlPrincipalSource {
    use crate::facts::ddl::MssqlPrincipalSource as P;
    use crate::ir::ddl_plan::MssqlPrincipalSourceIr as I;
    match s {
        I::FromExternalProvider => P::FromExternalProvider,
        I::WithPassword => P::WithPassword,
        I::FromCertificate => P::FromCertificate,
        I::FromAsymmetricKey => P::FromAsymmetricKey,
        I::FromWindows => P::FromWindows,
        I::ForLogin => P::ForLogin,
        I::WithoutLogin => P::WithoutLogin,
        I::Unparsed => P::Unparsed,
    }
}

fn project_ir_principal_kind(
    k: crate::ir::ddl_plan::PrincipalKindIr,
) -> crate::facts::ddl::PrincipalKindFacts {
    use crate::facts::ddl::PrincipalKindFacts as F;
    use crate::ir::ddl_plan::PrincipalKindIr as I;
    match k {
        I::User => F::User,
        I::Role => F::Role,
        I::Login => F::Login,
        I::Group => F::Group,
        I::ApplicationRole => F::ApplicationRole,
        I::DatabaseRole => F::DatabaseRole,
    }
}

fn project_principal_options(
    options: &crate::ir::ddl_plan::PrincipalOptionsIr,
) -> crate::facts::ddl::PrincipalFacts {
    use crate::facts::ddl::{
        PrincipalEnabledStateFacts, PrincipalMembershipAction, PrincipalMembershipFacts,
    };
    use crate::ir::ddl_plan::{PrincipalEnabledStateIr, PrincipalMembershipActionIr};
    crate::facts::ddl::PrincipalFacts {
        kind: project_ir_principal_kind(options.principal_kind),
        password_literal: options.password_literal.clone(),
        password_set: options.password_set,
        mysql_host: options.mysql_host.clone(),
        server_scope: options.server_scope,
        membership: options
            .membership
            .as_ref()
            .map(|m| PrincipalMembershipFacts {
                action: match m.action {
                    PrincipalMembershipActionIr::AddMember => PrincipalMembershipAction::AddMember,
                    PrincipalMembershipActionIr::DropMember => {
                        PrincipalMembershipAction::DropMember
                    }
                },
                member: IdentName::new(m.member.clone()),
            }),
        enabled_state: options.enabled_state.map(|s| match s {
            PrincipalEnabledStateIr::Enable => PrincipalEnabledStateFacts::Enable,
            PrincipalEnabledStateIr::Disable => PrincipalEnabledStateFacts::Disable,
        }),
        role_attributes: options
            .role_attributes
            .iter()
            .map(|a| crate::facts::ddl::RoleAttributeFacts {
                kind: project_ir_role_attribute_kind(a.kind),
                negated: a.negated,
            })
            .collect(),
        snowflake_user: options
            .snowflake_user
            .as_ref()
            .map(project_snowflake_user_facts),
        mssql_login: options
            .mssql_login
            .map(|m| crate::facts::ddl::MssqlLoginFacts {
                check_policy: m.check_policy,
                check_expiration: m.check_expiration,
            }),
    }
}

fn project_snowflake_user_facts(
    s: &crate::ir::ddl_plan::SnowflakeUserOptionsIr,
) -> crate::facts::ddl::SnowflakeUserFacts {
    use crate::facts::ddl::SecondaryRolesModeFacts;
    use crate::ir::ddl_plan::SecondaryRolesModeIr;
    crate::facts::ddl::SnowflakeUserFacts {
        default_role: s.default_role.clone().map(IdentName::new),
        default_secondary_roles: s.default_secondary_roles.map(|m| match m {
            SecondaryRolesModeIr::All => SecondaryRolesModeFacts::All,
            SecondaryRolesModeIr::None => SecondaryRolesModeFacts::None,
        }),
        must_change_password: s.must_change_password,
        disabled: s.disabled,
        user_type: s.user_type.clone().map(IdentName::new),
        mins_to_bypass_mfa: s.mins_to_bypass_mfa,
        days_to_expiry: s.days_to_expiry,
        mins_to_unlock: s.mins_to_unlock,
        rsa_public_key_set: s.rsa_public_key_set,
        rsa_public_key_2_set: s.rsa_public_key_2_set,
        network_policy: s.network_policy.clone().map(IdentName::new),
        network_policy_unset: s.network_policy_unset,
    }
}

fn project_ir_role_attribute_kind(
    k: crate::ir::ddl_plan::RoleAttributeKindIr,
) -> crate::facts::ddl::RoleAttributeKindFacts {
    use crate::facts::ddl::RoleAttributeKindFacts as F;
    use crate::ir::ddl_plan::RoleAttributeKindIr as I;
    match k {
        I::Superuser => F::Superuser,
        I::CreateDb => F::CreateDb,
        I::CreateRole => F::CreateRole,
        I::Login => F::Login,
        I::Inherit => F::Inherit,
        I::Replication => F::Replication,
        I::BypassRls => F::BypassRls,
    }
}

/// Build public [`StatementFacts`] from a dialect-neutral
/// `CREATE / ALTER / DROP { USER | ROLE | LOGIN }` [`DdlPlan`](crate::ir::ddl_plan::DdlPlan). Picks
/// the `StatementKind` via [`crate::ir::DdlPlan::statement_kind`]
/// (which maps `(action, DatabaseUser|Role|Login)` to the matching
/// public variant) and projects `principal_options` to
/// `ddl.principal`. Used by the lib-side dispatch for non-MSSQL
/// principal statements; MSSQL principals route through
/// [`derive_facts_from_mssql_ddl_plan`] to preserve the existing
/// `mssql_create_login` / `mssql_create_user` YAML kind dispatch.
pub fn derive_facts_from_principal_plan(
    plan: &crate::ir::DdlPlan,
    _source: &str,
) -> StatementFacts {
    let stmt_kind = plan.statement_kind().unwrap_or(StatementKind::CreateRole);
    // `object_kind` is the structured fact set at lowering. MSSQL `LOGIN`
    // collapses to `Generic` (its rules discriminate via
    // `ddl.principal.kind: login` / `kind: mssql_create_login`).
    let object_kind = plan.object_kind;
    let action = match plan.action {
        crate::ir::ddl_plan::DdlAction::Create => DdlAction::Create,
        crate::ir::ddl_plan::DdlAction::Alter => DdlAction::Alter,
        crate::ir::ddl_plan::DdlAction::Drop => DdlAction::Drop,
        _ => DdlAction::Create,
    };
    let target = plan.target.as_ref().map(|t| ObjectRef {
        kind: object_kind,
        name: TableRef::new(
            IdentName::new(t.name.clone()),
            t.schema.clone().map(IdentName::new),
            t.db.clone().map(IdentName::new),
            Some(t.span),
        ),
    });
    let mssql_principal =
        plan.mssql_principal_source
            .map(|source| crate::facts::ddl::MssqlPrincipalFacts {
                source: project_ir_principal_source(source),
            });
    let principal = plan
        .principal_options
        .as_ref()
        .map(project_principal_options);
    let ddl = DdlFacts {
        targets: Vec::new(),
        action,
        object_kind,
        target,
        options: DdlOptions {
            or_replace: plan.options.or_replace,
            if_exists: plan.options.if_exists,
            if_not_exists: plan.options.if_not_exists,
            ..DdlOptions::default()
        },
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: None,
        database: None,
        warehouse: None,
        stream: None,
        schema: None,
        function: None,
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal,
        principal,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: None,
        session: None,
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: None,
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind: stmt_kind,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        diff: None,
    }
}

// ---------------------------------------------------------------------------
// Postgres DDL projection (CREATE / ALTER / DROP DOMAIN).
// ---------------------------------------------------------------------------

/// Narrow closed enum naming the Postgres DDL statement kinds that
/// [`derive_facts_from_pg_ddl_plan`] dispatches on. Same pattern as
/// [`MssqlDdlKind`] — authoring this as a separate enum (rather than
/// matching the wide [`StatementKind`] taxonomy) lets the projection
/// enumerate every supported kind without a `_ =>` catch-all on a
/// domain enum.
///
/// Callers ([`crate::Engine::analyze_ddl_facts`]) resolve the variant
/// from the originating `AstStmt` and pass it explicitly; the
/// projection then maps to the public `StatementKind` + `DdlAction`
/// exhaustively.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PgDdlKind {
    CreateDomain,
    AlterDomain,
    DropDomain,
    /// `CREATE EXTENSION [IF NOT EXISTS] name [...] [CASCADE]` —
    /// Postgres extension install. CASCADE flows through the shared
    /// flag.
    CreateExtension,
    /// `REFRESH MATERIALIZED VIEW [CONCURRENTLY] name [WITH [NO] DATA]`
    /// — Postgres materialized-view refresh.
    RefreshMatview,
    /// `REINDEX { INDEX | TABLE | SCHEMA | DATABASE | SYSTEM }
    /// [CONCURRENTLY] [name]` — Postgres index rebuild.
    Reindex,
    /// `CREATE [UNIQUE] INDEX [CONCURRENTLY] [IF NOT EXISTS] name ON
    /// table [USING method] (cols)` — general SQL `CREATE INDEX`.
    CreateIndex,
    /// `CREATE SYNONYM name FOR object` — T-SQL object alias.
    CreateSynonym,
    /// `ALTER INDEX [IF EXISTS] name <sub-action>` /
    /// `ALTER INDEX ALL IN TABLESPACE …`.
    AlterIndex,
    /// `DO [LANGUAGE name] $$ ... $$` — Postgres anonymous code block.
    DoBlock,
    /// `CREATE [CONSTRAINT] TRIGGER name { BEFORE | AFTER | INSTEAD
    /// OF } event ON table ...` — Postgres trigger create.
    CreatePgTrigger,
    /// `ALTER TRIGGER name ON table { RENAME TO new_name | [NO]
    /// DEPENDS ON EXTENSION ext }` — Postgres trigger alter.
    AlterPgTrigger,
    /// `DROP TRIGGER [IF EXISTS] name ON table [CASCADE | RESTRICT]` —
    /// Postgres trigger drop. CASCADE flows through the shared flag.
    DropPgTrigger,
    /// `DROP INDEX [CONCURRENTLY] [IF EXISTS] name [, ...] [CASCADE |
    /// RESTRICT]` — Postgres index drop. CASCADE flows through the
    /// shared flag.
    DropPgIndex,
    /// `DROP EXTENSION [IF EXISTS] name [, ...] [CASCADE | RESTRICT]` —
    /// Postgres extension drop. CASCADE flows through the shared flag.
    DropPgExtension,
    /// `ALTER TABLE … {ENABLE|DISABLE} TRIGGER …` — Postgres
    /// per-trigger firing toggle.
    AlterPgTableTriggerState,
    /// `CREATE { ROLE | USER } …` — Postgres role/user creation.
    CreatePgRole,
    /// `ALTER { ROLE | USER } …` — Postgres role/user modification.
    AlterPgRole,
    /// `DROP { ROLE | USER } …` — Postgres role/user drop.
    DropPgRole,
    /// `SET` / `RESET` session-config.
    PgSet,
    /// `DISCARD { ALL | PLANS | SEQUENCES | TEMP }` — session-state
    /// reset.
    PgDiscard,
    /// `CREATE RULE …` — Postgres query-rewrite rule.
    CreatePgRule,
    /// `ALTER RULE … RENAME TO …` — Postgres rule rename.
    AlterPgRule,
    /// `DROP RULE …` — Postgres rule drop.
    DropPgRule,
    /// `DROP OWNED BY role [, ...] [CASCADE | RESTRICT]` — mass-drop
    /// every object owned by the listed roles.
    PgDropOwned,
    /// `REASSIGN OWNED BY old [, ...] TO new` — transfers ownership.
    PgReassignOwned,
    /// `CREATE TABLESPACE name LOCATION '…'`.
    PgCreateTablespace,
    /// `ALTER TABLESPACE …`.
    PgAlterTablespace,
    /// `DROP TABLESPACE [IF EXISTS] name`.
    PgDropTablespace,
    /// `CREATE/ALTER/DROP PUBLICATION …` — logical replication
    /// source.
    PgPublication,
    /// `CREATE/ALTER/DROP SUBSCRIPTION …` — logical replication
    /// sink.
    PgSubscription,
    /// `ALTER SYSTEM …` — server-wide configuration write.
    PgAlterSystem,
    /// `LOCK [TABLE] name …` — explicit table-level lock.
    PgLockTable,
    /// `DROP SEQUENCE [IF EXISTS] name [, ...] [CASCADE | RESTRICT]`.
    PgDropSequence,
    /// `DROP TYPE [IF EXISTS] name [, ...] [CASCADE | RESTRICT]`.
    PgDropType,
    /// `CREATE [TEMP[ORARY]] SEQUENCE [IF NOT EXISTS] name [...]` —
    /// cross-dialect sequence creation routed through the PG DDL
    /// dispatch.
    CreateSequence,
    /// `ALTER SEQUENCE [IF EXISTS] name …` — cross-dialect sequence
    /// modification.
    AlterSequence,
    /// `CREATE TYPE name …` — Postgres user-defined type (composite,
    /// enum, range).
    CreateType,
    /// `ALTER TYPE name …` — Postgres user-defined type modification
    /// (rename, add value, owner, etc.).
    AlterType,
}

/// Build [`StatementFacts`] for a Postgres DDL statement, routed
/// by the narrow [`PgDdlKind`] dispatch.
pub fn derive_facts_from_pg_ddl_plan(
    plan: &crate::ir::DdlPlan,
    kind: PgDdlKind,
    source: &str,
) -> StatementFacts {
    let stmt_kind = match kind {
        PgDdlKind::CreateDomain => StatementKind::PgCreateDomain,
        PgDdlKind::AlterDomain => StatementKind::PgAlterDomain,
        PgDdlKind::DropDomain => StatementKind::PgDropDomain,
        PgDdlKind::CreateExtension => StatementKind::PgCreateExtension,
        PgDdlKind::RefreshMatview => StatementKind::PgRefreshMatview,
        PgDdlKind::Reindex => StatementKind::PgReindex,
        PgDdlKind::CreateIndex => StatementKind::CreateIndex,
        PgDdlKind::CreateSynonym => StatementKind::CreateSynonym,
        PgDdlKind::AlterIndex => StatementKind::AlterIndex,
        PgDdlKind::DoBlock => StatementKind::DoBlock,
        PgDdlKind::CreatePgTrigger => StatementKind::PgCreateTrigger,
        PgDdlKind::AlterPgTrigger => StatementKind::PgAlterTrigger,
        PgDdlKind::DropPgTrigger => StatementKind::PgDropTrigger,
        PgDdlKind::DropPgIndex => StatementKind::PgDropIndex,
        PgDdlKind::DropPgExtension => StatementKind::PgDropExtension,
        PgDdlKind::AlterPgTableTriggerState => StatementKind::PgAlterTableTriggerState,
        PgDdlKind::CreatePgRole => StatementKind::PgCreateRole,
        PgDdlKind::AlterPgRole => StatementKind::PgAlterRole,
        PgDdlKind::DropPgRole => StatementKind::PgDropRole,
        PgDdlKind::PgSet => StatementKind::PgSet,
        PgDdlKind::PgDiscard => StatementKind::PgDiscard,
        PgDdlKind::CreatePgRule => StatementKind::PgCreateRule,
        PgDdlKind::AlterPgRule => StatementKind::PgAlterRule,
        PgDdlKind::DropPgRule => StatementKind::PgDropRule,
        PgDdlKind::PgDropOwned => StatementKind::PgDropOwned,
        PgDdlKind::PgReassignOwned => StatementKind::PgReassignOwned,
        PgDdlKind::PgCreateTablespace => StatementKind::PgCreateTablespace,
        PgDdlKind::PgAlterTablespace => StatementKind::PgAlterTablespace,
        PgDdlKind::PgDropTablespace => StatementKind::PgDropTablespace,
        PgDdlKind::PgPublication => StatementKind::PgPublication,
        PgDdlKind::PgSubscription => StatementKind::PgSubscription,
        PgDdlKind::PgAlterSystem => StatementKind::PgAlterSystem,
        PgDdlKind::PgLockTable => StatementKind::PgLockTable,
        PgDdlKind::PgDropSequence => StatementKind::PgDropSequence,
        PgDdlKind::PgDropType => StatementKind::PgDropType,
        PgDdlKind::CreateSequence => StatementKind::CreateSequence,
        PgDdlKind::AlterSequence => StatementKind::AlterSequence,
        PgDdlKind::CreateType => StatementKind::PgCreateType,
        PgDdlKind::AlterType => StatementKind::PgAlterType,
    };
    let action = match kind {
        PgDdlKind::CreateDomain => DdlAction::Create,
        PgDdlKind::AlterDomain => DdlAction::Alter,
        PgDdlKind::DropDomain => DdlAction::Drop,
        PgDdlKind::CreateExtension => DdlAction::Create,
        PgDdlKind::RefreshMatview => DdlAction::Refresh,
        PgDdlKind::Reindex => DdlAction::Configure,
        PgDdlKind::CreateIndex => DdlAction::Create,
        PgDdlKind::CreateSynonym => DdlAction::Create,
        PgDdlKind::AlterIndex => DdlAction::Alter,
        PgDdlKind::DoBlock => DdlAction::ControlFlow,
        PgDdlKind::CreatePgTrigger => DdlAction::Create,
        PgDdlKind::AlterPgTrigger => DdlAction::Alter,
        PgDdlKind::DropPgTrigger => DdlAction::Drop,
        PgDdlKind::DropPgIndex => DdlAction::Drop,
        PgDdlKind::DropPgExtension => DdlAction::Drop,
        PgDdlKind::AlterPgTableTriggerState => DdlAction::Alter,
        PgDdlKind::CreatePgRole => DdlAction::Create,
        PgDdlKind::AlterPgRole => DdlAction::Alter,
        PgDdlKind::DropPgRole => DdlAction::Drop,
        PgDdlKind::PgSet => DdlAction::Configure,
        PgDdlKind::PgDiscard => DdlAction::Configure,
        PgDdlKind::CreatePgRule => DdlAction::Create,
        PgDdlKind::AlterPgRule => DdlAction::Alter,
        PgDdlKind::DropPgRule => DdlAction::Drop,
        PgDdlKind::PgDropOwned => DdlAction::Drop,
        PgDdlKind::PgReassignOwned => DdlAction::Alter,
        PgDdlKind::PgCreateTablespace => DdlAction::Create,
        PgDdlKind::PgAlterTablespace => DdlAction::Alter,
        PgDdlKind::PgDropTablespace => DdlAction::Drop,
        PgDdlKind::PgPublication => DdlAction::Alter,
        PgDdlKind::PgSubscription => DdlAction::Alter,
        PgDdlKind::PgAlterSystem => DdlAction::Configure,
        PgDdlKind::PgLockTable => DdlAction::Configure,
        PgDdlKind::PgDropSequence => DdlAction::Drop,
        PgDdlKind::PgDropType => DdlAction::Drop,
        PgDdlKind::CreateSequence => DdlAction::Create,
        PgDdlKind::AlterSequence => DdlAction::Alter,
        PgDdlKind::CreateType => DdlAction::Create,
        PgDdlKind::AlterType => DdlAction::Alter,
    };
    // The plan read the target from its text, folding one that names no
    // relation: its name is read from the text again.
    // `ALTER TABLE … TRIGGER` targets the table its triggers are on.
    let target_kind = match kind {
        PgDdlKind::AlterPgTableTriggerState => ObjectKind::Table,
        PgDdlKind::CreateDomain
        | PgDdlKind::AlterDomain
        | PgDdlKind::DropDomain
        | PgDdlKind::CreateExtension
        | PgDdlKind::RefreshMatview
        | PgDdlKind::Reindex
        | PgDdlKind::CreateIndex
        | PgDdlKind::CreateSynonym
        | PgDdlKind::AlterIndex
        | PgDdlKind::DoBlock
        | PgDdlKind::CreatePgTrigger
        | PgDdlKind::AlterPgTrigger
        | PgDdlKind::DropPgTrigger
        | PgDdlKind::DropPgIndex
        | PgDdlKind::DropPgExtension
        | PgDdlKind::CreatePgRole
        | PgDdlKind::AlterPgRole
        | PgDdlKind::DropPgRole
        | PgDdlKind::PgSet
        | PgDdlKind::PgDiscard
        | PgDdlKind::CreatePgRule
        | PgDdlKind::AlterPgRule
        | PgDdlKind::DropPgRule
        | PgDdlKind::PgDropOwned
        | PgDdlKind::PgReassignOwned
        | PgDdlKind::PgCreateTablespace
        | PgDdlKind::PgAlterTablespace
        | PgDdlKind::PgDropTablespace
        | PgDdlKind::PgPublication
        | PgDdlKind::PgSubscription
        | PgDdlKind::PgAlterSystem
        | PgDdlKind::PgLockTable
        | PgDdlKind::PgDropSequence
        | PgDdlKind::PgDropType
        | PgDdlKind::CreateSequence
        | PgDdlKind::AlterSequence
        | PgDdlKind::CreateType
        | PgDdlKind::AlterType => plan.object_kind,
    };
    let target = plan.target.as_ref().map(|t| ObjectRef {
        kind: target_kind,
        name: parse_table_ref(t.span, source),
    });
    let domain = plan
        .domain
        .as_ref()
        .map(|detail| crate::facts::ddl::DomainFacts {
            actions: detail
                .actions
                .iter()
                .copied()
                .map(project_ir_domain_alter_action)
                .collect(),
        });
    let index = plan
        .pg_index
        .as_ref()
        .map(|detail| crate::facts::ddl::IndexFacts {
            action: project_ir_index_alter_action(detail.action),
        });
    let trigger = plan
        .pg_trigger
        .as_ref()
        .map(|detail| crate::facts::ddl::TriggerFacts {
            action: project_ir_trigger_alter_action(detail.action),
        });
    let trigger_state =
        plan.pg_trigger_state
            .as_ref()
            .map(|detail| crate::facts::ddl::TriggerStateFacts {
                action: project_ir_trigger_state_action(detail.action),
            });
    let pg_session = plan
        .pg_session
        .as_ref()
        .map(|detail| crate::facts::ddl::PgSessionFacts {
            action: project_ir_pg_session_action(detail.action),
        });
    let ddl = DdlFacts {
        targets: Vec::new(),
        action,
        object_kind: plan.object_kind,
        target,
        options: DdlOptions {
            if_exists: plan.options.if_exists,
            cascade: plan.options.cascade,
            restrict: plan.options.restrict,
            or_replace: plan.options.or_replace,
            ..DdlOptions::default()
        },
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: None,
        database: None,
        warehouse: None,
        stream: None,
        schema: None,
        function: None,
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain,
        index,
        trigger,
        trigger_state,
        pg_session,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: None,
        session: None,
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: None,
        managed_account: None,
        show: None,
        synonym: plan
            .synonym
            .as_ref()
            .map(|sp| crate::facts::ddl::SynonymFacts {
                referent: (!sp.referent.is_empty()).then(|| sp.referent.clone()),
                // Four-part server.database.schema.object => linked/remote server.
                referent_server_qualified: sp.referent_part_count >= 4,
            }),
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind: stmt_kind,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        diff: None,
    }
}

/// IR → public curation for `IrDomainAlterAction`.
/// Collapses six IR variants (`SetDefault`, `DropDefault`, `SetNotNull`,
/// `RenameConstraint`, `ValidateConstraint`, `SetSchema`) into
/// `Other`. Promoting one of those distinctions out of `Other` adds a
/// new public variant (additive, semver-minor).
fn project_ir_domain_alter_action(
    ir: crate::ir::ddl_plan::IrDomainAlterAction,
) -> crate::facts::ddl::DomainAlterAction {
    use crate::facts::ddl::DomainAlterAction as P;
    use crate::ir::ddl_plan::IrDomainAlterAction as I;
    match ir {
        I::RenameTo => P::RenameTo,
        I::OwnerTo => P::OwnerTo,
        I::DropNotNull => P::DropNotNull,
        I::DropConstraint { cascade } => P::DropConstraint { cascade },
        I::AddConstraint => P::AddConstraint,
        I::SetDefault
        | I::DropDefault
        | I::SetNotNull
        | I::RenameConstraint
        | I::ValidateConstraint
        | I::SetSchema => P::Other,
    }
}

/// IR → public curation for `IrIndexAlterAction`.
/// Collapses every non-rename IR variant (`SetTablespace`,
/// `AttachPartition`, `DependsOnExtension`, `SetParams`, `ResetParams`,
/// `AlterColumnStatistics`, `AllInTablespace`, and the T-SQL
/// `Rebuild`/`Reorganize`/`Disable`/`SetOptions`) into `Other`. Promoting
/// one of those distinctions out of `Other` adds a new public variant
/// (additive, semver-minor).
fn project_ir_index_alter_action(
    ir: crate::ir::ddl_plan::IrIndexAlterAction,
) -> crate::facts::ddl::IndexAlterAction {
    use crate::facts::ddl::IndexAlterAction as P;
    use crate::ir::ddl_plan::IrIndexAlterAction as I;
    match ir {
        I::RenameTo => P::RenameTo,
        I::SetTablespace
        | I::AttachPartition
        | I::DependsOnExtension
        | I::SetParams
        | I::ResetParams
        | I::AlterColumnStatistics
        | I::AllInTablespace
        | I::Rebuild
        | I::Reorganize
        | I::Disable
        | I::SetOptions => P::Other,
    }
}

/// IR → public curation for `IrTriggerAlterAction`.
/// Collapses `DependsOnExtension` (the only non-rename `ALTER TRIGGER`
/// shape in Postgres grammar) into `Other`. Promoting that
/// distinction out of `Other` adds a new public variant (additive,
/// semver-minor).
fn project_ir_trigger_alter_action(
    ir: crate::ir::ddl_plan::IrTriggerAlterAction,
) -> crate::facts::ddl::TriggerAlterAction {
    use crate::facts::ddl::TriggerAlterAction as P;
    use crate::ir::ddl_plan::IrTriggerAlterAction as I;
    match ir {
        I::RenameTo => P::RenameTo,
        I::DependsOnExtension => P::Other,
    }
}

/// IR → public curation for `IrTriggerStateAction`.
/// Collapses `EnableAlways` and `EnableReplica` (the
/// session-replication-role modifiers) into `Enable`. Promoting the
/// `Always` / `Replica` distinction out of `Enable` adds a new public
/// variant (additive, semver-minor).
fn project_ir_trigger_state_action(
    ir: crate::ir::ddl_plan::IrTriggerStateAction,
) -> crate::facts::ddl::TriggerStateAction {
    use crate::facts::ddl::TriggerStateAction as P;
    use crate::ir::ddl_plan::IrTriggerStateAction as I;
    match ir {
        I::Disable => P::Disable,
        I::Enable | I::EnableAlways | I::EnableReplica => P::Enable,
    }
}

/// IR → public curation for `IrPgSessionAction`.
/// Four IR variants get their own public arms (`SetRole`,
/// `SetSessionAuthorization`, `SetSearchPath`, `SetParameter`); all
/// five `Reset*` IR variants collapse into `Reset`. Promoting a
/// `ResetRole` / `ResetAll` distinction out of `Reset` adds a new
/// public variant (additive, semver-minor).
fn project_ir_pg_session_action(
    ir: crate::ir::ddl_plan::IrPgSessionAction,
) -> crate::facts::ddl::PgSessionAction {
    use crate::facts::ddl::PgSessionAction as P;
    use crate::ir::ddl_plan::IrPgSessionAction as I;
    match ir {
        I::SetRole => P::SetRole,
        I::SetSessionAuthorization => P::SetSessionAuthorization,
        I::SetSearchPath => P::SetSearchPath,
        I::SetParameter => P::SetParameter,
        I::ResetRole
        | I::ResetSessionAuthorization
        | I::ResetSearchPath
        | I::ResetParameter
        | I::ResetAll => P::Reset,
    }
}

// ---------------------------------------------------------------------------
// BigQuery DDL projection (EXPORT DATA / LOAD DATA / ASSERT / MODEL /
// SNAPSHOT TABLE / SEARCH INDEX / VECTOR INDEX).
// ---------------------------------------------------------------------------

/// Narrow closed enum naming the BigQuery DDL statement kinds that
/// [`derive_facts_from_bq_ddl_plan`] dispatches on. Same pattern as
/// [`MssqlDdlKind`] / [`PgDdlKind`] — authoring this as a separate enum
/// (rather than matching the wide [`StatementKind`] taxonomy) lets the
/// projection enumerate every supported kind without a `_ =>` catch-all
/// on a domain enum.
///
/// Callers ([`crate::Engine::analyze_ddl_facts`]) resolve the variant
/// from the originating `AstStmt` and pass it explicitly; the
/// projection then maps to the public `StatementKind` + `DdlAction`
/// exhaustively.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BqDdlKind {
    /// `EXPORT DATA OPTIONS(uri=…) AS SELECT …` — query results to GCS/S3/Azure.
    ExportData,
    /// `LOAD DATA INTO target FROM FILES(…)` — analog of `COPY INTO <table>`.
    LoadData,
    /// `ASSERT expr [AS description]` — runtime data-quality check.
    Assert,
    /// `CREATE MODEL [IF NOT EXISTS] name [TRANSFORM(…)] [OPTIONS(…)]
    /// [AS query | REMOTE WITH CONNECTION …]` — BQML training / definition.
    CreateModel,
    /// `ALTER MODEL [IF EXISTS] name SET OPTIONS(…)`.
    AlterModel,
    /// `DROP MODEL [IF EXISTS] name`.
    DropModel,
    /// `EXPORT MODEL name OPTIONS(URI=…)` — BQML artifact export.
    ExportModel,
    /// `CREATE SNAPSHOT TABLE name CLONE source [FOR SYSTEM_TIME AS OF …]`.
    CreateSnapshotTable,
    /// `DROP SNAPSHOT TABLE name` — span-only AST (no per-element detail).
    DropSnapshotTable,
    /// `CREATE SEARCH INDEX name ON table(cols) [OPTIONS(…)]`.
    CreateSearchIndex,
    /// `DROP SEARCH INDEX name ON table`.
    DropSearchIndex,
    /// `CREATE VECTOR INDEX name ON table(col) [OPTIONS(…)]`.
    CreateVectorIndex,
    /// `ALTER VECTOR INDEX …` — span-only AST (no per-element detail).
    AlterVectorIndex,
    /// `DROP VECTOR INDEX name [ON table]`.
    DropVectorIndex,
    /// `CREATE [OR REPLACE] EXTERNAL TABLE …` — cross-dialect statement
    /// (Snowflake / BigQuery both use it). Routed through `BqDdlKind`;
    /// the BQ-side carrier `bq_options` stays `None` when the AST is
    /// Snowflake-style (no OPTIONS / WITH CONNECTION).
    CreateExternalTable,
    /// `CREATE EXTERNAL SCHEMA … FROM { DATA CATALOG | HIVE METASTORE | … }`
    /// (Redshift Spectrum / federated). Routes the IAM_ROLE arn + URI/DATABASE
    /// literals through the same `bq_options` literal harvest.
    CreateExternalSchema,
}

/// The kind of an `ASSERT` in the dialect in force: BigQuery's own
/// statement in BigQuery, the generic assertion in every other dialect.
fn assert_statement_kind() -> StatementKind {
    use crate::ir::CatalogDialect as D;
    match D::from_dialect_name(crate::ir::normalize::dialect_in_force().name()) {
        D::BigQuery => StatementKind::BqAssert,
        D::Default
        | D::Snowflake
        | D::PostgreSql
        | D::Databricks
        | D::MySql
        | D::MsSql
        | D::Redshift => StatementKind::Assert,
    }
}

/// Build [`StatementFacts`] for a BigQuery DDL statement, routed by
/// the narrow [`BqDdlKind`] dispatch.
pub fn derive_facts_from_bq_ddl_plan(
    plan: &crate::ir::DdlPlan,
    kind: BqDdlKind,
    source: &str,
) -> StatementFacts {
    let stmt_kind = match kind {
        BqDdlKind::ExportData => StatementKind::BqExportData,
        BqDdlKind::LoadData => StatementKind::BqLoadData,
        BqDdlKind::Assert => assert_statement_kind(),
        BqDdlKind::CreateModel => StatementKind::BqCreateModel,
        BqDdlKind::AlterModel => StatementKind::BqAlterModel,
        BqDdlKind::DropModel => StatementKind::BqDropModel,
        BqDdlKind::ExportModel => StatementKind::BqExportModel,
        BqDdlKind::CreateSnapshotTable => StatementKind::BqCreateSnapshotTable,
        BqDdlKind::DropSnapshotTable => StatementKind::BqDropSnapshotTable,
        BqDdlKind::CreateSearchIndex => StatementKind::BqCreateSearchIndex,
        BqDdlKind::DropSearchIndex => StatementKind::BqDropSearchIndex,
        BqDdlKind::CreateVectorIndex => StatementKind::BqCreateVectorIndex,
        BqDdlKind::AlterVectorIndex => StatementKind::BqAlterVectorIndex,
        BqDdlKind::DropVectorIndex => StatementKind::BqDropVectorIndex,
        BqDdlKind::CreateExternalTable => StatementKind::CreateExternalTable,
        BqDdlKind::CreateExternalSchema => StatementKind::CreateExternalSchema,
    };
    let action = match kind {
        BqDdlKind::ExportData | BqDdlKind::LoadData | BqDdlKind::ExportModel => DdlAction::BulkLoad,
        BqDdlKind::Assert => DdlAction::ControlFlow,
        BqDdlKind::CreateModel
        | BqDdlKind::CreateSnapshotTable
        | BqDdlKind::CreateSearchIndex
        | BqDdlKind::CreateVectorIndex
        | BqDdlKind::CreateExternalTable
        | BqDdlKind::CreateExternalSchema => DdlAction::Create,
        BqDdlKind::AlterModel | BqDdlKind::AlterVectorIndex => DdlAction::Alter,
        BqDdlKind::DropModel
        | BqDdlKind::DropSnapshotTable
        | BqDdlKind::DropSearchIndex
        | BqDdlKind::DropVectorIndex => DdlAction::Drop,
    };
    // An external or snapshot table a statement creates is a table a later
    // statement reads; the other objects of the family keep the generic kind.
    let object_kind = match kind {
        BqDdlKind::CreateExternalTable => ObjectKind::ExternalTable,
        BqDdlKind::CreateSnapshotTable => ObjectKind::Table,
        BqDdlKind::ExportData
        | BqDdlKind::LoadData
        | BqDdlKind::Assert
        | BqDdlKind::CreateModel
        | BqDdlKind::AlterModel
        | BqDdlKind::DropModel
        | BqDdlKind::ExportModel
        | BqDdlKind::DropSnapshotTable
        | BqDdlKind::CreateSearchIndex
        | BqDdlKind::DropSearchIndex
        | BqDdlKind::CreateVectorIndex
        | BqDdlKind::AlterVectorIndex
        | BqDdlKind::DropVectorIndex
        | BqDdlKind::CreateExternalSchema => ObjectKind::Generic,
    };
    // A snapshot table keeps the parts the parser read, as written; any
    // other target the plan read from its text, folding one that names no
    // relation, so its name is read from the text again.
    let target = plan.target.as_ref().map(|t| ObjectRef {
        kind: object_kind,
        name: match kind {
            BqDdlKind::CreateSnapshotTable => TableRef::new(
                IdentName::new(t.name.clone()),
                t.schema.clone().map(IdentName::new),
                t.db.clone().map(IdentName::new),
                Some(t.span),
            ),
            BqDdlKind::ExportData
            | BqDdlKind::LoadData
            | BqDdlKind::Assert
            | BqDdlKind::CreateModel
            | BqDdlKind::AlterModel
            | BqDdlKind::DropModel
            | BqDdlKind::ExportModel
            | BqDdlKind::DropSnapshotTable
            | BqDdlKind::CreateSearchIndex
            | BqDdlKind::DropSearchIndex
            | BqDdlKind::CreateVectorIndex
            | BqDdlKind::AlterVectorIndex
            | BqDdlKind::DropVectorIndex
            | BqDdlKind::CreateExternalTable
            | BqDdlKind::CreateExternalSchema => parse_table_ref(t.span, source),
        },
    });
    let bq_assert = plan
        .bq_assert
        .as_ref()
        .map(|detail| crate::facts::ddl::BqAssertFacts {
            description: detail.description.as_ref().map(|d| d.text.clone()),
        });
    // BqAssert's predicate can carry subqueries (`(SELECT … FROM t) > 0`
    // / `EXISTS (SELECT … FROM t)` / etc.). The IR-side lowerer collected
    // the union of subquery `tables_read` onto
    // `IrBqAssertDetail::inner_reads_table`. Surface them as the assert
    // statement's `query.reads_table` so the metrics collector counts the
    // referenced tables and rule predicates over `query.reads_table` see
    // them. Empty `inner_reads_table` yields `query: None` so existing
    // BQ-* DDL rules predicating on `kind: bq_assert` stay unaffected.
    let bq_assert_query = plan.bq_assert.as_ref().and_then(|detail| {
        if detail.inner_reads_table.is_empty() {
            None
        } else {
            let reads_table: Vec<crate::facts::query::TableEvent> = detail
                .inner_reads_table
                .iter()
                .map(|t| crate::facts::query::TableEvent {
                    table: project_metadata_table_ref(t, t.span),
                    scope_id: crate::facts::identity::ScopeIdentity::OUTER,
                    source_span: t.span,
                    catalog_tags: Vec::new(),
                    row_count: None,
                    column_count: None,
                    access_kind: crate::facts::query::TableAccessKind::Read,
                    table_kind: None,
                    in_catalog: None,
                    searched_as: None,
                    temporary: false,
                })
                .collect();
            Some(crate::facts::query::QueryFacts {
                tables_used: tables_used(&reads_table, &[]),
                reads_table,
                ..crate::facts::query::QueryFacts::default()
            })
        }
    });
    let bq_create_model =
        plan.bq_create_model
            .as_ref()
            .map(|detail| crate::facts::ddl::BqCreateModelFacts {
                remote_connection: detail
                    .remote_connection
                    .as_ref()
                    .map(|r| r.connection_text.clone()),
                body: detail.body.as_ref().map(project_ir_bq_query_body),
            });
    let bq_export_data =
        plan.bq_export_data
            .as_ref()
            .map(|detail| crate::facts::ddl::BqExportDataFacts {
                body: detail.body.as_ref().map(project_ir_bq_query_body),
            });
    let bq_options = plan.bq_options.as_ref().map(project_ir_bq_options);
    let ddl = DdlFacts {
        targets: Vec::new(),
        action,
        object_kind,
        target,
        options: DdlOptions {
            or_replace: plan.options.or_replace,
            if_exists: plan.options.if_exists,
            if_not_exists: plan.options.if_not_exists,
            ..DdlOptions::default()
        },
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: None,
        database: None,
        warehouse: None,
        stream: None,
        schema: None,
        function: None,
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert,
        bq_create_model,
        bq_export_data,
        bq_options,
        datashare: None,
        tag: None,
        file_format: None,
        session: None,
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: None,
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind: stmt_kind,
        source_span: Some(plan.span),
        query: bq_assert_query,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        diff: None,
    }
}

// ---------------------------------------------------------------------------
// View DDL projection (cross-dialect CREATE / ALTER / DROP VIEW and
// CREATE / ALTER MATERIALIZED VIEW). Same dispatch pattern as
// [`PgDdlKind`] / [`MssqlDdlKind`] / [`BqDdlKind`]: the caller
// ([`crate::Engine::analyze_ddl_facts`]) resolves the variant from the
// originating `AstStmt`, the projection maps it to a public
// `StatementKind` + `DdlAction`, and the rule corpus predicates against
// the resulting `kind` / `ddl.options.or_replace` / `ddl.options.cascade`.
// ---------------------------------------------------------------------------

/// Project the `CREATE VIEW` security-context clauses into the public
/// [`ViewFacts`] carrier: the MySQL prelude (`DEFINER` + `SQL SECURITY`),
/// the PostgreSQL `WITH (...)` option list (`security_invoker`,
/// `security_barrier`, `check_option`) and Snowflake's `SECURE`. Returns
/// `None` when no such clause is
/// present, so `ddl.view` stays absent. The view lifecycle otherwise lowers
/// through the generic `DdlPlan`, so this is projected directly from the AST
/// at the dispatch site.
pub fn project_view_prelude_facts(
    view: &crate::ast::AstCreateView,
    source: &str,
) -> Option<ViewFacts> {
    let definer = view
        .definer
        .as_ref()
        .map(|d| definer_to_facts(&crate::ir::lower_definer(d, source)));
    let sql_security = view.sql_security.as_ref().map(|s| match s.mode {
        crate::ast::ViewSqlSecurityMode::Definer => ViewSqlSecurity::Definer,
        crate::ast::ViewSqlSecurityMode::Invoker => ViewSqlSecurity::Invoker,
    });

    let mut security_invoker = None;
    let mut security_barrier = None;
    let mut check_option = None;
    for prop in &view.with_options {
        let name = slice_span_text(source, prop.name_span);
        let value = prop.value_span.map(|s| slice_span_text(source, s));
        if name.eq_ignore_ascii_case("security_invoker") {
            security_invoker = pg_option_bool(value);
        } else if name.eq_ignore_ascii_case("security_barrier") {
            security_barrier = pg_option_bool(value);
        } else if name.eq_ignore_ascii_case("check_option") {
            let v = value.map(literal_value_or_name).unwrap_or_default();
            check_option = if v.eq_ignore_ascii_case("local") {
                Some(ViewCheckOption::Local)
            } else if v.eq_ignore_ascii_case("cascaded") {
                Some(ViewCheckOption::Cascaded)
            } else {
                None
            };
        }
    }
    // Trailing `WITH [CASCADED|LOCAL] CHECK OPTION` (bare form is CASCADED).
    if let Some(mode) = view.with_check_option_mode {
        check_option = Some(match mode {
            crate::ast::AstViewCheckOptionMode::Local => ViewCheckOption::Local,
            crate::ast::AstViewCheckOptionMode::Cascaded
            | crate::ast::AstViewCheckOptionMode::Default => ViewCheckOption::Cascaded,
        });
    }

    let secure = view.secure_span.is_some();
    if definer.is_none()
        && sql_security.is_none()
        && security_invoker.is_none()
        && security_barrier.is_none()
        && check_option.is_none()
        && !secure
    {
        return None;
    }
    Some(ViewFacts {
        definer,
        sql_security,
        security_invoker,
        security_barrier,
        check_option,
        secure,
        ..ViewFacts::default()
    })
}

/// Project the action an `ALTER VIEW` performs into [`ViewFacts`]: its
/// kind, and the policy attach / detach flags `ALTER TABLE` publishes in
/// [`TableFacts`]. Every action of the statement reaches `action`.
pub(crate) fn project_alter_view_facts(view: &crate::ast::AstAlterView) -> ViewFacts {
    use crate::ast::AstAlterViewActionKind as K;
    use ViewAlterActionKind as A;
    let mut facts = ViewFacts::default();
    let action = match &view.action.kind {
        K::AddRowAccessPolicy { .. } => {
            facts.row_access_policy_added = true;
            A::AddRowAccessPolicy
        }
        K::DropRowAccessPolicy { .. } => {
            facts.row_access_policy_removed = true;
            A::DropRowAccessPolicy
        }
        K::DropAllRowAccessPolicies { .. } => {
            facts.row_access_policy_removed = true;
            facts.drop_all_row_access_policies = true;
            A::DropAllRowAccessPolicies
        }
        K::UnsetAggregationPolicy { .. } => {
            facts.aggregation_policy_removed = true;
            A::UnsetAggregationPolicy
        }
        K::UnsetJoinPolicy { .. } => {
            facts.aggregation_policy_removed = true;
            A::UnsetJoinPolicy
        }
        K::AlterColumn {
            masking_policy,
            projection_policy,
            policy_unset,
            ..
        } => {
            facts.masking_policy_added = masking_policy.is_some() || projection_policy.is_some();
            facts.masking_policy_removed = policy_unset.is_some();
            A::AlterColumn
        }
        K::SetOptions { .. } => A::SetOptions,
        K::AlterColumnSetOptions { .. } => A::SetColumnOptions,
        K::RenameTo { .. } => A::Rename,
        K::RenameColumn { .. } => A::RenameColumn,
        K::SetSecure { .. } => A::SetSecure,
        K::UnsetSecure { .. } => A::UnsetSecure,
        K::SetComment { .. } => A::SetComment,
        K::UnsetComment { .. } => A::UnsetComment,
        K::SetChangeTracking { .. } => A::SetChangeTracking,
        K::SetTag { .. } => A::SetTag,
        K::UnsetTag { .. } => A::UnsetTag,
        K::SetAggregationPolicy { .. } => A::SetAggregationPolicy,
        K::SetJoinPolicy { .. } => A::SetJoinPolicy,
        K::AddColumn { .. } => A::AddColumn,
        K::DataMetricFunction { .. } => A::DataMetricFunction,
        K::OpaqueRemainder { .. } => A::Unknown,
    };
    facts.action = Some(action);
    facts
}

/// [`project_alter_view_facts`] for `ALTER MATERIALIZED VIEW`.
pub(crate) fn project_alter_materialized_view_facts(
    view: &crate::ast::AstAlterMaterializedView,
) -> ViewFacts {
    use crate::ast::AstAlterMaterializedViewActionKind as K;
    use ViewAlterActionKind as A;
    let mut facts = ViewFacts::default();
    let action = match &view.action.kind {
        K::AddRowAccessPolicy { .. } => {
            facts.row_access_policy_added = true;
            A::AddRowAccessPolicy
        }
        K::DropRowAccessPolicy { .. } => {
            facts.row_access_policy_removed = true;
            A::DropRowAccessPolicy
        }
        K::DropAllRowAccessPolicies { .. } => {
            facts.row_access_policy_removed = true;
            facts.drop_all_row_access_policies = true;
            A::DropAllRowAccessPolicies
        }
        K::AlterColumn {
            masking_policy,
            projection_policy,
            policy_unset,
            ..
        } => {
            facts.masking_policy_added = masking_policy.is_some() || projection_policy.is_some();
            facts.masking_policy_removed = policy_unset.is_some();
            A::AlterColumn
        }
        K::SetOptions { .. } => A::SetOptions,
        K::RenameColumn { .. } => A::RenameColumn,
        K::RenameTo { .. } => A::Rename,
        K::SetSecure { .. } => A::SetSecure,
        K::UnsetSecure { .. } => A::UnsetSecure,
        K::SetComment { .. } => A::SetComment,
        K::UnsetComment { .. } => A::UnsetComment,
        K::SetTag { .. } => A::SetTag,
        K::UnsetTag { .. } => A::UnsetTag,
        K::OpaqueRemainder { .. } => A::Unknown,
    };
    facts.action = Some(action);
    facts
}

/// Normalize a PostgreSQL boolean option literal (`true`/`false`, `on`/`off`,
/// `yes`/`no`, `1`/`0`, optionally quoted). A bare option with no `= value`
/// enables it, per PostgreSQL option semantics. Unrecognized spellings stay
/// unset rather than guessing.
fn pg_option_bool(value: Option<&str>) -> Option<bool> {
    let Some(raw) = value else {
        return Some(true);
    };
    let v = literal_value_or_name(raw);
    if v.eq_ignore_ascii_case("true")
        || v.eq_ignore_ascii_case("on")
        || v.eq_ignore_ascii_case("yes")
        || v == "1"
    {
        Some(true)
    } else if v.eq_ignore_ascii_case("false")
        || v.eq_ignore_ascii_case("off")
        || v.eq_ignore_ascii_case("no")
        || v == "0"
    {
        Some(false)
    } else {
        None
    }
}

/// Narrow closed enum naming the VIEW lifecycle statements that
/// [`derive_facts_from_view_ddl_plan`] dispatches on. The variant is
/// resolved from the `AstStmt` at the dispatch site (a CREATE VIEW is
/// `AstStmt::CreateView`, a DROP VIEW arrives via the generic
/// `AstStmt::Drop` filtered by `classify_drop_object == ObjectKind::View`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ViewDdlKind {
    CreateView,
    AlterView,
    DropView,
    AlterMaterializedView,
}

/// Build a public `StatementFacts` from a for a
/// view-lifecycle statement. The caller selects the [`ViewDdlKind`]
/// from the originating `AstStmt` variant. The projection exposes the
/// structural inputs the VIEW-* rules compose against — namely
/// `ddl.options.or_replace` and `ddl.options.cascade`.
pub fn derive_facts_from_view_ddl_plan(
    plan: &crate::ir::DdlPlan,
    kind: ViewDdlKind,
) -> StatementFacts {
    let stmt_kind = match kind {
        ViewDdlKind::CreateView => StatementKind::CreateView,
        ViewDdlKind::AlterView => StatementKind::AlterView,
        ViewDdlKind::DropView => StatementKind::DropView,
        ViewDdlKind::AlterMaterializedView => StatementKind::AlterMaterializedView,
    };
    let action = match kind {
        ViewDdlKind::CreateView => DdlAction::Create,
        ViewDdlKind::AlterView | ViewDdlKind::AlterMaterializedView => DdlAction::Alter,
        ViewDdlKind::DropView => DdlAction::Drop,
    };
    let object_kind = match kind {
        ViewDdlKind::AlterMaterializedView => ObjectKind::MaterializedView,
        _ => ObjectKind::View,
    };
    let target = plan.target.as_ref().map(|t| ObjectRef {
        kind: object_kind,
        name: TableRef::new(
            IdentName::new(t.name.clone()),
            t.schema.clone().map(IdentName::new),
            t.db.clone().map(IdentName::new),
            Some(t.span),
        ),
    });
    let ddl = DdlFacts {
        targets: Vec::new(),
        action,
        object_kind,
        target,
        options: DdlOptions {
            or_replace: plan.options.or_replace,
            if_exists: plan.options.if_exists,
            if_not_exists: plan.options.if_not_exists,
            cascade: plan.options.cascade,
            restrict: plan.options.restrict,
            ..DdlOptions::default()
        },
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: None,
        database: None,
        warehouse: None,
        stream: None,
        schema: None,
        function: None,
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: None,
        session: None,
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: None,
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind: stmt_kind,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        diff: None,
    }
}

/// IR → public projection for [`crate::ir::ddl_plan::IrBqQueryBody`].
/// Shared by the BqExportData and BqCreateModel projections. The IR
/// keeps a wrapper struct per filter clause to absorb future internal
/// additions; the public surface flattens to `Option<String>` because
/// rules today only predicate on clause existence / future content
/// patterns — no current rule discriminates on per-clause wrapper
/// fields, so the public stays narrower than the IR.
fn project_ir_bq_query_body(
    ir: &crate::ir::ddl_plan::IrBqQueryBody,
) -> crate::facts::ddl::BqQueryBodyFacts {
    let project_clause = |c: &Option<crate::ir::ddl_plan::IrBqFilterClause>| -> Option<String> {
        c.as_ref().map(|cc| cc.text.clone())
    };
    crate::facts::ddl::BqQueryBodyFacts {
        where_clause: project_clause(&ir.where_clause),
        having_clause: project_clause(&ir.having_clause),
        qualify_clause: project_clause(&ir.qualify_clause),
    }
}

/// IR → public projection for [`crate::ir::ddl_plan::IrBqOptionsDetail`].
/// Boundary curation: IR keeps raw key text; the public side normalizes via
/// [`IdentName`] (dialect-aware fold). Literal values are wrapped in
/// [`crate::facts::ddl::BqLiteralValue`] with a typed
/// [`crate::facts::ddl::CloudVendor`] classification when the literal's
/// URI scheme is recognized — the same canonical cloud-vendor taxonomy
/// derives from credential-mechanism variants.
fn project_ir_bq_options(
    ir: &crate::ir::ddl_plan::IrBqOptionsDetail,
) -> crate::facts::ddl::BqOptionsFacts {
    crate::facts::ddl::BqOptionsFacts {
        options: ir
            .options
            .iter()
            .map(|p| crate::facts::ddl::BqOptionPair {
                key: IdentName::new(p.key_raw.clone()),
                value_literal: p.value_literal.clone(),
            })
            .collect(),
        all_literal_values: ir
            .all_literal_values
            .iter()
            .map(|v| crate::facts::ddl::BqLiteralValue {
                value: v.value.clone(),
                cloud_scheme: classify_cloud_storage_uri(&v.value),
                url_password_literals: password_literals(&v.url_password_literals),
            })
            .collect(),
    }
}

/// Classify a literal value by URI scheme prefix into the canonical
/// public [`crate::facts::ddl::CloudVendor`] taxonomy. Case-insensitive;
/// only `s3`, `gs` / `gcs` and `azure` are recognized. Returns `None` for
/// literals that aren't
/// recognized cloud-storage URIs (file paths, plain options, etc.) —
/// rules predicate `cloud_scheme: { in: […] }` and never see the
/// `None` case.
fn classify_cloud_storage_uri(value: &str) -> Option<crate::facts::ddl::CloudVendor> {
    let trimmed = value.trim_start();
    let (scheme, rest) = trimmed.split_once("://")?;
    if !rest.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '/') {
        return None;
    }
    match scheme.to_ascii_lowercase().as_str() {
        "s3" => Some(crate::facts::ddl::CloudVendor::Aws),
        "gs" | "gcs" => Some(crate::facts::ddl::CloudVendor::GoogleCloud),
        "azure" => Some(crate::facts::ddl::CloudVendor::Azure),
        _ => None,
    }
}

/// Build a public `StatementFacts` directly from a lowered relational
/// plan and its companion `BindingTable` + `DerivedFacts`.
///
/// `outer_span` defaults to `None`; pass `Some(stmt.span())` when the
/// originating AST statement's byte range is known (the analyzer ledger
/// indexes facts by `source_span.start`; a root `RelPlan::Limit` carries
/// the clause-only span and would otherwise mismatch).
pub fn derive_facts_from_query_plan(
    plan: &crate::ir::plan::RelPlan,
    bindings: &crate::ir::column::BindingTable,
    derived_facts: &crate::ir::derived_facts::DerivedFacts,
    source: &str,
    function_catalog: &crate::ir::FunctionCatalog,
    reasoning: &dyn super::reasoning::Reasoning,
) -> StatementFacts {
    derive_facts_from_query_plan_with_catalog(
        plan,
        bindings,
        derived_facts,
        source,
        function_catalog,
        None,
        None,
        reasoning,
    )
}

/// Catalog-aware variant. The optional `catalog` parameter is the
/// IR-derived `IndexedCatalogContext` produced by
/// `lower_query_full_with_bindings(..., Some(&CatalogIndex))`. When
/// provided, the projection populates:
///
/// - `TableEvent.row_count` from `IndexedCatalogContext::table_row_count`
/// - `TableEvent.column_count` from the resolved `TableColumns` arity
/// - `TableEvent.catalog_tags` from `resolve_table_tags`
/// - `ColumnRef.nullability` and `data_type` from `column_metadata`
/// - `JoinColumnPair.type_compatibility` and `fk_relationship` by
///   inspecting both sides' `ColumnMetadata`
/// - `WindowEvent.partition_high_cardinality` via the IR
///   `is_high_cardinality_column` query
/// - `ProjectionEvent.taint_labels` via the IR taint pipeline
///
/// Without a catalog (`None`), every field stays at its stub
/// (empty `Vec` / `None` / `Unknown`); catalog-gated rules silently
/// stay inert.
pub fn derive_facts_from_query_plan_with_catalog(
    plan: &crate::ir::plan::RelPlan,
    bindings: &crate::ir::column::BindingTable,
    derived_facts: &crate::ir::derived_facts::DerivedFacts,
    source: &str,
    function_catalog: &crate::ir::FunctionCatalog,
    catalog: Option<&crate::ir::IndexedCatalogContext>,
    outer_span: Option<crate::lexer::token::Span>,
    reasoning: &dyn super::reasoning::Reasoning,
) -> StatementFacts {
    derive_facts_from_query_plan_and_held_plans(
        plan,
        &crate::ir::expression_fact::build_scan_index(plan),
        bindings,
        derived_facts,
        source,
        function_catalog,
        catalog,
        catalog,
        outer_span,
        reasoning,
        &[],
        false,
    )
}

/// As [`derive_facts_from_query_plan_with_catalog`], read through
/// `scan_index`, the scan index of `plan` and of the plans its expressions
/// hold outside it ([`crate::ir::expression_fact::build_scan_index_over`]):
/// the bodies of a policy statement, for which lowering returns no plan. A
/// column of a source in one of them is published with that source's
/// table.
pub(crate) fn derive_facts_from_query_plan_and_held_plans(
    plan: &crate::ir::plan::RelPlan,
    scan_index: &crate::ir::expression_fact::ScanIndex,
    bindings: &crate::ir::column::BindingTable,
    derived_facts: &crate::ir::derived_facts::DerivedFacts,
    source: &str,
    function_catalog: &crate::ir::FunctionCatalog,
    catalog: Option<&crate::ir::IndexedCatalogContext>,
    known: Option<&crate::ir::IndexedCatalogContext>,
    outer_span: Option<crate::lexer::token::Span>,
    reasoning: &dyn super::reasoning::Reasoning,
    placeholders: &[crate::lexer::token::Span],
    output_columns: bool,
) -> StatementFacts {
    let ctx = CatalogCtx {
        catalog,
        known,
        function_catalog,
        source,
        scan_index: Some(scan_index),
        reasoning,
        placeholders,
        output_columns,
    };
    project_query_statement(plan, bindings, derived_facts, &ctx, outer_span)
}

/// Assemble a `StatementFacts` for a relational plan from its lowered
/// pieces.
pub fn project_query_statement(
    plan: &crate::ir::plan::RelPlan,
    bindings: &crate::ir::column::BindingTable,
    derived_facts: &crate::ir::derived_facts::DerivedFacts,
    ctx: &CatalogCtx<'_>,
    outer_span: Option<crate::lexer::token::Span>,
) -> StatementFacts {
    // `outer_span` overrides `plan.span()` when the caller knows the AST
    // statement's full byte range. Root `RelPlan::Limit` (TOP/LIMIT/FETCH)
    // carries the clause-only span, which mis-indexes the ledger keyed on
    // the AST stmt's start; passing the outer span lifts that.
    let source_span = outer_span.or_else(|| Some(plan.span()));
    let query_facts = project_query_facts(plan, bindings, derived_facts, ctx);
    StatementFacts {
        declare: None,
        call: None,
        kind: statement_kind_from_rel_plan(plan),
        source_span,
        query: Some(query_facts),
        ddl: None,
        privilege: None,
        policy: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

/// Attach cross-scope per-predicate effects to
/// `PredicateEvent.cross_scope_effects`. `effects` is keyed by predicate
/// span; each `PredicateEvent` takes the entries whose span equals its
/// `source_span`.
fn project_cross_scope_effects_onto_scopes(
    effects: Vec<(
        crate::lexer::token::Span,
        crate::facts::query::PredicateCrossScopeEffect,
    )>,
    scopes: &mut [crate::facts::query::ScopeFacts],
) {
    if effects.is_empty() {
        return;
    }
    let mut by_span: std::collections::HashMap<
        crate::lexer::token::Span,
        Vec<crate::facts::query::PredicateCrossScopeEffect>,
    > = std::collections::HashMap::new();
    for (span, effect) in effects {
        by_span.entry(span).or_default().push(effect);
    }
    for scope in scopes.iter_mut() {
        for ev in scope.where_predicates.iter_mut() {
            if let Some(span) = ev.source_span {
                if let Some(effects) = by_span.get(&span) {
                    ev.cross_scope_effects = effects.clone();
                }
            }
        }
        for ev in scope.having_predicates.iter_mut() {
            if let Some(span) = ev.source_span {
                if let Some(effects) = by_span.get(&span) {
                    ev.cross_scope_effects = effects.clone();
                }
            }
        }
        // Unified channel — covers WHERE / HAVING / QUALIFY / JOIN ON
        // uniformly. Same span-match rule as the per-site projections.
        for ev in scope.predicates.iter_mut() {
            if let Some(span) = ev.source_span {
                if let Some(effects) = by_span.get(&span) {
                    ev.cross_scope_effects = effects.clone();
                }
            }
        }
    }
}

/// Top-level [`StatementKind`] discriminator from a
/// root. DML variants map directly; `WithScope` recurses through its
/// body (CTEs are scope bindings, not the statement's identity);
/// `Explain` projects to `StatementKind::Explain`; create-as-query
/// shapes map to the appropriate `Create*` variant; everything else
/// (a relational tree rooted in `Project` / `Filter` / `Aggregate` /
/// etc.) is `Select`.
fn statement_kind_from_rel_plan(plan: &crate::ir::plan::RelPlan) -> StatementKind {
    use crate::ir::plan::{CreateAsKind, RelPlan};
    match plan {
        RelPlan::Insert { .. } => StatementKind::Insert,
        RelPlan::Update { .. } => StatementKind::Update,
        RelPlan::Delete { .. } => StatementKind::Delete,
        RelPlan::Merge { .. } => StatementKind::Merge,
        RelPlan::MultiInsert { .. } => StatementKind::MultiInsert,
        RelPlan::SetOp { .. } => StatementKind::SetSelect,
        RelPlan::WithScope { body, .. } => statement_kind_from_rel_plan(body),
        RelPlan::Explain { .. } => StatementKind::Explain,
        RelPlan::CreateAsQuery { kind, .. } => match kind {
            CreateAsKind::View {
                materialized: true, ..
            } => StatementKind::CreateMaterializedView,
            CreateAsKind::View { .. } => StatementKind::CreateView,
            CreateAsKind::Table { .. } => StatementKind::CreateTable,
            CreateAsKind::DynamicTable { .. } => StatementKind::CreateDynamicTable,
        },
        RelPlan::CreateTableForm { .. } => StatementKind::CreateTable,
        // Relational trees rooted in expression-shaping operators are
        // `SELECT` statements. Sources alone (`Scan` / `Values` / etc.)
        // appear as roots in degenerate fixtures and also map to Select.
        RelPlan::Scan { .. }
        | RelPlan::Values { .. }
        | RelPlan::CteRef { .. }
        | RelPlan::ModelRef { .. }
        | RelPlan::TableFunction { .. }
        | RelPlan::Project { .. }
        | RelPlan::Filter { .. }
        | RelPlan::Aggregate { .. }
        | RelPlan::Window { .. }
        | RelPlan::Sort { .. }
        | RelPlan::Limit { .. }
        | RelPlan::Pivot { .. }
        | RelPlan::Unpivot { .. }
        | RelPlan::Unnest { .. }
        | RelPlan::Join { .. }
        | RelPlan::DerivedTable { .. }
        | RelPlan::TableSample { .. }
        | RelPlan::MatchRecognize { .. }
        | RelPlan::ConnectBy { .. }
        | RelPlan::InvalidInput { .. } => StatementKind::Select,
        // Parse failures (parser bailed → AstStmt::OpaqueContent →
        // RelPlan::Opaque, or parser recovered → RelPlan::ParseRecovery)
        // route to StatementKind::Opaque so the analyzer ledger's
        // UNKNOWN classification fires and `statements_skipped` counts
        // them. InvalidInput stays Select because the lowering succeeded
        // — we have a typed plan, the input just violates a semantic
        // invariant; downstream rules can still predicate on it.
        RelPlan::ParseRecovery { .. } | RelPlan::Opaque { .. } => StatementKind::Opaque,
    }
}

// ---------------------------------------------------------------------------
// Query projection.
// ---------------------------------------------------------------------------
//
// Maps a lowered `RelPlan` plus its companion `BindingTable` and IR-side
// `DerivedFacts` onto the public `QueryFacts` / `ScopeFacts` surface. The
// walk mirrors the scope-handling discipline of
// `crate::ir::derive_facts_from_plan` (`src/ir/derived_facts.rs`):
//
// - `WithScope` ctes, `DerivedTable`, scalar subqueries, and `EXISTS` /
//   `IN` / `LATERAL` subqueries allocate fresh `ScopeFacts` entries.
// - `Project` / `Filter` / `Aggregate` / `Window` / `Sort` / `Limit` /
//   `Pivot` / `Unpivot` / `Unnest` / `MatchRecognize` / `ConnectBy` /
//   `TableSample` / `Explain` / `WithScope.body` are scope-preserving
//   wrappers and inherit the enclosing scope's id.
// - `Join` and `SetOp` contribute events to the current scope and
//   recurse.
//
// Outer-only fields (`projections`, `group_by`, `order_by`, `limit`,
// `qualify`) populate on first encounter per scope — the walk descends
// top-down so the outermost owning node wins. Per-scope-set fields
// (`where_predicates`, `having_predicates`, `aggregates`,
// `window_functions`, `set_operations`, `scalar_subqueries`,
// `table_functions`, `star_projections`, `join_predicates`) accumulate
// across every encounter within the scope.
//
// Expression projection (`ScalarExpr` → `super::expr::Expr`) covers the
// closed-enum variant set: `Column`, `OuterRef`, `Lit`, `BinOp`,
// `UnaryOp`, `FuncCall`, `Case`, `Cast`, `InList`, `Between`, `Exists`,
// `ScalarSubquery`, `QuantifiedCmp`, `WindowFn`, `FieldAccess`, `Lambda`,
// `PatternVarRef`, `Opaque`. `Between` lowers to a public
// `BinaryOp(And, Gte, Lte)` chain because the public surface does not
// carry a dedicated `Between` variant. Subqueries inside expressions
// recursively invoke `project_query_facts` so every nested subquery
// carries its own `inner_facts: QueryFacts`.

use super::catalog::Nullability;
use super::expr::{
    BinaryOp, BinaryOpExpr, CaseBranch, CaseExpr, CastExpr, CastKind, CollectionExpr,
    CollectionKind, ComparisonOp as PublicComparisonOp, Expr, FieldAccessExpr, FuncCallExpr,
    InListExpr, NamedArgument, OpaqueExpr, OpaqueExprReason, OuterColumnRef, ParameterKind,
    ParameterRef, QuantifiedCmpExpr, QuantifiedRhsExpr, Quantifier as PublicQuantifier, StarExpr,
    SubqueryExpr, SubqueryKind, UnaryOp, UnaryOpExpr, WindowExpr, WindowFunctionName,
};
use super::identity::{
    ColumnRef, IdentName as PublicIdentName, ScopeIdentity, TableRef as PublicTableRef,
};
use super::literal::LiteralValue;
use super::query::{
    AggregateEvent, AggregateFunction, FunctionOrigin, JoinColumnPair, JoinEvent,
    JoinKind as PublicJoinKind, JoinPredicateEvent, JoinSource as PublicJoinSource, LimitEvent,
    NullsOrdering, OrderByEvent, OrderDirection, PredicateEvent, PredicateKind, PredicateNode,
    ProjectionEvent, ProjectionKind, QueryFacts, ScopeFacts, ScopeKind, SetOpEvent,
    SetOpKind as PublicSetOpKind, StarProjectionEvent, SubqueryRef, TableAccessKind, TableEvent,
    TableFunctionEvent, WindowEvent, WindowFrame as PublicWindowFrame, WindowFrameBound,
    WindowFrameExclusion, WindowFrameKind,
};
use super::reasoning::{ReadAt, ReadSite};
use crate::context::node_metadata as legacy_meta;
use crate::ir::column::{BindingTable, ColumnId};
use crate::ir::derived_facts::{derive_facts_from_plan, DerivedFacts};
use crate::ir::fingerprint::Fingerprint;
use crate::ir::plan::{
    AggregateCall, CteBody, FilterKind, FrameBound, FrameExclusion, FrameMode, GroupingSpec,
    JoinKind as IrJoinKind, ProjectItem, RelPlan, ResolvedFunc, SetOpKind as IrSetOpKind, SortKey,
    StarQualifier, WindowCall, WindowFrame as IrWindowFrame,
};
use crate::ir::scalar::{FieldStep, Lit, QuantifiedRhs, ScalarExpr};

/// Project a lowered query [`RelPlan`] (with its companion
/// [`BindingTable`] and the IR-side [`DerivedFacts`] cached on) into the public [`QueryFacts`] surface.
///
/// The projection populates every field rules can predicate on:
/// - Top-level convenience flags (`has_where`, `has_limit`, `has_qualify`,
///   `has_having`, `has_distinct`, `has_sample`, `has_implicit_cross_join`,
///   `has_join_predicate_filters`, `immediate_*` counts).
/// - `reads_table` / `writes_table` aggregates with `TableAccessKind`
///   discriminator derived from the root plan's DML shape.
/// - Per-scope `tables`, `joins`, `set_operations`, `where_predicates`,
///   `having_predicates`, `join_predicates`, `projections`, `group_by`,
///   `order_by`, `limit`, `qualify`, `aggregates`, `window_functions`,
///   `star_projections`, `scalar_subqueries`, `table_functions`.
/// - Expression trees as typed `super::expr::Expr` (closed-enum exhaustive
///   over `ScalarExpr`).
///
/// Subqueries embedded in expressions recursively project their own
/// [`QueryFacts`] into [`super::expr::SubqueryExpr::inner_facts`], so a
/// rule can traverse `where_predicates[].root.subquery.inner_facts.scopes…`
/// to reach inside-the-subquery facts.
pub fn project_query_facts<'a>(
    plan: &'a RelPlan,
    bindings: &'a BindingTable,
    derived_facts: &DerivedFacts,
    ctx: &'a CatalogCtx<'a>,
) -> QueryFacts {
    let reasoning = ctx.reasoning.for_query(super::reasoning::QueryInputs {
        plan,
        bindings,
        catalog: ctx.known.or(ctx.catalog),
        function_catalog: ctx.function_catalog,
        source: ctx.source,
    });
    let mut facts = project_query_facts_with_outer_ctes(
        plan,
        bindings,
        derived_facts,
        ctx,
        &[],
        reasoning.as_ref(),
    );
    if ctx.output_columns {
        facts.output_columns = project_output_columns(plan, bindings, ctx, reasoning.as_ref());
    }
    facts
}

/// Whether `written`, a select item of `project`, is a column that a filter
/// directly below the projection keeps only where it is not NULL: a
/// top-level `col IS NOT NULL` conjunct of its predicate.
fn kept_not_null_below(project: &RelPlan, written: &ScalarExpr) -> bool {
    let ScalarExpr::Column { column, .. } = written else {
        return false;
    };
    let RelPlan::Project { input, .. } = project else {
        return false;
    };
    let mut node = input.as_ref();
    while let RelPlan::Filter {
        input, predicate, ..
    } = node
    {
        if tests_not_null(predicate, *column) {
            return true;
        }
        node = input;
    }
    false
}

/// Whether `predicate` holds only where `column` is not NULL by a
/// `column IS NOT NULL` among its `AND`ed conjuncts.
fn tests_not_null(predicate: &ScalarExpr, column: ColumnId) -> bool {
    if let ScalarExpr::UnaryOp {
        op: crate::ir::scalar::UnaryOpKind::IsNotNull,
        arg,
        ..
    } = predicate
    {
        return matches!(arg.as_ref(), ScalarExpr::Column { column: tested, .. } if *tested == column);
    }
    if let ScalarExpr::BinOp {
        op: crate::ir::scalar::BinOpKind::And,
        left,
        right,
        ..
    } = predicate
    {
        return tests_not_null(left, column) || tests_not_null(right, column);
    }
    if let ScalarExpr::LogicalChain {
        op: crate::ir::scalar::LogicalOp::And,
        operands,
        ..
    } = predicate
    {
        return operands
            .iter()
            .any(|operand| tests_not_null(operand, column));
    }
    false
}

/// Nullability of `col` read at `site`: reasoning's answer, or, where
/// reasoning has none, the catalog's declaration for the id.
fn nullability_at(
    reasoning: &dyn super::reasoning::QueryReasoning,
    catalog: Option<&crate::ir::IndexedCatalogContext>,
    site: ReadSite<'_>,
    col: ColumnId,
) -> Nullability {
    match reasoning.nullability(site, col) {
        Nullability::Unknown => {
            let catalog_nullable = catalog.and_then(|cat| {
                let trait_obj: &dyn crate::ir::CatalogContext = cat;
                trait_obj.column_metadata(col).and_then(|m| m.nullable)
            });
            match catalog_nullable {
                Some(true) => Nullability::CatalogNullable,
                Some(false) => Nullability::CatalogNonNullable,
                None => Nullability::Unknown,
            }
        }
        known @ (Nullability::CatalogNullable
        | Nullability::CatalogNonNullable
        | Nullability::FilteredNonNullable
        | Nullability::DerivedNonNullable { .. }
        | Nullability::DerivedNullable { .. }) => known,
    }
}

/// Each column of the relation `plan` returns or makes
/// ([`returned_relation`]), in its order, named as the relation names it,
/// with what `reasoning` shows of it there.
fn project_output_columns(
    plan: &RelPlan,
    bindings: &BindingTable,
    ctx: &CatalogCtx<'_>,
    reasoning: &dyn super::reasoning::QueryReasoning,
) -> Vec<crate::facts::diff::OutputColumnFact> {
    use crate::facts::diff::OutputColumnFact;
    use crate::ir::schema::Position;
    let Some((relation, declared)) = returned_relation(plan) else {
        return Vec::new();
    };
    // A `CREATE … (names) AS` names the column at each position.
    let mut named: std::collections::HashMap<ColumnId, &str> = std::collections::HashMap::new();
    if let Some(declared) = declared {
        let positions = relation.positional_columns();
        for (index, name) in declared.iter().enumerate() {
            if let Position::Column(column) = positions.at(index) {
                named.insert(column, name.as_str());
            }
        }
    }
    let site = ReadSite {
        node: relation,
        at: ReadAt::Output,
    };
    relation
        .output_schema()
        .into_iter()
        .map(|column| {
            let name = named.get(&column).copied().unwrap_or_else(|| {
                bindings
                    .get(column)
                    .map_or("", |binding| binding.display_name.as_str())
            });
            let nullable = match nullability_at(reasoning, ctx.catalog, site, column) {
                Nullability::CatalogNullable | Nullability::DerivedNullable { .. } => Some(true),
                Nullability::CatalogNonNullable
                | Nullability::DerivedNonNullable { .. }
                | Nullability::FilteredNonNullable => Some(false),
                Nullability::Unknown => None,
            };
            let sources = reasoning.lineage_roots(column).map(|roots| {
                roots
                    .iter()
                    .map(|root| source_column_ref(*root, bindings, ctx))
                    .collect()
            });
            let taint_tags = reasoning
                .output_catalog_tags(column)
                .into_iter()
                .map(|tag| CatalogTag {
                    key: PublicIdentName::new(&tag.qualified_name),
                    value: tag.value,
                })
                .collect();
            let constraints = project_constraint_set(
                &reasoning.output_constraints(relation, column),
                reasoning.output_unique(relation, column),
            );
            OutputColumnFact {
                column: ColumnRef::minimal(column_name(name), None),
                nullable,
                sources,
                taint_tags,
                constraints,
            }
        })
        .collect()
}

/// A column's name `name`. One that can hold a literal (a column named by
/// its expression's text, which no identifier spells, or by a value a
/// pivot reads) is made of text the source writes somewhere the relations
/// that pass the name on do not record: a report masks it wherever the
/// source holds a literal it does not show.
fn column_name(name: &str) -> PublicIdentName {
    let written = PublicIdentName::new(name);
    let spells_an_identifier = name
        .chars()
        .next()
        .is_some_and(|first| !first.is_ascii_digit())
        && name
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '_' | '$' | '#' | '@'));
    let holds_text = !spells_an_identifier
        || name.contains('\'')
        || ["$$", "{{", "{%"].iter().any(|open| name.contains(open));
    match holds_text {
        true => written.written_at(Span {
            start: 0,
            end: u32::MAX,
        }),
        false => written,
    }
}

/// A column a value is drawn from, named with the table it is read from
/// where the plan names one.
fn source_column_ref(id: ColumnId, bindings: &BindingTable, ctx: &CatalogCtx<'_>) -> ColumnRef {
    use crate::ir::column::ColumnOrigin;
    let Some(binding) = bindings.get(id) else {
        return ColumnRef::minimal(PublicIdentName::new(""), None);
    };
    let table = match &binding.origin {
        ColumnOrigin::Table { table_node, .. } => ctx
            .scan_index
            .and_then(|index| index.get(table_node))
            .map(|table| project_metadata_table_ref(table, None)),
        ColumnOrigin::Computed { .. }
        | ColumnOrigin::Merged { .. }
        | ColumnOrigin::SetOp { .. }
        | ColumnOrigin::OuterRef { .. }
        | ColumnOrigin::RecursiveRef { .. }
        | ColumnOrigin::Unattributed { .. } => None,
    };
    ColumnRef::minimal(column_name(&binding.display_name), table)
}

/// Variant of [`project_query_facts`] for a scope nested in a statement:
/// `outer_ctes` are the CTE bindings visible at the scope's root, so a
/// `CteRef` inside it resolves to its binding even though `plan` does not
/// carry the enclosing `WithScope`, and `reasoning` is the scope's
/// reasoning. A statement root passes `&[]` and the statement's reasoning.
pub fn project_query_facts_with_outer_ctes<'a>(
    plan: &'a RelPlan,
    bindings: &'a BindingTable,
    derived_facts: &DerivedFacts,
    ctx: &'a CatalogCtx<'a>,
    outer_ctes: &[&'a crate::ir::plan::CteBinding],
    reasoning: &dyn super::reasoning::QueryReasoning,
) -> QueryFacts {
    let mut walker = QueryWalker::new(bindings, ctx, plan, reasoning, outer_ctes.to_vec());
    walker.walk(plan, ScopeIdentity::OUTER);
    let mut facts = walker.finalize(plan, derived_facts);
    // T-SQL OPENROWSET(...) call sites: walk the IR plan for
    // `OPENROWSET` TVF calls and project each one's literal string
    // arguments. Powers MSSQL-OPENROWSET-INLINE-CRED.
    for args in crate::ir::dynamic_sql::collect_openrowset_calls(plan) {
        let string_args = args
            .into_iter()
            .filter_map(|arg| project_remote_source_arg(arg, ctx))
            .collect();
        facts
            .openrowset_calls
            .push(crate::facts::query::OpenrowsetCallFacts { string_args });
    }
    // T-SQL OPENDATASOURCE(...) ad-hoc remote-source call sites. Same
    // shape as OPENROWSET; powers MSSQL-OPENDATASOURCE-INLINE-CRED.
    for args in crate::ir::dynamic_sql::collect_opendatasource_calls(plan) {
        let string_args = args
            .into_iter()
            .filter_map(|arg| project_remote_source_arg(arg, ctx))
            .collect();
        facts
            .opendatasource_calls
            .push(crate::facts::query::OpenrowsetCallFacts { string_args });
    }
    facts.function_calls = project_function_calls(plan, ctx.function_catalog);
    facts
}

/// A remote-source call's argument as facts: a string literal, with the
/// entries it writes read as a connection string, or a `'data source';
/// 'user';'password'` run, with its strings as those entries. `None` for
/// an argument that is neither.
fn project_remote_source_arg(
    arg: crate::ir::dynamic_sql::RemoteSourceArg,
    ctx: &CatalogCtx<'_>,
) -> Option<crate::facts::query::OpenrowsetArgFacts> {
    use crate::ir::dynamic_sql::RemoteSourceArg;
    use crate::ir::span_extract::{connection_string_entries, login_run_entries};
    let (value, entries) = match arg {
        RemoteSourceArg::String { written, span } => (
            written,
            connection_string_entries(span, ctx.source, ctx.placeholders),
        ),
        RemoteSourceArg::Text { span } => {
            let entries = login_run_entries(span, ctx.source, ctx.placeholders);
            if entries.is_empty() {
                return None;
            }
            (slice_span_text(ctx.source, span).to_string(), entries)
        }
    };
    let connection_string = entries
        .into_iter()
        .map(|entry| {
            let normalized = entry.key.to_ascii_uppercase();
            crate::facts::query::ConnectionStringEntry {
                key: IdentName::from_parts(entry.key, normalized),
                value_literal: entry.value,
            }
        })
        .collect();
    Some(crate::facts::query::OpenrowsetArgFacts {
        value,
        connection_string,
    })
}

/// Every function call in `plan`, nested plans included, named as a call
/// in an expression is published.
fn project_function_calls(
    plan: &RelPlan,
    catalog: &crate::ir::FunctionCatalog,
) -> Vec<crate::facts::query::FunctionCallEvent> {
    use crate::ir::visitor::{walk_rel_plan, walk_scalar_expr, RelPlanVisitor};

    struct Calls<'c> {
        catalog: &'c crate::ir::FunctionCatalog,
        found: Vec<crate::facts::query::FunctionCallEvent>,
    }

    impl<'a> RelPlanVisitor<'a> for Calls<'_> {
        fn visit_rel_plan(&mut self, plan: &'a RelPlan) {
            walk_rel_plan(self, plan);
        }

        fn visit_scalar_expr(&mut self, expr: &'a ScalarExpr) {
            if let ScalarExpr::FuncCall { func, span, .. } = expr {
                // A call the catalog does not hold keeps its name as
                // written, qualified or not: `pg_catalog.lo_export` is
                // `lo_export` in schema `pg_catalog`.
                let (name, schema) = match func {
                    ResolvedFunc::Unresolved {
                        raw_name,
                        namespace,
                        ..
                    } => {
                        let mut parts = crate::ir::lower_ddl::split_qualified(raw_name);
                        let name = parts.pop().unwrap_or_else(|| raw_name.clone());
                        let schema = namespace.clone().or_else(|| parts.pop());
                        (PublicIdentName::new(name), schema.map(PublicIdentName::new))
                    }
                    ResolvedFunc::Resolved { .. } => (resolved_func_name(func, self.catalog), None),
                };
                self.found.push(crate::facts::query::FunctionCallEvent {
                    name,
                    schema,
                    source_span: Some(*span),
                });
            }
            walk_scalar_expr(self, expr);
        }
    }

    let mut calls = Calls {
        catalog,
        found: Vec::new(),
    };
    calls.visit_rel_plan(plan);
    calls.found
}

/// Walker state for [`project_query_facts`]. The `scopes` vec grows as
/// the walk descends through scope boundaries (CTE bodies, derived
/// tables, subqueries); the outer scope is pre-allocated at index 0.
/// `bindings` and `ctx` are threaded through expression projection so
/// `ColumnId`s resolve to display names and recursive subquery
/// projection can re-call `derive_facts_from_plan`.
struct QueryWalker<'a, 'r> {
    scopes: Vec<ScopeFacts>,
    next_scope_id: u32,
    bindings: &'a BindingTable,
    ctx: &'a CatalogCtx<'a>,
    has_sample: bool,
    /// Semantic analyses for the root plan: nullability, lineage,
    /// uniqueness, taint, volatility, and the predicate / constraint
    /// / cardinality queries the walk consults.
    reasoning: &'r dyn super::reasoning::QueryReasoning,
    /// CTE bindings from every enclosing `WithScope` visible at the
    /// current walk position. Inner subqueries inherit this list
    /// when they call `project_query_facts` recursively, so a
    /// `CteRef` inside the subquery can be resolved by the null-guard
    /// proof even though the subquery's local `root_plan` does not
    /// carry the enclosing `WithScope`.
    cte_bindings_in_scope: Vec<&'a crate::ir::plan::CteBinding>,
    /// Structural-position context for the top-level scalar expression
    /// currently being projected. `build_subquery_expr` reads this when
    /// emitting a `SubqueryRef` so downstream consumers can filter on
    /// `position: projection`. Set via `project_scalar_expr_at` at each
    /// top-level call site; nested recursive calls inside
    /// `project_scalar_expr` inherit the value (a scalar subquery inside
    /// a `COALESCE(...)` in a SELECT list is still in `Projection`).
    current_subquery_position: crate::facts::SubqueryPosition,
    /// Where the expression currently being projected reads its columns.
    /// Set beside `current_subquery_position` at each top-level
    /// expression site; nested projection inherits it.
    current_site: ReadSite<'a>,
    /// Group key output → the projection of its expression, for each key
    /// a select item presented. The key's `group_by` entry reuses it, so
    /// the expression's subqueries are registered once.
    presented_keys: std::collections::HashMap<ColumnId, Expr>,
    /// Each read of a group key's output that the query wrote as the
    /// key's expression, by column and span → the expression. Such a read
    /// is presented as the expression.
    written_keys: std::collections::HashMap<(ColumnId, Span), &'a ScalarExpr>,
    /// Each column a DML statement of the plan writes, with the
    /// statement's target.
    written_columns: Vec<(&'a legacy_meta::TableRef, ColumnId)>,
    /// Each column an `UPDATE` assignment, a `MERGE` branch or an upsert's
    /// update action of the plan writes to a catalogued table, with its
    /// tags and its value's.
    written_tags: Vec<crate::facts::query::WrittenColumnEvent>,
    /// Each column a table function the walk has passed yields: no
    /// catalog is asked whether it is a key.
    function_columns: std::collections::BTreeSet<ColumnId>,
    /// Per select list, what it reads, gathered on the way down to its
    /// scope's sources.
    select_reads: std::collections::BTreeMap<SelectList, SelectReads>,
    /// The scopes whose select list the walk is below.
    under_select_list: std::collections::BTreeSet<ScopeIdentity>,
    /// The set-operation branch the walk is in, per scope; none outside
    /// one.
    branches: std::collections::BTreeMap<ScopeIdentity, u32>,
    /// The number of set-operation branches the walk has entered.
    branches_entered: u32,
    /// Per derived table's scope, the select list that reads its columns
    /// and the body columns those are.
    derived_reads: std::collections::BTreeMap<
        ScopeIdentity,
        (SelectList, std::collections::HashSet<ColumnId>),
    >,
    /// Each published table function, for `columns_selected`.
    pending_functions: Vec<PendingFunction<'a>>,
}

/// A select list: its scope, and the set-operation branch it is the list
/// of (0 outside one).
type SelectList = (ScopeIdentity, u32);

/// Whether the source of everything a written value reads is known.
#[derive(Debug, Clone, Copy)]
enum ValueSource {
    Known,
    /// The value reads a column the plan places at no position of its
    /// source: which of the source's columns it holds is not known.
    PartlyUnknown,
}

/// A published table function whose `columns_selected` is settled after
/// the walk.
struct PendingFunction<'a> {
    /// The select list of its query.
    list: SelectList,
    /// Its scope's.
    scope: ScopeIdentity,
    /// Its place in the scope's `table_functions`.
    index: usize,
    /// The node of the source it is.
    node: crate::ast::NodeId,
    columns: &'a [ColumnId],
    alias: Option<&'a crate::context::node_metadata::IdentKey>,
    /// What its arguments read.
    argument_reads: std::collections::HashSet<ColumnId>,
}

impl<'a, 'r> QueryWalker<'a, 'r> {
    fn new(
        bindings: &'a BindingTable,
        ctx: &'a CatalogCtx<'a>,
        root_plan: &'a RelPlan,
        reasoning: &'r dyn super::reasoning::QueryReasoning,
        cte_bindings_in_scope: Vec<&'a crate::ir::plan::CteBinding>,
    ) -> Self {
        Self {
            scopes: vec![empty_scope_facts(
                ScopeIdentity::OUTER,
                ScopeKind::Outer,
                Some(root_plan.span()),
            )],
            next_scope_id: 1,
            bindings,
            ctx,
            has_sample: false,
            reasoning,
            cte_bindings_in_scope,
            current_subquery_position: crate::facts::SubqueryPosition::Other,
            current_site: ReadSite {
                node: root_plan,
                at: ReadAt::Context,
            },
            presented_keys: std::collections::HashMap::new(),
            written_keys: crate::ir::derived_facts::written_again_keys(root_plan),
            written_columns: Vec::new(),
            written_tags: Vec::new(),
            function_columns: std::collections::BTreeSet::new(),
            select_reads: std::collections::BTreeMap::new(),
            under_select_list: std::collections::BTreeSet::new(),
            branches: std::collections::BTreeMap::new(),
            branches_entered: 0,
            derived_reads: std::collections::BTreeMap::new(),
            pending_functions: Vec::new(),
        }
    }

    /// The select list of `scope` the walk is in.
    fn select_list(&self, scope: ScopeIdentity) -> SelectList {
        (scope, self.branches.get(&scope).copied().unwrap_or(0))
    }

    /// Settle each table function's `columns_selected`: the select list of
    /// its query reads one of its columns, or a column of a call whose
    /// arguments read one (`UNNEST(a.c) u1, UNNEST(u1.y) u2` selecting
    /// `u2` reads `u1`).
    fn settle_selected_functions(&mut self) {
        let pending = std::mem::take(&mut self.pending_functions);
        let mut selected = vec![false; pending.len()];
        let mut changed = true;
        while changed {
            changed = false;
            for (function, settled) in pending.iter().zip(selected.iter_mut()) {
                if *settled {
                    continue;
                }
                let Some(reads) = self.select_reads.get_mut(&function.list) else {
                    continue;
                };
                if reads.reads_function(function.columns, function.alias, function.node) {
                    *settled = true;
                    changed = true;
                    reads
                        .columns
                        .extend(function.argument_reads.iter().copied());
                }
            }
        }
        for (function, settled) in pending.iter().zip(selected) {
            if let Some(event) = self
                .scope_mut(function.scope)
                .table_functions
                .get_mut(function.index)
            {
                event.columns_selected = settled;
            }
        }
    }

    /// What the query wrote where `expr` stands, where `expr` is a read
    /// of a group key the query wrote as the key's expression.
    fn written_again(&self, expr: &ScalarExpr) -> Option<&'a ScalarExpr> {
        match expr {
            ScalarExpr::Column { column, span } => {
                self.written_keys.get(&(*column, *span)).copied()
            }
            ScalarExpr::OuterRef { .. }
            | ScalarExpr::Lit { .. }
            | ScalarExpr::BinOp { .. }
            | ScalarExpr::LogicalChain { .. }
            | ScalarExpr::OperatorChain { .. }
            | ScalarExpr::UnaryOp { .. }
            | ScalarExpr::FuncCall { .. }
            | ScalarExpr::Case { .. }
            | ScalarExpr::Cast { .. }
            | ScalarExpr::InList { .. }
            | ScalarExpr::Between { .. }
            | ScalarExpr::Like { .. }
            | ScalarExpr::Exists { .. }
            | ScalarExpr::ScalarSubquery { .. }
            | ScalarExpr::QuantifiedCmp { .. }
            | ScalarExpr::RowCmp { .. }
            | ScalarExpr::WindowFn { .. }
            | ScalarExpr::FieldAccess { .. }
            | ScalarExpr::Lambda { .. }
            | ScalarExpr::PatternVarRef { .. }
            | ScalarExpr::Opaque { .. } => None,
        }
    }

    /// Run `project` with `site` as the walker's read site, restoring the
    /// previous site on return so sibling expressions are unaffected.
    fn at_site<T>(&mut self, site: ReadSite<'a>, project: impl FnOnce(&mut Self) -> T) -> T {
        let prev = std::mem::replace(&mut self.current_site, site);
        let result = project(self);
        self.current_site = prev;
        result
    }

    /// Project a scalar expression read at `site`, with `position` scoped
    /// on the walker for the duration of the call (and any nested calls).
    /// Inner recursive calls inside `project_scalar_expr` inherit both,
    /// so a scalar subquery embedded several layers deep in a projection
    /// expression still receives `position: projection`. Restores the
    /// previous position on return so sibling expressions are unaffected.
    fn project_scalar_expr_at(
        &mut self,
        expr: &ScalarExpr,
        site: ReadSite<'a>,
        position: crate::facts::SubqueryPosition,
    ) -> Expr {
        let prev = std::mem::replace(&mut self.current_subquery_position, position);
        let result = self.at_site(site, |w| w.project_scalar_expr(expr));
        self.current_subquery_position = prev;
        result
    }

    /// Nullability of `col` read at `site`: reasoning's answer, or, where
    /// reasoning has none, the catalog's declaration for the id.
    fn nullability_at(&self, site: ReadSite<'_>, col: ColumnId) -> Nullability {
        nullability_at(self.reasoning, self.ctx.catalog, site, col)
    }

    fn alloc_scope(&mut self, kind: ScopeKind, source_span: Option<Span>) -> ScopeIdentity {
        let id = ScopeIdentity(self.next_scope_id);
        self.next_scope_id += 1;
        self.scopes.push(empty_scope_facts(id, kind, source_span));
        id
    }

    fn scope_mut(&mut self, id: ScopeIdentity) -> &mut ScopeFacts {
        // Scopes are append-only and indexed by `ScopeIdentity(u32)` in
        // allocation order. `OUTER` is `ScopeIdentity(0)` at index 0;
        // every subsequent allocation pushes at the back.
        let idx = id.0 as usize;
        &mut self.scopes[idx]
    }

    fn walk(&mut self, plan: &'a RelPlan, current: ScopeIdentity) {
        // What this node's expressions read.
        let context = ReadSite {
            node: plan,
            at: ReadAt::Context,
        };
        match plan {
            RelPlan::Scan { table, span, .. } => self.walk_scan(current, table, span),

            // Sources that are not base tables: excluded from
            // `tables_read`, as in `derive_facts_from_plan`.
            RelPlan::Values { .. } | RelPlan::CteRef { .. } | RelPlan::ModelRef { .. } => {}

            RelPlan::TableFunction {
                call,
                alias,
                output_columns,
                lateral,
                node_id,
                span,
                ..
            } => self.walk_table_function(
                current,
                context,
                call,
                alias,
                output_columns,
                lateral,
                node_id,
                span,
            ),

            // Project: emit ProjectionEvents (outer-only per scope) and
            // walk input.
            RelPlan::Project {
                input,
                items,
                distinct,
                distinct_on,
                ..
            } => self.walk_project(current, context, input, items, distinct, distinct_on),

            // Filter: classify by `kind` (Where / Qualify / Having) and
            // emit a PredicateEvent into the corresponding per-scope-set
            // (or set the outer-only `qualify` slot on first encounter).
            RelPlan::Filter {
                input,
                computed,
                predicate,
                kind,
                span,
                ..
            } => self.walk_filter(current, context, input, computed, predicate, kind, span),

            // Aggregate: emit AggregateEvents for each call (per-scope-set),
            // populate group_by (outer-only per scope), and surface
            // having into having_predicates.
            RelPlan::Aggregate {
                input,
                grouping,
                aggregates,
                having,
                computed,
                span,
                ..
            } => self.walk_aggregate(
                plan, current, context, input, grouping, aggregates, having, computed, span,
            ),

            // Window: emit WindowEvents per call (per-scope-set) and
            // walk input.
            RelPlan::Window {
                input,
                windows,
                computed,
                ..
            } => self.walk_window(current, context, input, windows, computed),

            // Sort: populate order_by (outer-only per scope) and walk
            // input.
            RelPlan::Sort { input, keys, .. } => {
                self.emit_order_by(current, context, keys);
                self.walk(input, current);
            }

            // Limit: populate limit (outer-only per scope) and walk
            // input.
            RelPlan::Limit {
                input,
                limit,
                offset,
                span,
                ..
            } => self.walk_limit(current, context, input, limit, offset, span),

            RelPlan::TableSample { input, .. } => {
                self.has_sample = true;
                self.walk(input, current);
            }

            RelPlan::Pivot {
                input, aggregates, ..
            } => {
                // PIVOT carries aggregate calls; project them so rules
                // that audit aggregates over PIVOT see the same shape.
                self.emit_aggregate_calls(current, context, aggregates);
                self.walk(input, current);
            }

            RelPlan::Unpivot { input, .. }
            | RelPlan::Unnest { input, .. }
            | RelPlan::MatchRecognize { input, .. }
            | RelPlan::ConnectBy { input, .. } => {
                self.walk(input, current);
            }

            RelPlan::Explain { body, .. } => self.walk(body, current),

            RelPlan::Join {
                left,
                right,
                kind,
                lateral,
                natural,
                implicit,
                on,
                match_condition,
                span,
                clause_span,
                ..
            } => self.walk_join(
                plan,
                current,
                context,
                left,
                right,
                kind,
                lateral,
                natural,
                implicit,
                on,
                match_condition,
                span,
                clause_span,
            ),

            RelPlan::SetOp {
                op, inputs, span, ..
            } => self.walk_set_op(current, op, inputs, span),

            RelPlan::WithScope { ctes, body, .. } => self.walk_with_scope(current, ctes, body),

            RelPlan::DerivedTable {
                input,
                alias,
                columns,
                body_columns,
                span,
                ..
            } => self.walk_derived_table(current, input, alias, columns, body_columns, span),

            RelPlan::Insert {
                target,
                target_columns,
                unplaced_columns,
                source,
                on_conflict,
                span,
                ..
            } => self.walk_insert(
                current,
                target,
                target_columns,
                unplaced_columns,
                source,
                on_conflict,
                span,
            ),

            RelPlan::Update {
                target,
                assignments,
                from,
                predicate,
                span,
                ..
            } => self.walk_update(current, context, target, assignments, from, predicate, span),

            RelPlan::Delete {
                target,
                using,
                predicate,
                span,
                ..
            } => self.walk_delete(current, context, target, using, predicate, span),

            RelPlan::Merge {
                target,
                source,
                on,
                branches,
                span,
                ..
            } => self.walk_merge(current, context, target, source, on, branches, span),

            RelPlan::MultiInsert {
                source,
                unconditional_clauses,
                when_clauses,
                else_clauses,
                ..
            } => {
                let whens = when_clauses.iter().flat_map(|when| &when.targets);
                for into in unconditional_clauses
                    .iter()
                    .chain(whens)
                    .chain(else_clauses)
                {
                    self.written_columns.extend(
                        into.target_columns
                            .iter()
                            .map(|written| (&into.target, *written)),
                    );
                }
                self.walk(source, current);
            }

            RelPlan::CreateAsQuery {
                target, body, span, ..
            } => self.walk_create_as_query(current, target, body, span),

            RelPlan::CreateTableForm { target, span, .. } => {
                self.walk_create_table_form(current, target, span)
            }

            // Terminal recovery / opaque arms. No structure to project.
            RelPlan::InvalidInput { .. }
            | RelPlan::ParseRecovery { .. }
            | RelPlan::Opaque { .. } => {}
        }
    }

    /// [`Self::walk`] of a `RelPlan::Scan`.
    #[inline(never)]
    fn walk_scan(
        &mut self,
        current: ScopeIdentity,
        table: &'a crate::context::node_metadata::TableRef,
        span: &'a Span,
    ) {
        let (catalog_tags, row_count, column_count, table_kind, in_catalog, searched_as) =
            table_catalog_metadata(table, self.ctx.catalog);
        let event = TableEvent {
            table: project_metadata_table_ref(table, Some(*span)),
            scope_id: current,
            source_span: Some(*span),
            catalog_tags,
            row_count,
            column_count,
            access_kind: TableAccessKind::Read,
            table_kind,
            in_catalog,
            searched_as,
            temporary: false,
        };
        self.scope_mut(current).tables.push(event);
    }

    /// [`Self::walk`] of a `RelPlan::TableFunction`.
    #[inline(never)]
    #[allow(clippy::too_many_arguments)] // the variant's fields, as `walk` binds them
    fn walk_table_function(
        &mut self,
        current: ScopeIdentity,
        context: ReadSite<'a>,
        call: &'a ScalarExpr,
        alias: &'a Option<crate::context::node_metadata::IdentKey>,
        output_columns: &'a [ColumnId],
        lateral: &'a bool,
        node_id: &'a crate::ast::NodeId,
        span: &'a Span,
    ) {
        self.function_columns.extend(output_columns.iter().copied());
        // A source that is a call publishes it; one that is a
        // variable or another value is no call.
        let projected = match self.at_site(context, |w| w.project_scalar_expr(call)) {
            Expr::FuncCall { func_call } => Some(func_call),
            Expr::Column { .. }
            | Expr::Literal { .. }
            | Expr::BinaryOp { .. }
            | Expr::LogicalChain { .. }
            | Expr::OperatorChain { .. }
            | Expr::UnaryOp { .. }
            | Expr::Case { .. }
            | Expr::Cast { .. }
            | Expr::Tuple { .. }
            | Expr::InList { .. }
            | Expr::Subquery { .. }
            | Expr::QuantifiedCmp { .. }
            | Expr::Star { .. }
            | Expr::Collection { .. }
            | Expr::OuterColumn { .. }
            | Expr::Parameter { .. }
            | Expr::Window { .. }
            | Expr::FieldAccess { .. }
            | Expr::IndexAccess { .. }
            | Expr::Opaque { .. } => None,
        };
        if let Some(projected) = projected {
            let origin = match call.called_function() {
                Some(ResolvedFunc::Resolved { .. }) => FunctionOrigin::BuiltIn,
                Some(ResolvedFunc::Unresolved { .. }) | None => FunctionOrigin::User,
            };
            let mut argument_reads = std::collections::HashSet::new();
            collect_reads(call, &mut argument_reads);
            let index = self.scope_mut(current).table_functions.len();
            self.pending_functions.push(PendingFunction {
                list: self.select_list(current),
                scope: current,
                index,
                node: *node_id,
                columns: output_columns,
                alias: alias.as_ref(),
                argument_reads,
            });
            self.scope_mut(current)
                .table_functions
                .push(TableFunctionEvent {
                    call: projected,
                    origin,
                    // Settled once the walk has seen every select list.
                    columns_selected: false,
                    alias: alias.as_ref().map(|a| column_name(a.as_str())),
                    lateral: *lateral,
                    source_span: Some(*span),
                });
        }
    }

    /// [`Self::walk`] of a `RelPlan::Project`.
    #[inline(never)]
    fn walk_project(
        &mut self,
        current: ScopeIdentity,
        context: ReadSite<'a>,
        input: &'a RelPlan,
        items: &'a [ProjectItem],
        distinct: &'a bool,
        distinct_on: &'a [ScalarExpr],
    ) {
        // `has_distinct` reflects the scope's outermost
        // `Project { distinct: true }` — the visit order is
        // outside-in so the first arm to see this scope wins.
        // `DISTINCT ON` is excluded (semantically GROUP BY,
        // surfaced via `group_by`).
        if *distinct && !self.scope_mut(current).has_distinct {
            self.scope_mut(current).has_distinct = true;
        }
        self.emit_project_items(current, context, input, items, distinct_on);
        // The first `Project` down a scope's walk is its select
        // list (one per set-operation branch); one below it
        // computes what the list reads.
        let select_list = self.under_select_list.insert(current);
        let list = self.select_list(current);
        let reads = self.select_reads.entry(list).or_default();
        for item in items {
            match item {
                ProjectItem::Expr(p) if select_list => reads.add(&p.expr),
                ProjectItem::Expr(p) => reads.add_for(p.output, &p.expr),
                ProjectItem::Star(star) if select_list => {
                    let qualifier = match &star.qualifier {
                        StarQualifier::Unqualified => Some(None),
                        StarQualifier::Named(parts) => {
                            parts.last().map(|last| Some(last.name.clone()))
                        }
                        StarQualifier::FromExpr(expr) => {
                            reads.add(expr);
                            None
                        }
                    };
                    if let Some(qualifier) = qualifier {
                        reads.stars.push(StarCover {
                            qualifier,
                            enumerated: star.enumerated.clone(),
                        });
                    }
                    for replace in &star.replace {
                        reads.add(&replace.expr);
                    }
                }
                ProjectItem::Star(_) => {}
            }
        }
        // A derived table's select list: what its items read for the
        // enclosing list that reads their columns, it reads too.
        if select_list {
            if let Some((outer, body_columns)) = self.derived_reads.remove(&current) {
                let read: Vec<&ScalarExpr> = items
                    .iter()
                    .filter_map(|item| match item {
                        ProjectItem::Expr(p) if body_columns.contains(&p.output) => Some(&p.expr),
                        ProjectItem::Expr(_) | ProjectItem::Star(_) => None,
                    })
                    .collect();
                if let Some(outer_reads) = self.select_reads.get_mut(&outer) {
                    for expr in read {
                        outer_reads.add(expr);
                    }
                }
            }
        }
        self.walk(input, current);
        if select_list {
            self.under_select_list.remove(&current);
        }
    }

    /// [`Self::walk`] of a `RelPlan::Filter`.
    #[inline(never)]
    #[allow(clippy::too_many_arguments)] // the variant's fields, as `walk` binds them
    fn walk_filter(
        &mut self,
        current: ScopeIdentity,
        context: ReadSite<'a>,
        input: &'a RelPlan,
        computed: &'a [crate::ir::plan::ComputedItem],
        predicate: &'a ScalarExpr,
        kind: &'a crate::ir::plan::FilterKind,
        span: &'a Span,
    ) {
        let list = self.select_list(current);
        if let Some(reads) = self.select_reads.get_mut(&list) {
            reads.add_computed(computed);
        }
        let position = match kind {
            FilterKind::Where => crate::facts::SubqueryPosition::Where,
            FilterKind::Having => crate::facts::SubqueryPosition::Having,
            FilterKind::Qualify => crate::facts::SubqueryPosition::Qualify,
        };
        let projected = self.project_scalar_expr_at(predicate, context, position);
        match kind {
            FilterKind::Where => {
                let event = PredicateEvent {
                    root: projected.clone(),
                    scope_id: current,
                    null_effects: Vec::new(),
                    cross_scope_effects: Vec::new(),
                    source_span: Some(*span),
                };
                self.scope_mut(current).where_predicates.push(event);
                self.scope_mut(current).predicates.push(PredicateNode {
                    kind: PredicateKind::Where,
                    root: projected,
                    scope_id: current,
                    source_span: Some(*span),
                    null_effects: Vec::new(),
                    cross_scope_effects: Vec::new(),
                });
            }
            FilterKind::Qualify => {
                if self.scope_mut(current).qualify.is_none() {
                    self.scope_mut(current).qualify = Some(projected.clone());
                }
                self.scope_mut(current).predicates.push(PredicateNode {
                    kind: PredicateKind::Qualify,
                    root: projected,
                    scope_id: current,
                    source_span: Some(*span),
                    null_effects: Vec::new(),
                    cross_scope_effects: Vec::new(),
                });
            }
            FilterKind::Having => {
                let event = PredicateEvent {
                    root: projected.clone(),
                    null_effects: Vec::new(),
                    cross_scope_effects: Vec::new(),
                    scope_id: current,
                    source_span: Some(*span),
                };
                self.scope_mut(current).having_predicates.push(event);
                self.scope_mut(current).predicates.push(PredicateNode {
                    kind: PredicateKind::Having,
                    root: projected,
                    scope_id: current,
                    source_span: Some(*span),
                    null_effects: Vec::new(),
                    cross_scope_effects: Vec::new(),
                });
            }
        }
        self.walk(input, current);
    }

    /// [`Self::walk`] of a `RelPlan::Aggregate`.
    #[inline(never)]
    #[allow(clippy::too_many_arguments)] // the variant's fields, as `walk` binds them
    fn walk_aggregate(
        &mut self,
        plan: &'a RelPlan,
        current: ScopeIdentity,
        context: ReadSite<'a>,
        input: &'a RelPlan,
        grouping: &'a GroupingSpec,
        aggregates: &'a [crate::ir::plan::AggregateCall],
        having: &'a Option<ScalarExpr>,
        computed: &'a [crate::ir::plan::ComputedItem],
        span: &'a Span,
    ) {
        let list = self.select_list(current);
        if let Some(reads) = self.select_reads.get_mut(&list) {
            for call in aggregates {
                if reads.columns.contains(&call.output) {
                    for arg in call
                        .args
                        .iter()
                        .chain(call.named_args.iter().map(|(_, v)| v))
                    {
                        reads.add(arg);
                    }
                    if let Some(filter) = &call.filter {
                        reads.add(filter);
                    }
                    for key in call.arg_order.iter().chain(&call.within_group_order) {
                        reads.add(&key.expr);
                    }
                }
            }
            let keys: &[crate::ir::plan::GroupKey] = match grouping {
                GroupingSpec::None => &[],
                GroupingSpec::Standard(keys)
                | GroupingSpec::Cube(keys)
                | GroupingSpec::Rollup(keys)
                | GroupingSpec::All { keys, .. } => keys,
                GroupingSpec::GroupingSets(sets) => &sets.keys,
            };
            for key in keys {
                reads.add_for(key.output, &key.expr);
            }
            reads.add_computed(computed);
        }
        self.emit_aggregate_calls(current, context, aggregates);
        self.emit_group_by(current, context, plan, grouping);
        if let Some(having_expr) = having {
            // `HAVING` reads the grouped rows.
            let projected = self.project_scalar_expr_at(
                having_expr,
                ReadSite {
                    node: plan,
                    at: ReadAt::Defined,
                },
                crate::facts::SubqueryPosition::Having,
            );
            let event = PredicateEvent {
                root: projected.clone(),
                scope_id: current,
                source_span: Some(*span),
                null_effects: Vec::new(),
                cross_scope_effects: Vec::new(),
            };
            self.scope_mut(current).having_predicates.push(event);
            self.scope_mut(current).predicates.push(PredicateNode {
                kind: PredicateKind::Having,
                root: projected,
                scope_id: current,
                source_span: Some(*span),
                null_effects: Vec::new(),
                cross_scope_effects: Vec::new(),
            });
        }
        self.walk(input, current);
    }

    /// [`Self::walk`] of a `RelPlan::Window`.
    #[inline(never)]
    fn walk_window(
        &mut self,
        current: ScopeIdentity,
        context: ReadSite<'a>,
        input: &'a RelPlan,
        windows: &'a [crate::ir::plan::WindowCall],
        computed: &'a [crate::ir::plan::ComputedItem],
    ) {
        let list = self.select_list(current);
        if let Some(reads) = self.select_reads.get_mut(&list) {
            for call in windows {
                if reads.columns.contains(&call.output) {
                    for expr in call.args.iter().chain(&call.partition_by) {
                        reads.add(expr);
                    }
                    for key in &call.order_by {
                        reads.add(&key.expr);
                    }
                }
            }
            reads.add_computed(computed);
        }
        self.emit_window_calls(current, context, windows);
        self.walk(input, current);
    }

    /// [`Self::walk`] of a `RelPlan::Limit`.
    #[inline(never)]
    fn walk_limit(
        &mut self,
        current: ScopeIdentity,
        context: ReadSite<'a>,
        input: &'a RelPlan,
        limit: &'a Option<ScalarExpr>,
        offset: &'a Option<ScalarExpr>,
        span: &'a Span,
    ) {
        if self.scope_mut(current).limit.is_none() {
            let (limit_expr, offset_expr) = self.at_site(context, |w| {
                (
                    limit.as_ref().map(|e| w.project_scalar_expr(e)),
                    offset.as_ref().map(|e| w.project_scalar_expr(e)),
                )
            });
            self.scope_mut(current).limit = Some(LimitEvent {
                limit: limit_expr,
                offset: offset_expr,
                source_span: Some(*span),
            });
        }
        self.walk(input, current);
    }

    /// [`Self::walk`] of a `RelPlan::Join`.
    #[inline(never)]
    #[allow(clippy::too_many_arguments)] // the variant's fields, as `walk` binds them
    fn walk_join(
        &mut self,
        plan: &'a RelPlan,
        current: ScopeIdentity,
        context: ReadSite<'a>,
        left: &'a RelPlan,
        right: &'a RelPlan,
        kind: &'a crate::ir::plan::JoinKind,
        lateral: &'a bool,
        natural: &'a bool,
        implicit: &'a bool,
        on: &'a Option<ScalarExpr>,
        match_condition: &'a Option<ScalarExpr>,
        span: &'a Span,
        clause_span: &'a Span,
    ) {
        self.walk(left, current);
        self.walk(right, current);
        let on_predicate = on.as_ref().map(|e| {
            self.project_scalar_expr_at(e, context, crate::facts::SubqueryPosition::JoinOn)
        });
        let filters_join = on.as_ref().map(predicate_filters_join).unwrap_or(false);
        if let Some(predicate_expr) = on.as_ref() {
            let projected = self.project_scalar_expr_at(
                predicate_expr,
                context,
                crate::facts::SubqueryPosition::JoinOn,
            );
            let public_kind = project_join_kind(*kind, *lateral, *natural);
            self.scope_mut(current)
                .join_predicates
                .push(JoinPredicateEvent {
                    root: projected.clone(),
                    scope_id: current,
                    source_span: Some(*span),
                });
            self.scope_mut(current).predicates.push(PredicateNode {
                kind: PredicateKind::JoinOn {
                    join_kind: public_kind,
                },
                root: projected,
                scope_id: current,
                source_span: Some(*span),
                null_effects: Vec::new(),
                cross_scope_effects: Vec::new(),
            });
        }
        if let Some(mc_expr) = match_condition.as_ref() {
            let mc_span = mc_expr.span();
            let projected = self.at_site(context, |w| w.project_scalar_expr(mc_expr));
            self.scope_mut(current).predicates.push(PredicateNode {
                kind: PredicateKind::AsofMatch,
                root: projected,
                scope_id: current,
                source_span: Some(mc_span),
                null_effects: Vec::new(),
                cross_scope_effects: Vec::new(),
            });
        }
        let functions = self.ctx.function_catalog;
        if let (Some(l), Some(r)) = (
            principal_source(left, functions),
            principal_source(right, functions),
        ) {
            let right_source = join_right_source(&r, left, self.bindings);
            let join_key = ReadSite {
                node: plan,
                at: ReadAt::JoinKey,
            };
            let on_columns = on
                .as_ref()
                .map(|e| self.extract_join_column_pairs(e, join_key))
                .unwrap_or_default();
            // Catalog-aware row-count estimates for the
            // operands' principal base tables. Used by
            // Q-JOIN-CROSS-CENH to size the cartesian product in
            // its message; absent when no catalog is
            // attached or the table has no row_count estimate.
            let (left_row_count, right_row_count) = match self.ctx.catalog {
                Some(cat) => (
                    principal_scan_metadata_table_ref_with_ctes(left, &self.cte_bindings_in_scope)
                        .and_then(|t| cat.table_row_count(t)),
                    principal_scan_metadata_table_ref_with_ctes(right, &self.cte_bindings_in_scope)
                        .and_then(|t| cat.table_row_count(t)),
                ),
                None => (None, None),
            };
            let cartesian_estimate = match (left_row_count, right_row_count) {
                (Some(a), Some(b)) => Some(a.saturating_mul(b)),
                _ => None,
            };
            // A column the join names no reference to is anchored at its
            // clause.
            let dropped_padded_columns = self
                .reasoning
                .dropped_padded_columns(plan)
                .into_iter()
                .map(|dropped| {
                    let span = dropped.column_ref_span.or(Some(*clause_span));
                    let mut column = self.column_ref_at(context, dropped.column, span);
                    column.nullability = dropped.nullability;
                    column
                })
                .collect();
            self.scope_mut(current).joins.push(JoinEvent {
                left: l.name,
                right: r.name,
                right_source,
                kind: project_join_kind(*kind, *lateral, *natural),
                on_columns,
                on_predicate,
                source_span: Some(*clause_span),
                filters_join,
                implicit: *implicit,
                left_row_count,
                right_row_count,
                cartesian_estimate,
                dropped_padded_columns,
            });
        }
    }

    /// [`Self::walk`] of a `RelPlan::SetOp`.
    #[inline(never)]
    fn walk_set_op(
        &mut self,
        current: ScopeIdentity,
        op: &'a crate::ir::plan::SetOpKind,
        inputs: &'a [Box<RelPlan>],
        span: &'a Span,
    ) {
        self.scope_mut(current).set_operations.push(SetOpEvent {
            kind: project_set_op_kind(*op),
            branch_count: inputs.len() as u32,
            source_span: Some(*span),
        });
        // Each branch has a select list of its own.
        let enclosing = self.branches.get(&current).copied();
        for input in inputs {
            self.branches_entered += 1;
            self.branches.insert(current, self.branches_entered);
            self.walk(input, current);
        }
        match enclosing {
            Some(branch) => self.branches.insert(current, branch),
            None => self.branches.remove(&current),
        };
    }

    /// [`Self::walk`] of a `RelPlan::WithScope`.
    #[inline(never)]
    fn walk_with_scope(
        &mut self,
        current: ScopeIdentity,
        ctes: &'a [crate::ir::plan::CteBinding],
        body: &'a RelPlan,
    ) {
        // Push each CTE binding onto the scope's accumulated
        // outer-CTE list before walking its body, so a sibling
        // CTE (and the WithScope's body) can resolve CteRefs
        // to earlier-declared CTEs. Pop after walking the body
        // so sibling-level WithScopes don't leak.
        let pushed = ctes.len();
        for cte in ctes {
            self.cte_bindings_in_scope.push(cte);
            let recursive = matches!(cte.body, CteBody::Recursive { .. });
            let cte_scope = self.alloc_scope(
                ScopeKind::Cte {
                    name: PublicIdentName::new(cte.name.as_str()),
                    recursive,
                },
                Some(cte.span),
            );
            match &cte.body {
                CteBody::NonRecursive(body) => {
                    self.walk(body, cte_scope);
                }
                CteBody::Recursive { anchor, step, .. } => {
                    // An anchor's DISTINCT is over the anchor's rows only:
                    // it marks the scope where the anchor holds one of the
                    // scope's joins, never for a join of the step.
                    let joins_before = self.scope_mut(cte_scope).joins.len();
                    self.walk(anchor, cte_scope);
                    let scope = self.scope_mut(cte_scope);
                    if scope.joins.len() == joins_before {
                        scope.has_distinct = false;
                    }
                    self.walk(step, cte_scope);
                }
            }
        }
        self.walk(body, current);
        for _ in 0..pushed {
            self.cte_bindings_in_scope.pop();
        }
    }

    /// [`Self::walk`] of a `RelPlan::DerivedTable`.
    #[inline(never)]
    fn walk_derived_table(
        &mut self,
        current: ScopeIdentity,
        input: &'a RelPlan,
        alias: &'a Option<crate::context::node_metadata::IdentKey>,
        columns: &'a [ColumnId],
        body_columns: &'a [Option<ColumnId>],
        span: &'a Span,
    ) {
        let alias_ident = alias
            .as_ref()
            .map(|a| PublicIdentName::new(a.as_str()))
            .unwrap_or_else(|| PublicIdentName::new(""));
        let dt_scope =
            self.alloc_scope(ScopeKind::DerivedTable { alias: alias_ident }, Some(*span));
        // The body columns the enclosing select list reads
        // (`LATERAL (SELECT f.value AS v) x` read as `x.v`).
        let list = self.select_list(current);
        if let Some(reads) = self.select_reads.get(&list) {
            let read: std::collections::HashSet<ColumnId> = columns
                .iter()
                .zip(body_columns)
                .filter(|(column, _)| reads.columns.contains(column))
                .filter_map(|(_, body)| *body)
                .collect();
            if !read.is_empty() {
                self.derived_reads.insert(dt_scope, (list, read));
            }
        }
        self.walk(input, dt_scope);
    }

    /// [`Self::walk`] of a `RelPlan::Insert`.
    #[inline(never)]
    #[allow(clippy::too_many_arguments)] // the variant's fields, as `walk` binds them
    fn walk_insert(
        &mut self,
        current: ScopeIdentity,
        target: &'a crate::context::node_metadata::TableRef,
        target_columns: &'a [ColumnId],
        unplaced_columns: &'a [ColumnId],
        source: &'a crate::ir::plan::InsertSource,
        on_conflict: &'a Option<crate::ir::plan::OnConflict>,
        span: &'a Span,
    ) {
        use crate::ir::plan::ConflictAction;
        let updated: &'a [crate::ir::plan::Assignment] =
            match on_conflict.as_ref().map(|conflict| &conflict.action) {
                Some(
                    ConflictAction::DoUpdate { assignments, .. }
                    | ConflictAction::MySqlDuplicateKeyUpdate { assignments },
                ) => assignments,
                Some(ConflictAction::DoNothing) | None => &[],
            };
        self.written_columns.extend(
            target_columns
                .iter()
                .chain(unplaced_columns)
                .map(|written| (target, *written)),
        );
        for assignment in updated {
            self.publish_assignment(target, assignment, unplaced_columns);
        }
        let (catalog_tags, row_count, column_count, table_kind, in_catalog, searched_as) =
            target_catalog_metadata(target, self.ctx.catalog);
        self.scope_mut(current).tables.push(TableEvent {
            table: project_metadata_table_ref(target, Some(*span)),
            scope_id: current,
            source_span: Some(*span),
            catalog_tags,
            row_count,
            column_count,
            access_kind: TableAccessKind::InsertedInto,
            table_kind,
            in_catalog,
            searched_as,
            temporary: false,
        });
        if let Some(plan) = insert_source_plan(source) {
            self.walk(plan, current);
        }
    }

    /// [`Self::walk`] of a `RelPlan::Update`.
    #[inline(never)]
    #[allow(clippy::too_many_arguments)] // the variant's fields, as `walk` binds them
    fn walk_update(
        &mut self,
        current: ScopeIdentity,
        context: ReadSite<'a>,
        target: &'a crate::context::node_metadata::TableRef,
        assignments: &'a [crate::ir::plan::Assignment],
        from: &'a Option<Box<RelPlan>>,
        predicate: &'a Option<ScalarExpr>,
        span: &'a Span,
    ) {
        // Each table an assignment writes: in a multi-table UPDATE, any
        // table listed before `SET`.
        let mut updated: Vec<&'a legacy_meta::TableRef> = Vec::new();
        for assignment in assignments {
            let table = match self.ctx.scan_index {
                Some(index) => index.written_table(assignment, target),
                None => target,
            };
            self.publish_assignment(table, assignment, &[]);
            if !updated.contains(&table) {
                updated.push(table);
            }
        }
        for table in updated {
            let (catalog_tags, row_count, column_count, table_kind, in_catalog, searched_as) =
                target_catalog_metadata(table, self.ctx.catalog);
            self.scope_mut(current).tables.push(TableEvent {
                table: project_metadata_table_ref(table, Some(*span)),
                scope_id: current,
                source_span: Some(*span),
                catalog_tags,
                row_count,
                column_count,
                access_kind: TableAccessKind::Updated,
                table_kind,
                in_catalog,
                searched_as,
                temporary: false,
            });
        }
        if let Some(from) = from {
            self.walk(from, current);
        }
        if let Some(pred) = predicate {
            let projected = self.at_site(context, |w| w.project_scalar_expr(pred));
            self.scope_mut(current)
                .where_predicates
                .push(PredicateEvent {
                    root: projected.clone(),
                    scope_id: current,
                    source_span: Some(*span),
                    null_effects: Vec::new(),
                    cross_scope_effects: Vec::new(),
                });
            self.scope_mut(current).predicates.push(PredicateNode {
                kind: PredicateKind::UpdateWhere,
                root: projected,
                scope_id: current,
                source_span: Some(*span),
                null_effects: Vec::new(),
                cross_scope_effects: Vec::new(),
            });
        }
    }

    /// [`Self::walk`] of a `RelPlan::Delete`.
    #[inline(never)]
    fn walk_delete(
        &mut self,
        current: ScopeIdentity,
        context: ReadSite<'a>,
        target: &'a crate::context::node_metadata::TableRef,
        using: &'a Option<Box<RelPlan>>,
        predicate: &'a Option<ScalarExpr>,
        span: &'a Span,
    ) {
        let (catalog_tags, row_count, column_count, table_kind, in_catalog, searched_as) =
            target_catalog_metadata(target, self.ctx.catalog);
        self.scope_mut(current).tables.push(TableEvent {
            table: project_metadata_table_ref(target, Some(*span)),
            scope_id: current,
            source_span: Some(*span),
            catalog_tags,
            row_count,
            column_count,
            access_kind: TableAccessKind::DeletedFrom,
            table_kind,
            in_catalog,
            searched_as,
            temporary: false,
        });
        if let Some(using) = using {
            self.walk(using, current);
        }
        if let Some(pred) = predicate {
            let projected = self.at_site(context, |w| w.project_scalar_expr(pred));
            self.scope_mut(current)
                .where_predicates
                .push(PredicateEvent {
                    root: projected.clone(),
                    scope_id: current,
                    source_span: Some(*span),
                    null_effects: Vec::new(),
                    cross_scope_effects: Vec::new(),
                });
            self.scope_mut(current).predicates.push(PredicateNode {
                kind: PredicateKind::DeleteWhere,
                root: projected,
                scope_id: current,
                source_span: Some(*span),
                null_effects: Vec::new(),
                cross_scope_effects: Vec::new(),
            });
        }
    }

    /// [`Self::walk`] of a `RelPlan::Merge`.
    #[inline(never)]
    #[allow(clippy::too_many_arguments)] // the variant's fields, as `walk` binds them
    fn walk_merge(
        &mut self,
        current: ScopeIdentity,
        context: ReadSite<'a>,
        target: &'a crate::context::node_metadata::TableRef,
        source: &'a RelPlan,
        on: &'a ScalarExpr,
        branches: &'a [crate::ir::plan::MergeBranch],
        span: &'a Span,
    ) {
        for branch in branches {
            use crate::ir::plan::MergeAction;
            match &branch.action {
                MergeAction::Insert {
                    target_columns,
                    values,
                } => {
                    for (position, written) in target_columns.iter().enumerate() {
                        let read = values
                            .get(position)
                            .map(|value| self.referenced_columns(value))
                            .unwrap_or_default();
                        self.publish_written_column(target, *written, read, ValueSource::Known);
                    }
                }
                MergeAction::Update { assignments } => {
                    for assignment in assignments {
                        self.publish_assignment(target, assignment, &[]);
                    }
                }
                MergeAction::InsertStar { columns }
                | MergeAction::InsertAllByName { columns }
                | MergeAction::UpdateSetStar { columns }
                | MergeAction::UpdateAllByName { columns } => {
                    for column in columns {
                        self.publish_written_column(
                            target,
                            column.written,
                            column.source,
                            ValueSource::Known,
                        );
                    }
                }
                MergeAction::Delete | MergeAction::DoNothing => {}
            }
        }
        let (catalog_tags, row_count, column_count, table_kind, in_catalog, searched_as) =
            target_catalog_metadata(target, self.ctx.catalog);
        self.scope_mut(current).tables.push(TableEvent {
            table: project_metadata_table_ref(target, Some(*span)),
            scope_id: current,
            source_span: Some(*span),
            catalog_tags,
            row_count,
            column_count,
            access_kind: TableAccessKind::ReadAndWritten,
            table_kind,
            in_catalog,
            searched_as,
            temporary: false,
        });
        self.walk(source, current);
        let projected_on = self.at_site(context, |w| w.project_scalar_expr(on));
        self.scope_mut(current)
            .join_predicates
            .push(JoinPredicateEvent {
                root: projected_on.clone(),
                scope_id: current,
                source_span: Some(*span),
            });
        self.scope_mut(current).predicates.push(PredicateNode {
            kind: PredicateKind::MergeOn,
            root: projected_on,
            scope_id: current,
            source_span: Some(*span),
            null_effects: Vec::new(),
            cross_scope_effects: Vec::new(),
        });
        for branch in branches {
            if let Some(branch_pred) = &branch.predicate {
                let projected = self.at_site(context, |w| w.project_scalar_expr(branch_pred));
                self.scope_mut(current).predicates.push(PredicateNode {
                    kind: PredicateKind::MergeWhen {
                        branch_kind: project_merge_branch_kind(branch.kind),
                    },
                    root: projected,
                    scope_id: current,
                    source_span: Some(branch.span),
                    null_effects: Vec::new(),
                    cross_scope_effects: Vec::new(),
                });
            }
        }
    }

    /// [`Self::walk`] of a `RelPlan::CreateAsQuery`.
    #[inline(never)]
    fn walk_create_as_query(
        &mut self,
        current: ScopeIdentity,
        target: &'a crate::context::node_metadata::TableRef,
        body: &'a Option<Box<RelPlan>>,
        span: &'a Span,
    ) {
        let (catalog_tags, row_count, column_count, table_kind, in_catalog, searched_as) =
            table_catalog_metadata(target, self.ctx.catalog);
        self.scope_mut(current).tables.push(TableEvent {
            table: project_metadata_table_ref(target, Some(*span)),
            scope_id: current,
            source_span: Some(*span),
            catalog_tags,
            row_count,
            column_count,
            access_kind: TableAccessKind::Written,
            table_kind,
            in_catalog,
            searched_as,
            temporary: false,
        });
        if let Some(body) = body {
            self.walk(body, current);
        }
    }

    /// [`Self::walk`] of a `RelPlan::CreateTableForm`.
    #[inline(never)]
    fn walk_create_table_form(
        &mut self,
        current: ScopeIdentity,
        target: &'a crate::context::node_metadata::TableRef,
        span: &'a Span,
    ) {
        let (catalog_tags, row_count, column_count, table_kind, in_catalog, searched_as) =
            table_catalog_metadata(target, self.ctx.catalog);
        self.scope_mut(current).tables.push(TableEvent {
            table: project_metadata_table_ref(target, Some(*span)),
            scope_id: current,
            source_span: Some(*span),
            catalog_tags,
            row_count,
            column_count,
            access_kind: TableAccessKind::Written,
            table_kind,
            in_catalog,
            searched_as,
            temporary: false,
        });
    }

    // ── Per-node emit helpers ──────────────────────────────────────────────

    fn emit_project_items(
        &mut self,
        current: ScopeIdentity,
        site: ReadSite<'a>,
        input: &'a RelPlan,
        items: &'a [ProjectItem],
        distinct_on: &[ScalarExpr],
    ) {
        // The first item that is a bare read of a group key that took a
        // select item's expression is that item, and is presented as the
        // expression: its projection, kind and taint read what the query
        // wrote. A later bare read is an alias of it and stays a column
        // read.
        let key_exprs =
            crate::ir::derived_facts::collect_outer_scope_synthesized_outputs(input).key_exprs;
        // A projection's own nullability is its column at the
        // projecting node's output.
        let output = ReadSite {
            node: site.node,
            at: ReadAt::Output,
        };
        // Outer-only: only the outermost Project of a scope contributes
        // to `projections` / `star_projections` / `group_by`-via-DISTINCT-ON.
        // Per-scope-set accumulators (`scalar_subqueries`) must still
        // receive contributions from every
        // projection-item expression — notably, sibling SetOp arms walk
        // with a shared `current` scope and their projection expressions
        // are the only path that surfaces arm-local scalar subqueries.
        let outer_only_already_emitted = !self.scope_mut(current).projections.is_empty()
            || !self.scope_mut(current).star_projections.is_empty();
        for item in items {
            match item {
                ProjectItem::Expr(p) => {
                    // An item its block computes before its calls is
                    // presented as what the query wrote for it, read where
                    // the block computes it: over the block's input rows.
                    let computing = match &p.expr {
                        ScalarExpr::Column { column, .. } => {
                            input.computed_before_calls_at(*column)
                        }
                        ScalarExpr::OuterRef { .. }
                        | ScalarExpr::PatternVarRef { .. }
                        | ScalarExpr::Lit { .. }
                        | ScalarExpr::Opaque { .. }
                        | ScalarExpr::BinOp { .. }
                        | ScalarExpr::LogicalChain { .. }
                        | ScalarExpr::OperatorChain { .. }
                        | ScalarExpr::UnaryOp { .. }
                        | ScalarExpr::FuncCall { .. }
                        | ScalarExpr::Case { .. }
                        | ScalarExpr::Cast { .. }
                        | ScalarExpr::InList { .. }
                        | ScalarExpr::Between { .. }
                        | ScalarExpr::Like { .. }
                        | ScalarExpr::Exists { .. }
                        | ScalarExpr::ScalarSubquery { .. }
                        | ScalarExpr::QuantifiedCmp { .. }
                        | ScalarExpr::RowCmp { .. }
                        | ScalarExpr::WindowFn { .. }
                        | ScalarExpr::FieldAccess { .. }
                        | ScalarExpr::Lambda { .. } => None,
                    };
                    let (own, own_site) = match computing {
                        Some((node, item)) => (
                            &item.expr,
                            ReadSite {
                                node,
                                at: ReadAt::Context,
                            },
                        ),
                        None => (&p.expr, site),
                    };
                    // An item the query wrote as a key's expression is
                    // that occurrence; the key presents its own.
                    let again = self.written_again(own);
                    let key = if again.is_some() {
                        None
                    } else if let ScalarExpr::Column { column, .. } = own {
                        key_exprs
                            .get(column)
                            .filter(|_| !self.presented_keys.contains_key(column))
                            .map(|&expr| (*column, expr))
                    } else {
                        None
                    };
                    let (written, read_at) = match (again, key) {
                        (Some(written), _) => (written, site),
                        (None, Some((_, expr))) => (expr, site),
                        (None, None) => (own, own_site),
                    };
                    let projected = self.project_scalar_expr_at(
                        written,
                        read_at,
                        crate::facts::SubqueryPosition::Projection,
                    );
                    if let Some((key_output, _)) = key {
                        self.presented_keys.insert(key_output, projected.clone());
                    }
                    if outer_only_already_emitted {
                        continue;
                    }
                    // The name a select item is given is written after its
                    // expression: a string literal there is its name.
                    let alias = p.alias.as_ref().map(|a| {
                        PublicIdentName::new(a.as_str()).written_at(Span {
                            start: p.expr.span().end,
                            end: p.span.end.max(p.expr.span().end),
                        })
                    });
                    let kind = classify_projection_expr(written);
                    // Where analysis has no answer, a column the query's own
                    // filter keeps only where it is not NULL is not NULL.
                    let nullability = match self.nullability_at(output, p.output) {
                        Nullability::Unknown if kept_not_null_below(output.node, written) => {
                            Nullability::FilteredNonNullable
                        }
                        known @ (Nullability::Unknown
                        | Nullability::CatalogNullable
                        | Nullability::CatalogNonNullable
                        | Nullability::FilteredNonNullable
                        | Nullability::DerivedNonNullable { .. }
                        | Nullability::DerivedNullable { .. }) => known,
                    };
                    let mut taint_labels = self.taint_labels_for_expr(written);
                    self.merge_ir_taint_for_output(p.output, &mut taint_labels);
                    let value_exposure = self.value_exposure_for_output(p.output);
                    self.scope_mut(current).projections.push(ProjectionEvent {
                        expr: projected,
                        alias,
                        kind,
                        nullability,
                        taint_labels,
                        value_exposure,
                        lineage: None,
                        source_span: Some(p.span),
                    });
                }
                ProjectItem::Star(s) => {
                    if outer_only_already_emitted {
                        continue;
                    }
                    let qualifier = match &s.qualifier {
                        StarQualifier::Unqualified => None,
                        StarQualifier::Named(parts) => parts.first().map(|p| {
                            PublicTableRef::new(
                                PublicIdentName::new(p.name.as_str()),
                                None,
                                None,
                                Some(p.span),
                            )
                        }),
                        StarQualifier::FromExpr(_) => None,
                    };
                    let proj_kind = match &s.qualifier {
                        StarQualifier::Unqualified => ProjectionKind::StarUnqualified,
                        StarQualifier::Named(parts) => ProjectionKind::StarQualified {
                            table_alias: parts
                                .first()
                                .map(|p| PublicIdentName::new(p.name.as_str()))
                                .unwrap_or_else(|| PublicIdentName::new("")),
                        },
                        // `<expr>.*` doesn't have a single identifier
                        // alias to surface; fall to unqualified for the
                        // ProjectionKind discriminator.
                        StarQualifier::FromExpr(_) => ProjectionKind::StarUnqualified,
                    };
                    self.scope_mut(current)
                        .star_projections
                        .push(StarProjectionEvent {
                            kind: proj_kind.clone(),
                            expanded_count: None,
                            source_span: Some(s.span),
                        });
                    let star_expr = Expr::Star {
                        star: StarExpr {
                            qualifier,
                            exclude: Vec::new(),
                            replace: Vec::new(),
                            rename: Vec::new(),
                        },
                    };
                    self.scope_mut(current).projections.push(ProjectionEvent {
                        expr: star_expr,
                        alias: None,
                        kind: proj_kind,
                        nullability: Nullability::Unknown,
                        taint_labels: Vec::new(),
                        value_exposure: crate::facts::catalog::ValueExposure::Value,
                        lineage: None,
                        source_span: Some(s.span),
                    });
                }
            }
        }
        // PostgreSQL `DISTINCT ON (e1, e2, ...)` exprs surface as
        // additional group_by-shaped facts — the public schema has no
        // dedicated slot, so they ride along on the projection list as
        // additional projection facts is unreasonable. Carry them as
        // group_by entries for now; this is the closest semantic fit
        // (DISTINCT ON behaves like GROUP BY for de-duplication).
        // group_by is outer-only (same first-arm-wins semantics as
        // `projections`); the project_scalar_expr walk still runs so
        // any embedded subqueries surface on `scalar_subqueries`.
        for e in distinct_on {
            let projected = self.at_site(site, |w| w.project_scalar_expr(e));
            if outer_only_already_emitted {
                continue;
            }
            self.scope_mut(current).group_by.push(projected);
        }
    }

    fn emit_aggregate_calls(
        &mut self,
        current: ScopeIdentity,
        site: ReadSite<'a>,
        calls: &[AggregateCall],
    ) {
        for call in calls {
            let function = aggregate_function_for(
                &call.func,
                call.distinct,
                call.args.len(),
                self.ctx.function_catalog,
            );
            let args = self.at_site(site, |w| {
                call.args
                    .iter()
                    .map(|a| w.project_scalar_expr(a))
                    .collect::<Vec<_>>()
            });
            // An aggregate runs on a nullable argument when either
            //   - an arg is the literal NULL, or
            //   - an arg references a column that may be NULL because
            //     the catalog declares a column it reads nullable.
            // The catalog-aware branch drives `Q-NULL-COUNT-CENH`
            // (`COUNT(nullable_col)` silently excludes NULL rows).
            let on_nullable_argument = call.args.iter().any(|a| {
                if let ScalarExpr::Lit {
                    value: Lit::Null, ..
                } = a
                {
                    return true;
                }
                if let ScalarExpr::Column { column, .. } = a {
                    return self.column_is_known_nullable(site, *column);
                }
                false
            });
            // Aggregate is non-deterministic iff any IR-side scalar
            // argument (or the optional FILTER predicate) directly
            // reaches a volatile `ResolvedFunc`, OR references a column
            // the reasoning reports volatile; that set covers every
            // scope of the statement, so a correlated argument resolves
            // against its enclosing scope.
            // Subquery args are not descended into — volatility inside a
            // scalar subquery affects the subquery's own determinism.
            let deterministic = !call.args.iter().any(|a| {
                crate::ir::volatile_expr::expr_is_volatile(
                    a,
                    self.reasoning.volatile_columns(),
                    self.ctx.function_catalog,
                )
            }) && !call
                .filter
                .as_ref()
                .map(|f| {
                    crate::ir::volatile_expr::expr_is_volatile(
                        f,
                        self.reasoning.volatile_columns(),
                        self.ctx.function_catalog,
                    )
                })
                .unwrap_or(false);
            let (filter, within_group) = self.at_site(site, |w| {
                let filter = call.filter.as_ref().map(|e| w.project_scalar_expr(e));
                let within_group = if call.within_group_order.is_empty() {
                    None
                } else {
                    Some(
                        call.within_group_order
                            .iter()
                            .map(|k| w.project_scalar_expr(&k.expr))
                            .collect(),
                    )
                };
                (filter, within_group)
            });
            self.scope_mut(current).aggregates.push(AggregateEvent {
                function,
                args,
                distinct: call.distinct,
                filter,
                within_group,
                scope_id: current,
                source_span: Some(call.span),
                on_nullable_argument,
                deterministic,
            });
        }
    }

    /// The keys of `grouping`, the grouping of `aggregate`, as the scope's
    /// `GROUP BY`, with the high-cardinality columns they read: a column
    /// the block computes before its calls is read as its definition.
    fn emit_group_by(
        &mut self,
        current: ScopeIdentity,
        site: ReadSite<'a>,
        aggregate: &RelPlan,
        grouping: &GroupingSpec,
    ) {
        if !self.scope_mut(current).group_by.is_empty() {
            return;
        }
        let keys: Vec<&crate::ir::plan::GroupKey> = match grouping {
            GroupingSpec::None => Vec::new(),
            GroupingSpec::Standard(k) | GroupingSpec::Cube(k) | GroupingSpec::Rollup(k) => {
                k.iter().collect()
            }
            GroupingSpec::GroupingSets(sets) => sets.keys.iter().collect(),
            GroupingSpec::All { keys: k, .. } => k.iter().collect(),
        };
        // Collect the distinct high-cardinality columns across every
        // grouping key, deduplicated by ColumnId (two same-named
        // columns from different tables are genuinely two keys). One
        // entry is the ordinary per-entity rollup; two or more multiply
        // the group count toward one group per row — the rule counts
        // them in YAML.
        let mut hicard_cids: Vec<crate::ir::ColumnId> = Vec::new();
        let mut hicard_names: Vec<IdentName> = Vec::new();
        for k in keys {
            let mut cols = Vec::new();
            self.collect_referenced_columns(&k.expr, &mut cols);
            // A definition reads only the columns before it, so this ends.
            let mut at = 0;
            while let Some(&cid) = cols.get(at) {
                match aggregate.computed_before_calls_at(cid) {
                    Some((_, item)) => {
                        cols.remove(at);
                        self.collect_referenced_columns(&item.expr, &mut cols);
                    }
                    None => at += 1,
                }
            }
            for cid in cols {
                if hicard_cids.contains(&cid) {
                    continue;
                }
                if self.reasoning.is_high_cardinality_column(cid) {
                    hicard_cids.push(cid);
                    if let Some(binding) = self.bindings.get(cid) {
                        hicard_names.push(IdentName::new(binding.display_name.clone()));
                    }
                }
            }
            let projected = match self.presented_keys.get(&k.output) {
                Some(presented) => presented.clone(),
                None => self.at_site(site, |w| w.project_scalar_expr(&k.expr)),
            };
            self.scope_mut(current).group_by.push(projected);
        }
        if !hicard_names.is_empty() {
            let scope = self.scope_mut(current);
            scope.has_high_cardinality_group_by = true;
            scope.high_cardinality_group_by_columns = hicard_names;
        }
    }

    fn emit_window_calls(
        &mut self,
        current: ScopeIdentity,
        site: ReadSite<'a>,
        calls: &[WindowCall],
    ) {
        for call in calls {
            let function =
                window_function_for(&call.func, call.args.len(), self.ctx.function_catalog);
            let (args, partition_by, order_by, frame) = self.at_site(site, |w| {
                let args = call
                    .args
                    .iter()
                    .map(|a| w.project_scalar_expr(a))
                    .collect::<Vec<_>>();
                let partition_by = call
                    .partition_by
                    .iter()
                    .map(|e| w.project_scalar_expr(e))
                    .collect::<Vec<_>>();
                let order_by = call
                    .order_by
                    .iter()
                    .map(|k| w.project_order_by_event(k))
                    .collect::<Vec<_>>();
                let frame = call.frame.as_ref().map(|f| w.project_window_frame(f));
                (args, partition_by, order_by, frame)
            });
            // Window is non-deterministic iff its function resolves to
            // a volatile catalog entry, OR any of its IR-side scalar
            // args / partition keys / order keys reaches a volatile
            // catalog entry. Drives `Q-WIN-NONDET` and `Q-NONDET`.
            let fc = self.ctx.function_catalog;
            let volatile = self.reasoning.volatile_columns();
            let deterministic =
                !crate::ir::volatile_expr::resolved_func_is_volatile(&call.func, fc)
                    && !call
                        .args
                        .iter()
                        .any(|a| crate::ir::volatile_expr::expr_is_volatile(a, volatile, fc))
                    && !call
                        .partition_by
                        .iter()
                        .any(|p| crate::ir::volatile_expr::expr_is_volatile(p, volatile, fc))
                    && !call
                        .order_by
                        .iter()
                        .any(|k| crate::ir::volatile_expr::expr_is_volatile(&k.expr, volatile, fc));
            // High-cardinality PARTITION BY: at least one partition
            // key reaches a column the IR's `is_high_cardinality_column`
            // classifies as high-cardinality (name-pattern + catalog
            // row-count heuristic). Drives `Q-WIN-HICARD-CENH`.
            let partition_high_cardinality =
                self.partition_keys_high_cardinality(&call.partition_by);
            self.scope_mut(current).window_functions.push(WindowEvent {
                function,
                args,
                partition_by,
                order_by,
                frame,
                deterministic,
                partition_high_cardinality,
                source_span: Some(call.span),
            });
        }
        // Compute the per-scope "distinct non-empty PARTITION BY
        // signatures across all window calls" rollup that drives
        // `Q-WIN-MULTIPART`. Predicate-DSL has no `distinct-count`
        // quantifier, so the count is pre-computed here and recorded
        // as a single bool on the scope. The signature is built from
        // the IR-side `ScalarExpr` tree (not the projected public
        // `Expr`) so it uses stable `ColumnId`s rather than span-
        // sensitive Debug renderings — two windows partitioning on
        // the same source column hash to the same signature even
        // when their literal positions in the SQL differ.
        let mut signatures: std::collections::HashSet<String> = std::collections::HashSet::new();
        for call in calls {
            if call.partition_by.is_empty() {
                continue;
            }
            let sig = call
                .partition_by
                .iter()
                .map(ir_scalar_signature)
                .collect::<Vec<_>>()
                .join(",");
            signatures.insert(sig);
        }
        self.scope_mut(current).has_multiple_partition_schemes = signatures.len() >= 2;
    }

    fn emit_order_by(&mut self, current: ScopeIdentity, site: ReadSite<'a>, keys: &[SortKey]) {
        if !self.scope_mut(current).order_by.is_empty() {
            return;
        }
        let projected: Vec<OrderByEvent> = self.at_site(site, |w| {
            keys.iter().map(|k| w.project_order_by_event(k)).collect()
        });
        self.scope_mut(current).order_by = projected;
    }

    fn project_order_by_event(&mut self, key: &SortKey) -> OrderByEvent {
        OrderByEvent {
            expr: self.project_scalar_expr(&key.expr),
            direction: if key.ascending {
                OrderDirection::Asc
            } else {
                OrderDirection::Desc
            },
            nulls: match key.nulls_first {
                Some(true) => NullsOrdering::First,
                Some(false) => NullsOrdering::Last,
                None => NullsOrdering::Default,
            },
        }
    }

    fn project_window_frame(&mut self, frame: &IrWindowFrame) -> PublicWindowFrame {
        PublicWindowFrame {
            kind: match frame.mode {
                FrameMode::Rows => WindowFrameKind::Rows,
                FrameMode::Range => WindowFrameKind::Range,
                FrameMode::Groups => WindowFrameKind::Groups,
            },
            start: self.project_frame_bound(&frame.start),
            end: self.project_frame_bound(&frame.end),
            exclusion: match frame.exclusion {
                FrameExclusion::NoOthers => Some(WindowFrameExclusion::NoOthers),
                FrameExclusion::CurrentRow => Some(WindowFrameExclusion::CurrentRow),
                FrameExclusion::Group => Some(WindowFrameExclusion::Group),
                FrameExclusion::Ties => Some(WindowFrameExclusion::Ties),
            },
        }
    }

    fn project_frame_bound(&mut self, bound: &FrameBound) -> WindowFrameBound {
        match bound {
            FrameBound::UnboundedPreceding => WindowFrameBound::UnboundedPreceding,
            FrameBound::UnboundedFollowing => WindowFrameBound::UnboundedFollowing,
            FrameBound::CurrentRow => WindowFrameBound::CurrentRow,
            FrameBound::Preceding(e) => WindowFrameBound::Preceding {
                offset: self.project_scalar_expr(e),
            },
            FrameBound::Following(e) => WindowFrameBound::Following {
                offset: self.project_scalar_expr(e),
            },
        }
    }

    // ── Expression projection ─────────────────────────────────────────────

    fn project_scalar_expr(&mut self, expr: &ScalarExpr) -> Expr {
        match expr {
            ScalarExpr::Column { column, span } => {
                match self.written_keys.get(&(*column, *span)).copied() {
                    Some(written) => self.project_scalar_expr(written),
                    None => Expr::Column {
                        column: self.column_ref_from_id(*column, Some(*span)),
                    },
                }
            }
            ScalarExpr::OuterRef { column, span, .. } => Expr::OuterColumn {
                outer_column: OuterColumnRef {
                    column: self.column_ref_from_id(*column, Some(*span)),
                    depth: 1,
                },
            },
            ScalarExpr::Lit { value, span } => Expr::Literal {
                literal: project_lit(value),
                origin: TextOrigin::at(*span),
            },
            ScalarExpr::BinOp {
                op, left, right, ..
            } => Expr::BinaryOp {
                binary_op: BinaryOpExpr {
                    op: project_binary_op_str(op.as_sql_str()),
                    left: Box::new(self.project_scalar_expr(left)),
                    right: Box::new(self.project_scalar_expr(right)),
                },
            },
            // Projected flat: re-nesting the chain would make this walk
            // recurse once per operand.
            ScalarExpr::LogicalChain { op, operands, .. } => Expr::LogicalChain {
                logical_chain: crate::facts::expr::LogicalChainExpr {
                    op: match op {
                        crate::ir::scalar::LogicalOp::And => {
                            crate::facts::expr::LogicalChainOp::And
                        }
                        crate::ir::scalar::LogicalOp::Or => crate::facts::expr::LogicalChainOp::Or,
                    },
                    operands: operands
                        .iter()
                        .map(|o| self.project_scalar_expr(o))
                        .collect(),
                },
            },
            // Projected flat for the same reason; each operator as the
            // `BinOp` arm projects it.
            ScalarExpr::OperatorChain {
                operands,
                operators,
                ..
            } => Expr::OperatorChain {
                operator_chain: crate::facts::expr::OperatorChainExpr {
                    operands: operands
                        .iter()
                        .map(|o| self.project_scalar_expr(o))
                        .collect(),
                    operators: operators
                        .iter()
                        .map(|op| project_binary_op_str(op.as_sql_str()))
                        .collect(),
                },
            },
            // Project the typed pattern-match into this surface's native
            // binary-op form (`BinaryOp::Like` / `NotLike` / `Similar` /
            // …). ESCAPE keeps its wrapping-`BinaryOp` shape (the surface
            // has no escape slot).
            ScalarExpr::Like {
                kind,
                negated,
                expr,
                pattern,
                escape,
                ..
            } => {
                use crate::ir::scalar::LikeKind;
                let op = match (*kind, *negated) {
                    (LikeKind::Like, false) => BinaryOp::Like,
                    (LikeKind::Like, true) => BinaryOp::NotLike,
                    (LikeKind::ILike, false) => BinaryOp::ILike,
                    (LikeKind::ILike, true) => BinaryOp::NotILike,
                    (LikeKind::SimilarTo, false) => BinaryOp::Similar,
                    (LikeKind::SimilarTo, true) => BinaryOp::NotSimilar,
                    (LikeKind::RLike, false) => BinaryOp::Other(PublicIdentName::new("RLIKE")),
                    (LikeKind::RLike, true) => BinaryOp::Other(PublicIdentName::new("NOT RLIKE")),
                };
                let base = Expr::BinaryOp {
                    binary_op: BinaryOpExpr {
                        op,
                        left: Box::new(self.project_scalar_expr(expr)),
                        right: Box::new(self.project_scalar_expr(pattern)),
                    },
                };
                match escape {
                    Some(e) => Expr::BinaryOp {
                        binary_op: BinaryOpExpr {
                            op: BinaryOp::Other(PublicIdentName::new("ESCAPE")),
                            left: Box::new(base),
                            right: Box::new(self.project_scalar_expr(e)),
                        },
                    },
                    None => base,
                }
            }
            ScalarExpr::UnaryOp { op, arg, span } => match project_unary_op_kind(*op) {
                Some(uo) => Expr::UnaryOp {
                    unary_op: UnaryOpExpr {
                        op: uo,
                        operand: Box::new(self.project_scalar_expr(arg)),
                    },
                },
                None => Expr::Opaque {
                    opaque: OpaqueExpr {
                        reason: OpaqueExprReason::DialectSpecificFunction,
                        rendered: span_slice(*span, self.ctx.source).to_string(),
                        origin: TextOrigin::at(*span),
                    },
                },
            },
            ScalarExpr::FuncCall {
                func,
                args,
                named_args,
                span,
                ..
            } => {
                let (is_temporal, is_deterministic, is_aggregate, is_window) =
                    classify_resolved_func(func, self.ctx.function_catalog);
                Expr::FuncCall {
                    func_call: FuncCallExpr {
                        name: resolved_func_name(func, self.ctx.function_catalog),
                        schema: None,
                        args: args.iter().map(|a| self.project_scalar_expr(a)).collect(),
                        named_args: named_args
                            .iter()
                            .map(|(name, value)| NamedArgument {
                                name: PublicIdentName::from_parts(name.as_str(), name.as_str()),
                                value: self.project_scalar_expr(value),
                            })
                            .collect(),
                        is_temporal,
                        is_deterministic,
                        is_aggregate,
                        is_window,
                        catalog_resolved: matches!(func, ResolvedFunc::Resolved { .. }),
                        source_span: Some(*span),
                    },
                }
            }
            ScalarExpr::Case {
                operand,
                branches,
                else_,
                ..
            } => Expr::Case {
                case: CaseExpr {
                    operand: operand
                        .as_ref()
                        .map(|o| Box::new(self.project_scalar_expr(o))),
                    branches: branches
                        .iter()
                        .map(|(c, r)| CaseBranch {
                            condition: self.project_scalar_expr(c),
                            result: self.project_scalar_expr(r),
                        })
                        .collect(),
                    else_branch: else_
                        .as_ref()
                        .map(|e| Box::new(self.project_scalar_expr(e))),
                },
            },
            ScalarExpr::Cast {
                expr,
                target_type,
                try_cast,
                ..
            } => Expr::Cast {
                cast: CastExpr {
                    expr: Box::new(self.project_scalar_expr(expr)),
                    target_type: super::literal::DataType {
                        kind: super::literal::DataTypeKind::Other(PublicIdentName::new(
                            &target_type.repr,
                        )),
                        precision: None,
                        scale: None,
                        length: None,
                        element_type: None,
                        key_type: None,
                        fields: Vec::new(),
                        timezone: None,
                        raw: target_type.repr.clone(),
                    },
                    cast_kind: if *try_cast {
                        CastKind::Try
                    } else {
                        CastKind::Strict
                    },
                },
            },
            ScalarExpr::InList {
                expr,
                list,
                negated,
                ..
            } => Expr::InList {
                in_list: InListExpr {
                    expr: Box::new(self.project_scalar_expr(expr)),
                    values: list.iter().map(|v| self.project_scalar_expr(v)).collect(),
                    negated: *negated,
                },
            },
            ScalarExpr::Between {
                expr,
                low,
                high,
                negated,
                ..
            } => {
                // Public surface has no dedicated `Between`. Lower to
                // `(expr >= low) AND (expr <= high)`, negating the
                // outer AND when `negated` is true.
                let projected = self.project_scalar_expr(expr);
                let low_projected = self.project_scalar_expr(low);
                let high_projected = self.project_scalar_expr(high);
                let lower_bound = Expr::BinaryOp {
                    binary_op: BinaryOpExpr {
                        op: BinaryOp::Gte,
                        left: Box::new(projected.clone()),
                        right: Box::new(low_projected),
                    },
                };
                let upper_bound = Expr::BinaryOp {
                    binary_op: BinaryOpExpr {
                        op: BinaryOp::Lte,
                        left: Box::new(projected),
                        right: Box::new(high_projected),
                    },
                };
                let chained = Expr::BinaryOp {
                    binary_op: BinaryOpExpr {
                        op: BinaryOp::And,
                        left: Box::new(lower_bound),
                        right: Box::new(upper_bound),
                    },
                };
                if *negated {
                    Expr::UnaryOp {
                        unary_op: UnaryOpExpr {
                            op: UnaryOp::Not,
                            operand: Box::new(chained),
                        },
                    }
                } else {
                    chained
                }
            }
            ScalarExpr::Exists {
                subquery,
                negated,
                correlates_with,
                span,
            } => self.project_subquery_expr(
                subquery,
                if *negated {
                    SubqueryKind::NotExists
                } else {
                    SubqueryKind::Exists
                },
                !correlates_with.is_empty(),
                *span,
                Some(current_for_subquery_ref(self)),
            ),
            ScalarExpr::ScalarSubquery {
                subquery,
                correlates_with,
                span,
            } => self.project_subquery_expr(
                subquery,
                SubqueryKind::Scalar,
                !correlates_with.is_empty(),
                *span,
                Some(current_for_subquery_ref(self)),
            ),
            ScalarExpr::QuantifiedCmp {
                op,
                quantifier,
                negated,
                left,
                right,
                span,
            } => {
                let public_op = project_comparison_op(*op);
                let public_quantifier = project_quantifier(*quantifier);
                let lhs_projected = Box::new(self.project_scalar_expr(left));
                let rhs_projected = match right {
                    QuantifiedRhs::Subquery(subquery, correlates_with) => {
                        let subquery_expr = self.build_subquery_expr(
                            subquery,
                            quantified_subquery_kind(*op, *quantifier, *negated),
                            !correlates_with.is_empty(),
                            *span,
                            Some(current_for_subquery_ref(self)),
                        );
                        QuantifiedRhsExpr::Subquery {
                            subquery: Box::new(subquery_expr),
                        }
                    }
                    QuantifiedRhs::List(items) => QuantifiedRhsExpr::List {
                        items: items.iter().map(|e| self.project_scalar_expr(e)).collect(),
                    },
                };
                Expr::QuantifiedCmp {
                    quantified_cmp: QuantifiedCmpExpr {
                        op: public_op,
                        quantifier: public_quantifier,
                        negated: *negated,
                        lhs: lhs_projected,
                        rhs: rhs_projected,
                        source_span: Some(*span),
                    },
                }
            }
            // The row is published as a call of `ROW` with its elements,
            // the comparison as the one over a scalar subquery or the
            // quantified one it states.
            ScalarExpr::RowCmp {
                op,
                quantifier,
                negated,
                left,
                left_span,
                subquery,
                correlates_with,
                subquery_span,
                span,
            } => {
                let row = Expr::FuncCall {
                    func_call: FuncCallExpr {
                        name: PublicIdentName::new("ROW"),
                        schema: None,
                        args: left.iter().map(|e| self.project_scalar_expr(e)).collect(),
                        named_args: Vec::new(),
                        is_temporal: false,
                        is_deterministic: false,
                        is_aggregate: false,
                        is_window: false,
                        catalog_resolved: false,
                        source_span: Some(*left_span),
                    },
                };
                let correlated = !correlates_with.is_empty();
                let scope = Some(current_for_subquery_ref(self));
                match quantifier {
                    None => Expr::BinaryOp {
                        binary_op: BinaryOpExpr {
                            op: project_binary_op_str(op.as_sql_str()),
                            left: Box::new(row),
                            right: Box::new(self.project_subquery_expr(
                                subquery,
                                SubqueryKind::Scalar,
                                correlated,
                                *subquery_span,
                                scope,
                            )),
                        },
                    },
                    Some(quantifier) => {
                        let subquery = self.build_subquery_expr(
                            subquery,
                            quantified_subquery_kind(*op, *quantifier, *negated),
                            correlated,
                            *span,
                            scope,
                        );
                        Expr::QuantifiedCmp {
                            quantified_cmp: QuantifiedCmpExpr {
                                op: project_comparison_op(*op),
                                quantifier: project_quantifier(*quantifier),
                                negated: *negated,
                                lhs: Box::new(row),
                                rhs: QuantifiedRhsExpr::Subquery {
                                    subquery: Box::new(subquery),
                                },
                                source_span: Some(*span),
                            },
                        }
                    }
                }
            }
            ScalarExpr::WindowFn { call, .. } => Expr::Window {
                window: Box::new(WindowExpr {
                    function: window_function_for(
                        &call.func,
                        call.args.len(),
                        self.ctx.function_catalog,
                    ),
                    args: call
                        .args
                        .iter()
                        .map(|a| self.project_scalar_expr(a))
                        .collect(),
                    partition_by: call
                        .partition_by
                        .iter()
                        .map(|e| self.project_scalar_expr(e))
                        .collect(),
                    order_by: call
                        .order_by
                        .iter()
                        .map(|k| self.project_order_by_event(k))
                        .collect(),
                    frame: call.frame.as_ref().map(|f| self.project_window_frame(f)),
                }),
            },
            ScalarExpr::FieldAccess { base, path, .. } => {
                // Collapse path into a chain of FieldAccessExpr nodes;
                // each step becomes one outer `Expr::FieldAccess`. Index
                // steps map to `IndexAccess`.
                let mut acc = self.project_scalar_expr(base);
                for step in path {
                    use crate::ir::scalar::FieldStep;
                    acc = match step {
                        FieldStep::Field(name) => Expr::FieldAccess {
                            field_access: FieldAccessExpr {
                                object: Box::new(acc),
                                field: PublicIdentName::new(name),
                            },
                        },
                        FieldStep::Index(i) => Expr::IndexAccess {
                            index_access: super::expr::IndexAccessExpr {
                                collection: Box::new(acc),
                                index: Box::new(Expr::Literal {
                                    literal: LiteralValue::Integer { value: *i },
                                    origin: TextOrigin::default(),
                                }),
                            },
                        },
                        FieldStep::IndexExpr(e) => Expr::IndexAccess {
                            index_access: super::expr::IndexAccessExpr {
                                collection: Box::new(acc),
                                index: Box::new(self.project_scalar_expr(e)),
                            },
                        },
                    };
                }
                acc
            }
            ScalarExpr::Lambda { span, .. } => Expr::Opaque {
                opaque: OpaqueExpr {
                    reason: OpaqueExprReason::DialectSpecificFunction,
                    rendered: span_slice(*span, self.ctx.source).to_string(),
                    origin: TextOrigin::at(*span),
                },
            },
            ScalarExpr::PatternVarRef { column, span, .. } => Expr::Column {
                column: self.column_ref_from_id(*column, Some(*span)),
            },
            ScalarExpr::Opaque { span, reason } => Expr::Opaque {
                opaque: OpaqueExpr {
                    reason: classify_ir_opaque_reason(reason),
                    rendered: span_slice(*span, self.ctx.source).to_string(),
                    origin: TextOrigin::at(*span),
                },
            },
        }
    }

    fn project_subquery_expr(
        &mut self,
        subquery: &RelPlan,
        kind: SubqueryKind,
        correlated: bool,
        span: Span,
        scope_for_ref: Option<ScopeIdentity>,
    ) -> Expr {
        Expr::Subquery {
            subquery: self.build_subquery_expr(subquery, kind, correlated, span, scope_for_ref),
        }
    }

    /// Project the subquery's `QueryFacts`, register a `SubqueryRef`
    /// witness in the enclosing scope (when requested), and return the
    /// typed [`SubqueryExpr`]. Callers wrap as needed: `Expr::Subquery`
    /// for direct embedding, or carry into a structured parent like
    /// [`QuantifiedRhsExpr::Subquery`].
    fn build_subquery_expr(
        &mut self,
        subquery: &RelPlan,
        kind: SubqueryKind,
        correlated: bool,
        span: Span,
        scope_for_ref: Option<ScopeIdentity>,
    ) -> SubqueryExpr {
        // Recursively project the subquery's QueryFacts (its own outer
        // scope at index 0). Bindings are shared with the enclosing
        // statement; DerivedFacts is recomputed on the subtree because
        // the outer-only flags must reflect the subquery's own scope
        // boundaries, not the enclosing one's.
        let inner_derived = derive_facts_from_plan(
            self.ctx.source,
            subquery,
            self.bindings,
            self.ctx.function_catalog,
        );
        // The subquery's reasoning is a view of this one's statement.
        let inner_reasoning = self.reasoning.nested(subquery);
        let inner_facts = project_query_facts_with_outer_ctes(
            subquery,
            self.bindings,
            &inner_derived,
            self.ctx,
            &self.cte_bindings_in_scope,
            inner_reasoning.as_ref(),
        );

        // Surface a SubqueryRef witness in the enclosing scope so rules
        // can audit subquery presence by quantifier without traversing
        // expression trees. The `position` field is stamped from the
        // walker's structural-position context (set by the
        // `project_scalar_expr_at` call sites in `walk`), so rules like
        // Q-SUBQ-SCALAR that only care about projection-list subqueries
        // can filter on `position: projection` even when the subquery
        // is nested inside a function call.
        if let Some(scope) = scope_for_ref {
            let position = self.current_subquery_position;
            // A correlated subquery nested in this one runs once per row
            // of its own block, at whatever depth: it is listed in this
            // scope too, as it stands in its own.
            let nested: Vec<SubqueryRef> = inner_facts
                .scopes
                .iter()
                .flat_map(|inner| &inner.scalar_subqueries)
                .filter(|nested| nested.correlated)
                .map(|nested| SubqueryRef {
                    scope_id: scope,
                    ..nested.clone()
                })
                .collect();
            let witnesses = &mut self.scope_mut(scope).scalar_subqueries;
            witnesses.push(SubqueryRef {
                kind,
                correlated,
                scope_id: scope,
                source_span: Some(span),
                position,
            });
            witnesses.extend(nested);
        }

        SubqueryExpr {
            kind,
            correlated,
            source_span: Some(span),
            inner_facts: Box::new(inner_facts),
        }
    }

    /// True iff `col`, read at `site`, may be NULL because the catalog
    /// declares a column it reads nullable: `ColumnRef.nullability` there
    /// is `catalog_nullable`. A column NULL only where a join pads it or
    /// an operator makes it is not. Used by aggregate emission to
    /// populate [`AggregateEvent::on_nullable_argument`].
    fn column_is_known_nullable(&self, site: ReadSite<'_>, col: ColumnId) -> bool {
        matches!(self.nullability_at(site, col), Nullability::CatalogNullable)
    }

    /// True iff any partition-by key reaches a column the IR
    /// classifies as high-cardinality (name pattern + catalog
    /// row-count heuristic). Name-pattern check fires regardless
    /// of whether a catalog is attached; catalog refines.
    fn partition_keys_high_cardinality(&self, partition_by: &[ScalarExpr]) -> bool {
        let mut cols = Vec::new();
        for p in partition_by {
            self.collect_referenced_columns(p, &mut cols);
        }
        cols.iter()
            .any(|cid| self.reasoning.is_high_cardinality_column(*cid))
    }

    /// Union of taint labels reachable from any column reference
    /// inside `expr`. Walks the closed [`ScalarExpr`] enum, collects
    /// every referenced [`ColumnId`], looks up each one's catalog
    /// metadata, and projects the catalog `tags` slice through the
    /// public [`TaintLabel`] taxonomy. Subquery bodies (`Exists`,
    /// `ScalarSubquery`, `QuantifiedCmp` over a subquery RHS) are
    /// intentionally not descended into — they carry their own
    /// scope-local projections.
    fn taint_labels_for_expr(&self, expr: &ScalarExpr) -> Vec<crate::facts::catalog::TaintLabel> {
        let Some(catalog) = self.ctx.catalog else {
            return Vec::new();
        };
        use crate::ir::CatalogContext;
        let mut read: Vec<ColumnId> = Vec::new();
        self.collect_referenced_columns(expr, &mut read);
        let mut cols: Vec<ColumnId> = Vec::new();
        for column in read {
            self.collect_value_columns(column, &mut cols);
        }
        let mut labels: Vec<crate::facts::catalog::TaintLabel> = Vec::new();
        for cid in cols {
            if let Some(meta) = catalog.column_metadata(cid) {
                for projected in project_taint_labels(&meta.tags) {
                    if !labels.contains(&projected) {
                        labels.push(projected);
                    }
                }
            }
        }
        labels
    }

    /// The columns `column` may hold the value of: itself, or, where a
    /// join merges it, those of the columns the join keeps: both for an
    /// inner and a full join, the preserved side's for a join that keeps
    /// one side.
    fn collect_value_columns(&self, column: ColumnId, out: &mut Vec<ColumnId>) {
        use crate::ir::column::MergedValue;
        use crate::ir::ColumnOrigin;
        match self.bindings.get(column).map(|binding| &binding.origin) {
            Some(ColumnOrigin::Merged { value, .. }) => match value {
                MergedValue::Side { kept, .. } => self.collect_value_columns(*kept, out),
                MergedValue::Both { .. } | MergedValue::Either { .. } => {
                    for side in value.sides() {
                        self.collect_value_columns(side, out);
                    }
                }
            },
            Some(
                ColumnOrigin::Table { .. }
                | ColumnOrigin::Computed { .. }
                | ColumnOrigin::SetOp { .. }
                | ColumnOrigin::OuterRef { .. }
                | ColumnOrigin::RecursiveRef { .. }
                | ColumnOrigin::Unattributed { .. },
            )
            | None => {
                if !out.contains(&column) {
                    out.push(column);
                }
            }
        }
    }

    /// Merge the taint flowing into the projection's output `ColumnId`
    /// into `labels`. Taint reasoning propagates labels through
    /// aggregates, computed expressions, set ops, and cross-model
    /// `ModelRef` boundaries — every shape the source-walk in
    /// [`Self::taint_labels_for_expr`] cannot see because the
    /// per-`ColumnId` `column_metadata` channel is only seeded for
    /// `Scan` and `ModelRef` columns.
    ///
    /// Asked of the output column itself, so two outputs of one name
    /// each carry their own; labels already present are not duplicated.
    fn merge_ir_taint_for_output(
        &self,
        output: ColumnId,
        labels: &mut Vec<crate::facts::catalog::TaintLabel>,
    ) {
        extend_absent(labels, self.reasoning.output_taint_labels(output));
    }

    /// The public value-exposure for a projection's output
    /// column — the most-exposing class among its taint labels
    /// (`Value` when untainted), asked of the column as
    /// [`Self::merge_ir_taint_for_output`] asks.
    fn value_exposure_for_output(&self, output: ColumnId) -> crate::facts::catalog::ValueExposure {
        self.reasoning.output_value_exposure(output)
    }

    /// Record and publish each column `assignment` writes of `table`,
    /// column `i` taking position `i` of its value
    /// ([`Self::publish_written_column`]). What a query's position reads,
    /// and what a column an `INSERT` writes holds (an upsert's
    /// `EXCLUDED.c`), is answered by reasoning alone. `unplaced` are the
    /// columns an `INSERT` with no column list writes, placed at no
    /// position of its source: a value that reads one has a source that is
    /// not known.
    fn publish_assignment(
        &mut self,
        table: &'a legacy_meta::TableRef,
        assignment: &crate::ir::plan::Assignment,
        unplaced: &[ColumnId],
    ) {
        use crate::ir::plan::AssignedValue;
        for (position, written) in assignment.columns.iter().enumerate() {
            let read = match &assignment.value {
                AssignedValue::Row(values) => values
                    .get(position)
                    .map(|value| self.referenced_columns(value))
                    .unwrap_or_default(),
                AssignedValue::Query { .. } => Vec::new(),
            };
            let source = if read.iter().any(|column| unplaced.contains(column)) {
                ValueSource::PartlyUnknown
            } else {
                ValueSource::Known
            };
            self.publish_written_column(table, *written, read, source);
        }
    }

    /// The columns `expr` reads ([`Self::collect_referenced_columns`]).
    fn referenced_columns(&self, expr: &ScalarExpr) -> Vec<ColumnId> {
        let mut read = Vec::new();
        self.collect_referenced_columns(expr, &mut read);
        read
    }

    /// Record `written`, a column of `table` an `UPDATE` assignment, a
    /// `MERGE` branch or an upsert's update action writes from a value
    /// that reads the columns `read`, and publish it where the catalog
    /// resolves the column: the tags the catalog attaches to it, the tags
    /// of the columns its value is drawn from, and how much of them the
    /// value exposes. A column the value reads is drawn from itself, the
    /// columns a join merges into it, or the table column the plan pairs a
    /// reference's column with; where its `source` is known, reasoning
    /// adds the tags it finds on the written column's value and says the
    /// exposure, which is otherwise `Value`.
    fn publish_written_column(
        &mut self,
        table: &'a legacy_meta::TableRef,
        written: ColumnId,
        read: impl IntoIterator<Item = ColumnId>,
        source: ValueSource,
    ) {
        use crate::facts::catalog::ValueExposure;
        use crate::facts::query::WrittenColumnEvent;
        use crate::ir::{CatalogContext, ColumnOrigin};
        self.written_columns.push((table, written));
        let Some(catalog) = self.ctx.catalog else {
            return;
        };
        let Some(tags) = catalog.written_column_tags(written) else {
            return;
        };
        let Some(binding) = self.bindings.get(written) else {
            return;
        };
        let source_span = match &binding.origin {
            ColumnOrigin::Computed { expr_span, .. } => Some(*expr_span),
            ColumnOrigin::Table { .. }
            | ColumnOrigin::Merged { .. }
            | ColumnOrigin::SetOp { .. }
            | ColumnOrigin::OuterRef { .. }
            | ColumnOrigin::RecursiveRef { .. }
            | ColumnOrigin::Unattributed { .. } => None,
        };
        let mut column_taint_labels = Vec::new();
        extend_absent(&mut column_taint_labels, project_taint_labels(tags));
        let mut drawn = Vec::new();
        for column in read {
            self.collect_value_columns(column, &mut drawn);
        }
        let mut value_taint_labels = Vec::new();
        for column in drawn {
            let source = self
                .ctx
                .scan_index
                .and_then(|index| index.source_column(column, self.bindings))
                .unwrap_or(column);
            if let Some(meta) = catalog.column_metadata(source) {
                extend_absent(&mut value_taint_labels, project_taint_labels(&meta.tags));
            }
        }
        let value_exposure = match source {
            ValueSource::Known => {
                self.merge_ir_taint_for_output(written, &mut value_taint_labels);
                self.value_exposure_for_output(written)
            }
            // Reasoning counts every column an unknown source may be.
            ValueSource::PartlyUnknown => ValueExposure::Value,
        };
        self.written_tags.push(WrittenColumnEvent {
            table: project_metadata_table_ref(table, None),
            column: column_name(binding.display_name.as_str()),
            column_taint_labels,
            value_taint_labels,
            value_exposure,
            source_span,
        });
    }

    /// The columns `expr` reads. A read of a group key the query wrote as
    /// the key's expression reads what that expression reads.
    fn collect_referenced_columns(&self, expr: &ScalarExpr, out: &mut Vec<ColumnId>) {
        match expr {
            ScalarExpr::Column { column, span } => {
                match self.written_keys.get(&(*column, *span)).copied() {
                    Some(written) => self.collect_referenced_columns(written, out),
                    None => {
                        if !out.contains(column) {
                            out.push(*column);
                        }
                    }
                }
            }
            ScalarExpr::OuterRef { column, .. } => {
                if !out.contains(column) {
                    out.push(*column);
                }
            }
            ScalarExpr::PatternVarRef { column, .. } => {
                if !out.contains(column) {
                    out.push(*column);
                }
            }
            ScalarExpr::BinOp { left, right, .. } => {
                self.collect_referenced_columns(left, out);
                self.collect_referenced_columns(right, out);
            }
            ScalarExpr::LogicalChain { operands, .. }
            | ScalarExpr::OperatorChain { operands, .. } => {
                for operand in operands {
                    self.collect_referenced_columns(operand, out);
                }
            }
            ScalarExpr::Like {
                expr,
                pattern,
                escape,
                ..
            } => {
                self.collect_referenced_columns(expr, out);
                self.collect_referenced_columns(pattern, out);
                if let Some(e) = escape {
                    self.collect_referenced_columns(e, out);
                }
            }
            ScalarExpr::UnaryOp { arg, .. } => self.collect_referenced_columns(arg, out),
            ScalarExpr::FuncCall {
                args, named_args, ..
            } => {
                for a in args {
                    self.collect_referenced_columns(a, out);
                }
                for (_, a) in named_args {
                    self.collect_referenced_columns(a, out);
                }
            }
            ScalarExpr::Case {
                operand,
                branches,
                else_,
                ..
            } => {
                if let Some(o) = operand.as_ref() {
                    self.collect_referenced_columns(o, out);
                }
                for (c, r) in branches {
                    self.collect_referenced_columns(c, out);
                    self.collect_referenced_columns(r, out);
                }
                if let Some(e) = else_.as_ref() {
                    self.collect_referenced_columns(e, out);
                }
            }
            ScalarExpr::Cast { expr, .. } => self.collect_referenced_columns(expr, out),
            ScalarExpr::InList { expr, list, .. } => {
                self.collect_referenced_columns(expr, out);
                for e in list {
                    self.collect_referenced_columns(e, out);
                }
            }
            ScalarExpr::Between {
                expr, low, high, ..
            } => {
                self.collect_referenced_columns(expr, out);
                self.collect_referenced_columns(low, out);
                self.collect_referenced_columns(high, out);
            }
            ScalarExpr::QuantifiedCmp { left, right, .. } => {
                self.collect_referenced_columns(left, out);
                if let QuantifiedRhs::List(items) = right {
                    for e in items {
                        self.collect_referenced_columns(e, out);
                    }
                }
            }
            ScalarExpr::RowCmp { left, .. } => {
                for e in left {
                    self.collect_referenced_columns(e, out);
                }
            }
            ScalarExpr::WindowFn { call, .. } => {
                for a in &call.args {
                    self.collect_referenced_columns(a, out);
                }
                for p in &call.partition_by {
                    self.collect_referenced_columns(p, out);
                }
                for k in &call.order_by {
                    self.collect_referenced_columns(&k.expr, out);
                }
            }
            ScalarExpr::FieldAccess { base, .. } => self.collect_referenced_columns(base, out),
            ScalarExpr::Lambda { body, .. } => self.collect_referenced_columns(body, out),
            // Literals and subquery bodies do not contribute.
            ScalarExpr::Lit { .. }
            | ScalarExpr::Exists { .. }
            | ScalarExpr::ScalarSubquery { .. }
            | ScalarExpr::Opaque { .. } => {}
        }
    }

    /// Walk a join ON predicate and surface every simple
    /// `Column = Column` equality as a typed [`JoinColumnPair`].
    /// Descends through `AND` chains (each AND branch is an
    /// independent join key); ignores other shapes
    /// (`a + 1 = b`, `OR`, function-wrapped comparisons) because
    /// they cannot be paired column-for-column. Drives
    /// `Q-JOIN-TYPEMIS-CENH` (type mismatch) and `Q-JOIN-NULL-CENH`
    /// (nullable join column) when catalog metadata is attached.
    ///
    /// Two-pass shape: pass 1 collects the raw `(lcol, rcol, lspan,
    /// rspan)` tuples without computing FK relationship; pass 2
    /// builds a per-join origins pool (lineage-resolved
    /// `(TableRef, column_name)` set across every column on either
    /// side of any pair) and then computes `fk_relationship` per
    /// pair with composite-completeness visibility against that
    /// pool. The pool drives the composite-FK sibling check inside
    /// `compare_fk_relationship`: a matched edge that belongs to a
    /// composite constraint only counts as `Matches` if every
    /// column of the source constraint is also covered by some pair
    /// in this join.
    fn extract_join_column_pairs(
        &self,
        expr: &ScalarExpr,
        site: ReadSite<'_>,
    ) -> Vec<JoinColumnPair> {
        let mut raw_pairs: Vec<(ColumnId, ColumnId, Span, Span)> = Vec::new();
        Self::collect_raw_join_pairs(expr, &mut raw_pairs);
        let on: Vec<ColumnId> = raw_pairs
            .iter()
            .flat_map(|(lcol, rcol, _, _)| [*lcol, *rcol])
            .collect();

        // Resolve lineage origins for each pair ONCE; the pool is
        // the union of those resolutions. Each resolution is then
        // handed to `compare_fk_relationship` so it doesn't re-trace
        // the same `ColumnId` through `BindingTable`.
        let catalog = self.ctx.catalog;
        let resolved: Vec<(ColumnOrigins, ColumnOrigins)> = raw_pairs
            .iter()
            .map(|(lcol, rcol, _, _)| {
                let l = catalog
                    .map(|c| resolve_column_origins(*lcol, c, self.reasoning))
                    .unwrap_or_default();
                let r = catalog
                    .map(|c| resolve_column_origins(*rcol, c, self.reasoning))
                    .unwrap_or_default();
                (l, r)
            })
            .collect();

        let mut origins_pool: std::collections::HashSet<(
            legacy_meta::TableRef,
            crate::context::node_metadata::IdentKey,
        )> = std::collections::HashSet::new();
        for (l, r) in &resolved {
            for (t, k) in l.iter().chain(r.iter()) {
                origins_pool.insert((
                    t.clone(),
                    crate::context::node_metadata::IdentKey::new_as(k, NameKind::Column),
                ));
            }
        }

        raw_pairs
            .into_iter()
            .zip(resolved)
            .map(|((lcol, rcol, lspan, rspan), (l_origins, r_origins))| {
                let left_ref = self.column_ref_at(site, lcol, Some(lspan));
                let right_ref = self.column_ref_at(site, rcol, Some(rspan));
                let type_compatibility =
                    compare_data_types(&left_ref.data_type, &right_ref.data_type);
                let fk_relationship = compare_fk_relationship(
                    lcol,
                    rcol,
                    self.ctx.catalog,
                    &l_origins,
                    &r_origins,
                    &origins_pool,
                );
                // Pairs are in operand order; the reasoning finds each
                // column's input of the join.
                let left_key = self.reasoning.key_backed(site.node, lcol, &on);
                let right_key = self.reasoning.key_backed(site.node, rcol, &on);
                let unique_key_backed = left_key == Some(true) || right_key == Some(true);
                // A column a table function yields is no catalog's to key.
                let asked = |key: Option<bool>, col: ColumnId| {
                    key.is_some() && !self.function_columns.contains(&col)
                };
                let unique_key_backing_known =
                    self.ctx.catalog.is_some_and(|catalog| catalog.lists_keys())
                        && (asked(left_key, lcol) || asked(right_key, rcol));
                JoinColumnPair {
                    left: left_ref,
                    right: right_ref,
                    type_compatibility,
                    fk_relationship,
                    unique_key_backed,
                    unique_key_backing_known,
                }
            })
            .collect()
    }

    fn collect_raw_join_pairs(expr: &ScalarExpr, out: &mut Vec<(ColumnId, ColumnId, Span, Span)>) {
        match expr {
            ScalarExpr::BinOp {
                op, left, right, ..
            } => {
                let op_upper = op.as_sql_str();
                if op_upper == "AND" {
                    Self::collect_raw_join_pairs(left, out);
                    Self::collect_raw_join_pairs(right, out);
                    return;
                }
                if op_upper == "=" {
                    if let (
                        ScalarExpr::Column {
                            column: lcol,
                            span: lspan,
                        },
                        ScalarExpr::Column {
                            column: rcol,
                            span: rspan,
                        },
                    ) = (left.as_ref(), right.as_ref())
                    {
                        out.push((*lcol, *rcol, *lspan, *rspan));
                    }
                }
            }
            // N-ary spelling of the `AND` recursion above: every
            // conjunct of a chained ON predicate can carry a join
            // pair. `OR` is not a conjunction of join keys, so it
            // contributes nothing — as the `BinOp` arm's silence on
            // non-`AND` / non-`=` operators already implies.
            ScalarExpr::LogicalChain { op, operands, .. } => {
                if matches!(op, crate::ir::scalar::LogicalOp::And) {
                    for operand in operands {
                        Self::collect_raw_join_pairs(operand, out);
                    }
                }
            }
            // Other shapes are not Column = Column join keys; they
            // do not contribute a pair. The exhaustive arm avoids
            // a `_ =>` catch-all on the closed `ScalarExpr` enum.
            ScalarExpr::Column { .. }
            | ScalarExpr::OperatorChain { .. }
            | ScalarExpr::OuterRef { .. }
            | ScalarExpr::Lit { .. }
            | ScalarExpr::UnaryOp { .. }
            | ScalarExpr::FuncCall { .. }
            | ScalarExpr::Case { .. }
            | ScalarExpr::Cast { .. }
            | ScalarExpr::InList { .. }
            | ScalarExpr::Between { .. }
            | ScalarExpr::Like { .. }
            | ScalarExpr::Exists { .. }
            | ScalarExpr::ScalarSubquery { .. }
            | ScalarExpr::QuantifiedCmp { .. }
            | ScalarExpr::RowCmp { .. }
            | ScalarExpr::WindowFn { .. }
            | ScalarExpr::FieldAccess { .. }
            | ScalarExpr::Lambda { .. }
            | ScalarExpr::PatternVarRef { .. }
            | ScalarExpr::Opaque { .. } => {}
        }
    }

    /// A reference to `id` read at the walker's current site.
    fn column_ref_from_id(&self, id: ColumnId, span: Option<Span>) -> ColumnRef {
        self.column_ref_at(self.current_site, id, span)
    }

    fn column_ref_at(&self, site: ReadSite<'_>, id: ColumnId, span: Option<Span>) -> ColumnRef {
        let name = self
            .bindings
            .get(id)
            .map(|b| b.display_name.as_str())
            .unwrap_or("");
        // Bare catalog lookup populates data_type and catalog_tags only;
        // nullability is the column's where `site` reads it.
        let (data_type, _direct_nullability, catalog_tags) =
            column_catalog_metadata(id, self.ctx.catalog);
        let nullability = self.nullability_at(site, id);
        ColumnRef {
            name: column_name(name),
            table: None,
            source_span: span,
            data_type,
            catalog_tags,
            nullability,
            taint_labels: Vec::new(),
            lineage: None,
        }
    }

    /// Temporal sub-expressions gating any predicate of `plan`: calls to
    /// temporal functions, and the column references reasoning accepts
    /// as temporal.
    fn project_temporal_gating(
        &self,
        plan: &RelPlan,
    ) -> Vec<crate::facts::query::TemporalGatingExpression> {
        use crate::facts::query::{TemporalGatingExpression, TemporalGatingKind};
        use crate::ir::temporal_gating::{
            collect_temporal_gating_expressions, IrTemporalGatingKind,
        };
        collect_temporal_gating_expressions(plan, self.ctx.function_catalog, &|col| {
            self.reasoning.is_temporal_gating_column(col)
        })
        .into_iter()
        .map(|e| {
            let kind = match e.kind {
                IrTemporalGatingKind::FunctionCall { display_name } => {
                    TemporalGatingKind::FunctionCall {
                        function: PublicIdentName::new(&display_name),
                    }
                }
                IrTemporalGatingKind::ColumnReference { column } => {
                    TemporalGatingKind::ColumnReference {
                        column: self.temporal_column_ref(column, e.source_span),
                    }
                }
            };
            TemporalGatingExpression {
                source_span: e.source_span,
                kind,
            }
        })
        .collect()
    }

    /// Minimal `ColumnRef` for a temporal column inside a gating
    /// expression: display name, span and catalog metadata; no lineage
    /// or taint.
    fn temporal_column_ref(&self, id: ColumnId, span: Option<Span>) -> ColumnRef {
        let name = self
            .bindings
            .get(id)
            .map(|b| b.display_name.as_str())
            .unwrap_or("");
        let (data_type, nullability, catalog_tags) = column_catalog_metadata(id, self.ctx.catalog);
        ColumnRef {
            name: PublicIdentName::new(name),
            table: None,
            source_span: span,
            data_type,
            catalog_tags,
            nullability,
            taint_labels: Vec::new(),
            lineage: None,
        }
    }

    fn finalize(mut self, plan: &RelPlan, derived_facts: &DerivedFacts) -> QueryFacts {
        self.settle_selected_functions();
        let has_sample = self.has_sample;

        // Per-column structural atoms + lattice anomalies. The IR pass
        // already aggregates atoms across OR-branches per (scope,
        // column) and attaches the typed anomaly arms; the projection
        // is a 1:1 type-translation at the facts boundary. Drives
        // `Q-PRED-CONTRA`, `Q-PRED-RANGE`, `Q-PRED-REDUNDANT` via the
        // `anomalies` arm; future rules can compose against the atom
        // fields without growing the anomaly enum.
        let column_constraints = self.reasoning.column_constraint_events();
        let or_tautologies = self.reasoning.or_tautology_events();

        // Per-(predicate, column) null-handling witnesses, one per
        // referenced column at each WHERE / QUALIFY filter site, indexed
        // by predicate span and attached to the matching
        // `PredicateEvent.null_effects`. Rules compose semantic
        // predicates (e.g. `Q-JOIN-LEFT-FILT`) from these typed
        // primitives — no facts-layer categorisation.
        let mut null_effects_by_span: std::collections::HashMap<
            Span,
            Vec<crate::facts::query::PredicateNullEffect>,
        > = std::collections::HashMap::new();
        for raw in self.reasoning.predicate_null_witnesses() {
            let span = raw.predicate_span;
            let mut column = self.column_ref_from_id(raw.column, raw.column_ref_span);
            // The witness carries the predicate-site nullability, every
            // proof applied; it overrides the projection-time value.
            column.nullability = raw.nullability;
            // Per-witness emissions (Q-JOIN-LEFT-FILT, Q-NULL-NEQ)
            // anchor on the witness's top-level `source_span` —
            // prefer the column's reference span so the SARIF
            // diagnostic points at the actual column site in the
            // WHERE clause, not at the WHERE clause's start line.
            // Fall back to the enclosing predicate span only when
            // the column reference span is missing.
            let witness_span = column.source_span.or(Some(span));
            null_effects_by_span.entry(span).or_default().push(
                crate::facts::query::PredicateNullEffect {
                    column,
                    drops_null_row: raw.drops_null_row,
                    null_addressed: raw.null_addressed,
                    drops_padded_row: raw.drops_padded_row,
                    aggregate_derived: raw.aggregate_derived,
                    inequality_compared: raw.inequality_compared,
                    null_literal_compared: raw.null_literal_compared,
                    inner_join_key_protected: raw.inner_join_key_protected,
                    source_span: witness_span,
                },
            );
        }
        for scope in self.scopes.iter_mut() {
            for ev in scope.where_predicates.iter_mut() {
                if let Some(span) = ev.source_span {
                    if let Some(effects) = null_effects_by_span.get(&span) {
                        ev.null_effects = effects.clone();
                    }
                }
            }
            for ev in scope.having_predicates.iter_mut() {
                if let Some(span) = ev.source_span {
                    if let Some(effects) = null_effects_by_span.get(&span) {
                        ev.null_effects = effects.clone();
                    }
                }
            }
        }

        // Q-PROP-CONTRA: attach per-predicate cross-scope-constraint
        // effects onto each `PredicateEvent.cross_scope_effects`.
        // Mirrors the null-effects projection pattern: the IR pass
        // returns typed primitives keyed by predicate span; we group
        // and attach. Rules compose freely against
        // `where_predicates.exists.cross_scope_effects.exists.relationship: disjoint`.
        project_cross_scope_effects_onto_scopes(
            self.reasoning.cross_scope_effects(),
            &mut self.scopes,
        );

        let reads_table: Vec<TableEvent> = derived_facts
            .tables_read
            .iter()
            .map(|t| {
                let (catalog_tags, row_count, column_count, table_kind, in_catalog, searched_as) =
                    table_catalog_metadata(t, self.ctx.catalog);
                TableEvent {
                    table: project_metadata_table_ref(t, t.span),
                    scope_id: ScopeIdentity::OUTER,
                    source_span: t.span,
                    catalog_tags,
                    row_count,
                    column_count,
                    access_kind: TableAccessKind::Read,
                    table_kind,
                    in_catalog,
                    searched_as,
                    temporary: false,
                }
            })
            .collect();

        let write_kind = root_write_access_kind(plan);
        let writes_table: Vec<TableEvent> = derived_facts
            .tables_written
            .iter()
            .map(|t| {
                let (catalog_tags, row_count, column_count, table_kind, in_catalog, searched_as) =
                    target_catalog_metadata(t, self.ctx.catalog);
                TableEvent {
                    table: project_metadata_table_ref(t, t.span),
                    scope_id: ScopeIdentity::OUTER,
                    source_span: t.span,
                    catalog_tags,
                    row_count,
                    column_count,
                    access_kind: write_kind,
                    table_kind,
                    in_catalog,
                    searched_as,
                    temporary: false,
                }
            })
            .collect();

        // Q-JOIN-TEMPORAL-CENH / Q-MULTI-TEMPORAL-CENH: structural inputs.
        // The IR exposes (a) the set of reachable scans declaring
        // temporal columns and (b) the set of temporal sub-expressions
        // inside any predicate tree. Rules compose the verdict in YAML
        // (`temporal_join_tables: count gte 2` ∧
        // `temporal_gating_expressions: count eq 0`). Empty vecs when
        // no catalog is attached — the rules cannot evaluate and stay
        // silent. Single projection point: this block.
        let temporal_join_tables = self.reasoning.temporal_join_tables();
        let temporal_gating_expressions = self.project_temporal_gating(plan);

        // Q-SUBQ-REPEAT: name-keyed structural fingerprint over
        // every `ScalarSubquery` / `QuantifiedCmp(Subquery)` instance
        // in the lowered plan. EXISTS bodies are skipped per the
        // rule's intent. `Span` re-keyed onto the typed public
        // `RepeatedSubqueryEvent`.
        let repeated_subqueries = self.reasoning.repeated_subqueries();

        let schemas_touched =
            collect_schemas_touched(&derived_facts.tables_read, &derived_facts.tables_written);

        let merge = match plan {
            RelPlan::Merge {
                with_schema_evolution,
                branches,
                ..
            } => Some(crate::facts::query::MergeFacts {
                with_schema_evolution: *with_schema_evolution,
                branches: branches.iter().map(project_merge_branch).collect(),
            }),
            _ => None,
        };

        let table_hints = project_table_hints(plan);

        let references_column = project_column_references(
            self.bindings,
            self.ctx.catalog,
            self.ctx.scan_index,
            &self.written_columns,
        );

        // Saturating product across every `reads_table` row_count when
        // the statement has an implicit cross join. `None` when any
        // participating table lacks a catalog estimate, so
        // Q-JOIN-CROSS-IMPL's `{product}` only renders when fully
        // determined.
        let implicit_cross_product_estimate: Option<u64> =
            if derived_facts.has_implicit_cross_join && !reads_table.is_empty() {
                let mut product: u64 = 1;
                let mut all_known = true;
                for t in &reads_table {
                    match t.row_count {
                        Some(rc) => product = product.saturating_mul(rc),
                        None => {
                            all_known = false;
                            break;
                        }
                    }
                }
                if all_known {
                    Some(product)
                } else {
                    None
                }
            } else {
                None
            };

        QueryFacts {
            tables_used: tables_used(&reads_table, &writes_table),
            reads_table,
            writes_table,
            references_column,
            written_columns: self.written_tags,
            scopes: self.scopes,
            has_where: derived_facts.has_where,
            has_tautology_where: crate::ir::always_true::has_tautology_where(
                plan,
                self.ctx.source,
                self.bindings,
                Some(self.reasoning),
                crate::ir::always_true::RowsCounted::All,
            ),
            has_non_null_tautology_where: crate::ir::always_true::has_tautology_where(
                plan,
                self.ctx.source,
                self.bindings,
                Some(self.reasoning),
                crate::ir::always_true::RowsCounted::ExceptNullCompared,
            ),
            has_limit: derived_facts.has_limit,
            has_qualify: derived_facts.has_qualify,
            has_having: derived_facts.having.is_some(),
            has_distinct: derived_facts.has_distinct,
            has_sample,
            has_implicit_cross_join: derived_facts.has_implicit_cross_join,
            implicit_cross_product_estimate,
            has_join_predicate_filters: derived_facts.has_join_predicate_filters,
            schemas_touched,
            column_constraints,
            or_tautologies,
            temporal_join_tables,
            temporal_gating_expressions,
            repeated_subqueries,
            // Populated by script-level reasoning after this
            // projection returns. Default empty.
            stale_table_refs: Vec::new(),
            stale_column_refs: Vec::new(),
            merge,
            target_rows: project_target_rows(plan, self.ctx.source, self.bindings),
            overwrite: project_overwrite(plan),
            table_hints,
            // Stated by `project_query_facts` for a statement compared with
            // another version of it.
            output_columns: Vec::new(),
            // Populated after this projection by the SELECT dispatch in
            // lib.rs (via `collect_openrowset_calls`). Default empty
            // here so non-SELECT paths and missing-walker paths still
            // construct correctly.
            openrowset_calls: Vec::new(),
            opendatasource_calls: Vec::new(),
            function_calls: Vec::new(),
            // Populated by the caller from the statement-level
            // extraction. Default empty here.
            file_exports: Vec::new(),
        }
    }
}

/// The relation `plan` returns, or the one its `CREATE … AS` makes, with
/// the names a `CREATE … (names) AS` gives its columns by position. `None`
/// for a plan that returns no rows.
pub fn returned_relation(
    plan: &RelPlan,
) -> Option<(&RelPlan, Option<&[crate::context::node_metadata::IdentKey]>)> {
    match plan {
        RelPlan::CreateAsQuery { body, columns, .. } => {
            let (relation, _) = returned_relation(body.as_deref()?)?;
            Some((relation, columns.as_deref()))
        }
        RelPlan::WithScope { body, .. } => returned_relation(body),
        RelPlan::Project { .. }
        | RelPlan::Filter { .. }
        | RelPlan::Aggregate { .. }
        | RelPlan::Window { .. }
        | RelPlan::Sort { .. }
        | RelPlan::Limit { .. }
        | RelPlan::SetOp { .. }
        | RelPlan::Join { .. }
        | RelPlan::Scan { .. }
        | RelPlan::Values { .. }
        | RelPlan::CteRef { .. }
        | RelPlan::ModelRef { .. }
        | RelPlan::TableFunction { .. }
        | RelPlan::DerivedTable { .. }
        | RelPlan::TableSample { .. }
        | RelPlan::Pivot { .. }
        | RelPlan::Unpivot { .. }
        | RelPlan::Unnest { .. }
        | RelPlan::MatchRecognize { .. }
        | RelPlan::ConnectBy { .. } => Some((plan, None)),
        RelPlan::Insert { .. }
        | RelPlan::Update { .. }
        | RelPlan::Delete { .. }
        | RelPlan::Merge { .. }
        | RelPlan::MultiInsert { .. }
        | RelPlan::Explain { .. }
        | RelPlan::CreateTableForm { .. }
        | RelPlan::ParseRecovery { .. }
        | RelPlan::InvalidInput { .. }
        | RelPlan::Opaque { .. } => None,
    }
}

/// The public constraint arms of `constraints`, and `Unique` where the
/// column is `unique`.
fn project_constraint_set(
    constraints: &crate::ir::constraint_types::IrColumnConstraints,
    unique: bool,
) -> crate::facts::diff::ConstraintFactSet {
    use crate::facts::diff::{ConstraintFactArm, ConstraintFactSet};
    use crate::facts::literal::LiteralValue;
    let literal = |repr: &String| LiteralValue::Other { repr: repr.clone() };
    let mut arms: Vec<ConstraintFactArm> = Vec::new();
    if let Some(value) = &constraints.eq_value {
        arms.push(ConstraintFactArm::Eq {
            literal: literal(value),
        });
    }
    if let Some(values) = &constraints.in_values {
        arms.push(ConstraintFactArm::InSet {
            values: values.iter().map(literal).collect(),
        });
    }
    if constraints.is_not_null {
        arms.push(ConstraintFactArm::IsNotNull);
    }
    if constraints.lower_bound.is_some() || constraints.upper_bound.is_some() {
        arms.push(ConstraintFactArm::Range {
            low: constraints.lower_bound.as_ref().map(literal),
            high: constraints.upper_bound.as_ref().map(literal),
        });
    }
    if unique {
        arms.push(ConstraintFactArm::Unique);
    }
    ConstraintFactSet { arms }
}

/// Dedup schemas across `tables_read ∪ tables_written`, keyed on
/// `IdentName.normalized` and preserving first-seen order. A table with a
/// database and no schema (`d1..t`, or a bare name under `USE DATABASE
/// d1`) is in that database's default schema, written `d1..`: the
/// statement does not say which, so it never equals a named one.
fn collect_schemas_touched(
    reads: &[crate::context::node_metadata::TableRef],
    writes: &[crate::context::node_metadata::TableRef],
) -> Vec<IdentName> {
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut out: Vec<IdentName> = Vec::new();
    for t in reads.iter().chain(writes.iter()) {
        let ident = match (t.schema.as_ref(), t.db.as_ref()) {
            (Some(schema), _) => IdentName::new(schema.clone()),
            (None, Some(db)) => {
                let db = IdentName::new(db.clone());
                IdentName::from_parts(format!("{}..", db.raw), format!("{}..", db.normalized))
            }
            (None, None) => continue,
        };
        let ident = match t.span {
            Some(span) => ident.written_at(span),
            None => ident,
        };
        if seen.insert(ident.normalized.clone()) {
            out.push(ident);
        }
    }
    out
}

// `current_for_subquery_ref` is a thin helper to satisfy the
// ScopeIdentity "current scope" needed when emitting a SubqueryRef from
// within `project_scalar_expr`. The walker doesn't carry "current"
// through expression projection (expressions are scope-local within a
// `walk` call), so the SubqueryRef is recorded as residing in the
// enclosing scope at the time of expression projection. We grab the
// most recently allocated outer-style scope (or the OUTER scope as the
// only one when no inner scopes exist).
fn current_for_subquery_ref<'a>(_walker: &QueryWalker<'a, '_>) -> ScopeIdentity {
    // The walker emits expression-bearing events (predicates, projections,
    // …) only from a node whose scope id is known at the call site. The
    // emit helpers consult `scope_mut(current)` directly. For nested
    // ScalarExpr subqueries discovered while projecting an Expr, the
    // SubqueryRef is associated with the same enclosing scope. Because
    // expression projection is purely structural it doesn't change the
    // scope, and we record subquery refs against the OUTER scope as the
    // canonical "the subquery is owned by some enclosing scope" anchor.
    ScopeIdentity::OUTER
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn empty_scope_facts(
    scope_id: ScopeIdentity,
    kind: ScopeKind,
    source_span: Option<Span>,
) -> ScopeFacts {
    ScopeFacts {
        scope_id,
        kind,
        tables: Vec::new(),
        joins: Vec::new(),
        where_predicates: Vec::new(),
        join_predicates: Vec::new(),
        having_predicates: Vec::new(),
        predicates: Vec::new(),
        projections: Vec::new(),
        group_by: Vec::new(),
        order_by: Vec::new(),
        limit: None,
        qualify: None,
        aggregates: Vec::new(),
        window_functions: Vec::new(),
        set_operations: Vec::new(),
        star_projections: Vec::new(),
        scalar_subqueries: Vec::new(),
        table_functions: Vec::new(),
        has_distinct: false,
        has_multiple_partition_schemes: false,
        has_high_cardinality_group_by: false,
        high_cardinality_group_by_columns: Vec::new(),
        source_span,
    }
}

/// Project one IR `MergeBranch` onto the public branch facts. Kind
/// reuses the existing [`crate::facts::query::MergeBranchKind`]
/// projection (shared with per-branch predicate facts); every
/// `INSERT` / `UPDATE` spelling folds to one action; `guarded`
/// records whether the branch carries an additional `AND <condition>`.
fn project_merge_branch(b: &crate::ir::plan::MergeBranch) -> crate::facts::query::MergeBranchFacts {
    use crate::facts::query::MergeActionFacts;
    use crate::ir::plan::MergeAction;
    crate::facts::query::MergeBranchFacts {
        kind: project_merge_branch_kind(b.kind),
        action: match b.action {
            MergeAction::Insert { .. }
            | MergeAction::InsertStar { .. }
            | MergeAction::InsertAllByName { .. } => MergeActionFacts::Insert,
            MergeAction::Update { .. }
            | MergeAction::UpdateSetStar { .. }
            | MergeAction::UpdateAllByName { .. } => MergeActionFacts::Update,
            MergeAction::Delete => MergeActionFacts::Delete,
            MergeAction::DoNothing => MergeActionFacts::DoNothing,
        },
        guarded: b.predicate.is_some(),
    }
}

pub fn column_catalog_metadata(
    id: ColumnId,
    catalog: Option<&crate::ir::IndexedCatalogContext>,
) -> (
    Option<crate::facts::literal::DataType>,
    Nullability,
    Vec<CatalogTag>,
) {
    let Some(catalog) = catalog else {
        return (None, Nullability::Unknown, Vec::new());
    };
    use crate::ir::CatalogContext;
    let Some(meta) = catalog.column_metadata(id) else {
        return (None, Nullability::Unknown, Vec::new());
    };
    let data_type = meta
        .data_type
        .as_ref()
        .map(|s| classify_catalog_data_type(s));
    let nullability = match meta.nullable {
        Some(true) => Nullability::CatalogNullable,
        Some(false) => Nullability::CatalogNonNullable,
        None => Nullability::Unknown,
    };
    let catalog_tags = meta.tags.iter().map(project_catalog_tag).collect();
    (data_type, nullability, catalog_tags)
}

/// Compare two catalog-projected column data types and classify the
/// pairing for join-quality reporting. Both sides catalog-known and
/// the same kind → `Compatible`; both catalog-known but numerically
/// adjacent (e.g. `INT` vs `BIGINT`) → `ImplicitCast`; both
/// catalog-known but otherwise mismatched → `Mismatch`; either side
/// absent → `Unknown`.
fn compare_data_types(
    a: &Option<crate::facts::literal::DataType>,
    b: &Option<crate::facts::literal::DataType>,
) -> crate::facts::query::TypeCompatibility {
    use crate::facts::literal::DataTypeKind;
    use crate::facts::query::TypeCompatibility;
    let (Some(a), Some(b)) = (a.as_ref(), b.as_ref()) else {
        return TypeCompatibility::Unknown;
    };
    if a.kind == b.kind {
        return TypeCompatibility::Compatible;
    }
    let numeric = |k: &DataTypeKind| {
        matches!(
            k,
            DataTypeKind::TinyInt
                | DataTypeKind::SmallInt
                | DataTypeKind::Integer
                | DataTypeKind::BigInt
                | DataTypeKind::Real
                | DataTypeKind::Double
                | DataTypeKind::Numeric
                | DataTypeKind::Decimal
        )
    };
    let stringy = |k: &DataTypeKind| {
        matches!(
            k,
            DataTypeKind::Char
                | DataTypeKind::Varchar
                | DataTypeKind::Text
                | DataTypeKind::NChar
                | DataTypeKind::NVarchar
                | DataTypeKind::Clob
        )
    };
    let temporal = |k: &DataTypeKind| {
        matches!(
            k,
            DataTypeKind::Date
                | DataTypeKind::Time
                | DataTypeKind::Timestamp
                | DataTypeKind::TimestampTz
                | DataTypeKind::TimestampLtz
                | DataTypeKind::TimestampNtz
        )
    };
    if (numeric(&a.kind) && numeric(&b.kind))
        || (stringy(&a.kind) && stringy(&b.kind))
        || (temporal(&a.kind) && temporal(&b.kind))
    {
        TypeCompatibility::ImplicitCast
    } else {
        TypeCompatibility::Mismatch
    }
}

/// Resolve `cid` to the set of `(TableRef, column_name)` origins
/// by chain-tracing through its lineage roots to base-source `ColumnId`s,
/// then querying `column_origin` on each base. Falls back to a
/// direct lookup on `cid` itself for the no-CTE case where the
/// pair is on raw-table columns and no lineage roots are known.
///
/// Shared by `compare_fk_relationship` (which uses it for the
/// per-pair l/r origin lookup) and the per-join origins-pool
/// builder in `QueryWalker::extract_join_column_pairs` (which
/// unions origins across every column of every raw pair to
/// power the composite-FK sibling check).
fn resolve_column_origins(
    cid: ColumnId,
    catalog: &crate::ir::IndexedCatalogContext,
    reasoning: &dyn super::reasoning::QueryReasoning,
) -> Vec<(legacy_meta::TableRef, String)> {
    let mut out: Vec<(legacy_meta::TableRef, String)> = Vec::new();
    let mut seen: std::collections::HashSet<(legacy_meta::TableRef, String)> =
        std::collections::HashSet::new();
    let push_origin = |origin: Option<(legacy_meta::TableRef, String)>,
                       out: &mut Vec<_>,
                       seen: &mut std::collections::HashSet<_>| {
        if let Some(o) = origin {
            if seen.insert(o.clone()) {
                out.push(o);
            }
        }
    };
    match reasoning.lineage_roots(cid) {
        Some(sources) if !sources.is_empty() => {
            for src in sources {
                let origin = catalog
                    .column_origin(*src)
                    .map(|(t, k)| (t.clone(), k.as_str().to_string()));
                push_origin(origin, &mut out, &mut seen);
            }
        }
        _ => {
            let origin = catalog
                .column_origin(cid)
                .map(|(t, k)| (t.clone(), k.as_str().to_string()));
            push_origin(origin, &mut out, &mut seen);
        }
    }
    out
}

/// Classify the FK relationship between two equi-join columns.
///
/// Consults the IR-side `IndexedCatalogContext::table_fks` to
/// decide whether the join `(left = right)` follows a declared
/// foreign-key edge on EITHER table:
///
/// - `Matches` — at least one side's table declares an FK whose
///   `(local_col, ref_table, ref_col)` matches the joined pair
///   AND every column of the source constraint is covered by some
///   pair in the same join (the composite-completeness check).
/// - `Diverges` — at least one side's table has FKs declared but
///   no edge match qualifies (either no per-pair endpoint match,
///   or the matched edge belongs to a composite constraint whose
///   sibling columns aren't all covered by the join's other
///   pairs — a partial composite match is a logic error in the
///   same way a non-FK join is).
/// - `NoFkDefined` — neither table has FKs declared and at least
///   one side has catalog metadata (so we can vouch for the
///   absence of FKs rather than report `Unknown`).
/// - `Unknown` — catalog absent or no metadata for either side.
///
/// `l_origins` / `r_origins` are each side's `ColumnId` chain-traced
/// through `BindingTable` pass-through projections (CTE bodies,
/// derived tables, set-op inputs) to the underlying base-table
/// columns. Without that, a `ColumnId` bound at a CTE projection has
/// no direct `column_origin` entry and the function would collapse to
/// `Unknown` even when the catalog clearly declares the FK on the
/// underlying base tables.
///
/// `origins_pool` is the union of every pair's lineage-resolved
/// `(TableRef, column_name)` origins across the full join — used
/// solely to verify composite-FK sibling coverage. Built once per
/// join by the caller (`extract_join_column_pairs`).
fn compare_fk_relationship(
    left: ColumnId,
    right: ColumnId,
    catalog: Option<&crate::ir::IndexedCatalogContext>,
    l_origins: &[(legacy_meta::TableRef, String)],
    r_origins: &[(legacy_meta::TableRef, String)],
    origins_pool: &std::collections::HashSet<(
        legacy_meta::TableRef,
        crate::context::node_metadata::IdentKey,
    )>,
) -> crate::facts::query::FkRelationshipStatus {
    use crate::facts::query::FkRelationshipStatus;
    let Some(catalog) = catalog else {
        return FkRelationshipStatus::Unknown;
    };
    use crate::ir::CatalogContext;

    // A `Matches` claim survives only if the matched edge's
    // composite-column tuple is fully covered by `origins_pool`. For
    // a single-column FK `composite_columns` has length 1 (the
    // edge's own local column, which IS in `origins_pool` since the
    // pool was built from the pairs that include this one), so the
    // check is trivially true. For a composite FK the check
    // requires that every sibling column of the source constraint
    // also appears in some other pair on the same local-table side
    // of the join.
    let composite_covered =
        |edge: &crate::ir::FkEdge, local_table: &legacy_meta::TableRef| -> bool {
            edge.composite_columns
                .iter()
                .all(|sc| origins_pool.contains(&(local_table.clone(), sc.clone())))
        };

    let edge_matches = |edge: &crate::ir::FkEdge,
                        local_col: &str,
                        remote_table: &legacy_meta::TableRef,
                        remote_col: &str|
     -> bool {
        edge.local_column_name
            == crate::context::node_metadata::IdentKey::new_as(local_col, NameKind::Column)
            && edge.ref_table == *remote_table
            && edge.ref_column_name
                == crate::context::node_metadata::IdentKey::new_as(remote_col, NameKind::Column)
    };

    // For each (left_origin, right_origin) pair, check whether
    // either side carries an FK edge whose endpoints match the
    // joined columns AND whose composite tuple is fully covered.
    // A `Matches` on any cross-product entry wins.
    let any_pair_matches = l_origins.iter().any(|(l_tref, l_col)| {
        r_origins.iter().any(|(r_tref, r_col)| {
            catalog.table_fks(l_tref).iter().any(|edge| {
                edge_matches(edge, l_col, r_tref, r_col) && composite_covered(edge, l_tref)
            }) || catalog.table_fks(r_tref).iter().any(|edge| {
                edge_matches(edge, r_col, l_tref, l_col) && composite_covered(edge, r_tref)
            })
        })
    });
    if any_pair_matches {
        return FkRelationshipStatus::Matches;
    }

    let any_side_has_fks = l_origins
        .iter()
        .any(|(t, _)| !catalog.table_fks(t).is_empty())
        || r_origins
            .iter()
            .any(|(t, _)| !catalog.table_fks(t).is_empty());
    if any_side_has_fks {
        return FkRelationshipStatus::Diverges;
    }

    // Has-catalog-metadata fallback for `NoFkDefined`. Uses the
    // resolved base origins when lineage is available, otherwise
    // direct metadata on `cid` (handles plan-less / no-lineage
    // contexts identically to the pre-lineage version).
    let any_origin_has_table = !l_origins.is_empty() || !r_origins.is_empty();
    let any_direct_meta =
        catalog.column_metadata(left).is_some() || catalog.column_metadata(right).is_some();
    if any_origin_has_table || any_direct_meta {
        FkRelationshipStatus::NoFkDefined
    } else {
        FkRelationshipStatus::Unknown
    }
}

/// Append each of `items` that `list` does not already hold, in order.
fn extend_absent<T: PartialEq>(list: &mut Vec<T>, items: impl IntoIterator<Item = T>) {
    for item in items {
        if !list.contains(&item) {
            list.push(item);
        }
    }
}

/// Project a catalog tag list onto the typed public `TaintLabel`
/// taxonomy. Recognised governance classifications (PII, PHI,
/// Confidential, Restricted, Internal, Public — matched
/// case-insensitively against the tag's value) project to their
/// dedicated variant; everything else surfaces under
/// `TaintLabel::Other(qualified_name)` so customer predicates can
/// glob-match on dialect-specific labels.
fn project_taint_labels(tags: &[crate::ir::TagRef]) -> Vec<crate::facts::catalog::TaintLabel> {
    use crate::facts::catalog::TaintLabel;
    tags.iter()
        .map(|t| {
            let value_upper = t.value.as_deref().unwrap_or("").to_ascii_uppercase();
            match value_upper.as_str() {
                "PII" => TaintLabel::Pii,
                "PHI" => TaintLabel::Phi,
                "CONFIDENTIAL" => TaintLabel::Confidential,
                "RESTRICTED" => TaintLabel::Restricted,
                "INTERNAL" => TaintLabel::Internal,
                "PUBLIC" => TaintLabel::Public,
                _ => TaintLabel::Other(t.qualified_name.clone()),
            }
        })
        .collect()
}

/// Best-effort projection of a catalog-reported type string into the
/// typed. Recognised kind heads
/// project to dedicated variants; anything else falls into
/// `DataTypeKind::Other(raw_uppercase)`. The original spelling is
/// preserved on the `raw` field so customer predicates can match on
/// dialect-specific shapes via `data_type.raw: { matches: ... }`.
pub fn classify_catalog_data_type(raw: &str) -> crate::facts::literal::DataType {
    use crate::facts::literal::{DataType, DataTypeKind};
    let upper = raw.to_ascii_uppercase();
    let head = upper
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .next()
        .unwrap_or("");
    let kind = match head {
        "BOOLEAN" | "BOOL" => DataTypeKind::Boolean,
        "TINYINT" | "INT1" | "BYTEINT" => DataTypeKind::TinyInt,
        "SMALLINT" | "INT2" => DataTypeKind::SmallInt,
        "INT" | "INTEGER" | "INT4" => DataTypeKind::Integer,
        "BIGINT" | "INT8" | "LONG" => DataTypeKind::BigInt,
        "REAL" | "FLOAT4" => DataTypeKind::Real,
        "DOUBLE" | "FLOAT" | "FLOAT8" => DataTypeKind::Double,
        "NUMERIC" => DataTypeKind::Numeric,
        "DECIMAL" | "NUMBER" => DataTypeKind::Decimal,
        "CHAR" | "CHARACTER" => DataTypeKind::Char,
        "VARCHAR" | "STRING" | "VARCHAR2" => DataTypeKind::Varchar,
        "TEXT" | "CLOB" => DataTypeKind::Text,
        "NCHAR" => DataTypeKind::NChar,
        "NVARCHAR" | "NVARCHAR2" => DataTypeKind::NVarchar,
        "BINARY" | "BYTES" => DataTypeKind::Binary,
        "VARBINARY" => DataTypeKind::Varbinary,
        "BLOB" => DataTypeKind::Blob,
        "DATE" => DataTypeKind::Date,
        "TIME" => DataTypeKind::Time,
        "DATETIME" | "TIMESTAMP" => DataTypeKind::Timestamp,
        "TIMESTAMP_TZ" | "TIMESTAMPTZ" => DataTypeKind::TimestampTz,
        "TIMESTAMP_LTZ" => DataTypeKind::TimestampLtz,
        "TIMESTAMP_NTZ" => DataTypeKind::TimestampNtz,
        "INTERVAL" => DataTypeKind::Interval,
        "ARRAY" => DataTypeKind::Array,
        "MAP" => DataTypeKind::Map,
        "OBJECT" => DataTypeKind::Object,
        "STRUCT" => DataTypeKind::Struct,
        "VARIANT" => DataTypeKind::Variant,
        "JSON" => DataTypeKind::Json,
        "JSONB" => DataTypeKind::Jsonb,
        "UUID" => DataTypeKind::Uuid,
        "GEOGRAPHY" => DataTypeKind::Geography,
        "GEOMETRY" => DataTypeKind::Geometry,
        "VECTOR" => DataTypeKind::Vector,
        "INET" => DataTypeKind::Inet,
        "CIDR" => DataTypeKind::Cidr,
        "MACADDR" => DataTypeKind::MacAddr,
        _ => DataTypeKind::Other(PublicIdentName::new(&upper)),
    };
    DataType {
        kind,
        precision: None,
        scale: None,
        length: None,
        element_type: None,
        key_type: None,
        fields: Vec::new(),
        timezone: None,
        raw: raw.to_string(),
    }
}

/// The base-table columns a plan column traces back to.
type ColumnOrigins = Vec<(legacy_meta::TableRef, String)>;

/// `(catalog_tags, row_count, column_count, table_kind, in_catalog,
/// searched_as)` for a base table.
type TableCatalogMetadata = (
    Vec<CatalogTag>,
    Option<u64>,
    Option<u32>,
    Option<crate::facts::query::TableKind>,
    Option<bool>,
    Option<String>,
);

/// Look up catalog-derived metadata for a base table. Each element is
/// empty/None when no catalog is attached or the catalog has no entry for
/// the table.
fn table_catalog_metadata(
    table: &legacy_meta::TableRef,
    catalog: Option<&crate::ir::IndexedCatalogContext>,
) -> TableCatalogMetadata {
    let Some(catalog) = catalog else {
        return (Vec::new(), None, None, None, None, None);
    };
    use crate::ir::CatalogContext;
    let tags = catalog
        .resolve_table_tags(table)
        .iter()
        .map(project_catalog_tag)
        .collect();
    let row_count = catalog.table_row_count(table);
    let column_count = catalog.resolve_table_columns(table).map(|c| c.len() as u32);
    let table_kind = catalog.table_kind(table).map(project_table_kind);
    let in_catalog = catalog.table_in_catalog(table);
    let searched_as = catalog.table_searched(table).map(|names| {
        names
            .iter()
            .map(|name| {
                [
                    name.db.as_deref(),
                    name.schema.as_deref(),
                    Some(name.name.as_str()),
                ]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(".")
            })
            .collect::<Vec<_>>()
            .join(", ")
    });
    (
        tags,
        row_count,
        column_count,
        table_kind,
        in_catalog,
        searched_as,
    )
}

/// The tables `reads` and `writes` hold, once each, a table in both as
/// `writes` holds it, each at its first reference, in the order of those
/// references ([`crate::facts::query::QueryFacts::tables_used`]).
fn tables_used(reads: &[TableEvent], writes: &[TableEvent]) -> Vec<TableEvent> {
    let mut used: Vec<TableEvent> = Vec::with_capacity(reads.len() + writes.len());
    for event in writes.iter().chain(reads) {
        match used
            .iter_mut()
            .find(|held| held.table.canonical == event.table.canonical)
        {
            Some(held) => {
                let earlier = match (held.source_span, event.source_span) {
                    (Some(first), Some(at)) => at.start < first.start,
                    (None, Some(_)) => true,
                    (Some(_), None) | (None, None) => false,
                };
                if earlier {
                    held.source_span = event.source_span;
                    held.table.source_span = event.source_span;
                }
            }
            None => used.push(event.clone()),
        }
    }
    used.sort_by_key(|event| event.source_span.map_or(u32::MAX, |at| at.start));
    used
}

/// As [`table_catalog_metadata`], for a table a statement writes. The
/// column count of a DML target the catalog resolves is the number of
/// columns the catalog declares for it, whatever the statement reads.
fn target_catalog_metadata(
    table: &legacy_meta::TableRef,
    catalog: Option<&crate::ir::IndexedCatalogContext>,
) -> TableCatalogMetadata {
    let (tags, row_count, column_count, table_kind, in_catalog, searched_as) =
        table_catalog_metadata(table, catalog);
    let declared = catalog
        .and_then(|catalog| catalog.target_declared_columns(table))
        .map(|names| names.len() as u32);
    (
        tags,
        row_count,
        declared.or(column_count),
        table_kind,
        in_catalog,
        searched_as,
    )
}

/// Project the IR-side onto the public taxonomy.
fn project_table_kind(k: crate::ir::IrTableKind) -> crate::facts::query::TableKind {
    use crate::facts::query::TableKind;
    use crate::ir::IrTableKind;
    match k {
        IrTableKind::Table => TableKind::Table,
        IrTableKind::View => TableKind::View,
        IrTableKind::MaterializedView => TableKind::MaterializedView,
        IrTableKind::ExternalTable => TableKind::ExternalTable,
        IrTableKind::Temporary => TableKind::Temporary,
        IrTableKind::Unknown => TableKind::Unknown,
    }
}

/// Project an IR-side into a public
/// [`CatalogTag`]. The IR carries the qualified tag name and an
/// optional value; the public surface keeps the same pair.
fn project_catalog_tag(t: &crate::ir::TagRef) -> CatalogTag {
    CatalogTag {
        key: PublicIdentName::new(&t.qualified_name),
        value: t.value.clone(),
    }
}

/// Project every `ColumnOrigin::Table` binding in the statement to a
/// public [`ColumnReferenceEvent`], paired with the catalog-presence
/// outcome the lowerer recorded at `seed_catalog_ctx_from_scan` time.
/// A `ColumnOrigin::Unattributed` binding gives an event that names no
/// table.
///
/// Deduplicated by `(table, column_name)`, and for an unattributed
/// column by its qualifier too, which the event does not carry: a bare
/// name and the same name behind a qualifier are two events. A column read through a
/// CTE or derived-table reference is the reference's own computed
/// column, paired with the table column it is; that table column's
/// binding contributes the one event, however many references read
/// it.
///
/// `in_catalog` is a tri-state: present (`Some(true)` when the column
/// was found, `Some(false)` when it was absent) only when (a) a catalog
/// is attached, (b) the column resolved to a scan source, and (c) the
/// table itself was present in the catalog; or `Some(false)` for a
/// column of no source that no source in scope can have, with a table
/// the catalog knows among them. Otherwise `None`.
///
/// `written` holds each column a DML statement writes, with its target.
/// Such a column is a computed column of the statement, not a table
/// binding, so the loop over the bindings does not see it: where the
/// catalog declares the column for the target and no binding of the
/// target's column already gave the event, it is published here as a
/// column of the target that is in the catalog.
pub(crate) fn project_column_references(
    bindings: &crate::ir::column::BindingTable,
    catalog: Option<&crate::ir::catalog_context::IndexedCatalogContext>,
    scan_index: Option<&crate::ir::expression_fact::ScanIndex>,
    written: &[(&legacy_meta::TableRef, ColumnId)],
) -> Vec<crate::facts::query::ColumnReferenceEvent> {
    use crate::ir::column::ColumnOrigin;
    let mut out: Vec<crate::facts::query::ColumnReferenceEvent> = Vec::new();
    // (table, qualifier of an unattributed column, column name).
    let mut seen: std::collections::HashSet<(Option<legacy_meta::TableRef>, Option<&str>, String)> =
        std::collections::HashSet::new();
    // The written columns the catalog declares for their target, and
    // those an assignment writes by a name of the target's own that the
    // target lacks, with whether the catalog has them.
    let declared_written: Vec<(
        &legacy_meta::TableRef,
        ColumnId,
        legacy_meta::IdentKey,
        bool,
    )> = match catalog {
        Some(cat) => written
            .iter()
            .filter_map(|&(target, cid)| {
                let name = legacy_meta::IdentKey::new_as(
                    &bindings.get(cid)?.display_name,
                    NameKind::Column,
                );
                if cat.column_in_catalog(cid) == Some(false) {
                    return Some((target, cid, name, false));
                }
                cat.target_declared_columns(target)?
                    .contains(&name)
                    .then_some((target, cid, name, true))
            })
            .collect(),
        None => Vec::new(),
    };
    // (table, column) of every event given, kept only where a written
    // column could repeat one.
    let mut referenced: std::collections::HashSet<(legacy_meta::TableRef, legacy_meta::IdentKey)> =
        std::collections::HashSet::new();

    for (cid, binding) in bindings.iter() {
        let (column_name, span, table_node, qualifier) = match &binding.origin {
            ColumnOrigin::Table {
                column_name,
                span,
                table_node,
            } => (column_name, span, Some(table_node), None),
            ColumnOrigin::Unattributed {
                qualifier,
                name,
                span,
            } => (name, span, None, qualifier.as_deref()),
            ColumnOrigin::Computed { .. }
            | ColumnOrigin::Merged { .. }
            | ColumnOrigin::SetOp { .. }
            | ColumnOrigin::OuterRef { .. }
            | ColumnOrigin::RecursiveRef { .. } => continue,
        };

        // IR-derived table identity: the `table_node` carried on every
        // scan-bound `ColumnOrigin::Table` points at the AST `NodeId`
        // of the source `Scan` / `CteRef` / `ModelRef`. The
        // `ScanIndex` is built directly from the lowered `RelPlan`
        // (no catalog dependency); this resolves the column's owning
        // table even in catalog-less analysis.
        let scan_table = table_node
            .and_then(|node| scan_index.and_then(|idx| idx.get(node)))
            .cloned();

        // Catalog-augmented bits (`in_catalog`, `is_ambiguous`) are
        // populated only when an external catalog was attached; the
        // catalog's `column_origin` cache is keyed on the same scan
        // identity so we cross-reference for the presence outcome.
        let (catalog_table, in_catalog, is_ambiguous) = match catalog {
            Some(cat) => {
                let cat_origin = cat.column_origin(*cid).cloned();
                let cat_table = cat_origin.as_ref().map(|(t, _)| t.clone());
                let presence = match &cat_table {
                    Some(t) => match cat.table_in_catalog(t) {
                        Some(true) => cat.column_in_catalog(*cid),
                        _ => None,
                    },
                    // A column of no table: absent where every table in
                    // scope the catalog knows lacks it.
                    None => cat.column_in_catalog(*cid),
                };
                (cat_table, presence, cat.column_is_ambiguous(*cid))
            }
            None => (None, None, false),
        };

        // Prefer the IR-derived scan identity; the catalog cache
        // mirrors it when present but stays None when no catalog is
        // attached. Falling back to `catalog_table` covers the
        // (rare) path where a caller has a catalog but no scan
        // index.
        let table_ref = scan_table.or(catalog_table);

        let public_table = table_ref
            .as_ref()
            .map(|t| project_metadata_table_ref(t, None));
        if !declared_written.is_empty() {
            if let Some(table) = table_ref.as_ref() {
                referenced.insert((
                    table.clone(),
                    legacy_meta::IdentKey::new_as(column_name, NameKind::Column),
                ));
            }
        }
        let dedup_key = (table_ref, qualifier, column_name.clone());
        if !seen.insert(dedup_key) {
            continue;
        }

        let column = ColumnRef::minimal(self::column_name(column_name), public_table);
        out.push(crate::facts::query::ColumnReferenceEvent {
            column,
            in_catalog,
            is_ambiguous,
            source_span: Some(*span),
        });
    }

    for (target, cid, name, in_catalog) in declared_written {
        let Some(binding) = bindings.get(cid) else {
            continue;
        };
        let (ColumnOrigin::Computed { expr_span, .. } | ColumnOrigin::Merged { expr_span, .. }) =
            &binding.origin
        else {
            continue;
        };
        if !referenced.insert((target.clone(), name)) {
            continue;
        }
        let column = ColumnRef::minimal(
            column_name(&binding.display_name),
            Some(project_metadata_table_ref(target, None)),
        );
        out.push(crate::facts::query::ColumnReferenceEvent {
            column,
            in_catalog: Some(in_catalog),
            is_ambiguous: false,
            source_span: Some(*expr_span),
        });
    }

    out
}

pub fn project_metadata_table_ref(t: &legacy_meta::TableRef, span: Option<Span>) -> PublicTableRef {
    PublicTableRef::new(
        PublicIdentName::new(&t.name),
        t.schema.as_ref().map(PublicIdentName::new),
        t.db.as_ref().map(PublicIdentName::new),
        span.or(t.span),
    )
    .with_server(t.server.as_ref().map(PublicIdentName::new))
}

fn project_join_kind(ir: IrJoinKind, lateral: bool, natural: bool) -> PublicJoinKind {
    if lateral {
        return PublicJoinKind::Lateral;
    }
    if natural {
        return match ir {
            IrJoinKind::Inner => PublicJoinKind::NaturalInner,
            IrJoinKind::LeftOuter => PublicJoinKind::NaturalLeft,
            IrJoinKind::RightOuter => PublicJoinKind::NaturalRight,
            IrJoinKind::FullOuter => PublicJoinKind::NaturalFullOuter,
            // `NATURAL` does not pair with `CROSS` / `ASOF` / `SEMI` /
            // `ANTI` in any dialect; if the parser somehow surfaces it,
            // fall back to the non-natural projection rather than
            // inventing a public variant.
            IrJoinKind::Cross => PublicJoinKind::Cross,
            IrJoinKind::Asof => PublicJoinKind::AsOf,
            IrJoinKind::LeftSemi | IrJoinKind::RightSemi => PublicJoinKind::Semi,
            IrJoinKind::LeftAnti | IrJoinKind::RightAnti => PublicJoinKind::Anti,
        };
    }
    match ir {
        IrJoinKind::Inner => PublicJoinKind::Inner,
        IrJoinKind::LeftOuter => PublicJoinKind::Left,
        IrJoinKind::RightOuter => PublicJoinKind::Right,
        IrJoinKind::FullOuter => PublicJoinKind::FullOuter,
        IrJoinKind::Cross => PublicJoinKind::Cross,
        IrJoinKind::Asof => PublicJoinKind::AsOf,
        // The IR distinguishes left/right semi-anti for taint/lineage
        // direction. The public surface collapses to a single Semi/Anti
        // because rule predicates care about the join family, not the
        // projection side.
        IrJoinKind::LeftSemi | IrJoinKind::RightSemi => PublicJoinKind::Semi,
        IrJoinKind::LeftAnti | IrJoinKind::RightAnti => PublicJoinKind::Anti,
    }
}

fn project_merge_branch_kind(
    ir: crate::ir::plan::MergeBranchKind,
) -> crate::facts::query::MergeBranchKind {
    use crate::facts::query::MergeBranchKind as Pub;
    use crate::ir::plan::MergeBranchKind as Ir;
    match ir {
        Ir::WhenMatched => Pub::WhenMatched,
        Ir::WhenNotMatched => Pub::WhenNotMatched,
        Ir::WhenNotMatchedBySource => Pub::WhenNotMatchedBySource,
    }
}

fn project_set_op_kind(ir: IrSetOpKind) -> PublicSetOpKind {
    match ir {
        IrSetOpKind::UnionAll => PublicSetOpKind::UnionAll,
        IrSetOpKind::UnionDistinct => PublicSetOpKind::Union,
        IrSetOpKind::IntersectAll => PublicSetOpKind::IntersectAll,
        IrSetOpKind::IntersectDistinct => PublicSetOpKind::Intersect,
        IrSetOpKind::ExceptAll => PublicSetOpKind::ExceptAll,
        IrSetOpKind::ExceptDistinct => PublicSetOpKind::Except,
    }
    // `PublicSetOpKind::Minus` is reachable via dialect-specific MINUS
    // syntax; the IR folds it into `Except*` at lowering time, so the
    // public projection inherits that folding.
}

/// Public-typed variant of `crate::ir::derived_facts::principal_table` —
/// resolves a relational subtree to its single principal source
/// reference (right-recursive on joins for the `principal` heuristic): a
/// base table, a CTE, or a table function named by its function.
/// Returns `None` when no single source is identifiable (a function
/// source that is no call, set-ops with no first-input table, DML,
/// opaque fragments, …).
fn principal_source<'a>(
    plan: &'a RelPlan,
    functions: &crate::ir::FunctionCatalog,
) -> Option<PrincipalSource<'a>> {
    match plan {
        RelPlan::Scan { table, span, .. } => Some(PrincipalSource {
            name: project_metadata_table_ref(table, Some(*span)),
            call: None,
        }),
        RelPlan::CteRef { name, span, .. } => Some(PrincipalSource {
            name: PublicTableRef::new(PublicIdentName::new(name.as_str()), None, None, Some(*span)),
            call: None,
        }),
        RelPlan::ModelRef { model, span, .. } => {
            model.base_tables.first().map(|t| PrincipalSource {
                name: project_metadata_table_ref(t, Some(*span)),
                call: None,
            })
        }
        RelPlan::TableFunction { call, span, .. } => {
            call.called_function().map(|func| PrincipalSource {
                name: resolved_func_table_ref(func, functions, *span),
                call: Some(call),
            })
        }
        RelPlan::Join { right, .. } => principal_source(right, functions),
        RelPlan::SetOp { inputs, .. } => {
            inputs.first().and_then(|p| principal_source(p, functions))
        }
        RelPlan::Project { input, .. }
        | RelPlan::Filter { input, .. }
        | RelPlan::Aggregate { input, .. }
        | RelPlan::Window { input, .. }
        | RelPlan::Sort { input, .. }
        | RelPlan::Limit { input, .. }
        | RelPlan::TableSample { input, .. }
        | RelPlan::Pivot { input, .. }
        | RelPlan::Unpivot { input, .. }
        | RelPlan::MatchRecognize { input, .. }
        | RelPlan::ConnectBy { input, .. }
        | RelPlan::Unnest { input, .. }
        | RelPlan::DerivedTable { input, .. } => principal_source(input, functions),
        RelPlan::Explain { body, .. } => principal_source(body, functions),
        RelPlan::WithScope { body, .. } => principal_source(body, functions),
        RelPlan::CreateAsQuery { body, .. } => {
            body.as_deref().and_then(|b| principal_source(b, functions))
        }
        RelPlan::Values { .. }
        | RelPlan::CreateTableForm { .. }
        | RelPlan::Insert { .. }
        | RelPlan::Update { .. }
        | RelPlan::Delete { .. }
        | RelPlan::Merge { .. }
        | RelPlan::MultiInsert { .. }
        | RelPlan::ParseRecovery { .. }
        | RelPlan::InvalidInput { .. }
        | RelPlan::Opaque { .. } => None,
    }
}

/// A join operand's principal source: its published name, and the call
/// when the source is a table function.
struct PrincipalSource<'a> {
    name: PublicTableRef,
    call: Option<&'a ScalarExpr>,
}

/// What a join's right operand reads its rows from: a call is
/// correlated when an argument (or an argument's subquery) reads a
/// column the left operand yields.
fn join_right_source(
    right: &PrincipalSource<'_>,
    left: &RelPlan,
    bindings: &BindingTable,
) -> PublicJoinSource {
    let Some(call) = right.call else {
        return PublicJoinSource::Table;
    };
    let mut reads = std::collections::HashSet::new();
    collect_reads(call, &mut reads);
    if reads.is_empty() {
        return PublicJoinSource::TableFunction;
    }
    let left_columns: std::collections::HashSet<ColumnId> =
        left.output_schema().into_iter().collect();
    let left_sources = crate::ir::correlation::source_nodes(left);
    let reads_left = reads.iter().any(|column| {
        left_columns.contains(column)
            || bindings
                .get(*column)
                .is_some_and(|binding| match &binding.origin {
                    crate::ir::column::ColumnOrigin::Table { table_node, .. } => {
                        left_sources.contains(table_node)
                    }
                    crate::ir::column::ColumnOrigin::Computed { producing_node, .. } => {
                        left_sources.contains(producing_node)
                    }
                    crate::ir::column::ColumnOrigin::Merged { .. }
                    | crate::ir::column::ColumnOrigin::SetOp { .. }
                    | crate::ir::column::ColumnOrigin::OuterRef { .. }
                    | crate::ir::column::ColumnOrigin::RecursiveRef { .. }
                    | crate::ir::column::ColumnOrigin::Unattributed { .. } => false,
                })
    });
    match reads_left {
        true => PublicJoinSource::CorrelatedTableFunction,
        false => PublicJoinSource::TableFunction,
    }
}

/// Add each column `expr` reads to `into`, with each column its subqueries
/// read of an enclosing query.
fn collect_reads(expr: &ScalarExpr, into: &mut std::collections::HashSet<ColumnId>) {
    struct Reads<'s>(&'s mut std::collections::HashSet<ColumnId>);
    impl<'a> crate::ir::visitor::ScalarExprVisitor<'a> for Reads<'_> {
        fn visit_scalar_expr(&mut self, expr: &'a ScalarExpr) {
            if let ScalarExpr::Column { column, .. }
            | ScalarExpr::OuterRef { column, .. }
            | ScalarExpr::PatternVarRef { column, .. } = expr
            {
                self.0.insert(*column);
            }
            crate::ir::visitor::walk_scalar_expr_standalone(self, expr);
        }
        fn visit_scalar_subquery(&mut self, _plan: &'a RelPlan, correlates_with: &'a [ColumnId]) {
            self.0.extend(correlates_with.iter().copied());
        }
    }
    crate::ir::visitor::ScalarExprVisitor::visit_scalar_expr(&mut Reads(into), expr);
}

/// What a scope's select list reads.
#[derive(Default)]
struct SelectReads {
    /// Each column it reads, and each its windows, aggregates and computed
    /// items read for it.
    columns: std::collections::HashSet<ColumnId>,
    /// Its stars.
    stars: Vec<StarCover>,
}

/// What a star of a select list ranges over.
struct StarCover {
    /// The name that qualifies it (`f.*`); none for a bare star, which
    /// ranges over every source.
    qualifier: Option<crate::context::node_metadata::IdentKey>,
    /// The sources whose columns it was expanded into items for: what it
    /// reads of them, the items read.
    enumerated: Vec<crate::ast::NodeId>,
}

impl SelectReads {
    /// Add what `expr`, read for the list, reads.
    fn add(&mut self, expr: &ScalarExpr) {
        collect_reads(expr, &mut self.columns);
    }

    /// Add what `expr` reads where the list reads `output`.
    fn add_for(&mut self, output: ColumnId, expr: &ScalarExpr) {
        if self.columns.contains(&output) {
            self.add(expr);
        }
    }

    /// Add what each of `computed` that the list reads reads, the later
    /// first, as an entry reads only those before it.
    fn add_computed(&mut self, computed: &[crate::ir::plan::ComputedItem]) {
        for item in computed.iter().rev() {
            self.add_for(item.output, &item.expr);
        }
    }

    /// Whether the list reads a column of the table function source
    /// `node`, whose columns `columns` lists, aliased `alias`: one of them,
    /// or a star over the source that is not expanded into its columns.
    fn reads_function(
        &self,
        columns: &[ColumnId],
        alias: Option<&crate::context::node_metadata::IdentKey>,
        node: crate::ast::NodeId,
    ) -> bool {
        let covers = |star: &StarCover| match &star.qualifier {
            None => true,
            Some(qualifier) => alias == Some(qualifier),
        };
        self.stars
            .iter()
            .any(|star| covers(star) && !star.enumerated.contains(&node))
            || columns.iter().any(|column| self.columns.contains(column))
    }
}

/// Walk a subtree to its principal base-table reference as a
/// [`crate::context::node_metadata::TableRef`], descending through
/// `RelPlan::CteRef` into the named binding's body via `cte_bindings`.
/// Used at JoinEvent construction to resolve `left_row_count` /
/// `right_row_count` for CTE-wrapped operands (the realistic dbt
/// shape — `WITH stg AS (...) ... CROSS JOIN stg`). Without this
/// descent the CteRef arm returned `None` and catalog-gated rules
/// (Q-JOIN-CROSS-CENH) silently FN'd on every realistic SQL composition.
fn principal_scan_metadata_table_ref_with_ctes<'a>(
    plan: &'a RelPlan,
    cte_bindings: &[&'a crate::ir::plan::CteBinding],
) -> Option<&'a legacy_meta::TableRef> {
    match plan {
        RelPlan::Scan { table, .. } => Some(table),
        RelPlan::Join { right, .. } => {
            principal_scan_metadata_table_ref_with_ctes(right, cte_bindings)
        }
        RelPlan::SetOp { inputs, .. } => inputs
            .first()
            .and_then(|p| principal_scan_metadata_table_ref_with_ctes(p, cte_bindings)),
        RelPlan::Project { input, .. }
        | RelPlan::Filter { input, .. }
        | RelPlan::Aggregate { input, .. }
        | RelPlan::Window { input, .. }
        | RelPlan::Sort { input, .. }
        | RelPlan::Limit { input, .. }
        | RelPlan::TableSample { input, .. }
        | RelPlan::Pivot { input, .. }
        | RelPlan::Unpivot { input, .. }
        | RelPlan::MatchRecognize { input, .. }
        | RelPlan::ConnectBy { input, .. }
        | RelPlan::Unnest { input, .. }
        | RelPlan::DerivedTable { input, .. } => {
            principal_scan_metadata_table_ref_with_ctes(input, cte_bindings)
        }
        RelPlan::Explain { body, .. } => {
            principal_scan_metadata_table_ref_with_ctes(body, cte_bindings)
        }
        RelPlan::WithScope { ctes, body, .. } => {
            // The body reaches this scope's CTEs beside those around it;
            // a reference resolves by its scope, so a CTE of an outer
            // name stays apart from the outer one.
            let in_scope: Vec<&'a crate::ir::plan::CteBinding> =
                cte_bindings.iter().copied().chain(ctes.iter()).collect();
            principal_scan_metadata_table_ref_with_ctes(body, &in_scope)
        }
        RelPlan::CreateAsQuery { body, .. } => body
            .as_deref()
            .and_then(|b| principal_scan_metadata_table_ref_with_ctes(b, cte_bindings)),
        RelPlan::ModelRef { model, .. } => model.base_tables.first(),
        RelPlan::CteRef { scope, .. } => {
            // Descend through the CTE's body so realistic
            // `WITH stg AS (...) ... CROSS JOIN stg` shapes can
            // resolve to the underlying base-table for catalog
            // row-count lookup. For recursive CTEs, use the anchor.
            // The binding is the one the reference was resolved to, by
            // its scope: a CTE of the same name in another scope is
            // another relation, and one whose body reads it would loop.
            let binding = cte_bindings.iter().find(|b| b.scope == *scope)?;
            let body = match &binding.body {
                crate::ir::plan::CteBody::NonRecursive(b) => b.as_ref(),
                crate::ir::plan::CteBody::Recursive { anchor, .. } => anchor.as_ref(),
            };
            principal_scan_metadata_table_ref_with_ctes(body, cte_bindings)
        }
        RelPlan::Values { .. }
        | RelPlan::TableFunction { .. }
        | RelPlan::CreateTableForm { .. }
        | RelPlan::Insert { .. }
        | RelPlan::Update { .. }
        | RelPlan::Delete { .. }
        | RelPlan::Merge { .. }
        | RelPlan::MultiInsert { .. }
        | RelPlan::ParseRecovery { .. }
        | RelPlan::InvalidInput { .. }
        | RelPlan::Opaque { .. } => None,
    }
}

/// Determine the `TableAccessKind` for entries in
/// `QueryFacts.writes_table`, based on the root plan's DML shape.
/// `derived_facts.tables_written` is a flat set; the access kind is
/// uniform across entries because lowering attaches at most one
/// write-bearing root per statement.
fn root_write_access_kind(plan: &RelPlan) -> TableAccessKind {
    match plan {
        RelPlan::Insert { .. } | RelPlan::MultiInsert { .. } => TableAccessKind::InsertedInto,
        RelPlan::Update { .. } => TableAccessKind::Updated,
        RelPlan::Delete { .. } => TableAccessKind::DeletedFrom,
        RelPlan::Merge { .. } => TableAccessKind::ReadAndWritten,
        RelPlan::WithScope { body, .. } => root_write_access_kind(body),
        RelPlan::Explain { body, .. } => root_write_access_kind(body),
        RelPlan::CreateAsQuery { .. } | RelPlan::CreateTableForm { .. } => TableAccessKind::Written,
        // Non-DML root shapes: `tables_written` is empty for these per
        // the IR contract, so this fallback is unreachable in practice.
        // Falling to `Written` is a defensive choice if a future plan
        // shape introduces writes without one of the discriminated arms.
        RelPlan::Scan { .. }
        | RelPlan::Values { .. }
        | RelPlan::CteRef { .. }
        | RelPlan::ModelRef { .. }
        | RelPlan::Project { .. }
        | RelPlan::Filter { .. }
        | RelPlan::Aggregate { .. }
        | RelPlan::Window { .. }
        | RelPlan::Sort { .. }
        | RelPlan::Limit { .. }
        | RelPlan::Pivot { .. }
        | RelPlan::Unpivot { .. }
        | RelPlan::Unnest { .. }
        | RelPlan::Join { .. }
        | RelPlan::SetOp { .. }
        | RelPlan::DerivedTable { .. }
        | RelPlan::TableFunction { .. }
        | RelPlan::TableSample { .. }
        | RelPlan::MatchRecognize { .. }
        | RelPlan::ConnectBy { .. }
        | RelPlan::ParseRecovery { .. }
        | RelPlan::InvalidInput { .. }
        | RelPlan::Opaque { .. } => TableAccessKind::Written,
    }
}

/// Extract the inner relational source from an `INSERT INTO t <source>`
/// shape. `Values` carries a `RelPlan::Values` that contributes nothing
/// to `tables_read` but is walked uniformly for shape-completeness.
/// `DefaultValues` has no relational input.
fn insert_source_plan(source: &crate::ir::plan::InsertSource) -> Option<&RelPlan> {
    use crate::ir::plan::InsertSource as I;
    match source {
        I::Query(plan) | I::Values(plan) => Some(plan),
        I::DefaultValues => None,
    }
}

// ── Expression-projection helpers ──────────────────────────────────────────

/// Map an IR `Lit` to a public `LiteralValue`. Numeric literals carry
/// raw source text in IR; we parse where possible and fall to `Other`
/// for shapes the public surface doesn't model directly.
fn project_lit(lit: &Lit) -> LiteralValue {
    match lit {
        Lit::Null => LiteralValue::Null,
        Lit::Bool(b) => LiteralValue::Bool { value: *b },
        Lit::Integer(s) => match s.parse::<i64>() {
            Ok(n) => LiteralValue::Integer { value: n },
            Err(_) => LiteralValue::Other { repr: s.clone() },
        },
        Lit::Float(s) => match s.parse::<f64>() {
            Ok(n) => LiteralValue::Float { value: n },
            Err(_) => LiteralValue::Other { repr: s.clone() },
        },
        Lit::Str(s) => LiteralValue::String { value: s.clone() },
        Lit::Bytes { tag, value } => LiteralValue::Other {
            repr: format!("{}'{}'", tag, value),
        },
        Lit::Typed { type_name, value } => LiteralValue::Other {
            repr: format!("{} '{}'", type_name, value),
        },
        Lit::Variant(s) | Lit::Variable { written: s, .. } => {
            LiteralValue::Other { repr: s.clone() }
        }
    }
}

/// Map an IR binary-op string (uppercase keyword or symbolic) to the
/// public closed-enum [`BinaryOp`]. Unknown ops fall to `Other`.
fn project_binary_op_str(op: &str) -> BinaryOp {
    let normalized = op.trim().to_ascii_uppercase();
    match normalized.as_str() {
        "=" | "==" => BinaryOp::Eq,
        "!=" | "<>" => BinaryOp::Neq,
        "<" => BinaryOp::Lt,
        "<=" => BinaryOp::Lte,
        ">" => BinaryOp::Gt,
        ">=" => BinaryOp::Gte,
        "IS DISTINCT FROM" => BinaryOp::IsDistinctFrom,
        "IS NOT DISTINCT FROM" => BinaryOp::IsNotDistinctFrom,
        "LIKE" => BinaryOp::Like,
        "ILIKE" => BinaryOp::ILike,
        "NOT LIKE" => BinaryOp::NotLike,
        "NOT ILIKE" => BinaryOp::NotILike,
        "SIMILAR TO" | "SIMILAR" => BinaryOp::Similar,
        "NOT SIMILAR TO" | "NOT SIMILAR" => BinaryOp::NotSimilar,
        "IN" => BinaryOp::In,
        "NOT IN" => BinaryOp::NotIn,
        "+" => BinaryOp::Add,
        "-" => BinaryOp::Sub,
        "*" => BinaryOp::Mul,
        "/" => BinaryOp::Div,
        "%" | "MOD" => BinaryOp::Mod,
        "**" | "^" => BinaryOp::Pow,
        "AND" => BinaryOp::And,
        "OR" => BinaryOp::Or,
        "||" | "CONCAT" => BinaryOp::Concat,
        "&" => BinaryOp::BitAnd,
        "|" => BinaryOp::BitOr,
        "<<" => BinaryOp::ShiftLeft,
        ">>" => BinaryOp::ShiftRight,
        "->" => BinaryOp::JsonGet,
        "->>" => BinaryOp::JsonGetText,
        "@>" => BinaryOp::ArrayContains,
        "&&" => BinaryOp::ArrayOverlap,
        _ => BinaryOp::Other(PublicIdentName::new(op)),
    }
}

/// Map an IR to the public
/// closed-enum [`UnaryOp`]. Closed-enum exhaustive; dialect-specific
/// unary operators with no public equivalent (`AT LOCAL`, `COLLATE`,
/// `PRIOR`, `**`, `~`, `|/`, `@`, `IS NOT TRUE`, `IS JSON`, …) return
/// `None` — caller falls back to `Expr::Opaque`.
fn project_unary_op_kind(op: crate::ir::scalar::UnaryOpKind) -> Option<UnaryOp> {
    use crate::ir::scalar::{IsPredicate, UnaryOpKind};
    match op {
        UnaryOpKind::Not => Some(UnaryOp::Not),
        UnaryOpKind::Neg => Some(UnaryOp::Negate),
        UnaryOpKind::Plus => Some(UnaryOp::Plus),
        UnaryOpKind::IsNull => Some(UnaryOp::IsNull),
        UnaryOpKind::IsNotNull => Some(UnaryOp::IsNotNull),
        UnaryOpKind::Is(IsPredicate::True) => Some(UnaryOp::IsTrue),
        UnaryOpKind::Is(IsPredicate::False) => Some(UnaryOp::IsFalse),
        UnaryOpKind::AtLocal
        | UnaryOpKind::Collate
        | UnaryOpKind::Prior
        | UnaryOpKind::Spread
        | UnaryOpKind::BitwiseNot
        | UnaryOpKind::SquareRoot
        | UnaryOpKind::AbsoluteValue
        | UnaryOpKind::Is(
            IsPredicate::JsonValue
            | IsPredicate::JsonArray
            | IsPredicate::JsonObject
            | IsPredicate::JsonScalar
            | IsPredicate::NfcNormalized
            | IsPredicate::NfdNormalized
            | IsPredicate::NfkcNormalized
            | IsPredicate::NfkdNormalized,
        )
        | UnaryOpKind::IsNot(
            IsPredicate::True
            | IsPredicate::False
            | IsPredicate::JsonValue
            | IsPredicate::JsonArray
            | IsPredicate::JsonObject
            | IsPredicate::JsonScalar
            | IsPredicate::NfcNormalized
            | IsPredicate::NfdNormalized
            | IsPredicate::NfkcNormalized
            | IsPredicate::NfkdNormalized,
        ) => None,
    }
}

/// Project an IR to the public
/// [`PublicComparisonOp`]. Closed-enum, total: every IR variant has a
/// public counterpart by design — these two enums are kept in lock-step.
fn project_comparison_op(op: crate::ir::scalar::ComparisonOp) -> PublicComparisonOp {
    use crate::ir::scalar::ComparisonOp;
    match op {
        ComparisonOp::Eq => PublicComparisonOp::Eq,
        ComparisonOp::NotEq => PublicComparisonOp::NotEq,
        ComparisonOp::Lt => PublicComparisonOp::Lt,
        ComparisonOp::LtEq => PublicComparisonOp::LtEq,
        ComparisonOp::Gt => PublicComparisonOp::Gt,
        ComparisonOp::GtEq => PublicComparisonOp::GtEq,
    }
}

/// The public [`SubqueryKind`] of a quantified comparison's subquery: the
/// in-subquery vs not-in-subquery distinction where the comparison is one
/// (`= ANY`, `NOT IN`, `<> ALL`), else a scalar subquery. The comparison's
/// published shape carries the full typed structure regardless.
fn quantified_subquery_kind(
    op: crate::ir::scalar::ComparisonOp,
    quantifier: crate::ir::scalar::Quantifier,
    negated: bool,
) -> SubqueryKind {
    use crate::ir::scalar::{ComparisonOp, Quantifier};
    match (op, quantifier, negated) {
        (ComparisonOp::Eq, Quantifier::Any, false) => SubqueryKind::InSubquery,
        (ComparisonOp::Eq, Quantifier::Any, true)
        | (ComparisonOp::NotEq, Quantifier::All, false) => SubqueryKind::NotInSubquery,
        (
            ComparisonOp::Eq
            | ComparisonOp::NotEq
            | ComparisonOp::Lt
            | ComparisonOp::LtEq
            | ComparisonOp::Gt
            | ComparisonOp::GtEq,
            Quantifier::Any | Quantifier::All,
            false | true,
        ) => SubqueryKind::Scalar,
    }
}

/// Project an IR to the public
/// [`PublicQuantifier`]. Closed-enum, total.
fn project_quantifier(q: crate::ir::scalar::Quantifier) -> PublicQuantifier {
    use crate::ir::scalar::Quantifier;
    match q {
        Quantifier::Any => PublicQuantifier::Any,
        Quantifier::All => PublicQuantifier::All,
    }
}

/// Canonical name string for a [`ResolvedFunc`]. Resolved calls
/// consult the function catalog for the registered display name;
/// unresolved calls surface the raw source spelling verbatim.
pub(crate) fn resolved_func_canonical_name(
    func: &ResolvedFunc,
    catalog: &crate::ir::FunctionCatalog,
) -> String {
    match func {
        ResolvedFunc::Resolved { id, .. } => catalog
            .signature(*id)
            .map(|s| s.display_name.clone())
            .unwrap_or_else(|| func.display_hint()),
        ResolvedFunc::Unresolved { raw_name, .. } => raw_name.clone(),
    }
}

/// Stable structural signature for a [`ScalarExpr`]. Renders the IR
/// expression tree as a deterministic ASCII string that ignores
/// [`Span`] information and uses raw
/// values for column references — two expressions that bind to the
/// same source column produce the same signature regardless of
/// their position in the SQL text. Closed-enum exhaustive.
///
/// `Q-WIN-MULTIPART`.
fn ir_scalar_signature(expr: &ScalarExpr) -> String {
    match expr {
        ScalarExpr::Column { column, .. } => format!("c{}", column.as_u32()),
        ScalarExpr::OuterRef { scope, column, .. } => {
            format!("o{}.{}", scope.0, column.as_u32())
        }
        ScalarExpr::Lit { value, .. } => {
            let mut s = String::from("l(");
            value.fingerprint_into(&mut s);
            s.push(')');
            s
        }
        ScalarExpr::BinOp {
            op, left, right, ..
        } => format!(
            "b({},{},{})",
            op,
            ir_scalar_signature(left),
            ir_scalar_signature(right)
        ),
        ScalarExpr::LogicalChain { op, operands, .. } => format!(
            "lc({},{})",
            op,
            operands
                .iter()
                .map(ir_scalar_signature)
                .collect::<Vec<_>>()
                .join(",")
        ),
        ScalarExpr::OperatorChain {
            operands,
            operators,
            ..
        } => {
            let mut s = String::from("oc(");
            for (k, operand) in operands.iter().enumerate() {
                if let Some(op) = k.checked_sub(1).and_then(|k| operators.get(k)) {
                    s.push_str(&format!(",{op},"));
                }
                s.push_str(&ir_scalar_signature(operand));
            }
            s.push(')');
            s
        }
        ScalarExpr::Like {
            kind,
            negated,
            expr,
            pattern,
            escape,
            ..
        } => format!(
            "like({},{},{},{},{})",
            kind,
            negated,
            ir_scalar_signature(expr),
            ir_scalar_signature(pattern),
            escape
                .as_deref()
                .map(ir_scalar_signature)
                .unwrap_or_default()
        ),
        ScalarExpr::UnaryOp { op, arg, .. } => {
            let mut s = String::from("u(");
            op.fingerprint_into(&mut s);
            s.push(',');
            s.push_str(&ir_scalar_signature(arg));
            s.push(')');
            s
        }
        ScalarExpr::FuncCall {
            func,
            args,
            named_args,
            distinct,
            non_values,
            span: _,
        } => {
            let func_name = match func {
                ResolvedFunc::Resolved { id, .. } => format!("r{}", id),
                ResolvedFunc::Unresolved { raw_name, .. } => format!("u({})", raw_name),
            };
            let args_sig = args
                .iter()
                .map(ir_scalar_signature)
                .collect::<Vec<_>>()
                .join(",");
            let named_sig = named_args
                .iter()
                .map(|(k, v)| format!("{}={}", k.as_str(), ir_scalar_signature(v)))
                .collect::<Vec<_>>()
                .join(",");
            let mut non_values_sig = String::new();
            for value in non_values {
                non_values_sig.push(';');
                value.fingerprint_into(&mut non_values_sig);
            }
            format!(
                "f({},{},{},{},{})",
                func_name, distinct, args_sig, named_sig, non_values_sig
            )
        }
        ScalarExpr::Case {
            operand,
            branches,
            else_,
            ..
        } => {
            let op_sig = operand
                .as_ref()
                .map(|o| ir_scalar_signature(o))
                .unwrap_or_default();
            let br_sig = branches
                .iter()
                .map(|(c, r)| format!("{}=>{}", ir_scalar_signature(c), ir_scalar_signature(r)))
                .collect::<Vec<_>>()
                .join(";");
            let else_sig = else_
                .as_ref()
                .map(|e| ir_scalar_signature(e))
                .unwrap_or_default();
            format!("ca({},{},{})", op_sig, br_sig, else_sig)
        }
        ScalarExpr::Cast {
            expr,
            target_type,
            try_cast,
            span: _,
        } => {
            let mut s = String::from("cs(");
            s.push_str(&ir_scalar_signature(expr));
            s.push(',');
            target_type.fingerprint_into(&mut s);
            s.push(',');
            s.push(if *try_cast { '1' } else { '0' });
            s.push(')');
            s
        }
        ScalarExpr::InList {
            expr,
            list,
            negated,
            ..
        } => format!(
            "il({},{},{})",
            ir_scalar_signature(expr),
            negated,
            list.iter()
                .map(ir_scalar_signature)
                .collect::<Vec<_>>()
                .join(",")
        ),
        ScalarExpr::Between {
            expr,
            low,
            high,
            negated,
            ..
        } => format!(
            "bt({},{},{},{})",
            ir_scalar_signature(expr),
            negated,
            ir_scalar_signature(low),
            ir_scalar_signature(high)
        ),
        ScalarExpr::Exists {
            correlates_with,
            negated,
            ..
        } => format!(
            "ex({},{:?})",
            negated,
            correlates_with
                .iter()
                .map(|c| c.as_u32())
                .collect::<Vec<_>>()
        ),
        ScalarExpr::ScalarSubquery {
            correlates_with, ..
        } => format!(
            "ss({:?})",
            correlates_with
                .iter()
                .map(|c| c.as_u32())
                .collect::<Vec<_>>()
        ),
        ScalarExpr::QuantifiedCmp {
            op,
            quantifier,
            negated,
            left,
            right,
            ..
        } => {
            let right_sig = match right {
                QuantifiedRhs::List(items) => format!(
                    "L({})",
                    items
                        .iter()
                        .map(ir_scalar_signature)
                        .collect::<Vec<_>>()
                        .join(",")
                ),
                QuantifiedRhs::Subquery(_, correlates_with) => format!(
                    "S({:?})",
                    correlates_with
                        .iter()
                        .map(|c| c.as_u32())
                        .collect::<Vec<_>>()
                ),
            };
            let mut s = String::from("q(");
            op.fingerprint_into(&mut s);
            s.push(',');
            quantifier.fingerprint_into(&mut s);
            s.push(',');
            s.push(if *negated { '1' } else { '0' });
            s.push(',');
            s.push_str(&ir_scalar_signature(left));
            s.push(',');
            s.push_str(&right_sig);
            s.push(')');
            s
        }
        ScalarExpr::RowCmp {
            op,
            quantifier,
            negated,
            left,
            correlates_with,
            ..
        } => {
            let mut s = String::from("rc(");
            op.fingerprint_into(&mut s);
            s.push(',');
            match quantifier {
                Some(quantifier) => quantifier.fingerprint_into(&mut s),
                None => s.push('-'),
            }
            s.push(',');
            s.push(if *negated { '1' } else { '0' });
            s.push_str(",[");
            for (i, element) in left.iter().enumerate() {
                if i > 0 {
                    s.push(',');
                }
                s.push_str(&ir_scalar_signature(element));
            }
            s.push_str("],");
            s.push_str(&format!(
                "S({:?})",
                correlates_with
                    .iter()
                    .map(|c| c.as_u32())
                    .collect::<Vec<_>>()
            ));
            s.push(')');
            s
        }
        ScalarExpr::WindowFn { call, .. } => {
            let func_name = match &call.func {
                ResolvedFunc::Resolved { id, .. } => format!("r{}", id),
                ResolvedFunc::Unresolved { raw_name, .. } => format!("u({})", raw_name),
            };
            format!("wf({})", func_name)
        }
        ScalarExpr::FieldAccess { base, path, .. } => {
            let mut s = String::from("fa(");
            s.push_str(&ir_scalar_signature(base));
            s.push_str(",[");
            for (i, step) in path.iter().enumerate() {
                if i > 0 {
                    s.push(',');
                }
                field_step_signature_into(step, &mut s);
            }
            s.push_str("])");
            s
        }
        ScalarExpr::Lambda { params, body, .. } => format!(
            "la({:?},{})",
            params.iter().map(|p| p.id.as_u32()).collect::<Vec<_>>(),
            ir_scalar_signature(body)
        ),
        ScalarExpr::PatternVarRef { symbol, column, .. } => {
            let mut s = String::from("pv(");
            symbol.fingerprint_into(&mut s);
            s.push(',');
            s.push_str(&column.as_u32().to_string());
            s.push(')');
            s
        }
        ScalarExpr::Opaque { reason, .. } => format!("op({})", reason),
    }
}

/// Stable signature for one [`FieldStep`]. `IndexExpr` recurses
/// through [`ir_scalar_signature`] so distinct dynamic-index
/// expressions stay distinguishable.
fn field_step_signature_into(step: &FieldStep, out: &mut String) {
    match step {
        FieldStep::Field(name) => {
            out.push_str("f:");
            out.push_str(name);
        }
        FieldStep::Index(i) => {
            out.push_str("i:");
            out.push_str(&i.to_string());
        }
        FieldStep::IndexExpr(expr) => {
            out.push_str("x:");
            out.push_str(&ir_scalar_signature(expr));
        }
    }
}

/// Resolved-function name → public `IdentName` via the catalog.
fn resolved_func_name(
    func: &ResolvedFunc,
    catalog: &crate::ir::FunctionCatalog,
) -> PublicIdentName {
    PublicIdentName::new(resolved_func_canonical_name(func, catalog))
}

/// The function `func` calls as a relation is named: each dotted part of
/// its name a part of the reference (`dbo.fn` is schema `dbo`, name `fn`).
fn resolved_func_table_ref(
    func: &ResolvedFunc,
    catalog: &crate::ir::FunctionCatalog,
    span: Span,
) -> PublicTableRef {
    let written = resolved_func_canonical_name(func, catalog);
    let parts = crate::ir::lower_ddl::split_qualified(&written);
    let mut qualifiers = parts.iter().rev();
    let name = qualifiers.next().map_or_else(
        || PublicIdentName::new(written.as_str()),
        |part| PublicIdentName::new(part.as_str()),
    );
    let schema = qualifiers
        .next()
        .map(|part| PublicIdentName::new(part.as_str()));
    let database = qualifiers
        .next()
        .map(|part| PublicIdentName::new(part.as_str()));
    let server = qualifiers
        .next()
        .map(|part| PublicIdentName::new(part.as_str()));
    PublicTableRef::new(name, schema, database, Some(span)).with_server(server)
}

/// Catalog-derived classification of a function call: `(is_temporal,
/// is_deterministic, is_aggregate, is_window)`. All `false` for an
/// unresolved call — there is no catalog entry to flag — matching the
/// `catalog_resolved = false` companion. Custom rules predicating on
/// these flags should pair them with `catalog_resolved: true`.
fn classify_resolved_func(
    func: &ResolvedFunc,
    catalog: &crate::ir::FunctionCatalog,
) -> (bool, bool, bool, bool) {
    match func {
        ResolvedFunc::Resolved { id, .. } => {
            let sig = catalog.signature(*id);
            let is_temporal = sig.map(|s| s.is_temporal).unwrap_or(false);
            let is_deterministic = sig
                .map(|s| {
                    matches!(
                        s.determinism,
                        crate::ir::catalog::Determinism::Deterministic
                    )
                })
                .unwrap_or(false);
            (
                is_temporal,
                is_deterministic,
                catalog.is_aggregate_shape(*id),
                catalog.is_window_shape(*id),
            )
        }
        ResolvedFunc::Unresolved { .. } => (false, false, false, false),
    }
}

/// Map an IR `Opaque.reason` string to the closed `OpaqueExprReason`
/// public enum. The IR reason is free-form text from
/// `crate::ir::strict::OpaqueReason::Display`; we classify by substring
/// match for the known buckets and fall to `UnparsedFragment` as the
/// catch-all (already designed for "preserved-but-not-typed" content).
fn classify_ir_opaque_reason(reason: &str) -> OpaqueExprReason {
    let lower = reason.to_ascii_lowercase();
    if lower.contains("jinja") || lower.contains("{{") {
        OpaqueExprReason::JinjaTemplate
    } else if lower.contains("procedural") || lower.contains("variable") {
        OpaqueExprReason::ProceduralReference
    } else if lower.contains("unresolved") {
        OpaqueExprReason::UnresolvedReference
    } else if lower.contains("dialect") {
        OpaqueExprReason::DialectSpecificFunction
    } else {
        OpaqueExprReason::UnparsedFragment
    }
}

/// Classify a top-level projection-item expression to a public
/// `ProjectionKind`. Aggregates and window-function calls take their
/// dedicated variants; everything else is `Expression` (with bare
/// column references collapsed to `Column`).
fn classify_projection_expr(expr: &ScalarExpr) -> ProjectionKind {
    match expr {
        ScalarExpr::Column { .. } | ScalarExpr::OuterRef { .. } => ProjectionKind::Column,
        ScalarExpr::WindowFn { .. } => ProjectionKind::Window,
        ScalarExpr::FuncCall { .. } => {
            // Without a catalog query we cannot reliably classify a
            // FuncCall as aggregate vs. scalar; default to Expression
            // and let downstream rules use the funcCall.is_aggregate
            // flag (deferred to catalog wiring) for finer matching.
            ProjectionKind::Expression
        }
        _ => ProjectionKind::Expression,
    }
}

/// Map a resolved function to its public `AggregateFunction` discriminator.
/// Catalog-aware classification (count, sum, avg, etc.) requires the
/// function catalog; without it we route through the raw name.
///
/// The `arg_count` argument lets the projection distinguish
/// `COUNT(*)` (lowers to zero positional args in the IR) from
/// `COUNT(expr)` (one arg). The public `AggregateFunction` enum has
/// dedicated `CountStar` and `Count` variants for exactly that
/// reason; without this discriminator the rule corpus cannot
/// predicate against pure-row-count shapes.
fn aggregate_function_for(
    func: &ResolvedFunc,
    distinct: bool,
    arg_count: usize,
    catalog: &crate::ir::FunctionCatalog,
) -> AggregateFunction {
    let name = resolved_func_canonical_name(func, catalog).to_ascii_uppercase();
    match (name.as_str(), distinct, arg_count) {
        ("COUNT", true, _) => AggregateFunction::CountDistinct,
        ("COUNT", false, 0) => AggregateFunction::CountStar,
        ("COUNT", false, _) => AggregateFunction::Count,
        ("SUM", _, _) => AggregateFunction::Sum,
        ("AVG", _, _) => AggregateFunction::Avg,
        ("MIN", _, _) => AggregateFunction::Min,
        ("MAX", _, _) => AggregateFunction::Max,
        ("STDDEV_POP" | "STDDEV", _, _) => AggregateFunction::StddevPop,
        ("STDDEV_SAMP", _, _) => AggregateFunction::StddevSamp,
        ("VAR_POP", _, _) => AggregateFunction::VarPop,
        ("VAR_SAMP" | "VARIANCE", _, _) => AggregateFunction::VarSamp,
        ("ARRAY_AGG", _, _) => AggregateFunction::ArrayAgg,
        ("STRING_AGG", _, _) => AggregateFunction::StringAgg,
        ("LISTAGG", _, _) => AggregateFunction::ListAgg,
        ("BOOL_AND" | "BOOLAND_AGG", _, _) => AggregateFunction::BoolAnd,
        ("BOOL_OR" | "BOOLOR_AGG", _, _) => AggregateFunction::BoolOr,
        ("JSON_AGG" | "JSON_ARRAYAGG", _, _) => AggregateFunction::JsonAgg,
        ("JSON_OBJECTAGG" | "JSON_OBJECT_AGG", _, _) => AggregateFunction::JsonObjectAgg,
        ("PERCENTILE_CONT", _, _) => AggregateFunction::PercentileCont,
        ("PERCENTILE_DISC", _, _) => AggregateFunction::PercentileDisc,
        ("MEDIAN", _, _) => AggregateFunction::Median,
        ("MODE", _, _) => AggregateFunction::Mode,
        ("BIT_AND" | "BITAND_AGG", _, _) => AggregateFunction::BitAnd,
        ("BIT_OR" | "BITOR_AGG", _, _) => AggregateFunction::BitOr,
        ("BIT_XOR" | "BITXOR_AGG", _, _) => AggregateFunction::BitXor,
        _ => AggregateFunction::Other(PublicIdentName::new(&name)),
    }
}

/// Map a resolved function to its public `WindowFunctionName`. Windowed
/// aggregates collapse into `Aggregate(...)`; named window functions
/// (ROW_NUMBER, RANK, …) get their dedicated variants.
fn window_function_for(
    func: &ResolvedFunc,
    arg_count: usize,
    catalog: &crate::ir::FunctionCatalog,
) -> WindowFunctionName {
    let name = resolved_func_canonical_name(func, catalog).to_ascii_uppercase();
    match name.as_str() {
        "ROW_NUMBER" => WindowFunctionName::RowNumber,
        "RANK" => WindowFunctionName::Rank,
        "DENSE_RANK" => WindowFunctionName::DenseRank,
        "PERCENT_RANK" => WindowFunctionName::PercentRank,
        "CUME_DIST" => WindowFunctionName::CumeDist,
        "NTILE" => WindowFunctionName::Ntile,
        "LAG" => WindowFunctionName::Lag,
        "LEAD" => WindowFunctionName::Lead,
        "FIRST_VALUE" => WindowFunctionName::FirstValue,
        "LAST_VALUE" => WindowFunctionName::LastValue,
        "NTH_VALUE" => WindowFunctionName::NthValue,
        // Aggregate-as-window: route through the aggregate
        // classification for COUNT / SUM / etc. to preserve typed
        // matching on the inner discriminator (including the
        // `CountStar` vs `Count` discriminator via `arg_count`).
        "COUNT" | "SUM" | "AVG" | "MIN" | "MAX" | "STDDEV_POP" | "STDDEV" | "STDDEV_SAMP"
        | "VAR_POP" | "VAR_SAMP" | "VARIANCE" | "ARRAY_AGG" | "STRING_AGG" | "LISTAGG"
        | "BOOL_AND" | "BOOLAND_AGG" | "BOOL_OR" | "BOOLOR_AGG" | "JSON_AGG" | "JSON_ARRAYAGG"
        | "JSON_OBJECTAGG" | "JSON_OBJECT_AGG" | "PERCENTILE_CONT" | "PERCENTILE_DISC"
        | "MEDIAN" | "MODE" | "BIT_AND" | "BIT_OR" | "BIT_XOR" | "BITAND_AGG" | "BITOR_AGG"
        | "BITXOR_AGG" => {
            WindowFunctionName::Aggregate(aggregate_function_for(func, false, arg_count, catalog))
        }
        _ => WindowFunctionName::Other(PublicIdentName::new(&name)),
    }
}

/// Heuristic: does an `ON` predicate contain a column-vs-literal
/// comparison (a "filter predicate" rather than a "table tie")?
fn predicate_filters_join(expr: &ScalarExpr) -> bool {
    match expr {
        ScalarExpr::BinOp {
            op, left, right, ..
        } => {
            let op_upper = op.as_sql_str();
            // AND-chains: descend; OR is not.
            if op_upper == "AND" {
                return predicate_filters_join(left) || predicate_filters_join(right);
            }
            // Comparison set: =, <>, <, <=, >, >=.
            let is_cmp = matches!(op_upper, "=" | "<>" | "<" | "<=" | ">" | ">=");
            if !is_cmp {
                return false;
            }
            let is_col = |e: &ScalarExpr| matches!(e, ScalarExpr::Column { .. });
            let is_lit = |e: &ScalarExpr| matches!(e, ScalarExpr::Lit { .. });
            (is_col(left) && is_lit(right)) || (is_lit(left) && is_col(right))
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Policy projection (CREATE / ALTER / DROP <policy-kind> POLICY).
// ---------------------------------------------------------------------------

/// Build a public `StatementFacts` directly from a lowered
/// [`PolicyPlan`].
/// catalog is not consulted; the typed plan carries everything the
/// public schema needs.
///
/// `origin` carries the dialect of origin (built at the
/// `analyze_ddl_facts` dispatch site from the originating `AstStmt`
/// variant — see [`PolicyDialectOrigin`]). Only used by row-access
/// policy projection, where PG and Snowflake / BigQuery share the same
/// `PolicyKindIr::RowAccess` but map to different `StatementKind`s.
pub fn derive_facts_from_policy_plan(
    plan: &PolicyPlan,
    origin: PolicyDialectOrigin,
    source: &str,
) -> StatementFacts {
    let kind = match origin {
        PolicyDialectOrigin::Postgres => match plan.action {
            PolicyAction::Create => StatementKind::PgCreatePolicy,
            PolicyAction::Alter => StatementKind::PgAlterPolicy,
            PolicyAction::Drop => StatementKind::PgDropPolicy,
        },
        PolicyDialectOrigin::Standard => policy_statement_kind(plan.policy_kind, plan.action),
    };
    let cascade = match &plan.variant {
        PolicyPlanVariant::DropOnly { cascade, .. } => *cascade,
        PolicyPlanVariant::Password(_)
        | PolicyPlanVariant::Session(_)
        | PolicyPlanVariant::Network(_)
        | PolicyPlanVariant::Authentication(_)
        | PolicyPlanVariant::Aggregation(_)
        | PolicyPlanVariant::Projection(_)
        | PolicyPlanVariant::JoinPolicy(_)
        | PolicyPlanVariant::Masking(_)
        | PolicyPlanVariant::RowAccess(_) => false,
    };
    let policy = project_policy_facts(plan, source);
    let ddl = DdlFacts {
        targets: Vec::new(),
        action: match plan.action {
            PolicyAction::Create => DdlAction::Create,
            PolicyAction::Alter => DdlAction::Alter,
            PolicyAction::Drop => DdlAction::Drop,
        },
        object_kind: policy_kind_to_object_kind(plan.policy_kind),
        target: Some(policy_target(plan, source)),
        options: DdlOptions {
            or_replace: plan.or_replace,
            if_not_exists: plan.if_not_exists,
            if_exists: plan.if_exists,
            cascade,
            ..DdlOptions::default()
        },
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: None,
        database: None,
        warehouse: None,
        stream: None,
        schema: None,
        function: None,
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: None,
        session: None,
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: None,
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: Some(policy),
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        integration: None,
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        diff: None,
    }
}

fn policy_statement_kind(kind: PolicyKindIr, action: PolicyAction) -> StatementKind {
    use PolicyKindIr as K;
    match (kind, action) {
        (K::Masking, PolicyAction::Create) => StatementKind::CreateMaskingPolicy,
        (K::Masking, PolicyAction::Alter) => StatementKind::AlterMaskingPolicy,
        (K::Masking, PolicyAction::Drop) => StatementKind::DropMaskingPolicy,
        (K::RowAccess, PolicyAction::Create) => StatementKind::CreateRowAccessPolicy,
        (K::RowAccess, PolicyAction::Alter) => StatementKind::AlterRowAccessPolicy,
        (K::RowAccess, PolicyAction::Drop) => StatementKind::DropRowAccessPolicy,
        (K::Network, PolicyAction::Create) => StatementKind::CreateNetworkPolicy,
        (K::Network, PolicyAction::Alter) => StatementKind::AlterNetworkPolicy,
        (K::Network, PolicyAction::Drop) => StatementKind::DropNetworkPolicy,
        (K::Session, PolicyAction::Create) => StatementKind::CreateSessionPolicy,
        (K::Session, PolicyAction::Alter) => StatementKind::AlterSessionPolicy,
        (K::Session, PolicyAction::Drop) => StatementKind::DropSessionPolicy,
        (K::Password, PolicyAction::Create) => StatementKind::CreatePasswordPolicy,
        (K::Password, PolicyAction::Alter) => StatementKind::AlterPasswordPolicy,
        (K::Password, PolicyAction::Drop) => StatementKind::DropPasswordPolicy,
        (K::Aggregation, PolicyAction::Create) => StatementKind::CreateAggregationPolicy,
        (K::Aggregation, PolicyAction::Alter) => StatementKind::AlterAggregationPolicy,
        (K::Aggregation, PolicyAction::Drop) => StatementKind::DropAggregationPolicy,
        (K::Projection, PolicyAction::Create) => StatementKind::CreateProjectionPolicy,
        (K::Projection, PolicyAction::Alter) => StatementKind::AlterProjectionPolicy,
        (K::Projection, PolicyAction::Drop) => StatementKind::DropProjectionPolicy,
        (K::JoinPolicy, PolicyAction::Create) => StatementKind::CreateJoinPolicy,
        (K::JoinPolicy, PolicyAction::Alter) => StatementKind::AlterJoinPolicy,
        (K::JoinPolicy, PolicyAction::Drop) => StatementKind::DropJoinPolicy,
        (K::Authentication, PolicyAction::Create) => StatementKind::CreateAuthenticationPolicy,
        (K::Authentication, PolicyAction::Alter) => StatementKind::AlterAuthenticationPolicy,
        (K::Authentication, PolicyAction::Drop) => StatementKind::DropAuthenticationPolicy,
    }
}

fn policy_kind_to_object_kind(kind: PolicyKindIr) -> ObjectKind {
    match kind {
        PolicyKindIr::Masking => ObjectKind::MaskingPolicy,
        PolicyKindIr::RowAccess => ObjectKind::RowAccessPolicy,
        PolicyKindIr::Network => ObjectKind::NetworkPolicy,
        PolicyKindIr::Session => ObjectKind::SessionPolicy,
        PolicyKindIr::Password => ObjectKind::PasswordPolicy,
        PolicyKindIr::Aggregation => ObjectKind::AggregationPolicy,
        PolicyKindIr::Projection => ObjectKind::ProjectionPolicy,
        PolicyKindIr::JoinPolicy => ObjectKind::JoinPolicy,
        PolicyKindIr::Authentication => ObjectKind::AuthenticationPolicy,
    }
}

fn ir_policy_kind_to_facts(kind: PolicyKindIr) -> PolicyKind {
    match kind {
        PolicyKindIr::Masking => PolicyKind::Masking,
        PolicyKindIr::RowAccess => PolicyKind::RowAccess,
        PolicyKindIr::Network => PolicyKind::Network,
        PolicyKindIr::Session => PolicyKind::Session,
        PolicyKindIr::Password => PolicyKind::Password,
        PolicyKindIr::Aggregation => PolicyKind::Aggregation,
        PolicyKindIr::Projection => PolicyKind::Projection,
        PolicyKindIr::JoinPolicy => PolicyKind::JoinPolicy,
        PolicyKindIr::Authentication => PolicyKind::Authentication,
    }
}

fn policy_target(plan: &PolicyPlan, source: &str) -> ObjectRef {
    ObjectRef {
        kind: policy_kind_to_object_kind(plan.policy_kind),
        name: parse_table_ref(plan.policy_name_span, source),
    }
}

fn project_policy_facts(plan: &PolicyPlan, source: &str) -> PolicyFacts {
    let action = match plan.action {
        PolicyAction::Create => DdlAction::Create,
        PolicyAction::Alter => DdlAction::Alter,
        PolicyAction::Drop => DdlAction::Drop,
    };
    let renamed_to = plan
        .renamed_to_span
        .map(|sp| IdentName::new(slice_span_text(source, sp).trim()).written_at(sp));
    let set_tags = plan
        .set_tag_action_spans
        .iter()
        .flat_map(|sp| parse_tag_assignments(*sp, source))
        .collect();
    let unset_tags = plan
        .unset_tag_action_spans
        .iter()
        .flat_map(|sp| parse_tag_keys(*sp, source))
        .collect();
    let comment = match &plan.comment {
        PolicyCommentAction::Unchanged => PolicyCommentChange::Unchanged,
        PolicyCommentAction::Set { value_span } => {
            // Best-effort: if the value isn't a quoted string literal,
            // fall back to the trimmed raw text rather than dropping the
            // value — rules predicate on `kind: set` regardless.
            let text = crate::ir::policy_plan::comment_text_from_value_span(*value_span, source)
                .unwrap_or_else(|| slice_span_text(source, *value_span).trim().to_string());
            PolicyCommentChange::Set { text }
        }
        PolicyCommentAction::Unset => PolicyCommentChange::Unset,
    };
    let variant = project_policy_variant(plan, source);

    PolicyFacts {
        kind: ir_policy_kind_to_facts(plan.policy_kind),
        action,
        target: policy_target(plan, source),
        body_semantics: PolicyBodySemantics::Opaque {
            reason: super::policy::PolicyBodyOpaqueReason::UnparsedExpression,
        },
        variant,
        renamed_to,
        set_tags,
        unset_tags,
        comment,
    }
}

fn project_policy_variant(plan: &PolicyPlan, source: &str) -> PolicyVariantFacts {
    match &plan.variant {
        PolicyPlanVariant::Password(shape) => {
            PolicyVariantFacts::Password(project_password_shape(shape))
        }
        PolicyPlanVariant::Session(shape) => {
            PolicyVariantFacts::Session(project_session_shape(shape))
        }
        PolicyPlanVariant::Network(shape) => {
            PolicyVariantFacts::Network(project_network_shape(shape, source))
        }
        PolicyPlanVariant::Authentication(shape) => {
            PolicyVariantFacts::Authentication(project_auth_shape(shape, source))
        }
        PolicyPlanVariant::Aggregation(shape) => {
            PolicyVariantFacts::Aggregation(project_aggregation_shape(shape))
        }
        PolicyPlanVariant::Projection(shape) => {
            PolicyVariantFacts::Projection(project_projection_shape(shape))
        }
        PolicyPlanVariant::JoinPolicy(shape) => {
            PolicyVariantFacts::JoinPolicy(project_join_shape(shape))
        }
        PolicyPlanVariant::Masking(shape) => {
            PolicyVariantFacts::Masking(project_masking_shape(shape, source))
        }
        PolicyPlanVariant::RowAccess(shape) => {
            PolicyVariantFacts::RowAccess(project_row_access_shape(shape, source, plan.node_id))
        }
        // DROP statements have no per-kind body. Project to the empty
        // facts for the corresponding kind; the kind comes from
        // `plan.policy_kind` since `DropOnly` carries no payload.
        PolicyPlanVariant::DropOnly { .. } => match plan.policy_kind {
            PolicyKindIr::Password => PolicyVariantFacts::Password(PasswordPolicyFacts::default()),
            PolicyKindIr::Session => PolicyVariantFacts::Session(SessionPolicyFacts::default()),
            PolicyKindIr::Network => PolicyVariantFacts::Network(NetworkPolicyFacts::default()),
            PolicyKindIr::Authentication => {
                PolicyVariantFacts::Authentication(AuthenticationPolicyFacts::default())
            }
            PolicyKindIr::Aggregation => {
                PolicyVariantFacts::Aggregation(AggregationPolicyFacts::default())
            }
            PolicyKindIr::Projection => {
                PolicyVariantFacts::Projection(ProjectionPolicyFacts::default())
            }
            PolicyKindIr::JoinPolicy => PolicyVariantFacts::JoinPolicy(JoinPolicyFacts::default()),
            PolicyKindIr::Masking => PolicyVariantFacts::Masking(MaskingPolicyFacts::default()),
            PolicyKindIr::RowAccess => {
                PolicyVariantFacts::RowAccess(RowAccessPolicyFacts::default())
            }
        },
    }
}

fn project_aggregation_shape(s: &AggregationPolicyShape) -> AggregationPolicyFacts {
    AggregationPolicyFacts {
        arguments: Vec::new(),
        min_group_size: s.min_group_size,
        has_no_aggregation_constraint: s.has_no_aggregation_constraint,
        has_conditional_body: s.has_conditional_body,
        had_body_change: s.had_body_change,
    }
}

fn project_projection_shape(s: &ProjectionPolicyShape) -> ProjectionPolicyFacts {
    ProjectionPolicyFacts {
        arguments: Vec::new(),
        has_allow_list: s.has_allow_list,
        has_enforcement_disabled: s.has_enforcement_disabled,
        has_enforcement_enabled: s.has_enforcement_enabled,
        has_conditional_body: s.has_conditional_body,
        had_body_change: s.had_body_change,
    }
}

fn project_join_shape(s: &crate::ir::JoinPolicyShape) -> JoinPolicyFacts {
    JoinPolicyFacts {
        has_join_required: s.has_join_required,
        has_join_not_required: s.has_join_not_required,
        has_conditional_body: s.has_conditional_body,
        had_body_change: s.had_body_change,
    }
}

fn project_masking_shape(s: &MaskingPolicyShape, source: &str) -> MaskingPolicyFacts {
    let arguments: Vec<crate::facts::policy::PolicyArgument> = s
        .arguments
        .iter()
        .map(|a| crate::facts::policy::PolicyArgument {
            name: IdentName::new(slice_span_text(source, a.name_span).trim())
                .written_at(a.name_span),
            data_type: ast_type_text_to_data_type(slice_span_text(source, a.type_span)),
        })
        .collect();
    let arg_names: Vec<IdentName> = arguments.iter().map(|a| a.name.clone()).collect();
    let body = s
        .body
        .as_ref()
        .map(|b| project_policy_body_expr(b, source, &arg_names));
    let body_terminal_returns = body
        .as_ref()
        .map(project_terminal_returns)
        .unwrap_or_default();
    let arg_count = arguments.len() as u32;
    let body_terminal_flows = body_terminal_returns
        .iter()
        .map(|t| classify_mask_terminal_flow(t, arg_count))
        .collect();
    MaskingPolicyFacts {
        arguments,
        exempt_other_policies: s.exempt_other_policies,
        body,
        body_terminal_returns,
        body_terminal_flows,
        ..MaskingPolicyFacts::default()
    }
}

/// Classify a masking-body terminal return by its information flow from the
/// policy's input arguments: `Identity { arg_position }` when the return is
/// provably that argument's value unchanged, else `Altered`. RECOGNITION
/// only — the no-op-masking verdict stays in YAML (`MASK-ALLOW-ALL`).
fn classify_mask_terminal_flow(expr: &Expr, arg_count: u32) -> MaskTerminalFlow {
    for position in 0..arg_count {
        if expr_is_identity_on(expr, position) {
            return MaskTerminalFlow::Identity {
                arg_position: position,
            };
        }
    }
    MaskTerminalFlow::Altered
}

/// `true` iff `expr` provably evaluates, for ALL inputs, to the value of the
/// proc-argument at `position` unchanged. Recurses through information-
/// preserving shapes so it composes (`SUBSTR(val || '', 1, LENGTH(val))`
/// resolves to identity). Conservative: any shape not provably an identity
/// (a hash, a partial slice, a constant) is not identity.
fn expr_is_identity_on(expr: &Expr, position: u32) -> bool {
    if let Expr::Parameter { parameter } = expr {
        return parameter.kind == ParameterKind::ProcArg && parameter.position == Some(position);
    }
    // A cast strips for the purposes of "what value flows" (mirrors the
    // cast see-through already applied when collecting terminal returns).
    if let Expr::Cast { cast } = expr {
        return expr_is_identity_on(&cast.expr, position);
    }
    // `x || ''` / `'' || x`: concat with an empty-string literal yields x.
    if let Expr::BinaryOp { binary_op } = expr {
        if binary_op.op == BinaryOp::Concat {
            return (is_empty_string_literal(&binary_op.right)
                && expr_is_identity_on(&binary_op.left, position))
                || (is_empty_string_literal(&binary_op.left)
                    && expr_is_identity_on(&binary_op.right, position));
        }
        return false;
    }
    if let Expr::FuncCall { func_call } = expr {
        return func_is_identity_on(func_call, position);
    }
    false
}

/// Identity recognition for the function-call wrappers a no-op mask reaches
/// for. Names matched case-insensitively (the normalized form folds
/// per-dialect).
fn func_is_identity_on(fc: &FuncCallExpr, position: u32) -> bool {
    let fname = |n: &str| fc.name.normalized.eq_ignore_ascii_case(n);

    // CONCAT(…): identity iff exactly one argument is identity-on-position
    // and every other argument is an empty-string literal.
    if fname("concat") {
        let mut saw_identity = false;
        for a in &fc.args {
            if is_empty_string_literal(a) {
                continue;
            }
            if !saw_identity && expr_is_identity_on(a, position) {
                saw_identity = true;
            } else {
                return false;
            }
        }
        return saw_identity;
    }

    // COALESCE/NVL/IFNULL/ISNULL(…): identity iff every argument is identity
    // on the same position — the result is that input regardless of NULLs.
    if fname("coalesce") || fname("nvl") || fname("ifnull") || fname("isnull") {
        return !fc.args.is_empty() && fc.args.iter().all(|a| expr_is_identity_on(a, position));
    }

    // SUBSTR/SUBSTRING(x, 1) / SUBSTR(x, 1, LENGTH(x)): a full-length slice
    // from position 1 returns x unchanged.
    if fname("substr") || fname("substring") {
        let Some(arg0) = fc.args.first() else {
            return false;
        };
        if !expr_is_identity_on(arg0, position) {
            return false;
        }
        if !matches!(fc.args.get(1), Some(e) if is_integer_literal(e, 1)) {
            return false;
        }
        return match fc.args.len() {
            2 => true,
            3 => is_full_length_of(&fc.args[2], position),
            _ => false,
        };
    }

    false
}

/// `true` iff `expr` is a length builtin (`LENGTH`/`LEN`/`CHAR_LENGTH`/
/// `CHARACTER_LENGTH`/`DATALENGTH`) over a single argument that is itself
/// identity-on-`position` — i.e. it computes the full length of that input.
fn is_full_length_of(expr: &Expr, position: u32) -> bool {
    let Expr::FuncCall { func_call } = expr else {
        return false;
    };
    let is_len_builtin = [
        "length",
        "len",
        "char_length",
        "character_length",
        "datalength",
    ]
    .iter()
    .any(|f| func_call.name.normalized.eq_ignore_ascii_case(f));
    is_len_builtin && func_call.args.len() == 1 && expr_is_identity_on(&func_call.args[0], position)
}

/// `true` iff `expr` is the literal empty string `''`.
fn is_empty_string_literal(expr: &Expr) -> bool {
    matches!(
        expr,
        Expr::Literal {
            literal: LiteralValue::String { value },
            ..
        } if value.is_empty()
    )
}

/// `true` iff `expr` is the integer literal `n`.
fn is_integer_literal(expr: &Expr, n: i64) -> bool {
    matches!(
        expr,
        Expr::Literal {
            literal: LiteralValue::Integer { value },
            ..
        } if *value == n
    )
}

fn project_row_access_shape(
    s: &RowAccessPolicyShape,
    source: &str,
    node_id: crate::ast::NodeId,
) -> RowAccessPolicyFacts {
    let arguments: Vec<crate::facts::policy::PolicyArgument> = s
        .arguments
        .iter()
        .map(|a| crate::facts::policy::PolicyArgument {
            name: IdentName::new(slice_span_text(source, a.name_span).trim())
                .written_at(a.name_span),
            data_type: ast_type_text_to_data_type(slice_span_text(source, a.type_span)),
        })
        .collect();
    let arg_names: Vec<IdentName> = arguments.iter().map(|a| a.name.clone()).collect();
    // Structural projection of the policy body. The body is lowered
    // through the IR predicate algebra; any sub-expression the IR
    // proves equivalent to a boolean literal surfaces as
    // `Expr::Literal(Bool { value })` so rules that compose over
    // `body_terminal_returns` see the same structural primitive
    // regardless of whether the SQL spelled the constant directly
    // (`-> TRUE`) or through a foldable predicate (`USING (1 = 1)`,
    // `CASE WHEN … THEN TRUE ELSE TRUE END`, etc.). The IR does the
    // folding; the projection surfaces the folded shape.
    let body = s
        .body
        .as_ref()
        .map(|b| project_policy_body_with_constant_fold(b, source, &arg_names, node_id));
    let body_terminal_returns = body
        .as_ref()
        .map(project_terminal_returns)
        .unwrap_or_default();
    let using_predicate = s
        .using
        .as_ref()
        .map(|e| project_pg_policy_predicate(e, source, node_id));
    let check_predicate = s
        .check
        .as_ref()
        .map(|e| project_pg_policy_predicate(e, source, node_id));
    let permissiveness = s.permissiveness.map(project_pg_permissiveness_to_facts);
    let command = s.command.map(project_pg_command_to_facts);
    let applies_to = s
        .roles
        .iter()
        .filter_map(|span| source.get(span.start as usize..span.end as usize))
        .map(IdentName::new)
        .collect();
    RowAccessPolicyFacts {
        arguments,
        body,
        body_terminal_returns,
        using_predicate,
        check_predicate,
        permissiveness,
        command,
        applies_to,
        ..RowAccessPolicyFacts::default()
    }
}

fn project_pg_policy_predicate(
    expr: &AstExpr,
    source: &str,
    node_id: crate::ast::NodeId,
) -> PolicyPredicate {
    // Constant-fold the predicate so any sub-expression the IR proves
    // always-true (boolean literal, `1=1`, `AND` / `OR` / `CASE` of
    // tautologies, etc.) surfaces as `Expr::Literal(Bool { value:
    // true })`. PG-RLS-WEAK-CHECK and any future sibling rule compose
    // their verdict from `body_terminal_returns` against the same
    // structural primitive, regardless of how the SQL spelled the
    // tautology.
    let body = project_policy_body_with_constant_fold(expr, source, &[], node_id);
    let body_terminal_returns = project_terminal_returns(&body);
    PolicyPredicate {
        body,
        // `body_semantics` is retained for schema compatibility but
        // every rule consuming it has migrated to compose against
        // `body_terminal_returns`. Set to `Opaque` until the field
        // can be removed in a coordinated schema-version bump.
        body_semantics: PolicyBodySemantics::Opaque {
            reason: super::policy::PolicyBodyOpaqueReason::UnparsedExpression,
        },
        body_terminal_returns,
    }
}

fn project_pg_permissiveness_to_facts(
    p: PgPolicyPermissivenessIr,
) -> crate::facts::policy::PgPolicyPermissiveness {
    use crate::facts::policy::PgPolicyPermissiveness as P;
    match p {
        PgPolicyPermissivenessIr::Permissive => P::Permissive,
        PgPolicyPermissivenessIr::Restrictive => P::Restrictive,
    }
}

fn project_pg_command_to_facts(c: PgPolicyCommandIr) -> crate::facts::policy::PgPolicyCommand {
    use crate::facts::policy::PgPolicyCommand as C;
    match c {
        PgPolicyCommandIr::All => C::All,
        PgPolicyCommandIr::Select => C::Select,
        PgPolicyCommandIr::Insert => C::Insert,
        PgPolicyCommandIr::Update => C::Update,
        PgPolicyCommandIr::Delete => C::Delete,
    }
}

/// Convert a raw SQL type span (`STRING`, `NUMBER(10, 2)`, …) into a
/// minimal public [`super::literal::DataType`]. Today the facts pipeline
/// only carries the raw spelling and `DataTypeKind::Other(<name>)`; the
/// rule corpus matches on `data_type.raw: { matches: … }` when finer
/// distinctions are needed. Full structured type parsing remains a
/// future extension.
fn ast_type_text_to_data_type(raw: &str) -> super::literal::DataType {
    let trimmed = raw.trim();
    super::literal::DataType {
        kind: super::literal::DataTypeKind::Other(IdentName::new(trimmed)),
        precision: None,
        scale: None,
        length: None,
        element_type: None,
        key_type: None,
        fields: Vec::new(),
        timezone: None,
        raw: trimmed.to_string(),
    }
}

/// Project a parsed [`AstExpr`] (a CREATE / ALTER MASKING POLICY body
/// expression) into the public structural [`Expr`] tree.
///
/// `arguments` is the policy's argument-name list in source order
/// (CREATE only; empty for ALTER). Identifier references with no
/// qualifier whose normalized name matches one of `arguments` are
/// projected to `Expr::Parameter { kind: ProcArg, position, name }`;
/// all other unqualified identifiers project to `Expr::Column`.
///
/// AST variants without a structural public counterpart fold to
/// `Expr::Opaque { reason }` — the
/// projection never invents a public shape for an IR-internal concept.
/// Project a policy-body [`AstExpr`] and constant-fold each
/// sub-expression that the IR proves always-true into
/// `Expr::Literal(Bool { value: true })`. The fold is performed at
/// every recursion level so a `CASE WHEN x THEN (1 = 1) ELSE TRUE END`
/// surfaces as a CASE whose THEN arm is `Literal(true)`, and the same
/// CASE — when the IR proves the whole expression always-true —
/// surfaces as a single `Literal(true)`. Other sub-expressions retain
/// their structural shape produced by [`project_policy_body_expr`].
///
/// Folding sits at the projection boundary, which is the engine's
/// single source-of-truth seam for "what does the IR know about this
/// AST." The output is a structural noun (a literal) — not a verdict.
/// Rules predicating `body_terminal_returns: all: { kind: literal,
/// literal.kind: bool, literal.value: true }` compose the
/// allow-all verdict against the same primitive a hand-written
/// `-> TRUE` body produces.
fn project_policy_body_with_constant_fold(
    expr: &AstExpr,
    source: &str,
    arguments: &[IdentName],
    node_id: crate::ast::NodeId,
) -> Expr {
    if crate::ir::always_true::policy_body_is_always_true(expr, source, node_id, &[]) {
        return Expr::Literal {
            literal: super::literal::LiteralValue::Bool { value: true },
            origin: TextOrigin::default(),
        };
    }
    // Recurse into structural sub-expressions so nested foldable
    // shapes also reduce — e.g. a CASE WHEN whose individual arm is
    // `(1 = 1)` even when the outer CASE isn't always-true.
    use crate::ast::AstExpr as A;
    let recur = |e: &AstExpr| project_policy_body_with_constant_fold(e, source, arguments, node_id);
    match expr {
        A::Parenthesized { expr: inner, .. } => recur(inner),
        A::Case {
            operand,
            whens,
            else_expr,
            ..
        } => {
            let operand_proj = operand.as_ref().map(|o| Box::new(recur(o.as_ref())));
            let branches = whens
                .iter()
                .map(|w| super::expr::CaseBranch {
                    condition: recur(&w.cond),
                    result: recur(&w.result),
                })
                .collect();
            let else_branch = else_expr.as_ref().map(|e| Box::new(recur(e.as_ref())));
            Expr::Case {
                case: super::expr::CaseExpr {
                    operand: operand_proj,
                    branches,
                    else_branch,
                },
            }
        }
        _ => project_policy_body_expr(expr, source, arguments),
    }
}

fn project_policy_body_expr(expr: &AstExpr, source: &str, arguments: &[IdentName]) -> Expr {
    use AstExpr as A;
    let recur = |e: &AstExpr| project_policy_body_expr(e, source, arguments);
    let opaque_for = |span: Span, reason: OpaqueExprReason| Expr::Opaque {
        opaque: OpaqueExpr {
            reason,
            rendered: slice_span_text(source, span).to_string(),
            origin: TextOrigin::at(span),
        },
    };

    match expr {
        // Parens are precedence-only — transparent in the public tree.
        A::Parenthesized { expr, .. } => recur(expr),

        A::Ident { column_ref, .. } => {
            let raw = slice_span_text(source, column_ref.name.span).trim();
            let ident = IdentName::new(raw);
            if column_ref.qualifier.is_none() {
                if let Some(pos) = arguments
                    .iter()
                    .position(|a| a.normalized == ident.normalized)
                {
                    return Expr::Parameter {
                        parameter: ParameterRef {
                            name: Some(ident),
                            position: Some(pos as u32),
                            kind: ParameterKind::ProcArg,
                        },
                    };
                }
            }
            Expr::Column {
                column: ColumnRef::minimal(ident, None),
            }
        }

        A::Literal { literal, .. } => Expr::Literal {
            literal: project_ast_literal_value(literal, source),
            origin: TextOrigin::at(expr.span()),
        },

        A::Case {
            whens,
            else_expr,
            operand,
            ..
        } => {
            let projected_operand = operand.as_ref().map(|o| Box::new(recur(o)));
            let branches = whens
                .iter()
                .map(|w| CaseBranch {
                    condition: recur(&w.cond),
                    result: recur(&w.result),
                })
                .collect();
            let else_branch = else_expr.as_ref().map(|e| Box::new(recur(e)));
            Expr::Case {
                case: CaseExpr {
                    operand: projected_operand,
                    branches,
                    else_branch,
                },
            }
        }

        A::BinaryOp {
            left,
            operator,
            right,
            span,
            ..
        } => match project_ast_binary_op(*operator) {
            Some(op) => Expr::BinaryOp {
                binary_op: BinaryOpExpr {
                    op,
                    left: Box::new(recur(left)),
                    right: Box::new(recur(right)),
                },
            },
            None => opaque_for(*span, OpaqueExprReason::DialectSpecificFunction),
        },

        A::OperatorChain {
            operands,
            operators,
            span,
            ..
        } => match operators
            .iter()
            .map(|operator| project_ast_binary_op(operator.operator))
            .collect::<Option<Vec<_>>>()
        {
            Some(operators) => Expr::OperatorChain {
                operator_chain: crate::facts::expr::OperatorChainExpr {
                    operands: operands.iter().map(|o| recur(o)).collect(),
                    operators,
                },
            },
            None => opaque_for(*span, OpaqueExprReason::DialectSpecificFunction),
        },

        A::LogicalChain {
            operator, operands, ..
        } => Expr::LogicalChain {
            logical_chain: crate::facts::expr::LogicalChainExpr {
                op: match operator {
                    LogicalChainOperator::And => crate::facts::expr::LogicalChainOp::And,
                    LogicalChainOperator::Or => crate::facts::expr::LogicalChainOp::Or,
                },
                operands: operands.iter().map(|o| recur(o)).collect(),
            },
        },

        A::IsNull { expr, not_span, .. } => Expr::UnaryOp {
            unary_op: UnaryOpExpr {
                op: if not_span.is_some() {
                    UnaryOp::IsNotNull
                } else {
                    UnaryOp::IsNull
                },
                operand: Box::new(recur(expr)),
            },
        },

        A::IsPredicate {
            expr,
            not_span,
            predicate,
            span,
            ..
        } => {
            let published = match predicate {
                AstIsPredicate::True => Some(UnaryOp::IsTrue),
                AstIsPredicate::False => Some(UnaryOp::IsFalse),
                AstIsPredicate::JsonValue
                | AstIsPredicate::JsonArray
                | AstIsPredicate::JsonObject
                | AstIsPredicate::JsonScalar
                | AstIsPredicate::NfcNormalized
                | AstIsPredicate::NfdNormalized
                | AstIsPredicate::NfkcNormalized
                | AstIsPredicate::NfkdNormalized => None,
            };
            match published.filter(|_| not_span.is_none()) {
                Some(op) => Expr::UnaryOp {
                    unary_op: UnaryOpExpr {
                        op,
                        operand: Box::new(recur(expr)),
                    },
                },
                None => opaque_for(*span, OpaqueExprReason::DialectSpecificFunction),
            }
        }

        A::IsDistinctFrom {
            left,
            right,
            not_span,
            ..
        } => Expr::BinaryOp {
            binary_op: BinaryOpExpr {
                op: if not_span.is_some() {
                    BinaryOp::IsNotDistinctFrom
                } else {
                    BinaryOp::IsDistinctFrom
                },
                left: Box::new(recur(left)),
                right: Box::new(recur(right)),
            },
        },

        A::Like {
            expr,
            not_span,
            like_kind_span,
            pattern,
            ..
        } => {
            let kind_text = slice_span_text(source, *like_kind_span).trim();
            let negated = not_span.is_some();
            let op = if kind_text.eq_ignore_ascii_case("LIKE") {
                if negated {
                    BinaryOp::NotLike
                } else {
                    BinaryOp::Like
                }
            } else if kind_text.eq_ignore_ascii_case("ILIKE") {
                if negated {
                    BinaryOp::NotILike
                } else {
                    BinaryOp::ILike
                }
            } else {
                // RLIKE / REGEXP / dialect-specific spellings.
                BinaryOp::Other(IdentName::new(kind_text))
            };
            Expr::BinaryOp {
                binary_op: BinaryOpExpr {
                    op,
                    left: Box::new(recur(expr)),
                    right: Box::new(recur(pattern)),
                },
            }
        }

        A::SimilarTo {
            expr,
            not_span,
            pattern,
            ..
        } => Expr::BinaryOp {
            binary_op: BinaryOpExpr {
                op: if not_span.is_some() {
                    BinaryOp::NotSimilar
                } else {
                    BinaryOp::Similar
                },
                left: Box::new(recur(expr)),
                right: Box::new(recur(pattern)),
            },
        },

        A::Between {
            expr,
            lower,
            upper,
            negated,
            ..
        } => {
            // Mirror project_scalar_expr's lowering: BETWEEN → AND of
            // Gte/Lte; NOT BETWEEN wraps the chained AND in UnaryOp Not.
            let projected = recur(expr);
            let lower_p = recur(lower);
            let upper_p = recur(upper);
            let lo = Expr::BinaryOp {
                binary_op: BinaryOpExpr {
                    op: BinaryOp::Gte,
                    left: Box::new(projected.clone()),
                    right: Box::new(lower_p),
                },
            };
            let hi = Expr::BinaryOp {
                binary_op: BinaryOpExpr {
                    op: BinaryOp::Lte,
                    left: Box::new(projected),
                    right: Box::new(upper_p),
                },
            };
            let chain = Expr::BinaryOp {
                binary_op: BinaryOpExpr {
                    op: BinaryOp::And,
                    left: Box::new(lo),
                    right: Box::new(hi),
                },
            };
            if *negated {
                Expr::UnaryOp {
                    unary_op: UnaryOpExpr {
                        op: UnaryOp::Not,
                        operand: Box::new(chain),
                    },
                }
            } else {
                chain
            }
        }

        A::InList {
            expr,
            list,
            negated,
            ..
        } => Expr::InList {
            in_list: InListExpr {
                expr: Box::new(recur(expr)),
                values: list.iter().map(&recur).collect(),
                negated: *negated,
            },
        },

        A::Cast {
            expr, target_type, ..
        } => project_cast(expr, target_type, CastKind::Strict, source, arguments),
        A::TryCast {
            expr, target_type, ..
        } => project_cast(expr, target_type, CastKind::Try, source, arguments),
        A::SafeCast {
            expr, target_type, ..
        } => project_cast(expr, target_type, CastKind::Safe, source, arguments),
        A::TypeCast {
            expr, target_type, ..
        } => project_cast(expr, target_type, CastKind::Strict, source, arguments),

        A::FunctionCall {
            func_name, args, ..
        } => {
            let name_text = slice_span_text(source, func_name.span).trim();
            let name = IdentName::new(name_text);
            let mut projected_args = Vec::with_capacity(args.len());
            for a in args {
                match a.as_ref() {
                    AstFunctionArg::Positional(inner) => projected_args.push(recur(inner)),
                    // Named arguments / lambdas / wildcard arguments do
                    // not reduce to public-typed positional shapes.
                    _ => projected_args.push(Expr::Opaque {
                        opaque: OpaqueExpr {
                            reason: OpaqueExprReason::UnparsedFragment,
                            rendered: String::new(),
                            origin: TextOrigin::default(),
                        },
                    }),
                }
            }
            Expr::FuncCall {
                func_call: FuncCallExpr {
                    name,
                    schema: None,
                    args: projected_args,
                    named_args: Vec::new(),
                    is_temporal: false,
                    is_deterministic: true,
                    is_aggregate: false,
                    is_window: false,
                    catalog_resolved: false,
                    source_span: Some(func_name.span),
                },
            }
        }

        A::Array { elements, .. } => Expr::Collection {
            collection: CollectionExpr {
                kind: CollectionKind::Array,
                elements: elements.iter().map(recur).collect(),
            },
        },

        A::Object { entries, .. } => {
            // Public Collection is a flat element list; for an object
            // literal we flatten the key/value pairs in source order so
            // rule predicates can still walk the contents structurally.
            let mut elements = Vec::with_capacity(entries.len() * 2);
            for (k, v) in entries {
                elements.push(recur(k));
                elements.push(recur(v));
            }
            Expr::Collection {
                collection: CollectionExpr {
                    kind: CollectionKind::Dict,
                    elements,
                },
            }
        }

        A::Placeholder { .. } => Expr::Parameter {
            parameter: ParameterRef {
                name: None,
                position: None,
                kind: ParameterKind::Bind,
            },
        },

        A::ScriptingVarRef { name_span, .. } => Expr::Parameter {
            parameter: ParameterRef {
                name: Some(
                    IdentName::new(slice_span_text(source, *name_span).trim())
                        .written_at(*name_span),
                ),
                position: None,
                kind: ParameterKind::Variable,
            },
        },

        A::SessionVarRef { name_span, .. } => Expr::Parameter {
            parameter: ParameterRef {
                name: Some(
                    IdentName::new(slice_span_text(source, *name_span).trim())
                        .written_at(*name_span),
                ),
                position: None,
                kind: ParameterKind::SessionVar,
            },
        },

        // Variants without a public structural counterpart fold to
        // Opaque. New rules that need to reason about one of these
        // shapes should promote the corresponding variant first (an
        // additive public-Expr extension) rather than re-introducing
        // a per-rule digest field.
        other => opaque_for(other.span(), OpaqueExprReason::UnparsedFragment),
    }
}

/// Project one of the four AST cast forms with an outer-supplied
/// [`CastKind`]. Split out so each cast variant carries its own kind
/// without forcing the caller into nested matches.
fn project_cast(
    expr: &AstExpr,
    target_type: &crate::ast::AstDataType,
    cast_kind: CastKind,
    source: &str,
    arguments: &[IdentName],
) -> Expr {
    let target =
        ast_type_text_to_data_type(slice_span_text(source, ast_data_type_span(target_type)));
    Expr::Cast {
        cast: CastExpr {
            expr: Box::new(project_policy_body_expr(expr, source, arguments)),
            target_type: target,
            cast_kind,
        },
    }
}

/// Span of an [`crate::ast::AstDataType`]. The AST variants carry
/// per-variant span fields rather than a uniform `span()` method.
fn ast_data_type_span(t: &crate::ast::AstDataType) -> Span {
    use crate::ast::AstDataType as T;
    match t {
        T::Simple { name_span } => *name_span,
        T::WithPrecision {
            name_span,
            precision_span,
            ..
        } => Span {
            start: name_span.start,
            end: precision_span.end,
        },
        T::WithPrecisionScale {
            name_span,
            scale_span,
            ..
        } => Span {
            start: name_span.start,
            end: scale_span.end,
        },
        T::Parameterized { span, .. } => *span,
        T::CompoundInterval { span, .. } => *span,
    }
}

/// Map an AST [`BinaryOperator`] to a public [`BinaryOp`]. Returns
/// `None` when the operator has no public counterpart; the caller
/// folds to `Expr::Opaque` in that case.
fn project_ast_binary_op(op: BinaryOperator) -> Option<BinaryOp> {
    use BinaryOperator as B;
    Some(match op {
        B::Plus => BinaryOp::Add,
        B::Minus => BinaryOp::Sub,
        B::Multiply => BinaryOp::Mul,
        B::Divide => BinaryOp::Div,
        B::Modulo => BinaryOp::Mod,
        B::IntegerDivide => BinaryOp::Other(IdentName::new("DIV")),
        B::Equal => BinaryOp::Eq,
        B::NotEqual => BinaryOp::Neq,
        B::NullSafeEqual => BinaryOp::IsNotDistinctFrom,
        B::LessThan => BinaryOp::Lt,
        B::LessThanOrEqual => BinaryOp::Lte,
        B::GreaterThan => BinaryOp::Gt,
        B::GreaterThanOrEqual => BinaryOp::Gte,
        B::And | B::LogicalAnd => BinaryOp::And,
        B::Or | B::LogicalOr => BinaryOp::Or,
        B::Xor => BinaryOp::Other(IdentName::new("XOR")),
        B::Concat => BinaryOp::Concat,
        B::Like => BinaryOp::Like,
        B::ILike => BinaryOp::ILike,
        B::RLike => BinaryOp::Other(IdentName::new("rlike")),
        B::ArrayContains => BinaryOp::ArrayContains,
        B::ArrayOverlap => BinaryOp::ArrayOverlap,
        B::JsonField => BinaryOp::JsonGet,
        B::JsonFieldText => BinaryOp::JsonGetText,
        B::LeftShift => BinaryOp::ShiftLeft,
        B::RightShift => BinaryOp::ShiftRight,
        B::BitwiseXor | B::BitwiseXorPg => BinaryOp::BitXor,
        B::BitwiseAnd => BinaryOp::BitAnd,
        B::BitwiseOr => BinaryOp::BitOr,
        B::Exponent => BinaryOp::Pow,
        B::QueryMatch => BinaryOp::Other(IdentName::new("@@")),
        B::JsonExistsAny => BinaryOp::Other(IdentName::new("?|")),
        B::JsonExistsAll => BinaryOp::Other(IdentName::new("?&")),
        B::StartsWith => BinaryOp::Other(IdentName::new("^@")),
        B::Overlaps => BinaryOp::Other(IdentName::new("OVERLAPS")),
        B::SoundsLike => BinaryOp::Other(IdentName::new("SOUNDS LIKE")),
        B::MemberOf => BinaryOp::Other(IdentName::new("MEMBER OF")),
        // Operators without a curated public counterpart — caller folds.
        B::Not
        | B::BitwiseNot
        | B::Assign
        | B::SquareRoot
        | B::AbsoluteValue
        | B::BinaryCast
        | B::Distance
        | B::ArrayContainedBy
        | B::JsonPath
        | B::JsonPathText
        | B::JsonContains
        | B::JsonExists
        | B::RegexMatch
        | B::RegexMatchI
        | B::RegexNotMatch
        | B::RegexNotMatchI => return None,
    })
}

/// Project an [`AstLiteral`] (which carries spans, not values) into a
/// public [`LiteralValue`].
fn project_ast_literal_value(lit: &AstLiteral, source: &str) -> LiteralValue {
    match lit {
        AstLiteral::Null { .. } => LiteralValue::Null,
        AstLiteral::Boolean { span } => {
            let t = slice_span_text(source, *span).trim();
            LiteralValue::Bool {
                value: t.eq_ignore_ascii_case("true"),
            }
        }
        AstLiteral::Number { span }
        | AstLiteral::Money {
            amount_span: span, ..
        } => {
            let t = slice_span_text(source, *span).trim();
            if let Ok(n) = t.parse::<i64>() {
                LiteralValue::Integer { value: n }
            } else if let Ok(n) = t.parse::<f64>() {
                LiteralValue::Float { value: n }
            } else {
                LiteralValue::Other {
                    repr: t.to_string(),
                }
            }
        }
        AstLiteral::String { span } | AstLiteral::StringWithJinja { span } => {
            let raw = slice_span_text(source, *span);
            LiteralValue::String {
                value: literal_value_or_text(raw),
            }
        }
        AstLiteral::Adjacent { parts } => LiteralValue::String {
            value: crate::ir::span_extract::joined_string_literal_value(parts, source)
                .unwrap_or_else(|| slice_span_text(source, lit.span()).to_string()),
        },
    }
}

/// Walk a public [`Expr`] tree and produce the set of expressions that
/// every code path can yield as a final value. Transparent through
/// `Cast` (every cast strips for the purposes of "what does this
/// return"), and fans out the result of each `Case` branch and `else`.
/// All other shapes are themselves a terminal return.
fn project_terminal_returns(expr: &Expr) -> Vec<Expr> {
    let mut out = Vec::new();
    collect_terminal_returns(expr, &mut out);
    out
}

fn collect_terminal_returns(expr: &Expr, out: &mut Vec<Expr>) {
    match expr {
        Expr::Cast { cast } => collect_terminal_returns(&cast.expr, out),
        Expr::Case { case } => {
            for b in &case.branches {
                collect_terminal_returns(&b.result, out);
            }
            match &case.else_branch {
                Some(else_b) => collect_terminal_returns(else_b, out),
                // `CASE WHEN … END` with no ELSE returns NULL on the
                // fall-through path. Surface that as a terminal return
                // so a rule predicating "every terminal is X" correctly
                // sees the NULL as a counter-example.
                None => out.push(Expr::Literal {
                    literal: LiteralValue::Null,
                    origin: TextOrigin::default(),
                }),
            }
        }
        other => out.push(other.clone()),
    }
}

fn project_auth_shape(s: &AuthenticationPolicyShape, source: &str) -> AuthenticationPolicyFacts {
    use crate::facts::policy::{AuthMethod, MfaEnrollmentLevel};
    let authentication_methods = s
        .authentication_method_spans
        .iter()
        .filter_map(|sp| {
            let value = literal_value_or_text(slice_span_text(source, *sp));
            match value.to_ascii_uppercase().as_str() {
                "PASSWORD" => Some(AuthMethod::Password),
                "SAML" => Some(AuthMethod::Saml),
                "OAUTH" => Some(AuthMethod::Oauth),
                "KEYPAIR" => Some(AuthMethod::KeyPair),
                "PROGRAMMATIC_ACCESS_TOKEN" => Some(AuthMethod::ProgrammaticAccessToken),
                "ALL" => Some(AuthMethod::All),
                _ => None,
            }
        })
        .collect();
    let mfa_enrollment = s
        .mfa_enrollment_value_span
        .map(|sp| literal_value_or_text(slice_span_text(source, sp)).to_ascii_uppercase())
        .map_or(MfaEnrollmentLevel::Optional, |value| match value.as_str() {
            "REQUIRED" => MfaEnrollmentLevel::Required,
            "REQUIRED_PASSWORD_ONLY" => MfaEnrollmentLevel::RequiredPasswordOnly,
            _ => MfaEnrollmentLevel::Optional,
        });
    AuthenticationPolicyFacts {
        authentication_methods,
        mfa_enrollment,
        mfa_required: s.mfa_required,
        had_methods_change: s.had_methods_change,
        had_mfa_change: s.had_mfa_change,
        had_client_types_change: s.had_client_types_change,
        had_security_integrations_change: s.had_security_integrations_change,
        ..AuthenticationPolicyFacts::default()
    }
}

/// Structural recognition of an IPv4 allow/block entry: the CIDR prefix
/// length, whether the base address is in an RFC 1918 / loopback private
/// range, and whether it is the all-addresses route (a `/0` prefix, i.e.
/// `0.0.0.0/0`). Pure recognition — the danger verdict is YAML.
fn classify_ip_entry(raw: &str) -> (Option<u32>, Option<bool>, bool) {
    let (addr, cidr_prefix) = match raw.split_once('/') {
        Some((a, p)) => (a.trim(), p.trim().parse::<u32>().ok()),
        None => (raw.trim(), None),
    };
    let is_zero_route = cidr_prefix == Some(0);
    let octets: Option<[u32; 4]> = {
        let parts: Vec<&str> = addr.split('.').collect();
        if parts.len() == 4 {
            let mut o = [0u32; 4];
            let mut ok = true;
            for (i, part) in parts.iter().enumerate() {
                match part.parse::<u32>() {
                    Ok(v) if v <= 255 => o[i] = v,
                    _ => {
                        ok = false;
                        break;
                    }
                }
            }
            if ok {
                Some(o)
            } else {
                None
            }
        } else {
            None
        }
    };
    let is_private_range = octets.map(|o| {
        o[0] == 10
            || (o[0] == 172 && (16..=31).contains(&o[1]))
            || (o[0] == 192 && o[1] == 168)
            || o[0] == 127
    });
    (cidr_prefix, is_private_range, is_zero_route)
}

fn project_network_shape(s: &NetworkPolicyShape, source: &str) -> NetworkPolicyFacts {
    let to_ip_entries = |spans: &[Span]| -> Vec<IpListEntry> {
        spans
            .iter()
            .map(|sp| {
                let raw = literal_value_or_text(slice_span_text(source, *sp).trim());
                let (cidr_prefix, is_private_range, is_zero_route) = classify_ip_entry(&raw);
                IpListEntry {
                    raw,
                    cidr_prefix,
                    is_private_range,
                    is_zero_route,
                }
            })
            .collect()
    };
    let to_object_refs = |spans: &[Span]| -> Vec<ObjectRef> {
        spans
            .iter()
            .map(|sp| {
                let raw = literal_value_or_text(slice_span_text(source, *sp).trim());
                ObjectRef {
                    kind: ObjectKind::NetworkRule,
                    name: TableRef::new(IdentName::new(raw), None, None, Some(*sp)),
                }
            })
            .collect()
    };
    use crate::facts::policy::{NetworkPolicyProperty, NetworkPolicyPropertyKind as P};
    use crate::ir::policy_plan::NetworkPolicyPropertyKindIr as Pi;
    let properties = s
        .properties
        .iter()
        .map(|p| NetworkPolicyProperty {
            kind: match p {
                Pi::AllowedIpList => P::AllowedIpList,
                Pi::BlockedIpList => P::BlockedIpList,
                Pi::AllowedNetworkRules => P::AllowedNetworkRules,
                Pi::BlockedNetworkRules => P::BlockedNetworkRules,
                Pi::Comment => P::Comment,
            },
        })
        .collect();
    NetworkPolicyFacts {
        allowed_ip_lists: to_ip_entries(&s.allowed_ip_value_spans),
        blocked_ip_lists: to_ip_entries(&s.blocked_ip_value_spans),
        allowed_network_rules: to_object_refs(&s.allowed_rule_value_spans),
        blocked_network_rules: to_object_refs(&s.blocked_rule_value_spans),
        properties,
        had_set_action: s.had_set_action,
        had_add_action: s.had_add_action,
        had_remove_action: s.had_remove_action,
    }
}

/// Project an `EXEC <proc>` call's typed argument list into
/// [`CallArgumentFacts`] — the recognition primitive rules predicate on.
/// Dialect-neutral: records each argument's (optional) named-parameter
/// name and the typed shape of its value.
pub(crate) fn project_call_arguments(
    args: &[crate::ast::AstCallArg],
    source: &str,
) -> Vec<crate::facts::ddl::CallArgumentFacts> {
    use crate::facts::ddl::CallArgumentFacts;
    args.iter()
        .enumerate()
        .map(|(position, arg)| {
            let name = arg.name.as_ref().map(|id| {
                source
                    .get(id.span.start as usize..id.span.end as usize)
                    .unwrap_or("")
                    .trim_start_matches('@')
                    .to_ascii_lowercase()
            });
            let (value_kind, value_literal, value_number) = value_shape(&arg.value, source);
            CallArgumentFacts {
                name,
                position: u32::try_from(position).unwrap_or(u32::MAX),
                value_kind,
                value_literal,
                value_number,
                value_origin: super::identity::TextOrigin::at(arg.value.span()),
            }
        })
        .collect()
}

/// The shape of the value `expr` writes, with a string literal's decoded
/// text, lowercased, and an integer literal's number.
fn value_shape(
    expr: &AstExpr,
    source: &str,
) -> (
    crate::facts::ddl::ValueKind,
    Option<super::identity::WrittenText>,
    Option<f64>,
) {
    use crate::facts::ddl::ValueKind;
    match expr {
        AstExpr::Literal {
            literal: AstLiteral::String { span },
            ..
        } => {
            let raw = source
                .get(span.start as usize..span.end as usize)
                .unwrap_or("");
            (
                ValueKind::StringLiteral,
                Some(super::identity::WrittenText::at(
                    literal_value_or_text(raw).to_ascii_lowercase(),
                    *span,
                )),
                None,
            )
        }
        AstExpr::Literal {
            literal: AstLiteral::Number { span },
            ..
        } => (
            ValueKind::Number,
            None,
            source
                .get(span.start as usize..span.end as usize)
                .and_then(|raw| raw.trim().parse::<f64>().ok())
                .filter(|number| number.is_finite()),
        ),
        AstExpr::Literal {
            literal: AstLiteral::Money { .. },
            ..
        } => (ValueKind::Number, None, None),
        AstExpr::Literal {
            literal: AstLiteral::Null { .. },
            ..
        } => (ValueKind::Null, None, None),
        AstExpr::Ident { .. } | AstExpr::Placeholder { .. } => (ValueKind::Variable, None, None),
        _ => (ValueKind::Other, None, None),
    }
}

/// The variables of a `DECLARE`, `variables`, read from `source`.
pub(crate) fn project_declare(
    variables: &[crate::ast::AstDeclaredVariable],
    source: &str,
) -> crate::facts::ddl::DeclareFacts {
    let text = |span: Span| source.get(span.start as usize..span.end as usize);
    crate::facts::ddl::DeclareFacts {
        variables: variables
            .iter()
            .map(|variable| crate::facts::ddl::DeclaredVariableFacts {
                name: IdentName::new(text(variable.name.span).unwrap_or("")),
                data_type: variable
                    .type_span
                    .and_then(text)
                    .map(|written| written.trim().to_string()),
                default: variable
                    .default_expr
                    .as_deref()
                    .map(|expr| value_shape(expr, source).0),
            })
            .collect(),
    }
}

/// The table variable a T-SQL `DECLARE @t TABLE (…)` makes: its name at
/// `name`, its type the `TABLE` word at `table`.
pub(crate) fn project_declare_table(
    name: Span,
    table: Span,
    source: &str,
) -> crate::facts::ddl::DeclareFacts {
    let text = |span: Span| source.get(span.start as usize..span.end as usize);
    crate::facts::ddl::DeclareFacts {
        variables: vec![crate::facts::ddl::DeclaredVariableFacts {
            name: IdentName::new(text(name).unwrap_or("")),
            data_type: text(table).map(|written| written.trim().to_string()),
            default: None,
        }],
    }
}

fn project_session_shape(s: &SessionPolicyShape) -> SessionPolicyFacts {
    SessionPolicyFacts {
        session_idle_timeout_mins: s.session_idle_timeout_mins,
        session_ui_idle_timeout_mins: s.session_ui_idle_timeout_mins,
        unset_fields: s
            .unset_fields
            .iter()
            .filter_map(|f| match f {
                SessionPolicyFieldIr::SessionIdleTimeoutMins => {
                    Some(SessionPolicyField::SessionIdleTimeoutMins)
                }
                SessionPolicyFieldIr::SessionUiIdleTimeoutMins => {
                    Some(SessionPolicyField::SessionUiIdleTimeoutMins)
                }
                // The public `SessionPolicyField` enum does not yet
                // surface secondary-role unset variants. The IR
                // tracks them so that future schema extensions can
                // lift them; today the corresponding rules predicate
                // on `policy.variant.has_*_secondary_roles` instead.
                SessionPolicyFieldIr::AllowedSecondaryRoles
                | SessionPolicyFieldIr::BlockedSecondaryRoles => None,
            })
            .collect(),
    }
}

fn project_password_shape(s: &PasswordPolicyShape) -> PasswordPolicyFacts {
    let mut complexity_classes = Vec::new();
    if s.min_upper_case_chars.is_some_and(|v| v > 0) {
        complexity_classes.push(PasswordPolicyComplexityClass::Upper);
    }
    if s.min_lower_case_chars.is_some_and(|v| v > 0) {
        complexity_classes.push(PasswordPolicyComplexityClass::Lower);
    }
    if s.min_numeric_chars.is_some_and(|v| v > 0) {
        complexity_classes.push(PasswordPolicyComplexityClass::Numeric);
    }
    if s.min_special_chars.is_some_and(|v| v > 0) {
        complexity_classes.push(PasswordPolicyComplexityClass::Special);
    }

    PasswordPolicyFacts {
        min_length: s.min_length,
        max_length: s.max_length,
        min_upper_case_chars: s.min_upper_case_chars,
        min_lower_case_chars: s.min_lower_case_chars,
        min_numeric_chars: s.min_numeric_chars,
        min_special_chars: s.min_special_chars,
        min_age_days: s.min_age_days,
        max_age_days: s.max_age_days,
        max_retries: s.max_retries,
        lockout_time_mins: s.lockout_time_mins,
        history: s.history,
        unset_fields: s
            .unset_fields
            .iter()
            .map(|f| match f {
                PasswordPolicyFieldIr::MinLength => PasswordPolicyField::MinLength,
                PasswordPolicyFieldIr::MaxLength => PasswordPolicyField::MaxLength,
                PasswordPolicyFieldIr::MinUpperCaseChars => PasswordPolicyField::MinUpperCaseChars,
                PasswordPolicyFieldIr::MinLowerCaseChars => PasswordPolicyField::MinLowerCaseChars,
                PasswordPolicyFieldIr::MinNumericChars => PasswordPolicyField::MinNumericChars,
                PasswordPolicyFieldIr::MinSpecialChars => PasswordPolicyField::MinSpecialChars,
                PasswordPolicyFieldIr::MinAgeDays => PasswordPolicyField::MinAgeDays,
                PasswordPolicyFieldIr::MaxAgeDays => PasswordPolicyField::MaxAgeDays,
                PasswordPolicyFieldIr::MaxRetries => PasswordPolicyField::MaxRetries,
                PasswordPolicyFieldIr::LockoutTimeMins => PasswordPolicyField::LockoutTimeMins,
                PasswordPolicyFieldIr::History => PasswordPolicyField::History,
            })
            .collect(),
        complexity_classes,
    }
}

/// Parse `key1 = '<value1>' [, key2 = '<value2>']` from a SET TAG
/// action's `assignments_span`. Resilient: a fragment that doesn't
/// match the `key = 'value'` shape is skipped (the rule corpus
/// predicates on tag presence, not exact value-side recovery).
fn parse_tag_assignments(span: Span, source: &str) -> Vec<CatalogTag> {
    let text = slice_span_text(source, span);
    text.split(',')
        .filter_map(parse_one_tag_assignment)
        .collect()
}

fn parse_one_tag_assignment(chunk: &str) -> Option<CatalogTag> {
    let (key, value) = chunk.split_once('=')?;
    let key_str = key.trim();
    if key_str.is_empty() {
        return None;
    }
    let value_unquoted = string_literal_value(value).or_else(|| {
        let text = value.trim();
        (!text.is_empty()).then(|| text.to_string())
    });
    Some(CatalogTag {
        key: IdentName::new(key_str),
        value: value_unquoted,
    })
}

/// Parse `key1 [, key2]` from an UNSET TAG action's `tags_span`.
fn parse_tag_keys(span: Span, source: &str) -> Vec<IdentName> {
    slice_span_text(source, span)
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(IdentName::new)
        .collect()
}

// ---------------------------------------------------------------------------
// Integration projection (API + Storage).
// ---------------------------------------------------------------------------

/// Build a public `StatementFacts` directly from a lowered
/// [`IntegrationPlan`].
pub fn derive_facts_from_integration_plan(plan: &IntegrationPlan, source: &str) -> StatementFacts {
    let kind = integration_statement_kind(plan.integration_kind, plan.action);
    let object_kind = match plan.integration_kind {
        IntegrationKindIr::Api => ObjectKind::ApiIntegration,
        IntegrationKindIr::Storage => ObjectKind::StorageIntegration,
        IntegrationKindIr::ExternalAccess => ObjectKind::ExternalAccessIntegration,
        IntegrationKindIr::Notification => ObjectKind::NotificationIntegration,
        IntegrationKindIr::Security => ObjectKind::SecurityIntegration,
    };
    let target = ObjectRef {
        kind: object_kind,
        name: parse_table_ref(plan.name_span, source),
    };
    let integration = project_integration_facts(plan, source, target.clone());
    let ddl = DdlFacts {
        targets: Vec::new(),
        action: match plan.action {
            IntegrationAction::Create => DdlAction::Create,
            IntegrationAction::Alter => DdlAction::Alter,
            IntegrationAction::Drop => DdlAction::Drop,
        },
        object_kind,
        target: Some(target),
        options: DdlOptions {
            or_replace: plan.or_replace,
            if_not_exists: plan.if_not_exists,
            if_exists: plan.if_exists,
            ..DdlOptions::default()
        },
        alter_changes: Vec::new(),
        stage: None,
        storage_credential: None,
        dynamic_table: None,
        pipe: None,
        task: None,
        database: None,
        warehouse: None,
        stream: None,
        schema: None,
        function: None,
        procedure: None,
        table: None,
        catalog: None,
        table_maintenance: None,
        volume: None,
        external_location: None,
        connection: None,
        external_data_source: None,
        foreign_server: None,
        user_mapping: None,
        foreign_table: None,
        import_foreign_schema: None,
        flow: None,
        mssql_set_option: None,
        mssql_principal: None,
        principal: None,
        domain: None,
        index: None,
        trigger: None,
        trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        datashare: None,
        tag: None,
        file_format: None,
        session: None,
        share: None,
        secret: None,
        network_rule: None,
        resource_monitor: None,
        compute_pool: None,
        git_repository: None,
        image_repository: None,
        streamlit: None,
        service: None,
        notebook: None,
        alert: None,
        data_metric_function: None,
        replication_failover_group: None,
        account: None,
        semantic_view: None,
        cortex_search_service: None,
        application: None,
        application_package: None,
        listing: None,
        managed_account: None,
        show: None,
        synonym: None,
        server_configuration: None,
        mysql_load_data: None,
        event: None,
        create_trigger: None,
        view: None,
        external_function: None,
        trigger_body: None,
    };
    StatementFacts {
        declare: None,
        call: None,
        kind,
        source_span: Some(plan.span),
        query: None,
        ddl: Some(ddl),
        privilege: None,
        policy: None,
        integration: Some(integration),
        policy_attachment: None,
        use_stmt: None,
        pg_copy: None,

        mssql_backup: None,

        mssql_restore: None,
        mssql_dbcc: None,
        mssql_key_management: None,
        mssql_security_policy: None,
        mssql_key_backup: None,
        mssql_assembly: None,
        mssql_add_signature: None,
        mssql_service_master_key: None,
        pg_default_privileges: None,
        comment: None,
        handler: None,
        dynamic_sql_calls: Vec::new(),
        mssql_exec: None,
        impersonation: None,
        audit: None,
        security_object: None,
        execute_immediate_from: None,
        algebra: AlgebraFacts::default(),
        script_context: ScriptContext::default(),
        diff: None,
    }
}

fn integration_statement_kind(kind: IntegrationKindIr, action: IntegrationAction) -> StatementKind {
    match (kind, action) {
        (IntegrationKindIr::Api, IntegrationAction::Create) => StatementKind::CreateApiIntegration,
        (IntegrationKindIr::Api, IntegrationAction::Alter) => StatementKind::AlterApiIntegration,
        (IntegrationKindIr::Api, IntegrationAction::Drop) => StatementKind::DropApiIntegration,
        (IntegrationKindIr::Storage, IntegrationAction::Create) => {
            StatementKind::CreateStorageIntegration
        }
        (IntegrationKindIr::Storage, IntegrationAction::Alter) => {
            StatementKind::AlterStorageIntegration
        }
        (IntegrationKindIr::Storage, IntegrationAction::Drop) => {
            StatementKind::DropStorageIntegration
        }
        (IntegrationKindIr::ExternalAccess, IntegrationAction::Create) => {
            StatementKind::CreateExternalAccessIntegration
        }
        (IntegrationKindIr::ExternalAccess, IntegrationAction::Alter) => {
            StatementKind::AlterExternalAccessIntegration
        }
        (IntegrationKindIr::ExternalAccess, IntegrationAction::Drop) => {
            StatementKind::DropExternalAccessIntegration
        }
        (IntegrationKindIr::Notification, IntegrationAction::Create) => {
            StatementKind::CreateNotificationIntegration
        }
        (IntegrationKindIr::Notification, IntegrationAction::Alter) => {
            StatementKind::AlterNotificationIntegration
        }
        (IntegrationKindIr::Notification, IntegrationAction::Drop) => {
            StatementKind::DropNotificationIntegration
        }
        (IntegrationKindIr::Security, IntegrationAction::Create) => {
            StatementKind::CreateSecurityIntegration
        }
        (IntegrationKindIr::Security, IntegrationAction::Alter) => {
            StatementKind::AlterSecurityIntegration
        }
        (IntegrationKindIr::Security, IntegrationAction::Drop) => {
            StatementKind::DropSecurityIntegration
        }
    }
}

fn project_integration_facts(
    plan: &IntegrationPlan,
    source: &str,
    target: ObjectRef,
) -> IntegrationFacts {
    let action = match plan.action {
        IntegrationAction::Create => DdlAction::Create,
        IntegrationAction::Alter => DdlAction::Alter,
        IntegrationAction::Drop => DdlAction::Drop,
    };
    let kind = match plan.integration_kind {
        IntegrationKindIr::Api => IntegrationKind::Api,
        IntegrationKindIr::Storage => IntegrationKind::Storage,
        IntegrationKindIr::ExternalAccess => IntegrationKind::ExternalAccess,
        IntegrationKindIr::Notification => IntegrationKind::Notification,
        IntegrationKindIr::Security => IntegrationKind::Security,
    };
    let set_tags = plan
        .set_tag_action_spans
        .iter()
        .flat_map(|sp| parse_tag_assignments(*sp, source))
        .collect();
    let unset_tags = plan
        .unset_tag_action_spans
        .iter()
        .flat_map(|sp| parse_tag_keys(*sp, source))
        .collect();
    let comment = match &plan.comment {
        PolicyCommentAction::Unchanged => PolicyCommentChange::Unchanged,
        PolicyCommentAction::Set { value_span } => {
            let text = crate::ir::policy_plan::comment_text_from_value_span(*value_span, source)
                .unwrap_or_else(|| slice_span_text(source, *value_span).trim().to_string());
            PolicyCommentChange::Set { text }
        }
        PolicyCommentAction::Unset => PolicyCommentChange::Unset,
    };
    let variant = match &plan.variant {
        IntegrationPlanVariant::Api(shape) => {
            IntegrationVariantFacts::Api(project_api_integration_shape(shape))
        }
        IntegrationPlanVariant::Storage(shape) => {
            IntegrationVariantFacts::Storage(project_storage_integration_shape(shape))
        }
        IntegrationPlanVariant::ExternalAccess(shape) => IntegrationVariantFacts::ExternalAccess(
            project_external_access_integration_shape(shape),
        ),
        IntegrationPlanVariant::Notification(shape) => {
            IntegrationVariantFacts::Notification(project_notification_integration_shape(shape))
        }
        IntegrationPlanVariant::Security(shape) => {
            IntegrationVariantFacts::Security(project_security_integration_shape(shape))
        }
        // DROP — produce an empty per-kind variant. Routes via
        // `plan.integration_kind` so the discriminator stays correct.
        IntegrationPlanVariant::DropOnly => match plan.integration_kind {
            IntegrationKindIr::Api => {
                IntegrationVariantFacts::Api(ApiIntegrationVariantFacts::default())
            }
            IntegrationKindIr::Storage => {
                IntegrationVariantFacts::Storage(StorageIntegrationVariantFacts::default())
            }
            IntegrationKindIr::ExternalAccess => IntegrationVariantFacts::ExternalAccess(
                ExternalAccessIntegrationVariantFacts::default(),
            ),
            IntegrationKindIr::Notification => {
                IntegrationVariantFacts::Notification(NotificationIntegrationVariantFacts::default())
            }
            IntegrationKindIr::Security => {
                IntegrationVariantFacts::Security(SecurityIntegrationVariantFacts::default())
            }
        },
    };
    let renamed_to = plan
        .renamed_to_name_span
        .map(|sp| IdentName::new(slice_span_text(source, sp).trim()).written_at(sp));
    IntegrationFacts {
        kind,
        action,
        target,
        variant,
        renamed_to,
        set_tags,
        unset_tags,
        comment,
    }
}

fn project_api_integration_shape(s: &ApiIntegrationShape) -> ApiIntegrationVariantFacts {
    ApiIntegrationVariantFacts {
        enabled_on_create: s.enabled_on_create,
        has_api_key_on_create: s.has_api_key_on_create,
        has_allowed_prefixes_on_create: s.has_allowed_prefixes_on_create,
        has_blocked_prefixes_on_create: s.has_blocked_prefixes_on_create,
        had_set_enabled_to_true: s.had_set_enabled_to_true,
        had_set_enabled_to_false: s.had_set_enabled_to_false,
        had_set_api_key: s.had_set_api_key,
        had_unset_api_key: s.had_unset_api_key,
        had_set_aws_role: s.had_set_aws_role,
        had_set_azure_ad_application_id: s.had_set_azure_ad_application_id,
        had_set_allowed_prefixes: s.had_set_allowed_prefixes,
        had_set_blocked_prefixes: s.had_set_blocked_prefixes,
    }
}

fn project_storage_integration_shape(
    s: &StorageIntegrationShape,
) -> StorageIntegrationVariantFacts {
    StorageIntegrationVariantFacts {
        enabled_on_create: s.enabled_on_create,
        had_set_enabled_to_true: s.had_set_enabled_to_true,
        had_set_enabled_to_false: s.had_set_enabled_to_false,
        had_set_aws_role: s.had_set_aws_role,
        had_set_azure_tenant: s.had_set_azure_tenant,
        had_set_allowed_locations: s.had_set_allowed_locations,
        had_set_blocked_locations: s.had_set_blocked_locations,
    }
}

fn project_external_access_integration_shape(
    s: &ExternalAccessIntegrationShape,
) -> ExternalAccessIntegrationVariantFacts {
    ExternalAccessIntegrationVariantFacts {
        enabled_on_create: s.enabled_on_create,
        had_set_enabled_to_true: s.had_set_enabled_to_true,
        had_set_enabled_to_false: s.had_set_enabled_to_false,
        had_unset_enabled: s.had_unset_enabled,
        had_set_allowed_network_rules: s.had_set_allowed_network_rules,
        had_set_allowed_network_rules_nonempty: s.had_set_allowed_network_rules_nonempty,
        had_unset_allowed_network_rules: s.had_unset_allowed_network_rules,
        had_set_allowed_api_authentication_integrations: s
            .had_set_allowed_api_authentication_integrations,
        had_unset_allowed_api_authentication_integrations: s
            .had_unset_allowed_api_authentication_integrations,
        had_set_allowed_authentication_secrets: s.had_set_allowed_authentication_secrets,
        had_unset_allowed_authentication_secrets: s.had_unset_allowed_authentication_secrets,
        had_rename: s.had_rename,
    }
}

fn project_notification_integration_shape(
    s: &crate::ir::NotificationIntegrationShape,
) -> NotificationIntegrationVariantFacts {
    NotificationIntegrationVariantFacts {
        enabled_on_create: s.enabled_on_create,
        had_set_enabled_to_true: s.had_set_enabled_to_true,
        had_set_enabled_to_false: s.had_set_enabled_to_false,
        had_rename: s.had_rename,
    }
}

fn project_security_integration_shape(
    s: &crate::ir::SecurityIntegrationShape,
) -> SecurityIntegrationVariantFacts {
    SecurityIntegrationVariantFacts {
        integration_type: s.integration_type.clone(),
        enabled_on_create: s.enabled_on_create,
        had_set_enabled_to_true: s.had_set_enabled_to_true,
        had_set_enabled_to_false: s.had_set_enabled_to_false,
        had_unset_enabled: s.had_unset_enabled,
        set_properties: s
            .set_properties
            .iter()
            .map(|p| SecurityIntegrationProperty {
                name: IdentName::new(p.name.clone()),
                value: p.value.clone(),
                value_normalized: p.value.as_deref().map(normalize_secintg_property_value),
            })
            .collect(),
        unset_properties: s
            .unset_properties
            .iter()
            .map(|n| IdentName::new(n.clone()))
            .collect(),
        had_rename: s.had_rename,
    }
}

/// A security-integration property's value, upper-cased, for case- and
/// quote-insensitive rule matching.
fn normalize_secintg_property_value(value: &str) -> String {
    literal_value_or_name(value).to_ascii_uppercase()
}

// ── The rows a write reaches — public projection ──

/// How the `UPDATE` or `DELETE` `plan` reaches the rows of the tables it
/// writes; `None` for any other statement. A predicate is judged always
/// true by its shape alone.
/// What the statement's `INSERT OVERWRITE` replaces, through its `WITH`
/// and an `EXPLAIN`; `None` for any other statement.
fn project_overwrite(plan: &RelPlan) -> Option<crate::facts::query::OverwriteFacts> {
    use crate::facts::query::OverwriteFacts;
    use crate::ir::plan::OverwriteScope;
    let mut statement = plan;
    while let RelPlan::WithScope { body, .. } | RelPlan::Explain { body, .. } = statement {
        statement = body;
    }
    let RelPlan::Insert { overwrite, .. } = statement else {
        return None;
    };
    overwrite.map(|scope| match scope {
        OverwriteScope::Table => OverwriteFacts::Table,
        OverwriteScope::Partitions => OverwriteFacts::Partitions,
    })
}

fn project_target_rows(
    plan: &RelPlan,
    source: &str,
    bindings: &BindingTable,
) -> Option<crate::facts::query::TargetRowsFacts> {
    use crate::facts::query::{TargetJoin, TargetRowsFacts, WrittenRowsFacts};
    let mut ctes: Vec<&crate::ir::plan::CteBinding> = Vec::new();
    let mut statement = plan;
    loop {
        if let RelPlan::WithScope {
            ctes: bound, body, ..
        } = statement
        {
            ctes.extend(bound);
            statement = body;
        } else if let RelPlan::Explain { body, .. } = statement {
            statement = body;
        } else {
            break;
        }
    }
    // The source of each table written: the target's row (`None` where the
    // target stands beside the list), and each other source written.
    let mut written: Vec<Option<crate::ast::NodeId>> = Vec::new();
    let (sources, top) = if let RelPlan::Update {
        from,
        target_node,
        target_row,
        assignments,
        top,
        ..
    } = statement
    {
        for assignment in assignments {
            let row = match assignment.written_node == *target_node {
                true => *target_row,
                false => Some(assignment.written_node),
            };
            if !written.contains(&row) {
                written.push(row);
            }
        }
        (from.as_deref(), top.as_ref())
    } else if let RelPlan::Delete {
        using,
        target_row,
        deleted_sources,
        top,
        ..
    } = statement
    {
        written.push(*target_row);
        written.extend(deleted_sources.iter().map(|node| Some(*node)));
        (using.as_deref(), top.as_ref())
    } else {
        return None;
    };
    let written = written
        .into_iter()
        .map(|row| {
            let row = sources.zip(row).and_then(|(sources, row)| {
                let (matched, _) = joins_keep_matched(sources, row, source, bindings)?;
                Some((matched, sources.joined_source(row)?))
            });
            let join = match row {
                None => TargetJoin::NotASource,
                Some((false, _)) => TargetJoin::AllRows,
                Some((true, _)) => TargetJoin::MatchedRows,
            };
            let through_query = row.and_then(|(_, row)| query_rows(row, &ctes, source, bindings));
            WrittenRowsFacts {
                join,
                through_query,
            }
        })
        .collect();
    let cap = top.map(|top| crate::facts::query::RowCapFacts {
        percent: top.percent,
        count: written_count(&top.count),
        offset_only: false,
    });
    Some(TargetRowsFacts { written, cap })
}

/// The number `count` writes, where it is a numeric literal.
fn written_count(count: &crate::ir::scalar::ScalarExpr) -> Option<f64> {
    let crate::ir::scalar::ScalarExpr::Lit {
        value: Lit::Integer(text) | Lit::Float(text),
        ..
    } = count
    else {
        return None;
    };
    text.parse().ok()
}

/// Whether some join of `plan` over its source `row` keeps only the rows
/// of `row` its condition matches, with the rows of `plan`, which a join
/// above it reads; `None` where `row` is none of the sources `plan` joins.
/// The rows of each join are those of the side holding `row` grown by the
/// other side's, so a chain of joins is read once.
fn joins_keep_matched<'b>(
    plan: &RelPlan,
    row: crate::ast::NodeId,
    source: &str,
    bindings: &'b BindingTable,
) -> Option<(bool, crate::ir::queries::LeftRows<'b>)> {
    let RelPlan::Join {
        left,
        right,
        kind,
        on,
        match_condition,
        using,
        ..
    } = plan
    else {
        return (plan.node_id() == row)
            .then(|| (false, crate::ir::queries::LeftRows::of(plan, bindings)));
    };
    let (below, side, side_rows) = match joins_keep_matched(left, row, source, bindings) {
        Some((below, rows)) => (below, left.as_ref(), rows),
        None => {
            let (below, rows) = joins_keep_matched(right, row, source, bindings)?;
            (below, right.as_ref(), rows)
        }
    };
    let on_left = std::ptr::eq(side, left.as_ref());
    // A condition that is always true matches every pair of rows.
    let conditioned = match on.as_ref().or(match_condition.as_ref()) {
        Some(condition) => {
            !crate::ir::always_true::is_always_true(condition, source, None, bindings, None)
        }
        None => !using.is_empty(),
    };
    // A right side drops a row of the left where it can yield none for
    // it: what can drop its rows reads that row (`CROSS APPLY`,
    // `LATERAL`), or it yields none for any. However the join is spelled.
    let lateral_drops = on_left
        && right.row_yield(&side_rows, source, bindings) == crate::ir::queries::RowYield::MayBeNone;
    let here = match kind {
        IrJoinKind::Inner | IrJoinKind::LeftSemi | IrJoinKind::RightSemi => {
            conditioned || lateral_drops
        }
        IrJoinKind::Cross => lateral_drops,
        IrJoinKind::FullOuter => false,
        IrJoinKind::LeftOuter | IrJoinKind::Asof => !on_left && conditioned,
        IrJoinKind::RightOuter => on_left && conditioned,
        IrJoinKind::LeftAnti | IrJoinKind::RightAnti => true,
    };
    Some((below || here, side_rows.joined(plan, side)))
}

/// What the query `row`, a write's target row, does to the rows of the
/// table it reads: `None` where `row` is a table's own rows. A CTE it
/// reads through is looked up among `ctes`; a query whose rows are no one
/// table's adds nothing past it.
fn query_rows(
    row: &RelPlan,
    ctes: &[&crate::ir::plan::CteBinding],
    source: &str,
    bindings: &BindingTable,
) -> Option<crate::facts::query::TargetQueryFacts> {
    use crate::ir::queries::RowStep;
    if !matches!(row, RelPlan::DerivedTable { .. } | RelPlan::CteRef { .. }) {
        return None;
    }
    let mut facts = crate::facts::query::TargetQueryFacts::default();
    let mut query = row;
    // Each CTE is entered once: a body that names an earlier CTE moves on.
    for _ in 0..=ctes.len() {
        let Some(steps) = query.one_table_steps() else {
            break;
        };
        let mut next = None;
        for step in steps {
            match step {
                RowStep::Where(predicate) => {
                    if !crate::ir::always_true::is_always_true(
                        predicate, source, None, bindings, None,
                    ) {
                        facts.where_filters = true;
                    }
                }
                RowStep::Limit { count, percent } => {
                    facts.caps.push(crate::facts::query::RowCapFacts {
                        percent,
                        count: count.and_then(written_count),
                        offset_only: count.is_none(),
                    })
                }
                RowStep::Table(_) => {}
                RowStep::Cte { scope, .. } => {
                    next = ctes.iter().find(|cte| cte.scope == scope).and_then(|cte| {
                        match &cte.body {
                            CteBody::NonRecursive(body) => Some(body.as_ref()),
                            CteBody::Recursive { .. } => None,
                        }
                    });
                }
            }
        }
        match next {
            Some(body) => query = body,
            None => break,
        }
    }
    Some(facts)
}

// ── T-SQL table hints — public projection ──

/// Fold the IR `RelPlan` tree, collecting every T-SQL table hint
/// (`RelPlan::Scan.modifier.table_hints` and `RelPlan::Insert.target_hints`)
/// into a flat list of public [`crate::facts::query::TableHintFact`].
///
/// Single projection point at the facts boundary. The IR-internal
/// [`crate::ir::plan::ScanTableHintKind`] (22 variants) collapses to the
/// curated public [`crate::facts::query::MssqlTableHintKind`] (6 arms) here.
fn project_table_hints(plan: &RelPlan) -> Vec<crate::facts::query::TableHintFact> {
    use crate::ir::plan::{ScanTableHint, ScanTableHintKind};
    use crate::ir::visitor::{walk_rel_plan, RelPlanVisitor};

    struct Collector<'a> {
        hits: Vec<crate::facts::query::TableHintFact>,
        _src: std::marker::PhantomData<&'a ()>,
    }

    impl<'a> RelPlanVisitor<'a> for Collector<'a> {
        fn visit_rel_plan(&mut self, plan: &'a RelPlan) {
            // Selective on Scan / Insert. Recursion to children is
            // delegated to `walk_rel_plan` which handles every closed
            // RelPlan variant.
            if let RelPlan::Scan {
                table, modifier, ..
            } = plan
            {
                for hint in &modifier.table_hints {
                    self.hits.push(make_hint_fact(table, hint));
                }
            }
            if let RelPlan::Insert {
                target,
                target_hints,
                ..
            } = plan
            {
                for hint in target_hints {
                    self.hits.push(make_hint_fact(target, hint));
                }
            }
            walk_rel_plan(self, plan);
        }
    }

    fn make_hint_fact(
        table: &crate::context::node_metadata::TableRef,
        hint: &ScanTableHint,
    ) -> crate::facts::query::TableHintFact {
        crate::facts::query::TableHintFact {
            kind: project_table_hint_kind(&hint.kind),
            table: project_metadata_table_ref(table, Some(table.span.unwrap_or(hint.span))),
            source_span: hint.span,
        }
    }

    /// Map the IR's 22-variant closed enum onto the public curated
    /// enum. Rule-relevant SQL keywords project 1:1 (preserving the
    /// keyword name so YAML can distinguish `NOLOCK` from
    /// `READUNCOMMITTED` if a future rule needs to); the remaining
    /// hints fold into the catch-all public `Other` arm so the
    /// substrate doesn't grow per non-rule-relevant keyword.
    /// Exhaustive `match` — every IR variant is enumerated so adding
    /// one to the IR breaks the build until the projection classifies
    /// it deliberately.
    fn project_table_hint_kind(
        kind: &ScanTableHintKind,
    ) -> crate::facts::query::MssqlTableHintKind {
        use crate::facts::query::MssqlTableHintKind as P;
        match kind {
            ScanTableHintKind::NoLock => P::NoLock,
            ScanTableHintKind::ReadUncommitted => P::ReadUncommitted,
            ScanTableHintKind::TabLockX => P::TabLockX,
            ScanTableHintKind::XLock => P::XLock,
            ScanTableHintKind::ForceScan => P::ForceScan,
            ScanTableHintKind::ForceSeek { .. } => P::ForceSeek,
            ScanTableHintKind::Index { .. } => P::Index,
            ScanTableHintKind::ReadCommitted
            | ScanTableHintKind::ReadCommittedLock
            | ScanTableHintKind::RepeatableRead
            | ScanTableHintKind::Serializable
            | ScanTableHintKind::Snapshot
            | ScanTableHintKind::UpdLock
            | ScanTableHintKind::HoldLock
            | ScanTableHintKind::RowLock
            | ScanTableHintKind::PagLock
            | ScanTableHintKind::TabLock
            | ScanTableHintKind::ReadPast
            | ScanTableHintKind::NoWait
            | ScanTableHintKind::NoExpand
            | ScanTableHintKind::KeepIdentity
            | ScanTableHintKind::KeepDefaults
            | ScanTableHintKind::IgnoreConstraints
            | ScanTableHintKind::IgnoreTriggers
            | ScanTableHintKind::OtherSimple
            | ScanTableHintKind::KeyValue { .. } => P::Other,
        }
    }

    let mut collector = Collector {
        hits: Vec::new(),
        _src: std::marker::PhantomData,
    };
    collector.visit_rel_plan(plan);
    collector.hits
}
