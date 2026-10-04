// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Relational IR for Lexega.
//!
//! # What lives here
//!
//! - [`plan::RelPlan`] — the relational-algebra tree for query-bearing statements,
//!   closed-enum. [`ddl_plan::DdlPlan`] is the disjoint plan for every
//!   non-query statement; [`statement_plan::StatementPlan`] is their sum.
//! - [`scalar::ScalarExpr`] — IR scalar expressions, separate from `AstExpr`:
//!   names resolved to [`column::ColumnId`], correlation made explicit via
//!   [`scalar::ScalarExpr::OuterRef`].
//! - **Lowering** — [`lower_dispatch::lower_stmt`] turns an `AstStmt` into a
//!   `StatementPlan`; [`lower::lower_query`] and the per-object `lower_*` entry
//!   points cover the relational and DDL arms respectively.
//! - **Folds over the plan** — predicate extraction, correlation, outer-ref
//!   resolution and the derived-fact surface ([`derived_facts`]) all walk
//!   `RelPlan`.
//! - **Typed degradation** — ill-formed-but-parsed input becomes a typed
//!   [`plan::RelPlan::InvalidInput`]; upstream parse failure becomes
//!   [`plan::RelPlan::ParseRecovery`]; genuine coverage gaps become
//!   [`plan::RelPlan::Opaque`] carrying a discriminated [`strict::OpaqueReason`].
//!   [`strict::StrictMode`] controls whether opacity is tolerated or an error.
//!
//! # Known limits
//!
//! Listed here so they are not mistaken for finished work:
//!
//! - [`scalar::SqlType`] is a `{ repr: String }` stub; there is no type lattice
//!   (intentional — Lexega is a governance/lineage processor, not an optimizer).
//! - [`plan::ScriptPlan`] is a reserved stub: there is no cross-statement /
//!   script-level plan; `StatementPlan` is per-statement.
//! - No plan-level canonicalization rewrites (no decorrelation, no join
//!   reordering). Also intentional.
//!
//! # Stability
//!
//! `RelPlan`, `ScalarExpr`, `OpaqueReason`, and their sub-enums are **closed**.
//! A new variant is a deliberate design change; the exhaustive
//! matches in `schema.rs`, `visitor.rs`, `pretty.rs`, and `outer_refs.rs` fail
//! compilation on drift.
pub mod account_plan;
pub mod account_provisioning_plan;
pub mod add_signature_plan;
pub mod alert_plan;
pub mod always_true;
pub mod application_plan;
pub mod assembly_plan;
pub mod backup_plan;
pub mod catalog;
pub mod catalog_context;
pub mod catalog_plan;
pub mod column;
pub mod compute_pool_plan;
pub mod connection_plan;
pub mod constraint_types;
pub mod correlation;
pub mod cortex_search_service_plan;
pub mod data_metric_function_plan;
pub mod database_plan;
pub mod datashare_plan;
pub mod dbcc_plan;
pub mod ddl_plan;
pub mod derived_facts;
pub mod dynamic_sql;
pub mod dynamic_table_plan;
pub mod event_plan;
pub mod expression_fact;
pub mod external_data_source_plan;
pub mod external_function_plan;
pub mod external_location_plan;
pub mod file_format_plan;
pub mod fingerprint;
pub mod flow_plan;
pub mod foreign_server_plan;
pub mod foreign_table_plan;
pub mod function_plan;
pub mod git_repository_plan;
pub mod handler_plan;
pub mod image_repository_plan;
pub mod import_foreign_schema_plan;
pub mod integration_plan;
pub mod invalid_input;
pub mod key_backup_plan;
pub mod key_management_plan;
pub mod listing_plan;
pub mod lower;
pub mod lower_ddl;
pub mod lower_dispatch;
pub mod lower_inputs;
pub mod match_recognize_pattern;
pub mod model_catalog;
pub mod mysql_load_data_plan;
pub mod network_rule_plan;
pub mod normalize;
pub mod notebook_plan;
pub mod outer_refs;
pub mod pg_copy_plan;
pub mod pg_default_privileges_plan;
pub mod pipe_plan;
pub mod plan;
pub mod policy_attachment_plan;
pub mod policy_facts;
pub mod policy_plan;
pub mod predicate_atom;
pub mod predicate_extraction;
pub mod pretty;
pub mod privilege_plan;
pub mod procedure_plan;
pub mod queries;
pub mod replication_failover_group_plan;
pub mod resource_monitor_plan;
pub mod restore_plan;
pub mod scalar;
pub mod schema;
pub mod schema_plan;
pub mod secret_plan;
pub mod security_policy_plan;
pub mod semantic_view_plan;
pub mod server_configuration_plan;
pub mod service_master_key_plan;
pub mod service_plan;
pub mod session_plan;
pub mod share_plan;
pub mod span_extract;
pub mod stage_file_command_plan;
pub mod stage_plan;
pub mod statement_facts;
pub mod statement_plan;
pub mod storage_credential_plan;
pub mod stream_plan;
pub mod streamlit_plan;
pub mod strict;
pub mod synonym_plan;
pub mod table_maintenance_plan;
pub mod table_plan;
pub mod tag_plan;
pub mod task_plan;
pub mod temporal_gating;
#[cfg(test)]
mod tests;
pub mod trigger_create_plan;
pub mod types;
pub mod use_plan;
pub mod user_mapping_plan;
pub mod utils;
pub mod visitor;
pub mod volatile_expr;
pub mod volume_plan;
pub mod warehouse_plan;
pub use account_plan::{lower_alter_account_params_to_plan, AccountParameterIr, AccountPlan};
pub use account_provisioning_plan::{
    lower_create_account_to_plan, lower_create_managed_account_to_plan, lower_drop_account_to_plan,
    lower_drop_managed_account_to_plan, AccountProvisioningAction, AccountProvisioningOptions,
    AccountProvisioningTarget, ManagedAccountPlan, OrgAccountPlan,
};
pub use add_signature_plan::{lower_add_signature_to_plan, MssqlAddSignaturePlan};
pub use alert_plan::{
    lower_alter_alert_to_alert_plan, lower_create_alert_to_alert_plan,
    lower_drop_alert_to_alert_plan, AlertAction, AlertAlterActionKindIr, AlertAlterActionShape,
    AlertBodyParseStatusIr, AlertCreateOptionsShape, AlertOptions, AlertPlan, AlertTarget,
};
pub(crate) use application_plan::ApplicationAlterActionIr;
pub use application_plan::{
    lower_alter_application_package_to_plan, lower_alter_application_to_plan,
    lower_create_application_package_to_plan, lower_create_application_to_plan,
    lower_drop_application_package_to_plan, lower_drop_application_to_plan, ApplicationAction,
    ApplicationOptions, ApplicationPackagePlan, ApplicationPlan, ApplicationTarget,
};
pub use assembly_plan::{lower_assembly_to_plan, MssqlAssemblyPlan};
pub use backup_plan::{
    lower_backup_to_backup_plan, BackupDestinationKind, BackupTargetKind, MssqlBackupPlan,
};
pub use catalog::{
    ArgShape, CatalogDialect, Determinism, FunctionCatalog, FunctionId, FunctionKind,
    FunctionSignature, NullBehavior,
};
pub use catalog_context::{
    CatalogContext, ColumnConstraints, ColumnMetadata, DefaultExpr, EmptyCatalogContext, FkEdge,
    FkTarget, IndexedCatalogContext, IrTableKind, PolicyKind, PolicyRef, TableColumns, TagRef,
};
pub(crate) use catalog_plan::IrCatalogAlterAction;
pub use catalog_plan::{
    lower_alter_catalog_to_catalog_plan, lower_create_catalog_to_catalog_plan,
    lower_drop_catalog_to_catalog_plan, CatalogAction, CatalogOptions, CatalogPlan, CatalogTarget,
};
pub use column::*;
pub(crate) use compute_pool_plan::ComputePoolAlterActionIr;
pub use compute_pool_plan::{
    lower_alter_compute_pool_to_compute_pool_plan, lower_create_compute_pool_to_compute_pool_plan,
    lower_drop_compute_pool_to_compute_pool_plan, ComputePoolAction, ComputePoolOptions,
    ComputePoolPlan, ComputePoolTarget,
};
pub(crate) use connection_plan::IrConnectionAlterAction;
pub use connection_plan::{
    lower_alter_connection_to_connection_plan, lower_create_connection_to_connection_plan,
    lower_drop_connection_to_connection_plan, ConnectionAction, ConnectionOptions, ConnectionPlan,
    ConnectionTarget,
};
pub(crate) use cortex_search_service_plan::CortexSearchServiceAlterActionIr;
pub use cortex_search_service_plan::{
    lower_alter_cortex_search_service_to_plan, lower_create_cortex_search_service_to_plan,
    lower_drop_cortex_search_service_to_plan, CortexSearchServiceAction,
    CortexSearchServiceOptions, CortexSearchServicePlan, CortexSearchServiceTarget,
};
pub use data_metric_function_plan::{
    lower_create_data_metric_function_to_plan, lower_drop_data_metric_function_to_plan,
    DataMetricFunctionAction, DataMetricFunctionOptions, DataMetricFunctionPlan,
    DataMetricFunctionTarget,
};
pub use database_plan::{
    lower_alter_database_to_database_plan, lower_create_database_to_database_plan,
    lower_drop_database_to_database_plan, DatabaseAction, DatabaseOptions, DatabasePlan,
    DatabaseTarget,
};
pub(crate) use database_plan::{
    IrDatabaseAlterAction, IrDatabaseAlterActionDetail, IrDatabaseCreateOrigin, IrDatabaseProperty,
};
pub use datashare_plan::{
    lower_alter_datashare_to_datashare_plan, lower_create_datashare_to_datashare_plan,
    DatashareAction, DatashareObjectChange, DatashareObjectKind, DatashareOptions, DatasharePlan,
    DatashareTarget,
};
pub use dbcc_plan::{lower_dbcc_to_dbcc_plan, MssqlDbccPlan};
pub use ddl_plan::DdlPlan;
pub use derived_facts::{
    derive_facts_from_plan, derive_scan_modifier_facts, ChangesTag, DerivedFacts, OriginTag,
    ScanModifierFact, TimeTravelTag,
};
pub use dynamic_table_plan::{
    lower_alter_dynamic_table_to_dynamic_table_plan,
    lower_create_dynamic_table_to_dynamic_table_plan,
    lower_drop_dynamic_table_to_dynamic_table_plan, DynamicTableAction, DynamicTableAlterFlags,
    DynamicTableOptions, DynamicTablePlan, DynamicTableTarget,
};
pub(crate) use event_plan::lower_definer;
pub use event_plan::{
    lower_alter_event_to_plan, lower_create_event_to_plan, DefinerLowered, EventAction, EventPlan,
};
pub use external_data_source_plan::{
    lower_alter_external_data_source_to_plan, lower_create_external_data_source_to_plan,
    ExternalDataSourceAction, ExternalDataSourcePlan, ExternalDataSourceTypeKind,
};
pub use external_function_plan::{
    lower_create_external_function_to_plan, ExternalFunctionPlan, ExternalFunctionTarget,
};
pub(crate) use external_location_plan::IrExternalLocationAlterAction;
pub use external_location_plan::{
    lower_alter_external_location_to_external_location_plan,
    lower_create_external_location_to_external_location_plan,
    lower_drop_external_location_to_external_location_plan, ExternalLocationAction,
    ExternalLocationOptions, ExternalLocationPlan, ExternalLocationTarget,
};
pub use file_format_plan::{
    lower_alter_file_format_to_plan, lower_create_file_format_to_plan,
    lower_drop_file_format_to_plan, FileFormatAction, FileFormatOptions, FileFormatPlan,
    FileFormatTarget,
};
pub use flow_plan::{lower_create_flow_to_flow_plan, FlowAction, FlowPlan};
pub use foreign_server_plan::{
    lower_alter_foreign_server_to_plan, lower_create_foreign_server_to_plan, ForeignServerAction,
    ForeignServerPlan,
};
pub use foreign_table_plan::{lower_create_foreign_table_to_plan, ForeignTablePlan};
pub use function_plan::{
    lower_alter_function_to_function_plan, lower_create_function_to_function_plan,
    lower_create_table_function_to_function_plan, lower_drop_function_to_function_plan,
    FunctionAction, FunctionAlterActionKindIr, FunctionAlterActionShape, FunctionBodyShape,
    FunctionBodyStatementKindIr, FunctionOptions, FunctionPlan, FunctionPropertiesShape,
    FunctionPropertyKeyIr, FunctionTarget,
};
pub(crate) use git_repository_plan::GitRepositoryAlterActionIr;
pub use git_repository_plan::{
    lower_alter_git_repository_to_git_repository_plan,
    lower_create_git_repository_to_git_repository_plan,
    lower_drop_git_repository_to_git_repository_plan, GitRepositoryAction, GitRepositoryOptions,
    GitRepositoryPlan, GitRepositoryTarget,
};
pub use handler_plan::{
    lower_declare_handler_to_handler_plan, HandlerBodyShapeIr, HandlerBodyStatementKindIr,
    HandlerConditionIr, HandlerPlan, HandlerTypeIr,
};
pub(crate) use image_repository_plan::ImageRepositoryAlterActionIr;
pub use image_repository_plan::{
    lower_alter_image_repository_to_image_repository_plan,
    lower_create_image_repository_to_image_repository_plan,
    lower_drop_image_repository_to_image_repository_plan, ImageRepositoryAction,
    ImageRepositoryOptions, ImageRepositoryPlan, ImageRepositoryTarget,
};
pub use import_foreign_schema_plan::{
    lower_import_foreign_schema_to_plan, ImportFilterMode, ImportForeignSchemaPlan,
};
pub use integration_plan::{
    lower_alter_api_integration_to_integration_plan,
    lower_alter_external_access_integration_to_integration_plan,
    lower_alter_notification_integration_to_integration_plan,
    lower_alter_security_integration_to_integration_plan,
    lower_alter_storage_integration_to_integration_plan,
    lower_create_api_integration_to_integration_plan,
    lower_create_external_access_integration_to_integration_plan,
    lower_create_notification_integration_to_integration_plan,
    lower_create_security_integration_to_integration_plan,
    lower_create_storage_integration_to_integration_plan,
    lower_drop_api_integration_to_integration_plan,
    lower_drop_external_access_integration_to_integration_plan,
    lower_drop_notification_integration_to_integration_plan,
    lower_drop_security_integration_to_integration_plan,
    lower_drop_storage_integration_to_integration_plan, ApiIntegrationShape,
    ExternalAccessIntegrationShape, IntegrationAction, IntegrationKindIr, IntegrationPlan,
    IntegrationPlanVariant, NotificationIntegrationShape, SecurityIntegrationPropertyIr,
    SecurityIntegrationShape, StorageIntegrationShape,
};
pub use key_backup_plan::{lower_key_backup_to_plan, MssqlKeyBackupPlan};
pub use key_management_plan::{lower_key_management_to_plan, MssqlKeyManagementPlan};
pub(crate) use listing_plan::ListingAlterActionIr;
pub use listing_plan::{
    lower_alter_listing_to_plan, lower_create_listing_to_plan, lower_drop_listing_to_plan,
    ListingAction, ListingOptions, ListingPlan, ListingTarget,
};
pub use lower::{
    lower_query, lower_query_full, lower_query_full_with_bindings,
    lower_query_full_with_bindings_and_models,
    lower_query_full_with_bindings_models_and_policy_facts, lower_query_with_catalog,
    lower_query_with_catalog_and_session, LowerError, LowerErrorKind,
};
pub use lower_ddl::lower_ddl_stmt;
pub use lower_dispatch::lower_stmt;
pub use lower_inputs::{IrLowerInputs, LoweredStatement};
pub use model_catalog::{ModelCatalog, ModelEntry};
pub use mysql_load_data_plan::{lower_mysql_load_data_to_plan, MysqlLoadDataPlan};
pub use network_rule_plan::{
    lower_alter_network_rule_to_network_rule_plan, lower_create_network_rule_to_network_rule_plan,
    lower_drop_network_rule_to_network_rule_plan, NetworkRuleAction, NetworkRuleOptions,
    NetworkRulePlan, NetworkRuleTarget,
};
pub use normalize::{
    is_ignore_quoted_active, normalize_identifier, reset_identifier_case_mode_cache,
    set_normalization_dialect, CaseFold, NormalizationConfig, QuotedHandling,
};
pub(crate) use notebook_plan::NotebookAlterActionIr;
pub use notebook_plan::{
    lower_alter_notebook_to_notebook_plan, lower_create_notebook_to_notebook_plan,
    lower_drop_notebook_to_notebook_plan, NotebookAction, NotebookOptions, NotebookPlan,
    NotebookTarget,
};
pub use pg_copy_plan::{
    lower_pg_copy_to_pg_copy_plan, PgCopyDirection, PgCopyPlan, PgCopySubjectTable,
    PgCopyTargetKind,
};
pub use pg_default_privileges_plan::{
    lower_pg_default_privileges_to_plan, PgDefaultPrivilegesPlan,
};
pub use pipe_plan::{
    lower_alter_pipe_to_pipe_plan, lower_create_pipe_to_pipe_plan, lower_drop_pipe_to_pipe_plan,
    PipeAction, PipeAlterFlags, PipeCreateFlags, PipeOptions, PipePlan, PipeTarget,
};
pub use plan::*;
pub use policy_attachment_plan::{
    PolicyAttachmentPlan, PolicyAttachmentPrincipal, PolicyAttachmentTarget, PolicyAttachmentVerb,
};
pub use policy_facts::{
    MaskingPolicyFact, PgPolicyFact, PolicyStatementFacts, RowAccessPolicyFact,
};
pub use policy_plan::{
    lower_alter_aggregation_policy_to_policy_plan,
    lower_alter_authentication_policy_to_policy_plan, lower_alter_join_policy_to_policy_plan,
    lower_alter_masking_policy_to_policy_plan, lower_alter_network_policy_to_policy_plan,
    lower_alter_password_policy_to_policy_plan, lower_alter_pg_policy_to_policy_plan,
    lower_alter_projection_policy_to_policy_plan, lower_alter_row_access_policy_to_policy_plan,
    lower_alter_session_policy_to_policy_plan, lower_create_aggregation_policy_to_policy_plan,
    lower_create_authentication_policy_to_policy_plan, lower_create_join_policy_to_policy_plan,
    lower_create_masking_policy_to_policy_plan, lower_create_network_policy_to_policy_plan,
    lower_create_password_policy_to_policy_plan, lower_create_pg_policy_to_policy_plan,
    lower_create_projection_policy_to_policy_plan, lower_create_row_access_policy_to_policy_plan,
    lower_create_session_policy_to_policy_plan, lower_drop_aggregation_policy_to_policy_plan,
    lower_drop_authentication_policy_to_policy_plan, lower_drop_join_policy_to_policy_plan,
    lower_drop_masking_policy_to_policy_plan, lower_drop_network_policy_to_policy_plan,
    lower_drop_password_policy_to_policy_plan, lower_drop_pg_policy_to_policy_plan,
    lower_drop_projection_policy_to_policy_plan, lower_drop_row_access_policy_to_policy_plan,
    lower_drop_session_policy_to_policy_plan, AggregationPolicyShape, AuthenticationPolicyShape,
    JoinPolicyShape, MaskingArgumentIr, MaskingPolicyShape, NetworkPolicyShape,
    PasswordPolicyFieldIr, PasswordPolicyShape, PgPolicyCommandIr, PgPolicyPermissivenessIr,
    PolicyAction, PolicyCommentAction, PolicyKindIr, PolicyPlan, PolicyPlanVariant,
    ProjectionPolicyShape, RowAccessArgumentIr, RowAccessPolicyShape, SessionPolicyFieldIr,
    SessionPolicyShape,
};
pub use pretty::PrettyPlan;
pub use privilege_plan::{
    lower_alter_authorization_to_privilege_plan, lower_deny_to_privilege_plan,
    lower_grant_to_privilege_plan, lower_revoke_to_privilege_plan, PrivilegeAction,
    PrivilegeGrantee, PrivilegeObject, PrivilegeObjectScope, PrivilegeOptions, PrivilegePlan,
    PrivilegeSet, PrivilegeShape,
};
pub use procedure_plan::{
    lower_alter_procedure_to_procedure_plan, lower_create_procedure_to_procedure_plan,
    lower_drop_procedure_to_procedure_plan, ProcedureAction, ProcedureAlterActionKindIr,
    ProcedureAlterActionShape, ProcedureBodyShape, ProcedureBodyStatementKindIr, ProcedureOptions,
    ProcedurePlan, ProcedurePropertiesShape, ProcedurePropertyKeyIr, ProcedureTarget,
};
pub use replication_failover_group_plan::{
    lower_create_replication_failover_group_to_plan, lower_drop_replication_failover_group_to_plan,
    ReplicationFailoverGroupAction, ReplicationFailoverGroupOptions, ReplicationFailoverGroupPlan,
    ReplicationFailoverGroupTarget, ReplicationGroupType,
};
pub use resource_monitor_plan::{
    lower_alter_resource_monitor_to_resource_monitor_plan,
    lower_create_resource_monitor_to_resource_monitor_plan,
    lower_drop_resource_monitor_to_resource_monitor_plan, ResourceMonitorAction,
    ResourceMonitorOptions, ResourceMonitorPlan, ResourceMonitorTarget, ResourceMonitorTriggerIr,
};
pub use restore_plan::{
    lower_restore_db_to_plan, MssqlRestorePlan, RestoreSourceKind, RestoreTargetKind,
};
pub use scalar::*;
pub use schema_plan::{
    lower_alter_schema_to_schema_plan, lower_create_schema_to_schema_plan,
    lower_drop_schema_to_schema_plan, SchemaAction, SchemaOptions, SchemaPlan, SchemaTarget,
};
pub(crate) use schema_plan::{IrSchemaAlterAction, IrSchemaCreateOrigin};
pub use secret_plan::{
    lower_alter_secret_to_secret_plan, lower_create_secret_to_secret_plan,
    lower_drop_secret_to_secret_plan, SecretAction, SecretOptions, SecretPlan, SecretTarget,
};
pub use security_policy_plan::{lower_security_policy_to_plan, MssqlSecurityPolicyPlan};
pub(crate) use semantic_view_plan::SemanticViewAlterActionIr;
pub use semantic_view_plan::{
    lower_alter_semantic_view_to_semantic_view_plan,
    lower_create_semantic_view_to_semantic_view_plan,
    lower_drop_semantic_view_to_semantic_view_plan, SemanticViewAction, SemanticViewBaseTable,
    SemanticViewOptions, SemanticViewPlan, SemanticViewTarget,
};
pub use server_configuration_plan::{
    lower_mssql_alter_server_configuration_to_plan, ServerConfigurationPlan,
};
pub use service_master_key_plan::{lower_service_master_key_to_plan, MssqlServiceMasterKeyPlan};
pub(crate) use service_plan::ServiceAlterActionIr;
pub use service_plan::{
    lower_alter_service_to_service_plan, lower_create_service_to_service_plan,
    lower_drop_service_to_service_plan, ServiceAction, ServiceOptions, ServicePlan, ServiceTarget,
};
pub use session_plan::{
    lower_alter_session_to_session_plan, SessionAction, SessionParamIr, SessionPlan,
};
pub use share_plan::{
    lower_alter_share_to_share_plan, lower_create_share_to_share_plan,
    lower_drop_share_to_share_plan, ShareAction, ShareOptions, SharePlan, ShareTarget,
};
pub use stage_file_command_plan::{
    lower_stage_file_command_to_plan, StageFileCommandPlan, StageFileOperation,
};
pub use stage_plan::{
    lower_alter_stage_to_stage_plan, lower_copy_into_location_to_stage_plan,
    lower_copy_into_table_to_stage_plan, lower_create_stage_to_stage_plan,
    lower_drop_stage_to_stage_plan, lower_redshift_copy_to_stage_plan, lower_unload_to_stage_plan,
    StageAction, StageCredentialOption, StageCredentialValue, StageCredentials, StagePlan,
};
pub use statement_facts::{
    ForUpdateFact, IntoVarTarget, JinjaFragmentRef, LockStrength, OutputFormat, SelectAsKind,
    StatementFacts, WaitPolicy,
};
pub use statement_plan::StatementPlan;
pub(crate) use storage_credential_plan::IrStorageCredentialAlterAction;
pub use storage_credential_plan::{
    lower_alter_storage_credential_to_storage_credential_plan,
    lower_create_storage_credential_to_storage_credential_plan,
    lower_drop_storage_credential_to_storage_credential_plan, StorageCredentialAction,
    StorageCredentialKindIr, StorageCredentialPlan, StorageCredentialProvider,
    StorageCredentialProviderVariant,
};
pub use stream_plan::{
    lower_create_stream_to_stream_plan, lower_drop_stream_to_stream_plan, StreamAction,
    StreamCreateFlags, StreamOptions, StreamPlan, StreamTarget,
};
pub(crate) use streamlit_plan::StreamlitAlterActionIr;
pub use streamlit_plan::{
    lower_alter_streamlit_to_streamlit_plan, lower_create_streamlit_to_streamlit_plan,
    lower_drop_streamlit_to_streamlit_plan, StreamlitAction, StreamlitOptions, StreamlitPlan,
    StreamlitTarget,
};
pub use strict::*;
pub use synonym_plan::{lower_create_synonym_to_plan, SynonymPlan};
pub use table_maintenance_plan::{
    lower_cache_table_to_table_maintenance_plan, lower_describe_history_to_table_maintenance_plan,
    lower_optimize_to_table_maintenance_plan, lower_repair_table_to_table_maintenance_plan,
    lower_restore_to_table_maintenance_plan, lower_uncache_table_to_table_maintenance_plan,
    lower_vacuum_to_table_maintenance_plan, CacheOptions, RepairOptions, TableMaintenanceKind,
    TableMaintenancePlan, VacuumOptions,
};
pub use table_plan::{
    lower_alter_table_to_table_plan, lower_create_table_to_table_plan,
    lower_drop_all_row_access_policies_to_table_plan, lower_drop_table_to_table_plan,
    lower_mysql_rename_table_to_table_plan, lower_truncate_to_table_plan, TableAction,
    TableAlterFlags, TableOptions, TablePlan, TableRenamePairIr, TableTarget,
};
pub(crate) use table_plan::{
    IrBackupMode, IrCloneShape, IrCreateTableKind, IrDistStyle, IrSortKeySpec, IrTableAlterAction,
};
pub use tag_plan::{
    lower_alter_tag_to_tag_plan, lower_create_tag_to_tag_plan, lower_drop_tag_to_tag_plan,
    lower_undrop_tag_to_tag_plan, TagAction, TagAlterActionIr, TagOptions, TagPlan, TagPolicyRefIr,
    TagTarget,
};
pub use task_plan::{
    lower_alter_task_to_task_plan, lower_create_task_to_task_plan, lower_drop_task_to_task_plan,
    TaskAction, TaskAlterActionKindIr, TaskAlterActionShape, TaskBodyParseStatusIr,
    TaskCreateOptionsShape, TaskOptions, TaskOverlapPolicyIr, TaskPlan, TaskTarget,
};
pub use trigger_create_plan::{lower_create_mysql_trigger_to_plan, TriggerCreatePlan};
pub use types::SessionContext;
pub use use_plan::{lower_use_to_use_plan, UseKind, UsePlan, UseTarget};
pub use user_mapping_plan::{
    lower_alter_user_mapping_to_plan, lower_create_user_mapping_to_plan,
    lower_drop_user_mapping_to_plan, UserMappingAction, UserMappingOptionIr, UserMappingPlan,
};
pub use utils::slice_span;
pub use visitor::{
    walk_rel_plan, walk_rel_plan_mut, walk_scalar_expr, walk_scalar_expr_mut,
    walk_scalar_expr_standalone, walk_scalar_expr_standalone_mut, RelPlanMutator, RelPlanVisitor,
    ScalarExprMutator, ScalarExprVisitor,
};
pub use volume_plan::{
    lower_alter_volume_to_volume_plan, lower_create_volume_to_volume_plan,
    lower_drop_volume_to_volume_plan, VolumeAction, VolumeOptions, VolumePlan, VolumeTarget,
};
pub(crate) use volume_plan::{IrStorageLocation, IrVolumeAlterAction};
pub use warehouse_plan::{
    lower_alter_warehouse_to_warehouse_plan, lower_create_warehouse_to_warehouse_plan,
    lower_drop_warehouse_to_warehouse_plan, WarehouseAction, WarehouseAlterFlags,
    WarehouseCreateFlags, WarehouseOptions, WarehousePlan, WarehouseTarget,
};
