// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Public, customer-facing fact base.
//!
//! Every type re-exported from this module is part of the v1
//! contract; field renames after v1 are major-version breaking.
//!
//! Module map:
//! - [`identity`]      — `IdentName`, `TableRef`, `ColumnRef`, `ObjectRef`,
//!   `PrincipalRef`, `ScopeIdentity`, `ObjectKind`, `PrincipalKind`.
//! - [`literal`]       — `LiteralValue`, `IntervalValue`, `DataType` + variants.
//! - [`catalog`]       — `CatalogTag`, `TaintLabel`, `Nullability`, `ColumnLineage`.
//! - [`expr`]          — `Expr` AST and supporting variant payloads.
//! - [`query`]         — `QueryFacts`, `ScopeFacts`, `JoinEvent`, `PredicateEvent`,
//!   `ProjectionEvent`, `AggregateEvent`, `WindowEvent`, etc.
//! - [`ddl`]           — `DdlFacts`, `AlterChange` + sub-types, `DdlOptions`.
//! - [`privilege`]     — `PrivilegeFacts`, `Privilege`, `PrivilegeChangeKind`.
//! - [`policy`]        — `PolicyFacts`, `PolicyVariantFacts` + 8 variant structs.
//! - [`algebra`]       — `AlgebraFacts` + sub-events.
//! - [`diff`]          — `DiffFacts`, `DiffEvent`, `DiffContext`.
//! - [`script_context`]— `ScriptContext`, `EnclosingKind`.
//! - [`statement`]     — `StatementFacts`, `StatementKind`, `RiskLevel`.
//! - [`extract`]       — the plan-to-facts projections and `CatalogCtx`.
//! - [`reasoning`]     — `Reasoning` and the per-plan / per-script handles the
//!   fold consults for semantic analyses.

/// Fixed mask written over credential values in the facts copies that
/// leave the engine on an output surface. Fixed-width, so neither
/// content nor length leaks.
pub(crate) const MASKED_VALUE: &str = "****";

pub mod add_signature;
pub mod algebra;
pub mod assembly;
pub mod backup;
pub mod catalog;
pub mod category;
pub mod comment;
pub mod dbcc;
pub mod ddl;
pub mod diff;
pub mod expr;
pub mod extract;
pub mod handler;
pub mod identity;
pub mod integration;
pub mod key_backup;
pub mod key_management;
pub mod literal;
pub mod pg_copy;
pub mod pg_default_privileges;
pub mod policy;
pub mod policy_attachment;
pub mod privilege;
pub mod query;
pub mod reasoning;
pub mod restore;
pub mod script_context;
pub mod security_policy;
pub mod service_master_key;
pub mod statement;
pub mod use_stmt;

// ─────────────────────────────────────────────────────────────────────
// Top-level re-exports — the customer-API entry surface.
// ─────────────────────────────────────────────────────────────────────

pub use add_signature::{MssqlAddSignatureFacts, SignerKind as AddSignatureSignerKind};
pub use algebra::{
    AlgebraFacts, ContradictionEvent, CrossScopeContradictionEvent, RangeContradictionEvent,
    RedundancyEvent, TautologyEvent, TautologyKind, UpstreamConstraint, UpstreamFactsRef,
};
pub use assembly::{
    AssemblyAction as AssemblyActionFacts, AssemblyPermissionSet, MssqlAssemblyFacts,
};
pub use backup::{BackupDestination, BackupTarget, MssqlBackupFacts};
pub use catalog::{
    CatalogTag, ColumnLineage, LineageHop, LineageHopKind, NonNullableReason, Nullability,
    NullableReason, TaintLabel,
};
pub use category::{category_of_kind, RuleCategory};
pub use comment::{CommentOnFacts, CommentTargetKind};
pub use dbcc::MssqlDbccFacts;
pub use ddl::{
    AddColumnFacts, AddConstraintFacts, AlterChange, AttachMaskingPolicyFacts,
    AttachRowAccessPolicyFacts, ColumnModifyChange, ColumnReference, CommentTarget,
    ConstraintAlteration, ConstraintKind, DdlAction, DdlFacts, DdlOptions, FunctionAlterAction,
    FunctionAlterActionKind, FunctionBodyFacts, FunctionBodyStatementKind, FunctionFacts,
    FunctionPropertiesFacts, FunctionPropertyKey, GeneratedKind, IdentitySpec, ModifyKind,
    OpaqueAlterReason, ProcedureAlterAction, ProcedureAlterActionKind, ProcedureBodyFacts,
    ProcedureBodyStatementKind, ProcedureExecuteAsMode, ProcedureFacts, ProcedurePropertiesFacts,
    ProcedurePropertyKey, ReferentialAction, SearchOptimizationConfig, SearchOptimizationKind,
    StageCredentialOption, StageDdlFacts, StorageCredentialChangeKind, StorageCredentialFacts,
    StorageCredentialKindFacts, StorageCredentialLiteral, StorageCredentialProviderFacts,
    StorageCredentialProviderVariantFacts, TimeTravelClause,
};
pub use diff::{
    ClauseKind, ConstraintFactArm, ConstraintFactSet, CteFact, DiffContext, DiffEvent, DiffFacts,
    DiffStatementSnapshot, DistinctChange, ExpressionContainment, ExpressionDelta,
    ExpressionDeltaKind, ExpressionPathStep, ExpressionVariant, FieldAccessStep, LimitDirection,
    OpaqueDiffReason, OutputColumnFact, ScriptShape, SelectScope, SubqueryShape, UnaryOperator,
    WriteBoundedness,
};
pub use expr::{
    BinaryOp, BinaryOpExpr, CaseBranch, CaseExpr, CastExpr, CastKind, CollectionExpr,
    CollectionKind, Expr, FieldAccessExpr, FuncCallExpr, InListExpr, IndexAccessExpr, OpaqueExpr,
    OpaqueExprReason, OuterColumnRef, ParameterKind, ParameterRef, StarExpr, StarRename,
    SubqueryExpr, SubqueryKind, UnaryOp, UnaryOpExpr, WindowExpr, WindowFunctionName,
};
pub use extract::CatalogCtx;
pub use identity::{
    IdentName, ObjectKind, ObjectRef, PrincipalKind, PrincipalRef, ScopeIdentity, TableRef,
};
pub use integration::{
    ApiIntegrationVariantFacts, ExternalAccessIntegrationVariantFacts, IntegrationFacts,
    IntegrationKind, IntegrationVariantFacts, StorageIntegrationVariantFacts,
};
pub use key_backup::{
    BackupKeyObject as KeyBackupObjectFacts, KeyBackupAction as KeyBackupActionFacts,
    MssqlKeyBackupFacts,
};
pub use key_management::{KeyManagementAction, KeyManagementKind, MssqlKeyManagementFacts};
pub use literal::{DataType, DataTypeField, DataTypeKind, IntervalValue, LiteralValue};
pub use pg_copy::{PgCopyDirection, PgCopyFacts, PgCopyTargetKind};
pub use pg_default_privileges::{
    DefaultPrivilegesAction as DefaultPrivilegesActionFacts,
    PgDefaultPrivObjectClass as PgDefaultPrivObjectClassFacts, PgDefaultPrivilegesFacts,
};
pub use policy::{
    AggregationPolicyFacts, AuthMethod, AuthenticationPolicyFacts, ClientType, IpListEntry,
    MaskingPolicyFacts, MfaEnrollmentLevel, NetworkPolicyFacts, PasswordPolicyComplexityClass,
    PasswordPolicyFacts, PasswordPolicyField, PolicyArgument, PolicyBodyOpaqueReason,
    PolicyBodySemantics, PolicyCommentChange, PolicyFacts, PolicyKind, PolicyVariantFacts,
    ProjectionPolicyFacts, RowAccessPolicyFacts, SessionPolicyFacts, SessionPolicyField,
};
pub use policy_attachment::{
    PolicyAttachmentFacts, PolicyAttachmentPrincipalKind, PolicyAttachmentTargetKind,
    PolicyAttachmentVerb,
};
pub use privilege::{Privilege, PrivilegeChangeKind, PrivilegeFacts};
pub use query::{
    AggregateEvent, AggregateFunction, ColumnConstraintAnomaly, ColumnConstraintEvent,
    DroppedObjectKind, FkRelationshipStatus, JoinColumnPair, JoinEvent, JoinKind,
    JoinPredicateEvent, LateralEvent, LimitEvent, NullsOrdering, OrTautologyEvent, OrderByEvent,
    OrderDirection, PredicateEvent, ProjectionEvent, ProjectionKind, QueryFacts, RangeBoundFact,
    ScopeFacts, ScopeKind, SetOpEvent, SetOpKind, StaleColumnReference, StaleTableReference,
    StaleTableState, StarProjectionEvent, SubqueryPosition, SubqueryRef, TableAccessKind,
    TableEvent, TypeCompatibility, WindowEvent, WindowFrame, WindowFrameBound,
    WindowFrameExclusion, WindowFrameKind,
};
pub use restore::{MssqlRestoreFacts, RestoreSource, RestoreTarget};
pub use script_context::{
    ControlFlowKind, DbtModelContext, EarlierDdl, EnclosingKind, ScriptContext, SessionContextFacts,
};
pub use security_policy::{
    MssqlSecurityPolicyFacts, PolicyState as SecurityPolicyState,
    SecurityPolicyAction as SecurityPolicyActionFacts,
};
pub use service_master_key::{
    MssqlServiceMasterKeyFacts, ServiceMasterKeyOperation as ServiceMasterKeyOperationFacts,
};
pub use statement::{RiskLevel, StatementFacts, StatementKind};
pub use use_stmt::{UseFacts, UseStatementKind, UseTargetFacts};
