// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Typed Syntax Layer - Rigid AST with explicit token ownership
//!
//! This module defines typed syntax nodes that explicitly capture structural
//! tokens (parentheses, keywords, delimiters) as token IDs. The semantic AST
//! references these syntax nodes rather than storing spans directly.
//!
//! ## Architecture
//!
//! ```text
//! Token Stream (lexer output)
//!     │
//!     ▼
//! ┌─────────────────────────────────────────────────────────┐
//! │  Typed Syntax Nodes (this module)                       │
//! │  - SyntaxParenExpr, SyntaxOverClause, etc.              │
//! │  - Each owns TokenIds for structural tokens             │
//! │  - Formatter accesses tokens via O(1) ID lookups        │
//! └─────────────────────────────────────────────────────────┘
//!     │
//!     ▼
//! ┌─────────────────────────────────────────────────────────┐
//! │  Semantic AST                                           │
//! │  - References syntax nodes via typed IDs                │
//! │  - Pure semantic representation                         │
//! │  - No token/span ownership                              │
//! └─────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Benefits
//!
//! 1. **O(1) token access**: Formatter never scans for delimiters
//! 2. **Trivia preservation**: Comments attached to tokens are never lost
//! 3. **Separation of concerns**: Syntax owns structure, AST owns semantics
//! 4. **Robust formatting**: No "find the paren inside this span" heuristics

use crate::cst::TokenId;
use crate::lexer::Span;

pub mod jinja;
pub use jinja::{
    SyntaxJinjaArg, SyntaxJinjaArgId, SyntaxJinjaArgKind, SyntaxJinjaBinaryOpTokens,
    SyntaxJinjaDelimiter, SyntaxJinjaDelimiterId, SyntaxJinjaExpr, SyntaxJinjaExprId,
    SyntaxJinjaExprKind, SyntaxJinjaFilterArgs, SyntaxJinjaInlineFragment,
    SyntaxJinjaInlineFragmentId, SyntaxJinjaInlineFragmentKind, SyntaxJinjaInterpolation,
    SyntaxJinjaInterpolationId, SyntaxJinjaStmt, SyntaxJinjaStmtId,
};

// =============================================================================
// Syntax Node IDs - Typed handles into the syntax arena
// =============================================================================

/// ID for a parenthesized expression syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxParenExprId(pub u32);

/// ID for an OVER clause syntax node (window functions)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxOverClauseId(pub u32);

/// ID for a function call syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxFunctionCallId(pub u32);

/// ID for a CAST expression syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxCastExprId(pub u32);

/// ID for a TRY_CAST expression syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxTryCastId(pub u32);

/// ID for a SAFE_CAST expression syntax node (BigQuery)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxSafeCastId(pub u32);

/// ID for a parameterized type syntax node (e.g., `ARRAY<STRING>`, `STRUCT<a INT64>`)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxParameterizedTypeId(pub u32);

/// ID of a compound interval type node in the SyntaxArena.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxCompoundIntervalId(pub u32);

/// ID for an array subscript syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxArraySubscriptId(pub u32);

/// ID for an IN list predicate syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxInListId(pub u32);

/// ID for a subquery syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxSubqueryId(pub u32);

/// ID for a statement with optional semicolon
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxStatementId(pub u32);

/// ID for an array literal syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxArrayLiteralId(pub u32);

/// ID for an object literal syntax node: {key: value, ...}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxObjectLiteralId(pub u32);

/// ID for a BETWEEN expression syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxBetweenExprId(pub u32);

/// ID for a CASE expression syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxCaseExprId(pub u32);

/// ID for an object field access with colon notation (obj:field)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxColonFieldId(pub u32);

/// ID for an object field access with bracket notation (obj["field"])
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxBracketFieldId(pub u32);

/// ID for an object field access with dot notation (expr.field)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxDotFieldId(pub u32);

/// ID for a type cast with :: operator (expr::type)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxTypeCastId(pub u32);

/// ID for an EXTRACT expression (EXTRACT(field FROM expr))
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxExtractId(pub u32);

/// ID for a POSITION expression (POSITION(needle IN haystack))
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxPositionId(pub u32);

/// ID for a TRIM expression (`TRIM([spec] [chars] FROM source)`)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxTrimId(pub u32);

/// ID for a SUBSTRING expression (SUBSTRING(source FROM start [FOR length]))
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxSubstringId(pub u32);

/// ID for a COLLATE expression (expr COLLATE 'spec')
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxCollateId(pub u32);

/// ID for an AT TIME ZONE / AT LOCAL expression
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxAtTimeZoneId(pub u32);

/// ID for a scripting variable reference (:var_name)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxScriptingVarId(pub u32);

/// ID for an IN subquery predicate (expr IN (SELECT ...))
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxInSubqueryId(pub u32);

/// ID for an EXISTS subquery predicate (`[NOT] EXISTS (SELECT ...)`)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxExistsSubqueryId(pub u32);

/// ID for a REPLACE item (SELECT * REPLACE(expr AS col))
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxReplaceItemId(pub u32);

/// ID for a DISTINCT ON clause (DISTINCT ON (expr_list))
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxDistinctOnId(pub u32);

/// ID for a row value constructor (tuple) expression: (expr, expr, ...)
/// Used as LHS in predicates like `(a, b) IN (SELECT x, y FROM t)`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxRowConstructorId(pub u32);

/// ID for a RETURNING clause (PostgreSQL)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxReturningId(pub u32);

/// ID for a RENAME item (SELECT * RENAME(col AS alias))
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxRenameItemId(pub u32);

/// ID for an EXCLUDE modifier (SELECT * EXCLUDE(...))
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxExcludeId(pub u32);

/// ID for a RENAME modifier (SELECT * RENAME(...))
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxRenameId(pub u32);

/// ID for a REPLACE modifier (SELECT * REPLACE(...))
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxReplaceId(pub u32);

/// ID for an ORDER BY item syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxOrderItemId(pub u32);

/// ID for a GROUP BY clause syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxGroupById(pub u32);

/// ID for a CALL statement syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxCallStmtId(pub u32);

/// ID for a CREATE ROW ACCESS POLICY statement syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxCreateRowAccessPolicyId(pub u32);

/// ID for a CREATE MASKING POLICY statement syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxCreateMaskingPolicyId(pub u32);

/// ID for a CREATE NETWORK POLICY statement syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxCreateNetworkPolicyId(pub u32);

/// ID for a CREATE SESSION POLICY statement syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxCreateSessionPolicyId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxAlterRowAccessPolicyStmtId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxAlterRowAccessPolicyActionId(pub u32);

/// ID for a DROP ROW ACCESS POLICY statement syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxDropRowAccessPolicyId(pub u32);

/// ID for a DROP ALL ROW ACCESS POLICIES statement syntax node (BigQuery)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxDropAllRowAccessPoliciesId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxAlterMaskingPolicyStmtId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxAlterMaskingPolicyActionId(pub u32);

/// ID for a DROP MASKING POLICY statement syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxDropMaskingPolicyId(pub u32);

/// ID for an ALTER NETWORK POLICY statement syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxAlterNetworkPolicyId(pub u32);

/// ID for an ALTER NETWORK POLICY action syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxAlterNetworkPolicyActionId(pub u32);

/// ID for an ALTER SESSION POLICY statement syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxAlterSessionPolicyStmtId(pub u32);

/// ID for an ALTER SESSION POLICY action syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxAlterSessionPolicyActionId(pub u32);

/// ID for a DROP NETWORK POLICY statement syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxDropNetworkPolicyId(pub u32);

/// ID for a DROP SESSION POLICY statement syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxDropSessionPolicyId(pub u32);

/// ID for a CREATE AUTHENTICATION POLICY statement syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxCreateAuthenticationPolicyId(pub u32);

/// ID for an ALTER AUTHENTICATION POLICY statement syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxAlterAuthenticationPolicyStmtId(pub u32);

/// ID for an ALTER AUTHENTICATION POLICY action syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxAlterAuthenticationPolicyActionId(pub u32);

/// ID for a DROP AUTHENTICATION POLICY statement syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxDropAuthenticationPolicyId(pub u32);

/// ID for a CREATE API INTEGRATION statement syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxCreateApiIntegrationId(pub u32);

/// ID for an ALTER API INTEGRATION statement syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxAlterApiIntegrationStmtId(pub u32);

/// ID for an ALTER API INTEGRATION action syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxAlterApiIntegrationActionId(pub u32);

/// ID for a DROP API INTEGRATION statement syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxDropApiIntegrationId(pub u32);

/// ID for a CREATE PASSWORD POLICY statement syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxCreatePasswordPolicyId(pub u32);

/// ID for an ALTER PASSWORD POLICY statement syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxAlterPasswordPolicyStmtId(pub u32);

/// ID for an ALTER PASSWORD POLICY action syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxAlterPasswordPolicyActionId(pub u32);

/// ID for a DROP PASSWORD POLICY statement syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxDropPasswordPolicyId(pub u32);

/// ID for a CREATE AGGREGATION POLICY statement syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxCreateAggregationPolicyId(pub u32);

/// ID for an ALTER AGGREGATION POLICY statement syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxAlterAggregationPolicyStmtId(pub u32);

/// ID for an ALTER AGGREGATION POLICY action syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxAlterAggregationPolicyActionId(pub u32);

/// ID for a DROP AGGREGATION POLICY statement syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxDropAggregationPolicyId(pub u32);

/// ID for a CREATE PROJECTION POLICY statement syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxCreateProjectionPolicyId(pub u32);

/// ID for an ALTER PROJECTION POLICY statement syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxAlterProjectionPolicyStmtId(pub u32);

/// ID for an ALTER PROJECTION POLICY action syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxAlterProjectionPolicyActionId(pub u32);

/// ID for a DROP PROJECTION POLICY statement syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxDropProjectionPolicyId(pub u32);

/// ID for a CREATE STORAGE INTEGRATION statement syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxCreateStorageIntegrationId(pub u32);

/// ID for an ALTER STORAGE INTEGRATION statement syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxAlterStorageIntegrationStmtId(pub u32);

/// ID for an ALTER STORAGE INTEGRATION action syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxAlterStorageIntegrationActionId(pub u32);

/// ID for a DROP STORAGE INTEGRATION statement syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxDropStorageIntegrationId(pub u32);

/// ID for a CREATE EXTERNAL ACCESS INTEGRATION statement syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxCreateExternalAccessIntegrationId(pub u32);

/// ID for an ALTER EXTERNAL ACCESS INTEGRATION statement syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxAlterExternalAccessIntegrationStmtId(pub u32);

/// ID for an ALTER EXTERNAL ACCESS INTEGRATION action syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxAlterExternalAccessIntegrationActionId(pub u32);

/// ID for a DROP EXTERNAL ACCESS INTEGRATION statement syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxDropExternalAccessIntegrationId(pub u32);

/// ID for a CREATE STREAM statement syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxCreateStreamId(pub u32);

/// ID for an ALTER STREAM statement syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxAlterStreamStmtId(pub u32);

/// ID for an ALTER STREAM action syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxAlterStreamActionId(pub u32);

/// ID for a DROP STREAM statement syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxDropStreamId(pub u32);

/// ID for a data type with precision syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxTypePrecisionId(pub u32);

/// ID for a data type with precision and scale syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxTypePrecisionScaleId(pub u32);

/// ID for a CTE (Common Table Expression) syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxCteId(pub u32);

/// ID for a binary operation syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxBinaryOpId(pub u32);

/// ID for a quantified subquery syntax node (`expr <op> ANY/ALL (SELECT ...)`)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxQuantifiedSubqueryId(pub u32);

/// ID for a MATCH_RECOGNIZE clause syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxMatchRecognizeId(pub u32);

/// ID for a MEASURES item in MATCH_RECOGNIZE
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxMeasureItemId(pub u32);

/// ID for a DEFINE symbol in MATCH_RECOGNIZE
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxDefineSymbolId(pub u32);

/// ID for a table reference syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxTableRefId(pub u32);

/// ID for a MERGE INSERT VALUES clause syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxMergeInsertValuesId(pub u32);

/// ID for an inline constraint syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxInlineConstraintId(pub u32);

/// ID for a VALUES clause syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxValuesId(pub u32);

/// ID for a CREATE VIEW column list syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxViewColumnListId(pub u32);

/// ID for a single CREATE VIEW column definition syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxViewColumnId(pub u32);

/// ID for a view column COMMENT attribute
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxViewColumnCommentId(pub u32);

/// ID for a view column MASKING POLICY attribute
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxViewColumnMaskingPolicyId(pub u32);

/// ID for a view column PROJECTION POLICY attribute
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxViewColumnProjectionPolicyId(pub u32);

/// ID for a view column TAG attribute
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxViewColumnTagId(pub u32);

/// ID for an ALTER TABLE statement syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxAlterTableStmtId(pub u32);

/// ID for an ALTER TABLE action-list syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxAlterTableActionListId(pub u32);

/// ID for a single ALTER TABLE action syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxAlterTableActionId(pub u32);

/// ID for an ALTER STAGE statement syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxAlterStageStmtId(pub u32);

/// ID for a single ALTER STAGE action syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxAlterStageActionId(pub u32);

/// ID for an ALTER DYNAMIC TABLE statement syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxAlterDynamicTableStmtId(pub u32);

// -- PostgreSQL utility statement CST IDs --

/// ID for a CREATE INDEX statement syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxCreateIndexStmtId(pub u32);

/// ID for a COMMENT ON statement syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxCommentOnStmtId(pub u32);

/// ID for a DO block statement syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxDoBlockStmtId(pub u32);

/// ID for a VACUUM statement syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxVacuumStmtId(pub u32);

/// ID for an ANALYZE statement syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxAnalyzeStmtId(pub u32);

/// ID for an OPTIMIZE statement syntax node (Databricks)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxOptimizeStmtId(pub u32);

/// ID for a DESCRIBE HISTORY statement syntax node (Databricks)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxDescribeHistoryStmtId(pub u32);

/// ID for a RESTORE statement syntax node (Databricks)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxRestoreStmtId(pub u32);

/// ID for a CREATE TYPE statement syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxCreateTypeStmtId(pub u32);

/// ID for an ALTER TYPE statement syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxAlterTypeStmtId(pub u32);

/// ID for a CREATE EXTENSION statement syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxCreateExtensionStmtId(pub u32);

/// ID for a CREATE SEQUENCE statement syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxCreateSequenceStmtId(pub u32);

/// ID for an ALTER SEQUENCE statement syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxAlterSequenceStmtId(pub u32);

/// ID for a CREATE TRIGGER statement syntax node (PostgreSQL)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxCreatePgTriggerStmtId(pub u32);

/// ID for an ALTER TRIGGER statement syntax node (PostgreSQL)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxAlterPgTriggerStmtId(pub u32);

/// ID for a DROP TRIGGER statement syntax node (PostgreSQL)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxDropPgTriggerStmtId(pub u32);

/// ID for a CREATE DOMAIN statement syntax node (PostgreSQL)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxCreateDomainStmtId(pub u32);

/// ID for an ALTER DOMAIN statement syntax node (PostgreSQL)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxAlterDomainStmtId(pub u32);

/// ID for a DROP DOMAIN statement syntax node (PostgreSQL)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxDropDomainStmtId(pub u32);

/// ID for a CREATE POLICY statement syntax node (PostgreSQL)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxCreatePgPolicyStmtId(pub u32);

/// ID for an ALTER POLICY statement syntax node (PostgreSQL)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxAlterPgPolicyStmtId(pub u32);

/// ID for a DROP POLICY statement syntax node (PostgreSQL)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxDropPgPolicyStmtId(pub u32);

/// ID for an ALTER INDEX statement syntax node (PostgreSQL)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxAlterIndexStmtId(pub u32);

/// ID for a REINDEX statement syntax node (PostgreSQL)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxReindexStmtId(pub u32);

/// ID for a PG PREPARE statement syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxPgPrepareStmtId(pub u32);

/// ID for a PG EXECUTE statement syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxPgExecuteStmtId(pub u32);

/// ID for a PG DEALLOCATE statement syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxPgDeallocateStmtId(pub u32);

/// ID for a PG COPY statement syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxPgCopyStmtId(pub u32);

/// ID for a PG REFRESH MATERIALIZED VIEW statement syntax node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxPgRefreshMatviewStmtId(pub u32);

/// ID for a set operator syntax node (UNION/INTERSECT/EXCEPT/MINUS [ALL|DISTINCT])
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxSetOperatorId(pub u32);

// =============================================================================
// Typed Syntax Nodes - Own structural tokens explicitly
// =============================================================================

/// Parenthesized expression: (expr)
///
/// Explicitly owns the parenthesis tokens so the formatter can:
/// 1. Emit `(` with its leading/trailing trivia
/// 2. Format the inner expression
/// 3. Emit `)` with its leading/trailing trivia
///
/// No scanning needed - direct O(1) access to both parens.
#[derive(Debug, Clone, Copy)]
pub struct SyntaxParenExpr {
    /// Opening parenthesis token
    pub l_paren: TokenId,
    /// The expression inside (references another syntax node or expression)
    pub inner_span: Span,
    /// Closing parenthesis token
    pub r_paren: TokenId,
    /// Span covering the entire parenthesized expression
    pub span: Span,
}

/// Row value constructor (tuple): (expr, expr, ...)
///
/// Used as LHS in predicates like `(a, b) IN (SELECT x, y FROM t)`.
/// SQL-92 standard row value constructors.
///
/// Explicitly owns the parenthesis tokens.
#[derive(Debug, Clone)]
pub struct SyntaxRowConstructor {
    /// Opening parenthesis token
    pub l_paren: TokenId,
    /// Comma tokens between elements (length = elements.len() - 1)
    pub commas: Vec<TokenId>,
    /// Closing parenthesis token
    pub r_paren: TokenId,
    /// Span covering the entire row constructor
    pub span: Span,
}

/// Window function OVER clause: OVER (partition_by ORDER BY frame)
///
/// Example: `SUM(amount) OVER (PARTITION BY acct_id ORDER BY ts)`
///
/// Explicitly owns:
/// - OVER keyword token
/// - Opening/closing parenthesis tokens
/// - Optional keyword tokens for PARTITION BY, ORDER BY
/// - Optional IGNORE/RESPECT NULLS tokens (before OVER)
#[derive(Debug, Clone, Copy)]
pub struct SyntaxOverClause {
    /// Optional IGNORE or RESPECT keyword token (before OVER)
    pub null_handling_keyword: Option<TokenId>,
    /// Optional NULLS keyword token (after IGNORE/RESPECT)
    pub nulls_keyword: Option<TokenId>,
    /// OVER keyword token (None for WINDOW clause definitions which have no OVER)
    pub over_keyword: Option<TokenId>,
    /// Optional opening parenthesis token (None for bare `OVER w`)
    pub l_paren: Option<TokenId>,
    /// Optional PARTITION keyword token
    pub partition_keyword: Option<TokenId>,
    /// Optional BY keyword token after PARTITION
    pub partition_by_keyword: Option<TokenId>,
    /// Optional ORDER keyword token
    pub order_keyword: Option<TokenId>,
    /// Optional BY keyword token after ORDER
    pub order_by_keyword: Option<TokenId>,
    /// Optional closing parenthesis token (None for bare `OVER w`)
    pub r_paren: Option<TokenId>,
    /// Span covering the entire OVER clause
    pub span: Span,
}

/// Function call: func_name(arg1, arg2, ...)
///
/// Explicitly owns parenthesis tokens for precise trivia handling.
#[derive(Debug, Clone, Copy)]
pub struct SyntaxFunctionCall {
    /// Optional `APPROXIMATE` keyword token preceding the function name
    /// (Redshift approximate aggregates: `APPROXIMATE COUNT(DISTINCT x)`).
    /// Owned here so the formatter emits it byte-exact, mirroring how the
    /// `DISTINCT`/`ALL` quantifier token is owned via `distinct_keyword`.
    pub approximate_keyword: Option<TokenId>,
    /// Function name token
    pub func_name: TokenId,
    /// Opening parenthesis token
    pub l_paren: TokenId,
    /// Optional DISTINCT keyword token
    pub distinct_keyword: Option<TokenId>,
    /// Closing parenthesis token
    pub r_paren: TokenId,
    /// Span covering the entire function call
    pub span: Span,
}

/// CAST expression: CAST(expr AS type)
///
/// Explicitly owns CAST keyword and parentheses.
#[derive(Debug, Clone, Copy)]
pub struct SyntaxCastExpr {
    /// CAST keyword token
    pub cast_keyword: TokenId,
    /// Opening parenthesis token
    pub l_paren: TokenId,
    /// AS keyword token
    pub as_keyword: TokenId,
    /// Closing parenthesis token
    pub r_paren: TokenId,
    /// Span covering the entire CAST expression
    pub span: Span,
}

/// TRY_CAST expression: TRY_CAST(expr AS type)
///
/// Explicitly owns TRY_CAST keyword and parentheses.
#[derive(Debug, Clone, Copy)]
pub struct SyntaxTryCast {
    /// TRY_CAST keyword token
    pub try_cast_keyword: TokenId,
    /// Opening parenthesis token
    pub l_paren: TokenId,
    /// AS keyword token
    pub as_keyword: TokenId,
    /// Closing parenthesis token
    pub r_paren: TokenId,
    /// Span covering the entire TRY_CAST expression
    pub span: Span,
}

/// SAFE_CAST expression: SAFE_CAST(expr AS type) (BigQuery)
///
/// Explicitly owns SAFE_CAST keyword and parentheses.
#[derive(Debug, Clone, Copy)]
pub struct SyntaxSafeCast {
    /// SAFE_CAST keyword token
    pub safe_cast_keyword: TokenId,
    /// Opening parenthesis token
    pub l_paren: TokenId,
    /// AS keyword token
    pub as_keyword: TokenId,
    /// Closing parenthesis token
    pub r_paren: TokenId,
    /// Span covering the entire SAFE_CAST expression
    pub span: Span,
}

/// Parameterized type: `ARRAY<STRING>`, `STRUCT<a INT64, b STRING>`
///
/// Used for BigQuery-style generic type parameters with angle brackets.
#[derive(Debug, Clone)]
pub struct SyntaxParameterizedType {
    /// Span covering the entire type (from name through closing >)
    pub span: Span,
}

/// Compound INTERVAL type: INTERVAL YEAR [(p)] [TO MONTH], INTERVAL DAY(2) TO SECOND(3), etc.
#[derive(Debug, Clone)]
pub struct SyntaxCompoundInterval {
    /// Span covering the full type from INTERVAL through the last unit/precision
    pub span: Span,
}

/// Array subscript: `expr[index]`
///
/// Explicitly owns bracket tokens.
#[derive(Debug, Clone, Copy)]
pub struct SyntaxArraySubscript {
    /// Opening bracket token
    pub l_bracket: TokenId,
    /// Closing bracket token
    pub r_bracket: TokenId,
    /// Span covering the entire subscript expression
    pub span: Span,
}

/// IN list predicate: `expr [NOT] IN (val1, val2, ...)`
///
/// Explicitly owns parentheses around the list.
#[derive(Debug, Clone, Copy)]
pub struct SyntaxInList {
    /// Optional NOT keyword token
    pub not_keyword: Option<TokenId>,
    /// IN keyword token
    pub in_keyword: TokenId,
    /// Opening parenthesis token
    pub l_paren: TokenId,
    /// Closing parenthesis token
    pub r_paren: TokenId,
    /// Span covering the entire IN predicate
    pub span: Span,
}

/// Subquery: (SELECT ...)
///
/// Explicitly owns the parentheses wrapping the subquery.
#[derive(Debug, Clone, Copy)]
pub struct SyntaxSubquery {
    /// Opening parenthesis token
    pub l_paren: TokenId,
    /// Span of the SELECT statement inside
    pub select_span: Span,
    /// Closing parenthesis token
    pub r_paren: TokenId,
    /// Span covering the entire subquery including parens
    pub span: Span,
}

/// Statement with optional trailing semicolon
///
/// Owns the semicolon token if present, providing O(1) access.
#[derive(Debug, Clone, Copy)]
pub struct SyntaxStatement {
    /// Span of the statement body (excludes semicolon)
    pub body_span: Span,
    /// Optional semicolon token
    pub semicolon: Option<TokenId>,
}

/// Array literal: [elem1, elem2, ...]
///
/// Explicitly owns bracket tokens.
#[derive(Debug, Clone, Copy)]
pub struct SyntaxArrayLiteral {
    /// Opening bracket token
    pub l_bracket: TokenId,
    /// Closing bracket token
    pub r_bracket: TokenId,
    /// Span covering the entire array literal
    pub span: Span,
}

/// Object literal: {key: value, ...} or {} for empty object
///
/// Snowflake syntax for inline object construction. Equivalent to OBJECT_CONSTRUCT().
/// Explicitly owns curly brace tokens.
#[derive(Debug, Clone, Copy)]
pub struct SyntaxObjectLiteral {
    /// Opening curly brace token
    pub l_curly: TokenId,
    /// Closing curly brace token
    pub r_curly: TokenId,
    /// Span covering the entire object literal
    pub span: Span,
}

/// BETWEEN expression: `expr [NOT] BETWEEN lower AND upper`
///
/// Explicitly owns BETWEEN and AND keywords.
#[derive(Debug, Clone, Copy)]
pub struct SyntaxBetweenExpr {
    /// Optional NOT keyword token
    pub not_keyword: Option<TokenId>,
    /// BETWEEN keyword token
    pub between_keyword: TokenId,
    /// Optional SYMMETRIC keyword token (PG-specific)
    pub symmetric_keyword: Option<TokenId>,
    /// AND keyword token
    pub and_keyword: TokenId,
    /// Span covering the entire BETWEEN expression
    pub span: Span,
}

/// CASE expression: `CASE [expr] WHEN ... THEN ... [ELSE ...] END`
///
/// Explicitly owns CASE and END keywords.
#[derive(Debug, Clone, Copy)]
pub struct SyntaxCaseExpr {
    /// CASE keyword token
    pub case_keyword: TokenId,
    /// END keyword token
    pub end_keyword: TokenId,
    /// Optional ELSE keyword token
    pub else_keyword: Option<TokenId>,
    /// Span covering the entire CASE expression
    pub span: Span,
}

/// Object field access with colon notation: obj:field
///
/// Example: `payload:customer_id`
#[derive(Debug, Clone, Copy)]
pub struct SyntaxColonField {
    /// Colon token
    pub colon: TokenId,
    /// Span covering the entire field access
    pub span: Span,
}

/// Object field access with bracket notation: obj["field"]
///
/// Example: `payload["customer_id"]`
#[derive(Debug, Clone, Copy)]
pub struct SyntaxBracketField {
    /// Opening bracket token
    pub l_bracket: TokenId,
    /// Closing bracket token
    pub r_bracket: TokenId,
    /// Span covering the entire field access
    pub span: Span,
}

/// Object field access with dot notation: expr.field
///
/// Example: `data['key'].subfield`, `func().result`
/// Used for Snowflake semi-structured data access when dot follows bracket or function call.
#[derive(Debug, Clone, Copy)]
pub struct SyntaxDotField {
    /// Dot token
    pub dot: TokenId,
    /// Span covering just the dot token
    pub span: Span,
}

/// Type cast with :: operator: expr::type
///
/// Example: `'123'::INTEGER`, `value::VARCHAR(50)`
#[derive(Debug, Clone, Copy)]
pub struct SyntaxTypeCast {
    /// Double-colon operator token
    pub double_colon: TokenId,
    /// Span covering the entire type cast
    pub span: Span,
}

/// EXTRACT expression: EXTRACT(field FROM expr)
///
/// Example: `EXTRACT(DOW FROM created_at)`, `EXTRACT(YEAR FROM order_date)`
#[derive(Debug, Clone, Copy)]
pub struct SyntaxExtract {
    /// EXTRACT identifier token (not a keyword, it's an identifier)
    pub extract_token: TokenId,
    /// Left parenthesis token
    pub lparen: TokenId,
    /// FROM keyword token (separates field from expression)
    pub from_token: TokenId,
    /// Right parenthesis token
    pub rparen: TokenId,
    /// Span covering the entire EXTRACT expression
    pub span: Span,
}

/// POSITION expression: POSITION(needle IN haystack)
///
/// Example: `POSITION('x' IN column_name)`, `POSITION(search_string IN target_string)`
#[derive(Debug, Clone, Copy)]
pub struct SyntaxPosition {
    /// POSITION identifier token
    pub position_token: TokenId,
    /// Left parenthesis token
    pub lparen: TokenId,
    /// IN keyword token (separates needle from haystack)
    pub in_token: TokenId,
    /// Right parenthesis token
    pub rparen: TokenId,
    /// Span covering the entire POSITION expression
    pub span: Span,
}

/// TRIM expression: `TRIM([BOTH|LEADING|TRAILING] [chars] FROM source)`
///
/// Example: `TRIM(BOTH 'x' FROM name)`, `TRIM(LEADING FROM name)`, `TRIM('x' FROM name)`
#[derive(Debug, Clone, Copy)]
pub struct SyntaxTrim {
    /// TRIM identifier token (not a keyword, it's an identifier)
    pub trim_token: TokenId,
    /// Left parenthesis token
    pub lparen: TokenId,
    /// FROM keyword token (separates spec/chars from the source string)
    pub from_token: TokenId,
    /// Right parenthesis token
    pub rparen: TokenId,
    /// Span covering the entire TRIM expression
    pub span: Span,
}

/// SUBSTRING expression: SUBSTRING(source FROM start [FOR length])
///
/// Example: `SUBSTRING(name FROM 2 FOR 3)`, `SUBSTRING(name FROM 2)`, `SUBSTRING(name FOR 3)`
#[derive(Debug, Clone, Copy)]
pub struct SyntaxSubstring {
    /// SUBSTRING identifier token
    pub substring_token: TokenId,
    /// Left parenthesis token
    pub lparen: TokenId,
    /// FROM keyword token (precedes the start position), if present
    pub from_token: Option<TokenId>,
    /// FOR keyword token (precedes the length), if present
    pub for_token: Option<TokenId>,
    /// Right parenthesis token
    pub rparen: TokenId,
    /// Span covering the entire SUBSTRING expression
    pub span: Span,
}

/// DISTINCT ON clause: DISTINCT ON (expr_list)
///
/// Example: `DISTINCT ON (location, date)`, `DISTINCT ON (user_id)`
#[derive(Debug, Clone, Copy)]
pub struct SyntaxDistinctOn {
    /// DISTINCT keyword token
    pub distinct_token: TokenId,
    /// ON keyword token
    pub on_token: TokenId,
    /// Left parenthesis token
    pub lparen: TokenId,
    /// Right parenthesis token
    pub rparen: TokenId,
    /// Span covering the entire DISTINCT ON clause
    pub span: Span,
}

/// RETURNING clause (PostgreSQL): RETURNING expr_list
///
/// Example: `RETURNING *`, `RETURNING id, name`, `RETURNING id + 1 AS next_id`
#[derive(Debug, Clone, Copy)]
pub struct SyntaxReturning {
    /// RETURNING keyword token
    pub returning_token: TokenId,
    /// Span covering the entire RETURNING clause
    pub span: Span,
}

/// COLLATE expression: expr COLLATE 'spec'
///
/// Example: `name COLLATE 'en-ci'`, `COLLATE(col1, 'de')`
#[derive(Debug, Clone, Copy)]
pub struct SyntaxCollate {
    /// COLLATE keyword token
    pub collate_keyword: TokenId,
    /// Collation specification string literal token
    pub spec_literal: TokenId,
    /// Span covering the entire COLLATE expression
    pub span: Span,
}

/// AT TIME ZONE expression: expr AT TIME ZONE zone_expr
/// Also covers AT LOCAL (where zone tokens are None).
///
/// Example: `ts AT TIME ZONE 'UTC'`, `ts AT LOCAL`
#[derive(Debug, Clone, Copy)]
pub struct SyntaxAtTimeZone {
    /// AT identifier token
    pub at_token: TokenId,
    /// TIME identifier token (None for AT LOCAL)
    pub time_token: Option<TokenId>,
    /// ZONE identifier token (None for AT LOCAL)
    pub zone_token: Option<TokenId>,
    /// LOCAL keyword token (None for AT TIME ZONE)
    pub local_token: Option<TokenId>,
    /// Span covering the entire AT TIME ZONE / AT LOCAL expression
    pub span: Span,
}

/// Scripting variable reference: :var_name
///
/// Example: `:my_variable`, `:result_count`
#[derive(Debug, Clone, Copy)]
pub struct SyntaxScriptingVar {
    /// Leading colon token
    pub colon: TokenId,
    /// Span covering the entire variable reference
    pub span: Span,
}

/// IN subquery predicate: `expr [NOT] IN (SELECT ...)`
///
/// Example: `id NOT IN (SELECT user_id FROM banned_users)`
#[derive(Debug, Clone, Copy)]
pub struct SyntaxInSubquery {
    /// Optional NOT keyword token
    pub not_keyword: Option<TokenId>,
    /// IN keyword token
    pub in_keyword: TokenId,
    /// Opening paren token
    pub l_paren: TokenId,
    /// Closing paren token
    pub r_paren: TokenId,
    /// Span covering the entire IN subquery predicate
    pub span: Span,
}

/// EXISTS subquery predicate: `[NOT] EXISTS (SELECT ...)`
///
/// Example: `EXISTS (SELECT 1 FROM users WHERE active = true)`
#[derive(Debug, Clone, Copy)]
pub struct SyntaxExistsSubquery {
    /// Optional NOT keyword token
    pub not_keyword: Option<TokenId>,
    /// EXISTS keyword token
    pub exists_keyword: TokenId,
    /// Opening parenthesis token
    pub lparen: TokenId,
    /// Closing parenthesis token
    pub rparen: TokenId,
    /// Span covering the entire EXISTS predicate
    pub span: Span,
}

/// REPLACE item: expr AS column
///
/// Used in SELECT * REPLACE(...) modifier.
/// Example: SELECT * REPLACE(100 AS salary, 'ACTIVE' AS status)
#[derive(Debug, Clone, Copy)]
pub struct SyntaxReplaceItem {
    /// AS keyword token
    pub as_keyword: TokenId,
    /// Span covering the entire REPLACE item
    pub span: Span,
}

/// RENAME item: `column [AS] alias`
///
/// Used in SELECT * RENAME(...) modifier.
/// Example: SELECT * RENAME(old_name AS new_name, col1 AS col2)
#[derive(Debug, Clone, Copy)]
pub struct SyntaxRenameItem {
    /// Optional AS keyword token (AS is optional in RENAME)
    pub as_keyword: Option<TokenId>,
    /// Span covering the entire RENAME item
    pub span: Span,
}

/// EXCLUDE modifier: * EXCLUDE (col1, col2, ...)
///
/// Used in SELECT * EXCLUDE(...) to exclude specific columns.
/// Example: SELECT * EXCLUDE (col1, col2), t.* EXCLUDE col1
#[derive(Debug, Clone, Copy)]
pub struct SyntaxExclude {
    /// EXCLUDE keyword token
    pub exclude_keyword: TokenId,
    /// Opening parenthesis token (if has_parens)
    pub lparen: Option<TokenId>,
    /// Closing parenthesis token (if has_parens)
    pub rparen: Option<TokenId>,
    /// Span covering the entire EXCLUDE clause
    pub span: Span,
}

/// RENAME modifier: * RENAME (old AS new, ...)
///
/// Used in SELECT * RENAME(...) to rename columns.
/// Example: SELECT * RENAME (old_name AS new_name)
#[derive(Debug, Clone, Copy)]
pub struct SyntaxRename {
    /// RENAME keyword token
    pub rename_keyword: TokenId,
    /// Opening parenthesis token (if has_parens)
    pub lparen: Option<TokenId>,
    /// Closing parenthesis token (if has_parens)
    pub rparen: Option<TokenId>,
    /// Span covering the entire RENAME clause
    pub span: Span,
}

/// REPLACE modifier: * REPLACE (expr AS col, ...)
///
/// Used in SELECT * REPLACE(...) to replace column values.
/// Example: SELECT * REPLACE (UPPER(name) AS name)
#[derive(Debug, Clone, Copy)]
pub struct SyntaxReplace {
    /// REPLACE keyword token
    pub replace_keyword: TokenId,
    /// Opening parenthesis token
    pub lparen: TokenId,
    /// Closing parenthesis token
    pub rparen: TokenId,
    /// Span covering the entire REPLACE clause
    pub span: Span,
}

/// ORDER BY item: expr [ASC|DESC] [NULLS FIRST|LAST]
///
/// Example: `ORDER BY name ASC NULLS FIRST, created_at DESC`
#[derive(Debug, Clone, Copy)]
pub struct SyntaxOrderItem {
    /// Optional ASC or DESC keyword token
    pub direction_keyword: Option<TokenId>,
    /// Optional NULLS keyword token
    pub nulls_keyword: Option<TokenId>,
    /// Optional FIRST or LAST keyword token (after NULLS)
    pub nulls_order_keyword: Option<TokenId>,
    /// Span covering the entire ORDER BY item
    pub span: Span,
}

/// GROUP BY clause: GROUP BY expr1, expr2
///
/// Example: `GROUP BY region, category`
#[derive(Debug, Clone, Copy)]
pub struct SyntaxGroupBy {
    /// GROUP keyword token
    pub group_keyword: TokenId,
    /// BY keyword token
    pub by_keyword: TokenId,
    /// Span covering the entire GROUP BY clause
    pub span: Span,
}

/// Data type with precision: VARCHAR(50), NUMBER(10)
///
/// Example: `CAST(x AS VARCHAR(100))`, `DECIMAL(10)`
#[derive(Debug, Clone, Copy)]
pub struct SyntaxTypePrecision {
    /// Opening parenthesis token
    pub l_paren: TokenId,
    /// Closing parenthesis token
    pub r_paren: TokenId,
    /// Span covering the entire type with precision
    pub span: Span,
}

/// Data type with precision and scale: NUMBER(10,2), DECIMAL(5,4)
///
/// Example: `CAST(x AS NUMBER(10,2))`, `DECIMAL(18,6)`
#[derive(Debug, Clone, Copy)]
pub struct SyntaxTypePrecisionScale {
    /// Opening parenthesis token
    pub l_paren: TokenId,
    /// Comma token between precision and scale
    pub comma: TokenId,
    /// Closing parenthesis token
    pub r_paren: TokenId,
    /// Span covering the entire type with precision and scale
    pub span: Span,
}

/// CTE (Common Table Expression): name AS (SELECT ...)
///
/// Example: `WITH cte AS (SELECT * FROM t)`
#[derive(Debug, Clone, Copy)]
pub struct SyntaxCte {
    /// AS keyword token
    pub as_keyword: TokenId,
    /// Opening parenthesis before subquery
    pub l_paren: TokenId,
    /// Closing parenthesis after subquery
    pub r_paren: TokenId,
    /// Span covering the entire CTE
    pub span: Span,
}

/// Binary operation expression: `<left> <operator> <right>`
///
/// Examples: `a + b`, `x = 10`, `name LIKE 'test%'`, `active AND verified`
///
/// Owns the operator token for structural trivia preservation.
/// The operator identity is stored separately in the semantic AST.
#[derive(Debug, Clone, Copy)]
pub struct SyntaxBinaryOp {
    /// The operator token (+, -, *, /, =, <, >, AND, OR, LIKE, etc.)
    pub op_token: TokenId,
    /// Span covering the entire binary operation expression
    pub span: Span,
}

/// Set operator: UNION [ALL|DISTINCT], INTERSECT [ALL|DISTINCT], EXCEPT [ALL|DISTINCT], MINUS
///
/// Owns the operator keyword token and optional modifier (ALL/DISTINCT) token.
/// The formatter emits these tokens directly from the source instead of synthesizing text.
///
/// Examples: `UNION ALL`, `INTERSECT DISTINCT`, `EXCEPT`, `MINUS`
#[derive(Debug, Clone, Copy)]
pub struct SyntaxSetOperator {
    /// The set operator keyword token (UNION, INTERSECT, EXCEPT, or MINUS)
    pub op_keyword: TokenId,
    /// Optional modifier keyword token (ALL or DISTINCT)
    pub modifier_keyword: Option<TokenId>,
    /// Span covering the entire set operator (keyword + optional modifier)
    pub span: Span,
}

/// Quantified subquery comparison: `<left> <op> ANY/ALL (SELECT ...)`
///
/// Example: `price < ANY (SELECT cost FROM products)`
///
/// Owns the operator and quantifier tokens for structural trivia preservation.
/// The operator identity and quantifier type are stored separately in the semantic AST.
#[derive(Debug, Clone, Copy)]
pub struct SyntaxQuantifiedSubquery {
    /// The comparison operator token (=, !=, <, <=, >, >=)
    pub op_token: TokenId,
    /// The quantifier keyword token (ANY or ALL)
    pub quantifier_keyword: TokenId,
    /// Span covering the entire quantified subquery expression
    pub span: Span,
}

// =============================================================================
// Syntax Arena - Stores all typed syntax nodes
// =============================================================================

/// MATCH_RECOGNIZE clause syntax node
///
/// Owns tokens for PATTERN and DEFINE keywords, parentheses, etc.
#[derive(Debug, Clone)]
pub struct SyntaxMatchRecognize {
    /// MATCH_RECOGNIZE keyword token
    pub match_recognize_keyword: TokenId,
    /// Opening paren after MATCH_RECOGNIZE keyword
    pub mr_lparen: TokenId,
    /// Closing paren at end of MATCH_RECOGNIZE clause
    pub mr_rparen: TokenId,
    /// Optional PARTITION keyword token
    pub partition_keyword: Option<TokenId>,
    /// BY keyword after PARTITION (if PARTITION BY present)
    pub partition_by_keyword: Option<TokenId>,
    /// Comma tokens separating PARTITION BY expressions (max 15)
    pub partition_by_commas: [TokenId; 16],
    pub partition_by_comma_count: u8,
    /// Optional ORDER keyword token
    pub order_keyword: Option<TokenId>,
    /// BY keyword after ORDER (if ORDER BY present)
    pub order_by_keyword: Option<TokenId>,
    /// Comma tokens separating ORDER BY items (max 15)
    pub order_by_commas: [TokenId; 16],
    pub order_by_comma_count: u8,
    /// Optional MEASURES keyword token
    pub measures_keyword: Option<TokenId>,
    /// Comma tokens separating MEASURES items (max 15)
    pub measures_commas: [TokenId; 16],
    pub measures_comma_count: u8,
    /// Optional ONE/ALL keyword token for rows per match (first keyword only)
    pub rows_per_match_keyword: Option<TokenId>,
    /// All keyword tokens for rows per match clause (ONE/ALL, ROW/ROWS, PER, MATCH, etc.)
    /// Max 7 tokens: ALL ROWS PER MATCH SHOW EMPTY MATCHES
    pub rows_per_match_tokens: [TokenId; 8],
    pub rows_per_match_token_count: u8,
    /// Optional AFTER keyword token for after match skip (first keyword only)
    pub after_match_keyword: Option<TokenId>,
    /// All keyword tokens for after match skip clause (AFTER, MATCH, SKIP, TO, NEXT/FIRST/LAST, ROW/symbol)
    /// Max 6 tokens: AFTER MATCH SKIP TO LAST/FIRST/NEXT ROW
    pub after_match_skip_tokens: [TokenId; 6],
    pub after_match_skip_token_count: u8,
    /// PATTERN keyword token
    pub pattern_keyword: TokenId,
    /// Opening paren for PATTERN (...)
    pub pattern_lparen: TokenId,
    /// Closing paren for PATTERN (...)
    pub pattern_rparen: TokenId,
    /// All tokens inside PATTERN (...) for trivia preservation
    pub pattern_tokens: Vec<TokenId>,
    /// DEFINE keyword token
    pub define_keyword: TokenId,
    /// Comma tokens separating DEFINE symbols (max 15)
    pub define_commas: [TokenId; 16],
    pub define_comma_count: u8,
    /// Span covering the entire MATCH_RECOGNIZE clause
    pub span: Span,
}

/// MEASURES item in MATCH_RECOGNIZE: [RUNNING|FINAL] expr AS alias
#[derive(Debug, Clone, Copy)]
pub struct SyntaxMeasureItem {
    /// Optional RUNNING or FINAL keyword token
    pub semantic_modifier: Option<TokenId>,
    /// AS keyword token
    pub as_keyword: TokenId,
    /// Span covering the entire measure
    pub span: Span,
}

/// DEFINE symbol in MATCH_RECOGNIZE: symbol AS condition
#[derive(Debug, Clone, Copy)]
pub struct SyntaxDefineSymbol {
    /// Symbol name token (identifier)
    pub symbol_token: TokenId,
    /// AS keyword token
    pub as_keyword: TokenId,
    /// Span covering the entire definition
    pub span: Span,
}

/// CALL statement: CALL procedure_name(arg1, arg2, ...);
///
/// Explicitly owns CALL keyword, parentheses, and optional semicolon.
#[derive(Debug, Clone, Copy)]
pub struct SyntaxCallStmt {
    /// CALL keyword token
    pub call_keyword: TokenId,
    /// Opening parenthesis token (if args present)
    pub l_paren: Option<TokenId>,
    /// Closing parenthesis token (if args present)
    pub r_paren: Option<TokenId>,
    /// Optional semicolon token
    pub semicolon: Option<TokenId>,
    /// Span covering the entire CALL statement
    pub span: Span,
}

/// Table reference with optional AS keyword for alias
/// Example: `table_name AS alias` or `table_name alias`
#[derive(Debug, Clone, Copy)]
pub struct SyntaxTableRef {
    /// Optional AS keyword token (None if alias provided without AS)
    pub as_keyword: Option<TokenId>,
    /// Optional AS keyword token for result_alias (after PIVOT/UNPIVOT/MATCH_RECOGNIZE)
    pub result_alias_as_keyword: Option<TokenId>,
    /// Opening paren for subquery/VALUES wrapper: FROM (SELECT ...) or FROM (VALUES ...)
    pub subquery_lparen: Option<TokenId>,
    /// Closing paren for subquery/VALUES wrapper
    pub subquery_rparen: Option<TokenId>,
    /// Opening paren for alias columns: AS t(col1, col2, ...)
    pub alias_columns_lparen: Option<TokenId>,
    /// Closing paren for alias columns
    pub alias_columns_rparen: Option<TokenId>,
    /// Opening paren for result-alias columns: PIVOT (...) AS p(col1, col2, ...)
    pub result_alias_columns_lparen: Option<TokenId>,
    /// Closing paren for result-alias columns
    pub result_alias_columns_rparen: Option<TokenId>,
    /// Span covering the entire table reference
    pub span: Span,
}

/// MERGE INSERT VALUES clause: INSERT (col1, col2) VALUES (val1, val2)
///
/// Explicitly owns structural tokens for proper trivia preservation.
#[derive(Debug, Clone)]
pub struct SyntaxMergeInsertValues {
    /// INSERT keyword token
    pub insert_keyword: TokenId,
    /// Optional column list opening paren
    pub columns_lparen: Option<TokenId>,
    /// Optional column list closing paren
    pub columns_rparen: Option<TokenId>,
    /// VALUES keyword token
    pub values_keyword: TokenId,
    /// Values row opening paren
    pub values_lparen: TokenId,
    /// Values row closing paren
    pub values_rparen: TokenId,
    /// Span covering the entire INSERT ... VALUES (...) clause
    pub span: Span,
}

/// Inline constraint in CREATE TABLE column definition
///
/// Examples:
/// - CONSTRAINT pk_id PRIMARY KEY
/// - CONSTRAINT uk_email UNIQUE
/// - CONSTRAINT fk_parent FOREIGN KEY REFERENCES parent_table(id) ON DELETE CASCADE
/// - CONSTRAINT chk_status CHECK (status IN ('active', 'inactive'))
///
/// Explicitly owns all structural tokens for proper trivia preservation.
///
/// Captures token IDs for keywords and spans for complex content like CHECK expressions
/// and REFERENCES targets. Enables proper keyword casing while preserving trivia.
#[derive(Debug, Clone, Copy)]
pub struct SyntaxInlineConstraint {
    /// Optional CONSTRAINT keyword token
    pub constraint_keyword: Option<TokenId>,
    /// Optional constraint name token (identifier after CONSTRAINT)
    pub constraint_name: Option<TokenId>,
    /// First constraint type keyword: PRIMARY, UNIQUE, FOREIGN, or CHECK
    pub constraint_type_keyword: TokenId,
    /// Optional KEY keyword (after PRIMARY/FOREIGN)
    pub key_keyword: Option<TokenId>,
    /// Optional REFERENCES keyword (for FOREIGN KEY)
    pub references_keyword: Option<TokenId>,
    /// Span of referenced table and columns: table(col1, col2) after REFERENCES
    /// Extends from token after REFERENCES to just before ON keyword (or end if no ON)
    pub references_target_span: Option<Span>,
    /// Optional ON keyword (for referential actions)
    pub on_keyword: Option<TokenId>,
    /// Optional DELETE or UPDATE keyword (after ON)
    pub action_trigger_keyword: Option<TokenId>,
    /// Optional CASCADE, SET NULL, SET DEFAULT, RESTRICT, or NO ACTION keyword
    pub action_keyword: Option<TokenId>,
    /// Span of CHECK expression: (expr) after CHECK keyword
    /// Includes the parentheses and everything inside
    pub check_expr_span: Option<Span>,
    /// Span covering the entire inline constraint
    pub span: Span,
}

/// VALUES clause with row parentheses tracking
/// Syntax: VALUES (expr, expr), (expr, expr)
#[derive(Debug, Clone)]
pub struct SyntaxValues {
    pub values_keyword: TokenId,   // VALUES keyword token
    pub row_lparens: Vec<TokenId>, // Opening ( for each row
    pub row_rparens: Vec<TokenId>, // Closing ) for each row
    pub span: Span,
}

/// CREATE VIEW column list with explicit token tracking
///
/// Example: `(col1 MASKING POLICY mp1, col2 WITH TAG (t1='v1'))`
///
/// Explicitly owns:
/// - Opening/closing parenthesis tokens
/// - Individual column definitions with their structural tokens
///
/// This enables the formatter to emit each component with proper trivia
/// preservation, including commas, optional WITH keywords, and column attributes.
#[derive(Debug, Clone)]
pub struct SyntaxViewColumnList {
    /// Opening parenthesis token
    pub l_paren: TokenId,
    /// Closing parenthesis token
    pub r_paren: TokenId,
    /// Individual column definitions
    pub columns: Vec<SyntaxViewColumnId>,
    /// Comma tokens separating columns (length = columns.len() - 1)
    pub commas: Vec<TokenId>,
    /// Span covering the entire column list including parens
    pub span: Span,
}

/// Single column definition in CREATE VIEW column list
///
/// Examples:
/// - `col1`
/// - `col2 COMMENT 'description'`
/// - `email WITH MASKING POLICY email_mask`
/// - `diagnosis TAG (phi='health')`
/// - `account WITH PROJECTION POLICY proj_p`
///
/// Explicitly owns:
/// - Column name token
/// - IDs for optional attribute clauses
#[derive(Debug, Clone, Copy)]
pub struct SyntaxViewColumn {
    /// Column name token
    pub name: TokenId,
    /// Optional COMMENT attribute
    pub comment_id: Option<SyntaxViewColumnCommentId>,
    /// Optional MASKING POLICY attribute
    pub masking_policy_id: Option<SyntaxViewColumnMaskingPolicyId>,
    /// Optional PROJECTION POLICY attribute
    pub projection_policy_id: Option<SyntaxViewColumnProjectionPolicyId>,
    /// Optional TAG attribute
    pub tag_id: Option<SyntaxViewColumnTagId>,
    /// Span covering the entire column definition (name + all attributes)
    pub span: Span,
}

/// COMMENT attribute on a VIEW column: `COMMENT '<string>'`
#[derive(Debug, Clone, Copy)]
pub struct SyntaxViewColumnComment {
    /// COMMENT keyword token
    pub comment_keyword: TokenId,
    /// String literal token
    pub string_literal: TokenId,
    /// Span covering COMMENT and string
    pub span: Span,
}

/// MASKING POLICY attribute on a VIEW column
/// Syntax: `[ WITH ] MASKING POLICY <policy_name> [ USING ( <col> , ... ) ]`
#[derive(Debug, Clone, Copy)]
pub struct SyntaxViewColumnMaskingPolicy {
    /// Optional WITH keyword
    pub with_keyword: Option<TokenId>,
    /// MASKING keyword token
    pub masking_keyword: TokenId,
    /// POLICY keyword token
    pub policy_keyword: TokenId,
    /// Policy name token
    pub policy_name: TokenId,
    /// Optional USING keyword
    pub using_keyword: Option<TokenId>,
    /// Optional opening paren for USING clause
    pub using_l_paren: Option<TokenId>,
    /// Optional closing paren for USING clause
    pub using_r_paren: Option<TokenId>,
    /// Span covering entire attribute
    pub span: Span,
}

/// PROJECTION POLICY attribute on a VIEW column
/// Syntax: `[ WITH ] PROJECTION POLICY <policy_name>`
#[derive(Debug, Clone, Copy)]
pub struct SyntaxViewColumnProjectionPolicy {
    /// Optional WITH keyword
    pub with_keyword: Option<TokenId>,
    /// PROJECTION keyword token
    pub projection_keyword: TokenId,
    /// POLICY keyword token
    pub policy_keyword: TokenId,
    /// Policy name token
    pub policy_name: TokenId,
    /// Span covering entire attribute
    pub span: Span,
}

/// TAG attribute on a VIEW column
/// Syntax: `[ WITH ] TAG ( <tag_name> = '<tag_value>' [ , ... ] )`
#[derive(Debug, Clone, Copy)]
pub struct SyntaxViewColumnTag {
    /// Optional WITH keyword
    pub with_keyword: Option<TokenId>,
    /// TAG keyword token
    pub tag_keyword: TokenId,
    /// Opening parenthesis token
    pub l_paren: TokenId,
    /// Closing parenthesis token
    pub r_paren: TokenId,
    /// Span covering entire attribute
    pub span: Span,
}

// =============================================================================
// ALTER TABLE typed syntax
// =============================================================================

/// ALTER TABLE statement syntax node.
///
/// Owns the core structural keyword tokens and points to an action list node
/// that owns delimiter trivia between actions (e.g. commas).
#[derive(Debug, Clone, Copy)]
pub struct SyntaxAlterTableStmt {
    pub alter_keyword: TokenId,
    pub table_keyword: TokenId,
    pub if_keyword: Option<TokenId>,
    pub exists_keyword: Option<TokenId>,
    /// Span covering the table name/object reference.
    pub name_span: Span,
    pub actions: SyntaxAlterTableActionListId,
    pub span: Span,
}

/// ALTER TABLE action list: `<action> (, <action>)*`
///
/// Owns the commas between actions to preserve trivia and enable robust
/// destructuring.
#[derive(Debug, Clone)]
pub struct SyntaxAlterTableActionList {
    pub actions: Vec<SyntaxAlterTableActionId>,
    pub commas: Vec<TokenId>,
    pub span: Span,
}

/// A single ALTER TABLE action.
///
/// This node is intentionally minimal: it owns the action span and an optional
/// leading keyword token to support fast classification in the formatter/policy
/// layer without scanning.
#[derive(Debug, Clone, Copy)]
pub struct SyntaxAlterTableAction {
    pub leading_keyword: Option<TokenId>,
    pub span: Span,
}

// =============================================================================
// ALTER STAGE typed syntax
// =============================================================================

/// ALTER STAGE statement syntax node.
///
/// Owns the core structural keyword tokens for ALTER STAGE statements.
#[derive(Debug, Clone, Copy)]
pub struct SyntaxAlterStageStmt {
    pub alter_keyword: TokenId,
    pub stage_keyword: TokenId,
    pub if_keyword: Option<TokenId>,
    pub exists_keyword: Option<TokenId>,
    /// Span covering the stage name/object reference.
    pub name_span: Span,
    pub action: SyntaxAlterStageActionId,
    pub span: Span,
}

/// A single ALTER STAGE action.
#[derive(Debug, Clone, Copy)]
pub struct SyntaxAlterStageAction {
    pub leading_keyword: Option<TokenId>,
    pub span: Span,
}

// =============================================================================
// ALTER DYNAMIC TABLE typed syntax
// =============================================================================

/// ALTER DYNAMIC TABLE statement syntax node.
///
/// Owns the core structural keyword tokens for ALTER DYNAMIC TABLE statements.
#[derive(Debug, Clone, Copy)]
pub struct SyntaxAlterDynamicTableStmt {
    pub alter_keyword: TokenId,
    /// DYNAMIC is an identifier, not a keyword, so we just store its TokenId
    pub dynamic_token: TokenId,
    pub table_keyword: TokenId,
    pub if_keyword: Option<TokenId>,
    pub exists_keyword: Option<TokenId>,
    /// Span covering the table name/object reference.
    pub name_span: Span,
    /// Span covering the action (everything after the table name).
    pub action_span: Span,
    pub span: Span,
}

// =============================================================================
// CREATE ROW ACCESS POLICY typed syntax
// =============================================================================

/// CREATE ROW ACCESS POLICY statement syntax node.
///
/// Owns structural keyword tokens and delimiters for CREATE ROW ACCESS POLICY statements.
/// Content spans (policy name, signature, body) are reused from the AST layer.
#[derive(Debug, Clone, Copy)]
pub struct SyntaxCreateRowAccessPolicy {
    // Keywords as TokenIds (includes trivia)
    pub create_keyword: TokenId,
    pub or_keyword: Option<TokenId>,
    pub replace_keyword: Option<TokenId>,
    pub row_keyword: TokenId,
    pub access_keyword: TokenId,
    pub policy_keyword: TokenId,

    // Snowflake-specific keywords (None for BigQuery)
    pub as_keyword: Option<TokenId>,
    pub returns_keyword: Option<TokenId>,
    pub boolean_keyword: Option<TokenId>,

    // Snowflake-specific structural delimiters (None for BigQuery)
    pub lparen: Option<TokenId>,      // Before signature
    pub rparen: Option<TokenId>,      // After signature
    pub arrow_token: Option<TokenId>, // The "->" operator

    // Snowflake-specific content spans (None for BigQuery)
    pub signature_span: Option<Span>, // (arg1 TYPE, arg2 TYPE)

    // BigQuery-specific keywords/tokens (None for Snowflake)
    pub if_keyword: Option<TokenId>,     // IF
    pub not_keyword: Option<TokenId>,    // NOT
    pub exists_keyword: Option<TokenId>, // EXISTS
    pub on_keyword: Option<TokenId>,     // ON

    // BigQuery-specific content spans (None for Snowflake)
    pub table_name_span: Option<Span>,
    pub grant_to_clause_span: Option<Span>,
    pub filter_using_clause_span: Option<Span>,

    // Common content spans
    pub policy_name_span: Span,
    pub body_expr_span: Span,
    pub comment_span: Option<Span>,

    pub span: Span,
}

// =============================================================================
// ALTER ROW ACCESS POLICY typed syntax
// =============================================================================

/// ALTER ROW ACCESS POLICY statement syntax node.
#[derive(Debug, Clone, Copy)]
pub struct SyntaxAlterRowAccessPolicyStmt {
    pub alter_keyword: TokenId,
    pub row_keyword: TokenId,
    pub access_keyword: TokenId,
    pub policy_keyword: TokenId,
    pub if_keyword: Option<TokenId>,
    pub exists_keyword: Option<TokenId>,
    pub name_span: Span,
    pub action_id: SyntaxAlterRowAccessPolicyActionId,
    pub span: Span,
}

/// ALTER ROW ACCESS POLICY action syntax node.
#[derive(Debug, Clone, Copy)]
pub struct SyntaxAlterRowAccessPolicyAction {
    pub span: Span,
}

/// DROP ROW ACCESS POLICY statement syntax node.
#[derive(Debug, Clone)]
pub struct SyntaxDropRowAccessPolicy {
    pub drop_keyword: TokenId,
    pub row_keyword: TokenId,
    pub access_keyword: TokenId,
    pub policy_keyword: TokenId,
    pub if_keyword: Option<TokenId>,
    pub exists_keyword: Option<TokenId>,
    pub policy_name_span: Span,
    // BigQuery-specific
    pub on_keyword: Option<TokenId>,
    pub table_name_span: Option<Span>,
    pub span: Span,
}

/// DROP ALL ROW ACCESS POLICIES statement syntax node (BigQuery).
#[derive(Debug, Clone)]
pub struct SyntaxDropAllRowAccessPolicies {
    pub drop_keyword: TokenId,
    pub all_keyword: TokenId,
    pub row_keyword: TokenId,
    pub access_keyword: TokenId,
    /// POLICIES is an Identifier token
    pub policies_token: TokenId,
    pub on_keyword: TokenId,
    pub table_name_span: Span,
    pub span: Span,
}

// =============================================================================
// MASKING POLICY typed syntax
// =============================================================================

/// CREATE MASKING POLICY statement syntax node.
/// Content spans (policy name, signature, body) are reused from the AST layer.
#[derive(Debug, Clone, Copy)]
pub struct SyntaxCreateMaskingPolicy {
    // Keywords as TokenIds (includes trivia)
    pub create_keyword: TokenId,
    pub or_keyword: Option<TokenId>,
    pub replace_keyword: Option<TokenId>,
    pub if_keyword: Option<TokenId>,
    pub not_keyword: Option<TokenId>,
    pub exists_keyword: Option<TokenId>,
    pub masking_keyword: TokenId,
    pub policy_keyword: TokenId,
    pub as_keyword: TokenId, // REQUIRED for MASKING POLICY
    pub returns_keyword: TokenId,

    // Structural delimiters
    pub lparen: TokenId,      // Before signature
    pub rparen: TokenId,      // After signature
    pub arrow_token: TokenId, // The "->" operator

    // Content spans (reused from AST)
    pub policy_name_span: Span,
    pub signature_span: Span,
    pub return_type_span: Span, // The return type (e.g., "STRING", "VARCHAR")
    pub body_expr_span: Span,
    pub comment_span: Option<Span>,
    pub exempt_other_policies_span: Option<Span>,

    pub span: Span,
}

/// ALTER MASKING POLICY statement syntax node.
#[derive(Debug, Clone, Copy)]
pub struct SyntaxAlterMaskingPolicyStmt {
    pub alter_keyword: TokenId,
    pub masking_keyword: TokenId,
    pub policy_keyword: TokenId,
    pub if_keyword: Option<TokenId>,
    pub exists_keyword: Option<TokenId>,
    pub name_span: Span,
    pub action_id: SyntaxAlterMaskingPolicyActionId,
    pub span: Span,
}

/// ALTER MASKING POLICY action syntax node.
#[derive(Debug, Clone, Copy)]
pub struct SyntaxAlterMaskingPolicyAction {
    pub span: Span,
}

/// DROP MASKING POLICY statement syntax node.
#[derive(Debug, Clone)]
pub struct SyntaxDropMaskingPolicy {
    pub drop_keyword: TokenId,
    pub masking_token: TokenId, // MASKING is Identifier!
    pub policy_keyword: TokenId,
    pub if_keyword: Option<TokenId>,
    pub exists_keyword: Option<TokenId>,
    pub policy_name_span: Span,
    pub span: Span,
}

// ============================================================================
// Network Policy Syntax Nodes
// ============================================================================

/// CREATE NETWORK POLICY statement syntax node.
#[derive(Debug, Clone)]
pub struct SyntaxCreateNetworkPolicy {
    pub create_keyword: TokenId,
    pub or_keyword: Option<TokenId>,
    pub replace_keyword: Option<TokenId>,
    pub if_keyword: Option<TokenId>,
    pub not_keyword: Option<TokenId>,
    pub exists_keyword: Option<TokenId>,
    // NOTE: 'NETWORK' is Identifier, not Keyword - stored as span
    pub network_span: Span,
    pub policy_keyword: TokenId,

    pub policy_name_span: Span,
    pub span: Span,
}

/// ALTER NETWORK POLICY statement syntax node.
#[derive(Debug, Clone)]
pub struct SyntaxAlterNetworkPolicy {
    pub alter_keyword: TokenId,
    // NOTE: 'NETWORK' is Identifier, not Keyword - stored as span
    pub network_span: Span,
    pub policy_keyword: TokenId,
    pub if_keyword: Option<TokenId>,
    pub exists_keyword: Option<TokenId>,
    pub name_span: Span,
    pub action_id: SyntaxAlterNetworkPolicyActionId,
    pub span: Span,
}

/// ALTER NETWORK POLICY action syntax node.
#[derive(Debug, Clone, Copy)]
pub struct SyntaxAlterNetworkPolicyAction {
    pub span: Span,
}

/// DROP NETWORK POLICY statement syntax node.
#[derive(Debug, Clone)]
pub struct SyntaxDropNetworkPolicy {
    pub drop_keyword: TokenId,
    // NOTE: 'NETWORK' is Identifier, not Keyword - stored as span
    pub network_span: Span,
    pub policy_keyword: TokenId,
    pub if_keyword: Option<TokenId>,
    pub exists_keyword: Option<TokenId>,
    pub policy_name_span: Span,
    pub span: Span,
}

// ============================================================================
// Session Policy Syntax Nodes
// ============================================================================

/// CREATE SESSION POLICY statement syntax node.
#[derive(Debug, Clone)]
pub struct SyntaxCreateSessionPolicy {
    pub create_keyword: TokenId,
    pub or_keyword: Option<TokenId>,
    pub replace_keyword: Option<TokenId>,
    pub if_keyword: Option<TokenId>,
    pub not_keyword: Option<TokenId>,
    pub exists_keyword: Option<TokenId>,
    pub session_keyword: TokenId,
    pub policy_keyword: TokenId,

    pub policy_name_span: Span,

    // Decomposed properties (name = value triples)
    pub properties: Vec<crate::ast::CreatePolicyProperty>,

    pub span: Span,
}

/// ALTER SESSION POLICY statement syntax node.
#[derive(Debug, Clone)]
pub struct SyntaxAlterSessionPolicy {
    pub alter_keyword: TokenId,
    pub session_keyword: TokenId,
    pub policy_keyword: TokenId,
    pub if_keyword: Option<TokenId>,
    pub exists_keyword: Option<TokenId>,
    pub name_span: Span,
    pub action_id: SyntaxAlterSessionPolicyActionId,
    pub span: Span,
}

/// ALTER SESSION POLICY action syntax node.
#[derive(Debug, Clone, Copy)]
pub struct SyntaxAlterSessionPolicyAction {
    pub span: Span,
}

/// DROP SESSION POLICY statement syntax node.
#[derive(Debug, Clone)]
pub struct SyntaxDropSessionPolicy {
    pub drop_keyword: TokenId,
    pub session_keyword: TokenId,
    pub policy_keyword: TokenId,
    pub if_keyword: Option<TokenId>,
    pub exists_keyword: Option<TokenId>,
    pub policy_name_span: Span,
    pub span: Span,
}

// ============================================================================
// Authentication Policy Syntax Nodes
// ============================================================================

/// CREATE AUTHENTICATION POLICY statement syntax node.
#[derive(Debug, Clone)]
pub struct SyntaxCreateAuthenticationPolicy {
    pub create_keyword: TokenId,
    pub or_keyword: Option<TokenId>,
    pub replace_keyword: Option<TokenId>,
    pub alter_keyword_in_create: Option<TokenId>, // For CREATE OR ALTER
    pub if_keyword: Option<TokenId>,
    pub not_keyword: Option<TokenId>,
    pub exists_keyword: Option<TokenId>,
    pub authentication_token: TokenId, // AUTHENTICATION is Identifier!
    pub policy_keyword: TokenId,

    pub policy_name_span: Span,

    // Property spans
    pub authentication_methods_span: Option<Span>,
    pub client_types_span: Option<Span>,
    pub client_policy_span: Option<Span>,
    pub mfa_enrollment_span: Option<Span>,
    pub mfa_policy_span: Option<Span>,
    pub pat_policy_span: Option<Span>,
    pub workload_identity_policy_span: Option<Span>,
    pub security_integrations_span: Option<Span>,
    pub comment_span: Option<Span>,

    pub span: Span,
}

/// ALTER AUTHENTICATION POLICY statement syntax node.
#[derive(Debug, Clone)]
pub struct SyntaxAlterAuthenticationPolicy {
    pub alter_keyword: TokenId,
    pub authentication_token: TokenId, // AUTHENTICATION is Identifier!
    pub policy_keyword: TokenId,
    pub if_keyword: Option<TokenId>,
    pub exists_keyword: Option<TokenId>,
    pub name_span: Span,
    pub action_id: SyntaxAlterAuthenticationPolicyActionId,
    pub span: Span,
}

/// ALTER AUTHENTICATION POLICY action syntax node.
#[derive(Debug, Clone, Copy)]
pub struct SyntaxAlterAuthenticationPolicyAction {
    pub span: Span,
}

/// DROP AUTHENTICATION POLICY statement syntax node.
#[derive(Debug, Clone)]
pub struct SyntaxDropAuthenticationPolicy {
    pub drop_keyword: TokenId,
    pub authentication_token: TokenId, // AUTHENTICATION is Identifier!
    pub policy_keyword: TokenId,
    pub if_keyword: Option<TokenId>,
    pub exists_keyword: Option<TokenId>,
    pub policy_name_span: Span,
    pub span: Span,
}

/// CREATE API INTEGRATION statement syntax node.
#[derive(Debug, Clone)]
pub struct SyntaxCreateApiIntegration {
    pub create_keyword: TokenId,
    pub or_keyword: Option<TokenId>,
    pub replace_keyword: Option<TokenId>,
    pub if_keyword: Option<TokenId>,
    pub not_keyword: Option<TokenId>,
    pub exists_keyword: Option<TokenId>,
    pub api_token: TokenId, // API is Identifier!
    pub integration_keyword: TokenId,

    pub integration_name_span: Span,

    // All property spans for CREATE API INTEGRATION
    pub api_provider_span: Option<Span>,
    pub api_aws_role_arn_span: Option<Span>,
    pub api_allowed_prefixes_span: Option<Span>,
    pub api_blocked_prefixes_span: Option<Span>,
    pub api_key_span: Option<Span>,
    pub enabled_span: Option<Span>,
    pub comment_span: Option<Span>,

    // Azure-specific
    pub azure_tenant_id_span: Option<Span>,
    pub azure_ad_application_id_span: Option<Span>,

    // Google-specific
    pub google_audience_span: Option<Span>,

    // Git-specific
    pub allowed_authentication_secrets_span: Option<Span>,
    pub api_user_authentication_span: Option<Span>,
    pub tls_trusted_certificates_span: Option<Span>,
    pub use_privatelink_endpoint_span: Option<Span>,

    pub span: Span,
}

/// ALTER API INTEGRATION statement syntax node.
#[derive(Debug, Clone)]
pub struct SyntaxAlterApiIntegration {
    pub alter_keyword: TokenId,
    pub api_token: TokenId, // API is Identifier!
    pub integration_keyword: TokenId,
    pub if_keyword: Option<TokenId>,
    pub exists_keyword: Option<TokenId>,
    pub name_span: Span,
    pub action_id: SyntaxAlterApiIntegrationActionId,
    pub span: Span,
}

/// ALTER API INTEGRATION action syntax node.
#[derive(Debug, Clone, Copy)]
pub struct SyntaxAlterApiIntegrationAction {
    pub span: Span,
}

/// DROP API INTEGRATION statement syntax node.
#[derive(Debug, Clone)]
pub struct SyntaxDropApiIntegration {
    pub drop_keyword: TokenId,
    pub api_token: Option<TokenId>, // Optional API keyword
    pub integration_keyword: TokenId,
    pub if_keyword: Option<TokenId>,
    pub exists_keyword: Option<TokenId>,
    pub integration_name_span: Span,
    pub span: Span,
}

/// CREATE PASSWORD POLICY statement syntax node.
#[derive(Debug, Clone)]
pub struct SyntaxCreatePasswordPolicy {
    pub create_keyword: TokenId,
    pub or_keyword: Option<TokenId>,
    pub replace_keyword: Option<TokenId>,
    pub if_keyword: Option<TokenId>,
    pub not_keyword: Option<TokenId>,
    pub exists_keyword: Option<TokenId>,
    pub password_token: TokenId, // PASSWORD is Identifier!
    pub policy_keyword: TokenId,

    pub policy_name_span: Span,

    // Decomposed properties (name = value triples)
    pub properties: Vec<crate::ast::CreatePolicyProperty>,

    pub span: Span,
}

/// ALTER PASSWORD POLICY statement syntax node.
#[derive(Debug, Clone)]
pub struct SyntaxAlterPasswordPolicy {
    pub alter_keyword: TokenId,
    pub password_token: TokenId, // PASSWORD is Identifier!
    pub policy_keyword: TokenId,
    pub if_keyword: Option<TokenId>,
    pub exists_keyword: Option<TokenId>,
    pub name_span: Span,
    pub action_id: SyntaxAlterPasswordPolicyActionId,
    pub span: Span,
}

/// ALTER PASSWORD POLICY action syntax node.
#[derive(Debug, Clone, Copy)]
pub struct SyntaxAlterPasswordPolicyAction {
    pub span: Span,
}

/// DROP PASSWORD POLICY statement syntax node.
#[derive(Debug, Clone)]
pub struct SyntaxDropPasswordPolicy {
    pub drop_keyword: TokenId,
    pub password_token: TokenId, // PASSWORD is Identifier!
    pub policy_keyword: TokenId,
    pub if_keyword: Option<TokenId>,
    pub exists_keyword: Option<TokenId>,
    pub policy_name_span: Span,
    pub span: Span,
}

/// CREATE AGGREGATION POLICY statement syntax node.
#[derive(Debug, Clone)]
pub struct SyntaxCreateAggregationPolicy {
    pub create_keyword: TokenId,
    pub or_keyword: Option<TokenId>,
    pub replace_keyword: Option<TokenId>,
    pub if_keyword: Option<TokenId>,
    pub not_keyword: Option<TokenId>,
    pub exists_keyword: Option<TokenId>,
    pub aggregation_token: TokenId, // AGGREGATION is Identifier!
    pub policy_keyword: TokenId,
    pub policy_name_span: Span,

    // AS () RETURNS AGGREGATION_CONSTRAINT -> <body>
    pub as_keyword: TokenId,
    pub lparen_token: TokenId,
    pub rparen_token: TokenId,
    pub as_signature_span: Span, // Flat span from AS through )
    pub returns_keyword: TokenId,
    pub return_type_span: Span, // AGGREGATION_CONSTRAINT identifier
    pub returns_span: Span,     // Flat span from RETURNS through return type
    pub arrow_token: TokenId,

    pub body_span: Span,
    pub comment_span: Option<Span>,
    pub span: Span,
}

/// ALTER AGGREGATION POLICY statement syntax node.
#[derive(Debug, Clone)]
pub struct SyntaxAlterAggregationPolicy {
    pub alter_keyword: TokenId,
    pub aggregation_token: TokenId, // AGGREGATION is Identifier!
    pub policy_keyword: TokenId,
    pub if_keyword: Option<TokenId>,
    pub exists_keyword: Option<TokenId>,
    pub name_span: Span,
    pub action_id: SyntaxAlterAggregationPolicyActionId,
    pub span: Span,
}

/// ALTER AGGREGATION POLICY action syntax node.
#[derive(Debug, Clone, Copy)]
pub struct SyntaxAlterAggregationPolicyAction {
    pub span: Span,
}

/// DROP AGGREGATION POLICY statement syntax node.
#[derive(Debug, Clone)]
pub struct SyntaxDropAggregationPolicy {
    pub drop_keyword: TokenId,
    pub aggregation_token: TokenId, // AGGREGATION is Identifier!
    pub policy_keyword: TokenId,
    pub if_keyword: Option<TokenId>,
    pub exists_keyword: Option<TokenId>,
    pub policy_name_span: Span,
    pub span: Span,
}

/// CREATE PROJECTION POLICY statement syntax node.
#[derive(Debug, Clone)]
pub struct SyntaxCreateProjectionPolicy {
    pub create_keyword: TokenId,
    pub or_keyword: Option<TokenId>,
    pub replace_keyword: Option<TokenId>,
    pub if_keyword: Option<TokenId>,
    pub not_keyword: Option<TokenId>,
    pub exists_keyword: Option<TokenId>,
    pub projection_token: TokenId, // PROJECTION is Identifier, not Keyword!
    pub policy_keyword: TokenId,

    pub policy_name_span: Span,

    // AS () RETURNS PROJECTION_CONSTRAINT -> <body>
    pub as_keyword: Option<TokenId>,
    pub lparen_token: Option<TokenId>,
    pub rparen_token: Option<TokenId>,
    pub returns_keyword: Option<TokenId>,
    pub return_type_span: Option<Span>, // PROJECTION_CONSTRAINT identifier
    pub arrow_token: Option<TokenId>,   // -> operator

    /// Span covering the entire body expression
    pub body_span: Span,

    pub comment_span: Option<Span>,

    pub span: Span,
}

/// ALTER PROJECTION POLICY statement syntax node.
#[derive(Debug, Clone)]
pub struct SyntaxAlterProjectionPolicy {
    pub alter_keyword: TokenId,
    pub projection_token: TokenId, // PROJECTION is Identifier!
    pub policy_keyword: TokenId,
    pub if_keyword: Option<TokenId>,
    pub exists_keyword: Option<TokenId>,
    pub name_span: Span,
    pub action_id: SyntaxAlterProjectionPolicyActionId,
    pub span: Span,
}

/// ALTER PROJECTION POLICY action syntax node.
#[derive(Debug, Clone, Copy)]
pub struct SyntaxAlterProjectionPolicyAction {
    pub span: Span,
}

/// DROP PROJECTION POLICY statement syntax node.
#[derive(Debug, Clone)]
pub struct SyntaxDropProjectionPolicy {
    pub drop_keyword: TokenId,
    pub projection_token: TokenId, // PROJECTION is Identifier!
    pub policy_keyword: TokenId,
    pub if_keyword: Option<TokenId>,
    pub exists_keyword: Option<TokenId>,
    pub policy_name_span: Span,
    pub span: Span,
}

/// CREATE STORAGE INTEGRATION statement syntax node.
#[derive(Debug, Clone)]
pub struct SyntaxCreateStorageIntegration {
    pub create_keyword: TokenId,
    pub or_keyword: Option<TokenId>,
    pub replace_keyword: Option<TokenId>,
    pub if_keyword: Option<TokenId>,
    pub not_keyword: Option<TokenId>,
    pub exists_keyword: Option<TokenId>,
    pub storage_keyword: TokenId,
    pub integration_keyword: TokenId,

    pub integration_name_span: Span,

    // Property spans (same as AST)
    pub type_span: Option<Span>,
    pub storage_provider_span: Option<Span>,
    pub enabled_span: Option<Span>,
    pub storage_allowed_locations_span: Option<Span>,
    pub storage_blocked_locations_span: Option<Span>,
    pub comment_span: Option<Span>,
    pub storage_aws_role_arn_span: Option<Span>,
    pub storage_aws_external_id_span: Option<Span>,
    pub storage_aws_object_acl_span: Option<Span>,
    pub azure_tenant_id_span: Option<Span>,
    pub use_privatelink_endpoint_span: Option<Span>,

    pub span: Span,
}

/// ALTER STORAGE INTEGRATION statement syntax node.
#[derive(Debug, Clone)]
pub struct SyntaxAlterStorageIntegration {
    pub alter_keyword: TokenId,
    pub storage_keyword: Option<TokenId>,
    pub integration_keyword: TokenId,
    pub if_keyword: Option<TokenId>,
    pub exists_keyword: Option<TokenId>,
    pub name_span: Span,
    pub action_id: SyntaxAlterStorageIntegrationActionId,
    pub span: Span,
}

/// ALTER STORAGE INTEGRATION action syntax node.
#[derive(Debug, Clone, Copy)]
pub struct SyntaxAlterStorageIntegrationAction {
    pub span: Span, // Actions have minimal CST - details in AST
}

/// DROP STORAGE INTEGRATION statement syntax node.
#[derive(Debug, Clone)]
pub struct SyntaxDropStorageIntegration {
    pub drop_keyword: TokenId,
    pub storage_keyword: Option<TokenId>,
    pub integration_keyword: TokenId,
    pub if_keyword: Option<TokenId>,
    pub exists_keyword: Option<TokenId>,
    pub integration_name_span: Span,
    pub span: Span,
}

/// CREATE EXTERNAL ACCESS INTEGRATION statement syntax node.
#[derive(Debug, Clone)]
pub struct SyntaxCreateExternalAccessIntegration {
    pub create_keyword: TokenId,
    pub or_keyword: Option<TokenId>,
    pub replace_keyword: Option<TokenId>,
    pub external_token: TokenId, // EXTERNAL is Identifier, not Keyword
    pub access_keyword: TokenId,
    pub integration_keyword: TokenId,
    pub if_keyword: Option<TokenId>,
    pub not_keyword: Option<TokenId>,
    pub exists_keyword: Option<TokenId>,
    pub integration_name_span: Span,
    pub span: Span,
}

/// ALTER EXTERNAL ACCESS INTEGRATION statement syntax node.
#[derive(Debug, Clone)]
pub struct SyntaxAlterExternalAccessIntegration {
    pub alter_keyword: TokenId,
    pub external_token: TokenId, // EXTERNAL is Identifier, not Keyword
    pub access_keyword: TokenId,
    pub integration_keyword: TokenId,
    pub if_keyword: Option<TokenId>,
    pub exists_keyword: Option<TokenId>,
    pub name_span: Span,
    pub action_id: SyntaxAlterExternalAccessIntegrationActionId,
    pub span: Span,
}

/// ALTER EXTERNAL ACCESS INTEGRATION action syntax node.
#[derive(Debug, Clone, Copy)]
pub struct SyntaxAlterExternalAccessIntegrationAction {
    pub span: Span,
}

/// DROP EXTERNAL ACCESS INTEGRATION statement syntax node.
#[derive(Debug, Clone)]
pub struct SyntaxDropExternalAccessIntegration {
    pub drop_keyword: TokenId,
    pub external_token: Option<TokenId>, // Optional - EXTERNAL is Identifier
    pub access_keyword: Option<TokenId>, // Optional
    pub integration_keyword: TokenId,
    pub if_keyword: Option<TokenId>,
    pub exists_keyword: Option<TokenId>,
    pub integration_name_span: Span,
    pub span: Span,
}

/// CREATE STREAM statement syntax node.
#[derive(Debug, Clone)]
pub struct SyntaxCreateStream {
    pub create_keyword: TokenId,
    pub or_keyword: Option<TokenId>,
    pub replace_keyword: Option<TokenId>,
    pub stream_keyword: TokenId,
    pub if_keyword: Option<TokenId>,
    pub not_keyword: Option<TokenId>,
    pub exists_keyword: Option<TokenId>,
    pub name_span: Span,
    pub clone_span: Option<Span>,
    pub tag_clause_span: Option<Span>,
    pub copy_grants_span: Option<Span>,
    pub on_keyword: Option<TokenId>,
    pub source_type_span: Option<Span>,
    pub source_name_span: Option<Span>,
    pub time_travel_span: Option<Span>,
    pub append_only_span: Option<Span>,
    pub show_initial_rows_span: Option<Span>,
    pub insert_only_span: Option<Span>,
    pub comment_span: Option<Span>,
    pub span: Span,
}

/// ALTER STREAM statement syntax node.
#[derive(Debug, Clone)]
pub struct SyntaxAlterStreamStmt {
    pub alter_keyword: TokenId,
    pub stream_keyword: TokenId,
    pub if_keyword: Option<TokenId>,
    pub exists_keyword: Option<TokenId>,
    pub name_span: Span,
    pub action_id: SyntaxAlterStreamActionId,
    pub span: Span,
}

/// ALTER STREAM action syntax node.
#[derive(Debug, Clone, Copy)]
pub struct SyntaxAlterStreamAction {
    pub span: Span,
}

/// DROP STREAM statement syntax node.
#[derive(Debug, Clone)]
pub struct SyntaxDropStream {
    pub drop_keyword: TokenId,
    pub stream_keyword: TokenId,
    pub if_keyword: Option<TokenId>,
    pub exists_keyword: Option<TokenId>,
    pub name_span: Span,
    pub span: Span,
}

// =============================================================================
// PostgreSQL Utility Statement CST Nodes
// =============================================================================

/// `CREATE [UNIQUE] INDEX [CONCURRENTLY] [IF NOT EXISTS] name ON table`
///     [USING method] (columns) [INCLUDE (columns)] [WHERE predicate]
#[derive(Debug, Clone, Copy)]
pub struct SyntaxCreateIndexStmt {
    /// CREATE keyword token
    pub create_keyword: TokenId,
    /// UNIQUE keyword token (if present)
    pub unique_keyword: Option<TokenId>,
    /// CLUSTERED / NONCLUSTERED keyword token (T-SQL index type, if present)
    pub clustered_keyword: Option<TokenId>,
    /// COLUMNSTORE keyword token (T-SQL columnstore index, if present)
    pub columnstore_keyword: Option<TokenId>,
    /// FULLTEXT / SPATIAL keyword token (MySQL index kind, if present)
    pub mysql_index_kind_keyword: Option<TokenId>,
    /// INDEX keyword token
    pub index_keyword: TokenId,
    /// CONCURRENTLY keyword token (if present)
    pub concurrently_keyword: Option<TokenId>,
    /// IF keyword token (if IF NOT EXISTS present)
    pub if_keyword: Option<TokenId>,
    /// NOT keyword token (if IF NOT EXISTS present)
    pub not_keyword: Option<TokenId>,
    /// EXISTS keyword token (if IF NOT EXISTS present)
    pub exists_keyword: Option<TokenId>,
    /// Index name span (may be absent for anonymous indexes)
    pub name_span: Option<Span>,
    /// ON keyword token
    pub on_keyword: TokenId,
    /// Table name span
    pub table_name_span: Span,
    /// USING keyword token (if present)
    pub using_keyword: Option<TokenId>,
    /// Method name span after USING (e.g., btree, hash, gin)
    pub using_method_span: Option<Span>,
    /// Left paren of column list
    pub columns_l_paren: TokenId,
    /// Right paren of column list
    pub columns_r_paren: TokenId,
    /// INCLUDE keyword token (if present)
    pub include_keyword: Option<TokenId>,
    /// Left paren of INCLUDE column list (if present)
    pub include_l_paren: Option<TokenId>,
    /// Right paren of INCLUDE column list (if present)
    pub include_r_paren: Option<TokenId>,
    /// WHERE keyword token (if present)
    pub where_keyword: Option<TokenId>,
    /// Entire statement span
    pub span: Span,
}

/// COMMENT ON {object_type} object_name IS {'text' | NULL}
#[derive(Debug, Clone, Copy)]
pub struct SyntaxCommentOnStmt {
    /// COMMENT keyword token
    pub comment_keyword: TokenId,
    /// ON keyword token
    pub on_keyword: TokenId,
    /// Object kind span (TABLE, COLUMN, INDEX, etc. — may be multi-word)
    pub object_kind_span: Span,
    /// Object name span (qualified identifier, WITHOUT signature parens)
    pub object_name_span: Span,
    /// Left paren of function/procedure signature (if present)
    pub signature_l_paren: Option<TokenId>,
    /// Right paren of function/procedure signature (if present)
    pub signature_r_paren: Option<TokenId>,
    /// IS keyword token
    pub is_keyword: TokenId,
    /// Comment value span (string literal or NULL)
    pub comment_value_span: Span,
    /// Entire statement span
    pub span: Span,
}

/// DO [LANGUAGE lang] $$ body $$
#[derive(Debug, Clone, Copy)]
pub struct SyntaxDoBlockStmt {
    /// DO keyword token
    pub do_keyword: TokenId,
    /// LANGUAGE keyword token (if present)
    pub language_keyword: Option<TokenId>,
    /// Language name span (if LANGUAGE present)
    pub language_name_span: Option<Span>,
    /// Body token (dollar-quoted string literal)
    pub body_token: TokenId,
    /// Entire statement span
    pub span: Span,
}

/// VACUUM statement (PostgreSQL + Databricks)
///
/// PG:  `VACUUM [FULL] [FREEZE] [VERBOSE] [ANALYZE] [table [(column, ...)]]`
///      VACUUM (option [, ...]) [table [(column, ...)]]
/// DBX: VACUUM table_name [RETAIN num HOURS] [FULL|LITE] [DRY RUN]
#[derive(Debug, Clone, Copy)]
pub struct SyntaxVacuumStmt {
    /// VACUUM keyword token (identifier in our lexer)
    pub vacuum_keyword: TokenId,
    /// Left paren of options (if parenthesized form)
    pub options_l_paren: Option<TokenId>,
    /// Right paren of options (if parenthesized form)
    pub options_r_paren: Option<TokenId>,
    /// FULL keyword token (PG non-parenthesized form, or Databricks Iceberg FULL)
    pub full_keyword: Option<TokenId>,
    /// FREEZE keyword token (non-parenthesized form)
    pub freeze_keyword: Option<TokenId>,
    /// VERBOSE keyword token (non-parenthesized form)
    pub verbose_keyword: Option<TokenId>,
    /// ANALYZE keyword token (non-parenthesized form)
    pub analyze_keyword: Option<TokenId>,
    /// Redshift DELETE keyword token (`VACUUM DELETE ONLY`)
    pub delete_keyword: Option<TokenId>,
    /// Redshift ONLY keyword token following DELETE
    pub delete_only_keyword: Option<TokenId>,
    /// Redshift SORT keyword token (`VACUUM SORT ONLY`)
    pub sort_keyword: Option<TokenId>,
    /// Redshift ONLY keyword token following SORT
    pub sort_only_keyword: Option<TokenId>,
    /// Redshift REINDEX keyword token
    pub reindex_keyword: Option<TokenId>,
    /// Redshift RECLUSTER keyword token
    pub recluster_keyword: Option<TokenId>,
    /// Table name span (if present)
    pub table_name_span: Option<Span>,
    /// Left paren of column list after table (if present)
    pub columns_l_paren: Option<TokenId>,
    /// Right paren of column list after table (if present)
    pub columns_r_paren: Option<TokenId>,
    // --- Databricks-specific tokens ---
    /// RETAIN keyword token (Databricks Delta Lake)
    pub retain_keyword: Option<TokenId>,
    /// Retention value token (numeric literal)
    pub retain_value_token: Option<TokenId>,
    /// HOURS keyword token (Databricks)
    pub hours_keyword: Option<TokenId>,
    /// DRY keyword token (Databricks)
    pub dry_keyword: Option<TokenId>,
    /// RUN keyword token (Databricks)
    pub run_keyword: Option<TokenId>,
    /// LITE keyword token (Databricks Iceberg)
    pub lite_keyword: Option<TokenId>,
    /// Entire statement span
    pub span: Span,
}

/// `ANALYZE [VERBOSE] [table [(column, ...)]]`
#[derive(Debug, Clone, Copy)]
pub struct SyntaxAnalyzeStmt {
    /// ANALYZE keyword token (identifier in our lexer)
    pub analyze_keyword: TokenId,
    /// VERBOSE keyword token (if present)
    pub verbose_keyword: Option<TokenId>,
    /// Redshift COMPRESSION keyword token (if present)
    pub compression_keyword: Option<TokenId>,
    /// Table name span (if present)
    pub table_name_span: Option<Span>,
    /// Left paren of column list (if present)
    pub columns_l_paren: Option<TokenId>,
    /// Right paren of column list (if present)
    pub columns_r_paren: Option<TokenId>,
    /// Entire statement span
    pub span: Span,
}

/// Databricks `OPTIMIZE table_name [FULL] [WHERE predicate] [ZORDER BY (col1, ...)]`
#[derive(Debug, Clone, Copy)]
pub struct SyntaxOptimizeStmt {
    /// OPTIMIZE keyword token (Identifier in our lexer)
    pub optimize_keyword: TokenId,
    /// Table name span (possibly qualified)
    pub table_name_span: Span,
    /// FULL keyword token (if present — Keyword::Full in our lexer)
    pub full_keyword: Option<TokenId>,
    /// WHERE keyword token (if present)
    pub where_keyword: Option<TokenId>,
    /// ZORDER keyword token (Identifier in our lexer, if present)
    pub zorder_keyword: Option<TokenId>,
    /// BY keyword token after ZORDER (if present)
    pub by_keyword: Option<TokenId>,
    /// Left paren of ZORDER BY column list (if present)
    pub zorder_l_paren: Option<TokenId>,
    /// Right paren of ZORDER BY column list (if present)
    pub zorder_r_paren: Option<TokenId>,
    /// Entire statement span
    pub stmt_span: Span,
}

/// Databricks DESCRIBE HISTORY table_name
#[derive(Debug, Clone, Copy)]
pub struct SyntaxDescribeHistoryStmt {
    /// DESCRIBE / DESC keyword token
    pub describe_keyword: TokenId,
    /// HISTORY keyword token (Identifier in our lexer)
    pub history_keyword: TokenId,
    /// Table name span (possibly qualified: catalog.schema.table)
    pub table_name_span: Span,
    /// Entire statement span
    pub stmt_span: Span,
}

/// Databricks `RESTORE [TABLE] table_name [TO] {TIMESTAMP AS OF expr | VERSION AS OF int}`
#[derive(Debug, Clone, Copy)]
pub struct SyntaxRestoreStmt {
    /// RESTORE keyword token (Identifier in our lexer)
    pub restore_keyword: TokenId,
    /// Optional TABLE keyword token
    pub table_keyword: Option<TokenId>,
    /// Table name span (possibly qualified: catalog.schema.table)
    pub table_name_span: Span,
    /// Optional TO keyword token
    pub to_keyword: Option<TokenId>,
    /// TIMESTAMP or VERSION keyword token (Identifier)
    pub time_travel_keyword: TokenId,
    /// AS keyword token
    pub as_keyword: TokenId,
    /// OF keyword token
    pub of_keyword: TokenId,
    /// Entire statement span
    pub stmt_span: Span,
}

/// CREATE TYPE name AS ENUM (...) / AS (...) / AS RANGE (...)
#[derive(Debug, Clone, Copy)]
pub struct SyntaxCreateTypeStmt {
    /// CREATE keyword token
    pub create_keyword: TokenId,
    /// TYPE keyword token
    pub type_keyword: TokenId,
    /// Type name span
    pub type_name_span: Span,
    /// AS keyword token (if present — absent for shell types)
    pub as_keyword: Option<TokenId>,
    /// Sub-keyword after AS: ENUM or RANGE (if present; absent for composite types)
    pub sub_keyword: Option<TokenId>,
    /// Body left paren (if present)
    pub body_l_paren: Option<TokenId>,
    /// Body right paren (if present)
    pub body_r_paren: Option<TokenId>,
    /// Span covering data type identifier before parens (Snowflake: `CREATE TYPE x AS NUMBER(3,0)`)
    pub data_type_span: Option<Span>,
    /// Span covering trailing clause like `COMMENT = '...'` (Snowflake)
    pub trailing_span: Option<Span>,
    /// Entire statement span
    pub span: Span,
}

/// ALTER TYPE name {ADD VALUE | RENAME TO | ADD ATTRIBUTE | SET SCHEMA | OWNER TO | ...}
#[derive(Debug, Clone, Copy)]
pub struct SyntaxAlterTypeStmt {
    /// ALTER keyword token
    pub alter_keyword: TokenId,
    /// TYPE keyword token
    pub type_keyword: TokenId,
    /// Type name span
    pub type_name_span: Span,
    /// Primary action keyword (ADD, RENAME, SET, OWNER)
    pub action_keyword: Option<TokenId>,
    /// Secondary action keyword (VALUE, TO, SCHEMA, ATTRIBUTE)
    pub action_keyword2: Option<TokenId>,
    /// IF keyword (for ADD VALUE IF NOT EXISTS)
    pub action_if_keyword: Option<TokenId>,
    /// NOT keyword (for ADD VALUE IF NOT EXISTS)
    pub action_not_keyword: Option<TokenId>,
    /// EXISTS keyword (for ADD VALUE IF NOT EXISTS)
    pub action_exists_keyword: Option<TokenId>,
    /// Primary value span (string literal for ADD VALUE, attr name for ADD ATTRIBUTE, old value for RENAME VALUE)
    pub action_value_span: Option<Span>,
    /// BEFORE or AFTER keyword (for ADD VALUE positioning)
    pub action_position_keyword: Option<TokenId>,
    /// Value span after BEFORE/AFTER
    pub action_position_value_span: Option<Span>,
    /// TO keyword (for RENAME TO, OWNER TO, RENAME VALUE ... TO)
    pub action_to_keyword: Option<TokenId>,
    /// Target name/value span (new name for RENAME TO, schema for SET SCHEMA, new value for RENAME VALUE)
    pub action_target_span: Option<Span>,
    /// Extra span for ADD ATTRIBUTE trailing tokens (data type, COLLATE, CASCADE/RESTRICT)
    pub action_extra_span: Option<Span>,
    /// Entire statement span
    pub span: Span,
}

/// `CREATE EXTENSION [IF NOT EXISTS] name [WITH] [SCHEMA schema] [VERSION version] [CASCADE]`
#[derive(Debug, Clone, Copy)]
pub struct SyntaxCreateExtensionStmt {
    /// CREATE keyword token
    pub create_keyword: TokenId,
    /// EXTENSION keyword token (identifier in our lexer)
    pub extension_keyword: TokenId,
    /// IF keyword token (if IF NOT EXISTS present)
    pub if_keyword: Option<TokenId>,
    /// NOT keyword token (if IF NOT EXISTS present)
    pub not_keyword: Option<TokenId>,
    /// EXISTS keyword token (if IF NOT EXISTS present)
    pub exists_keyword: Option<TokenId>,
    /// Extension name span
    pub extension_name_span: Span,
    /// WITH keyword token (if present)
    pub with_keyword: Option<TokenId>,
    /// SCHEMA keyword token (if SCHEMA clause present)
    pub schema_keyword: Option<TokenId>,
    /// Schema name span (if SCHEMA clause present)
    pub schema_name_span: Option<Span>,
    /// VERSION keyword token (if VERSION clause present)
    pub version_keyword: Option<TokenId>,
    /// Version value span (if VERSION clause present)
    pub version_span: Option<Span>,
    /// CASCADE keyword token (if present)
    pub cascade_keyword: Option<TokenId>,
    /// Entire statement span
    pub span: Span,
}

/// PostgreSQL CREATE SEQUENCE statement CST
#[derive(Debug, Clone)]
pub struct SyntaxCreateSequenceStmt {
    /// CREATE keyword token
    pub create_keyword: TokenId,
    /// OR keyword token (if OR REPLACE present)
    pub or_keyword: Option<TokenId>,
    /// REPLACE keyword token (if OR REPLACE present)
    pub replace_keyword: Option<TokenId>,
    /// TEMPORARY/TEMP keyword token (if present)
    pub temp_keyword: Option<TokenId>,
    /// UNLOGGED keyword token (if present)
    pub unlogged_keyword: Option<TokenId>,
    /// SEQUENCE keyword token (identifier)
    pub sequence_keyword: TokenId,
    /// IF keyword token (if IF NOT EXISTS present)
    pub if_keyword: Option<TokenId>,
    /// NOT keyword token (if IF NOT EXISTS present)
    pub not_keyword: Option<TokenId>,
    /// EXISTS keyword token (if IF NOT EXISTS present)
    pub exists_keyword: Option<TokenId>,
    /// Sequence name span
    pub name_span: Span,
    /// Span covering all options after the name
    pub options_span: Option<Span>,
    /// Entire statement span
    pub span: Span,
}

/// PostgreSQL ALTER SEQUENCE statement CST
#[derive(Debug, Clone)]
pub struct SyntaxAlterSequenceStmt {
    /// ALTER keyword token
    pub alter_keyword: TokenId,
    /// SEQUENCE keyword token (identifier)
    pub sequence_keyword: TokenId,
    /// IF keyword token (if IF EXISTS present)
    pub if_keyword: Option<TokenId>,
    /// EXISTS keyword token (if IF EXISTS present)
    pub exists_keyword: Option<TokenId>,
    /// Sequence name span
    pub name_span: Span,
    /// Span covering all clauses after the name
    pub options_span: Option<Span>,
    /// Entire statement span
    pub span: Span,
}

/// PostgreSQL CREATE TRIGGER statement CST
#[derive(Debug, Clone)]
pub struct SyntaxCreatePgTriggerStmt {
    /// CREATE keyword token
    pub create_keyword: TokenId,
    /// OR keyword token (if OR REPLACE present)
    pub or_keyword: Option<TokenId>,
    /// REPLACE keyword token (if OR REPLACE present)
    pub replace_keyword: Option<TokenId>,
    /// CONSTRAINT keyword token (if CONSTRAINT trigger)
    pub constraint_keyword: Option<TokenId>,
    /// TRIGGER keyword token
    pub trigger_keyword: TokenId,
    /// Trigger name span
    pub trigger_name_span: Span,
    /// Timing keyword(s) span (BEFORE / AFTER / INSTEAD OF)
    pub timing_span: Span,
    /// ON keyword token
    pub on_keyword: TokenId,
    /// Table name span
    pub table_name_span: Span,
    /// EXECUTE keyword token
    pub execute_keyword: TokenId,
    /// FUNCTION or PROCEDURE keyword token
    pub func_or_proc_keyword: TokenId,
    /// Function name span
    pub function_name_span: Span,
    /// Function call parens span (including parens)
    pub function_call_parens_span: Span,
    /// Entire statement span
    pub span: Span,
}

/// PostgreSQL ALTER TRIGGER statement CST
#[derive(Debug, Clone)]
pub struct SyntaxAlterPgTriggerStmt {
    /// ALTER keyword token
    pub alter_keyword: TokenId,
    /// TRIGGER keyword token
    pub trigger_keyword: TokenId,
    /// Trigger name span
    pub trigger_name_span: Span,
    /// ON keyword token
    pub on_keyword: TokenId,
    /// Table name span
    pub table_name_span: Span,
    /// Entire statement span
    pub span: Span,
}

/// PostgreSQL DROP TRIGGER statement CST
#[derive(Debug, Clone)]
pub struct SyntaxDropPgTriggerStmt {
    /// DROP keyword token
    pub drop_keyword: TokenId,
    /// TRIGGER keyword token
    pub trigger_keyword: TokenId,
    /// IF keyword token (if IF EXISTS)
    pub if_keyword: Option<TokenId>,
    /// EXISTS keyword token (if IF EXISTS)
    pub exists_keyword: Option<TokenId>,
    /// Trigger name span
    pub trigger_name_span: Span,
    /// ON keyword token
    pub on_keyword: TokenId,
    /// Table name span
    pub table_name_span: Span,
    /// Entire statement span
    pub span: Span,
}

/// CST node for CREATE DOMAIN statement (PostgreSQL)
#[derive(Debug, Clone, Copy)]
pub struct SyntaxCreateDomainStmt {
    /// CREATE keyword token
    pub create_keyword: TokenId,
    /// DOMAIN identifier token
    pub domain_keyword: TokenId,
    /// Domain name span
    pub domain_name_span: Span,
    /// AS keyword token (if present)
    pub as_keyword: Option<TokenId>,
    /// Data type span
    pub data_type_span: Span,
    /// Entire statement span
    pub span: Span,
}

/// CST node for ALTER DOMAIN statement (PostgreSQL)
#[derive(Debug, Clone, Copy)]
pub struct SyntaxAlterDomainStmt {
    /// ALTER keyword token
    pub alter_keyword: TokenId,
    /// DOMAIN identifier token
    pub domain_keyword: TokenId,
    /// Domain name span
    pub domain_name_span: Span,
    /// Entire statement span
    pub span: Span,
}

/// CST node for DROP DOMAIN statement (PostgreSQL)
#[derive(Debug, Clone, Copy)]
pub struct SyntaxDropDomainStmt {
    /// DROP keyword token
    pub drop_keyword: TokenId,
    /// DOMAIN identifier token
    pub domain_keyword: TokenId,
    /// IF keyword token (if IF EXISTS)
    pub if_keyword: Option<TokenId>,
    /// EXISTS keyword token (if IF EXISTS)
    pub exists_keyword: Option<TokenId>,
    /// Entire statement span
    pub span: Span,
}

/// Syntax node for CREATE POLICY (PostgreSQL RLS)
#[derive(Debug, Clone, Copy)]
pub struct SyntaxCreatePgPolicyStmt {
    pub create_keyword: TokenId,
    pub policy_keyword: TokenId,
    pub span: Span,
}

/// Syntax node for ALTER POLICY (PostgreSQL RLS)
#[derive(Debug, Clone, Copy)]
pub struct SyntaxAlterPgPolicyStmt {
    pub alter_keyword: TokenId,
    pub policy_keyword: TokenId,
    pub span: Span,
}

/// Syntax node for DROP POLICY (PostgreSQL RLS)
#[derive(Debug, Clone, Copy)]
pub struct SyntaxDropPgPolicyStmt {
    pub drop_keyword: TokenId,
    pub policy_keyword: TokenId,
    pub if_keyword: Option<TokenId>,
    pub exists_keyword: Option<TokenId>,
    pub span: Span,
}

/// Syntax node for ALTER INDEX (PostgreSQL)
#[derive(Debug, Clone, Copy)]
pub struct SyntaxAlterIndexStmt {
    pub alter_keyword: TokenId,
    pub index_keyword: TokenId,
    pub span: Span,
}

/// Syntax node for REINDEX (PostgreSQL)
#[derive(Debug, Clone, Copy)]
pub struct SyntaxReindexStmt {
    pub reindex_keyword: TokenId,
    pub span: Span,
}

/// Syntax node for PG PREPARE
#[derive(Debug, Clone, Copy)]
pub struct SyntaxPgPrepareStmt {
    pub prepare_keyword: TokenId,
    pub span: Span,
}

/// Syntax node for PG EXECUTE
#[derive(Debug, Clone, Copy)]
pub struct SyntaxPgExecuteStmt {
    pub execute_keyword: TokenId,
    pub span: Span,
}

/// Syntax node for PG DEALLOCATE
#[derive(Debug, Clone, Copy)]
pub struct SyntaxPgDeallocateStmt {
    pub deallocate_keyword: TokenId,
    pub span: Span,
}

/// Syntax node for PG COPY
#[derive(Debug, Clone, Copy)]
pub struct SyntaxPgCopyStmt {
    pub copy_keyword: TokenId,
    pub span: Span,
}

/// Syntax node for PG REFRESH MATERIALIZED VIEW
#[derive(Debug, Clone, Copy)]
pub struct SyntaxPgRefreshMatviewStmt {
    pub refresh_keyword: TokenId,
    pub span: Span,
}

///
/// The parser allocates nodes here and returns IDs.
/// The formatter uses IDs to look up nodes and access their token IDs.
#[derive(Debug, Clone, Default)]
pub struct SyntaxArena {
    pub paren_exprs: Vec<SyntaxParenExpr>,
    pub row_constructors: Vec<SyntaxRowConstructor>,
    pub over_clauses: Vec<SyntaxOverClause>,
    pub function_calls: Vec<SyntaxFunctionCall>,
    pub cast_exprs: Vec<SyntaxCastExpr>,
    pub in_lists: Vec<SyntaxInList>,
    pub subqueries: Vec<SyntaxSubquery>,
    pub statements: Vec<SyntaxStatement>,
    pub array_literals: Vec<SyntaxArrayLiteral>,
    pub object_literals: Vec<SyntaxObjectLiteral>,
    pub array_subscripts: Vec<SyntaxArraySubscript>,
    pub between_exprs: Vec<SyntaxBetweenExpr>,
    pub case_exprs: Vec<SyntaxCaseExpr>,
    pub try_casts: Vec<SyntaxTryCast>,
    pub safe_casts: Vec<SyntaxSafeCast>,
    pub parameterized_types: Vec<SyntaxParameterizedType>,
    pub compound_intervals: Vec<SyntaxCompoundInterval>,
    pub colon_fields: Vec<SyntaxColonField>,
    pub bracket_fields: Vec<SyntaxBracketField>,
    pub dot_fields: Vec<SyntaxDotField>,
    pub type_casts: Vec<SyntaxTypeCast>,
    pub extracts: Vec<SyntaxExtract>,
    pub positions: Vec<SyntaxPosition>,
    pub trims: Vec<SyntaxTrim>,
    pub substrings: Vec<SyntaxSubstring>,
    pub collates: Vec<SyntaxCollate>,
    pub at_time_zones: Vec<SyntaxAtTimeZone>,
    pub scripting_vars: Vec<SyntaxScriptingVar>,
    pub distinct_ons: Vec<SyntaxDistinctOn>,
    pub returnings: Vec<SyntaxReturning>,
    pub in_subqueries: Vec<SyntaxInSubquery>,
    pub exists_subqueries: Vec<SyntaxExistsSubquery>,
    pub replace_items: Vec<SyntaxReplaceItem>,
    pub rename_items: Vec<SyntaxRenameItem>,
    pub excludes: Vec<SyntaxExclude>,
    pub renames: Vec<SyntaxRename>,
    pub replaces: Vec<SyntaxReplace>,
    pub order_items: Vec<SyntaxOrderItem>,
    pub group_by_clauses: Vec<SyntaxGroupBy>,
    pub type_precisions: Vec<SyntaxTypePrecision>,
    pub type_precision_scales: Vec<SyntaxTypePrecisionScale>,
    pub ctes: Vec<SyntaxCte>,
    pub binary_ops: Vec<SyntaxBinaryOp>,
    pub quantified_subqueries: Vec<SyntaxQuantifiedSubquery>,
    pub match_recognizes: Vec<SyntaxMatchRecognize>,
    pub measure_items: Vec<SyntaxMeasureItem>,
    pub define_symbols: Vec<SyntaxDefineSymbol>,
    pub table_refs: Vec<SyntaxTableRef>,
    pub jinja_delimiters: Vec<SyntaxJinjaDelimiter>,
    pub jinja_stmts: Vec<SyntaxJinjaStmt>,
    pub jinja_exprs: Vec<SyntaxJinjaExpr>,
    pub jinja_args: Vec<SyntaxJinjaArg>,
    pub jinja_inline_fragments: Vec<SyntaxJinjaInlineFragment>,
    pub jinja_interpolations: Vec<SyntaxJinjaInterpolation>,
    pub merge_insert_values: Vec<SyntaxMergeInsertValues>,
    pub inline_constraints: Vec<SyntaxInlineConstraint>,
    pub values: Vec<SyntaxValues>,
    pub call_stmts: Vec<SyntaxCallStmt>,
    pub alter_table_stmts: Vec<SyntaxAlterTableStmt>,
    pub alter_table_action_lists: Vec<SyntaxAlterTableActionList>,
    pub alter_table_actions: Vec<SyntaxAlterTableAction>,
    pub alter_stage_stmts: Vec<SyntaxAlterStageStmt>,
    pub alter_stage_actions: Vec<SyntaxAlterStageAction>,
    pub alter_dynamic_table_stmts: Vec<SyntaxAlterDynamicTableStmt>,
    pub create_row_access_policies: Vec<SyntaxCreateRowAccessPolicy>,
    pub create_masking_policies: Vec<SyntaxCreateMaskingPolicy>,
    pub alter_row_access_policy_stmts: Vec<SyntaxAlterRowAccessPolicyStmt>,
    pub alter_row_access_policy_actions: Vec<SyntaxAlterRowAccessPolicyAction>,
    pub drop_row_access_policies: Vec<SyntaxDropRowAccessPolicy>,
    pub drop_all_row_access_policies: Vec<SyntaxDropAllRowAccessPolicies>,
    pub alter_masking_policy_stmts: Vec<SyntaxAlterMaskingPolicyStmt>,
    pub alter_masking_policy_actions: Vec<SyntaxAlterMaskingPolicyAction>,
    pub drop_masking_policies: Vec<SyntaxDropMaskingPolicy>,
    pub create_network_policies: Vec<SyntaxCreateNetworkPolicy>,
    pub alter_network_policy_stmts: Vec<SyntaxAlterNetworkPolicy>,
    pub alter_network_policy_actions: Vec<SyntaxAlterNetworkPolicyAction>,
    pub drop_network_policies: Vec<SyntaxDropNetworkPolicy>,
    pub create_session_policies: Vec<SyntaxCreateSessionPolicy>,
    pub alter_session_policy_stmts: Vec<SyntaxAlterSessionPolicy>,
    pub alter_session_policy_actions: Vec<SyntaxAlterSessionPolicyAction>,
    pub drop_session_policies: Vec<SyntaxDropSessionPolicy>,
    pub create_authentication_policies: Vec<SyntaxCreateAuthenticationPolicy>,
    pub alter_authentication_policy_stmts: Vec<SyntaxAlterAuthenticationPolicy>,
    pub alter_authentication_policy_actions: Vec<SyntaxAlterAuthenticationPolicyAction>,
    pub drop_authentication_policies: Vec<SyntaxDropAuthenticationPolicy>,
    pub create_api_integrations: Vec<SyntaxCreateApiIntegration>,
    pub alter_api_integration_stmts: Vec<SyntaxAlterApiIntegration>,
    pub alter_api_integration_actions: Vec<SyntaxAlterApiIntegrationAction>,
    pub drop_api_integrations: Vec<SyntaxDropApiIntegration>,
    pub create_password_policies: Vec<SyntaxCreatePasswordPolicy>,
    pub alter_password_policy_stmts: Vec<SyntaxAlterPasswordPolicy>,
    pub alter_password_policy_actions: Vec<SyntaxAlterPasswordPolicyAction>,
    pub drop_password_policies: Vec<SyntaxDropPasswordPolicy>,
    pub create_aggregation_policies: Vec<SyntaxCreateAggregationPolicy>,
    pub alter_aggregation_policy_stmts: Vec<SyntaxAlterAggregationPolicy>,
    pub alter_aggregation_policy_actions: Vec<SyntaxAlterAggregationPolicyAction>,
    pub drop_aggregation_policies: Vec<SyntaxDropAggregationPolicy>,
    pub create_projection_policies: Vec<SyntaxCreateProjectionPolicy>,
    pub alter_projection_policy_stmts: Vec<SyntaxAlterProjectionPolicy>,
    pub alter_projection_policy_actions: Vec<SyntaxAlterProjectionPolicyAction>,
    pub drop_projection_policies: Vec<SyntaxDropProjectionPolicy>,
    pub create_storage_integrations: Vec<SyntaxCreateStorageIntegration>,
    pub alter_storage_integration_stmts: Vec<SyntaxAlterStorageIntegration>,
    pub alter_storage_integration_actions: Vec<SyntaxAlterStorageIntegrationAction>,
    pub drop_storage_integrations: Vec<SyntaxDropStorageIntegration>,
    pub create_external_access_integrations: Vec<SyntaxCreateExternalAccessIntegration>,
    pub alter_external_access_integration_stmts: Vec<SyntaxAlterExternalAccessIntegration>,
    pub alter_external_access_integration_actions: Vec<SyntaxAlterExternalAccessIntegrationAction>,
    pub drop_external_access_integrations: Vec<SyntaxDropExternalAccessIntegration>,
    pub create_streams: Vec<SyntaxCreateStream>,
    pub alter_stream_stmts: Vec<SyntaxAlterStreamStmt>,
    pub alter_stream_actions: Vec<SyntaxAlterStreamAction>,
    pub drop_streams: Vec<SyntaxDropStream>,
    pub view_column_lists: Vec<SyntaxViewColumnList>,
    pub view_columns: Vec<SyntaxViewColumn>,
    pub view_column_comments: Vec<SyntaxViewColumnComment>,
    pub view_column_masking_policies: Vec<SyntaxViewColumnMaskingPolicy>,
    pub view_column_projection_policies: Vec<SyntaxViewColumnProjectionPolicy>,
    pub view_column_tags: Vec<SyntaxViewColumnTag>,
    // PostgreSQL utility statement CST storage
    pub create_index_stmts: Vec<SyntaxCreateIndexStmt>,
    pub comment_on_stmts: Vec<SyntaxCommentOnStmt>,
    pub do_block_stmts: Vec<SyntaxDoBlockStmt>,
    pub vacuum_stmts: Vec<SyntaxVacuumStmt>,
    pub analyze_stmts: Vec<SyntaxAnalyzeStmt>,
    pub create_type_stmts: Vec<SyntaxCreateTypeStmt>,
    pub alter_type_stmts: Vec<SyntaxAlterTypeStmt>,
    pub create_extension_stmts: Vec<SyntaxCreateExtensionStmt>,
    pub create_sequence_stmts: Vec<SyntaxCreateSequenceStmt>,
    pub alter_sequence_stmts: Vec<SyntaxAlterSequenceStmt>,
    pub create_pg_trigger_stmts: Vec<SyntaxCreatePgTriggerStmt>,
    pub alter_pg_trigger_stmts: Vec<SyntaxAlterPgTriggerStmt>,
    pub drop_pg_trigger_stmts: Vec<SyntaxDropPgTriggerStmt>,
    pub create_domain_stmts: Vec<SyntaxCreateDomainStmt>,
    pub alter_domain_stmts: Vec<SyntaxAlterDomainStmt>,
    pub drop_domain_stmts: Vec<SyntaxDropDomainStmt>,
    pub create_pg_policy_stmts: Vec<SyntaxCreatePgPolicyStmt>,
    pub alter_pg_policy_stmts: Vec<SyntaxAlterPgPolicyStmt>,
    pub drop_pg_policy_stmts: Vec<SyntaxDropPgPolicyStmt>,
    pub alter_index_stmts: Vec<SyntaxAlterIndexStmt>,
    pub reindex_stmts: Vec<SyntaxReindexStmt>,
    pub pg_prepare_stmts: Vec<SyntaxPgPrepareStmt>,
    pub pg_execute_stmts: Vec<SyntaxPgExecuteStmt>,
    pub pg_deallocate_stmts: Vec<SyntaxPgDeallocateStmt>,
    pub pg_copy_stmts: Vec<SyntaxPgCopyStmt>,
    pub pg_refresh_matview_stmts: Vec<SyntaxPgRefreshMatviewStmt>,
    pub set_operators: Vec<SyntaxSetOperator>,
    // Databricks utility statement CST storage
    pub optimize_stmts: Vec<SyntaxOptimizeStmt>,
    pub describe_history_stmts: Vec<SyntaxDescribeHistoryStmt>,
    pub restore_stmts: Vec<SyntaxRestoreStmt>,
}

impl SyntaxArena {
    pub fn new() -> Self {
        Self::default()
    }

    // Allocation methods - return typed IDs

    pub fn alloc_paren_expr(&mut self, node: SyntaxParenExpr) -> SyntaxParenExprId {
        let id = SyntaxParenExprId(self.paren_exprs.len() as u32);
        self.paren_exprs.push(node);
        id
    }

    pub fn alloc_row_constructor(&mut self, node: SyntaxRowConstructor) -> SyntaxRowConstructorId {
        let id = SyntaxRowConstructorId(self.row_constructors.len() as u32);
        self.row_constructors.push(node);
        id
    }

    pub fn alloc_over_clause(&mut self, node: SyntaxOverClause) -> SyntaxOverClauseId {
        let id = SyntaxOverClauseId(self.over_clauses.len() as u32);
        self.over_clauses.push(node);
        id
    }

    pub fn alloc_function_call(&mut self, node: SyntaxFunctionCall) -> SyntaxFunctionCallId {
        let id = SyntaxFunctionCallId(self.function_calls.len() as u32);
        self.function_calls.push(node);
        id
    }

    pub fn alloc_cast_expr(&mut self, node: SyntaxCastExpr) -> SyntaxCastExprId {
        let id = SyntaxCastExprId(self.cast_exprs.len() as u32);
        self.cast_exprs.push(node);
        id
    }

    pub fn alloc_in_list(&mut self, node: SyntaxInList) -> SyntaxInListId {
        let id = SyntaxInListId(self.in_lists.len() as u32);
        self.in_lists.push(node);
        id
    }

    pub fn alloc_subquery(&mut self, node: SyntaxSubquery) -> SyntaxSubqueryId {
        let id = SyntaxSubqueryId(self.subqueries.len() as u32);
        self.subqueries.push(node);
        id
    }

    pub fn alloc_array_literal(&mut self, node: SyntaxArrayLiteral) -> SyntaxArrayLiteralId {
        let id = SyntaxArrayLiteralId(self.array_literals.len() as u32);
        self.array_literals.push(node);
        id
    }

    pub fn alloc_object_literal(&mut self, node: SyntaxObjectLiteral) -> SyntaxObjectLiteralId {
        let id = SyntaxObjectLiteralId(self.object_literals.len() as u32);
        self.object_literals.push(node);
        id
    }

    pub fn alloc_between_expr(&mut self, node: SyntaxBetweenExpr) -> SyntaxBetweenExprId {
        let id = SyntaxBetweenExprId(self.between_exprs.len() as u32);
        self.between_exprs.push(node);
        id
    }

    pub fn alloc_case_expr(&mut self, node: SyntaxCaseExpr) -> SyntaxCaseExprId {
        let id = SyntaxCaseExprId(self.case_exprs.len() as u32);
        self.case_exprs.push(node);
        id
    }

    pub fn alloc_try_cast(&mut self, node: SyntaxTryCast) -> SyntaxTryCastId {
        let id = SyntaxTryCastId(self.try_casts.len() as u32);
        self.try_casts.push(node);
        id
    }

    pub fn alloc_safe_cast(&mut self, node: SyntaxSafeCast) -> SyntaxSafeCastId {
        let id = SyntaxSafeCastId(self.safe_casts.len() as u32);
        self.safe_casts.push(node);
        id
    }

    pub fn alloc_parameterized_type(
        &mut self,
        node: SyntaxParameterizedType,
    ) -> SyntaxParameterizedTypeId {
        let id = SyntaxParameterizedTypeId(self.parameterized_types.len() as u32);
        self.parameterized_types.push(node);
        id
    }

    pub fn alloc_compound_interval(
        &mut self,
        node: SyntaxCompoundInterval,
    ) -> SyntaxCompoundIntervalId {
        let id = SyntaxCompoundIntervalId(self.compound_intervals.len() as u32);
        self.compound_intervals.push(node);
        id
    }

    pub fn alloc_array_subscript(&mut self, node: SyntaxArraySubscript) -> SyntaxArraySubscriptId {
        let id = SyntaxArraySubscriptId(self.array_subscripts.len() as u32);
        self.array_subscripts.push(node);
        id
    }

    pub fn alloc_colon_field(&mut self, node: SyntaxColonField) -> SyntaxColonFieldId {
        let id = SyntaxColonFieldId(self.colon_fields.len() as u32);
        self.colon_fields.push(node);
        id
    }

    pub fn alloc_bracket_field(&mut self, node: SyntaxBracketField) -> SyntaxBracketFieldId {
        let id = SyntaxBracketFieldId(self.bracket_fields.len() as u32);
        self.bracket_fields.push(node);
        id
    }

    pub fn alloc_dot_field(&mut self, node: SyntaxDotField) -> SyntaxDotFieldId {
        let id = SyntaxDotFieldId(self.dot_fields.len() as u32);
        self.dot_fields.push(node);
        id
    }

    pub fn alloc_type_cast(&mut self, node: SyntaxTypeCast) -> SyntaxTypeCastId {
        let id = SyntaxTypeCastId(self.type_casts.len() as u32);
        self.type_casts.push(node);
        id
    }

    pub fn alloc_extract(&mut self, node: SyntaxExtract) -> SyntaxExtractId {
        let id = SyntaxExtractId(self.extracts.len() as u32);
        self.extracts.push(node);
        id
    }

    pub fn alloc_position(&mut self, node: SyntaxPosition) -> SyntaxPositionId {
        let id = SyntaxPositionId(self.positions.len() as u32);
        self.positions.push(node);
        id
    }

    pub fn alloc_trim(&mut self, node: SyntaxTrim) -> SyntaxTrimId {
        let id = SyntaxTrimId(self.trims.len() as u32);
        self.trims.push(node);
        id
    }

    pub fn alloc_substring(&mut self, node: SyntaxSubstring) -> SyntaxSubstringId {
        let id = SyntaxSubstringId(self.substrings.len() as u32);
        self.substrings.push(node);
        id
    }

    pub fn alloc_collate(&mut self, node: SyntaxCollate) -> SyntaxCollateId {
        let id = SyntaxCollateId(self.collates.len() as u32);
        self.collates.push(node);
        id
    }

    pub fn alloc_at_time_zone(&mut self, node: SyntaxAtTimeZone) -> SyntaxAtTimeZoneId {
        let id = SyntaxAtTimeZoneId(self.at_time_zones.len() as u32);
        self.at_time_zones.push(node);
        id
    }

    pub fn alloc_scripting_var(&mut self, node: SyntaxScriptingVar) -> SyntaxScriptingVarId {
        let id = SyntaxScriptingVarId(self.scripting_vars.len() as u32);
        self.scripting_vars.push(node);
        id
    }

    pub fn alloc_distinct_on(&mut self, node: SyntaxDistinctOn) -> SyntaxDistinctOnId {
        let id = SyntaxDistinctOnId(self.distinct_ons.len() as u32);
        self.distinct_ons.push(node);
        id
    }

    pub fn alloc_returning(&mut self, node: SyntaxReturning) -> SyntaxReturningId {
        let id = SyntaxReturningId(self.returnings.len() as u32);
        self.returnings.push(node);
        id
    }

    pub fn alloc_in_subquery(&mut self, node: SyntaxInSubquery) -> SyntaxInSubqueryId {
        let id = SyntaxInSubqueryId(self.in_subqueries.len() as u32);
        self.in_subqueries.push(node);
        id
    }

    pub fn alloc_exists_subquery(&mut self, node: SyntaxExistsSubquery) -> SyntaxExistsSubqueryId {
        let id = SyntaxExistsSubqueryId(self.exists_subqueries.len() as u32);
        self.exists_subqueries.push(node);
        id
    }

    pub fn alloc_replace_item(&mut self, node: SyntaxReplaceItem) -> SyntaxReplaceItemId {
        let id = SyntaxReplaceItemId(self.replace_items.len() as u32);
        self.replace_items.push(node);
        id
    }

    pub fn alloc_rename_item(&mut self, node: SyntaxRenameItem) -> SyntaxRenameItemId {
        let id = SyntaxRenameItemId(self.rename_items.len() as u32);
        self.rename_items.push(node);
        id
    }

    pub fn alloc_exclude(&mut self, node: SyntaxExclude) -> SyntaxExcludeId {
        let id = SyntaxExcludeId(self.excludes.len() as u32);
        self.excludes.push(node);
        id
    }

    pub fn alloc_rename(&mut self, node: SyntaxRename) -> SyntaxRenameId {
        let id = SyntaxRenameId(self.renames.len() as u32);
        self.renames.push(node);
        id
    }

    pub fn alloc_replace(&mut self, node: SyntaxReplace) -> SyntaxReplaceId {
        let id = SyntaxReplaceId(self.replaces.len() as u32);
        self.replaces.push(node);
        id
    }

    pub fn alloc_order_item(&mut self, node: SyntaxOrderItem) -> SyntaxOrderItemId {
        let id = SyntaxOrderItemId(self.order_items.len() as u32);
        self.order_items.push(node);
        id
    }

    pub fn alloc_group_by(&mut self, node: SyntaxGroupBy) -> SyntaxGroupById {
        let id = SyntaxGroupById(self.group_by_clauses.len() as u32);
        self.group_by_clauses.push(node);
        id
    }

    pub fn alloc_call_stmt(&mut self, node: SyntaxCallStmt) -> SyntaxCallStmtId {
        let id = SyntaxCallStmtId(self.call_stmts.len() as u32);
        self.call_stmts.push(node);
        id
    }

    pub fn alloc_alter_table_stmt(&mut self, node: SyntaxAlterTableStmt) -> SyntaxAlterTableStmtId {
        let id = SyntaxAlterTableStmtId(self.alter_table_stmts.len() as u32);
        self.alter_table_stmts.push(node);
        id
    }

    pub fn alloc_alter_table_action_list(
        &mut self,
        node: SyntaxAlterTableActionList,
    ) -> SyntaxAlterTableActionListId {
        let id = SyntaxAlterTableActionListId(self.alter_table_action_lists.len() as u32);
        self.alter_table_action_lists.push(node);
        id
    }

    pub fn alloc_alter_table_action(
        &mut self,
        node: SyntaxAlterTableAction,
    ) -> SyntaxAlterTableActionId {
        let id = SyntaxAlterTableActionId(self.alter_table_actions.len() as u32);
        self.alter_table_actions.push(node);
        id
    }

    pub fn alloc_alter_stage_stmt(&mut self, node: SyntaxAlterStageStmt) -> SyntaxAlterStageStmtId {
        let id = SyntaxAlterStageStmtId(self.alter_stage_stmts.len() as u32);
        self.alter_stage_stmts.push(node);
        id
    }

    pub fn alloc_alter_stage_action(
        &mut self,
        node: SyntaxAlterStageAction,
    ) -> SyntaxAlterStageActionId {
        let id = SyntaxAlterStageActionId(self.alter_stage_actions.len() as u32);
        self.alter_stage_actions.push(node);
        id
    }

    pub fn alloc_alter_dynamic_table_stmt(
        &mut self,
        node: SyntaxAlterDynamicTableStmt,
    ) -> SyntaxAlterDynamicTableStmtId {
        let id = SyntaxAlterDynamicTableStmtId(self.alter_dynamic_table_stmts.len() as u32);
        self.alter_dynamic_table_stmts.push(node);
        id
    }

    pub fn alloc_type_precision(&mut self, node: SyntaxTypePrecision) -> SyntaxTypePrecisionId {
        let id = SyntaxTypePrecisionId(self.type_precisions.len() as u32);
        self.type_precisions.push(node);
        id
    }

    pub fn alloc_type_precision_scale(
        &mut self,
        node: SyntaxTypePrecisionScale,
    ) -> SyntaxTypePrecisionScaleId {
        let id = SyntaxTypePrecisionScaleId(self.type_precision_scales.len() as u32);
        self.type_precision_scales.push(node);
        id
    }

    pub fn alloc_cte(&mut self, node: SyntaxCte) -> SyntaxCteId {
        let id = SyntaxCteId(self.ctes.len() as u32);
        self.ctes.push(node);
        id
    }

    pub fn alloc_binary_op(&mut self, node: SyntaxBinaryOp) -> SyntaxBinaryOpId {
        let id = SyntaxBinaryOpId(self.binary_ops.len() as u32);
        self.binary_ops.push(node);
        id
    }

    pub fn alloc_quantified_subquery(
        &mut self,
        node: SyntaxQuantifiedSubquery,
    ) -> SyntaxQuantifiedSubqueryId {
        let id = SyntaxQuantifiedSubqueryId(self.quantified_subqueries.len() as u32);
        self.quantified_subqueries.push(node);
        id
    }

    pub fn alloc_match_recognize(&mut self, node: SyntaxMatchRecognize) -> SyntaxMatchRecognizeId {
        let id = SyntaxMatchRecognizeId(self.match_recognizes.len() as u32);
        self.match_recognizes.push(node);
        id
    }

    pub fn alloc_measure_item(&mut self, node: SyntaxMeasureItem) -> SyntaxMeasureItemId {
        let id = SyntaxMeasureItemId(self.measure_items.len() as u32);
        self.measure_items.push(node);
        id
    }

    pub fn alloc_define_symbol(&mut self, node: SyntaxDefineSymbol) -> SyntaxDefineSymbolId {
        let id = SyntaxDefineSymbolId(self.define_symbols.len() as u32);
        self.define_symbols.push(node);
        id
    }

    pub fn alloc_table_ref(&mut self, node: SyntaxTableRef) -> SyntaxTableRefId {
        let id = SyntaxTableRefId(self.table_refs.len() as u32);
        self.table_refs.push(node);
        id
    }

    pub fn alloc_jinja_delimiter(&mut self, node: SyntaxJinjaDelimiter) -> SyntaxJinjaDelimiterId {
        let id = SyntaxJinjaDelimiterId(self.jinja_delimiters.len() as u32);
        self.jinja_delimiters.push(node);
        id
    }

    pub fn alloc_jinja_stmt(&mut self, node: SyntaxJinjaStmt) -> SyntaxJinjaStmtId {
        let id = SyntaxJinjaStmtId(self.jinja_stmts.len() as u32);
        self.jinja_stmts.push(node);
        id
    }

    pub fn alloc_jinja_expr(&mut self, node: SyntaxJinjaExpr) -> SyntaxJinjaExprId {
        let id = SyntaxJinjaExprId(self.jinja_exprs.len() as u32);
        self.jinja_exprs.push(node);
        id
    }

    pub fn alloc_jinja_arg(&mut self, node: SyntaxJinjaArg) -> SyntaxJinjaArgId {
        let id = SyntaxJinjaArgId(self.jinja_args.len() as u32);
        self.jinja_args.push(node);
        id
    }

    pub fn alloc_jinja_inline_fragment(
        &mut self,
        node: SyntaxJinjaInlineFragment,
    ) -> SyntaxJinjaInlineFragmentId {
        let id = SyntaxJinjaInlineFragmentId(self.jinja_inline_fragments.len() as u32);
        self.jinja_inline_fragments.push(node);
        id
    }

    pub fn alloc_jinja_interpolation(
        &mut self,
        node: SyntaxJinjaInterpolation,
    ) -> SyntaxJinjaInterpolationId {
        let id = SyntaxJinjaInterpolationId(self.jinja_interpolations.len() as u32);
        self.jinja_interpolations.push(node);
        id
    }

    pub fn alloc_merge_insert_values(
        &mut self,
        node: SyntaxMergeInsertValues,
    ) -> SyntaxMergeInsertValuesId {
        let id = SyntaxMergeInsertValuesId(self.merge_insert_values.len() as u32);
        self.merge_insert_values.push(node);
        id
    }

    pub fn alloc_inline_constraint(
        &mut self,
        node: SyntaxInlineConstraint,
    ) -> SyntaxInlineConstraintId {
        let id = SyntaxInlineConstraintId(self.inline_constraints.len() as u32);
        self.inline_constraints.push(node);
        id
    }

    pub fn alloc_values(&mut self, node: SyntaxValues) -> SyntaxValuesId {
        let id = SyntaxValuesId(self.values.len() as u32);
        self.values.push(node);
        id
    }

    // Lookup methods - get nodes by ID

    pub fn get_paren_expr(&self, id: SyntaxParenExprId) -> &SyntaxParenExpr {
        &self.paren_exprs[id.0 as usize]
    }

    pub fn get_row_constructor(&self, id: SyntaxRowConstructorId) -> &SyntaxRowConstructor {
        &self.row_constructors[id.0 as usize]
    }

    pub fn get_over_clause(&self, id: SyntaxOverClauseId) -> &SyntaxOverClause {
        &self.over_clauses[id.0 as usize]
    }

    pub fn get_function_call(&self, id: SyntaxFunctionCallId) -> &SyntaxFunctionCall {
        &self.function_calls[id.0 as usize]
    }

    pub fn get_cast_expr(&self, id: SyntaxCastExprId) -> &SyntaxCastExpr {
        &self.cast_exprs[id.0 as usize]
    }

    pub fn get_in_list(&self, id: SyntaxInListId) -> &SyntaxInList {
        &self.in_lists[id.0 as usize]
    }

    pub fn get_subquery(&self, id: SyntaxSubqueryId) -> &SyntaxSubquery {
        &self.subqueries[id.0 as usize]
    }

    pub fn get_statement(&self, id: SyntaxStatementId) -> &SyntaxStatement {
        &self.statements[id.0 as usize]
    }

    pub fn get_array_literal(&self, id: SyntaxArrayLiteralId) -> &SyntaxArrayLiteral {
        &self.array_literals[id.0 as usize]
    }

    pub fn get_object_literal(&self, id: SyntaxObjectLiteralId) -> &SyntaxObjectLiteral {
        &self.object_literals[id.0 as usize]
    }

    pub fn get_between_expr(&self, id: SyntaxBetweenExprId) -> &SyntaxBetweenExpr {
        &self.between_exprs[id.0 as usize]
    }

    pub fn get_case_expr(&self, id: SyntaxCaseExprId) -> &SyntaxCaseExpr {
        &self.case_exprs[id.0 as usize]
    }

    pub fn get_try_cast(&self, id: SyntaxTryCastId) -> &SyntaxTryCast {
        &self.try_casts[id.0 as usize]
    }

    pub fn get_safe_cast(&self, id: SyntaxSafeCastId) -> &SyntaxSafeCast {
        &self.safe_casts[id.0 as usize]
    }

    pub fn get_parameterized_type(
        &self,
        id: SyntaxParameterizedTypeId,
    ) -> &SyntaxParameterizedType {
        &self.parameterized_types[id.0 as usize]
    }

    pub fn get_array_subscript(&self, id: SyntaxArraySubscriptId) -> &SyntaxArraySubscript {
        &self.array_subscripts[id.0 as usize]
    }

    pub fn get_colon_field(&self, id: SyntaxColonFieldId) -> &SyntaxColonField {
        &self.colon_fields[id.0 as usize]
    }

    pub fn get_bracket_field(&self, id: SyntaxBracketFieldId) -> &SyntaxBracketField {
        &self.bracket_fields[id.0 as usize]
    }

    pub fn get_dot_field(&self, id: SyntaxDotFieldId) -> &SyntaxDotField {
        &self.dot_fields[id.0 as usize]
    }

    pub fn get_type_cast(&self, id: SyntaxTypeCastId) -> &SyntaxTypeCast {
        &self.type_casts[id.0 as usize]
    }

    pub fn get_extract(&self, id: SyntaxExtractId) -> &SyntaxExtract {
        &self.extracts[id.0 as usize]
    }

    pub fn get_position(&self, id: SyntaxPositionId) -> &SyntaxPosition {
        &self.positions[id.0 as usize]
    }

    pub fn get_trim(&self, id: SyntaxTrimId) -> &SyntaxTrim {
        &self.trims[id.0 as usize]
    }

    pub fn get_substring(&self, id: SyntaxSubstringId) -> &SyntaxSubstring {
        &self.substrings[id.0 as usize]
    }

    pub fn get_collate(&self, id: SyntaxCollateId) -> &SyntaxCollate {
        &self.collates[id.0 as usize]
    }

    pub fn get_at_time_zone(&self, id: SyntaxAtTimeZoneId) -> &SyntaxAtTimeZone {
        &self.at_time_zones[id.0 as usize]
    }

    pub fn get_scripting_var(&self, id: SyntaxScriptingVarId) -> &SyntaxScriptingVar {
        &self.scripting_vars[id.0 as usize]
    }

    pub fn get_distinct_on(&self, id: SyntaxDistinctOnId) -> &SyntaxDistinctOn {
        &self.distinct_ons[id.0 as usize]
    }

    pub fn get_returning(&self, id: SyntaxReturningId) -> &SyntaxReturning {
        &self.returnings[id.0 as usize]
    }

    pub fn get_in_subquery(&self, id: SyntaxInSubqueryId) -> &SyntaxInSubquery {
        &self.in_subqueries[id.0 as usize]
    }

    pub fn get_exists_subquery(&self, id: SyntaxExistsSubqueryId) -> &SyntaxExistsSubquery {
        &self.exists_subqueries[id.0 as usize]
    }

    pub fn get_replace_item(&self, id: SyntaxReplaceItemId) -> &SyntaxReplaceItem {
        &self.replace_items[id.0 as usize]
    }

    pub fn get_rename_item(&self, id: SyntaxRenameItemId) -> &SyntaxRenameItem {
        &self.rename_items[id.0 as usize]
    }

    pub fn get_exclude(&self, id: SyntaxExcludeId) -> &SyntaxExclude {
        &self.excludes[id.0 as usize]
    }

    pub fn get_rename(&self, id: SyntaxRenameId) -> &SyntaxRename {
        &self.renames[id.0 as usize]
    }

    pub fn get_replace(&self, id: SyntaxReplaceId) -> &SyntaxReplace {
        &self.replaces[id.0 as usize]
    }

    pub fn get_call_stmt(&self, id: SyntaxCallStmtId) -> &SyntaxCallStmt {
        &self.call_stmts[id.0 as usize]
    }

    pub fn get_alter_table_stmt(&self, id: SyntaxAlterTableStmtId) -> &SyntaxAlterTableStmt {
        &self.alter_table_stmts[id.0 as usize]
    }

    pub fn get_alter_table_action_list(
        &self,
        id: SyntaxAlterTableActionListId,
    ) -> &SyntaxAlterTableActionList {
        &self.alter_table_action_lists[id.0 as usize]
    }

    pub fn get_alter_table_action(&self, id: SyntaxAlterTableActionId) -> &SyntaxAlterTableAction {
        &self.alter_table_actions[id.0 as usize]
    }

    pub fn get_alter_dynamic_table_stmt(
        &self,
        id: SyntaxAlterDynamicTableStmtId,
    ) -> &SyntaxAlterDynamicTableStmt {
        &self.alter_dynamic_table_stmts[id.0 as usize]
    }

    pub fn get_order_item(&self, id: SyntaxOrderItemId) -> &SyntaxOrderItem {
        &self.order_items[id.0 as usize]
    }

    pub fn get_group_by(&self, id: SyntaxGroupById) -> &SyntaxGroupBy {
        &self.group_by_clauses[id.0 as usize]
    }

    pub fn get_type_precision(&self, id: SyntaxTypePrecisionId) -> &SyntaxTypePrecision {
        &self.type_precisions[id.0 as usize]
    }

    pub fn get_type_precision_scale(
        &self,
        id: SyntaxTypePrecisionScaleId,
    ) -> &SyntaxTypePrecisionScale {
        &self.type_precision_scales[id.0 as usize]
    }

    pub fn get_cte(&self, id: SyntaxCteId) -> &SyntaxCte {
        &self.ctes[id.0 as usize]
    }

    pub fn get_binary_op(&self, id: SyntaxBinaryOpId) -> &SyntaxBinaryOp {
        &self.binary_ops[id.0 as usize]
    }

    pub fn get_quantified_subquery(
        &self,
        id: SyntaxQuantifiedSubqueryId,
    ) -> &SyntaxQuantifiedSubquery {
        &self.quantified_subqueries[id.0 as usize]
    }

    pub fn get_match_recognize(&self, id: SyntaxMatchRecognizeId) -> &SyntaxMatchRecognize {
        &self.match_recognizes[id.0 as usize]
    }

    pub fn get_measure_item(&self, id: SyntaxMeasureItemId) -> &SyntaxMeasureItem {
        &self.measure_items[id.0 as usize]
    }

    pub fn get_define_symbol(&self, id: SyntaxDefineSymbolId) -> &SyntaxDefineSymbol {
        &self.define_symbols[id.0 as usize]
    }

    pub fn get_table_ref(&self, id: SyntaxTableRefId) -> &SyntaxTableRef {
        &self.table_refs[id.0 as usize]
    }

    pub fn get_jinja_delimiter(&self, id: SyntaxJinjaDelimiterId) -> &SyntaxJinjaDelimiter {
        &self.jinja_delimiters[id.0 as usize]
    }

    pub fn get_jinja_stmt(&self, id: SyntaxJinjaStmtId) -> &SyntaxJinjaStmt {
        &self.jinja_stmts[id.0 as usize]
    }

    pub fn get_jinja_expr(&self, id: SyntaxJinjaExprId) -> &SyntaxJinjaExpr {
        &self.jinja_exprs[id.0 as usize]
    }

    pub fn get_jinja_arg(&self, id: SyntaxJinjaArgId) -> &SyntaxJinjaArg {
        &self.jinja_args[id.0 as usize]
    }

    pub fn get_jinja_inline_fragment(
        &self,
        id: SyntaxJinjaInlineFragmentId,
    ) -> &SyntaxJinjaInlineFragment {
        &self.jinja_inline_fragments[id.0 as usize]
    }

    pub fn get_jinja_interpolation(
        &self,
        id: SyntaxJinjaInterpolationId,
    ) -> &SyntaxJinjaInterpolation {
        &self.jinja_interpolations[id.0 as usize]
    }

    pub fn get_merge_insert_values(
        &self,
        id: SyntaxMergeInsertValuesId,
    ) -> &SyntaxMergeInsertValues {
        &self.merge_insert_values[id.0 as usize]
    }

    pub fn get_inline_constraint(&self, id: SyntaxInlineConstraintId) -> &SyntaxInlineConstraint {
        &self.inline_constraints[id.0 as usize]
    }

    pub fn get_values(&self, id: SyntaxValuesId) -> &SyntaxValues {
        &self.values[id.0 as usize]
    }

    pub fn alloc_create_row_access_policy(
        &mut self,
        node: SyntaxCreateRowAccessPolicy,
    ) -> SyntaxCreateRowAccessPolicyId {
        let id = SyntaxCreateRowAccessPolicyId(self.create_row_access_policies.len() as u32);
        self.create_row_access_policies.push(node);
        id
    }

    pub fn alloc_alter_row_access_policy_stmt(
        &mut self,
        node: SyntaxAlterRowAccessPolicyStmt,
    ) -> SyntaxAlterRowAccessPolicyStmtId {
        let id = SyntaxAlterRowAccessPolicyStmtId(self.alter_row_access_policy_stmts.len() as u32);
        self.alter_row_access_policy_stmts.push(node);
        id
    }

    pub fn alloc_alter_row_access_policy_action(
        &mut self,
        node: SyntaxAlterRowAccessPolicyAction,
    ) -> SyntaxAlterRowAccessPolicyActionId {
        let id =
            SyntaxAlterRowAccessPolicyActionId(self.alter_row_access_policy_actions.len() as u32);
        self.alter_row_access_policy_actions.push(node);
        id
    }

    pub fn alloc_drop_row_access_policy(
        &mut self,
        node: SyntaxDropRowAccessPolicy,
    ) -> SyntaxDropRowAccessPolicyId {
        let id = SyntaxDropRowAccessPolicyId(self.drop_row_access_policies.len() as u32);
        self.drop_row_access_policies.push(node);
        id
    }

    pub fn alloc_drop_all_row_access_policies(
        &mut self,
        node: SyntaxDropAllRowAccessPolicies,
    ) -> SyntaxDropAllRowAccessPoliciesId {
        let id = SyntaxDropAllRowAccessPoliciesId(self.drop_all_row_access_policies.len() as u32);
        self.drop_all_row_access_policies.push(node);
        id
    }

    pub fn alloc_create_masking_policy(
        &mut self,
        node: SyntaxCreateMaskingPolicy,
    ) -> SyntaxCreateMaskingPolicyId {
        let id = SyntaxCreateMaskingPolicyId(self.create_masking_policies.len() as u32);
        self.create_masking_policies.push(node);
        id
    }

    pub fn alloc_alter_masking_policy_stmt(
        &mut self,
        node: SyntaxAlterMaskingPolicyStmt,
    ) -> SyntaxAlterMaskingPolicyStmtId {
        let id = SyntaxAlterMaskingPolicyStmtId(self.alter_masking_policy_stmts.len() as u32);
        self.alter_masking_policy_stmts.push(node);
        id
    }

    pub fn alloc_alter_masking_policy_action(
        &mut self,
        node: SyntaxAlterMaskingPolicyAction,
    ) -> SyntaxAlterMaskingPolicyActionId {
        let id = SyntaxAlterMaskingPolicyActionId(self.alter_masking_policy_actions.len() as u32);
        self.alter_masking_policy_actions.push(node);
        id
    }

    pub fn alloc_drop_masking_policy(
        &mut self,
        node: SyntaxDropMaskingPolicy,
    ) -> SyntaxDropMaskingPolicyId {
        let id = SyntaxDropMaskingPolicyId(self.drop_masking_policies.len() as u32);
        self.drop_masking_policies.push(node);
        id
    }

    pub fn alloc_create_network_policy(
        &mut self,
        node: SyntaxCreateNetworkPolicy,
    ) -> SyntaxCreateNetworkPolicyId {
        let id = SyntaxCreateNetworkPolicyId(self.create_network_policies.len() as u32);
        self.create_network_policies.push(node);
        id
    }

    pub fn alloc_alter_network_policy_stmt(
        &mut self,
        node: SyntaxAlterNetworkPolicy,
    ) -> SyntaxAlterNetworkPolicyId {
        let id = SyntaxAlterNetworkPolicyId(self.alter_network_policy_stmts.len() as u32);
        self.alter_network_policy_stmts.push(node);
        id
    }

    pub fn alloc_alter_network_policy_action(
        &mut self,
        node: SyntaxAlterNetworkPolicyAction,
    ) -> SyntaxAlterNetworkPolicyActionId {
        let id = SyntaxAlterNetworkPolicyActionId(self.alter_network_policy_actions.len() as u32);
        self.alter_network_policy_actions.push(node);
        id
    }

    pub fn alloc_drop_network_policy(
        &mut self,
        node: SyntaxDropNetworkPolicy,
    ) -> SyntaxDropNetworkPolicyId {
        let id = SyntaxDropNetworkPolicyId(self.drop_network_policies.len() as u32);
        self.drop_network_policies.push(node);
        id
    }

    pub fn alloc_create_session_policy(
        &mut self,
        node: SyntaxCreateSessionPolicy,
    ) -> SyntaxCreateSessionPolicyId {
        let id = SyntaxCreateSessionPolicyId(self.create_session_policies.len() as u32);
        self.create_session_policies.push(node);
        id
    }

    pub fn alloc_alter_session_policy_stmt(
        &mut self,
        node: SyntaxAlterSessionPolicy,
    ) -> SyntaxAlterSessionPolicyStmtId {
        let id = SyntaxAlterSessionPolicyStmtId(self.alter_session_policy_stmts.len() as u32);
        self.alter_session_policy_stmts.push(node);
        id
    }

    pub fn alloc_alter_session_policy_action(
        &mut self,
        node: SyntaxAlterSessionPolicyAction,
    ) -> SyntaxAlterSessionPolicyActionId {
        let id = SyntaxAlterSessionPolicyActionId(self.alter_session_policy_actions.len() as u32);
        self.alter_session_policy_actions.push(node);
        id
    }

    pub fn alloc_drop_session_policy(
        &mut self,
        node: SyntaxDropSessionPolicy,
    ) -> SyntaxDropSessionPolicyId {
        let id = SyntaxDropSessionPolicyId(self.drop_session_policies.len() as u32);
        self.drop_session_policies.push(node);
        id
    }

    pub fn alloc_create_authentication_policy(
        &mut self,
        node: SyntaxCreateAuthenticationPolicy,
    ) -> SyntaxCreateAuthenticationPolicyId {
        let id =
            SyntaxCreateAuthenticationPolicyId(self.create_authentication_policies.len() as u32);
        self.create_authentication_policies.push(node);
        id
    }

    pub fn alloc_alter_authentication_policy_stmt(
        &mut self,
        node: SyntaxAlterAuthenticationPolicy,
    ) -> SyntaxAlterAuthenticationPolicyStmtId {
        let id = SyntaxAlterAuthenticationPolicyStmtId(
            self.alter_authentication_policy_stmts.len() as u32,
        );
        self.alter_authentication_policy_stmts.push(node);
        id
    }

    pub fn alloc_alter_authentication_policy_action(
        &mut self,
        node: SyntaxAlterAuthenticationPolicyAction,
    ) -> SyntaxAlterAuthenticationPolicyActionId {
        let id = SyntaxAlterAuthenticationPolicyActionId(
            self.alter_authentication_policy_actions.len() as u32,
        );
        self.alter_authentication_policy_actions.push(node);
        id
    }

    pub fn alloc_drop_authentication_policy(
        &mut self,
        node: SyntaxDropAuthenticationPolicy,
    ) -> SyntaxDropAuthenticationPolicyId {
        let id = SyntaxDropAuthenticationPolicyId(self.drop_authentication_policies.len() as u32);
        self.drop_authentication_policies.push(node);
        id
    }

    pub fn alloc_create_api_integration(
        &mut self,
        node: SyntaxCreateApiIntegration,
    ) -> SyntaxCreateApiIntegrationId {
        let id = SyntaxCreateApiIntegrationId(self.create_api_integrations.len() as u32);
        self.create_api_integrations.push(node);
        id
    }

    pub fn alloc_alter_api_integration_stmt(
        &mut self,
        node: SyntaxAlterApiIntegration,
    ) -> SyntaxAlterApiIntegrationStmtId {
        let id = SyntaxAlterApiIntegrationStmtId(self.alter_api_integration_stmts.len() as u32);
        self.alter_api_integration_stmts.push(node);
        id
    }

    pub fn alloc_alter_api_integration_action(
        &mut self,
        node: SyntaxAlterApiIntegrationAction,
    ) -> SyntaxAlterApiIntegrationActionId {
        let id = SyntaxAlterApiIntegrationActionId(self.alter_api_integration_actions.len() as u32);
        self.alter_api_integration_actions.push(node);
        id
    }

    pub fn alloc_drop_api_integration(
        &mut self,
        node: SyntaxDropApiIntegration,
    ) -> SyntaxDropApiIntegrationId {
        let id = SyntaxDropApiIntegrationId(self.drop_api_integrations.len() as u32);
        self.drop_api_integrations.push(node);
        id
    }

    pub fn alloc_create_password_policy(
        &mut self,
        node: SyntaxCreatePasswordPolicy,
    ) -> SyntaxCreatePasswordPolicyId {
        let id = SyntaxCreatePasswordPolicyId(self.create_password_policies.len() as u32);
        self.create_password_policies.push(node);
        id
    }

    pub fn alloc_alter_password_policy_stmt(
        &mut self,
        node: SyntaxAlterPasswordPolicy,
    ) -> SyntaxAlterPasswordPolicyStmtId {
        let id = SyntaxAlterPasswordPolicyStmtId(self.alter_password_policy_stmts.len() as u32);
        self.alter_password_policy_stmts.push(node);
        id
    }

    pub fn alloc_alter_password_policy_action(
        &mut self,
        node: SyntaxAlterPasswordPolicyAction,
    ) -> SyntaxAlterPasswordPolicyActionId {
        let id = SyntaxAlterPasswordPolicyActionId(self.alter_password_policy_actions.len() as u32);
        self.alter_password_policy_actions.push(node);
        id
    }

    pub fn alloc_drop_password_policy(
        &mut self,
        node: SyntaxDropPasswordPolicy,
    ) -> SyntaxDropPasswordPolicyId {
        let id = SyntaxDropPasswordPolicyId(self.drop_password_policies.len() as u32);
        self.drop_password_policies.push(node);
        id
    }

    pub fn alloc_create_aggregation_policy(
        &mut self,
        node: SyntaxCreateAggregationPolicy,
    ) -> SyntaxCreateAggregationPolicyId {
        let id = SyntaxCreateAggregationPolicyId(self.create_aggregation_policies.len() as u32);
        self.create_aggregation_policies.push(node);
        id
    }

    pub fn alloc_alter_aggregation_policy_stmt(
        &mut self,
        node: SyntaxAlterAggregationPolicy,
    ) -> SyntaxAlterAggregationPolicyStmtId {
        let id =
            SyntaxAlterAggregationPolicyStmtId(self.alter_aggregation_policy_stmts.len() as u32);
        self.alter_aggregation_policy_stmts.push(node);
        id
    }

    pub fn alloc_alter_aggregation_policy_action(
        &mut self,
        node: SyntaxAlterAggregationPolicyAction,
    ) -> SyntaxAlterAggregationPolicyActionId {
        let id = SyntaxAlterAggregationPolicyActionId(
            self.alter_aggregation_policy_actions.len() as u32
        );
        self.alter_aggregation_policy_actions.push(node);
        id
    }

    pub fn alloc_drop_aggregation_policy(
        &mut self,
        node: SyntaxDropAggregationPolicy,
    ) -> SyntaxDropAggregationPolicyId {
        let id = SyntaxDropAggregationPolicyId(self.drop_aggregation_policies.len() as u32);
        self.drop_aggregation_policies.push(node);
        id
    }

    pub fn alloc_create_projection_policy(
        &mut self,
        node: SyntaxCreateProjectionPolicy,
    ) -> SyntaxCreateProjectionPolicyId {
        let id = SyntaxCreateProjectionPolicyId(self.create_projection_policies.len() as u32);
        self.create_projection_policies.push(node);
        id
    }

    pub fn alloc_alter_projection_policy_stmt(
        &mut self,
        node: SyntaxAlterProjectionPolicy,
    ) -> SyntaxAlterProjectionPolicyStmtId {
        let id = SyntaxAlterProjectionPolicyStmtId(self.alter_projection_policy_stmts.len() as u32);
        self.alter_projection_policy_stmts.push(node);
        id
    }

    pub fn alloc_alter_projection_policy_action(
        &mut self,
        node: SyntaxAlterProjectionPolicyAction,
    ) -> SyntaxAlterProjectionPolicyActionId {
        let id =
            SyntaxAlterProjectionPolicyActionId(self.alter_projection_policy_actions.len() as u32);
        self.alter_projection_policy_actions.push(node);
        id
    }

    pub fn alloc_drop_projection_policy(
        &mut self,
        node: SyntaxDropProjectionPolicy,
    ) -> SyntaxDropProjectionPolicyId {
        let id = SyntaxDropProjectionPolicyId(self.drop_projection_policies.len() as u32);
        self.drop_projection_policies.push(node);
        id
    }

    pub fn alloc_create_storage_integration(
        &mut self,
        node: SyntaxCreateStorageIntegration,
    ) -> SyntaxCreateStorageIntegrationId {
        let id = SyntaxCreateStorageIntegrationId(self.create_storage_integrations.len() as u32);
        self.create_storage_integrations.push(node);
        id
    }

    pub fn alloc_alter_storage_integration_stmt(
        &mut self,
        node: SyntaxAlterStorageIntegration,
    ) -> SyntaxAlterStorageIntegrationStmtId {
        let id =
            SyntaxAlterStorageIntegrationStmtId(self.alter_storage_integration_stmts.len() as u32);
        self.alter_storage_integration_stmts.push(node);
        id
    }

    pub fn alloc_alter_storage_integration_action(
        &mut self,
        node: SyntaxAlterStorageIntegrationAction,
    ) -> SyntaxAlterStorageIntegrationActionId {
        let id = SyntaxAlterStorageIntegrationActionId(
            self.alter_storage_integration_actions.len() as u32,
        );
        self.alter_storage_integration_actions.push(node);
        id
    }

    pub fn alloc_drop_storage_integration(
        &mut self,
        node: SyntaxDropStorageIntegration,
    ) -> SyntaxDropStorageIntegrationId {
        let id = SyntaxDropStorageIntegrationId(self.drop_storage_integrations.len() as u32);
        self.drop_storage_integrations.push(node);
        id
    }

    pub fn alloc_create_external_access_integration(
        &mut self,
        node: SyntaxCreateExternalAccessIntegration,
    ) -> SyntaxCreateExternalAccessIntegrationId {
        let id = SyntaxCreateExternalAccessIntegrationId(
            self.create_external_access_integrations.len() as u32,
        );
        self.create_external_access_integrations.push(node);
        id
    }

    pub fn alloc_alter_external_access_integration_stmt(
        &mut self,
        node: SyntaxAlterExternalAccessIntegration,
    ) -> SyntaxAlterExternalAccessIntegrationStmtId {
        let id = SyntaxAlterExternalAccessIntegrationStmtId(
            self.alter_external_access_integration_stmts.len() as u32,
        );
        self.alter_external_access_integration_stmts.push(node);
        id
    }

    pub fn alloc_alter_external_access_integration_action(
        &mut self,
        node: SyntaxAlterExternalAccessIntegrationAction,
    ) -> SyntaxAlterExternalAccessIntegrationActionId {
        let id = SyntaxAlterExternalAccessIntegrationActionId(
            self.alter_external_access_integration_actions.len() as u32,
        );
        self.alter_external_access_integration_actions.push(node);
        id
    }

    pub fn alloc_drop_external_access_integration(
        &mut self,
        node: SyntaxDropExternalAccessIntegration,
    ) -> SyntaxDropExternalAccessIntegrationId {
        let id = SyntaxDropExternalAccessIntegrationId(
            self.drop_external_access_integrations.len() as u32,
        );
        self.drop_external_access_integrations.push(node);
        id
    }

    // ========================================================================
    // Getter methods for policy/integration syntax nodes
    // (47 methods — closing the alloc/get symmetry gap)
    // ========================================================================

    pub fn get_alter_aggregation_policy_action(
        &self,
        id: SyntaxAlterAggregationPolicyActionId,
    ) -> &SyntaxAlterAggregationPolicyAction {
        &self.alter_aggregation_policy_actions[id.0 as usize]
    }

    pub fn get_alter_aggregation_policy_stmt(
        &self,
        id: SyntaxAlterAggregationPolicyStmtId,
    ) -> &SyntaxAlterAggregationPolicy {
        &self.alter_aggregation_policy_stmts[id.0 as usize]
    }

    pub fn get_alter_api_integration_action(
        &self,
        id: SyntaxAlterApiIntegrationActionId,
    ) -> &SyntaxAlterApiIntegrationAction {
        &self.alter_api_integration_actions[id.0 as usize]
    }

    pub fn get_alter_api_integration_stmt(
        &self,
        id: SyntaxAlterApiIntegrationStmtId,
    ) -> &SyntaxAlterApiIntegration {
        &self.alter_api_integration_stmts[id.0 as usize]
    }

    pub fn get_alter_authentication_policy_action(
        &self,
        id: SyntaxAlterAuthenticationPolicyActionId,
    ) -> &SyntaxAlterAuthenticationPolicyAction {
        &self.alter_authentication_policy_actions[id.0 as usize]
    }

    pub fn get_alter_authentication_policy_stmt(
        &self,
        id: SyntaxAlterAuthenticationPolicyStmtId,
    ) -> &SyntaxAlterAuthenticationPolicy {
        &self.alter_authentication_policy_stmts[id.0 as usize]
    }

    pub fn get_alter_external_access_integration_action(
        &self,
        id: SyntaxAlterExternalAccessIntegrationActionId,
    ) -> &SyntaxAlterExternalAccessIntegrationAction {
        &self.alter_external_access_integration_actions[id.0 as usize]
    }

    pub fn get_alter_external_access_integration_stmt(
        &self,
        id: SyntaxAlterExternalAccessIntegrationStmtId,
    ) -> &SyntaxAlterExternalAccessIntegration {
        &self.alter_external_access_integration_stmts[id.0 as usize]
    }

    pub fn get_alter_masking_policy_action(
        &self,
        id: SyntaxAlterMaskingPolicyActionId,
    ) -> &SyntaxAlterMaskingPolicyAction {
        &self.alter_masking_policy_actions[id.0 as usize]
    }

    pub fn get_alter_masking_policy_stmt(
        &self,
        id: SyntaxAlterMaskingPolicyStmtId,
    ) -> &SyntaxAlterMaskingPolicyStmt {
        &self.alter_masking_policy_stmts[id.0 as usize]
    }

    pub fn get_alter_network_policy_action(
        &self,
        id: SyntaxAlterNetworkPolicyActionId,
    ) -> &SyntaxAlterNetworkPolicyAction {
        &self.alter_network_policy_actions[id.0 as usize]
    }

    pub fn get_alter_network_policy_stmt(
        &self,
        id: SyntaxAlterNetworkPolicyId,
    ) -> &SyntaxAlterNetworkPolicy {
        &self.alter_network_policy_stmts[id.0 as usize]
    }

    pub fn get_alter_password_policy_action(
        &self,
        id: SyntaxAlterPasswordPolicyActionId,
    ) -> &SyntaxAlterPasswordPolicyAction {
        &self.alter_password_policy_actions[id.0 as usize]
    }

    pub fn get_alter_password_policy_stmt(
        &self,
        id: SyntaxAlterPasswordPolicyStmtId,
    ) -> &SyntaxAlterPasswordPolicy {
        &self.alter_password_policy_stmts[id.0 as usize]
    }

    pub fn get_alter_projection_policy_action(
        &self,
        id: SyntaxAlterProjectionPolicyActionId,
    ) -> &SyntaxAlterProjectionPolicyAction {
        &self.alter_projection_policy_actions[id.0 as usize]
    }

    pub fn get_alter_projection_policy_stmt(
        &self,
        id: SyntaxAlterProjectionPolicyStmtId,
    ) -> &SyntaxAlterProjectionPolicy {
        &self.alter_projection_policy_stmts[id.0 as usize]
    }

    pub fn get_alter_row_access_policy_action(
        &self,
        id: SyntaxAlterRowAccessPolicyActionId,
    ) -> &SyntaxAlterRowAccessPolicyAction {
        &self.alter_row_access_policy_actions[id.0 as usize]
    }

    pub fn get_alter_row_access_policy_stmt(
        &self,
        id: SyntaxAlterRowAccessPolicyStmtId,
    ) -> &SyntaxAlterRowAccessPolicyStmt {
        &self.alter_row_access_policy_stmts[id.0 as usize]
    }

    pub fn get_alter_session_policy_action(
        &self,
        id: SyntaxAlterSessionPolicyActionId,
    ) -> &SyntaxAlterSessionPolicyAction {
        &self.alter_session_policy_actions[id.0 as usize]
    }

    pub fn get_alter_session_policy_stmt(
        &self,
        id: SyntaxAlterSessionPolicyStmtId,
    ) -> &SyntaxAlterSessionPolicy {
        &self.alter_session_policy_stmts[id.0 as usize]
    }

    pub fn get_alter_stage_action(&self, id: SyntaxAlterStageActionId) -> &SyntaxAlterStageAction {
        &self.alter_stage_actions[id.0 as usize]
    }

    pub fn get_alter_stage_stmt(&self, id: SyntaxAlterStageStmtId) -> &SyntaxAlterStageStmt {
        &self.alter_stage_stmts[id.0 as usize]
    }

    pub fn get_alter_storage_integration_action(
        &self,
        id: SyntaxAlterStorageIntegrationActionId,
    ) -> &SyntaxAlterStorageIntegrationAction {
        &self.alter_storage_integration_actions[id.0 as usize]
    }

    pub fn get_alter_storage_integration_stmt(
        &self,
        id: SyntaxAlterStorageIntegrationStmtId,
    ) -> &SyntaxAlterStorageIntegration {
        &self.alter_storage_integration_stmts[id.0 as usize]
    }

    pub fn get_create_aggregation_policy(
        &self,
        id: SyntaxCreateAggregationPolicyId,
    ) -> &SyntaxCreateAggregationPolicy {
        &self.create_aggregation_policies[id.0 as usize]
    }

    pub fn get_create_api_integration(
        &self,
        id: SyntaxCreateApiIntegrationId,
    ) -> &SyntaxCreateApiIntegration {
        &self.create_api_integrations[id.0 as usize]
    }

    pub fn get_create_authentication_policy(
        &self,
        id: SyntaxCreateAuthenticationPolicyId,
    ) -> &SyntaxCreateAuthenticationPolicy {
        &self.create_authentication_policies[id.0 as usize]
    }

    pub fn get_create_external_access_integration(
        &self,
        id: SyntaxCreateExternalAccessIntegrationId,
    ) -> &SyntaxCreateExternalAccessIntegration {
        &self.create_external_access_integrations[id.0 as usize]
    }

    pub fn get_create_masking_policy(
        &self,
        id: SyntaxCreateMaskingPolicyId,
    ) -> &SyntaxCreateMaskingPolicy {
        &self.create_masking_policies[id.0 as usize]
    }

    pub fn get_create_network_policy(
        &self,
        id: SyntaxCreateNetworkPolicyId,
    ) -> &SyntaxCreateNetworkPolicy {
        &self.create_network_policies[id.0 as usize]
    }

    pub fn get_create_password_policy(
        &self,
        id: SyntaxCreatePasswordPolicyId,
    ) -> &SyntaxCreatePasswordPolicy {
        &self.create_password_policies[id.0 as usize]
    }

    pub fn get_create_projection_policy(
        &self,
        id: SyntaxCreateProjectionPolicyId,
    ) -> &SyntaxCreateProjectionPolicy {
        &self.create_projection_policies[id.0 as usize]
    }

    pub fn get_create_row_access_policy(
        &self,
        id: SyntaxCreateRowAccessPolicyId,
    ) -> &SyntaxCreateRowAccessPolicy {
        &self.create_row_access_policies[id.0 as usize]
    }

    pub fn get_create_session_policy(
        &self,
        id: SyntaxCreateSessionPolicyId,
    ) -> &SyntaxCreateSessionPolicy {
        &self.create_session_policies[id.0 as usize]
    }

    pub fn get_create_storage_integration(
        &self,
        id: SyntaxCreateStorageIntegrationId,
    ) -> &SyntaxCreateStorageIntegration {
        &self.create_storage_integrations[id.0 as usize]
    }

    pub fn get_drop_aggregation_policy(
        &self,
        id: SyntaxDropAggregationPolicyId,
    ) -> &SyntaxDropAggregationPolicy {
        &self.drop_aggregation_policies[id.0 as usize]
    }

    pub fn get_drop_all_row_access_policies(
        &self,
        id: SyntaxDropAllRowAccessPoliciesId,
    ) -> &SyntaxDropAllRowAccessPolicies {
        &self.drop_all_row_access_policies[id.0 as usize]
    }

    pub fn get_drop_api_integration(
        &self,
        id: SyntaxDropApiIntegrationId,
    ) -> &SyntaxDropApiIntegration {
        &self.drop_api_integrations[id.0 as usize]
    }

    pub fn get_drop_authentication_policy(
        &self,
        id: SyntaxDropAuthenticationPolicyId,
    ) -> &SyntaxDropAuthenticationPolicy {
        &self.drop_authentication_policies[id.0 as usize]
    }

    pub fn get_drop_external_access_integration(
        &self,
        id: SyntaxDropExternalAccessIntegrationId,
    ) -> &SyntaxDropExternalAccessIntegration {
        &self.drop_external_access_integrations[id.0 as usize]
    }

    pub fn get_drop_masking_policy(
        &self,
        id: SyntaxDropMaskingPolicyId,
    ) -> &SyntaxDropMaskingPolicy {
        &self.drop_masking_policies[id.0 as usize]
    }

    pub fn get_drop_network_policy(
        &self,
        id: SyntaxDropNetworkPolicyId,
    ) -> &SyntaxDropNetworkPolicy {
        &self.drop_network_policies[id.0 as usize]
    }

    pub fn get_drop_password_policy(
        &self,
        id: SyntaxDropPasswordPolicyId,
    ) -> &SyntaxDropPasswordPolicy {
        &self.drop_password_policies[id.0 as usize]
    }

    pub fn get_drop_projection_policy(
        &self,
        id: SyntaxDropProjectionPolicyId,
    ) -> &SyntaxDropProjectionPolicy {
        &self.drop_projection_policies[id.0 as usize]
    }

    pub fn get_drop_row_access_policy(
        &self,
        id: SyntaxDropRowAccessPolicyId,
    ) -> &SyntaxDropRowAccessPolicy {
        &self.drop_row_access_policies[id.0 as usize]
    }

    pub fn get_drop_session_policy(
        &self,
        id: SyntaxDropSessionPolicyId,
    ) -> &SyntaxDropSessionPolicy {
        &self.drop_session_policies[id.0 as usize]
    }

    pub fn get_drop_storage_integration(
        &self,
        id: SyntaxDropStorageIntegrationId,
    ) -> &SyntaxDropStorageIntegration {
        &self.drop_storage_integrations[id.0 as usize]
    }

    pub fn alloc_create_stream(&mut self, node: SyntaxCreateStream) -> SyntaxCreateStreamId {
        let id = SyntaxCreateStreamId(self.create_streams.len() as u32);
        self.create_streams.push(node);
        id
    }

    pub fn alloc_alter_stream_stmt(
        &mut self,
        node: SyntaxAlterStreamStmt,
    ) -> SyntaxAlterStreamStmtId {
        let id = SyntaxAlterStreamStmtId(self.alter_stream_stmts.len() as u32);
        self.alter_stream_stmts.push(node);
        id
    }

    pub fn alloc_alter_stream_action(
        &mut self,
        node: SyntaxAlterStreamAction,
    ) -> SyntaxAlterStreamActionId {
        let id = SyntaxAlterStreamActionId(self.alter_stream_actions.len() as u32);
        self.alter_stream_actions.push(node);
        id
    }

    pub fn alloc_drop_stream(&mut self, node: SyntaxDropStream) -> SyntaxDropStreamId {
        let id = SyntaxDropStreamId(self.drop_streams.len() as u32);
        self.drop_streams.push(node);
        id
    }

    pub fn alloc_view_column_list(&mut self, node: SyntaxViewColumnList) -> SyntaxViewColumnListId {
        let id = SyntaxViewColumnListId(self.view_column_lists.len() as u32);
        self.view_column_lists.push(node);
        id
    }

    pub fn alloc_view_column(&mut self, node: SyntaxViewColumn) -> SyntaxViewColumnId {
        let id = SyntaxViewColumnId(self.view_columns.len() as u32);
        self.view_columns.push(node);
        id
    }

    pub fn alloc_view_column_comment(
        &mut self,
        node: SyntaxViewColumnComment,
    ) -> SyntaxViewColumnCommentId {
        let id = SyntaxViewColumnCommentId(self.view_column_comments.len() as u32);
        self.view_column_comments.push(node);
        id
    }

    pub fn alloc_view_column_masking_policy(
        &mut self,
        node: SyntaxViewColumnMaskingPolicy,
    ) -> SyntaxViewColumnMaskingPolicyId {
        let id = SyntaxViewColumnMaskingPolicyId(self.view_column_masking_policies.len() as u32);
        self.view_column_masking_policies.push(node);
        id
    }

    pub fn alloc_view_column_projection_policy(
        &mut self,
        node: SyntaxViewColumnProjectionPolicy,
    ) -> SyntaxViewColumnProjectionPolicyId {
        let id =
            SyntaxViewColumnProjectionPolicyId(self.view_column_projection_policies.len() as u32);
        self.view_column_projection_policies.push(node);
        id
    }

    pub fn alloc_view_column_tag(&mut self, node: SyntaxViewColumnTag) -> SyntaxViewColumnTagId {
        let id = SyntaxViewColumnTagId(self.view_column_tags.len() as u32);
        self.view_column_tags.push(node);
        id
    }

    pub fn get_create_stream(&self, id: SyntaxCreateStreamId) -> &SyntaxCreateStream {
        &self.create_streams[id.0 as usize]
    }

    pub fn get_alter_stream_stmt(&self, id: SyntaxAlterStreamStmtId) -> &SyntaxAlterStreamStmt {
        &self.alter_stream_stmts[id.0 as usize]
    }

    pub fn get_alter_stream_action(
        &self,
        id: SyntaxAlterStreamActionId,
    ) -> &SyntaxAlterStreamAction {
        &self.alter_stream_actions[id.0 as usize]
    }

    pub fn get_drop_stream(&self, id: SyntaxDropStreamId) -> &SyntaxDropStream {
        &self.drop_streams[id.0 as usize]
    }

    pub fn get_view_column_list(&self, id: SyntaxViewColumnListId) -> &SyntaxViewColumnList {
        &self.view_column_lists[id.0 as usize]
    }

    pub fn get_view_column(&self, id: SyntaxViewColumnId) -> &SyntaxViewColumn {
        &self.view_columns[id.0 as usize]
    }

    pub fn get_view_column_comment(
        &self,
        id: SyntaxViewColumnCommentId,
    ) -> &SyntaxViewColumnComment {
        &self.view_column_comments[id.0 as usize]
    }

    pub fn get_view_column_masking_policy(
        &self,
        id: SyntaxViewColumnMaskingPolicyId,
    ) -> &SyntaxViewColumnMaskingPolicy {
        &self.view_column_masking_policies[id.0 as usize]
    }

    pub fn get_view_column_projection_policy(
        &self,
        id: SyntaxViewColumnProjectionPolicyId,
    ) -> &SyntaxViewColumnProjectionPolicy {
        &self.view_column_projection_policies[id.0 as usize]
    }

    pub fn get_view_column_tag(&self, id: SyntaxViewColumnTagId) -> &SyntaxViewColumnTag {
        &self.view_column_tags[id.0 as usize]
    }

    // -- PostgreSQL utility statement alloc/get methods --

    pub fn alloc_create_index_stmt(
        &mut self,
        node: SyntaxCreateIndexStmt,
    ) -> SyntaxCreateIndexStmtId {
        let id = SyntaxCreateIndexStmtId(self.create_index_stmts.len() as u32);
        self.create_index_stmts.push(node);
        id
    }

    pub fn get_create_index_stmt(&self, id: SyntaxCreateIndexStmtId) -> &SyntaxCreateIndexStmt {
        &self.create_index_stmts[id.0 as usize]
    }

    pub fn alloc_comment_on_stmt(&mut self, node: SyntaxCommentOnStmt) -> SyntaxCommentOnStmtId {
        let id = SyntaxCommentOnStmtId(self.comment_on_stmts.len() as u32);
        self.comment_on_stmts.push(node);
        id
    }

    pub fn get_comment_on_stmt(&self, id: SyntaxCommentOnStmtId) -> &SyntaxCommentOnStmt {
        &self.comment_on_stmts[id.0 as usize]
    }

    pub fn alloc_do_block_stmt(&mut self, node: SyntaxDoBlockStmt) -> SyntaxDoBlockStmtId {
        let id = SyntaxDoBlockStmtId(self.do_block_stmts.len() as u32);
        self.do_block_stmts.push(node);
        id
    }

    pub fn get_do_block_stmt(&self, id: SyntaxDoBlockStmtId) -> &SyntaxDoBlockStmt {
        &self.do_block_stmts[id.0 as usize]
    }

    pub fn alloc_vacuum_stmt(&mut self, node: SyntaxVacuumStmt) -> SyntaxVacuumStmtId {
        let id = SyntaxVacuumStmtId(self.vacuum_stmts.len() as u32);
        self.vacuum_stmts.push(node);
        id
    }

    pub fn get_vacuum_stmt(&self, id: SyntaxVacuumStmtId) -> &SyntaxVacuumStmt {
        &self.vacuum_stmts[id.0 as usize]
    }

    pub fn alloc_analyze_stmt(&mut self, node: SyntaxAnalyzeStmt) -> SyntaxAnalyzeStmtId {
        let id = SyntaxAnalyzeStmtId(self.analyze_stmts.len() as u32);
        self.analyze_stmts.push(node);
        id
    }

    pub fn alloc_optimize_stmt(&mut self, node: SyntaxOptimizeStmt) -> SyntaxOptimizeStmtId {
        let id = SyntaxOptimizeStmtId(self.optimize_stmts.len() as u32);
        self.optimize_stmts.push(node);
        id
    }

    pub fn get_optimize_stmt(&self, id: SyntaxOptimizeStmtId) -> &SyntaxOptimizeStmt {
        &self.optimize_stmts[id.0 as usize]
    }

    pub fn alloc_describe_history_stmt(
        &mut self,
        node: SyntaxDescribeHistoryStmt,
    ) -> SyntaxDescribeHistoryStmtId {
        let id = SyntaxDescribeHistoryStmtId(self.describe_history_stmts.len() as u32);
        self.describe_history_stmts.push(node);
        id
    }

    pub fn get_describe_history_stmt(
        &self,
        id: SyntaxDescribeHistoryStmtId,
    ) -> &SyntaxDescribeHistoryStmt {
        &self.describe_history_stmts[id.0 as usize]
    }

    pub fn alloc_restore_stmt(&mut self, node: SyntaxRestoreStmt) -> SyntaxRestoreStmtId {
        let id = SyntaxRestoreStmtId(self.restore_stmts.len() as u32);
        self.restore_stmts.push(node);
        id
    }

    pub fn get_restore_stmt(&self, id: SyntaxRestoreStmtId) -> &SyntaxRestoreStmt {
        &self.restore_stmts[id.0 as usize]
    }

    pub fn get_analyze_stmt(&self, id: SyntaxAnalyzeStmtId) -> &SyntaxAnalyzeStmt {
        &self.analyze_stmts[id.0 as usize]
    }

    pub fn alloc_create_type_stmt(&mut self, node: SyntaxCreateTypeStmt) -> SyntaxCreateTypeStmtId {
        let id = SyntaxCreateTypeStmtId(self.create_type_stmts.len() as u32);
        self.create_type_stmts.push(node);
        id
    }

    pub fn get_create_type_stmt(&self, id: SyntaxCreateTypeStmtId) -> &SyntaxCreateTypeStmt {
        &self.create_type_stmts[id.0 as usize]
    }

    pub fn alloc_alter_type_stmt(&mut self, node: SyntaxAlterTypeStmt) -> SyntaxAlterTypeStmtId {
        let id = SyntaxAlterTypeStmtId(self.alter_type_stmts.len() as u32);
        self.alter_type_stmts.push(node);
        id
    }

    pub fn get_alter_type_stmt(&self, id: SyntaxAlterTypeStmtId) -> &SyntaxAlterTypeStmt {
        &self.alter_type_stmts[id.0 as usize]
    }

    pub fn alloc_create_extension_stmt(
        &mut self,
        node: SyntaxCreateExtensionStmt,
    ) -> SyntaxCreateExtensionStmtId {
        let id = SyntaxCreateExtensionStmtId(self.create_extension_stmts.len() as u32);
        self.create_extension_stmts.push(node);
        id
    }

    pub fn get_create_extension_stmt(
        &self,
        id: SyntaxCreateExtensionStmtId,
    ) -> &SyntaxCreateExtensionStmt {
        &self.create_extension_stmts[id.0 as usize]
    }

    pub fn alloc_create_sequence_stmt(
        &mut self,
        node: SyntaxCreateSequenceStmt,
    ) -> SyntaxCreateSequenceStmtId {
        let id = SyntaxCreateSequenceStmtId(self.create_sequence_stmts.len() as u32);
        self.create_sequence_stmts.push(node);
        id
    }

    pub fn get_create_sequence_stmt(
        &self,
        id: SyntaxCreateSequenceStmtId,
    ) -> &SyntaxCreateSequenceStmt {
        &self.create_sequence_stmts[id.0 as usize]
    }

    pub fn alloc_alter_sequence_stmt(
        &mut self,
        node: SyntaxAlterSequenceStmt,
    ) -> SyntaxAlterSequenceStmtId {
        let id = SyntaxAlterSequenceStmtId(self.alter_sequence_stmts.len() as u32);
        self.alter_sequence_stmts.push(node);
        id
    }

    pub fn get_alter_sequence_stmt(
        &self,
        id: SyntaxAlterSequenceStmtId,
    ) -> &SyntaxAlterSequenceStmt {
        &self.alter_sequence_stmts[id.0 as usize]
    }

    pub fn alloc_create_pg_trigger_stmt(
        &mut self,
        node: SyntaxCreatePgTriggerStmt,
    ) -> SyntaxCreatePgTriggerStmtId {
        let id = SyntaxCreatePgTriggerStmtId(self.create_pg_trigger_stmts.len() as u32);
        self.create_pg_trigger_stmts.push(node);
        id
    }

    pub fn get_create_pg_trigger_stmt(
        &self,
        id: SyntaxCreatePgTriggerStmtId,
    ) -> &SyntaxCreatePgTriggerStmt {
        &self.create_pg_trigger_stmts[id.0 as usize]
    }

    pub fn alloc_alter_pg_trigger_stmt(
        &mut self,
        node: SyntaxAlterPgTriggerStmt,
    ) -> SyntaxAlterPgTriggerStmtId {
        let id = SyntaxAlterPgTriggerStmtId(self.alter_pg_trigger_stmts.len() as u32);
        self.alter_pg_trigger_stmts.push(node);
        id
    }

    pub fn get_alter_pg_trigger_stmt(
        &self,
        id: SyntaxAlterPgTriggerStmtId,
    ) -> &SyntaxAlterPgTriggerStmt {
        &self.alter_pg_trigger_stmts[id.0 as usize]
    }

    pub fn alloc_drop_pg_trigger_stmt(
        &mut self,
        node: SyntaxDropPgTriggerStmt,
    ) -> SyntaxDropPgTriggerStmtId {
        let id = SyntaxDropPgTriggerStmtId(self.drop_pg_trigger_stmts.len() as u32);
        self.drop_pg_trigger_stmts.push(node);
        id
    }

    pub fn get_drop_pg_trigger_stmt(
        &self,
        id: SyntaxDropPgTriggerStmtId,
    ) -> &SyntaxDropPgTriggerStmt {
        &self.drop_pg_trigger_stmts[id.0 as usize]
    }

    pub fn alloc_create_domain_stmt(
        &mut self,
        node: SyntaxCreateDomainStmt,
    ) -> SyntaxCreateDomainStmtId {
        let id = SyntaxCreateDomainStmtId(self.create_domain_stmts.len() as u32);
        self.create_domain_stmts.push(node);
        id
    }

    pub fn get_create_domain_stmt(&self, id: SyntaxCreateDomainStmtId) -> &SyntaxCreateDomainStmt {
        &self.create_domain_stmts[id.0 as usize]
    }

    pub fn alloc_alter_domain_stmt(
        &mut self,
        node: SyntaxAlterDomainStmt,
    ) -> SyntaxAlterDomainStmtId {
        let id = SyntaxAlterDomainStmtId(self.alter_domain_stmts.len() as u32);
        self.alter_domain_stmts.push(node);
        id
    }

    pub fn get_alter_domain_stmt(&self, id: SyntaxAlterDomainStmtId) -> &SyntaxAlterDomainStmt {
        &self.alter_domain_stmts[id.0 as usize]
    }

    pub fn alloc_drop_domain_stmt(&mut self, node: SyntaxDropDomainStmt) -> SyntaxDropDomainStmtId {
        let id = SyntaxDropDomainStmtId(self.drop_domain_stmts.len() as u32);
        self.drop_domain_stmts.push(node);
        id
    }

    pub fn get_drop_domain_stmt(&self, id: SyntaxDropDomainStmtId) -> &SyntaxDropDomainStmt {
        &self.drop_domain_stmts[id.0 as usize]
    }

    pub fn alloc_create_pg_policy_stmt(
        &mut self,
        node: SyntaxCreatePgPolicyStmt,
    ) -> SyntaxCreatePgPolicyStmtId {
        let id = SyntaxCreatePgPolicyStmtId(self.create_pg_policy_stmts.len() as u32);
        self.create_pg_policy_stmts.push(node);
        id
    }

    pub fn get_create_pg_policy_stmt(
        &self,
        id: SyntaxCreatePgPolicyStmtId,
    ) -> &SyntaxCreatePgPolicyStmt {
        &self.create_pg_policy_stmts[id.0 as usize]
    }

    pub fn alloc_alter_pg_policy_stmt(
        &mut self,
        node: SyntaxAlterPgPolicyStmt,
    ) -> SyntaxAlterPgPolicyStmtId {
        let id = SyntaxAlterPgPolicyStmtId(self.alter_pg_policy_stmts.len() as u32);
        self.alter_pg_policy_stmts.push(node);
        id
    }

    pub fn get_alter_pg_policy_stmt(
        &self,
        id: SyntaxAlterPgPolicyStmtId,
    ) -> &SyntaxAlterPgPolicyStmt {
        &self.alter_pg_policy_stmts[id.0 as usize]
    }

    pub fn alloc_drop_pg_policy_stmt(
        &mut self,
        node: SyntaxDropPgPolicyStmt,
    ) -> SyntaxDropPgPolicyStmtId {
        let id = SyntaxDropPgPolicyStmtId(self.drop_pg_policy_stmts.len() as u32);
        self.drop_pg_policy_stmts.push(node);
        id
    }

    pub fn get_drop_pg_policy_stmt(&self, id: SyntaxDropPgPolicyStmtId) -> &SyntaxDropPgPolicyStmt {
        &self.drop_pg_policy_stmts[id.0 as usize]
    }

    pub fn alloc_alter_index_stmt(&mut self, node: SyntaxAlterIndexStmt) -> SyntaxAlterIndexStmtId {
        let id = SyntaxAlterIndexStmtId(self.alter_index_stmts.len() as u32);
        self.alter_index_stmts.push(node);
        id
    }

    pub fn get_alter_index_stmt(&self, id: SyntaxAlterIndexStmtId) -> &SyntaxAlterIndexStmt {
        &self.alter_index_stmts[id.0 as usize]
    }

    pub fn alloc_reindex_stmt(&mut self, node: SyntaxReindexStmt) -> SyntaxReindexStmtId {
        let id = SyntaxReindexStmtId(self.reindex_stmts.len() as u32);
        self.reindex_stmts.push(node);
        id
    }

    pub fn get_reindex_stmt(&self, id: SyntaxReindexStmtId) -> &SyntaxReindexStmt {
        &self.reindex_stmts[id.0 as usize]
    }

    pub fn alloc_pg_prepare_stmt(&mut self, node: SyntaxPgPrepareStmt) -> SyntaxPgPrepareStmtId {
        let id = SyntaxPgPrepareStmtId(self.pg_prepare_stmts.len() as u32);
        self.pg_prepare_stmts.push(node);
        id
    }

    pub fn get_pg_prepare_stmt(&self, id: SyntaxPgPrepareStmtId) -> &SyntaxPgPrepareStmt {
        &self.pg_prepare_stmts[id.0 as usize]
    }

    pub fn alloc_pg_execute_stmt(&mut self, node: SyntaxPgExecuteStmt) -> SyntaxPgExecuteStmtId {
        let id = SyntaxPgExecuteStmtId(self.pg_execute_stmts.len() as u32);
        self.pg_execute_stmts.push(node);
        id
    }

    pub fn get_pg_execute_stmt(&self, id: SyntaxPgExecuteStmtId) -> &SyntaxPgExecuteStmt {
        &self.pg_execute_stmts[id.0 as usize]
    }

    pub fn alloc_pg_deallocate_stmt(
        &mut self,
        node: SyntaxPgDeallocateStmt,
    ) -> SyntaxPgDeallocateStmtId {
        let id = SyntaxPgDeallocateStmtId(self.pg_deallocate_stmts.len() as u32);
        self.pg_deallocate_stmts.push(node);
        id
    }

    pub fn get_pg_deallocate_stmt(&self, id: SyntaxPgDeallocateStmtId) -> &SyntaxPgDeallocateStmt {
        &self.pg_deallocate_stmts[id.0 as usize]
    }

    pub fn alloc_pg_copy_stmt(&mut self, node: SyntaxPgCopyStmt) -> SyntaxPgCopyStmtId {
        let id = SyntaxPgCopyStmtId(self.pg_copy_stmts.len() as u32);
        self.pg_copy_stmts.push(node);
        id
    }

    pub fn get_pg_copy_stmt(&self, id: SyntaxPgCopyStmtId) -> &SyntaxPgCopyStmt {
        &self.pg_copy_stmts[id.0 as usize]
    }

    pub fn alloc_pg_refresh_matview_stmt(
        &mut self,
        node: SyntaxPgRefreshMatviewStmt,
    ) -> SyntaxPgRefreshMatviewStmtId {
        let id = SyntaxPgRefreshMatviewStmtId(self.pg_refresh_matview_stmts.len() as u32);
        self.pg_refresh_matview_stmts.push(node);
        id
    }

    pub fn get_pg_refresh_matview_stmt(
        &self,
        id: SyntaxPgRefreshMatviewStmtId,
    ) -> &SyntaxPgRefreshMatviewStmt {
        &self.pg_refresh_matview_stmts[id.0 as usize]
    }

    pub fn alloc_set_operator(&mut self, node: SyntaxSetOperator) -> SyntaxSetOperatorId {
        let id = SyntaxSetOperatorId(self.set_operators.len() as u32);
        self.set_operators.push(node);
        id
    }

    pub fn get_set_operator(&self, id: SyntaxSetOperatorId) -> &SyntaxSetOperator {
        &self.set_operators[id.0 as usize]
    }
}

// =============================================================================
// Token Lookup Helper
// =============================================================================
