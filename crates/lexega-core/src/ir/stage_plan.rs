// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side stage / storage-DDL carrier for `CREATE STAGE`, `ALTER
//! STAGE`, and `COPY INTO <location>`.
//!
//! Sibling-tier fact analogous to [`super::PrivilegePlan`]: typed
//! projection of the AST that downstream `derive_facts_from_stage_plan`
//! folds into a public `StatementFacts.ddl.stage` carrier.
//!
//! Carries credential options (`CREDENTIALS=(...)` / `SET CREDENTIALS=`)
//! and URL literal content (`URL='...'` / `SET URL='...'` / the
//! quoted-string location of `COPY INTO 's3://…'`).

use super::ddl_plan::DdlTarget;
use crate::ast::{
    AstAlterStage, AstAlterStageActionKind, AstCopyOption, AstCreateStage, AstDrop,
    AstStageCredentialOption, AstStageCredentialOptionValue, AstStageCredentialsKind, NodeId,
};
use crate::lexer::token::Span;

/// Typed projection of `CREATE STAGE` / `ALTER STAGE` for downstream
/// IR consumers.
///
/// The `url_literal` field consolidates URL content from `CREATE STAGE
/// URL='…'` and `ALTER STAGE … SET URL='…'` into a single
/// content-predicate-friendly slot. The `credentials` field
/// consolidates `CREDENTIALS=(…)` from CREATE and `SET CREDENTIALS=(…)`
/// from ALTER. ALTER STAGE statements with multiple SET actions union
/// their credential options across actions.
#[derive(Debug, Clone)]
pub struct StagePlan {
    pub action: StageAction,
    /// `OR REPLACE` present (CREATE STAGE only).
    pub or_replace: bool,
    pub credentials: StageCredentials,
    /// URL literal content (quotes stripped). `None` when the
    /// statement has no URL clause / SET URL action, or when the
    /// value side is not a string literal.
    pub url_literal: Option<String>,
    /// `ENCRYPTION = (TYPE = 'NONE')` observed (CREATE) or any
    /// `SET ENCRYPTION = (TYPE = 'NONE')` action observed (ALTER).
    /// Read from `AstCreateStage.encryption_clause` and
    /// `AstAlterStageActionKind::SetEncryption`. Multi-action ALTER
    /// statements may set both `encryption_disabled` and
    /// `encryption_enabled` true when the action list contains both.
    pub encryption_disabled: bool,
    /// `ENCRYPTION = (TYPE = '<not NONE>')` observed (CREATE) or any
    /// `SET ENCRYPTION = (TYPE = '<not NONE>')` action observed
    /// (ALTER).
    pub encryption_enabled: bool,
    /// `SET TAG …` action observed on ALTER STAGE. Always `false` for
    /// CREATE STAGE — `AstCreateStage.tag_clause` does not set it
    /// even when the clause is present.
    pub set_tag: bool,
    /// `UNSET TAG …` action observed on ALTER STAGE.
    pub unset_tag: bool,
    /// `SET STORAGE_INTEGRATION = …` action observed on ALTER STAGE.
    /// Set from this action only — distinct from
    /// `StageCredentials::StorageIntegration`,
    /// which simply records that the stage references an integration.
    pub set_storage_integration: bool,
    /// `COPY INTO <location> FROM <source>` whose FROM clause is either
    /// a bare table reference (no WHERE possible without subquery
    /// wrapping) or a parenthesized subquery without a `WHERE` keyword.
    /// Always `false` for `Create`, `Alter`, and `Drop` actions — only
    /// set when
    /// `action == StageAction::CopyToLocation`.
    pub unbounded_export: bool,
    /// `CREATE STAGE` or `ALTER STAGE` whose `extras` vector
    /// (defensive-design unrecognized clauses) is non-empty: the parser
    /// preserved a clause it does not structurally understand. Drives
    /// `SNW-UNKNOWN`. Always `false` for `Drop` and `CopyToLocation`.
    pub has_unknown_clauses: bool,
    /// `NAME = VALUE` copy options carried from a `COPY INTO` statement
    /// (either direction). Empty for CREATE / ALTER / DROP STAGE.
    pub copy_options: Vec<AstCopyOption>,
    /// DDL target object. Carries the loaded table for
    /// `COPY INTO <table>` (`CopyToTable`); `None` for the other actions,
    /// whose facts have never carried a stage/location target.
    pub target: Option<DdlTarget>,
    pub node_id: NodeId,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StageAction {
    /// `CREATE STAGE`
    Create,
    /// `ALTER STAGE`
    Alter,
    /// `DROP STAGE` — projected from the generic `AstStmt::Drop`
    /// when the object type span resolves to `STAGE`.
    Drop,
    /// `COPY INTO <location>` — unload form. Projects to
    /// [`crate::facts::StatementKind::CopyIntoLocation`].
    CopyToLocation,
    /// Redshift `UNLOAD ('query') TO <location>`. Projects to
    /// [`crate::facts::StatementKind::RedshiftUnload`]. Distinct from
    /// `CopyToLocation` so the facts statement-kind reflects the actual
    /// statement; it shares the credential / URL projection so the same
    /// credential-exposure rules apply.
    Unload,
    /// Redshift `COPY <table> FROM <s3-source>` — the bulk-LOAD form.
    /// Projects to [`crate::facts::StatementKind::RedshiftCopy`]. Shares the
    /// credential / URL projection with `Unload` and `CopyToLocation` so the
    /// same credential-exposure rules (CRED-*) apply; distinct so the facts
    /// statement-kind reflects the actual statement (`redshift_copy`).
    Load,
    /// Snowflake `COPY INTO <table> FROM <stage>` — the load form. Projects
    /// to [`crate::facts::StatementKind::CopyIntoTable`]. Carries the typed
    /// `copy_options` (`ON_ERROR`, `PURGE`, …); no credential projection
    /// (load-side credentials live on the referenced stage).
    CopyToTable,
}

/// Credential clause shape. `None` means the statement omitted the
/// `CREDENTIALS=(...)` / `STORAGE_INTEGRATION=` clause entirely.
#[derive(Debug, Clone)]
pub enum StageCredentials {
    /// `CREDENTIALS = ( KEY = VALUE … )`
    Inline { options: Vec<StageCredentialOption> },
    /// `STORAGE_INTEGRATION = integration_name`
    StorageIntegration { name_span: Option<Span> },
    /// No credentials clause present.
    None,
}

/// One typed `KEY = VALUE` pair from an inline credentials clause.
///
/// Source-string-free: the option name is carried as a span only
/// (mirroring [`super::PrivilegePlan`]'s convention). The facts
/// boundary slices and normalizes the name text.
#[derive(Debug, Clone)]
pub struct StageCredentialOption {
    /// Span of the option name token.
    pub name_span: Span,
    /// Parsed value side.
    pub value: StageCredentialValue,
}

/// Value side of a credential option.
#[derive(Debug, Clone)]
pub enum StageCredentialValue {
    /// String literal with quotes stripped and `''` escapes folded.
    StringLiteral { span: Span, text: String },
    /// Non-string-literal value (parameter, identifier, numeric, …).
    Other { span: Span },
}

/// Lower a typed [`AstCreateStage`] into a [`StagePlan`].
///
/// Pure structural projection — credential options and URL literal
/// come from the typed AST. The encryption clause is span-only on the
/// AST, so we slice the source range and classify with the
/// NONE-detection rule (case-insensitive containment of
/// `'NONE'` / `"NONE"` in the upper-cased clause text).
pub fn lower_create_stage_to_stage_plan(s: &AstCreateStage, source: &str) -> StagePlan {
    let credentials = match s.credentials_clause.as_ref() {
        None => StageCredentials::None,
        Some(c) => match c.kind {
            AstStageCredentialsKind::Credentials => StageCredentials::Inline {
                options: c.options.iter().map(lower_credential_option).collect(),
            },
            AstStageCredentialsKind::StorageIntegration => StageCredentials::StorageIntegration {
                name_span: c.integration_name_span,
            },
        },
    };
    let url_literal = s.url_clause.as_ref().and_then(|u| {
        if u.url_text.is_empty() {
            None
        } else {
            Some(u.url_text.clone())
        }
    });
    let (encryption_disabled, encryption_enabled) = match s.encryption_clause {
        Some(span) => classify_create_encryption_clause(source, span),
        None => (false, false),
    };
    StagePlan {
        action: StageAction::Create,
        copy_options: Vec::new(),
        target: None,
        or_replace: s.or_replace_span.is_some(),
        credentials,
        url_literal,
        encryption_disabled,
        encryption_enabled,
        // CREATE STAGE WITH TAG (...) does not set the tag flags:
        // they stay false on CREATE.
        set_tag: false,
        unset_tag: false,
        set_storage_integration: false,
        unbounded_export: false,
        has_unknown_clauses: !s.extras.is_empty(),
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a typed [`AstAlterStage`] into a [`StagePlan`]. Multi-action
/// `SET` statements union their credential options across actions; the
/// last `SET URL` action wins (consistent with how Snowflake applies
/// the actions in source order). Actions other than `SET CREDENTIALS`,
/// `SET STORAGE_INTEGRATION`, and `SET URL` contribute nothing to the
/// credential / URL projection.
///
/// Encryption / tag / storage-integration flags reflect any matching
/// action observed across the action list — multiple actions of the
/// same kind compose with `OR`.
pub fn lower_alter_stage_to_stage_plan(s: &AstAlterStage, source: &str) -> StagePlan {
    let mut inline_options: Vec<StageCredentialOption> = Vec::new();
    let mut storage_integration_span: Option<Span> = None;
    let mut url_literal: Option<String> = None;
    let mut encryption_disabled = false;
    let mut encryption_enabled = false;
    let mut set_tag = false;
    let mut unset_tag = false;
    let mut set_storage_integration = false;

    for action in std::iter::once(&s.action).chain(s.additional_actions.iter()) {
        match &action.kind {
            AstAlterStageActionKind::SetCredentials(c) => {
                for opt in &c.options {
                    inline_options.push(lower_credential_option(opt));
                }
            }
            AstAlterStageActionKind::SetStorageIntegration(si) => {
                storage_integration_span = Some(si.integration_name_span);
                set_storage_integration = true;
            }
            AstAlterStageActionKind::SetUrl(u) => {
                if !u.url_text.is_empty() {
                    url_literal = Some(u.url_text.clone());
                }
            }
            AstAlterStageActionKind::SetEncryption(enc) => {
                if let Some(type_span) = enc.encryption_type_span {
                    if classify_alter_encryption_type(source, type_span) {
                        encryption_disabled = true;
                    } else {
                        encryption_enabled = true;
                    }
                }
            }
            AstAlterStageActionKind::SetTag(_) => set_tag = true,
            AstAlterStageActionKind::UnsetTag(_) => unset_tag = true,
            _ => {}
        }
    }

    let credentials = if !inline_options.is_empty() {
        StageCredentials::Inline {
            options: inline_options,
        }
    } else if let Some(name_span) = storage_integration_span {
        StageCredentials::StorageIntegration {
            name_span: Some(name_span),
        }
    } else {
        StageCredentials::None
    };

    StagePlan {
        action: StageAction::Alter,
        copy_options: Vec::new(),
        target: None,
        or_replace: false,
        credentials,
        url_literal,
        encryption_disabled,
        encryption_enabled,
        set_tag,
        unset_tag,
        set_storage_integration,
        unbounded_export: false,
        has_unknown_clauses: !s.extras.is_empty(),
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a generic `AstStmt::Drop` into a [`StagePlan`] when the
/// `object_type_span` resolves to `STAGE` (case-insensitive).
///
/// Returns `None` for any other object type — DROP for non-stage
/// targets is handled by the generic DDL lowering elsewhere.
pub fn lower_drop_stage_to_stage_plan(s: &AstDrop, source: &str) -> Option<StagePlan> {
    let object_type_span = s.object_type_span?;
    let text = source.get(object_type_span.start as usize..object_type_span.end as usize)?;
    if !text.trim().eq_ignore_ascii_case("STAGE") {
        return None;
    }
    Some(StagePlan {
        action: StageAction::Drop,
        copy_options: Vec::new(),
        target: None,
        or_replace: false,
        credentials: StageCredentials::None,
        url_literal: None,
        encryption_disabled: false,
        encryption_enabled: false,
        set_tag: false,
        unset_tag: false,
        set_storage_integration: false,
        unbounded_export: false,
        has_unknown_clauses: false,
        node_id: s.node_id,
        span: s.span,
    })
}

/// Resolve `AstCreateStage.encryption_clause` (a span covering the
/// entire `ENCRYPTION = (TYPE = '...')` clause) into the
/// (disabled, enabled) flag pair.
/// Detection rule: case-insensitive containment of `'NONE'` /
/// `"NONE"` in the upper-cased clause text → disabled; else enabled.
fn classify_create_encryption_clause(source: &str, span: Span) -> (bool, bool) {
    let Some(text) = source.get(span.start as usize..span.end as usize) else {
        return (false, false);
    };
    let upper = text.to_uppercase();
    if upper.contains("'NONE'") || upper.contains("\"NONE\"") {
        (true, false)
    } else {
        (false, true)
    }
}

/// Resolve `SetEncryptionAction.encryption_type_span` (a span covering
/// just the type value, e.g. `'NONE'` or `'AWS_SSE_S3'`) into a
/// disabled-flag boolean: trim quotes /
/// whitespace then case-insensitive equality with `NONE`.
fn classify_alter_encryption_type(source: &str, span: Span) -> bool {
    let Some(text) = source.get(span.start as usize..span.end as usize) else {
        return false;
    };
    text.trim().trim_matches('\'').eq_ignore_ascii_case("NONE")
}

/// Lower a `COPY INTO <location>` statement into a [`StagePlan`].
///
/// The variant is struct-shaped on `AstStmt`, so this lowering takes
/// the relevant fields directly rather than a `&Ast<…>` reference.
/// Mirrors the credential / URL projection of the CREATE / ALTER
/// stage lowerings; downstream content predicates (CRED-*) match
/// against the same `StageCredentials` / `url_literal` fields.
///
/// The `unbounded_export` flag is computed from the FROM clause
/// shape: a bare table reference is always unbounded (no `WHERE` is
/// possible without wrapping in a subquery); a parenthesized
/// subquery is unbounded only when it contains no `WHERE` keyword.
/// Drives `SNW-EXPORT-UNBOUNDED`.
pub fn lower_copy_into_location_to_stage_plan(
    span: Span,
    node_id: NodeId,
    from_span: Span,
    source: &str,
    location_url: Option<&str>,
    credentials: &[AstStageCredentialOption],
    copy_options: &[AstCopyOption],
) -> StagePlan {
    let creds = if credentials.is_empty() {
        StageCredentials::None
    } else {
        StageCredentials::Inline {
            options: credentials.iter().map(lower_credential_option).collect(),
        }
    };
    let url_literal = location_url
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let unbounded_export = classify_copy_into_location_unbounded(source, from_span);
    StagePlan {
        action: StageAction::CopyToLocation,
        or_replace: false,
        credentials: creds,
        url_literal,
        encryption_disabled: false,
        encryption_enabled: false,
        set_tag: false,
        unset_tag: false,
        set_storage_integration: false,
        unbounded_export,
        has_unknown_clauses: false,
        copy_options: copy_options.to_vec(),
        target: None,
        node_id,
        span,
    }
}

/// Lower a Snowflake `COPY INTO <table> FROM <stage|location>` into a
/// [`StagePlan`].
///
/// The load form. Carries the typed `copy_options` (`ON_ERROR`, `PURGE`,
/// `FORCE`, …) so load-option rules can fire, plus the same credential /
/// URL projection as the unload direction: loading straight from an
/// external location embeds `CREDENTIALS=(...)` on the statement itself
/// (stage-name sources carry credentials on the stage object instead, so
/// both fields are empty there). Tagged [`StageAction::CopyToTable`] →
/// facts statement-kind `copy_into_table`.
pub fn lower_copy_into_table_to_stage_plan(
    span: Span,
    node_id: NodeId,
    table_name_span: Span,
    source: &str,
    location_url: Option<&str>,
    credentials: &[AstStageCredentialOption],
    copy_options: &[AstCopyOption],
) -> StagePlan {
    let creds = if credentials.is_empty() {
        StageCredentials::None
    } else {
        StageCredentials::Inline {
            options: credentials.iter().map(lower_credential_option).collect(),
        }
    };
    let url_literal = location_url
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    StagePlan {
        action: StageAction::CopyToTable,
        or_replace: false,
        credentials: creds,
        url_literal,
        encryption_disabled: false,
        encryption_enabled: false,
        set_tag: false,
        unset_tag: false,
        set_storage_integration: false,
        unbounded_export: false,
        has_unknown_clauses: false,
        copy_options: copy_options.to_vec(),
        // Preserve the loaded table as the DDL target — the same identity the
        // generic DDL path carried before COPY INTO <table> routed here.
        target: super::lower_ddl::target_from(table_name_span, source),
        node_id,
        span,
    }
}

/// Lower a Redshift `UNLOAD ('query') TO <location>` into a [`StagePlan`].
///
/// Reuses the same credential / URL projection as the `COPY INTO <location>`
/// lowering so the credential-exposure rules (CRED-*) fire on the typed
/// `StageCredentials::Inline` options. The action is tagged [`StageAction::Unload`]
/// so the facts statement-kind is `redshift_unload` rather than
/// `copy_into_location`.
pub fn lower_unload_to_stage_plan(
    span: Span,
    node_id: NodeId,
    source: &str,
    location_url: Option<&str>,
    credentials: &[AstStageCredentialOption],
) -> StagePlan {
    let _ = source;
    let creds = if credentials.is_empty() {
        StageCredentials::None
    } else {
        StageCredentials::Inline {
            options: credentials.iter().map(lower_credential_option).collect(),
        }
    };
    let url_literal = location_url
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    StagePlan {
        action: StageAction::Unload,
        copy_options: Vec::new(),
        target: None,
        or_replace: false,
        credentials: creds,
        url_literal,
        encryption_disabled: false,
        encryption_enabled: false,
        set_tag: false,
        unset_tag: false,
        set_storage_integration: false,
        // UNLOAD's source query is a quoted string, so the bare-table vs
        // subquery-without-WHERE distinction that drives unbounded-export
        // detection for COPY INTO does not apply here.
        unbounded_export: false,
        has_unknown_clauses: false,
        node_id,
        span,
    }
}

/// Lower a Redshift `COPY <table> FROM <s3-source>` into a [`StagePlan`].
///
/// The load counterpart to [`lower_unload_to_stage_plan`]. Reuses the same
/// credential / URL projection so the credential-exposure rules (CRED-*) fire
/// on the typed `StageCredentials::Inline` options. The action is tagged
/// [`StageAction::Load`] so the facts statement-kind is `redshift_copy`.
pub fn lower_redshift_copy_to_stage_plan(
    span: Span,
    node_id: NodeId,
    location_url: Option<&str>,
    credentials: &[AstStageCredentialOption],
) -> StagePlan {
    let creds = if credentials.is_empty() {
        StageCredentials::None
    } else {
        StageCredentials::Inline {
            options: credentials.iter().map(lower_credential_option).collect(),
        }
    };
    let url_literal = location_url
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    StagePlan {
        action: StageAction::Load,
        copy_options: Vec::new(),
        target: None,
        or_replace: false,
        credentials: creds,
        url_literal,
        encryption_disabled: false,
        encryption_enabled: false,
        set_tag: false,
        unset_tag: false,
        set_storage_integration: false,
        // COPY's bulk LOAD is an ingest, not an export; the unbounded-export
        // signal (an UNLOAD/COPY-INTO concern) does not apply.
        unbounded_export: false,
        has_unknown_clauses: false,
        node_id,
        span,
    }
}

/// Classify the FROM clause of a `COPY INTO <location>` statement as
/// unbounded (no row filter) or bounded.
///
/// Detection rule:
/// - bare table reference (no `(` in the FROM-clause text) → always
///   unbounded, since `WHERE` can only attach to a subquery wrapper;
/// - parenthesized subquery (`(` present) → unbounded only when no
///   `WHERE` keyword appears in the clause.
///
/// Tokenizes the FROM-clause source slice through the standard lexer
/// rather than performing a string scan, so `WHERE`/`(` inside string
/// literals or comments do not influence the classification.
fn classify_copy_into_location_unbounded(source: &str, from_span: Span) -> bool {
    use crate::lexer::{tokenize, Keyword, Punctuation, TokenKind};

    let Some(text) = source.get(from_span.start as usize..from_span.end as usize) else {
        return false;
    };
    let lex_result = tokenize(text);
    let mut has_where = false;
    let mut has_lparen = false;
    for tok in &lex_result.tokens {
        match tok.kind {
            TokenKind::Keyword(Keyword::Where) => has_where = true,
            TokenKind::Punctuation(Punctuation::LParen) => has_lparen = true,
            _ => {}
        }
    }
    if !has_lparen {
        // Bare table reference — always unbounded.
        true
    } else {
        // Subquery — unbounded only if no WHERE keyword present.
        !has_where
    }
}

fn lower_credential_option(opt: &AstStageCredentialOption) -> StageCredentialOption {
    StageCredentialOption {
        name_span: opt.name_span,
        value: match &opt.value {
            AstStageCredentialOptionValue::StringLiteral { span, text } => {
                StageCredentialValue::StringLiteral {
                    span: *span,
                    text: text.clone(),
                }
            }
            AstStageCredentialOptionValue::Other { span } => {
                StageCredentialValue::Other { span: *span }
            }
        },
    }
}
