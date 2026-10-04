// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for Databricks Unity Catalog `CREATE/ALTER
//! [STORAGE | SERVICE] CREDENTIAL` statements.
//!
//! Sibling-tier fact analogous to [`super::PrivilegePlan`] and
//! [`super::StagePlan`]: typed projection of the AST that downstream
//! `derive_facts_from_storage_credential_plan` folds into a public
//! `StatementFacts.ddl.storage_credential` carrier.
//!
//! The provider taxonomy is the closed-enum shape mirrored from the
//! Databricks SQL reference (AWS_IAM_ROLE / AZURE_MANAGED_IDENTITY /
//! AZURE_SERVICE_PRINCIPAL / DATABRICKS_GCP_SERVICE_ACCOUNT /
//! CLOUDFLARE_API_TOKEN), with an `Unparsed` defensive escape.
//!
//! Predicate split (per CRED-* rule INTENT):
//! - `provider.variant.kind` and per-variant typed slots
//!   (`client_secret`, `access_key_id`) drive the rules that target
//!   structurally-identified secrets (CRED-PWD-LEAK / CRED-APIKEY-LEAK).
//! - `provider.all_literal_values` carries every literal argument
//!   flattened into a single `Vec<String>` for content-pattern rules
//!   that fire regardless of which slot holds the suspicious value
//!   (CRED-AWS-LEAK matches `AKIA*` / `ASIA*`; CRED-CONNSTR-LEAK
//!   matches `*://*:*@*`).

use crate::ast::{
    AlterStorageCredentialAction, AstAlterStorageCredential, AstCreateStorageCredential,
    AstDropStorageCredential, AstStorageCredentialProvider, AstStorageCredentialProviderVariant,
    CredentialKind, NodeId,
};
use crate::lexer::token::Span;

#[derive(Debug, Clone)]
pub struct StorageCredentialPlan {
    pub action: StorageCredentialAction,
    pub credential_kind: StorageCredentialKindIr,
    pub if_not_exists: bool,
    pub provider: Option<StorageCredentialProvider>,
    /// Typed list of `ALTER STORAGE CREDENTIAL` action variants, in
    /// source order. Empty on `Create`. Rules compose against
    /// `ddl.storage_credential.actions: { exists: { kind: <variant> } }`
    /// — names the SQL action, not the rule verdict.
    pub(crate) actions: Vec<IrStorageCredentialAlterAction>,
    /// `Some` when `CREATE STORAGE CREDENTIAL ... COMMENT '<text>'`
    /// is present. Spans the quoted string literal; projection layer
    /// unquotes via `policy_plan::comment_text_from_value_span` for
    /// content-pattern rules (CRED-CONNSTR-LEAK / CRED-PWD-LEAK) that
    /// flag URLs with embedded credentials in metadata fields.
    pub comment_value_span: Option<Span>,
    pub node_id: NodeId,
    pub span: Span,
}

/// IR-internal mirror of [`crate::ast::AlterStorageCredentialAction`].
/// Public-facts mirror: `src/facts/ddl.rs::StorageCredentialAlterAction`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum IrStorageCredentialAlterAction {
    /// `ALTER … CREDENTIAL <name> RENAME TO <new_name>`.
    RenameTo,
    /// `ALTER … CREDENTIAL <name> OWNER TO <principal>`.
    OwnerTo,
    /// `ALTER … CREDENTIAL <name> <provider-clause>`. The structurally
    /// identified provider variant is exposed via
    /// [`StorageCredentialPlan::provider`].
    SetProvider,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StorageCredentialAction {
    Create,
    Alter,
    Drop,
}

/// Mirror of [`crate::ast::CredentialKind`] in the IR namespace so the
/// public-facts module doesn't need to import from `ast`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StorageCredentialKindIr {
    Storage,
    Service,
    Bare,
}

#[derive(Debug, Clone)]
pub struct StorageCredentialProvider {
    pub variant: StorageCredentialProviderVariant,
    /// Every string-literal argument across all variant slots,
    /// flattened in source order. Drives content-pattern predicates.
    pub all_literal_values: Vec<String>,
}

/// IR-side closed enum mirroring the Databricks provider taxonomy. The
/// public-facts equivalent in `facts::ddl` carries the same variants
/// with serde derives so YAML predicates can target them by name.
#[derive(Debug, Clone)]
pub enum StorageCredentialProviderVariant {
    AwsIamRole {
        role_arn: Option<String>,
    },
    AzureManagedIdentity {
        managed_identity_id: Option<String>,
        access_connector_id: Option<String>,
    },
    AzureServicePrincipal {
        directory_id: Option<String>,
        application_id: Option<String>,
        client_secret: Option<String>,
    },
    DatabricksGcpServiceAccount,
    CloudflareApiToken {
        account_id: Option<String>,
        access_key_id: Option<String>,
        secret_access_key: Option<String>,
    },
    Unparsed,
}

pub fn lower_create_storage_credential_to_storage_credential_plan(
    s: &AstCreateStorageCredential,
) -> StorageCredentialPlan {
    StorageCredentialPlan {
        action: StorageCredentialAction::Create,
        credential_kind: lower_credential_kind(s.credential_kind),
        if_not_exists: s.if_not_exists,
        provider: s.provider.as_ref().map(lower_provider),
        actions: Vec::new(),
        comment_value_span: s.comment_value_span,
        node_id: s.node_id,
        span: s.span,
    }
}

pub fn lower_drop_storage_credential_to_storage_credential_plan(
    s: &AstDropStorageCredential,
) -> StorageCredentialPlan {
    StorageCredentialPlan {
        action: StorageCredentialAction::Drop,
        credential_kind: lower_credential_kind(s.credential_kind),
        if_not_exists: false,
        provider: None,
        actions: Vec::new(),
        comment_value_span: None,
        node_id: s.node_id,
        span: s.span,
    }
}

pub fn lower_alter_storage_credential_to_storage_credential_plan(
    s: &AstAlterStorageCredential,
) -> StorageCredentialPlan {
    let (provider, action) = match &s.action {
        AlterStorageCredentialAction::SetProvider { provider: p, .. } => (
            Some(lower_provider(p)),
            IrStorageCredentialAlterAction::SetProvider,
        ),
        AlterStorageCredentialAction::RenameTo { .. } => {
            (None, IrStorageCredentialAlterAction::RenameTo)
        }
        AlterStorageCredentialAction::OwnerTo { .. } => {
            (None, IrStorageCredentialAlterAction::OwnerTo)
        }
    };
    StorageCredentialPlan {
        action: StorageCredentialAction::Alter,
        credential_kind: lower_credential_kind(s.credential_kind),
        if_not_exists: false,
        provider,
        actions: vec![action],
        comment_value_span: None,
        node_id: s.node_id,
        span: s.span,
    }
}

fn lower_credential_kind(k: CredentialKind) -> StorageCredentialKindIr {
    match k {
        CredentialKind::Storage => StorageCredentialKindIr::Storage,
        CredentialKind::Service => StorageCredentialKindIr::Service,
        CredentialKind::Bare => StorageCredentialKindIr::Bare,
    }
}

fn lower_provider(p: &AstStorageCredentialProvider) -> StorageCredentialProvider {
    let variant = match &p.variant {
        AstStorageCredentialProviderVariant::AwsIamRole { role_arn_text, .. } => {
            StorageCredentialProviderVariant::AwsIamRole {
                role_arn: role_arn_text.clone(),
            }
        }
        AstStorageCredentialProviderVariant::AzureManagedIdentity {
            managed_identity_id_text,
            access_connector_id_text,
            ..
        } => StorageCredentialProviderVariant::AzureManagedIdentity {
            managed_identity_id: managed_identity_id_text.clone(),
            access_connector_id: access_connector_id_text.clone(),
        },
        AstStorageCredentialProviderVariant::AzureServicePrincipal {
            directory_id_text,
            application_id_text,
            client_secret_text,
            ..
        } => StorageCredentialProviderVariant::AzureServicePrincipal {
            directory_id: directory_id_text.clone(),
            application_id: application_id_text.clone(),
            client_secret: client_secret_text.clone(),
        },
        AstStorageCredentialProviderVariant::DatabricksGcpServiceAccount { .. } => {
            StorageCredentialProviderVariant::DatabricksGcpServiceAccount
        }
        AstStorageCredentialProviderVariant::CloudflareApiToken {
            account_id_text,
            access_key_id_text,
            secret_access_key_text,
            ..
        } => StorageCredentialProviderVariant::CloudflareApiToken {
            account_id: account_id_text.clone(),
            access_key_id: access_key_id_text.clone(),
            secret_access_key: secret_access_key_text.clone(),
        },
        AstStorageCredentialProviderVariant::Unparsed { .. } => {
            StorageCredentialProviderVariant::Unparsed
        }
    };
    StorageCredentialProvider {
        variant,
        all_literal_values: p.all_literal_values.clone(),
    }
}
