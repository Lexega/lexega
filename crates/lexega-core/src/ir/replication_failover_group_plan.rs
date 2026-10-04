// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for Snowflake `CREATE / DROP {REPLICATION|FAILOVER} GROUP`.
//!
//! A replication or failover group replicates account objects (databases,
//! shares, …) to other Snowflake accounts. `ALLOWED_ACCOUNTS` lists the
//! target accounts — the cross-account egress primitive (data leaves this
//! account for the named org/accounts), the same exposure shape as a
//! SHARE's consumer accounts. The secondary (`AS REPLICA OF`) form makes
//! this account a replication target of another. Which accounts are
//! acceptable is YAML policy.

use crate::ast::types::AstCreateReplicationFailoverGroup;
use crate::ast::{AstDrop, NodeId};
use crate::ir::utils::slice_span;
use crate::lexer::token::Span;

#[derive(Debug, Clone)]
pub struct ReplicationFailoverGroupPlan {
    pub action: ReplicationFailoverGroupAction,
    pub group_type: ReplicationGroupType,
    pub target: Option<ReplicationFailoverGroupTarget>,
    /// `ALLOWED_ACCOUNTS` entries (`org.account`) — the egress targets.
    pub allowed_accounts: Vec<String>,
    /// `OBJECT_TYPES` entries (upper-cased), e.g. `DATABASES`, `ROLES`.
    pub object_types: Vec<String>,
    /// `ALLOWED_DATABASES` entries.
    pub allowed_databases: Vec<String>,
    /// `ALLOWED_SHARES` entries.
    pub allowed_shares: Vec<String>,
    /// Secondary `AS REPLICA OF <source>` form.
    pub is_replica: bool,
    /// A `REPLICATION_SCHEDULE` clause was present.
    pub has_replication_schedule: bool,
    pub options: ReplicationFailoverGroupOptions,
    pub node_id: NodeId,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReplicationFailoverGroupAction {
    Create,
    Drop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReplicationGroupType {
    Replication,
    Failover,
}

#[derive(Debug, Clone)]
pub struct ReplicationFailoverGroupTarget {
    pub name: String,
    pub span: Span,
}

#[derive(Debug, Clone, Default)]
pub struct ReplicationFailoverGroupOptions {
    pub if_not_exists: bool,
    pub if_exists: bool,
    /// `OR REPLACE` present (CREATE only).
    pub or_replace: bool,
}

/// Lower a typed [`AstCreateReplicationFailoverGroup`] into a plan.
pub fn lower_create_replication_failover_group_to_plan(
    s: &AstCreateReplicationFailoverGroup,
    source: &str,
) -> ReplicationFailoverGroupPlan {
    ReplicationFailoverGroupPlan {
        action: ReplicationFailoverGroupAction::Create,
        group_type: group_type_from_text(slice_span(source, s.group_type_span).unwrap_or("")),
        target: Some(target_from_span(source, s.name_span)),
        allowed_accounts: split_list(source, s.allowed_accounts_span),
        object_types: split_list_upper(source, s.object_types_span),
        allowed_databases: split_list(source, s.allowed_databases_span),
        allowed_shares: split_list(source, s.allowed_shares_span),
        is_replica: s.replica_source_span.is_some(),
        has_replication_schedule: s.replication_schedule_span.is_some(),
        options: ReplicationFailoverGroupOptions {
            if_not_exists: s.if_not_exists_span.is_some(),
            if_exists: false,
            or_replace: s.or_replace_span.is_some(),
        },
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a generic [`AstDrop`] whose object type is a replication / failover
/// group. The caller gates on the object type and passes its kind.
pub fn lower_drop_replication_failover_group_to_plan(
    s: &AstDrop,
    group_type: ReplicationGroupType,
    source: &str,
) -> ReplicationFailoverGroupPlan {
    ReplicationFailoverGroupPlan {
        action: ReplicationFailoverGroupAction::Drop,
        group_type,
        target: s
            .target_name_span
            .map(|span| target_from_span(source, span)),
        allowed_accounts: Vec::new(),
        object_types: Vec::new(),
        allowed_databases: Vec::new(),
        allowed_shares: Vec::new(),
        is_replica: false,
        has_replication_schedule: false,
        options: ReplicationFailoverGroupOptions {
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
            or_replace: false,
        },
        node_id: s.node_id,
        span: s.span,
    }
}

fn group_type_from_text(text: &str) -> ReplicationGroupType {
    if text.trim().eq_ignore_ascii_case("FAILOVER") {
        ReplicationGroupType::Failover
    } else {
        ReplicationGroupType::Replication
    }
}

/// Split a bare comma-separated list (no surrounding parens) into trimmed,
/// unquoted entries.
fn split_list(source: &str, span: Option<Span>) -> Vec<String> {
    let Some(span) = span else {
        return Vec::new();
    };
    slice_span(source, span)
        .unwrap_or("")
        .split(',')
        .map(|s| s.trim().trim_matches('\'').trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

fn split_list_upper(source: &str, span: Option<Span>) -> Vec<String> {
    split_list(source, span)
        .into_iter()
        .map(|s| s.to_ascii_uppercase())
        .collect()
}

fn target_from_span(source: &str, span: Span) -> ReplicationFailoverGroupTarget {
    ReplicationFailoverGroupTarget {
        name: slice_span(source, span).unwrap_or("").trim().to_string(),
        span,
    }
}
