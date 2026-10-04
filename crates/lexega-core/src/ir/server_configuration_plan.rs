// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for the T-SQL `ALTER SERVER CONFIGURATION SET …` statement
//! (SQL Server instance-level reconfiguration).
//!
//! A typed projection of [`crate::ast::types::AstMssqlAlterServerConfiguration`]
//! that `derive_facts_from_server_configuration_plan` folds into the public
//! `StatementFacts.ddl.server_configuration` carrier. Carries the configuration
//! subsystem (the recognition discriminator); the value clause is dropped at
//! the AST→IR boundary.

use crate::ast::types::AstMssqlAlterServerConfiguration;
use crate::ast::NodeId;
use crate::lexer::token::Span;

#[derive(Debug, Clone)]
pub struct ServerConfigurationPlan {
    /// Lowercased configuration subsystem (the first word after `SET`).
    pub subsystem: Option<String>,
    pub node_id: NodeId,
    pub span: Span,
}

pub fn lower_mssql_alter_server_configuration_to_plan(
    s: &AstMssqlAlterServerConfiguration,
    source: &str,
) -> ServerConfigurationPlan {
    let subsystem = s.subsystem_span.and_then(|sp| {
        source
            .get(sp.start as usize..sp.end as usize)
            .map(|w| w.trim().to_ascii_lowercase())
    });
    ServerConfigurationPlan {
        subsystem,
        node_id: s.node_id,
        span: s.span,
    }
}
