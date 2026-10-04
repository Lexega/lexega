// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Statement-level formatters
//!
//! Each module handles formatting for a specific statement type or category.
//! All formatters follow the same pattern:
//! - Take &mut Printer and statement AST node
//! - Build formatted output via printer methods
//! - Return Result<(), FormatterError>
//!
//! Note: Statement-level span tracking happens in Formatter::format_script(),
//! not in individual formatters. These functions only build output.

pub mod alter_masking_policy;
pub mod alter_misc;
pub mod alter_network_policy;
pub mod alter_policy_integration;
pub mod async_control;
pub mod copy_into;
pub mod create_dynamic_table;
pub mod create_masking_policy;
pub mod create_network_policy;
pub mod create_policy_integration;
pub mod create_proc_func;
pub mod create_stage;
pub mod create_task;
pub mod ddl;
pub mod dml;
pub mod drop_integration;
pub mod drop_network_policy;
pub mod drop_policy_misc;
pub mod multi_insert;
pub mod password_policy;
pub mod pg_utility;
pub mod pipe_chain;
pub mod projection_policy;
pub mod row_access_policy;
pub mod scripting;
pub mod select;
pub mod session_policy;
pub mod set_select;
pub mod show;
pub mod stream;
pub mod transaction;
pub mod use_stmt;

// Re-export common formatter functions for convenience
pub use alter_masking_policy::format_alter_masking_policy;
pub use alter_misc::{format_alter_dynamic_table, format_alter_stage};
pub use alter_network_policy::format_alter_network_policy;
pub use alter_policy_integration::{
    format_alter_aggregation_policy, format_alter_api_integration,
    format_alter_authentication_policy, format_alter_external_access_integration,
    format_alter_storage_integration,
};
pub use async_control::{format_await, format_cancel};
pub use copy_into::{format_copy_into_location, format_copy_into_table};
pub use create_dynamic_table::format_create_dynamic_table;
pub use create_masking_policy::format_create_masking_policy;
pub use create_network_policy::format_create_network_policy;
pub use create_policy_integration::{
    format_create_aggregation_policy, format_create_api_integration,
    format_create_authentication_policy, format_create_external_access_integration,
    format_create_storage_integration,
};
pub use create_proc_func::{
    format_create_function, format_create_procedure, format_create_table_function,
};
pub use create_stage::format_create_stage;
pub use create_task::format_create_task;
pub use ddl::{
    format_alter_table, format_create_table, format_create_view, format_drop, format_truncate,
};
pub use dml::{format_delete, format_insert, format_merge, format_update};
pub use drop_integration::{
    format_drop_api_integration, format_drop_external_access_integration,
    format_drop_storage_integration,
};
pub use drop_network_policy::format_drop_network_policy;
pub use drop_policy_misc::{
    format_drop_aggregation_policy, format_drop_authentication_policy, format_drop_masking_policy,
};
pub use multi_insert::format_multi_insert;
pub use password_policy::{
    format_alter_password_policy, format_create_password_policy, format_drop_password_policy,
};
pub use pg_utility::{
    format_alter_pg_trigger, format_alter_sequence, format_alter_type, format_analyze,
    format_comment_on, format_create_extension, format_create_index, format_create_pg_trigger,
    format_create_sequence, format_create_synonym, format_create_type, format_do_block,
    format_drop_pg_trigger, format_vacuum,
};
pub use pipe_chain::format_pipe_chain;
pub use projection_policy::{
    format_alter_projection_policy, format_create_projection_policy, format_drop_projection_policy,
};
pub use row_access_policy::{
    format_alter_row_access_policy, format_create_row_access_policy,
    format_drop_all_row_access_policies, format_drop_row_access_policy,
};
pub use scripting::format_statement as format_scripting_statement;
pub use select::{format_select, format_table_ref};
pub use session_policy::{
    format_alter_session_policy, format_create_session_policy, format_drop_session_policy,
};
pub use set_select::format_set_select;
pub use show::{format_describe, format_show};
pub use stream::{format_alter_stream, format_create_stream, format_drop_stream};
pub use transaction::{
    format_begin_transaction, format_commit, format_rollback, format_set_variable,
};
pub use use_stmt::format_use_stmt;
pub mod pg_domain;
pub use pg_domain::{format_alter_domain, format_create_domain, format_drop_domain};
pub mod pg_policy;
pub use pg_policy::{format_alter_pg_policy, format_create_pg_policy, format_drop_pg_policy};
pub mod pg_alter_index;
pub use pg_alter_index::{format_alter_index, format_reindex};
pub mod pg_prepare;
pub use pg_prepare::{format_pg_deallocate, format_pg_execute, format_pg_prepare};
pub mod pg_copy;
pub use pg_copy::format_pg_copy;
pub mod pg_refresh_matview;
pub use pg_refresh_matview::format_pg_refresh_matview;
pub mod dbx_statements;
pub use dbx_statements::format_optimize;
pub mod dbx_external_location;
pub use dbx_external_location::{
    format_alter_external_location, format_create_external_location, format_drop_external_location,
};
