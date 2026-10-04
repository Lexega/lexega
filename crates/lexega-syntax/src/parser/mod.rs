// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser: token streams from the lexer to the AST.
//!
//! One permissive parser serves every dialect. `core` holds the `Parser`
//! state, token navigation, statement dispatch and error recovery; every
//! other module parses one statement family, expression form or clause —
//! `select`, `expr`, `scripting`, `grant`, `create_table`, and so on, with
//! dialect-specific statements in modules named for their dialect.
//!
//! ## Parser Design
//!
//! The parser uses a **recursive descent** approach with:
//! - **Operator precedence climbing** for expression parsing
//! - **Lookahead** via `peek()` to guide parsing decisions
//! - **Span tracking** throughout to maintain source positions
//! - **Mode-aware parsing** (SQL vs Scripting contexts)
//! - **Statement-level recovery**: a statement that fails to parse is kept
//!   as opaque content, and the rest of the script still parses
//!
//! ## Entry Points
//!
//! - `try_parse_script()` / `try_parse_script_with_dialect()`: Parse an
//!   entire script with multiple statements
//! - `try_parse_stmt()`: Parse a single top-level statement
//! - `try_parse_select()`: Parse a SELECT statement
//! - `try_parse_block_stmt()`: Parse a BEGIN...END block
//!
//! Each has a `parse_*` counterpart that returns `Option` instead of a
//! `ParseError`.

pub mod add_signature;
pub mod aggregation_policy;
pub mod alter_authorization;
pub mod alter_function;
pub mod alter_masking_policy;
pub mod alter_network_policy;
pub mod alter_procedure;
pub mod alter_row_access_policy;
pub mod alter_session;
pub mod alter_stage;
pub mod alter_table;
pub mod alter_user_account;
pub mod alter_view;
pub mod api_integration;
pub mod assembly;
pub mod authentication_policy;
pub mod backup;
pub mod bq_grant;
pub mod bq_statements;
pub mod copy_into;
pub mod core;
pub mod create_external_function;
pub mod create_masking_policy;
pub mod create_network_policy;
pub mod create_row_access_policy;
pub mod create_stage;
pub mod create_synonym;
pub mod create_table;
pub mod create_view;
pub mod cte;
pub mod data_metric_function;
pub mod database;
pub mod dbcc;
pub mod dbx_catalog;
pub mod dbx_connection;
pub mod dbx_external_location;
pub mod dbx_statements;
pub mod dbx_storage_credential;
pub mod dbx_volume;
pub mod drop_network_policy;
pub mod dynamic_table;
pub mod explain;
pub mod expr;
pub mod expr_case;
pub mod expr_functions;
pub mod expr_operators;
pub mod expr_predicates;
pub mod external_access_integration;
pub mod external_data_source;
pub mod file_format;
pub mod foreign_server;
pub mod foreign_table;
pub mod grant;
pub mod import_foreign_schema;
pub mod insert;
pub mod jinja_expr;
pub mod jinja_stmt;
pub mod join_policy;
pub mod key_backup;
pub mod key_management;
pub mod mssql_audit;
pub mod mssql_deny;
pub mod mssql_exec;
pub mod mssql_grant;
pub mod mssql_revoke;
pub mod mssql_security_object;
pub mod mssql_server_configuration;
pub mod mssql_statements;
pub mod mysql_event;
pub mod mysql_grant;
pub mod mysql_load_data;
pub mod mysql_rename_table;
pub mod mysql_set;
pub mod mysql_trigger;
pub mod notification_integration;
pub mod output;
pub mod password_policy;
pub mod pg_admin;
pub mod pg_alter_index;
pub mod pg_copy;
pub mod pg_default_privileges;
pub mod pg_domain;
pub mod pg_policy;
pub mod pg_prepare;
pub mod pg_refresh_matview;
pub mod pg_utility;
pub mod pipe;
pub mod principal;
pub mod procedure_params;
pub mod projection_policy;
pub mod redshift_copy;
pub mod restore;
pub mod returning;
pub mod schema;
pub mod scripting;
pub mod security_policy;
pub mod select;
pub mod select_clauses;
pub mod select_jinja;
pub mod select_projection;
pub mod service_master_key;
pub mod session_policy;
pub mod set_operations;
pub mod setuser;
pub mod snowflake_account_ddl;
pub mod sql_stmt;
pub mod storage_integration;
pub mod stream;
pub mod table_ref;
pub mod tag;
pub mod task;
pub mod unload;
pub mod user_mapping;
pub mod warehouse;

// Dialect-specific modules removed - all parsers always available

pub use core::*;

use crate::ast::{AstScript, AstSelect, AstStmt};
use crate::error::ParseResult;
use crate::lexer::Token;

//
// New Result-returning APIs
//

/// Parse a complete script with multiple statements, returning a Result.
///
/// This is the recommended API for parsing scripts. Returns detailed error
/// information if parsing fails.
///
/// # Arguments
///
/// * `tokens` - Token slice from the lexer
///
/// # Returns
///
/// * `Ok(AstScript)` - All statements parsed successfully
/// * `Err(ParseError)` - Parse error in any statement
pub fn try_parse_script_with_dialect(
    source: &str,
    tokens: &[Token],
    dialect: &dyn crate::dialect::Dialect,
) -> ParseResult<AstScript> {
    let mut parser = core::Parser::with_dialect(source, tokens, dialect);
    let script = parser.try_parse_script()?;

    // CRITICAL SAFETY CHECK: Verify all tokens were consumed
    parser.verify_all_tokens_consumed()?;

    Ok(script)
}

/// Try to parse a complete SQL script from a token stream.
///
/// Uses the default Snowflake dialect.
///
/// # Arguments
///
/// * `tokens` - Token slice from the lexer
///
/// # Returns
///
/// * `Ok(AstScript)` - All statements parsed successfully
/// * `Err(ParseError)` - Parse error in any statement
pub fn try_parse_script(source: &str, tokens: &[Token]) -> ParseResult<AstScript> {
    let mut parser = core::Parser::new(source, tokens);
    let script = parser.try_parse_script()?;

    // CRITICAL SAFETY CHECK: Verify all tokens were consumed
    // This prevents silent data loss if the parser skips tokens
    parser.verify_all_tokens_consumed()?;

    Ok(script)
}

/// Analysis-pipeline parse entry: like [`try_parse_script_with_dialect`] /
/// [`try_parse_script`] (per `dialect`), but installs the template layer's
/// placeholder spans so credential-value captures can recognize a rendered
/// placeholder as "not a statically-known literal".
pub fn try_parse_script_with_placeholders(
    source: &str,
    tokens: &[Token],
    dialect: Option<&dyn crate::dialect::Dialect>,
    placeholder_spans: &[crate::lexer::token::Span],
) -> ParseResult<AstScript> {
    let mut parser = match dialect {
        Some(d) => core::Parser::with_dialect(source, tokens, d),
        None => core::Parser::new(source, tokens),
    };
    parser.set_placeholder_spans(placeholder_spans);
    let script = parser.try_parse_script()?;
    parser.verify_all_tokens_consumed()?;
    Ok(script)
}

/// Parse a single SQL or Snowflake Scripting statement, returning a Result.
///
/// # Arguments
///
/// * `tokens` - Token slice from the lexer
///
/// # Returns
///
/// * `Ok(AstStmt)` - Successfully parsed statement
/// * `Err(ParseError)` - Parse error with span and kind
pub fn try_parse_stmt(source: &str, tokens: &[Token]) -> ParseResult<AstStmt> {
    let mut parser = core::Parser::new(source, tokens);
    // Use try_parse_flow_stmt to handle both regular statements and pipe chains (->>)
    let stmt = parser.parse_flow_statement()?;

    // CRITICAL SAFETY CHECK: Verify all tokens were consumed
    // This prevents silent data loss if the parser skips tokens
    parser.verify_all_tokens_consumed()?;

    // Note: Span coverage verification should be done at the string-level API
    // since we need the original source string here

    Ok(stmt)
}

/// Parse a Snowflake Scripting block, returning a Result.
pub fn try_parse_block_stmt(source: &str, tokens: &[Token]) -> ParseResult<AstStmt> {
    let stmt = crate::parser::scripting::try_parse_scripting_block_from_tokens(source, tokens)?;

    // CRITICAL SAFETY CHECK: Verify all tokens were consumed
    // This prevents silent data loss if the parser skips tokens
    let mut parser = core::Parser::new(source, tokens);
    // Advance to end based on statement span
    while let Some(t) = parser.peek() {
        if t.span.start >= stmt.span().end {
            break;
        }
        parser.advance();
    }
    parser.verify_all_tokens_consumed()?;

    Ok(stmt)
}

//
// Option-returning entry points: the same parsers, with the error discarded
//

///
/// Parses all statements in the token stream, handling both SQL statements
/// and Snowflake Scripting blocks. Statements are typically separated by
/// semicolons.
///
/// # Arguments
///
/// * `tokens` - Token slice from the lexer
///
/// # Returns
///
/// * `Some(AstScript)` - All statements parsed successfully
/// * `None` - Parse error in any statement
pub fn parse_script(source: &str, tokens: &[Token]) -> Option<AstScript> {
    let mut parser = core::Parser::new(source, tokens);
    parser.parse().ok()
}

/// Parse a single SQL or Snowflake Scripting statement.
///
/// Main entry point for parsing individual statements. Automatically detects
/// the statement type and delegates to the appropriate specialized parser.
///
/// Supports:
/// - DML: SELECT, INSERT, UPDATE, DELETE, MERGE
/// - DDL: CREATE TABLE, CREATE FUNCTION/PROCEDURE, DROP, TRUNCATE
/// - Query: SHOW, DESCRIBE
/// - Scripting: BEGIN...END blocks, IF, LOOP, RETURN, etc.
///
/// # Arguments
///
/// * `tokens` - Token slice from the lexer
///
/// # Returns
///
/// * `Some(AstStmt)` - Successfully parsed statement
/// * `None` - Parse error
pub fn parse_stmt(source: &str, tokens: &[Token]) -> Option<AstStmt> {
    let mut parser = core::Parser::new(source, tokens);
    parser.parse().ok()?.stmts.into_iter().next()
}

/// Parse a Snowflake Scripting block (`BEGIN ... END` or
/// `DECLARE ... BEGIN ... END`) from a token slice.
///
/// Calls the scripting::parse_scripting_block function.
pub fn parse_block_stmt(source: &str, tokens: &[Token]) -> Option<AstStmt> {
    let mut parser = core::Parser::new(source, tokens);
    parser.parse().ok()?.stmts.into_iter().next()
}

/// Parse a SELECT statement.
///
/// Specialized parser for SELECT queries including all clauses:
/// - WITH (CTEs)
/// - SELECT projection (columns, *, expressions)
/// - FROM (tables, joins, subqueries)
/// - WHERE (filter conditions)
/// - GROUP BY, HAVING
/// - QUALIFY (window function filter)
/// - ORDER BY
/// - LIMIT, OFFSET
///
/// Also handles set operations (UNION, INTERSECT, EXCEPT).
///
/// # Arguments
///
/// * `tokens` - Token slice from the lexer
///
/// # Returns
///
/// * `Some(AstSelect)` - Successfully parsed SELECT
/// * `None` - Parse error or not a SELECT statement
pub fn parse_select(source: &str, tokens: &[Token]) -> Option<AstSelect> {
    sql_stmt::parse_select_from_tokens(source, tokens)
}

/// Backwards-compatible alias for callers still using the
/// older free function name.
pub fn parse_select_from_tokens(source: &str, tokens: &[Token]) -> Option<AstSelect> {
    parse_select(source, tokens)
}
