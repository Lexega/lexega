// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! SQL statement parsing.
//!
//! This module contains parsers for all major SQL statements:
//!
//! ## DML (Data Manipulation Language)
//! - **SELECT**: Query parsing with JOINs, WHERE, GROUP BY, HAVING, ORDER BY, LIMIT
//! - **INSERT**: Single and multi-insert statements with VALUES or SELECT
//! - **UPDATE**: Update statements with WHERE clause
//! - **DELETE**: Delete statements with optional USING clause
//! - **MERGE**: Merge statements with WHEN MATCHED/NOT MATCHED
//!
//! ## DDL (Data Definition Language)
//! - **CREATE TABLE**: All variants (standard, LIKE, CLONE, CTAS, USING TEMPLATE)
//! - **CREATE FUNCTION/PROCEDURE**: User-defined function/procedure definitions
//! - **DROP**: Drop statements with IF EXISTS
//! - **TRUNCATE**: Table truncation
//!
//! ## Query Components
//! - **WITH (CTEs)**: Common Table Expressions, including RECURSIVE
//! - **JOINs**: INNER, LEFT, RIGHT, FULL, CROSS, NATURAL, DIRECTED
//! - **Set operations**: UNION, INTERSECT, EXCEPT with ALL/DISTINCT
//! - **Window functions**: OVER clause with PARTITION BY and ORDER BY
//!
//! ## Snowflake-Specific
//! - **SHOW**: Various SHOW commands
//! - **DESCRIBE/DESC**: Table and function descriptions
//! - **Pipe operators**: `->>, |>` for result chaining
//!
//! All parsers maintain complete span information for source reconstruction.

use crate::ast::{
    AstSelect, AstSetOpKind, AstSetSelect, AstShowKind, AstStmt, ShowGrantsObject,
    ShowGrantsRelation, ShowGrantsSpec, ShowName, ShowPolicyKind, ShowPrincipal, ShowPrincipalKind,
    ShowScope,
};
use crate::lexer::{Keyword, Span, Token, TokenKind};
use crate::parser::copy_into::try_parse_copy_into_stmt_with_parser;
use crate::parser::core::Parser;
use crate::parser::set_operations::try_parse_set_or_select_stmt;

/// SQL statement parsing entrypoints.
///
/// These call the Parser methods from core.rs directly.
pub fn parse_select_from_tokens(source: &str, tokens: &[crate::lexer::Token]) -> Option<AstSelect> {
    let mut parser = Parser::new(source, tokens);
    parser.try_parse_select_in_mode().ok()
}

/// Parse a TRUNCATE statement with Result-based error handling.
pub(crate) fn try_parse_truncate_stmt_with_parser(
    p: &mut Parser<'_>,
) -> crate::error::ParseResult<AstStmt> {
    use crate::error::{ExpectInvariant, ParseError, ParseResultExt};

    let kw = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["TRUNCATE".to_string()])?; // TRUNCATE
    let keyword_span = kw.span;
    let mut span = keyword_span;
    let mut _table_span: Option<Span> = None;
    let mut if_exists_span: Option<Span> = None;
    let mut _target_table_span: Option<Span> = None;

    // Optional TABLE keyword
    if let Some(tok) = p.peek_non_trivia() {
        if tok.lexeme(p.source).eq_ignore_ascii_case("TABLE") {
            let t = p
                .advance()
                .expect_invariant("TRUNCATE: TABLE keyword confirmed by peek");
            _table_span = Some(t.span);
            span.end = t.span.end;
        }
    }

    // Optional IF EXISTS clause
    if let Some(tok) = p.peek_non_trivia() {
        if tok.lexeme(p.source).eq_ignore_ascii_case("IF") {
            let if_tok = p
                .advance()
                .expect_invariant("TRUNCATE: IF keyword confirmed by peek");
            if let Some(exists_tok) = p.peek_non_trivia() {
                if exists_tok.lexeme(p.source).eq_ignore_ascii_case("EXISTS") {
                    let ex = p
                        .advance()
                        .expect_invariant("TRUNCATE: EXISTS keyword confirmed by peek");
                    if_exists_span = Some(Span {
                        start: if_tok.span.start,
                        end: ex.span.end,
                    });
                    span.end = ex.span.end;
                }
            }
        }
    }

    // Parse table name (mandatory)
    let name_start_idx = p.idx;
    while let Some(tok) = p.peek_non_trivia() {
        match tok.kind {
            TokenKind::Eof
            | TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
            | TokenKind::Operator(crate::lexer::Operator::Pipe) => break,
            _ => {
                let _ = p.advance();
            }
        }
    }
    let name_end_idx = p.idx;
    let table_span = if name_end_idx > name_start_idx {
        let first = &p.tokens[name_start_idx];
        let last = &p.tokens[name_end_idx - 1];
        let span_local = Span {
            start: first.span.start,
            end: last.span.end,
        };
        span.end = last.span.end;
        Some(span_local)
    } else {
        // No table name found
        return Err(ParseError::new(
            p.current_span(),
            crate::error::ParseErrorKind::InvalidSyntax {
                message: "TRUNCATE statement requires a table name".to_string(),
            },
        ));
    };

    _target_table_span = table_span;

    let stmt = crate::parser::sql_stmt::build_truncate(
        p.id_gen.next(),
        span,
        keyword_span,
        _table_span, // The TABLE keyword span
        if_exists_span,
        table_span, // The target table name span
    );
    Ok(AstStmt::Truncate(stmt))
}

/// Parse a DROP statement (DROP TABLE, DROP VIEW, etc.)
/// Syntax: DROP [object_type] [IF EXISTS] <name> [CASCADE | RESTRICT]
pub(crate) fn try_parse_drop_stmt_with_parser(
    p: &mut Parser<'_>,
) -> crate::error::ParseResult<AstStmt> {
    use crate::error::{ExpectInvariant, ParseResultExt};

    let drop_kw = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["DROP".to_string()])?; // DROP
    let keyword_span = drop_kw.span;

    // MySQL: DROP PREPARE name — synonym for DEALLOCATE PREPARE name.
    // Route to the shared prepared-statement teardown node rather than a
    // generic Drop, which would read as dropping an object.
    if p.dialect.supports_prepared_statement_execution() {
        if let Some(tok) = p.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Identifier { .. })
                && tok.lexeme(p.source).eq_ignore_ascii_case("PREPARE")
            {
                let drop_keyword_id = p.last_token_id();
                return p.try_parse_drop_prepare_stmt(keyword_span, drop_keyword_id);
            }
        }
    }

    // Check for NETWORK POLICY (requires special handling)
    let saved_idx = p.idx;
    if let Some(tok) = p.peek_non_trivia() {
        // Check for DROP ALL ROW ACCESS POLICIES (BigQuery standalone syntax)
        // ALL is a Keyword, ROW is Keyword, ACCESS is Keyword, POLICIES is Identifier
        if matches!(tok.kind, TokenKind::Keyword(crate::lexer::Keyword::All)) {
            p.advance(); // consume ALL
            if let Some(row_tok) = p.peek_non_trivia() {
                if matches!(row_tok.kind, TokenKind::Keyword(crate::lexer::Keyword::Row)) {
                    p.advance(); // consume ROW
                    if let Some(access_tok) = p.peek_non_trivia() {
                        if matches!(
                            access_tok.kind,
                            TokenKind::Keyword(crate::lexer::Keyword::Access)
                        ) {
                            p.advance(); // consume ACCESS
                            if let Some(policies_tok) = p.peek_non_trivia() {
                                if matches!(policies_tok.kind, TokenKind::Identifier { .. })
                                    && policies_tok
                                        .lexeme(p.source)
                                        .eq_ignore_ascii_case("POLICIES")
                                {
                                    // It's DROP ALL ROW ACCESS POLICIES - reset and use specialized parser
                                    p.idx = saved_idx - 1; // Back to before DROP
                                    return p.try_parse_drop_all_row_access_policies();
                                }
                            }
                        }
                    }
                }
            }
            // Not ALL ROW ACCESS POLICIES, restore and continue
            p.idx = saved_idx;
        // Check for DROP ROW ACCESS POLICY (ROW is Keyword)
        } else if matches!(tok.kind, TokenKind::Keyword(crate::lexer::Keyword::Row)) {
            p.advance(); // consume ROW
            if let Some(access_tok) = p.peek_non_trivia() {
                if matches!(
                    access_tok.kind,
                    TokenKind::Keyword(crate::lexer::Keyword::Access)
                ) {
                    p.advance(); // consume ACCESS
                    if let Some(policy_tok) = p.peek_non_trivia() {
                        if matches!(
                            policy_tok.kind,
                            TokenKind::Keyword(crate::lexer::Keyword::Policy)
                        ) {
                            // It's DROP ROW ACCESS POLICY - reset and use specialized parser
                            p.idx = saved_idx - 1; // Back to before DROP
                            return p.try_parse_drop_row_access_policy();
                        }
                    }
                }
            }
            // Not ROW ACCESS POLICY, restore and continue with generic parser
            p.idx = saved_idx;
        } else if matches!(tok.kind, TokenKind::Identifier { .. })
            && tok.lexeme(p.source).eq_ignore_ascii_case("MASKING")
        {
            p.advance(); // consume MASKING
            if let Some(policy_tok) = p.peek_non_trivia() {
                if matches!(
                    policy_tok.kind,
                    TokenKind::Keyword(crate::lexer::Keyword::Policy)
                ) {
                    // It's DROP MASKING POLICY - reset and use specialized parser
                    p.idx = saved_idx - 1; // Back to before DROP
                    return p.try_parse_drop_masking_policy();
                }
            }
            // Not MASKING POLICY, restore and continue with generic parser
            p.idx = saved_idx;
        } else if matches!(tok.kind, TokenKind::Identifier { .. })
            && tok.lexeme(p.source).eq_ignore_ascii_case("NETWORK")
        {
            p.advance(); // consume NETWORK
            if let Some(policy_tok) = p.peek_non_trivia() {
                if matches!(
                    policy_tok.kind,
                    TokenKind::Keyword(crate::lexer::Keyword::Policy)
                ) {
                    // It's DROP NETWORK POLICY - reset and use specialized parser
                    p.idx = saved_idx - 1; // Back to before DROP
                    return p.try_parse_drop_network_policy();
                }
            }
            // Not NETWORK POLICY, restore and continue with generic parser
            p.idx = saved_idx;
        } else if matches!(tok.kind, TokenKind::Identifier { .. })
            && tok.lexeme(p.source).eq_ignore_ascii_case("SESSION")
        {
            p.advance(); // consume SESSION
            if let Some(policy_tok) = p.peek_non_trivia() {
                if matches!(
                    policy_tok.kind,
                    TokenKind::Keyword(crate::lexer::Keyword::Policy)
                ) {
                    // It's DROP SESSION POLICY - reset and use specialized parser
                    p.idx = saved_idx - 1; // Back to before DROP
                    return p.try_parse_drop_session_policy();
                }
            }
            // Not SESSION POLICY, restore and continue with generic parser
            p.idx = saved_idx;
        } else if matches!(tok.kind, TokenKind::Identifier { .. })
            && tok.lexeme(p.source).eq_ignore_ascii_case("PASSWORD")
        {
            p.advance(); // consume PASSWORD
            if let Some(policy_tok) = p.peek_non_trivia() {
                if matches!(
                    policy_tok.kind,
                    TokenKind::Keyword(crate::lexer::Keyword::Policy)
                ) {
                    // It's DROP PASSWORD POLICY - reset and use specialized parser
                    p.idx = saved_idx - 1; // Back to before DROP
                    return p.try_parse_drop_password_policy();
                }
            }
            // Not PASSWORD POLICY, restore and continue with generic parser
            p.idx = saved_idx;
        } else if matches!(tok.kind, TokenKind::Identifier { .. })
            && tok.lexeme(p.source).eq_ignore_ascii_case("AUTHENTICATION")
        {
            p.advance(); // consume AUTHENTICATION
            if let Some(policy_tok) = p.peek_non_trivia() {
                if matches!(
                    policy_tok.kind,
                    TokenKind::Keyword(crate::lexer::Keyword::Policy)
                ) {
                    // It's DROP AUTHENTICATION POLICY - reset and use specialized parser
                    p.idx = saved_idx - 1; // Back to before DROP
                    return p.try_parse_drop_authentication_policy();
                }
            }
            // Not AUTHENTICATION POLICY, restore and continue with generic parser
            p.idx = saved_idx;
        } else if matches!(tok.kind, TokenKind::Identifier { .. })
            && tok.lexeme(p.source).eq_ignore_ascii_case("API")
        {
            p.advance(); // consume API
            if let Some(integration_tok) = p.peek_non_trivia() {
                if matches!(
                    integration_tok.kind,
                    TokenKind::Keyword(crate::lexer::Keyword::Integration)
                ) {
                    // It's DROP API INTEGRATION - reset and use specialized parser
                    p.idx = saved_idx - 1; // Back to before DROP
                    return p.try_parse_drop_api_integration();
                }
            }
            // Not API INTEGRATION, restore and continue with generic parser
            p.idx = saved_idx;
        } else if matches!(
            tok.kind,
            TokenKind::Keyword(crate::lexer::Keyword::Notification)
        ) {
            p.advance(); // consume NOTIFICATION
            if let Some(integration_tok) = p.peek_non_trivia() {
                if matches!(
                    integration_tok.kind,
                    TokenKind::Keyword(crate::lexer::Keyword::Integration)
                ) {
                    // DROP NOTIFICATION INTEGRATION
                    p.idx = saved_idx - 1; // Back to before DROP
                    return p.try_parse_drop_notification_integration();
                }
            }
            p.idx = saved_idx;
        } else if matches!(tok.kind, TokenKind::Identifier { .. })
            && tok.lexeme(p.source).eq_ignore_ascii_case("AGGREGATION")
        {
            p.advance(); // consume AGGREGATION
            if let Some(policy_tok) = p.peek_non_trivia() {
                if matches!(
                    policy_tok.kind,
                    TokenKind::Keyword(crate::lexer::Keyword::Policy)
                ) {
                    // It's DROP AGGREGATION POLICY - reset and use specialized parser
                    p.idx = saved_idx - 1; // Back to before DROP
                    return p.try_parse_drop_aggregation_policy();
                }
            }
            // Not AGGREGATION POLICY, restore and continue with generic parser
            p.idx = saved_idx;
        } else if matches!(tok.kind, TokenKind::Identifier { .. })
            && tok.lexeme(p.source).eq_ignore_ascii_case("PROJECTION")
        {
            p.advance(); // consume PROJECTION
            if let Some(policy_tok) = p.peek_non_trivia() {
                if matches!(
                    policy_tok.kind,
                    TokenKind::Keyword(crate::lexer::Keyword::Policy)
                ) {
                    // It's DROP PROJECTION POLICY - reset and use specialized parser
                    p.idx = saved_idx - 1; // Back to before DROP
                    return p.try_parse_drop_projection_policy();
                }
            }
            // Not PROJECTION POLICY, restore and continue with generic parser
            p.idx = saved_idx;
        } else if matches!(tok.kind, TokenKind::Keyword(crate::lexer::Keyword::Join)) {
            // DROP JOIN POLICY (JOIN lexes as a keyword)
            p.advance(); // consume JOIN
            if let Some(policy_tok) = p.peek_non_trivia() {
                if matches!(
                    policy_tok.kind,
                    TokenKind::Keyword(crate::lexer::Keyword::Policy)
                ) {
                    p.idx = saved_idx - 1; // Back to before DROP
                    return p.try_parse_drop_join_policy();
                }
            }
            // Not JOIN POLICY, restore and continue with generic parser
            p.idx = saved_idx;
        } else if matches!(tok.kind, TokenKind::Identifier { .. })
            && tok.lexeme(p.source).eq_ignore_ascii_case("EXTERNAL")
        {
            p.advance(); // consume EXTERNAL
            if let Some(next_tok) = p.peek_non_trivia() {
                if matches!(next_tok.kind, TokenKind::Identifier { .. })
                    && next_tok.lexeme(p.source).eq_ignore_ascii_case("LOCATION")
                {
                    // It's DROP EXTERNAL LOCATION - reset and use specialized parser
                    p.idx = saved_idx - 1; // Back to before DROP
                    return p.try_parse_drop_external_location();
                } else if matches!(
                    next_tok.kind,
                    TokenKind::Keyword(crate::lexer::Keyword::Access)
                ) {
                    // It's DROP EXTERNAL ACCESS INTEGRATION - reset and use specialized parser
                    p.idx = saved_idx - 1; // Back to before DROP
                    return p.try_parse_drop_external_access_integration();
                } else if matches!(next_tok.kind, TokenKind::Identifier { .. })
                    && next_tok.lexeme(p.source).eq_ignore_ascii_case("MODEL")
                {
                    // It's DROP EXTERNAL MODEL (SQL Server 2025) - reset and use specialized parser
                    p.idx = saved_idx - 1; // Back to before DROP
                    return p.try_parse_mssql_drop_external_model();
                }
            }
            // Not EXTERNAL LOCATION, ACCESS, or MODEL, restore and continue with generic parser
            p.idx = saved_idx;
        } else if matches!(tok.kind, TokenKind::Keyword(crate::lexer::Keyword::Storage))
            || matches!(
                tok.kind,
                TokenKind::Keyword(crate::lexer::Keyword::Integration)
            )
        {
            // Check for DROP [STORAGE] INTEGRATION or DROP STORAGE CREDENTIAL
            let has_storage =
                matches!(tok.kind, TokenKind::Keyword(crate::lexer::Keyword::Storage));
            if has_storage {
                // Peek ahead to see if next is CREDENTIAL
                let saved_peek = p.idx;
                p.advance(); // consume STORAGE
                if let Some(next_tok) = p.peek_non_trivia() {
                    if matches!(next_tok.kind, TokenKind::Identifier { .. })
                        && next_tok.lexeme(p.source).eq_ignore_ascii_case("CREDENTIAL")
                    {
                        // DROP STORAGE CREDENTIAL (Databricks Unity Catalog)
                        p.idx = saved_idx - 1; // Back to before DROP
                        return p.try_parse_drop_storage_credential();
                    }
                }
                // Not CREDENTIAL — check for INTEGRATION
                p.idx = saved_peek;
                p.advance(); // consume STORAGE again
            }
            if let Some(int_tok) = p.peek_non_trivia() {
                if matches!(
                    int_tok.kind,
                    TokenKind::Keyword(crate::lexer::Keyword::Integration)
                ) {
                    // It's DROP [STORAGE] INTEGRATION - reset and use specialized parser
                    p.idx = saved_idx - 1; // Back to before DROP
                    return p.try_parse_drop_storage_integration();
                }
            }
            // Not STORAGE INTEGRATION, restore and continue with generic parser
            p.idx = saved_idx;
        } else if matches!(tok.kind, TokenKind::Identifier { .. })
            && tok.lexeme(p.source).eq_ignore_ascii_case("CREDENTIAL")
        {
            // Bare DROP CREDENTIAL — dialect grammar decides (T-SQL
            // identity/secret vs Databricks storage).
            p.idx = saved_idx - 1; // Back to before DROP
            if p.dialect.bare_credential_is_identity_secret() {
                return p.try_parse_mssql_security_object_stmt(
                    crate::ast::types::AstMssqlAuditAction::Drop,
                );
            }
            return p.try_parse_drop_storage_credential();
        } else if matches!(tok.kind, TokenKind::Identifier { .. })
            && tok.lexeme(p.source).eq_ignore_ascii_case("SERVICE")
        {
            // DROP SERVICE — peek next: CREDENTIAL?
            p.advance(); // consume SERVICE
            if let Some(next_tok) = p.peek_non_trivia() {
                if matches!(next_tok.kind, TokenKind::Identifier { .. })
                    && next_tok.lexeme(p.source).eq_ignore_ascii_case("CREDENTIAL")
                {
                    // DROP SERVICE CREDENTIAL (Databricks Unity Catalog)
                    p.idx = saved_idx - 1; // Back to before DROP
                    return p.try_parse_drop_storage_credential();
                }
            }
            // Not SERVICE CREDENTIAL, restore and continue with generic parser
            p.idx = saved_idx;
        } else if matches!(tok.kind, TokenKind::Identifier { .. })
            && tok.lexeme(p.source).eq_ignore_ascii_case("CONNECTION")
        {
            // DROP CONNECTION (Databricks Unity Catalog)
            p.idx = saved_idx - 1; // Back to before DROP
            return p.try_parse_drop_connection();
        } else if (tok.lexeme(p.source).eq_ignore_ascii_case("SERVER")
            || tok.lexeme(p.source).eq_ignore_ascii_case("DATABASE"))
            && p.tokens
                .get(p.idx + 1)
                .map(|t| t.lexeme(p.source).eq_ignore_ascii_case("AUDIT"))
                .unwrap_or(false)
        {
            // DROP SERVER AUDIT [SPECIFICATION] / DROP DATABASE AUDIT
            // SPECIFICATION — must win over DROP DATABASE.
            p.idx = saved_idx - 1; // Back to before DROP
            return p.try_parse_mssql_audit_ddl_stmt(crate::ast::types::AstMssqlAuditAction::Drop);
        } else if p.peek_mssql_security_object_at(tok) {
            // DROP { MASTER|SYMMETRIC|ASYMMETRIC KEY | CERTIFICATE |
            // [DATABASE SCOPED] CREDENTIAL } — must win over DROP DATABASE.
            p.idx = saved_idx - 1; // Back to before DROP
            return p.try_parse_mssql_security_object_stmt(
                crate::ast::types::AstMssqlAuditAction::Drop,
            );
        } else if tok.lexeme(p.source).eq_ignore_ascii_case("DATABASE")
            && p.tokens
                .get(p.idx + 1)
                .map(|t| t.lexeme(p.source).eq_ignore_ascii_case("ROLE"))
                .unwrap_or(false)
            && p.tokens
                .get(p.idx + 2)
                .map(|t| {
                    p.can_be_identifier_token(t) || t.lexeme(p.source).eq_ignore_ascii_case("IF")
                })
                .unwrap_or(false)
        {
            // DROP DATABASE ROLE <name> (Snowflake) — principal substrate.
            // Must win over DROP DATABASE; the name/IF guard leaves
            // `DROP DATABASE <db-named-role>` to that arm.
            p.idx = saved_idx - 1; // Back to before DROP
            return p.try_parse_drop_principal_stmt();
        } else if matches!(tok.kind, TokenKind::Identifier { .. })
            && tok.lexeme(p.source).eq_ignore_ascii_case("DATABASE")
        {
            // It's DROP DATABASE - reset and use specialized parser
            p.idx = saved_idx - 1; // Back to before DROP
            return p.try_parse_drop_database();
        } else if matches!(tok.kind, TokenKind::Identifier { .. })
            && tok.lexeme(p.source).eq_ignore_ascii_case("SCHEMA")
        {
            // It's DROP SCHEMA - reset and use specialized parser
            p.idx = saved_idx - 1; // Back to before DROP
            return p.try_parse_drop_schema();
        } else if matches!(tok.kind, TokenKind::Identifier { .. })
            && tok.lexeme(p.source).eq_ignore_ascii_case("TASK")
        {
            // It's DROP TASK - reset and use specialized parser
            p.idx = saved_idx - 1; // Back to before DROP
            return crate::parser::task::try_parse_drop_task(p);
        } else if matches!(tok.kind, TokenKind::Identifier { .. })
            && tok.lexeme(p.source).eq_ignore_ascii_case("WAREHOUSE")
        {
            // It's DROP WAREHOUSE - reset and use specialized parser
            p.idx = saved_idx - 1; // Back to before DROP
            return crate::parser::warehouse::try_parse_drop_warehouse(p);
        } else if matches!(tok.kind, TokenKind::Identifier { .. })
            && tok.lexeme(p.source).eq_ignore_ascii_case("PIPE")
        {
            // It's DROP PIPE - reset and use specialized parser
            p.idx = saved_idx - 1; // Back to before DROP
            return crate::parser::pipe::try_parse_drop_pipe(p);
        } else if matches!(tok.kind, TokenKind::Identifier { .. })
            && tok.lexeme(p.source).eq_ignore_ascii_case("STREAM")
        {
            // It's DROP STREAM - reset and use specialized parser
            p.idx = saved_idx - 1; // Back to before DROP
            return crate::parser::stream::try_parse_drop_stream(p);
        } else if matches!(tok.kind, TokenKind::Keyword(crate::lexer::Keyword::Trigger)) {
            // DROP TRIGGER — distinguish PG vs MSSQL via lookahead.
            // PG:   DROP TRIGGER [IF EXISTS] name ON table_name [CASCADE|RESTRICT]
            // MSSQL: DROP TRIGGER [IF EXISTS] name [,...n] [ON DATABASE|ALL SERVER]
            // Key insight: PG always has ON <table_name>; MSSQL has no ON, comma list,
            // or ON DATABASE / ON ALL SERVER.
            p.advance(); // consume TRIGGER (already peeked)
                         // Skip IF EXISTS
            if let Some(t) = p.peek_non_trivia() {
                if matches!(t.kind, TokenKind::Keyword(crate::lexer::Keyword::If)) {
                    p.advance(); // IF
                    if let Some(t2) = p.peek_non_trivia() {
                        if matches!(t2.kind, TokenKind::Keyword(crate::lexer::Keyword::Exists)) {
                            p.advance(); // EXISTS
                        }
                    }
                }
            }
            // Skip first qualified name (ident [. ident]*)
            if p.peek_non_trivia().is_some() {
                p.advance(); // first identifier
                while let Some(t) = p.peek_non_trivia() {
                    if matches!(
                        t.kind,
                        TokenKind::Punctuation(crate::lexer::Punctuation::Dot)
                    ) {
                        p.advance(); // dot
                        if p.peek_non_trivia().is_some() {
                            p.advance(); // next part
                        }
                    } else {
                        break;
                    }
                }
            }
            // Now determine: PG if ON + normal table name; MSSQL otherwise
            let is_pg = if let Some(t) = p.peek_non_trivia() {
                if matches!(t.kind, TokenKind::Keyword(crate::lexer::Keyword::On)) {
                    // Peek past ON to see what follows
                    let on_saved = p.idx;
                    p.advance(); // consume ON for peek
                    let result = if let Some(t2) = p.peek_non_trivia() {
                        // ON DATABASE or ON ALL SERVER → MSSQL DDL trigger
                        let lex = t2.lexeme(p.source);
                        !lex.eq_ignore_ascii_case("DATABASE")
                            && !matches!(t2.kind, TokenKind::Keyword(crate::lexer::Keyword::All))
                    } else {
                        false
                    };
                    p.idx = on_saved;
                    result
                } else {
                    false // no ON = MSSQL (comma list, semicolon, or EOF)
                }
            } else {
                false
            };
            p.idx = saved_idx - 1; // restore to before DROP
            if is_pg {
                return p.try_parse_drop_pg_trigger_stmt();
            } else {
                return crate::parser::scripting::try_parse_drop_mssql_trigger(p);
            }
        } else if matches!(tok.kind, TokenKind::Identifier { .. })
            && tok.lexeme(p.source).eq_ignore_ascii_case("DOMAIN")
        {
            // It's DROP DOMAIN (PostgreSQL) - reset and use specialized parser
            p.idx = saved_idx - 1; // Back to before DROP
            return p.try_parse_drop_domain_stmt();
        } else if matches!(tok.kind, TokenKind::Keyword(crate::lexer::Keyword::Policy)) {
            // It's DROP POLICY (PostgreSQL RLS) - reset and use specialized parser
            p.idx = saved_idx - 1; // Back to before DROP
            return p.try_parse_drop_pg_policy_stmt();
        } else if matches!(tok.kind, TokenKind::Identifier { .. })
            && tok.lexeme(p.source).eq_ignore_ascii_case("OWNED")
        {
            // It's DROP OWNED BY (PostgreSQL role management)
            p.idx = saved_idx - 1; // Back to before DROP
            return p.try_parse_pg_drop_owned_stmt();
        } else if matches!(tok.kind, TokenKind::Identifier { .. })
            && tok.lexeme(p.source).eq_ignore_ascii_case("PUBLICATION")
        {
            // It's DROP PUBLICATION (PostgreSQL logical replication)
            p.idx = saved_idx - 1; // Back to before DROP
            return p.try_parse_pg_publication_stmt();
        } else if matches!(tok.kind, TokenKind::Identifier { .. })
            && tok.lexeme(p.source).eq_ignore_ascii_case("SUBSCRIPTION")
        {
            // It's DROP SUBSCRIPTION (PostgreSQL logical replication)
            p.idx = saved_idx - 1; // Back to before DROP
            return p.try_parse_pg_subscription_stmt();
        } else if matches!(tok.kind, TokenKind::Identifier { .. })
            && (tok.lexeme(p.source).eq_ignore_ascii_case("ROLE")
                || tok.lexeme(p.source).eq_ignore_ascii_case("USER")
                || tok.lexeme(p.source).eq_ignore_ascii_case("LOGIN"))
        {
            // DROP { ROLE | USER | LOGIN } — dialect-neutral principal
            // substrate.
            p.idx = saved_idx - 1; // Back to before DROP
            return p.try_parse_drop_principal_stmt();
        } else if (tok.lexeme(p.source).eq_ignore_ascii_case("SERVER")
            || tok.lexeme(p.source).eq_ignore_ascii_case("APPLICATION"))
            && p.tokens
                .get(p.idx + 1)
                .map(|t| t.lexeme(p.source).eq_ignore_ascii_case("ROLE"))
                .unwrap_or(false)
        {
            // DROP SERVER ROLE | DROP APPLICATION ROLE (T-SQL) — principal
            // substrate. (Token stream is significant-only, so idx+1 is
            // the next meaningful token.)
            p.idx = saved_idx - 1; // Back to before DROP
            return p.try_parse_drop_principal_stmt();
        } else if matches!(tok.kind, TokenKind::Identifier { .. })
            && tok.lexeme(p.source).eq_ignore_ascii_case("EXTENSION")
        {
            // It's DROP EXTENSION (PostgreSQL)
            p.idx = saved_idx - 1; // Back to before DROP
            return p.try_parse_pg_drop_extension_stmt();
        } else if matches!(tok.kind, TokenKind::Identifier { .. })
            && tok.lexeme(p.source).eq_ignore_ascii_case("RULE")
        {
            // It's DROP RULE (PostgreSQL)
            p.idx = saved_idx - 1; // Back to before DROP
            return p.try_parse_pg_drop_rule_stmt();
        } else if matches!(tok.kind, TokenKind::Identifier { .. })
            && tok.lexeme(p.source).eq_ignore_ascii_case("SEQUENCE")
        {
            // It's DROP SEQUENCE (PostgreSQL)
            p.idx = saved_idx - 1; // Back to before DROP
            return p.try_parse_pg_drop_sequence_stmt();
        } else if matches!(tok.kind, TokenKind::Keyword(crate::lexer::Keyword::Type))
            || (matches!(tok.kind, TokenKind::Identifier { .. })
                && tok.lexeme(p.source).eq_ignore_ascii_case("TYPE"))
        {
            // It's DROP TYPE (PostgreSQL)
            p.idx = saved_idx - 1; // Back to before DROP
            return p.try_parse_pg_drop_type_stmt();
        } else if matches!(tok.kind, TokenKind::Identifier { .. })
            && tok.lexeme(p.source).eq_ignore_ascii_case("INDEX")
        {
            // It's DROP INDEX (PostgreSQL)
            p.idx = saved_idx - 1; // Back to before DROP
            return p.try_parse_pg_drop_index_stmt();
        } else if matches!(tok.kind, TokenKind::Identifier { .. })
            && tok.lexeme(p.source).eq_ignore_ascii_case("TABLESPACE")
        {
            // It's DROP TABLESPACE (PostgreSQL)
            p.idx = saved_idx - 1; // Back to before DROP
            return p.try_parse_pg_drop_tablespace_stmt();
        } else if matches!(tok.kind, TokenKind::Identifier { .. })
            && tok.lexeme(p.source).eq_ignore_ascii_case("SNAPSHOT")
        {
            // It's DROP SNAPSHOT TABLE (BigQuery)
            p.idx = saved_idx - 1; // Back to before DROP
            return p.try_parse_bq_drop_snapshot_table();
        } else if matches!(tok.kind, TokenKind::Identifier { .. })
            && tok.lexeme(p.source).eq_ignore_ascii_case("SEARCH")
        {
            // It's DROP SEARCH INDEX (BigQuery)
            p.idx = saved_idx - 1; // Back to before DROP
            return p.try_parse_bq_drop_search_index();
        } else if matches!(tok.kind, TokenKind::Identifier { .. })
            && tok.lexeme(p.source).eq_ignore_ascii_case("VECTOR")
        {
            // It's DROP VECTOR INDEX (BigQuery)
            p.idx = saved_idx - 1; // Back to before DROP
            return p.try_parse_bq_drop_vector_index();
        } else if matches!(tok.kind, TokenKind::Identifier { .. })
            && tok.lexeme(p.source).eq_ignore_ascii_case("MODEL")
        {
            // It's DROP MODEL (BigQuery BQML)
            p.idx = saved_idx - 1; // Back to before DROP
            return p.try_parse_bq_drop_model();
        } else if matches!(tok.kind, TokenKind::Identifier { .. })
            && tok.lexeme(p.source).eq_ignore_ascii_case("CATALOG")
        {
            // It's DROP CATALOG (Databricks Unity Catalog)
            p.idx = saved_idx - 1; // Back to before DROP
            return p.try_parse_drop_catalog();
        } else if matches!(tok.kind, TokenKind::Identifier { .. })
            && tok.lexeme(p.source).eq_ignore_ascii_case("VOLUME")
        {
            // It's DROP VOLUME (Databricks Unity Catalog)
            p.idx = saved_idx - 1; // Back to before DROP
            return p.try_parse_drop_volume();
        } else if matches!(tok.kind, TokenKind::Keyword(crate::lexer::Keyword::Table)) {
            // Could be DROP TABLE or DROP TABLE FUNCTION (BigQuery TVF)
            p.advance(); // consume TABLE
            if let Some(func_tok) = p.peek_non_trivia() {
                if matches!(
                    func_tok.kind,
                    TokenKind::Keyword(crate::lexer::Keyword::Function)
                ) {
                    // It's DROP TABLE FUNCTION - reset and use specialized parser
                    p.idx = saved_idx - 1; // Back to before DROP
                    return crate::parser::scripting::parse_drop_table_function(p);
                }
            }
            // Not TABLE FUNCTION, restore and continue with generic DROP TABLE
            p.idx = saved_idx;
        }
    }

    let mut span = keyword_span;
    let mut object_type_span: Option<Span> = None;
    let mut if_exists_span: Option<Span> = None;
    let mut target_name_span: Option<Span> = None;
    let mut cascade_restrict_span: Option<Span> = None;

    // Parse object type (TABLE, VIEW, DATABASE, SCHEMA, etc.)
    // Handle compound types: DYNAMIC TABLE, EXTERNAL TABLE, MATERIALIZED VIEW
    if let Some(tok) = p.peek_non_trivia() {
        // Object type is typically a keyword (TABLE, VIEW, etc.)
        match &tok.kind {
            TokenKind::Keyword(_) | TokenKind::Identifier { .. } => {
                let obj_tok = p
                    .advance()
                    .expect_invariant("DROP: object type token confirmed by peek");
                let mut obj_span = obj_tok.span;

                // Check for compound object types: DYNAMIC TABLE, EXTERNAL TABLE, MATERIALIZED VIEW
                if obj_tok.lexeme(p.source).eq_ignore_ascii_case("DYNAMIC")
                    || obj_tok.lexeme(p.source).eq_ignore_ascii_case("EXTERNAL")
                {
                    // Look for TABLE keyword
                    if let Some(next) = p.peek_non_trivia() {
                        if matches!(next.kind, TokenKind::Keyword(crate::lexer::Keyword::Table)) {
                            let table_tok = p
                                .advance()
                                .expect_invariant("TABLE keyword consumed after peek");
                            obj_span.end = table_tok.span.end;
                        }
                    }
                } else if obj_tok
                    .lexeme(p.source)
                    .eq_ignore_ascii_case("MATERIALIZED")
                {
                    // Look for VIEW keyword
                    if let Some(next) = p.peek_non_trivia() {
                        if matches!(next.kind, TokenKind::Keyword(crate::lexer::Keyword::View)) {
                            let view_tok = p
                                .advance()
                                .expect_invariant("VIEW keyword consumed after peek");
                            obj_span.end = view_tok.span.end;
                        }
                    }
                } else if obj_tok.lexeme(p.source).eq_ignore_ascii_case("SECURITY") {
                    // Look for INTEGRATION keyword (DROP SECURITY INTEGRATION)
                    if let Some(next) = p.peek_non_trivia() {
                        if matches!(
                            next.kind,
                            TokenKind::Keyword(crate::lexer::Keyword::Integration)
                        ) {
                            let intg_tok = p
                                .advance()
                                .expect_invariant("INTEGRATION keyword consumed after peek");
                            obj_span.end = intg_tok.span.end;
                        }
                    }
                } else if obj_tok.lexeme(p.source).eq_ignore_ascii_case("FILE") {
                    // Two-word compound DROP FILE FORMAT (FORMAT lexes as a
                    // keyword). Extend the object-type span so the downstream
                    // `drop_target_is_file_format` gate matches.
                    if p.peek_non_trivia().is_some_and(|t| {
                        matches!(t.kind, TokenKind::Keyword(crate::lexer::Keyword::Format))
                    }) {
                        let format_tok = p.advance().expect_invariant("FORMAT consumed after peek");
                        obj_span.end = format_tok.span.end;
                    }
                } else if obj_tok.lexeme(p.source).eq_ignore_ascii_case("NETWORK") {
                    // Look for RULE identifier (DROP NETWORK RULE). DROP
                    // NETWORK POLICY routes through its own typed parser
                    // before reaching the generic DROP path.
                    if let Some(next) = p.peek_non_trivia() {
                        if matches!(next.kind, TokenKind::Identifier { .. })
                            && next.lexeme(p.source).eq_ignore_ascii_case("RULE")
                        {
                            let rule_tok = p
                                .advance()
                                .expect_invariant("RULE identifier consumed after peek");
                            obj_span.end = rule_tok.span.end;
                        }
                    }
                } else if obj_tok.lexeme(p.source).eq_ignore_ascii_case("RESOURCE") {
                    // Look for MONITOR identifier (DROP RESOURCE MONITOR).
                    if let Some(next) = p.peek_non_trivia() {
                        if matches!(next.kind, TokenKind::Identifier { .. })
                            && next.lexeme(p.source).eq_ignore_ascii_case("MONITOR")
                        {
                            let monitor_tok = p
                                .advance()
                                .expect_invariant("MONITOR identifier consumed after peek");
                            obj_span.end = monitor_tok.span.end;
                        }
                    }
                } else if obj_tok.lexeme(p.source).eq_ignore_ascii_case("COMPUTE") {
                    // Two-word compound DROP COMPUTE POOL.
                    if p.peek_non_trivia()
                        .is_some_and(|t| t.lexeme(p.source).eq_ignore_ascii_case("POOL"))
                    {
                        let pool_tok = p.advance().expect_invariant("POOL consumed after peek");
                        obj_span.end = pool_tok.span.end;
                    }
                } else if obj_tok.lexeme(p.source).eq_ignore_ascii_case("GIT") {
                    // Two-word compound DROP GIT REPOSITORY.
                    if p.peek_non_trivia()
                        .is_some_and(|t| t.lexeme(p.source).eq_ignore_ascii_case("REPOSITORY"))
                    {
                        let repo_tok = p
                            .advance()
                            .expect_invariant("REPOSITORY consumed after peek");
                        obj_span.end = repo_tok.span.end;
                    }
                } else if obj_tok.lexeme(p.source).eq_ignore_ascii_case("IMAGE") {
                    // Two-word compound DROP IMAGE REPOSITORY.
                    if p.peek_non_trivia()
                        .is_some_and(|t| t.lexeme(p.source).eq_ignore_ascii_case("REPOSITORY"))
                    {
                        let repo_tok = p
                            .advance()
                            .expect_invariant("REPOSITORY consumed after peek");
                        obj_span.end = repo_tok.span.end;
                    }
                } else if obj_tok.lexeme(p.source).eq_ignore_ascii_case("SEMANTIC") {
                    // Two-word compound DROP SEMANTIC VIEW (VIEW lexes as a keyword).
                    if p.peek_non_trivia()
                        .is_some_and(|t| t.lexeme(p.source).eq_ignore_ascii_case("VIEW"))
                    {
                        let view_tok = p.advance().expect_invariant("VIEW consumed after peek");
                        obj_span.end = view_tok.span.end;
                    }
                } else if obj_tok.lexeme(p.source).eq_ignore_ascii_case("CORTEX") {
                    // Three-word compound DROP CORTEX SEARCH SERVICE: extend the
                    // object-type span past SEARCH SERVICE so the downstream
                    // gate matches.
                    if p.peek_non_trivia()
                        .is_some_and(|t| t.lexeme(p.source).eq_ignore_ascii_case("SEARCH"))
                    {
                        let search_tok = p.advance().expect_invariant("SEARCH consumed after peek");
                        obj_span.end = search_tok.span.end;
                        if p.peek_non_trivia()
                            .is_some_and(|t| t.lexeme(p.source).eq_ignore_ascii_case("SERVICE"))
                        {
                            let service_tok =
                                p.advance().expect_invariant("SERVICE consumed after peek");
                            obj_span.end = service_tok.span.end;
                        }
                    }
                } else if obj_tok.lexeme(p.source).eq_ignore_ascii_case("APPLICATION") {
                    // Two-word compound DROP APPLICATION PACKAGE (bare DROP
                    // APPLICATION stays single-word). Extend past PACKAGE so the
                    // package gate matches.
                    if p.peek_non_trivia()
                        .is_some_and(|t| t.lexeme(p.source).eq_ignore_ascii_case("PACKAGE"))
                    {
                        let pkg_tok = p.advance().expect_invariant("PACKAGE consumed after peek");
                        obj_span.end = pkg_tok.span.end;
                    }
                } else if obj_tok.lexeme(p.source).eq_ignore_ascii_case("MANAGED") {
                    // Two-word compound DROP MANAGED ACCOUNT.
                    if p.peek_non_trivia()
                        .is_some_and(|t| t.lexeme(p.source).eq_ignore_ascii_case("ACCOUNT"))
                    {
                        let acct_tok = p.advance().expect_invariant("ACCOUNT consumed after peek");
                        obj_span.end = acct_tok.span.end;
                    }
                } else if obj_tok.lexeme(p.source).eq_ignore_ascii_case("REPLICATION")
                    || obj_tok.lexeme(p.source).eq_ignore_ascii_case("FAILOVER")
                {
                    // Two-word compound DROP {REPLICATION|FAILOVER} GROUP.
                    if p.peek_non_trivia()
                        .is_some_and(|t| t.lexeme(p.source).eq_ignore_ascii_case("GROUP"))
                    {
                        let group_tok = p.advance().expect_invariant("GROUP consumed after peek");
                        obj_span.end = group_tok.span.end;
                    }
                } else if obj_tok.lexeme(p.source).eq_ignore_ascii_case("DATA") {
                    // Three-word compound DROP DATA METRIC FUNCTION: extend the
                    // object-type span past METRIC FUNCTION so the downstream
                    // gate matches.
                    if p.peek_non_trivia()
                        .is_some_and(|t| t.lexeme(p.source).eq_ignore_ascii_case("METRIC"))
                    {
                        let metric_tok = p.advance().expect_invariant("METRIC consumed after peek");
                        obj_span.end = metric_tok.span.end;
                        if p.peek_non_trivia()
                            .is_some_and(|t| t.lexeme(p.source).eq_ignore_ascii_case("FUNCTION"))
                        {
                            let function_tok =
                                p.advance().expect_invariant("FUNCTION consumed after peek");
                            obj_span.end = function_tok.span.end;
                        }
                    }
                }

                object_type_span = Some(obj_span);
                span.end = obj_span.end;
            }
            _ => {}
        }
    }

    // Parse IF EXISTS
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(crate::lexer::Keyword::If)) {
            let if_tok = p
                .advance()
                .expect_invariant("DROP: IF keyword confirmed by peek");
            let if_start = if_tok.span.start;
            let mut if_end = if_tok.span.end;

            // Consume EXISTS
            if let Some(exists_tok) = p.peek_non_trivia() {
                if matches!(
                    exists_tok.kind,
                    TokenKind::Keyword(crate::lexer::Keyword::Exists)
                ) {
                    let e = p
                        .advance()
                        .expect_invariant("DROP: EXISTS keyword confirmed by peek");
                    if_end = e.span.end;
                }
            }

            if_exists_span = Some(Span {
                start: if_start,
                end: if_end,
            });
            span.end = if_end;
        }
    }

    // Parse object name (mandatory)
    let name_start_idx = p.idx;
    while let Some(tok) = p.peek_non_trivia() {
        match tok.kind {
            TokenKind::Eof
            | TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
            | TokenKind::Operator(crate::lexer::Operator::Pipe) => break,
            // CASCADE and RESTRICT are not keywords in our lexer, check by name
            _ => {
                if tok.lexeme(p.source).eq_ignore_ascii_case("CASCADE")
                    || tok.lexeme(p.source).eq_ignore_ascii_case("RESTRICT")
                {
                    break;
                }
                let t = p
                    .advance()
                    .expect_invariant("DROP: object name token confirmed by peek");
                span.end = t.span.end;
            }
        }
    }

    if p.idx > name_start_idx {
        let name_end_idx = p.idx - 1;
        if name_end_idx >= name_start_idx {
            let first_span = p.tokens[name_start_idx].span;
            let last_span = p.tokens[name_end_idx].span;
            target_name_span = Some(Span {
                start: first_span.start,
                end: last_span.end,
            });
        }
    }

    // Parse optional CASCADE or RESTRICT
    if let Some(tok) = p.peek_non_trivia() {
        if tok.lexeme(p.source).eq_ignore_ascii_case("CASCADE")
            || tok.lexeme(p.source).eq_ignore_ascii_case("RESTRICT")
        {
            let t = p
                .advance()
                .expect_invariant("DROP: CASCADE/RESTRICT confirmed by peek");
            cascade_restrict_span = Some(t.span);
            span.end = t.span.end;
        }
    }

    Ok(AstStmt::Drop(crate::ast::AstDrop {
        node_id: p.id_gen.next(),
        span,
        keyword_span,
        object_type_span,
        if_exists_span,
        target_name_span,
        cascade_restrict_span,
    }))
}

/// Parse a SHOW statement with Result-based error handling.
pub(crate) fn try_parse_show_stmt_with_parser(
    p: &mut Parser<'_>,
) -> crate::error::ParseResult<AstStmt> {
    use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResultExt};

    let kw = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["SHOW".to_string()])?; // SHOW
    let keyword_span = kw.span;
    let mut span = keyword_span;
    let mut terse_span: Option<Span> = None;
    let mut history_span: Option<Span> = None;
    let mut object_span: Option<Span> = None;
    let mut like_pattern_span: Option<Span> = None;
    let mut in_span: Option<Span> = None;
    let mut in_scope_span: Option<Span> = None;
    let mut starts_with_span: Option<Span> = None;
    let mut limit_span: Option<Span> = None;
    let mut limit_from_span: Option<Span> = None;
    // Token index range [start, end) of the IN-scope tokens (scope-kind
    // keyword + optional qualified name), for typed classification.
    let mut scope_token_range: Option<(usize, usize)> = None;

    // Check for TERSE modifier
    if let Some(tok) = p.peek_non_trivia() {
        if tok.lexeme(p.source).eq_ignore_ascii_case("TERSE") {
            let t = p
                .advance()
                .expect_invariant("SHOW: TERSE modifier confirmed by peek");
            terse_span = Some(t.span);
            span.end = t.span.end;
        }
    }

    // Check for HISTORY modifier (before object type)
    if let Some(tok) = p.peek_non_trivia() {
        if tok.lexeme(p.source).eq_ignore_ascii_case("HISTORY") {
            let h = p
                .advance()
                .expect_invariant("SHOW: HISTORY modifier confirmed by peek");
            history_span = Some(h.span);
            span.end = h.span.end;
        }
    }

    // Parse object type (mandatory - TABLES, DATABASES, etc.)
    let start_idx = p.idx;
    // `end_idx` tracks the index past the last token consumed *as part of
    // the object phrase*. We can't read `p.idx` after the loop:
    // `peek_non_trivia` (via `skip_trivia`) advances past the zero-width
    // `Eof` at end-of-input, so an unterminated `SHOW TABLES` would
    // overshoot and pull `Eof` into the phrase. Capturing it right after
    // each advance keeps the terminator out of the range, matching the
    // `;`-terminated case (which breaks on `Semi`).
    let mut end_idx = start_idx;
    while let Some(tok) = p.peek_non_trivia() {
        match tok.kind {
            TokenKind::Keyword(crate::lexer::Keyword::Like)
            | TokenKind::Keyword(crate::lexer::Keyword::In)
            | TokenKind::Keyword(crate::lexer::Keyword::Limit) => break,
            TokenKind::Eof
            | TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
            | TokenKind::Operator(crate::lexer::Operator::Pipe) => break,
            _ => {
                if tok.lexeme(p.source).eq_ignore_ascii_case("STARTS") {
                    // STARTS WITH encountered, don't consume - handle below
                    break;
                } else {
                    let _ = p.advance();
                    end_idx = p.idx;
                }
            }
        }
    }
    if end_idx > start_idx {
        let first = &p.tokens[start_idx];
        let last = &p.tokens[end_idx - 1];
        object_span = Some(Span {
            start: first.span.start,
            end: last.span.end,
        });
        span.end = last.span.end;
    }

    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(crate::lexer::Keyword::Like)) {
            let _ = p.advance();
            if let Some(pat) = p.advance() {
                like_pattern_span = Some(pat.span);
                span.end = pat.span.end;
            }
        }
    }

    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(crate::lexer::Keyword::In)) {
            let in_tok = p
                .advance()
                .expect_invariant("SHOW: IN keyword confirmed by peek");
            in_span = Some(in_tok.span); // Store the IN keyword span
            let scope_first_idx = p.idx;
            if let Some(first_scope) = p.advance() {
                let scope_start = first_scope.span.start;
                let mut scope_end = first_scope.span.end;
                // Past the last consumed scope token (see object-phrase
                // note above: `p.idx` overshoots the terminator at EOF).
                let mut scope_tok_end = p.idx;

                // Consume qualified name (e.g., "SCHEMA mydb.myschema")
                while let Some(next) = p.peek_non_trivia() {
                    match next.kind {
                        TokenKind::Identifier { .. }
                        | TokenKind::Punctuation(crate::lexer::Punctuation::Dot) => {
                            let tok = p
                                .advance()
                                .expect_invariant("SHOW: IN scope token confirmed by peek");
                            scope_end = tok.span.end;
                            scope_tok_end = p.idx;
                        }
                        _ => break,
                    }
                }

                in_scope_span = Some(Span {
                    start: scope_start,
                    end: scope_end,
                });
                span.end = scope_end;
                scope_token_range = Some((scope_first_idx, scope_tok_end));
            }
        }
    }

    // Handle STARTS WITH clause
    if let Some(tok) = p.peek_non_trivia() {
        if tok.lexeme(p.source).eq_ignore_ascii_case("STARTS") {
            let starts_tok = p
                .advance()
                .expect_invariant("SHOW: STARTS keyword confirmed by peek");
            if let Some(with_tok) = p.peek_non_trivia() {
                if with_tok.lexeme(p.source).eq_ignore_ascii_case("WITH") {
                    let _ = p.advance();
                    if let Some(pattern) = p.advance() {
                        starts_with_span = Some(Span {
                            start: starts_tok.span.start,
                            end: pattern.span.end,
                        });
                        span.end = pattern.span.end;
                    }
                }
            }
        }
    }

    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(crate::lexer::Keyword::Limit)) {
            let _ = p.advance();
            if let Some(num) = p.advance() {
                limit_span = Some(num.span);
                span.end = num.span.end;
            }
            if let Some(from_tok) = p.peek_non_trivia() {
                if from_tok.lexeme(p.source).eq_ignore_ascii_case("FROM") {
                    let _ = p.advance();
                    if let Some(off) = p.advance() {
                        limit_from_span = Some(off.span);
                        span.end = off.span.end;
                    }
                }
            }
        }
    }

    // Validate that we have an object type
    if object_span.is_none() {
        return Err(ParseError::new(
            p.current_span(),
            ParseErrorKind::MissingClause {
                clause: "SHOW statement requires an object type (e.g., TABLES, DATABASES, SCHEMAS)"
                    .to_string(),
            },
        ));
    }

    // Typed recognition over the object-phrase / IN-scope token ranges
    // captured above (`end_idx` / `scope_token_range` exclude the
    // statement terminator). Purely additive — spans are unchanged.
    let phrase_slice: &[Token] = if end_idx <= p.tokens.len() && start_idx <= end_idx {
        &p.tokens[start_idx..end_idx]
    } else {
        &[]
    };
    let scope_slice: &[Token] = match scope_token_range {
        Some((s, e)) if e <= p.tokens.len() && s <= e => &p.tokens[s..e],
        _ => &[],
    };
    let (kind, scope) = classify_show(phrase_slice, scope_slice, p.source);

    let stmt = crate::parser::sql_stmt::build_show(
        p.id_gen.next(),
        span,
        keyword_span,
        terse_span,
        history_span,
        object_span,
        like_pattern_span,
        in_span,
        in_scope_span,
        starts_with_span,
        limit_span,
        limit_from_span,
        kind,
        scope,
    );
    Ok(AstStmt::Show(Box::new(stmt)))
}

/// Parse a USE statement (USE ROLE, USE DATABASE, USE SCHEMA, USE WAREHOUSE, USE SECONDARY ROLES)
pub(crate) fn try_parse_use_stmt_with_parser(
    p: &mut Parser<'_>,
) -> crate::error::ParseResult<AstStmt> {
    use crate::ast::{AstUse, AstUseKind};
    use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResultExt};

    let use_kw = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["USE".to_string()])?;
    let use_keyword_span = use_kw.span;
    let mut span = use_keyword_span;

    // Parse context type keyword (ROLE, DATABASE, SCHEMA, WAREHOUSE, SECONDARY ROLES)
    let next = p.peek_non_trivia().ok_or_eof(
        p.current_span(),
        vec!["ROLE, DATABASE, SCHEMA, or WAREHOUSE".to_string()],
    )?;

    let kind_keyword: Option<&crate::lexer::Token>;
    let kind: AstUseKind;
    let mut secondary_roles_span: Option<Span> = None;

    if next.lexeme(p.source).eq_ignore_ascii_case("ROLE") {
        kind_keyword = Some(
            p.advance()
                .expect_invariant("ROLE keyword consumed after lexeme check"),
        );
        kind = AstUseKind::Role;
    } else if next.lexeme(p.source).eq_ignore_ascii_case("CATALOG") {
        kind_keyword = Some(
            p.advance()
                .expect_invariant("CATALOG keyword consumed after lexeme check"),
        );
        kind = AstUseKind::Catalog;
    } else if next.lexeme(p.source).eq_ignore_ascii_case("DATABASE") {
        kind_keyword = Some(
            p.advance()
                .expect_invariant("DATABASE keyword consumed after lexeme check"),
        );
        kind = AstUseKind::Database;
    } else if next.lexeme(p.source).eq_ignore_ascii_case("SCHEMA") {
        kind_keyword = Some(
            p.advance()
                .expect_invariant("SCHEMA keyword consumed after lexeme check"),
        );
        kind = AstUseKind::Schema;
    } else if next.lexeme(p.source).eq_ignore_ascii_case("WAREHOUSE") {
        kind_keyword = Some(
            p.advance()
                .expect_invariant("WAREHOUSE keyword consumed after lexeme check"),
        );
        kind = AstUseKind::Warehouse;
    } else if next.lexeme(p.source).eq_ignore_ascii_case("SECONDARY") {
        let secondary_tok = p
            .advance()
            .expect_invariant("SECONDARY keyword consumed after lexeme check");
        // Expect ROLES after SECONDARY
        let roles_tok = p
            .peek_non_trivia()
            .ok_or_eof(p.current_span(), vec!["ROLES".to_string()])?;
        if !roles_tok.lexeme(p.source).eq_ignore_ascii_case("ROLES") {
            return Err(ParseError::new(
                roles_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected ROLES after SECONDARY, found '{}'",
                        roles_tok.lexeme(p.source)
                    ),
                },
            ));
        }
        let roles_tok = p
            .advance()
            .expect_invariant("ROLES keyword consumed after validation"); // Consume ROLES
                                                                          // Store combined span for SECONDARY ROLES
        secondary_roles_span = Some(Span {
            start: secondary_tok.span.start,
            end: roles_tok.span.end,
        });
        kind_keyword = Some(secondary_tok);
        kind = AstUseKind::SecondaryRoles;
    } else {
        // DATABASE keyword is optional: "USE mydb" is valid
        // Treat as USE DATABASE
        kind_keyword = None;
        kind = AstUseKind::Database;
    }

    // For SECONDARY ROLES, use the combined span; otherwise use the token span
    let kind_keyword_span = secondary_roles_span.or_else(|| kind_keyword.as_ref().map(|t| t.span));
    if let Some(ref kw_span) = kind_keyword_span {
        span.end = kw_span.end;
    }

    // Parse object name (identifier or qualified name for schema: db.schema)
    // For USE SECONDARY ROLES, there's no object name (ALL or NONE are special values handled later)
    if matches!(kind, AstUseKind::SecondaryRoles) {
        // USE SECONDARY ROLES [ALL | NONE]
        let value_tok = p
            .peek_non_trivia()
            .ok_or_eof(p.current_span(), vec!["ALL or NONE".to_string()])?;
        let value_span = value_tok.span;
        let _ = p.advance();
        span.end = value_span.end;

        return Ok(AstStmt::Use(AstUse {
            node_id: p.id_gen.next(),
            span,
            kind,
            use_keyword_span,
            kind_keyword_span,
            object_span: value_span,
        }));
    }

    // Parse identifier/object reference
    let start_idx = p.idx;
    let mut object_end = span.end;

    // Consume identifier tokens (handles qualified names like db.schema)
    while let Some(tok) = p.peek_non_trivia() {
        match tok.kind {
            TokenKind::Identifier { .. }
            | TokenKind::Punctuation(crate::lexer::Punctuation::Dot) => {
                let t = p
                    .advance()
                    .expect_invariant("Identifier or Dot consumed after match");
                object_end = t.span.end;
            }
            // Handle Jinja expressions: USE DATABASE {{ database }}
            TokenKind::JinjaExprOpen => {
                // Consume opening {{ delimiter
                let open_tok = p
                    .advance()
                    .expect_invariant("JinjaExprOpen consumed after match");
                object_end = open_tok.span.end;

                // Parse the Jinja expression content
                let _ = p.parse_jinja_expr();

                // Consume closing }} delimiter
                if let Some(close) = p.peek_non_trivia() {
                    if matches!(close.kind, TokenKind::JinjaExprClose) {
                        let close_tok = p
                            .advance()
                            .expect_invariant("JinjaExprClose consumed after match");
                        object_end = close_tok.span.end;
                    }
                }
            }
            TokenKind::Keyword(_) => {
                // Check if this is IDENTIFIER() function
                if tok.lexeme(p.source).eq_ignore_ascii_case("IDENTIFIER") {
                    let t = p
                        .advance()
                        .expect_invariant("IDENTIFIER keyword consumed after lexeme check");
                    object_end = t.span.end;

                    // Expect ( $variable )
                    if let Some(lparen) = p.peek_non_trivia() {
                        if matches!(
                            lparen.kind,
                            TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                        ) {
                            let _ = p.advance();
                            // Consume until closing paren
                            let mut depth = 1;
                            while depth > 0 {
                                if let Some(t) = p.advance() {
                                    object_end = t.span.end;
                                    match t.kind {
                                        TokenKind::Punctuation(
                                            crate::lexer::Punctuation::LParen,
                                        ) => depth += 1,
                                        TokenKind::Punctuation(
                                            crate::lexer::Punctuation::RParen,
                                        ) => depth -= 1,
                                        _ => {}
                                    }
                                } else {
                                    break;
                                }
                            }
                        }
                    }
                    break;
                } else {
                    break;
                }
            }
            _ => break,
        }
    }

    let end_idx = p.idx;
    if end_idx == start_idx {
        return Err(ParseError::new(
            p.current_span(),
            ParseErrorKind::MissingClause {
                clause: format!(
                    "USE {} requires an object name",
                    match kind {
                        AstUseKind::Role => "ROLE",
                        AstUseKind::Catalog => "CATALOG",
                        AstUseKind::Database => "DATABASE",
                        AstUseKind::Schema => "SCHEMA",
                        AstUseKind::Warehouse => "WAREHOUSE",
                        AstUseKind::SecondaryRoles => "SECONDARY ROLES",
                    }
                ),
            },
        ));
    }

    let first_tok = &p.tokens[start_idx];
    let object_span = Span {
        start: first_tok.span.start,
        end: object_end,
    };
    span.end = object_end;

    Ok(AstStmt::Use(AstUse {
        node_id: p.id_gen.next(),
        span,
        kind,
        use_keyword_span,
        kind_keyword_span,
        object_span,
    }))
}

/// Parse a DESCRIBE statement with Result-based error handling.
pub(crate) fn try_parse_describe_stmt_with_parser(
    p: &mut Parser<'_>,
) -> crate::error::ParseResult<AstStmt> {
    use crate::error::ParseResultExt;

    let kw = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["DESCRIBE".to_string()])?; // DESCRIBE
    let keyword_span = kw.span;
    let mut span = keyword_span;
    let mut object_span: Option<Span> = None;
    let mut type_clause_span: Option<Span> = None;

    let start_idx = p.idx;
    while let Some(tok) = p.peek_non_trivia() {
        match tok.kind {
            TokenKind::Eof | TokenKind::Punctuation(crate::lexer::Punctuation::Semi) => break,
            _ => {
                // Check for TYPE keyword
                if tok.lexeme(p.source).eq_ignore_ascii_case("TYPE") {
                    break;
                }
                let _ = p.advance();
            }
        }
    }
    let end_idx = p.idx;
    if end_idx > start_idx {
        let first = &p.tokens[start_idx];
        let last = &p.tokens[end_idx - 1];
        object_span = Some(Span {
            start: first.span.start,
            end: last.span.end,
        });
        span.end = last.span.end;
    }

    // Check for optional TYPE clause
    if let Some(tok) = p.peek_non_trivia() {
        if tok.lexeme(p.source).eq_ignore_ascii_case("TYPE") {
            let type_start = tok.span.start;
            let _ = p.advance(); // TYPE

            // Consume = sign
            if let Some(eq_tok) = p.peek_non_trivia() {
                if matches!(eq_tok.kind, TokenKind::Operator(crate::lexer::Operator::Eq)) {
                    let _ = p.advance();
                }
            }

            // Consume COLUMNS or STAGE
            if let Some(val_tok) = p.peek_non_trivia() {
                let _ = p.advance();
                type_clause_span = Some(Span {
                    start: type_start,
                    end: val_tok.span.end,
                });
                span.end = val_tok.span.end;
            }
        }
    }

    Ok(AstStmt::Describe(crate::ast::AstDescribe {
        node_id: p.id_gen.next(),
        span,
        kind: crate::ast::AstDescribeKind::Other, // Generic - formatter will preserve
        keyword_span,
        object_span,
        type_clause_span,
    }))
}

/// Parse SET assignments naturally using the current parser position.
/// Parses "col1 = expr1, col2 = expr2, ..." into individual AstSetAssignment structs.
/// Stops at WHEN, semicolon, or EOF (natural descent).
fn parse_set_assignments_natural(p: &mut Parser<'_>) -> Vec<crate::ast::AstSetAssignment> {
    let mut assignments = Vec::new();

    // Skip SET keyword if present
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(crate::lexer::Keyword::Set)) {
            p.advance();
        }
    }

    // Parse assignments: column = expr, column = expr, ...
    loop {
        p.skip_trivia();

        // Check for terminating keywords (WHEN, semicolon, EOF)
        if let Some(tok) = p.peek_non_trivia() {
            match &tok.kind {
                TokenKind::Keyword(crate::lexer::Keyword::When)
                | TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
                | TokenKind::Eof => break,
                _ => {}
            }
        } else {
            break;
        }

        // Parse column expression (typically an identifier)
        let column = match p.parse_primary_expr_in_mode() {
            Ok(expr) => expr,
            Err(_) => break,
        };

        // Expect equals sign
        p.skip_trivia();
        let equals_span = match p.peek_non_trivia() {
            Some(tok) if matches!(tok.kind, TokenKind::Operator(crate::lexer::Operator::Eq)) => {
                let span = tok.span;
                p.advance();
                span
            }
            _ => break,
        };

        // Parse value expression (stop at comma, WHEN, semicolon, or EOF)
        let value = match p.parse_expr_in_mode() {
            Ok(expr) => expr,
            Err(_) => break,
        };

        // Calculate assignment span
        let assignment_span = crate::lexer::Span {
            start: crate::parser::scripting::expr_span_start(&column),
            end: crate::parser::scripting::expr_span_end(&value),
        };

        assignments.push(crate::ast::AstSetAssignment {
            node_id: p.id_gen.next(),
            column: Box::new(column),
            equals_span,
            value: Box::new(value),
            span: assignment_span,
        });

        // Check for comma (continue) or terminating keyword
        p.skip_trivia();
        if let Some(tok) = p.peek_non_trivia() {
            match &tok.kind {
                TokenKind::Punctuation(crate::lexer::Punctuation::Comma) => {
                    p.advance();
                    continue;
                }
                TokenKind::Keyword(crate::lexer::Keyword::When)
                | TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
                | TokenKind::Eof => break,
                _ => break,
            }
        }
        break;
    }

    assignments
}

/// MySQL: trailing `ORDER BY ... LIMIT n` tail on single-table UPDATE/DELETE.
/// Reuses the SELECT order-by parser; `LIMIT` here is a bare row-count
/// expression (no OFFSET/comma form). Gated by the dialect predicate.
#[allow(clippy::type_complexity)] // 3-tuple of optionals mirrors the AST fields it fills
fn parse_dml_order_limit_tail(
    p: &mut Parser<'_>,
) -> crate::error::ParseResult<(
    Option<Box<crate::ast::AstOrderBy>>,
    Option<Box<crate::ast::AstExpr>>,
    Option<Span>,
)> {
    if !p.dialect.supports_update_delete_order_limit() {
        return Ok((None, None, None));
    }
    let order_by = p.parse_select_order_by()?.map(Box::new);
    let mut limit = None;
    let mut limit_keyword_span = None;
    if let Some(tok) = p.peek() {
        if matches!(tok.kind, TokenKind::Keyword(crate::lexer::Keyword::Limit)) {
            limit_keyword_span = Some(tok.span);
            p.advance(); // consume LIMIT
            limit = Some(Box::new(p.parse_expr()?));
        }
    }
    Ok((order_by, limit, limit_keyword_span))
}

/// MySQL DML modifier: consume an identifier-lexed keyword (`LOW_PRIORITY`,
/// `IGNORE`, `QUICK`) when it appears next, returning its span. Caller gates
/// on the dialect predicate.
fn consume_dml_modifier(p: &mut Parser<'_>, lexeme: &str) -> Option<Span> {
    use crate::error::ExpectInvariant;
    let tok = p.peek()?;
    if matches!(tok.kind, TokenKind::Identifier { .. })
        && tok.lexeme(p.source).eq_ignore_ascii_case(lexeme)
    {
        return Some(
            p.advance()
                .expect_invariant("DML modifier confirmed by peek")
                .span,
        );
    }
    None
}

/// MySQL multi-table DELETE target before FROM: an optionally `.*`-qualified
/// table reference (`t1` or `t1.*`). The dotted name is parsed by the shared
/// `parse_qualified_name_span` (which consumes the trailing dot before a
/// non-identifier `*`); the `*` is then folded into the ref span. `parts` is
/// `None` because these are deletion-target qualifiers, not decomposable names.
fn parse_delete_target(
    p: &mut Parser<'_>,
) -> crate::error::ParseResult<Box<crate::ast::AstTableRef>> {
    use crate::error::ExpectInvariant;
    let name_span = p.parse_qualified_name_span()?;
    let mut end = name_span.end;
    if let Some(tok) = p.peek() {
        if matches!(tok.kind, TokenKind::Operator(crate::lexer::Operator::Star)) {
            end = p
                .advance()
                .expect_invariant("star confirmed by peek")
                .span
                .end;
        }
    }
    let full = Span {
        start: name_span.start,
        end,
    };
    let name = crate::ast::AstObjectRef {
        node_id: p.id_gen.next(),
        span: name_span,
        parts: None,
        identifier_arg: None,
    };
    Ok(Box::new(build_table_ref(
        p.id_gen.next(),
        full,
        name,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )))
}

pub(crate) fn try_parse_update_stmt_with_parser(
    p: &mut Parser<'_>,
) -> crate::error::ParseResult<AstStmt> {
    use crate::error::{ParseError, ParseErrorKind, ParseResultExt};

    // Consume UPDATE keyword
    let kw = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["UPDATE".to_string()])?;
    let keyword_span = kw.span;
    let start_span = keyword_span;

    // T-SQL: optional TOP clause after UPDATE keyword
    let top = p.try_parse_top_clause()?;

    // MySQL: LOW_PRIORITY / IGNORE modifiers (both lex as identifiers).
    let (mut low_priority_span, mut ignore_span) = (None, None);
    if p.dialect.supports_dml_modifiers() {
        low_priority_span = consume_dml_modifier(p, "LOW_PRIORITY");
        ignore_span = consume_dml_modifier(p, "IGNORE");
    }

    // Parse target table reference
    let mut target_table = p.parse_table_factor(start_span)?.ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidSyntax {
                message: "UPDATE requires a table name".to_string(),
            },
        )
    })?;

    // MySQL multi-table UPDATE: attach a join chain to the primary target and
    // collect comma-separated additional targets (`UPDATE t1 JOIN t2 ...` and
    // `UPDATE t1, t2 ...`). Each comma element is itself a table factor + join
    // chain.
    let mut additional_targets: Vec<Box<crate::ast::AstTableRef>> = Vec::new();
    if p.dialect.supports_multi_table_update() {
        p.parse_join_chain(&mut target_table)?;
        while let Some(tok) = p.peek() {
            if !matches!(
                tok.kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
            ) {
                break;
            }
            let comma_span = tok.span;
            p.advance(); // consume comma
            if let Some(mut next) = p.parse_table_factor(comma_span)? {
                p.parse_join_chain(&mut next)?;
                additional_targets.push(next);
            } else {
                break;
            }
        }
    }

    // Expect SET keyword
    let set_kw_span = p.expect_keyword(crate::lexer::Keyword::Set).map_err(|_| {
        let span = p.current_span();
        let message = "UPDATE requires SET clause to specify column assignments. Example: UPDATE table SET column = value";
        ParseError::new(
            span,
            ParseErrorKind::MissingClause {
                clause: format!("SET - {}", message),
            },
        )
    })?;
    let set_start = set_kw_span.start;

    // Parse SET assignments: col = expr, col = expr, ...
    let mut set_assignments = Vec::new();
    loop {
        // Parse column expression - use additive precedence to stop before = operator
        let column = p.parse_add_expr_in_mode()?;

        // Expect equals sign
        let tok = p
            .peek()
            .ok_or_eof(p.current_span(), vec!["=".to_string()])?;

        if !matches!(tok.kind, TokenKind::Operator(crate::lexer::Operator::Eq)) {
            return Err(ParseError::unexpected_token(
                tok.span,
                vec!["=".to_string()],
                Parser::token_description(tok, p.source),
            ));
        }
        let equals_span = tok.span;
        p.advance();

        // Parse value expression
        let value = p.parse_expr()?;

        let assignment_span = crate::lexer::Span {
            start: crate::parser::scripting::expr_span_start(&column),
            end: crate::parser::scripting::expr_span_end(&value),
        };

        set_assignments.push(crate::ast::AstSetAssignment {
            node_id: p.id_gen.next(),
            column: Box::new(column),
            equals_span,
            value: Box::new(value),
            span: assignment_span,
        });

        // Check for comma or end of SET clause
        if let Some(tok) = p.peek() {
            if matches!(
                tok.kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
            ) {
                p.advance();
                continue;
            }
        }
        break;
    }

    if set_assignments.is_empty() {
        return Err(ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidSyntax {
                message: "SET clause must specify at least one column assignment".to_string(),
            },
        ));
    }

    // Calculate set_span
    let set_end = set_assignments
        .last()
        .map(|a| a.span.end)
        .unwrap_or(set_start);
    let set_span = crate::lexer::Span {
        start: set_start,
        end: set_end,
    };

    // MSSQL: optional OUTPUT clause appears after SET and before FROM/WHERE
    let output = p.try_parse_output_clause(&[
        crate::lexer::Keyword::From,
        crate::lexer::Keyword::Where,
        crate::lexer::Keyword::Returning,
    ])?;

    // Parse optional FROM clause with full join support
    let mut from = Vec::new();
    let mut from_keyword_span: Option<Span> = None;
    if let Some(tok) = p.peek() {
        if matches!(tok.kind, TokenKind::Keyword(crate::lexer::Keyword::From)) {
            from_keyword_span = Some(tok.span);
            let from_span = tok.span;
            // Use parse_select_from_clause to handle JOINs properly
            if let Ok(from_items) = p.parse_select_from_clause(from_span) {
                // Extract AstTableRef from each FromItem
                // UPDATE doesn't support Jinja in FROM, so we only handle TableRef variants
                for item in from_items {
                    if let Some(table_ref) = item.as_table_ref() {
                        from.push(table_ref.clone());
                    }
                }
            }
        }
    }

    // Parse optional WHERE clause
    let mut where_keyword_span: Option<Span> = None;
    let where_clause = if let Some(tok) = p.peek() {
        if matches!(tok.kind, TokenKind::Keyword(crate::lexer::Keyword::Where)) {
            where_keyword_span = Some(tok.span);
            p.advance();
            p.parse_expr().ok()
        } else {
            None
        }
    } else {
        None
    };

    // Parse optional RETURNING clause (PostgreSQL)
    let returning = p.try_parse_returning()?;

    // MySQL: trailing ORDER BY ... LIMIT n (single-table UPDATE).
    let (order_by, limit, limit_keyword_span) = parse_dml_order_limit_tail(p)?;

    // Calculate final span — trailing clauses extend the end so the
    // formatter does not lose them in the inter-statement gap.
    let mut end_pos = if let Some(ref ret) = returning {
        ret.span.end
    } else if let Some(ref out) = output {
        out.span.end
    } else if let Some(ref wc) = where_clause {
        crate::parser::scripting::expr_span_end(wc)
    } else if let Some(last_from) = from.last() {
        // Include joins in the span calculation
        last_from.span.end
    } else if let Some(last_set) = set_assignments.last() {
        last_set.span.end
    } else {
        // Fallback to target table span if both FROM and SET are empty
        target_table.name.span.end
    };
    if let Some(ref ob) = order_by {
        end_pos = end_pos.max(ob.span.end);
    }
    if let Some(ref lim) = limit {
        end_pos = end_pos.max(crate::parser::scripting::expr_span_end(lim));
    }

    let span = crate::lexer::Span {
        start: start_span.start,
        end: end_pos,
    };

    let body_start = target_table.name.span.start;
    let body_span = Some(crate::lexer::Span {
        start: body_start,
        end: end_pos,
    });

    let mut stmt = build_update(
        p.id_gen.next(),
        span,
        keyword_span,
        body_span,
        Some(*target_table),
        Some(set_span),
        set_assignments,
        from,
        where_clause,
    );
    stmt.set_keyword_span = Some(set_kw_span);
    stmt.from_keyword_span = from_keyword_span;
    stmt.where_keyword_span = where_keyword_span;
    stmt.low_priority_span = low_priority_span;
    stmt.ignore_span = ignore_span;
    stmt.additional_targets = additional_targets;
    stmt.order_by = order_by;
    stmt.limit = limit;
    stmt.limit_keyword_span = limit_keyword_span;
    stmt.output = output;
    stmt.returning = returning;
    stmt.top = top;
    Ok(AstStmt::Update(Box::new(stmt)))
}

/// Parse a DELETE statement with Result-based error handling.
pub(crate) fn try_parse_delete_stmt_with_parser(
    p: &mut Parser<'_>,
) -> crate::error::ParseResult<AstStmt> {
    use crate::error::{ParseError, ParseResultExt};

    let kw = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["DELETE".to_string()])?; // DELETE
    let keyword_span = kw.span;
    let start_span = keyword_span;

    // T-SQL: optional TOP clause after DELETE keyword
    let top = p.try_parse_top_clause()?;

    // MySQL: LOW_PRIORITY / QUICK / IGNORE modifiers (all lex as identifiers).
    let (mut low_priority_span, mut quick_span, mut ignore_span) = (None, None, None);
    if p.dialect.supports_dml_modifiers() {
        low_priority_span = consume_dml_modifier(p, "LOW_PRIORITY");
        quick_span = consume_dml_modifier(p, "QUICK");
        ignore_span = consume_dml_modifier(p, "IGNORE");
    }

    // Target list before FROM:
    //  - T-SQL: a single alias (`DELETE d FROM ...`) — skipped (the FROM
    //    clause carries the real table reference with joins).
    //  - MySQL multi-table: a comma-separated list of optionally `.*`-
    //    qualified targets (`DELETE t1, t2 FROM ...`, `DELETE t1.* FROM ...`).
    let mut targets: Vec<Box<crate::ast::AstTableRef>> = Vec::new();
    let next_tok = p.peek().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            crate::error::ParseErrorKind::InvalidSyntax {
                message: "DELETE statement requires FROM clause to specify target table"
                    .to_string(),
            },
        )
    })?;
    if !matches!(
        next_tok.kind,
        TokenKind::Keyword(crate::lexer::Keyword::From)
    ) {
        if p.dialect.supports_multi_table_delete() {
            loop {
                targets.push(parse_delete_target(p)?);
                if let Some(comma) = p.peek() {
                    if matches!(
                        comma.kind,
                        TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                    ) {
                        p.advance(); // consume comma, continue target list
                        continue;
                    }
                }
                break;
            }
        } else {
            // T-SQL target alias — skip it.
            p.advance();
        }
    }

    // Expect FROM keyword
    let from_tok = p.peek().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            crate::error::ParseErrorKind::InvalidSyntax {
                message: "DELETE statement requires FROM clause to specify target table"
                    .to_string(),
            },
        )
    })?;
    if !matches!(
        from_tok.kind,
        TokenKind::Keyword(crate::lexer::Keyword::From)
    ) {
        return Err(ParseError::unexpected_token(
            from_tok.span,
            vec!["FROM".to_string()],
            Parser::token_description(from_tok, p.source),
        ));
    }
    let from_span = from_tok.span;
    let from_keyword_span = from_tok.span;
    p.advance(); // consume FROM

    // Parse target table reference (mandatory)
    let mut target_table = p.parse_table_factor(from_span)?.ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            crate::error::ParseErrorKind::InvalidSyntax {
                message: "DELETE FROM requires a table name".to_string(),
            },
        )
    })?;

    // T-SQL: DELETE ... FROM table JOIN other_table ... WHERE ...
    // The FROM clause can include JOINs, just like SELECT FROM.
    // parse_table_factor only parses a single table; we need parse_join_chain
    // to attach any JOINs (INNER JOIN, LEFT JOIN, etc.) to the target table.
    p.parse_join_chain(&mut target_table)?;

    // MSSQL: optional OUTPUT clause appears after target and before additional source/filters
    let output = p.try_parse_output_clause(&[
        crate::lexer::Keyword::Using,
        crate::lexer::Keyword::From,
        crate::lexer::Keyword::Where,
        crate::lexer::Keyword::Returning,
    ])?;

    // Parse optional USING/FROM clause
    let mut using = Vec::new();
    let mut using_keyword_span: Option<Span> = None;
    if let Some(tok) = p.peek() {
        if matches!(tok.kind, TokenKind::Keyword(crate::lexer::Keyword::Using))
            || matches!(tok.kind, TokenKind::Keyword(crate::lexer::Keyword::From))
        {
            using_keyword_span = Some(tok.span);
            let using_span = tok.span;
            p.advance(); // consume USING/FROM

            // Parse comma-separated table references, each allowing a JOIN
            // chain (`USING t1 JOIN t2 ON ...`).
            loop {
                if let Some(mut table_ref) = p.parse_table_factor(using_span)? {
                    p.parse_join_chain(&mut table_ref)?;
                    using.push(*table_ref);

                    // Check for comma
                    if let Some(comma_tok) = p.peek() {
                        if matches!(
                            comma_tok.kind,
                            TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                        ) {
                            p.advance(); // consume comma
                            continue;
                        }
                    }
                }
                break;
            }
        }
    }

    // Parse optional WHERE clause
    let mut where_keyword_span: Option<Span> = None;
    let where_clause = if let Some(tok) = p.peek() {
        if matches!(tok.kind, TokenKind::Keyword(crate::lexer::Keyword::Where)) {
            where_keyword_span = Some(tok.span);
            p.advance(); // consume WHERE
            let expr = p.parse_expr()?;
            Some(expr)
        } else {
            None
        }
    } else {
        None
    };

    // Parse optional RETURNING clause (PostgreSQL)
    let returning = p.try_parse_returning()?;

    // MySQL: trailing ORDER BY ... LIMIT n (single-table DELETE).
    let (order_by, limit, limit_keyword_span) = parse_dml_order_limit_tail(p)?;

    // Calculate final span — trailing clauses extend the end so the
    // formatter does not lose them in the inter-statement gap. Table-ref
    // spans already include any attached join chain.
    let mut end_pos = if let Some(ref ret) = returning {
        ret.span.end
    } else if let Some(ref out) = output {
        out.span.end
    } else if let Some(ref wc) = where_clause {
        crate::parser::scripting::expr_span_end(wc)
    } else if let Some(last_using) = using.last() {
        last_using.span.end
    } else {
        // Table-ref span covers any PARTITION (p, ...) selection.
        target_table.span.end
    };
    if let Some(ref ob) = order_by {
        end_pos = end_pos.max(ob.span.end);
    }
    if let Some(ref lim) = limit {
        end_pos = end_pos.max(crate::parser::scripting::expr_span_end(lim));
    }

    let span = crate::lexer::Span {
        start: start_span.start,
        end: end_pos,
    };

    // Calculate body_span (everything after DELETE keyword, starting with FROM)
    let body_span = Some(crate::lexer::Span {
        start: from_span.start,
        end: end_pos,
    });

    let mut stmt = crate::parser::sql_stmt::build_delete(
        p.id_gen.next(),
        span,
        keyword_span,
        body_span,
        Some(*target_table),
        using,
        where_clause,
    );
    stmt.from_keyword_span = Some(from_keyword_span);
    stmt.using_keyword_span = using_keyword_span;
    stmt.where_keyword_span = where_keyword_span;
    stmt.targets = targets;
    stmt.low_priority_span = low_priority_span;
    stmt.quick_span = quick_span;
    stmt.ignore_span = ignore_span;
    stmt.order_by = order_by;
    stmt.limit = limit;
    stmt.limit_keyword_span = limit_keyword_span;
    stmt.output = output;
    stmt.returning = returning;
    stmt.top = top;
    Ok(AstStmt::Delete(Box::new(stmt)))
}

/// Parse a MERGE statement with Result-based error handling.
pub(crate) fn try_parse_merge_stmt_with_parser(
    p: &mut Parser<'_>,
) -> crate::error::ParseResult<AstStmt> {
    use crate::error::{ExpectInvariant, ParseError, ParseResultExt};

    let kw = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["MERGE".to_string()])?; // MERGE
    let keyword_span = kw.span;
    let mut span = keyword_span;
    let mut with_schema_evolution_span: Option<Span> = None;
    let mut target_table_span: Option<Span> = None;
    let mut using_span: Option<Span> = None;
    let mut on_span: Option<Span> = None;
    let mut clauses: Vec<crate::ast::AstMergeClause> = Vec::new();

    // Databricks: optional WITH SCHEMA EVOLUTION after MERGE
    if let Some(with_tok) = p.peek_non_trivia() {
        if matches!(
            with_tok.kind,
            TokenKind::Keyword(crate::lexer::Keyword::With)
        ) {
            let with_start = with_tok.span.start;
            let checkpoint = p.idx;
            let _ = p.advance(); // WITH

            let mut matched = false;
            if let Some(schema_tok) = p.peek_non_trivia() {
                if schema_tok.lexeme(p.source).eq_ignore_ascii_case("SCHEMA") {
                    let _ = p.advance();
                    if let Some(evolution_tok) = p.peek_non_trivia() {
                        if evolution_tok
                            .lexeme(p.source)
                            .eq_ignore_ascii_case("EVOLUTION")
                        {
                            let evolution = p
                                .advance()
                                .expect_invariant("MERGE: EVOLUTION token confirmed by peek");
                            with_schema_evolution_span = Some(Span {
                                start: with_start,
                                end: evolution.span.end,
                            });
                            span.end = evolution.span.end;
                            matched = true;
                        }
                    }
                }
            }

            if !matched {
                // Not WITH SCHEMA EVOLUTION; rewind so target parsing sees WITH token.
                p.idx = checkpoint;
            }
        }
    }

    // Parse target table: MERGE [INTO] table_ref [AS alias]
    // INTO is optional (BigQuery omits it: MERGE `table` AS T USING ...)
    let mut into_span: Option<Span> = None;
    if let Some(tok) = p.peek_non_trivia() {
        // Consume optional INTO keyword. The target span must exclude INTO
        // itself — it covers only the table reference tokens so that downstream
        // consumers see the raw table name.
        if matches!(tok.kind, TokenKind::Keyword(crate::lexer::Keyword::Into)) {
            let into_tok = p
                .advance()
                .expect_invariant("MERGE: INTO keyword confirmed by peek");
            into_span = Some(into_tok.span);
        }
        let target_start = match p.peek_non_trivia() {
            Some(next) => next.span.start,
            None => {
                return Err(ParseError::new(
                    p.current_span(),
                    crate::error::ParseErrorKind::InvalidSyntax {
                        message: "MERGE statement requires a target table".to_string(),
                    },
                ));
            }
        };

        // Consume tokens until USING (the target table ref + optional alias)
        while let Some(t) = p.peek_non_trivia() {
            match &t.kind {
                TokenKind::Keyword(crate::lexer::Keyword::Using)
                | TokenKind::Eof
                | TokenKind::Punctuation(crate::lexer::Punctuation::Semi) => break,
                _ => {
                    let _ = p.advance();
                }
            }
        }
        let end = match p.tokens.get(p.idx.saturating_sub(1)) {
            Some(last) => last.span.end,
            None => target_start,
        };
        target_table_span = Some(Span {
            start: target_start,
            end,
        });
        span.end = end;
    }

    // Validate target table exists
    if target_table_span.is_none() {
        return Err(ParseError::new(
            p.current_span(),
            crate::error::ParseErrorKind::InvalidSyntax {
                message: "MERGE statement requires a target table".to_string(),
            },
        ));
    }

    // Parse USING clause (mandatory)
    // Can be: USING table_ref alias
    //     or: USING (SELECT ...) alias
    let mut using_subquery: Option<Box<crate::ast::AstStmt>> = None;
    let mut using_table_ref: Option<Box<crate::ast::AstTableRef>> = None;
    let mut using_alias_span: Option<Span> = None;
    let mut using_keyword_span: Option<Span> = None;

    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(crate::lexer::Keyword::Using)) {
            let using_tok = p
                .advance()
                .expect_invariant("MERGE: USING keyword confirmed by peek");
            using_keyword_span = Some(using_tok.span);
            let start = using_tok.span.start;

            // Check if next token is opening paren (subquery)
            p.skip_trivia();
            if let Some(next) = p.peek_non_trivia() {
                if matches!(
                    next.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                ) {
                    // This is a subquery: USING (SELECT ...) alias
                    let lparen_tok = p.advance().expect_invariant(
                        "MERGE: opening paren for USING subquery confirmed by peek",
                    );
                    let subquery_start = lparen_tok.span.start;

                    // Check if it's a SELECT or WITH (subquery) vs just a parenthesized table ref
                    p.skip_trivia();
                    if let Some(inner) = p.peek_non_trivia() {
                        if matches!(
                            inner.kind,
                            TokenKind::Keyword(crate::lexer::Keyword::Select)
                                | TokenKind::Keyword(crate::lexer::Keyword::With)
                        ) {
                            // Parse the SELECT/WITH statement
                            match p.parse_statement() {
                                Ok(stmt) => {
                                    if matches!(
                                        stmt,
                                        crate::ast::AstStmt::Select(_)
                                            | crate::ast::AstStmt::SetSelect(_)
                                    ) {
                                        using_subquery = Some(Box::new(stmt));
                                    }
                                }
                                Err(_) => {
                                    // Fall back to span-based parsing
                                }
                            }
                        }
                    }

                    // Skip to closing paren (in case subquery parsing failed or it's a table ref)
                    let mut paren_depth = 1;
                    while paren_depth > 0 {
                        if let Some(t) = p.peek_non_trivia() {
                            match &t.kind {
                                TokenKind::Punctuation(crate::lexer::Punctuation::LParen) => {
                                    paren_depth += 1;
                                    let _ = p.advance();
                                }
                                TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => {
                                    paren_depth -= 1;
                                    let _ = p.advance();
                                }
                                TokenKind::Eof => break,
                                _ => {
                                    let _ = p.advance();
                                }
                            }
                        } else {
                            break;
                        }
                    }

                    // Now look for the alias (identifier before ON)
                    p.skip_trivia();

                    // Skip optional AS keyword
                    if let Some(as_tok) = p.peek_non_trivia() {
                        if matches!(as_tok.kind, TokenKind::Keyword(crate::lexer::Keyword::As)) {
                            let _ = p.advance();
                            p.skip_trivia();
                        }
                    }

                    if let Some(alias_tok) = p.peek_non_trivia() {
                        if !matches!(
                            alias_tok.kind,
                            TokenKind::Keyword(crate::lexer::Keyword::On)
                        ) {
                            // This is the alias
                            let alias = p
                                .advance()
                                .expect_invariant("MERGE: USING alias confirmed by peek");
                            using_alias_span = Some(alias.span);
                        }
                    }

                    let end = match p.tokens.get(p.idx.saturating_sub(1)) {
                        Some(last) => last.span.end,
                        None => subquery_start,
                    };
                    using_span = Some(Span { start, end });
                    span.end = end;
                } else {
                    // Regular table reference: USING table_name [alias]
                    // Parse a full structured AstTableRef so downstream
                    // consumers can use the name and alias without
                    // re-parsing raw bytes.
                    if let Ok(Some(tref)) = p.parse_table_factor(using_tok.span) {
                        let ref_end = tref.span.end;
                        using_table_ref = Some(tref);
                        using_span = Some(Span {
                            start,
                            end: ref_end,
                        });
                        span.end = ref_end;
                    } else {
                        // parse_table_factor returned None (EOF or unrecognised
                        // token) — fall back to consuming until ON.
                        while let Some(t) = p.peek_non_trivia() {
                            match &t.kind {
                                TokenKind::Keyword(crate::lexer::Keyword::On)
                                | TokenKind::Eof
                                | TokenKind::Punctuation(crate::lexer::Punctuation::Semi) => break,
                                _ => {
                                    let _ = p.advance();
                                }
                            }
                        }
                        let end = match p.tokens.get(p.idx.saturating_sub(1)) {
                            Some(last) => last.span.end,
                            None => using_tok.span.end,
                        };
                        using_span = Some(Span { start, end });
                        span.end = end;
                    }
                }
            } else {
                // No token after USING
                let end = using_tok.span.end;
                using_span = Some(Span { start, end });
                span.end = end;
            }
        }
    }

    // Validate USING clause exists
    if using_span.is_none() {
        return Err(ParseError::new(
            p.current_span(),
            crate::error::ParseErrorKind::InvalidSyntax {
                message: "MERGE statement requires USING clause to specify source table or query"
                    .to_string(),
            },
        ));
    }

    // Parse ON clause (mandatory)
    let mut on_condition: Option<Box<crate::ast::AstExpr>> = None;
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(crate::lexer::Keyword::On)) {
            let on_tok = p
                .advance()
                .expect_invariant("MERGE: ON keyword confirmed by peek");
            let start = on_tok.span.start;
            // Try to parse the ON condition as an expression.
            // parse_expr will stop naturally at WHEN because WHEN has no
            // binding power in the expression parser.
            let checkpoint = p.idx;
            match p.parse_expr() {
                Ok(expr) => {
                    let cond_end = expr.span().end;
                    on_span = Some(Span {
                        start,
                        end: cond_end,
                    });
                    span.end = cond_end;
                    on_condition = Some(Box::new(expr));
                }
                Err(_) => {
                    // Fallback: consume tokens until WHEN (original behavior)
                    p.idx = checkpoint;
                    while let Some(t) = p.peek_non_trivia() {
                        match &t.kind {
                            TokenKind::Keyword(crate::lexer::Keyword::When)
                            | TokenKind::Eof
                            | TokenKind::Punctuation(crate::lexer::Punctuation::Semi) => break,
                            _ => {
                                let _ = p.advance();
                            }
                        }
                    }
                    let end_idx = p.idx;
                    if end_idx > checkpoint {
                        let last = &p.tokens[end_idx - 1];
                        on_span = Some(Span {
                            start,
                            end: last.span.end,
                        });
                        span.end = last.span.end;
                    }
                }
            }
        }
    }

    // Validate ON clause exists
    if on_span.is_none() {
        return Err(ParseError::new(
            p.current_span(),
            crate::error::ParseErrorKind::InvalidSyntax {
                message: "MERGE statement requires ON clause to specify join condition".to_string(),
            },
        ));
    }

    // Parse WHEN clauses (at least one recommended but not strictly required by parser)
    loop {
        p.skip_trivia();
        let tok = match p.peek_non_trivia() {
            Some(t) => t,
            None => break,
        };
        if !matches!(tok.kind, TokenKind::Keyword(crate::lexer::Keyword::When)) {
            break;
        }
        let when_tok = p
            .advance()
            .expect_invariant("MERGE: WHEN keyword confirmed by peek");
        let when_span = when_tok.span;
        let clause_start = when_span.start;
        let mut not_span: Option<Span> = None;
        let matched_span: Span;
        let mut by_source_span: Option<(Span, Span)> = None;
        let mut and_condition_span: Option<Span> = None;
        let then_span: Span;
        let mut kind = crate::ast::AstMergeClauseKind::Matched;

        // Parse [NOT] MATCHED
        if let Some(next) = p.peek_non_trivia() {
            if matches!(next.kind, TokenKind::Keyword(crate::lexer::Keyword::Not)) {
                let n = p
                    .advance()
                    .expect_invariant("MERGE: NOT keyword confirmed by peek");
                not_span = Some(n.span);
                kind = crate::ast::AstMergeClauseKind::NotMatched;
            }
        }
        if let Some(next) = p.peek_non_trivia() {
            if next.lexeme(p.source).eq_ignore_ascii_case("MATCHED") {
                let m = p
                    .advance()
                    .expect_invariant("MERGE: MATCHED keyword confirmed by peek");
                matched_span = m.span;

                // Check for "BY SOURCE" or "BY TARGET" after "NOT MATCHED"
                if kind == crate::ast::AstMergeClauseKind::NotMatched {
                    if let Some(by_tok) = p.peek_non_trivia() {
                        if by_tok.lexeme(p.source).eq_ignore_ascii_case("BY") {
                            let by_token =
                                p.advance().expect_invariant("BY token should be available"); // consume BY
                            if let Some(qualifier_tok) = p.peek_non_trivia() {
                                if qualifier_tok
                                    .lexeme(p.source)
                                    .eq_ignore_ascii_case("SOURCE")
                                {
                                    let source_token = p
                                        .advance()
                                        .expect_invariant("SOURCE token should be available"); // consume SOURCE
                                    kind = crate::ast::AstMergeClauseKind::NotMatchedBySource;
                                    by_source_span = Some((by_token.span, source_token.span));
                                } else if qualifier_tok
                                    .lexeme(p.source)
                                    .eq_ignore_ascii_case("TARGET")
                                {
                                    let target_token = p
                                        .advance()
                                        .expect_invariant("TARGET token should be available"); // consume TARGET
                                    kind = crate::ast::AstMergeClauseKind::NotMatchedByTarget;
                                    by_source_span = Some((by_token.span, target_token.span));
                                }
                            }
                        }
                    }
                }
            } else {
                // WHEN must be followed by [NOT] MATCHED
                return Err(ParseError::new(
                    next.span,
                    crate::error::ParseErrorKind::InvalidSyntax {
                        message: "WHEN clause requires MATCHED or NOT MATCHED".to_string(),
                    },
                ));
            }
        } else {
            return Err(ParseError::new(
                p.current_span(),
                crate::error::ParseErrorKind::InvalidSyntax {
                    message: "WHEN clause requires MATCHED or NOT MATCHED".to_string(),
                },
            ));
        }

        // Parse optional AND condition
        let mut and_condition: Option<Box<crate::ast::AstExpr>> = None;
        if let Some(next) = p.peek_non_trivia() {
            if matches!(next.kind, TokenKind::Keyword(crate::lexer::Keyword::And)) {
                let and_tok = p
                    .advance()
                    .expect_invariant("MERGE: AND keyword confirmed by peek");
                let cond_start = and_tok.span.start;
                // Parse the condition expression - parse_expr will stop naturally at THEN
                // because THEN has no binding power in the expression parser
                match p.parse_expr() {
                    Ok(expr) => {
                        let cond_end = expr.span().end;
                        and_condition_span = Some(Span {
                            start: cond_start,
                            end: cond_end,
                        });
                        and_condition = Some(Box::new(expr));
                    }
                    Err(_) => {
                        // Fallback: just consume tokens until THEN (keep original behavior)
                        let mut cond_end = and_tok.span.end;
                        while let Some(t) = p.peek_non_trivia() {
                            if t.lexeme(p.source).eq_ignore_ascii_case("THEN") {
                                break;
                            }
                            let tok = p
                                .advance()
                                .expect_invariant("MERGE: AND condition token confirmed by peek");
                            cond_end = tok.span.end;
                        }
                        and_condition_span = Some(Span {
                            start: cond_start,
                            end: cond_end,
                        });
                    }
                }
            }
        }

        // Parse THEN keyword (mandatory)
        if let Some(next) = p.peek_non_trivia() {
            if next.lexeme(p.source).eq_ignore_ascii_case("THEN") {
                let th = p
                    .advance()
                    .expect_invariant("MERGE: THEN keyword confirmed by peek");
                then_span = th.span;
            } else {
                return Err(ParseError::new(
                    next.span,
                    crate::error::ParseErrorKind::InvalidSyntax {
                        message:
                            "WHEN MATCHED/NOT MATCHED clause requires THEN keyword before action"
                                .to_string(),
                    },
                ));
            }
        } else {
            return Err(ParseError::new(
                p.current_span(),
                crate::error::ParseErrorKind::InvalidSyntax {
                    message: "WHEN MATCHED/NOT MATCHED clause requires THEN keyword before action"
                        .to_string(),
                },
            ));
        }

        // Parse action: UPDATE, DELETE, or INSERT
        let mut action = crate::ast::AstMergeActionKind::Delete {
            delete_span: when_span,
        };
        if let Some(next) = p.peek_non_trivia() {
            match &next.kind {
                TokenKind::Keyword(crate::lexer::Keyword::Update) => {
                    let update_tok = p
                        .advance()
                        .expect_invariant("MERGE: UPDATE keyword confirmed by peek");
                    if let Some(n1) = p.peek_non_trivia() {
                        if n1.lexeme(p.source).eq_ignore_ascii_case("ALL") {
                            let _ = p.advance();
                            if let Some(by_tok) = p.peek_non_trivia() {
                                if by_tok.lexeme(p.source).eq_ignore_ascii_case("BY") {
                                    let _ = p.advance();
                                    if let Some(name_tok) = p.peek_non_trivia() {
                                        if name_tok.lexeme(p.source).eq_ignore_ascii_case("NAME") {
                                            let name = p
                                                .advance()
                                                .expect_invariant("MERGE: NAME keyword in UPDATE ALL BY NAME confirmed by peek");
                                            action =
                                                crate::ast::AstMergeActionKind::UpdateAllByName {
                                                    update_span: update_tok.span,
                                                    all_span: n1.span,
                                                    by_span: by_tok.span,
                                                    name_span: name.span,
                                                };
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if matches!(action, crate::ast::AstMergeActionKind::Delete { .. }) {
                        // Databricks: UPDATE SET *
                        p.skip_trivia();
                        if let Some(set_tok) = p.peek_non_trivia() {
                            if matches!(
                                set_tok.kind,
                                TokenKind::Keyword(crate::lexer::Keyword::Set)
                            ) {
                                let _ = p.advance(); // consume SET
                                p.skip_trivia();
                                if let Some(star_tok) = p.peek_non_trivia() {
                                    if matches!(
                                        star_tok.kind,
                                        TokenKind::Operator(crate::lexer::Operator::Star)
                                    ) {
                                        let star = p.advance().expect_invariant(
                                            "MERGE: star token confirmed by peek",
                                        );
                                        action = crate::ast::AstMergeActionKind::UpdateSetStar {
                                            update_span: Span {
                                                start: update_tok.span.start,
                                                end: star.span.end,
                                            },
                                        };
                                    }
                                }
                            }
                        }
                    }

                    if matches!(action, crate::ast::AstMergeActionKind::Delete { .. }) {
                        // Parse SET assignments naturally (no pre-scanning)
                        let set_start = update_tok.span.start;
                        let assignments = parse_set_assignments_natural(p);

                        // Calculate span from assignments if present
                        let set_end = if let Some(last) = assignments.last() {
                            last.span.end
                        } else {
                            update_tok.span.end
                        };

                        action = crate::ast::AstMergeActionKind::UpdateSet {
                            set_span: Span {
                                start: set_start,
                                end: set_end,
                            },
                            assignments,
                        };
                    }
                }
                TokenKind::Keyword(crate::lexer::Keyword::Delete) => {
                    let del_tok = p
                        .advance()
                        .expect_invariant("MERGE: DELETE keyword confirmed by peek");
                    action = crate::ast::AstMergeActionKind::Delete {
                        delete_span: del_tok.span,
                    };
                }
                TokenKind::Keyword(crate::lexer::Keyword::Insert) => {
                    let insert_tok = p
                        .advance()
                        .expect_invariant("MERGE: INSERT keyword confirmed by peek");
                    let insert_start = insert_tok.span.start;
                    if let Some(n1) = p.peek_non_trivia() {
                        if n1.lexeme(p.source).eq_ignore_ascii_case("ALL") {
                            let _ = p.advance();
                            if let Some(by_tok) = p.peek_non_trivia() {
                                if by_tok.lexeme(p.source).eq_ignore_ascii_case("BY") {
                                    let _ = p.advance();
                                    if let Some(name_tok) = p.peek_non_trivia() {
                                        if name_tok.lexeme(p.source).eq_ignore_ascii_case("NAME") {
                                            let name = p
                                                .advance()
                                                .expect_invariant("MERGE: NAME keyword in INSERT ALL BY NAME confirmed by peek");
                                            action =
                                                crate::ast::AstMergeActionKind::InsertAllByName {
                                                    insert_span: insert_tok.span,
                                                    all_span: n1.span,
                                                    by_span: by_tok.span,
                                                    name_span: name.span,
                                                };
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if matches!(action, crate::ast::AstMergeActionKind::Delete { .. }) {
                        // Databricks: INSERT *
                        p.skip_trivia();
                        if let Some(star_tok) = p.peek_non_trivia() {
                            if matches!(
                                star_tok.kind,
                                TokenKind::Operator(crate::lexer::Operator::Star)
                            ) {
                                let star = p
                                    .advance()
                                    .expect_invariant("MERGE: star token confirmed by peek");
                                action = crate::ast::AstMergeActionKind::InsertStar {
                                    insert_span: Span {
                                        start: insert_start,
                                        end: star.span.end,
                                    },
                                };
                            }
                        }
                    }

                    if matches!(action, crate::ast::AstMergeActionKind::Delete { .. }) {
                        // Parse INSERT columns and values with proper CST tracking

                        // Track TokenIds for syntax layer
                        let insert_token_id = p.last_token_id();
                        let mut columns_lparen_id: Option<crate::cst::TokenId> = None;
                        let mut columns_rparen_id: Option<crate::cst::TokenId> = None;
                        let mut values_keyword_id: Option<crate::cst::TokenId> = None;
                        let mut values_lparen_id: Option<crate::cst::TokenId> = None;
                        let mut values_rparen_id: Option<crate::cst::TokenId> = None;

                        // Parse optional column list: (col1, col2, ...)
                        let mut columns_span: Option<Span> = None;
                        let mut columns: Vec<crate::ast::AstExpr> = Vec::new();

                        p.skip_trivia();
                        if let Some(tok) = p.peek_non_trivia() {
                            if matches!(
                                tok.kind,
                                TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                            ) {
                                columns_lparen_id = Some(p.current_token_id());
                                let lparen =
                                    p.advance().expect_invariant("LParen consumed after match");
                                let list_start = lparen.span.start;
                                let mut list_end = lparen.span.end;

                                // Parse column expressions
                                loop {
                                    p.skip_trivia();
                                    if let Some(t) = p.peek_non_trivia() {
                                        if matches!(
                                            t.kind,
                                            TokenKind::Punctuation(
                                                crate::lexer::Punctuation::RParen
                                            )
                                        ) {
                                            columns_rparen_id = Some(p.current_token_id());
                                            let rparen =
                                                p.advance().expect_invariant("Token available");
                                            list_end = rparen.span.end;
                                            break;
                                        }
                                    }

                                    // Parse column as expression (typically identifier)
                                    if let Ok(col_expr) = p.parse_primary_expr_in_mode() {
                                        columns.push(col_expr);
                                    } else {
                                        // Skip unparseable token
                                        if p.peek().is_some() {
                                            p.advance();
                                        } else {
                                            break;
                                        }
                                    }

                                    // Check for comma (more columns) or rparen (done)
                                    p.skip_trivia();
                                    if let Some(t) = p.peek_non_trivia() {
                                        if matches!(
                                            t.kind,
                                            TokenKind::Punctuation(
                                                crate::lexer::Punctuation::Comma
                                            )
                                        ) {
                                            p.advance();
                                            continue;
                                        }
                                    }
                                }

                                columns_span = Some(Span {
                                    start: list_start,
                                    end: list_end,
                                });
                            }
                        }

                        // Parse VALUES clause with expression parsing
                        let mut values_span_opt: Option<Span> = None;
                        let mut values: Vec<crate::ast::AstExpr> = Vec::new();

                        p.skip_trivia();
                        if let Some(vtok) = p.peek_non_trivia() {
                            if matches!(
                                vtok.kind,
                                TokenKind::Keyword(crate::lexer::Keyword::Values)
                            ) {
                                values_keyword_id = Some(p.current_token_id());
                                let values_kw = p.advance().expect_invariant("Token available");
                                let values_start = values_kw.span.start;
                                let mut values_end = values_kw.span.end;

                                // Parse value row: (val1, val2, ...)
                                p.skip_trivia();
                                if let Some(t) = p.peek_non_trivia() {
                                    if matches!(
                                        t.kind,
                                        TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                                    ) {
                                        values_lparen_id = Some(p.current_token_id());
                                        p.advance(); // consume opening paren

                                        // Parse value expressions
                                        loop {
                                            p.skip_trivia();
                                            if let Some(next) = p.peek_non_trivia() {
                                                if matches!(
                                                    next.kind,
                                                    TokenKind::Punctuation(
                                                        crate::lexer::Punctuation::RParen
                                                    )
                                                ) {
                                                    values_rparen_id = Some(p.current_token_id());
                                                    let rparen = p
                                                        .advance()
                                                        .expect_invariant("Token available");
                                                    values_end = rparen.span.end;
                                                    break;
                                                }
                                            }

                                            // Parse value expression
                                            if let Ok(val_expr) = p.parse_expr() {
                                                values.push(val_expr);
                                            } else {
                                                // Skip unparseable token
                                                if p.peek().is_some() {
                                                    p.advance();
                                                } else {
                                                    break;
                                                }
                                            }

                                            // Check for comma (more values) or rparen (done)
                                            p.skip_trivia();
                                            if let Some(next) = p.peek_non_trivia() {
                                                if matches!(
                                                    next.kind,
                                                    TokenKind::Punctuation(
                                                        crate::lexer::Punctuation::Comma
                                                    )
                                                ) {
                                                    p.advance();
                                                    continue;
                                                }
                                            }
                                        }

                                        values_span_opt = Some(Span {
                                            start: values_start,
                                            end: values_end,
                                        });
                                    }
                                }
                            }
                        }

                        if let Some(values_span) = values_span_opt {
                            // Allocate syntax entry if we have all required tokens
                            let syntax_id = if let (Some(vkw), Some(vlp), Some(vrp)) =
                                (values_keyword_id, values_lparen_id, values_rparen_id)
                            {
                                Some(p.syntax_arena.alloc_merge_insert_values(
                                    crate::syntax::SyntaxMergeInsertValues {
                                        insert_keyword: insert_token_id,
                                        columns_lparen: columns_lparen_id,
                                        columns_rparen: columns_rparen_id,
                                        values_keyword: vkw,
                                        values_lparen: vlp,
                                        values_rparen: vrp,
                                        span: Span {
                                            start: insert_start,
                                            end: values_span.end,
                                        },
                                    },
                                ))
                            } else {
                                None
                            };

                            action = crate::ast::AstMergeActionKind::InsertValues {
                                insert_span: Span {
                                    start: insert_start,
                                    end: values_span.end,
                                },
                                columns_span,
                                columns,
                                values_span,
                                values,
                                syntax_id,
                            };
                        }
                    }
                }
                _ => {
                    return Err(ParseError::new(
                        next.span,
                        crate::error::ParseErrorKind::InvalidSyntax {
                            message: "MERGE action must be UPDATE, DELETE, or INSERT".to_string(),
                        },
                    ));
                }
            }
        } else {
            return Err(ParseError::new(
                p.current_span(),
                crate::error::ParseErrorKind::InvalidSyntax {
                    message: "THEN keyword requires an action (UPDATE, DELETE, or INSERT)"
                        .to_string(),
                },
            ));
        }

        let clause_end = match p.tokens.get(p.idx.saturating_sub(1)) {
            Some(last) => last.span.end,
            None => when_span.end,
        };
        span.end = clause_end;
        let clause = crate::ast::AstMergeClause {
            node_id: p.id_gen.next(),
            kind,
            when_span,
            not_span,
            matched_span,
            by_source_span,
            and_condition_span,
            and_condition,
            then_span,
            action,
            span: Span {
                start: clause_start,
                end: clause_end,
            },
        };
        clauses.push(clause);
    }

    // MSSQL: optional OUTPUT clause after WHEN clauses
    let output = p.try_parse_output_clause(&[])?;
    if let Some(ref out) = output {
        span.end = out.span.end;
    }

    let mut stmt = crate::parser::sql_stmt::build_merge(
        p.id_gen.next(),
        span,
        keyword_span,
        with_schema_evolution_span,
        target_table_span,
        using_span,
        using_subquery,
        using_table_ref,
        using_alias_span,
        on_span,
        on_condition,
        clauses,
    );
    stmt.using_keyword_span = using_keyword_span;
    stmt.into_span = into_span;
    stmt.output = output;
    Ok(AstStmt::Merge(Box::new(stmt)))
}

/// Build a new `AstSetSelect` node given the current left-hand
/// statement, operator kind, ALL flag, and right-hand SELECT.
///
/// This is a pure helper with no dependency on `Parser` internals.
pub fn build_set_select(
    node_id: crate::ast::NodeId,
    left_stmt: AstStmt,
    op_kind: AstSetOpKind,
    modifier: crate::ast::AstSetModifier,
    set_op_syntax_id: Option<crate::syntax::SyntaxSetOperatorId>,
    right_select: AstSelect,
) -> AstSetSelect {
    let right_stmt = AstStmt::Select(Box::new(right_select));
    AstSetSelect {
        node_id,
        left: Box::new(left_stmt),
        op: op_kind,
        modifier,
        right: Box::new(right_stmt),
        set_op_syntax_id,
        semicolon_token: None,
        paren_syntax_id: None,
        order_by: None,
        limit: None,
        offset: None,
        limit_keyword_span: None,
        fetch_clause_span: None,
        offset_keyword_span: None,
        limit_offset_comma_span: None,
    }
}

pub fn build_set_quantifier_all() -> crate::ast::AstSetQuantifier {
    crate::ast::AstSetQuantifier::All
}

pub fn build_set_quantifier_distinct() -> crate::ast::AstSetQuantifier {
    crate::ast::AstSetQuantifier::Distinct
}

pub fn build_select_item(
    node_id: crate::ast::NodeId,
    expr: crate::ast::AstExpr,
    alias: Option<crate::ast::AstIdentifierWithAs>,
    span: crate::lexer::Span,
) -> crate::ast::AstSelectItem {
    crate::ast::AstSelectItem {
        node_id,
        expr,
        alias,
        // The T-SQL projection-assignment peek-ahead is the sole
        // populator; default constructors leave this None.
        assign_target: None,
        span,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn build_insert(
    node_id: crate::ast::NodeId,
    span: crate::lexer::Span,
    keyword_span: crate::lexer::Span,
    overwrite_span: Option<crate::lexer::Span>,
    target_table_span: Option<crate::lexer::Span>,
    columns_span: Option<crate::lexer::Span>,
    body_span: Option<crate::lexer::Span>,
    source_kind: crate::ast::AstInsertSourceKind,
    values_span: Option<crate::lexer::Span>,
    values_rows_spans: Vec<crate::lexer::Span>,
    values_rows: Vec<Vec<crate::ast::AstExpr>>,
    query_span: Option<crate::lexer::Span>,
    query: Option<Box<crate::ast::AstStmt>>,
) -> crate::ast::AstInsert {
    crate::ast::AstInsert {
        node_id,
        span,
        keyword_span,
        into_span: None,
        overwrite_span,
        replace_span: None,
        target_table_span,
        columns_span,
        body_span,
        source_kind,
        values_span,
        values_keyword_span: None,
        semicolon_token: None,
        values_rows_spans,
        values_rows,
        query_span,
        query,
        // PostgreSQL extensions
        output: None,
        returning: None,
        on_conflict: None,
        with_clause: None,
        // Snowflake extensions
        overwrite: overwrite_span.is_some(),
        // PostgreSQL extensions
        overriding_value_span: None,
        default_values_span: None,
        // MSSQL extensions
        table_hints: None,
        // MySQL extensions
        priority: None,
        ignore_span: None,
        values_row_constructor: false,
        partition_span: None,
        row_alias_span: None,
        set_clause_span: None,
        set_assignments: Vec::new(),
        on_duplicate_key_update: None,
    }
}

pub fn build_delete(
    node_id: crate::ast::NodeId,
    span: crate::lexer::Span,
    keyword_span: crate::lexer::Span,
    body_span: Option<crate::lexer::Span>,
    target_table: Option<crate::ast::AstTableRef>,
    using: Vec<crate::ast::AstTableRef>,
    where_clause: Option<crate::ast::AstExpr>,
) -> crate::ast::AstDelete {
    crate::ast::AstDelete {
        node_id,
        span,
        keyword_span,
        body_span,
        top: None,
        from_keyword_span: None,
        target_table: target_table.map(Box::new),
        targets: Vec::new(),
        using: using.into_iter().map(Box::new).collect(),
        using_keyword_span: None,
        where_clause: where_clause.map(Box::new),
        where_keyword_span: None,
        low_priority_span: None,
        quick_span: None,
        ignore_span: None,
        order_by: None,
        limit: None,
        limit_keyword_span: None,
        output: None,
        returning: None,
        with_clause: None,
        semicolon_token: None,
    }
}

pub fn build_update(
    node_id: crate::ast::NodeId,
    span: crate::lexer::Span,
    keyword_span: crate::lexer::Span,
    body_span: Option<crate::lexer::Span>,
    target_table: Option<crate::ast::AstTableRef>,
    set_span: Option<crate::lexer::Span>,
    set_assignments: Vec<crate::ast::AstSetAssignment>,
    from: Vec<crate::ast::AstTableRef>,
    where_clause: Option<crate::ast::AstExpr>,
) -> crate::ast::AstUpdate {
    crate::ast::AstUpdate {
        node_id,
        span,
        keyword_span,
        body_span,
        top: None,
        target_table: target_table.map(Box::new),
        set_span,
        set_keyword_span: None,
        set_assignments,
        from: from.into_iter().map(Box::new).collect(),
        from_keyword_span: None,
        where_clause: where_clause.map(Box::new),
        where_keyword_span: None,
        low_priority_span: None,
        ignore_span: None,
        additional_targets: Vec::new(),
        order_by: None,
        limit: None,
        limit_keyword_span: None,
        output: None,
        returning: None,
        with_clause: None,
        semicolon_token: None,
    }
}

pub fn build_truncate(
    node_id: crate::ast::NodeId,
    span: crate::lexer::Span,
    keyword_span: crate::lexer::Span,
    table_span: Option<crate::lexer::Span>,
    if_exists_span: Option<crate::lexer::Span>,
    target_table_span: Option<crate::lexer::Span>,
) -> crate::ast::AstTruncate {
    crate::ast::AstTruncate {
        node_id,
        span,
        keyword_span,
        table_span,
        if_exists_span,
        target_table_span,
    }
}

pub fn build_merge(
    node_id: crate::ast::NodeId,
    span: crate::lexer::Span,
    keyword_span: crate::lexer::Span,
    with_schema_evolution_span: Option<crate::lexer::Span>,
    target_table_span: Option<crate::lexer::Span>,
    using_span: Option<crate::lexer::Span>,
    using_subquery: Option<Box<crate::ast::AstStmt>>,
    using_table_ref: Option<Box<crate::ast::AstTableRef>>,
    using_alias_span: Option<crate::lexer::Span>,
    on_span: Option<crate::lexer::Span>,
    on_condition: Option<Box<crate::ast::AstExpr>>,
    clauses: Vec<crate::ast::AstMergeClause>,
) -> crate::ast::AstMerge {
    crate::ast::AstMerge {
        node_id,
        span,
        keyword_span,
        with_clause: None,
        with_schema_evolution_span,
        into_span: None,
        target_table_span,
        using_span,
        using_keyword_span: None,
        using_table_ref,
        using_subquery,
        using_alias_span,
        on_span,
        on_condition,
        clauses,
        output: None,
        semicolon_token: None,
    }
}

/// Build a [`ShowName`] from a contiguous token range (the qualified
/// name as written), or `None` if the range is empty.
fn show_name_from(toks: &[Token], source: &str) -> Option<ShowName> {
    let first = toks.first()?;
    let last = toks.last()?;
    let span = Span {
        start: first.span.start,
        end: last.span.end,
    };
    let text = source
        .get(span.start as usize..span.end as usize)
        .map(str::to_string)
        .unwrap_or_default();
    Some(ShowName { text, span })
}

/// Classify the `IN <scope>` token range (scope-kind keyword followed
/// by an optional qualified name). `None` when no IN clause was present.
fn classify_show_scope(scope: &[Token], source: &str) -> Option<ShowScope> {
    let kind_tok = scope.first()?;
    let kind = kind_tok.lexeme(source);
    let name = show_name_from(&scope[1..], source);
    let typed = if kind.eq_ignore_ascii_case("ACCOUNT") {
        ShowScope::Account
    } else if kind.eq_ignore_ascii_case("DATABASE") {
        ShowScope::Database(name)
    } else if kind.eq_ignore_ascii_case("SCHEMA") {
        ShowScope::Schema(name)
    } else if kind.eq_ignore_ascii_case("TABLE") {
        match name {
            Some(n) => ShowScope::Table(n),
            None => ShowScope::Other {
                kind: "TABLE".to_string(),
                name: None,
            },
        }
    } else if kind.eq_ignore_ascii_case("VIEW") {
        match name {
            Some(n) => ShowScope::View(n),
            None => ShowScope::Other {
                kind: "VIEW".to_string(),
                name: None,
            },
        }
    } else {
        ShowScope::Other {
            kind: kind.to_ascii_uppercase(),
            name,
        }
    };
    Some(typed)
}

/// Classify a non-grants object phrase (class nouns only) into a typed
/// [`AstShowKind`]. The long tail folds into `Other(upper_phrase)`.
fn classify_show_object_class(phrase: &[Token], source: &str) -> AstShowKind {
    let joined = phrase
        .iter()
        .map(|t| t.lexeme(source))
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_uppercase();
    let s = joined.as_str();

    if s.ends_with("POLICIES") || s.ends_with("POLICY") {
        let prefix = s
            .trim_end_matches("POLICIES")
            .trim_end_matches("POLICY")
            .trim();
        let kind = match prefix {
            "MASKING" => ShowPolicyKind::Masking,
            "ROW ACCESS" => ShowPolicyKind::RowAccess,
            "SESSION" => ShowPolicyKind::Session,
            "PASSWORD" => ShowPolicyKind::Password,
            "NETWORK" => ShowPolicyKind::Network,
            "AUTHENTICATION" => ShowPolicyKind::Authentication,
            "PROJECTION" => ShowPolicyKind::Projection,
            "AGGREGATION" => ShowPolicyKind::Aggregation,
            "JOIN" => ShowPolicyKind::Join,
            _ => ShowPolicyKind::Unspecified,
        };
        return AstShowKind::Policies(kind);
    }
    if s.ends_with("INTEGRATIONS") || s == "INTEGRATION" {
        return AstShowKind::Integrations;
    }

    match s {
        "OBJECTS" => AstShowKind::Objects,
        "TABLES" | "TABLE" => AstShowKind::Tables,
        "EXTERNAL TABLES" => AstShowKind::ExternalTables,
        "DYNAMIC TABLES" => AstShowKind::DynamicTables,
        "ICEBERG TABLES" => AstShowKind::IcebergTables,
        "EVENT TABLES" => AstShowKind::EventTables,
        "VIEWS" | "VIEW" => AstShowKind::Views,
        "MATERIALIZED VIEWS" => AstShowKind::MaterializedViews,
        "COLUMNS" | "COLUMN" => AstShowKind::Columns,
        "DATABASES" | "DATABASE" => AstShowKind::Databases,
        "SCHEMAS" | "SCHEMA" => AstShowKind::Schemas,
        "SEQUENCES" => AstShowKind::Sequences,
        "STAGES" => AstShowKind::Stages,
        "PIPES" => AstShowKind::Pipes,
        "STREAMS" => AstShowKind::Streams,
        "TASKS" => AstShowKind::Tasks,
        "FUNCTIONS" | "USER FUNCTIONS" | "EXTERNAL FUNCTIONS" => AstShowKind::Functions,
        "PROCEDURES" => AstShowKind::Procedures,
        "WAREHOUSES" => AstShowKind::Warehouses,
        "USERS" => AstShowKind::Users,
        "ROLES" => AstShowKind::Roles,
        "PARAMETERS" => AstShowKind::Parameters,
        "FILE FORMATS" => AstShowKind::FileFormats,
        "TAGS" => AstShowKind::Tags,
        "PRIMARY KEYS" => AstShowKind::PrimaryKeys,
        _ => AstShowKind::Other(joined),
    }
}

/// Parse the principal side of `SHOW GRANTS TO/OF …`.
fn classify_show_principal(toks: &[Token], source: &str) -> ShowPrincipal {
    let (kind, name_start) = match toks.first().map(|t| t.lexeme(source)) {
        Some(l) if l.eq_ignore_ascii_case("ROLE") => (ShowPrincipalKind::Role, 1),
        Some(l) if l.eq_ignore_ascii_case("USER") => (ShowPrincipalKind::User, 1),
        Some(l) if l.eq_ignore_ascii_case("SHARE") => (ShowPrincipalKind::Share, 1),
        Some(l) if l.eq_ignore_ascii_case("DATABASE") => {
            if toks
                .get(1)
                .is_some_and(|t| t.lexeme(source).eq_ignore_ascii_case("ROLE"))
            {
                (ShowPrincipalKind::DatabaseRole, 2)
            } else {
                (ShowPrincipalKind::Other("DATABASE".to_string()), 1)
            }
        }
        Some(l) if l.eq_ignore_ascii_case("APPLICATION") => {
            if toks
                .get(1)
                .is_some_and(|t| t.lexeme(source).eq_ignore_ascii_case("ROLE"))
            {
                (ShowPrincipalKind::ApplicationRole, 2)
            } else {
                (ShowPrincipalKind::Application, 1)
            }
        }
        Some(l) => (ShowPrincipalKind::Other(l.to_ascii_uppercase()), 1),
        None => (ShowPrincipalKind::Other(String::new()), 0),
    };
    let name = show_name_from(toks.get(name_start..).unwrap_or(&[]), source).unwrap_or(ShowName {
        text: String::new(),
        span: toks
            .first()
            .map(|t| t.span)
            .unwrap_or(Span { start: 0, end: 0 }),
    });
    ShowPrincipal { kind, name }
}

/// Parse the object side of `SHOW GRANTS ON …`.
fn classify_show_grants_object(toks: &[Token], source: &str) -> ShowGrantsObject {
    match toks.first().map(|t| t.lexeme(source)) {
        Some(l) if l.eq_ignore_ascii_case("ACCOUNT") => ShowGrantsObject::Account,
        Some(l) => {
            let object_class = l.to_ascii_uppercase();
            let name = show_name_from(&toks[1..], source).unwrap_or(ShowName {
                text: String::new(),
                span: toks[0].span,
            });
            ShowGrantsObject::Named { object_class, name }
        }
        None => ShowGrantsObject::Account,
    }
}

/// Parse the grant relation following `[FUTURE] GRANTS`. `scope`
/// carries the typed `IN <container>` (for `FUTURE GRANTS IN SCHEMA …`).
fn classify_show_grants_relation(
    clause: &[Token],
    scope: Option<ShowScope>,
    source: &str,
) -> ShowGrantsRelation {
    match clause.first().map(|t| t.lexeme(source)) {
        None => match scope {
            Some(s) => ShowGrantsRelation::In(s),
            None => ShowGrantsRelation::CurrentUser,
        },
        Some(l) if l.eq_ignore_ascii_case("ON") => {
            ShowGrantsRelation::On(classify_show_grants_object(&clause[1..], source))
        }
        Some(l) if l.eq_ignore_ascii_case("TO") => {
            ShowGrantsRelation::To(classify_show_principal(&clause[1..], source))
        }
        Some(l) if l.eq_ignore_ascii_case("OF") => {
            ShowGrantsRelation::Of(classify_show_principal(&clause[1..], source))
        }
        _ => ShowGrantsRelation::CurrentUser,
    }
}

/// Classify a SHOW statement's object-phrase + IN-scope token ranges
/// into typed recognition. Token-only — no source re-parse downstream.
fn classify_show(
    phrase: &[Token],
    scope: &[Token],
    source: &str,
) -> (AstShowKind, Option<ShowScope>) {
    let scope_typed = classify_show_scope(scope, source);

    let (future, rest_start) = match phrase.first().map(|t| t.lexeme(source)) {
        Some(l) if l.eq_ignore_ascii_case("FUTURE") => {
            if phrase
                .get(1)
                .is_some_and(|t| t.lexeme(source).eq_ignore_ascii_case("GRANTS"))
            {
                (true, 2)
            } else {
                return (classify_show_object_class(phrase, source), scope_typed);
            }
        }
        Some(l) if l.eq_ignore_ascii_case("GRANTS") => (false, 1),
        _ => return (classify_show_object_class(phrase, source), scope_typed),
    };

    let clause = phrase.get(rest_start..).unwrap_or(&[]);
    let relation = classify_show_grants_relation(clause, scope_typed, source);
    (
        AstShowKind::Grants(ShowGrantsSpec { future, relation }),
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn build_show(
    node_id: crate::ast::NodeId,
    span: crate::lexer::Span,
    keyword_span: crate::lexer::Span,
    terse_span: Option<crate::lexer::Span>,
    history_span: Option<crate::lexer::Span>,
    object_span: Option<crate::lexer::Span>,
    like_pattern_span: Option<crate::lexer::Span>,
    in_span: Option<crate::lexer::Span>,
    in_scope_span: Option<crate::lexer::Span>,
    starts_with_span: Option<crate::lexer::Span>,
    limit_span: Option<crate::lexer::Span>,
    limit_from_span: Option<crate::lexer::Span>,
    kind: crate::ast::AstShowKind,
    scope: Option<crate::ast::ShowScope>,
) -> crate::ast::AstShow {
    crate::ast::AstShow {
        node_id,
        span,
        kind,
        scope,
        keyword_span,
        terse_span,
        history_span,
        object_span,
        like_pattern_span,
        in_span,
        in_scope_span,
        starts_with_span,
        limit_span,
        limit_from_span,
    }
}

pub fn build_select_span(
    select_span: crate::lexer::Span,
    last_span_end: u32,
) -> crate::lexer::Span {
    crate::lexer::Span {
        start: select_span.start,
        end: last_span_end,
    }
}

pub fn build_copy_into_span(
    keyword_span: crate::lexer::Span,
    last_span_end: u32,
) -> crate::lexer::Span {
    crate::lexer::Span {
        start: keyword_span.start,
        end: last_span_end,
    }
}

pub fn build_into_var_span(
    colon_span: crate::lexer::Span,
    ident_span: crate::lexer::Span,
) -> crate::lexer::Span {
    crate::lexer::Span {
        start: colon_span.start,
        end: ident_span.end,
    }
}

pub fn build_top(
    node_id: crate::ast::NodeId,
    span: crate::lexer::Span,
    top_span: crate::lexer::Span,
    expr: crate::ast::AstExpr,
    percent_span: Option<crate::lexer::Span>,
    with_ties_span: Option<crate::lexer::Span>,
) -> crate::ast::AstTop {
    crate::ast::AstTop {
        node_id,
        span,
        top_span,
        expr,
        percent_span,
        with_ties_span,
    }
}

/// Map a token kind to a set-operator kind, if applicable.
///
/// This keeps the UNION/INTERSECT/EXCEPT/MINUS keyword mapping with the
/// other SQL statement helpers, but is completely pure and does not
/// depend on `Parser` internals.
pub fn is_set_op_keyword(kind: &crate::lexer::TokenKind) -> Option<AstSetOpKind> {
    match kind {
        TokenKind::Keyword(Keyword::Union) => Some(AstSetOpKind::Union),
        TokenKind::Keyword(Keyword::Intersect) => Some(AstSetOpKind::Intersect),
        TokenKind::Keyword(Keyword::Except) => Some(AstSetOpKind::Except),
        TokenKind::Keyword(Keyword::Minus) => Some(AstSetOpKind::Minus),
        _ => None,
    }
}

pub fn finalize_set_or_select(left_stmt: AstStmt, last_set: Option<AstSetSelect>) -> AstStmt {
    match last_set {
        Some(set) => AstStmt::SetSelect(set),
        None => left_stmt,
    }
}

pub fn parse_set_all_flag(kind: &crate::lexer::TokenKind) -> bool {
    matches!(kind, TokenKind::Keyword(Keyword::All))
}

/// Calculate the complete span for a table reference including all optional clauses
pub fn calculate_table_ref_span(
    name_span: crate::lexer::Span,
    alias: &Option<crate::ast::AstIdentifier>,
    alias_columns: &Option<Vec<crate::ast::AstIdentifier>>,
    time_travel: &Option<Box<crate::ast::AstTimeTravelClause>>,
    sample: &Option<Box<crate::ast::AstSampleClause>>,
    changes: &Option<Box<crate::ast::AstChangesClause>>,
    pivot: &Option<Box<crate::ast::AstPivotClause>>,
    unpivot: &Option<Box<crate::ast::AstUnpivotClause>>,
    match_recognize: &Option<Box<crate::ast::AstMatchRecognize>>,
    table_hints: &Option<Box<crate::ast::AstTableHintClause>>,
) -> crate::lexer::Span {
    let mut end = name_span.end;

    // Extend to time travel clause
    if let Some(tt) = time_travel {
        let tt_end = match tt.as_ref() {
            crate::ast::AstTimeTravelClause::SnowflakeAtBefore(at) => at.span.end,
            crate::ast::AstTimeTravelClause::ForSystemTime(fst) => fst.span.end,
            crate::ast::AstTimeTravelClause::DatabricksAsOf(dbx) => dbx.span.end,
        };
        if tt_end > end {
            end = tt_end;
        }
    }

    // Extend to sample clause
    if let Some(s) = sample {
        if s.span.end > end {
            end = s.span.end;
        }
    }

    // Extend to changes clause
    if let Some(c) = changes {
        if c.span.end > end {
            end = c.span.end;
        }
    }

    // Extend to pivot clause
    if let Some(p) = pivot {
        if p.span.end > end {
            end = p.span.end;
        }
    }

    // Extend to unpivot clause
    if let Some(u) = unpivot {
        if u.span.end > end {
            end = u.span.end;
        }
    }

    // Extend to match_recognize clause
    if let Some(mr) = match_recognize {
        if mr.span.end > end {
            end = mr.span.end;
        }
    }

    // Extend to table hints (T-SQL WITH (NOLOCK) etc.)
    if let Some(hints) = table_hints {
        if hints.span.end > end {
            end = hints.span.end;
        }
    }

    // Extend to alias columns (rightmost element)
    if let Some(cols) = alias_columns {
        if let Some(last_col) = cols.last() {
            if last_col.span.end > end {
                end = last_col.span.end;
            }
        }
    }

    // Extend to alias (but only if no alias_columns, since alias_columns comes after alias)
    if alias_columns.is_none() {
        if let Some(a) = alias {
            if a.span.end > end {
                end = a.span.end;
            }
        }
    }

    crate::lexer::Span {
        start: name_span.start,
        end,
    }
}

pub fn build_table_ref(
    node_id: crate::ast::NodeId,
    span: crate::lexer::Span,
    name: crate::ast::AstObjectRef,
    alias: Option<crate::ast::AstIdentifier>,
    alias_columns: Option<Vec<crate::ast::AstIdentifier>>,
    result_alias: Option<crate::ast::AstIdentifier>,
    result_alias_columns: Option<Vec<crate::ast::AstIdentifier>>,
    subquery: Option<Box<AstStmt>>,
    subquery_lparen_span: Option<crate::lexer::Span>,
    subquery_rparen_span: Option<crate::lexer::Span>,
    values: Option<Box<crate::ast::AstValues>>,
    lateral_keyword_span: Option<crate::lexer::Span>,
    time_travel: Option<Box<crate::ast::AstTimeTravelClause>>,
    sample: Option<Box<crate::ast::AstSampleClause>>,
    changes: Option<Box<crate::ast::AstChangesClause>>,
    stage_options: Option<crate::ast::AstStageOptions>,
    table_function: Option<Box<crate::ast::AstExpr>>,
    with_offset: Option<Box<crate::ast::AstWithOffset>>,
    pivot: Option<Box<crate::ast::AstPivotClause>>,
    unpivot: Option<Box<crate::ast::AstUnpivotClause>>,
    match_recognize: Option<Box<crate::ast::AstMatchRecognize>>,
    table_hints: Option<Box<crate::ast::AstTableHintClause>>,
    syntax_id: Option<crate::syntax::SyntaxTableRefId>,
) -> crate::ast::AstTableRef {
    crate::ast::AstTableRef {
        node_id,
        span,
        name: Box::new(name),
        prefix_inline_fragments: Box::new(Vec::new()),
        alias: alias.map(Box::new),
        alias_columns: alias_columns.map(Box::new),
        result_alias: result_alias.map(Box::new),
        result_alias_columns: result_alias_columns.map(Box::new),
        subquery,
        subquery_lparen_span,
        subquery_rparen_span,
        paren_group: None,
        values,
        lateral_keyword_span,
        only_span: None,
        time_travel,
        sample,
        changes,
        stage_options: stage_options.map(Box::new),
        table_function,
        tvf_schema_span: None,
        with_offset,
        pivot,
        unpivot,
        match_recognize,
        table_hints,
        // Threaded post-build by the base-table parse path (the only
        // place MySQL index hints are grammatical).
        index_hints: None,
        partition_selection: None,
        syntax_id,
        suffix_inline_fragments: Box::new(Vec::new()),
        joins: Box::new(Vec::new()),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn build_select(
    node_id: crate::ast::NodeId,
    span: crate::lexer::Span,
    select_span: crate::lexer::Span,
    select_as_qualifier: Option<crate::lexer::Span>,
    set_quantifier: Option<Box<crate::ast::AstSetQuantifier>>,
    set_quantifier_span: Option<crate::lexer::Span>,
    top: Option<Box<crate::ast::AstTop>>,
    projection: crate::ast::AstProjection,
    from: Vec<crate::ast::FromItem>,
    statement_fragments: Vec<crate::ast::JinjaStatementFragment>,
    where_clause: Option<Box<crate::ast::ConditionClause>>,
    group_by: Option<crate::ast::AstGroupBy>,
    having: Option<Box<crate::ast::ConditionClause>>,
    connect_by: Option<Box<crate::ast::AstConnectBy>>,
    order_by: Option<crate::ast::AstOrderBy>,
    qualify: Option<Box<crate::ast::ConditionClause>>,
    into_target: Option<Box<crate::ast::AstSelectIntoTarget>>,
    limit: Option<Box<crate::ast::AstExpr>>,
    offset: Option<Box<crate::ast::AstExpr>>,
    limit_keyword_span: Option<crate::lexer::Span>,
    fetch_clause_span: Option<crate::lexer::Span>,
    offset_keyword_span: Option<crate::lexer::Span>,
    for_update: Option<Box<Vec<crate::ast::AstForUpdate>>>,
    semicolon_token: Option<crate::cst::TokenId>,
    window_clause: Option<Box<crate::ast::AstWindowClause>>,
) -> AstSelect {
    AstSelect {
        node_id,
        span,
        select_span,
        select_as_qualifier,
        set_quantifier,
        set_quantifier_span,
        top,
        projection: Box::new(projection),
        from,
        statement_fragments,
        where_clause,
        group_by: group_by.map(Box::new),
        connect_by,
        order_by: order_by.map(Box::new),
        pre_limit_extension_clauses: Box::new(Vec::new()),
        having,
        qualify,
        limit,
        offset,
        limit_keyword_span,
        fetch_clause_span,
        offset_keyword_span,
        // Threaded post-build by the main SELECT parse path (the only
        // caller that parses LIMIT); early-return builders have no LIMIT.
        limit_offset_comma_span: None,
        for_update,
        for_json_xml: None,
        post_locking_extension_clauses: Box::new(Vec::new()),
        window_clause,
        with_clause: None,
        into_target,
        semicolon_token,
        paren_syntax_id: None,
        // Threaded post-build by the MySQL TABLE-statement parser; the
        // standard SELECT path always leaves this None.
        table_syntax_span: None,
    }
}

/// Parse an INSERT statement with Result-based error handling and specified expression mode.
/// This is a wrapper that calls the parser method.
pub(crate) fn try_parse_insert_stmt_with_parser(
    p: &mut Parser<'_>,
) -> crate::error::ParseResult<AstStmt> {
    p.try_parse_insert_stmt_in_mode()
}

// =============================================================================
// Parser methods - statement parsing
// =============================================================================

impl Parser<'_> {
    // NOTE: The actual implementations of these methods will replace the standalone
    // functions above. All `p` parameter references will be converted to `self`.
    // This is a work in progress - the standalone functions above will be removed
    // once all methods are properly implemented and tested.

    pub(crate) fn try_parse_truncate_stmt_with_parser(
        &mut self,
    ) -> crate::error::ParseResult<AstStmt> {
        try_parse_truncate_stmt_with_parser(self)
    }

    pub(crate) fn try_parse_drop_stmt_with_parser(&mut self) -> crate::error::ParseResult<AstStmt> {
        try_parse_drop_stmt_with_parser(self)
    }

    pub(crate) fn try_parse_show_stmt_with_parser(&mut self) -> crate::error::ParseResult<AstStmt> {
        try_parse_show_stmt_with_parser(self)
    }

    pub(crate) fn try_parse_describe_stmt_with_parser(
        &mut self,
    ) -> crate::error::ParseResult<AstStmt> {
        try_parse_describe_stmt_with_parser(self)
    }

    pub(crate) fn try_parse_use_stmt_with_parser(&mut self) -> crate::error::ParseResult<AstStmt> {
        try_parse_use_stmt_with_parser(self)
    }

    pub(crate) fn try_parse_update_stmt_with_parser(
        &mut self,
    ) -> crate::error::ParseResult<AstStmt> {
        try_parse_update_stmt_with_parser(self)
    }

    pub(crate) fn try_parse_delete_stmt_with_parser(
        &mut self,
    ) -> crate::error::ParseResult<AstStmt> {
        try_parse_delete_stmt_with_parser(self)
    }

    pub(crate) fn try_parse_merge_stmt_with_parser(
        &mut self,
    ) -> crate::error::ParseResult<AstStmt> {
        try_parse_merge_stmt_with_parser(self)
    }

    pub(crate) fn try_parse_set_or_select_stmt(&mut self) -> crate::error::ParseResult<AstStmt> {
        try_parse_set_or_select_stmt(self)
    }

    /// Parse a standalone VALUES query: VALUES (...), (...) [ORDER BY ...] [LIMIT ...] [OFFSET ...]
    /// Then check for set operations (UNION/INTERSECT/EXCEPT).
    pub(crate) fn try_parse_values_query_stmt(&mut self) -> crate::error::ParseResult<AstStmt> {
        try_parse_values_query_stmt(self)
    }

    pub(crate) fn try_parse_copy_into_stmt_with_parser(
        &mut self,
    ) -> crate::error::ParseResult<AstStmt> {
        try_parse_copy_into_stmt_with_parser(self)
    }
}

/// Parse a standalone VALUES query, potentially followed by set operations (UNION/INTERSECT/EXCEPT).
///
/// Grammar: VALUES (expr, ...) [, (expr, ...)] [ORDER BY ...] [LIMIT ...] [OFFSET ...]
///          [UNION [ALL] (SELECT ... | VALUES ...)]
fn try_parse_values_query_stmt(p: &mut Parser<'_>) -> crate::error::ParseResult<AstStmt> {
    use crate::error::{ExpectInvariant, ParseError};

    // Parse VALUES rows using existing parse_values()
    let values = p.parse_values().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            crate::error::ParseErrorKind::InvalidStatement {
                message: "Expected VALUES clause with at least one row".to_string(),
            },
        )
    })?;

    // Parse optional ORDER BY
    let order_by = if let Some(tok) = p.peek() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Order)) {
            p.parse_select_order_by()?
        } else {
            None
        }
    } else {
        None
    };

    // Parse optional LIMIT / OFFSET / FETCH
    let limit_offset = p.parse_select_limit_offset()?;

    // Calculate span
    let mut span_end = values.span.end;
    if let Some(ref ob) = order_by {
        span_end = ob.span.end;
    }
    if let Some(ref off) = limit_offset.offset_expr {
        span_end = off.span().end;
    }
    if let Some(ref off_kw) = limit_offset.offset_keyword_span {
        span_end = span_end.max(off_kw.end);
    }
    if let Some(ref lim) = limit_offset.limit_expr {
        span_end = span_end.max(lim.span().end);
    }
    if let Some(ref fetch) = limit_offset.fetch_clause_span {
        span_end = span_end.max(fetch.end);
    }

    let vq = crate::ast::AstValuesQuery {
        node_id: p.id_gen.next(),
        span: Span {
            start: values.span.start,
            end: span_end,
        },
        values,
        order_by: order_by.map(Box::new),
        limit: limit_offset.limit_expr.map(Box::new),
        offset: limit_offset.offset_expr.map(Box::new),
        limit_keyword_span: limit_offset.limit_keyword_span,
        fetch_clause_span: limit_offset.fetch_clause_span,
        offset_keyword_span: limit_offset.offset_keyword_span,
        paren_syntax_id: None,
    };

    let mut left_stmt = AstStmt::ValuesQuery(Box::new(vq));

    // Check for set operations (UNION/INTERSECT/EXCEPT) after VALUES
    while let Some(op_tok) = p.peek() {
        let op_kind = match is_set_op_keyword(&op_tok.kind) {
            Some(k) => k,
            None => break,
        };
        let op_keyword_tok = p
            .advance()
            .expect_invariant("set operator keyword confirmed by peek");
        let op_keyword_token_id = p.last_token_id();
        let mut op_span = op_keyword_tok.span;

        // Optional ALL or DISTINCT
        let mut modifier = crate::ast::AstSetModifier::None;
        let mut modifier_token_id: Option<crate::cst::TokenId> = None;
        if let Some(next) = p.peek() {
            if parse_set_all_flag(&next.kind) {
                let mod_tok = p
                    .advance()
                    .expect_invariant("ALL keyword confirmed by peek");
                modifier = crate::ast::AstSetModifier::All;
                modifier_token_id = Some(p.last_token_id());
                op_span.end = mod_tok.span.end;
            } else if matches!(next.kind, TokenKind::Keyword(Keyword::Distinct)) {
                let mod_tok = p
                    .advance()
                    .expect_invariant("DISTINCT keyword confirmed by peek");
                modifier = crate::ast::AstSetModifier::Distinct;
                modifier_token_id = Some(p.last_token_id());
                op_span.end = mod_tok.span.end;
            }
        }

        // Allocate syntax node for the set operator
        let set_op_syntax_id =
            p.syntax_arena
                .alloc_set_operator(crate::syntax::SyntaxSetOperator {
                    op_keyword: op_keyword_token_id,
                    modifier_keyword: modifier_token_id,
                    span: op_span,
                });

        // Parse right operand — can be SELECT or VALUES
        let right_stmt = crate::parser::set_operations::try_parse_set_operand(p)?;

        // Build set select with generic AstStmt right side
        let new_set = AstSetSelect {
            node_id: p.id_gen.next(),
            left: Box::new(left_stmt),
            op: op_kind,
            modifier,
            right: Box::new(right_stmt),
            set_op_syntax_id: Some(set_op_syntax_id),
            semicolon_token: None,
            paren_syntax_id: None,
            order_by: None,
            limit: None,
            offset: None,
            limit_keyword_span: None,
            fetch_clause_span: None,
            offset_keyword_span: None,
            limit_offset_comma_span: None,
        };
        left_stmt = AstStmt::SetSelect(new_set);
    }

    // A trailing ORDER BY / LIMIT after a VALUES-led set operation belongs to
    // the whole set node, same as the SELECT-led path.
    if let AstStmt::SetSelect(ref mut set) = left_stmt {
        crate::parser::set_operations::attach_set_query_tail(p, set)?;
    }

    Ok(left_stmt)
}
