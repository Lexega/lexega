// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Snowflake GRANT / REVOKE typed parser.
//!
//! Parses `AstStmt::Grant` / `AstStmt::Revoke` into typed structured shapes
//! (privilege list, object spec, grantee, options). A body it cannot type is
//! kept as the span-only `AstGrantShape::Unparsed` /
//! `AstRevokeShape::Unparsed`.
//!
//! ## Token-classification primer
//!
//! Most identifiers in GRANT / REVOKE syntax (`ROLE`, `USER`, `SHARE`,
//! `USAGE`, `MODIFY`, `OWNERSHIP`, `OPTION`, `PRIVILEGES`, `FUTURE`,
//! `CASCADE`, `RESTRICT`, …) lex as `Identifier { kind: Unquoted }`,
//! not as `Keyword(...)`. The matchers below use
//! `tok.lexeme(source).eq_ignore_ascii_case(...)` for these.
//!
//! Multi-word names (e.g. `ROW ACCESS POLICY`, `EXTERNAL VOLUME`,
//! `DATA METRIC FUNCTION`, `WITH GRANT OPTION`) split into 2-3 tokens
//! and must be composed at parse time. The classifiers in this module
//! use bounded N-token lookahead and longest-match.
//!
//! ## Failure semantics
//!
//! Each top-shape body parser returns `Result`. On `Err`, `parse_grant`
//! / `parse_revoke` roll the parser back to just past the leading
//! keyword and consume tokens up to the next semicolon/EOF as the
//! `Unparsed` placeholder. Customer SQL never fails to parse at the
//! statement level because GRANT / REVOKE was malformed — it merely
//! degrades to span-only.

use crate::ast::{
    AstAllPrivileges, AstCascadeMode, AstFunctionArgType, AstFunctionSignature, AstGrant,
    AstGrantObject, AstGrantShape, AstGrantee, AstObjectKind, AstObjectScope,
    AstOwnershipDisposition, AstOwnershipGrantBody, AstPluralObjectKind, AstPrivilege,
    AstPrivilegeGrantBody, AstPrivilegeKind, AstPrivilegeList, AstPrivilegeRevokeBody, AstRevoke,
    AstRevokeShape, AstRoleGrantBody, AstStmt,
};
use crate::error::{ParseError, ParseErrorKind, ParseResult};
use crate::lexer::token::{LiteralKind, Span, Token, TokenKind};
use crate::lexer::{Keyword, Operator, Punctuation};
use crate::parser::core::Parser;

// ---------------------------------------------------------------------------
// Top-level entries.
// ---------------------------------------------------------------------------

/// Parse a `GRANT ...` statement. Always succeeds: typed-parse failure
/// degrades the body to `AstGrantShape::Unparsed`.
pub(crate) fn parse_grant(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    let _depth = p.track_depth("grant")?;

    let grant_kw = expect_keyword(p, Keyword::Grant, "GRANT")?;
    let stmt_start = grant_kw.span.start;
    let keyword_span = grant_kw.span;
    let body_start_idx = p.idx;
    let body_start_pos = body_start_pos_after(grant_kw);

    let shape = match try_parse_grant_shape(p) {
        Ok(shape) => shape,
        Err(_) => {
            // Roll back and consume to semicolon as Unparsed.
            p.idx = body_start_idx;
            let body_end = consume_to_terminator(p);
            AstGrantShape::Unparsed {
                body_span: Span {
                    start: body_start_pos,
                    end: body_end,
                },
            }
        }
    };

    let span_end = current_position(p);

    Ok(AstStmt::Grant(Box::new(AstGrant {
        node_id: p.id_gen.next(),
        span: Span {
            start: stmt_start,
            end: span_end,
        },
        keyword_span,
        shape,
        semicolon_token: None,
    })))
}

/// Parse a `REVOKE ...` statement. Always succeeds.
pub(crate) fn parse_revoke(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    let _depth = p.track_depth("revoke")?;

    let revoke_kw = expect_keyword(p, Keyword::Revoke, "REVOKE")?;
    let stmt_start = revoke_kw.span.start;
    let keyword_span = revoke_kw.span;
    let body_start_idx = p.idx;
    let body_start_pos = body_start_pos_after(revoke_kw);

    // Optional `GRANT OPTION FOR` prefix.
    let grant_option_for = consume_grant_option_for(p);

    let prefix_end_idx = p.idx;
    let prefix_end_pos = current_position(p);

    let shape = match try_parse_revoke_shape(p) {
        Ok(shape) => shape,
        Err(_) => {
            // Roll back to before the typed shape attempt (but after
            // GRANT OPTION FOR if it was successfully consumed).
            p.idx = prefix_end_idx;
            let body_end = consume_to_terminator(p);
            AstRevokeShape::Unparsed {
                body_span: Span {
                    start: prefix_end_pos,
                    end: body_end,
                },
            }
        }
    };

    let cascade_mode = consume_cascade_mode(p);

    // If no shape and no grant_option_for, we still need a body span.
    let span_end = current_position(p);

    let _ = body_start_idx; // suppress unused-var if grant_option_for unused below
    let _ = body_start_pos;

    Ok(AstStmt::Revoke(Box::new(AstRevoke {
        node_id: p.id_gen.next(),
        span: Span {
            start: stmt_start,
            end: span_end,
        },
        keyword_span,
        grant_option_for,
        shape,
        cascade_mode,
        semicolon_token: None,
    })))
}

// ---------------------------------------------------------------------------
// Shape dispatch.
// ---------------------------------------------------------------------------

fn try_parse_grant_shape(p: &mut Parser<'_>) -> ParseResult<AstGrantShape> {
    if peek_lexeme_eq(p, "OWNERSHIP") {
        consume_one(p)?; // OWNERSHIP
        let body = parse_ownership_body(p)?;
        return Ok(AstGrantShape::Ownership(body));
    }
    if peek_two_lexemes_eq(p, "DATABASE", "ROLE") {
        let body = parse_role_body(p, /* qualified= */ true, /* expect_to= */ true)?;
        return Ok(AstGrantShape::DatabaseRole(body));
    }
    if peek_lexeme_eq(p, "ROLE") {
        let body = parse_role_body(p, /* qualified= */ false, /* expect_to= */ true)?;
        return Ok(AstGrantShape::Role(body));
    }
    let body = parse_privilege_grant_body(p)?;
    Ok(AstGrantShape::Privilege(body))
}

fn try_parse_revoke_shape(p: &mut Parser<'_>) -> ParseResult<AstRevokeShape> {
    if peek_two_lexemes_eq(p, "DATABASE", "ROLE") {
        let body = parse_role_body(p, /* qualified= */ true, /* expect_to= */ false)?;
        return Ok(AstRevokeShape::DatabaseRole(body));
    }
    if peek_lexeme_eq(p, "ROLE") {
        let body = parse_role_body(p, /* qualified= */ false, /* expect_to= */ false)?;
        return Ok(AstRevokeShape::Role(body));
    }
    let body = parse_privilege_revoke_body(p)?;
    Ok(AstRevokeShape::Privilege(body))
}

// ---------------------------------------------------------------------------
// Body parsers.
// ---------------------------------------------------------------------------

fn parse_privilege_grant_body(p: &mut Parser<'_>) -> ParseResult<AstPrivilegeGrantBody> {
    let privileges = parse_privilege_list(p)?;
    expect_keyword(p, Keyword::On, "ON")?;
    let object = parse_grant_object(p)?;
    expect_keyword(p, Keyword::To, "TO")?;
    let grantee = parse_grantee(p)?;
    let with_grant_option = consume_with_grant_option(p);
    Ok(AstPrivilegeGrantBody {
        privileges,
        objects: vec![object],
        grantees: vec![grantee],
        with_grant_option,
    })
}

fn parse_privilege_revoke_body(p: &mut Parser<'_>) -> ParseResult<AstPrivilegeRevokeBody> {
    let privileges = parse_privilege_list(p)?;
    expect_keyword(p, Keyword::On, "ON")?;
    let object = parse_grant_object(p)?;
    expect_keyword(p, Keyword::From, "FROM")?;
    let grantee = parse_grantee(p)?;
    Ok(AstPrivilegeRevokeBody {
        privileges,
        objects: vec![object],
        grantees: vec![grantee],
    })
}

fn parse_role_body(
    p: &mut Parser<'_>,
    qualified: bool,
    expect_to: bool,
) -> ParseResult<AstRoleGrantBody> {
    let role_keyword_span = if qualified {
        // DATABASE ROLE
        let db_tok = consume_one(p)?;
        let role_tok = consume_one(p)?;
        Span {
            start: db_tok.span.start,
            end: role_tok.span.end,
        }
    } else {
        // ROLE
        let role_tok = consume_one(p)?;
        role_tok.span
    };

    let role_name_span = p.parse_qualified_name_span()?;

    if expect_to {
        expect_keyword(p, Keyword::To, "TO")?;
    } else {
        expect_keyword(p, Keyword::From, "FROM")?;
    }

    let grantee = parse_grantee(p)?;
    Ok(AstRoleGrantBody {
        role_keyword_span,
        role_name_span,
        grantee,
    })
}

fn parse_ownership_body(p: &mut Parser<'_>) -> ParseResult<AstOwnershipGrantBody> {
    expect_keyword(p, Keyword::On, "ON")?;
    let object = parse_grant_object(p)?;
    expect_keyword(p, Keyword::To, "TO")?;
    let grantee = parse_grantee(p)?;
    let disposition = consume_ownership_disposition(p);
    Ok(AstOwnershipGrantBody {
        object,
        grantee,
        disposition,
    })
}

// ---------------------------------------------------------------------------
// Privilege list.
// ---------------------------------------------------------------------------

pub(crate) fn parse_privilege_list(p: &mut Parser<'_>) -> ParseResult<AstPrivilegeList> {
    let start_span = p
        .peek_non_trivia()
        .map(|t| t.span)
        .ok_or_else(|| eof_err(p, "privilege"))?;

    // `ALL [ PRIVILEGES ]`?
    if peek_token_kind(p, TokenKind::Keyword(Keyword::All)) {
        let all_tok = consume_one(p)?;
        let mut end = all_tok.span.end;
        let privileges_keyword = if peek_lexeme_eq(p, "PRIVILEGES") {
            let priv_tok = consume_one(p)?;
            end = priv_tok.span.end;
            true
        } else {
            false
        };
        let span = Span {
            start: all_tok.span.start,
            end,
        };
        return Ok(AstPrivilegeList {
            all: Some(AstAllPrivileges {
                privileges_keyword,
                span,
            }),
            privileges: Vec::new(),
            span,
        });
    }

    // Comma-separated privilege list.
    let mut privileges: Vec<AstPrivilege> = Vec::new();
    let first = parse_one_privilege(p)?;
    let mut end = first.span.end;
    privileges.push(first);

    while peek_token_kind(p, TokenKind::Punctuation(Punctuation::Comma)) {
        consume_one(p)?; // comma
        let next = parse_one_privilege(p)?;
        end = next.span.end;
        privileges.push(next);
    }

    let span = Span {
        start: start_span.start,
        end,
    };
    Ok(AstPrivilegeList {
        all: None,
        privileges,
        span,
    })
}

fn parse_one_privilege(p: &mut Parser<'_>) -> ParseResult<AstPrivilege> {
    let first = p
        .peek_non_trivia()
        .ok_or_else(|| eof_err(p, "privilege name"))?;

    if !is_privilege_part(first) {
        return Err(invalid_stmt(
            first.span,
            format!(
                "Expected privilege name, found '{}'",
                first.lexeme(p.source)
            ),
        ));
    }

    let start = first.span.start;
    let mut end = first.span.end;
    let mut lexemes: Vec<String> = Vec::new();

    while let Some(tok) = p.peek_non_trivia() {
        if is_privilege_terminator(tok) {
            break;
        }
        if !is_privilege_part(tok) {
            break;
        }
        let consumed = p.advance().expect("peek confirmed");
        lexemes.push(consumed.lexeme(p.source).to_uppercase());
        end = consumed.span.end;
    }

    let kind = classify_privilege(&lexemes);
    Ok(AstPrivilege {
        kind,
        span: Span { start, end },
    })
}

/// Predicate: tokens that may participate in a privilege name.
fn is_privilege_part(tok: &Token) -> bool {
    matches!(
        &tok.kind,
        TokenKind::Identifier { .. } | TokenKind::Keyword(_)
    )
}

/// Predicate: tokens that terminate a privilege name (followed by `ON`,
/// comma, or `WITH`). `TO` / `FROM` terminate server-tier T-SQL
/// permissions that omit the `ON` clause (`GRANT CONTROL SERVER TO x`);
/// no dialect's privilege name contains either word.
fn is_privilege_terminator(tok: &Token) -> bool {
    matches!(
        tok.kind,
        TokenKind::Keyword(Keyword::On)
            | TokenKind::Keyword(Keyword::With)
            | TokenKind::Keyword(Keyword::To)
            | TokenKind::Keyword(Keyword::From)
            | TokenKind::Punctuation(Punctuation::Comma)
            | TokenKind::Punctuation(Punctuation::Semi)
            | TokenKind::Eof
    )
}

/// Classify a privilege name (uppercased lexemes joined by spaces) into
/// a typed `AstPrivilegeKind`. Unrecognized forms land in
/// `AstPrivilegeKind::Other`.
fn classify_privilege(lexemes: &[String]) -> AstPrivilegeKind {
    use AstPrivilegeKind::*;
    let joined: String = lexemes.join(" ");
    match joined.as_str() {
        // Data-level
        "SELECT" => Select,
        "INSERT" => Insert,
        "UPDATE" => Update,
        "DELETE" => Delete,
        "TRUNCATE" => Truncate,
        "REFERENCES" => References,
        // Schema/object-level
        "MODIFY" => Modify,
        "MONITOR" => Monitor,
        "OPERATE" => Operate,
        "USAGE" => Usage,
        "APPLY" => Apply,
        "EXECUTE" => Execute,
        "READ" => Read,
        "WRITE" => Write,
        // Databricks Unity Catalog
        "MANAGE" => Manage,
        "READ FILES" => ReadFiles,
        "WRITE FILES" => WriteFiles,
        "EXTERNAL USE LOCATION" => ExternalUseLocation,
        "EXTERNAL USE SCHEMA" => ExternalUseSchema,
        "CREATE STORAGE CREDENTIAL" => CreateStorageCredential,
        "CREATE EXTERNAL LOCATION" => CreateExternalLocation,
        "SET SHARE PERMISSION" => SetSharePermission,
        // Snowflake-special
        "OWNERSHIP" => Ownership,
        "MANAGE GRANTS" => ManageGrants,
        "APPLY MASKING POLICY" => ApplyMaskingPolicy,
        "APPLY ROW ACCESS POLICY" => ApplyRowAccessPolicy,
        "APPLY TAG" => ApplyTag,
        "APPLY AGGREGATION POLICY" => ApplyAggregationPolicy,
        "APPLY PROJECTION POLICY" => ApplyProjectionPolicy,
        "IMPORT SHARE" => ImportShare,
        "IMPORTED PRIVILEGES" => ImportedPrivileges,
        // CREATE <object>
        "CREATE TABLE" => CreateTable,
        "CREATE VIEW" => CreateView,
        "CREATE SCHEMA" => CreateSchema,
        "CREATE DATABASE" => CreateDatabase,
        "CREATE ROLE" => CreateRole,
        "CREATE USER" => CreateUser,
        "CREATE FUNCTION" => CreateFunction,
        "CREATE PROCEDURE" => CreateProcedure,
        "CREATE MASKING POLICY" => CreateMaskingPolicy,
        "CREATE ROW ACCESS POLICY" => CreateRowAccessPolicy,
        "CREATE NETWORK POLICY" => CreateNetworkPolicy,
        "CREATE SESSION POLICY" => CreateSessionPolicy,
        "CREATE PASSWORD POLICY" => CreatePasswordPolicy,
        "CREATE STAGE" => CreateStage,
        "CREATE WAREHOUSE" => CreateWarehouse,
        "CREATE TASK" => CreateTask,
        "CREATE PIPE" => CreatePipe,
        "CREATE EXTERNAL TABLE" => CreateExternalTable,
        "CREATE" => Create,
        _ => Other {
            lexemes: lexemes.to_vec(),
        },
    }
}

// ---------------------------------------------------------------------------
// Object spec (post-`ON`).
// ---------------------------------------------------------------------------

fn parse_grant_object(p: &mut Parser<'_>) -> ParseResult<AstGrantObject> {
    // ON ACCOUNT
    if peek_lexeme_eq(p, "ACCOUNT") {
        let tok = consume_one(p)?;
        return Ok(AstGrantObject::Account {
            keyword_span: tok.span,
        });
    }
    // ON METASTORE (Databricks Unity Catalog metastore-tier singleton).
    if peek_lexeme_eq(p, "METASTORE") {
        let tok = consume_one(p)?;
        return Ok(AstGrantObject::Metastore {
            keyword_span: tok.span,
        });
    }
    // ON ALL <plural> IN ...
    if peek_token_kind(p, TokenKind::Keyword(Keyword::All)) {
        consume_one(p)?; // ALL
        let (plural_kind, plural_kind_span) = parse_plural_object_kind(p)?;
        expect_keyword(p, Keyword::In, "IN")?;
        let scope = parse_object_scope(p)?;
        return Ok(AstGrantObject::AllInScope {
            plural_kind,
            plural_kind_span,
            scope,
        });
    }
    // ON FUTURE <plural> IN ...
    if peek_lexeme_eq(p, "FUTURE") {
        consume_one(p)?; // FUTURE
        let (plural_kind, plural_kind_span) = parse_plural_object_kind(p)?;
        expect_keyword(p, Keyword::In, "IN")?;
        let scope = parse_object_scope(p)?;
        return Ok(AstGrantObject::FutureInScope {
            plural_kind,
            plural_kind_span,
            scope,
        });
    }
    // ON <object_kind> <name>[(<args>)]
    //
    // Redshift / PostgreSQL also accept a bare relation name with no
    // object-kind keyword (`GRANT … ON sales TO …`), which defaults to a
    // TABLE/relation. Try the keyword form first; if no object-kind keyword is
    // recognized, fall back to an implicit TABLE so the statement parses fully.
    // Otherwise it degrades to `AstGrantShape::Unparsed`, which erases the
    // grantees (and with them any grant-to-PUBLIC recognition).
    // `parse_object_kind` does not consume tokens on its error path.
    let (object_kind, kind_span) = match parse_object_kind(p) {
        Ok(parsed) => parsed,
        Err(_) => {
            // No keyword token: the object-kind span is the zero-width point at
            // the start of the object name (GRANT is span-passthrough-formatted,
            // so an empty kind span emits nothing).
            let here = p.peek_non_trivia().map(|t| t.span.start).unwrap_or(0);
            (
                AstObjectKind::Table,
                Span {
                    start: here,
                    end: here,
                },
            )
        }
    };
    let name_span = p.parse_qualified_name_span()?;
    let function_signature = if peek_token_kind(p, TokenKind::Punctuation(Punctuation::LParen)) {
        Some(parse_function_signature(p)?)
    } else {
        None
    };
    Ok(AstGrantObject::Single {
        object_kind,
        kind_span,
        name_span,
        function_signature,
    })
}

fn parse_object_scope(p: &mut Parser<'_>) -> ParseResult<AstObjectScope> {
    let first = p
        .peek_non_trivia()
        .ok_or_else(|| eof_err(p, "DATABASE, SCHEMA, or CATALOG"))?;
    let lex = first.lexeme(p.source);
    if lex.eq_ignore_ascii_case("DATABASE") {
        let kw = consume_one(p)?;
        let name_span = p.parse_qualified_name_span()?;
        Ok(AstObjectScope::Database {
            keyword_span: kw.span,
            name_span,
        })
    } else if lex.eq_ignore_ascii_case("SCHEMA") {
        let kw = consume_one(p)?;
        let name_span = p.parse_qualified_name_span()?;
        Ok(AstObjectScope::Schema {
            keyword_span: kw.span,
            name_span,
        })
    } else if lex.eq_ignore_ascii_case("CATALOG") {
        let kw = consume_one(p)?;
        let name_span = p.parse_qualified_name_span()?;
        Ok(AstObjectScope::Catalog {
            keyword_span: kw.span,
            name_span,
        })
    } else {
        Err(invalid_stmt(
            first.span,
            format!("Expected DATABASE, SCHEMA, or CATALOG, found '{}'", lex),
        ))
    }
}

/// Recognize a single-object-kind token sequence and consume it.
/// Bounded 3-token lookahead, longest-match.
fn parse_object_kind(p: &mut Parser<'_>) -> ParseResult<(AstObjectKind, Span)> {
    let lexs = peek_lexemes_n(p, 3);
    if lexs.is_empty() {
        return Err(eof_err(p, "object kind"));
    }

    if lexs.len() >= 3 {
        let joined = format!("{} {} {}", lexs[0].0, lexs[1].0, lexs[2].0);
        if let Some(kind) = match_object_kind(&joined) {
            let span = Span {
                start: lexs[0].1.start,
                end: lexs[2].1.end,
            };
            for _ in 0..3 {
                consume_one(p)?;
            }
            return Ok((kind, span));
        }
    }
    if lexs.len() >= 2 {
        let joined = format!("{} {}", lexs[0].0, lexs[1].0);
        if let Some(kind) = match_object_kind(&joined) {
            let span = Span {
                start: lexs[0].1.start,
                end: lexs[1].1.end,
            };
            for _ in 0..2 {
                consume_one(p)?;
            }
            return Ok((kind, span));
        }
    }
    if let Some(kind) = match_object_kind(&lexs[0].0) {
        let span = lexs[0].1;
        consume_one(p)?;
        return Ok((kind, span));
    }

    Err(invalid_stmt(
        lexs[0].1,
        format!("Unrecognized object kind '{}'", lexs[0].0),
    ))
}

fn match_object_kind(joined: &str) -> Option<AstObjectKind> {
    use AstObjectKind::*;
    Some(match joined {
        // 1-token
        "TABLE" => Table,
        "VIEW" => View,
        "SCHEMA" => Schema,
        "DATABASE" => Database,
        "WAREHOUSE" => Warehouse,
        "USER" => User,
        "ROLE" => Role,
        "SHARE" => Share,
        "APPLICATION" => Application,
        "ACCOUNT" => Account,
        "INTEGRATION" => Integration,
        "STAGE" => Stage,
        "FUNCTION" => Function,
        "PROCEDURE" => Procedure,
        "SEQUENCE" => Sequence,
        "STREAM" => Stream,
        "TASK" => Task,
        "PIPE" => Pipe,
        "TAG" => Tag,
        "SECRET" => Secret,
        "SERVICE" => Service,
        "STREAMLIT" => Streamlit,
        "ALERT" => Alert,
        "CONNECTION" => Connection,
        // Databricks Unity Catalog (1-token)
        "CATALOG" => Catalog,
        "VOLUME" => Volume,
        "METASTORE" => Metastore,
        // 2-token
        "MATERIALIZED VIEW" => MaterializedView,
        "DYNAMIC TABLE" => DynamicTable,
        "EXTERNAL TABLE" => ExternalTable,
        "ICEBERG TABLE" => IcebergTable,
        "HYBRID TABLE" => HybridTable,
        "EXTERNAL VOLUME" => ExternalVolume,
        "EXTERNAL LOCATION" => ExternalLocation,
        "STORAGE CREDENTIAL" => StorageCredential,
        "FILE FORMAT" => FileFormat,
        "FAILOVER GROUP" => FailoverGroup,
        "REPLICATION GROUP" => ReplicationGroup,
        "RESOURCE MONITOR" => ResourceMonitor,
        "COMPUTE POOL" => ComputePool,
        "DATABASE ROLE" => Role, // grantee uses Role; object kind reuses it
        "APPLICATION PACKAGE" => ApplicationPackage,
        "NETWORK RULE" => NetworkRule,
        "NETWORK POLICY" => NetworkPolicy,
        "MASKING POLICY" => MaskingPolicy,
        "AGGREGATION POLICY" => AggregationPolicy,
        "AUTHENTICATION POLICY" => AuthenticationPolicy,
        "PASSWORD POLICY" => PasswordPolicy,
        "SESSION POLICY" => SessionPolicy,
        "PROJECTION POLICY" => ProjectionPolicy,
        "SEMANTIC VIEW" => SemanticView,
        // 3-token
        "ROW ACCESS POLICY" => RowAccessPolicy,
        "DATA METRIC FUNCTION" => DataMetricFunction,
        _ => return None,
    })
}

fn parse_plural_object_kind(p: &mut Parser<'_>) -> ParseResult<(AstPluralObjectKind, Span)> {
    let lexs = peek_lexemes_n(p, 3);
    if lexs.is_empty() {
        return Err(eof_err(p, "plural object kind"));
    }
    if lexs.len() >= 3 {
        let joined = format!("{} {} {}", lexs[0].0, lexs[1].0, lexs[2].0);
        if let Some(kind) = match_plural_object_kind(&joined) {
            let span = Span {
                start: lexs[0].1.start,
                end: lexs[2].1.end,
            };
            for _ in 0..3 {
                consume_one(p)?;
            }
            return Ok((kind, span));
        }
    }
    if lexs.len() >= 2 {
        let joined = format!("{} {}", lexs[0].0, lexs[1].0);
        if let Some(kind) = match_plural_object_kind(&joined) {
            let span = Span {
                start: lexs[0].1.start,
                end: lexs[1].1.end,
            };
            for _ in 0..2 {
                consume_one(p)?;
            }
            return Ok((kind, span));
        }
    }
    if let Some(kind) = match_plural_object_kind(&lexs[0].0) {
        let span = lexs[0].1;
        consume_one(p)?;
        return Ok((kind, span));
    }
    Err(invalid_stmt(
        lexs[0].1,
        format!("Unrecognized plural object kind '{}'", lexs[0].0),
    ))
}

fn match_plural_object_kind(joined: &str) -> Option<AstPluralObjectKind> {
    use AstPluralObjectKind::*;
    Some(match joined {
        // 1-token
        "TABLES" => Tables,
        "VIEWS" => Views,
        "SCHEMAS" => Schemas,
        "FUNCTIONS" => Functions,
        "PROCEDURES" => Procedures,
        "SEQUENCES" => Sequences,
        "STAGES" => Stages,
        "STREAMS" => Streams,
        "TASKS" => Tasks,
        "PIPES" => Pipes,
        "TAGS" => Tags,
        // 2-token
        "MATERIALIZED VIEWS" => MaterializedViews,
        "DYNAMIC TABLES" => DynamicTables,
        "EXTERNAL TABLES" => ExternalTables,
        "ICEBERG TABLES" => IcebergTables,
        "HYBRID TABLES" => HybridTables,
        "FILE FORMATS" => FileFormats,
        "MASKING POLICIES" => MaskingPolicies,
        "AGGREGATION POLICIES" => AggregationPolicies,
        "AUTHENTICATION POLICIES" => AuthenticationPolicies,
        "PASSWORD POLICIES" => PasswordPolicies,
        "NETWORK POLICIES" => NetworkPolicies,
        "SESSION POLICIES" => SessionPolicies,
        "PROJECTION POLICIES" => ProjectionPolicies,
        "SEMANTIC VIEWS" => SemanticViews,
        // 3-token
        "ROW ACCESS POLICIES" => RowAccessPolicies,
        "DATA METRIC FUNCTIONS" => DataMetricFunctions,
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// Function signature parsing.
// ---------------------------------------------------------------------------

fn parse_function_signature(p: &mut Parser<'_>) -> ParseResult<AstFunctionSignature> {
    let lparen = consume_one(p)?;
    let mut args: Vec<AstFunctionArgType> = Vec::new();
    if !peek_token_kind(p, TokenKind::Punctuation(Punctuation::RParen)) {
        loop {
            let arg = parse_function_arg_type(p)?;
            args.push(arg);
            if peek_token_kind(p, TokenKind::Punctuation(Punctuation::Comma)) {
                consume_one(p)?;
                continue;
            }
            break;
        }
    }
    let rparen = expect_punctuation(p, Punctuation::RParen, ")")?;
    Ok(AstFunctionSignature {
        lparen_span: lparen.span,
        rparen_span: rparen.span,
        args,
    })
}

fn parse_function_arg_type(p: &mut Parser<'_>) -> ParseResult<AstFunctionArgType> {
    // Argument type tokens are mostly Identifier (NUMBER, VARCHAR, STRING).
    // We accept any sequence of identifier-like tokens and length specs
    // until we hit `,` or `)`.
    let first = p
        .peek_non_trivia()
        .ok_or_else(|| eof_err(p, "argument type"))?;
    let start = first.span.start;
    let mut end = first.span.end;

    // Consume identifier-like tokens.
    while let Some(tok) = p.peek_non_trivia() {
        if matches!(
            tok.kind,
            TokenKind::Punctuation(Punctuation::Comma)
                | TokenKind::Punctuation(Punctuation::RParen)
        ) {
            break;
        }
        let consumed = p.advance().expect("peek confirmed");
        end = consumed.span.end;
    }

    Ok(AstFunctionArgType {
        span: Span { start, end },
    })
}

// ---------------------------------------------------------------------------
// Grantee.
// ---------------------------------------------------------------------------

pub(crate) fn parse_grantee(p: &mut Parser<'_>) -> ParseResult<AstGrantee> {
    if peek_two_lexemes_eq(p, "DATABASE", "ROLE") {
        let db_tok = consume_one(p)?;
        let role_tok = consume_one(p)?;
        let name_span = p.parse_qualified_name_span()?;
        return Ok(AstGrantee::DatabaseRole {
            keyword_span: Span {
                start: db_tok.span.start,
                end: role_tok.span.end,
            },
            name_span,
        });
    }
    if peek_two_lexemes_eq(p, "APPLICATION", "ROLE") {
        let app_tok = consume_one(p)?;
        let role_tok = consume_one(p)?;
        let name_span = p.parse_qualified_name_span()?;
        return Ok(AstGrantee::ApplicationRole {
            keyword_span: Span {
                start: app_tok.span.start,
                end: role_tok.span.end,
            },
            name_span,
        });
    }
    if peek_lexeme_eq(p, "ROLE") {
        let kw = consume_one(p)?;
        let name_span = p.parse_qualified_name_span()?;
        return Ok(AstGrantee::Role {
            role_keyword_span: Some(kw.span),
            name_span,
        });
    }
    if peek_lexeme_eq(p, "USER") {
        let kw = consume_one(p)?;
        let name_span = p.parse_qualified_name_span()?;
        return Ok(AstGrantee::User {
            keyword_span: kw.span,
            name_span,
        });
    }
    if peek_lexeme_eq(p, "SHARE") {
        let kw = consume_one(p)?;
        let name_span = p.parse_qualified_name_span()?;
        return Ok(AstGrantee::Share {
            keyword_span: kw.span,
            name_span,
        });
    }
    if peek_lexeme_eq(p, "APPLICATION") {
        let kw = consume_one(p)?;
        let name_span = p.parse_qualified_name_span()?;
        return Ok(AstGrantee::Application {
            keyword_span: kw.span,
            name_span,
        });
    }
    // `GROUP <name>` — Redshift permission group (deprecated PG noise word).
    // In grantee position GROUP is unambiguous (no GROUP BY here).
    if peek_lexeme_eq(p, "GROUP") {
        let kw = consume_one(p)?;
        let name_span = p.parse_qualified_name_span()?;
        return Ok(AstGrantee::Group {
            keyword_span: kw.span,
            name_span,
        });
    }
    // Bare role name (`TO r1`) — ROLE keyword omitted. A MySQL grantee is
    // `'user'@'host'`; consume an optional `@host` suffix so a REVOKE
    // (or GRANT routed here) from `'u'@'h'` parses instead of leaving the
    // `@host` dangling. MySQL users are projected to `Role`, mirroring the
    // MySQL GRANT grantee reader.
    let mut name_span = p.parse_qualified_name_span()?;
    name_span.end = consume_optional_grantee_host(p, name_span.end);
    Ok(AstGrantee::Role {
        role_keyword_span: None,
        name_span,
    })
}

/// Consume an optional MySQL `@host` grantee suffix, returning the extended
/// span end. Handles the quoted form (`@` is `Operator::At` + a host token) and
/// the unquoted form (`@host` lexes as a single AtVariable identifier). A no-op
/// (returns `name_end`) when no `@host` follows — harmless for non-MySQL
/// grantees, where `@` never appears in grantee position.
fn consume_optional_grantee_host(p: &mut Parser<'_>, name_end: u32) -> u32 {
    let at_present = matches!(
        p.peek_non_trivia().map(|t| &t.kind),
        Some(TokenKind::Operator(Operator::At))
    );
    if at_present {
        let _ = consume_one(p); // @
        let host_end = match p.peek_non_trivia() {
            Some(h) => {
                let ok = matches!(h.kind, TokenKind::Literal(LiteralKind::String))
                    || p.can_be_identifier_token(h);
                ok.then_some(h.span.end)
            }
            None => None,
        };
        if let Some(end) = host_end {
            let _ = consume_one(p); // host
            return end;
        }
        return name_end;
    }
    // Unquoted `user@host`: the host lexes as a single `@host` AtVariable token.
    let unquoted_host_end = p.peek_non_trivia().and_then(|t| {
        if matches!(t.kind, TokenKind::Identifier { .. }) && t.lexeme(p.source).starts_with('@') {
            Some(t.span.end)
        } else {
            None
        }
    });
    if let Some(end) = unquoted_host_end {
        let _ = consume_one(p); // @host
        return end;
    }
    name_end
}

// ---------------------------------------------------------------------------
// Trailing-clause consumers.
// ---------------------------------------------------------------------------

pub(crate) fn consume_with_grant_option(p: &mut Parser<'_>) -> Option<Span> {
    if !peek_token_kind(p, TokenKind::Keyword(Keyword::With)) {
        return None;
    }
    let lexs = peek_lexemes_n(p, 3);
    if lexs.len() < 3 {
        return None;
    }
    if lexs[0].0 != "WITH" || lexs[1].0 != "GRANT" || lexs[2].0 != "OPTION" {
        return None;
    }
    let start = lexs[0].1.start;
    let end = lexs[2].1.end;
    for _ in 0..3 {
        let _ = p.advance();
    }
    Some(Span { start, end })
}

pub(crate) fn consume_grant_option_for(p: &mut Parser<'_>) -> Option<Span> {
    let lexs = peek_lexemes_n(p, 3);
    if lexs.len() < 3 {
        return None;
    }
    if lexs[0].0 != "GRANT" || lexs[1].0 != "OPTION" || lexs[2].0 != "FOR" {
        return None;
    }
    let start = lexs[0].1.start;
    let end = lexs[2].1.end;
    for _ in 0..3 {
        let _ = p.advance();
    }
    Some(Span { start, end })
}

pub(crate) fn consume_cascade_mode(p: &mut Parser<'_>) -> Option<AstCascadeMode> {
    if peek_lexeme_eq(p, "RESTRICT") {
        let _ = p.advance();
        Some(AstCascadeMode::Restrict)
    } else if peek_lexeme_eq(p, "CASCADE") {
        let _ = p.advance();
        Some(AstCascadeMode::Cascade)
    } else {
        None
    }
}

fn consume_ownership_disposition(p: &mut Parser<'_>) -> Option<AstOwnershipDisposition> {
    let lexs = peek_lexemes_n(p, 3);
    if lexs.len() < 3 {
        return None;
    }
    let head = lexs[0].0.as_str();
    if (head == "COPY" || head == "REVOKE") && lexs[1].0 == "CURRENT" && lexs[2].0 == "GRANTS" {
        let disposition = if head == "COPY" {
            AstOwnershipDisposition::Copy
        } else {
            AstOwnershipDisposition::Revoke
        };
        for _ in 0..3 {
            let _ = p.advance();
        }
        return Some(disposition);
    }
    None
}

// ---------------------------------------------------------------------------
// Token-level helpers.
// ---------------------------------------------------------------------------

pub(crate) fn expect_keyword<'a>(
    p: &mut Parser<'a>,
    keyword: Keyword,
    label: &str,
) -> ParseResult<&'a Token> {
    let tok = p.peek_non_trivia().ok_or_else(|| eof_err(p, label))?;
    if !matches!(tok.kind, TokenKind::Keyword(k) if k == keyword) {
        let msg = format!(
            "Expected {} keyword, found '{}'",
            label,
            tok.lexeme(p.source)
        );
        return Err(invalid_stmt(tok.span, msg));
    }
    Ok(p.advance().expect("peek confirmed"))
}

fn expect_punctuation<'a>(
    p: &mut Parser<'a>,
    punc: Punctuation,
    label: &str,
) -> ParseResult<&'a Token> {
    let tok = p.peek_non_trivia().ok_or_else(|| eof_err(p, label))?;
    if !matches!(tok.kind, TokenKind::Punctuation(pk) if pk == punc) {
        let msg = format!("Expected {}, found '{}'", label, tok.lexeme(p.source));
        return Err(invalid_stmt(tok.span, msg));
    }
    Ok(p.advance().expect("peek confirmed"))
}

fn consume_one<'a>(p: &mut Parser<'a>) -> ParseResult<&'a Token> {
    let _ = p.peek_non_trivia();
    p.advance().ok_or_else(|| eof_err(p, "token"))
}

pub(crate) fn peek_lexeme_eq(p: &mut Parser<'_>, expected: &str) -> bool {
    p.peek_non_trivia()
        .map(|t| t.lexeme(p.source).eq_ignore_ascii_case(expected))
        .unwrap_or(false)
}

fn peek_two_lexemes_eq(p: &mut Parser<'_>, first: &str, second: &str) -> bool {
    let lexs = peek_lexemes_n(p, 2);
    lexs.len() == 2
        && lexs[0].0.eq_ignore_ascii_case(first)
        && lexs[1].0.eq_ignore_ascii_case(second)
}

fn peek_token_kind(p: &mut Parser<'_>, want: TokenKind) -> bool {
    match p.peek_non_trivia() {
        Some(t) => {
            std::mem::discriminant(&t.kind) == std::mem::discriminant(&want) && t.kind == want
        }
        None => false,
    }
}

/// Peek up to `max` non-trivia, non-EOF tokens without mutating `p.idx`.
/// Returns each as `(uppercased lexeme, span)`.
fn peek_lexemes_n(p: &Parser<'_>, max: usize) -> Vec<(String, Span)> {
    let mut out: Vec<(String, Span)> = Vec::new();
    let mut i = p.idx;
    while out.len() < max && i < p.tokens.len() {
        let t = &p.tokens[i];
        i += 1;
        if matches!(
            t.kind,
            TokenKind::Eof | TokenKind::LineComment | TokenKind::BlockComment
        ) {
            continue;
        }
        out.push((t.lexeme(p.source).to_uppercase(), t.span));
    }
    out
}

/// Consume tokens until a semicolon, EOF, or a structural Jinja delimiter.
/// Returns the byte position one past the last consumed token.
pub(crate) fn consume_to_terminator(p: &mut Parser<'_>) -> u32 {
    let mut end = current_position(p);
    while let Some(tok) = p.peek_non_trivia() {
        if matches!(
            tok.kind,
            TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof
        ) {
            break;
        }
        let consumed = p.advance().expect("peek confirmed");
        end = consumed.span.end;
    }
    end
}

#[inline]
pub(crate) fn current_position(p: &Parser<'_>) -> u32 {
    if let Some(prev) = p.idx.checked_sub(1).and_then(|i| p.tokens.get(i)) {
        prev.span.end
    } else {
        0
    }
}

#[inline]
pub(crate) fn body_start_pos_after(tok: &Token) -> u32 {
    tok.span.end
}

fn eof_err(p: &Parser<'_>, expected: &str) -> ParseError {
    ParseError::new(
        // Use the last token's span if available, else default.
        p.tokens
            .last()
            .map(|t| t.span)
            .unwrap_or(Span { start: 0, end: 0 }),
        ParseErrorKind::InvalidStatement {
            message: format!("Expected {} but reached end of input", expected),
        },
    )
}

fn invalid_stmt(span: Span, message: String) -> ParseError {
    ParseError::new(span, ParseErrorKind::InvalidStatement { message })
}
