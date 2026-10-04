// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! DDL / non-query statement plan.
//!
//! [`DdlPlan`] is the IR-side carrier for every statement that is
//! not a query-bearing relational tree (`SELECT` / `INSERT` /
//! `UPDATE` / `DELETE` / `MERGE`). It is intentionally **a single
//! struct, not an AST mirror**: it captures the small set of facts
//! IR-side analyses and signal emitters consume — verb (action),
//! object (what kind of thing is being acted on), target identity,
//! optional inner body, and a typed options slot — without
//! enumerating one variant per AST statement kind.
//!
//! # Why a struct, not an enum
//!
//! [`super::plan::RelPlan`] is an enum because relational algebra
//! has a closed set of *operators* (Project, Filter, Join, …).
//! DDL has no analogous operator algebra. What IR-side consumers
//! actually need from a DDL statement is:
//!
//! - The **verb** ([`DdlAction`]) — `CREATE` vs `ALTER` vs `DROP`
//!   etc. A small closed enum.
//! - The **object kind** ([`ObjectKind`]) — shared by IR-side
//!   dispatch and YAML-rule emission, so there is one taxonomy.
//! - The **target identity** ([`DdlTarget`]) — `db.schema.name` of
//!   the modified object, when the statement names one.
//! - The **body**, when the statement nests another statement
//!   (e.g. `CREATE VIEW v AS <query>`, `CREATE PROCEDURE p AS <body>`,
//!   `BEGIN .. END` blocks). Recursive: an optional shared
//!   [`super::statement_plan::StatementPlan`], so a procedure body
//!   carries its own plan.
//! - **Options** ([`DdlOptions`]) — `OR REPLACE`, `IF EXISTS`,
//!   `TEMPORARY`, etc. Typed fields, not a string map.
//!
//! Statement-specific facts that don't fit this skeleton (e.g.
//! per-policy predicate trees) live on dedicated typed sibling
//! structs lowered beside the plan — the `PolicyStatementFacts`
//! pattern, scaled out.
//!
//! # Internal types
//!
//! `DdlPlan` and its component enums are internal IR types — they
//! must not appear in user-visible JSON, baseline output, or
//! rule-author surfaces.

use std::rc::Rc;

use crate::ast::NodeId;
use crate::facts::identity::ObjectKind;
use crate::lexer::Span;

use super::statement_plan::StatementPlan;

/// IR plan for a non-query statement.
#[derive(Debug, Clone)]
pub struct DdlPlan {
    /// Abstract verb performed by the statement.
    pub action: DdlAction,
    /// What kind of database object the statement acts on — the
    /// structured object-kind fact. Non-object statements (transaction
    /// control, session config, bulk ops) carry `ObjectKind::Generic`.
    pub object_kind: ObjectKind,
    /// `db.schema.name` of the object, when the statement names
    /// one. `None` for verbs that don't reference a named object
    /// (e.g. `BEGIN TRANSACTION`).
    pub target: Option<DdlTarget>,
    /// Inner statement plans for statements that nest other
    /// statements (`CREATE VIEW v AS <query>`, `CREATE PROCEDURE p
    /// AS <body>`, `BEGIN .. END`, `IF ... THEN ... ELSE ...`,
    /// `WHILE/FOR/LOOP/REPEAT`, MSSQL `TRY/CATCH`, etc.). Empty
    /// `Vec` means the statement has no body. Single-stmt wrappers
    /// (`CREATE VIEW v AS <SELECT>`) carry one entry; multi-stmt
    /// procedural blocks (`BEGIN s1; s2; END`) carry one entry per
    /// inner statement, in source order. Branch-bearing constructs
    /// (`IF .. ELSEIF .. ELSE`, `CASE .. WHEN .. ELSE`) flatten the
    /// branch bodies and the `ELSE` body into this one slot.
    pub body: Vec<Rc<StatementPlan>>,
    /// Typed flag bag: `OR REPLACE`, `IF EXISTS`, `TEMPORARY`,
    /// etc. All flags default to `false`; reads from any flag
    /// always return a defined value.
    pub options: DdlOptions,
    /// AST node id of the originating statement.
    pub node_id: NodeId,
    /// Source span of the originating statement.
    pub span: Span,
    /// Typed per-element schema mutations for `ALTER` actions that
    /// rename a table or alter its column set. Populated only for
    /// [`DdlAction::Alter`] on table-shaped objects; empty otherwise.
    ///
    /// This is the IR's structural answer to "what did this ALTER
    /// actually do?" — sidestepping the classification
    /// helpers in `super::table_plan::classify_alter_action` that
    /// collapse identity into per-category booleans. Consumers that
    /// track schema state across statements read this directly rather
    /// than re-walking the AST.
    pub schema_mutations: Vec<DdlSchemaMutation>,
    /// MSSQL `SET <option> <value>`-specific typed identity. Populated
    /// only when this `DdlPlan` originated from
    /// [`crate::ast::AstStmt::MssqlSetOption`]; `None` for every other
    /// AST kind. Carries the parser-resolved `option_kind` and
    /// `value` so facts projection and rule predicates dispatch on
    /// typed variants instead of re-tokenising `option_span` /
    /// `value_span`.
    pub mssql_set_option: Option<MssqlSetOptionDetail>,
    /// MSSQL `CREATE LOGIN` / `CREATE USER` source-clause typed
    /// identity. Populated only when this `DdlPlan` originated from a
    /// MSSQL `CREATE LOGIN` / `CREATE USER` (carried via
    /// [`crate::ast::AstStmt::CreatePrincipal`] with a non-`None`
    /// `options.mssql_source`); `None` for every other AST kind.
    pub mssql_principal_source: Option<MssqlPrincipalSourceIr>,
    /// Dialect-neutral `CREATE / ALTER { USER | ROLE | LOGIN }` typed
    /// option bag. Populated only when this `DdlPlan` originated from
    /// [`crate::ast::AstStmt::CreatePrincipal`] or
    /// [`crate::ast::AstStmt::AlterPrincipal`]; `None` for every other
    /// AST kind. Carries the [`PrincipalKindIr`] discriminator and any
    /// captured typed clauses (`password_literal`, MySQL `mysql_host`)
    /// so the facts projection can expose them under
    /// `ddl.principal.*` without re-walking the AST.
    pub principal_options: Option<PrincipalOptionsIr>,
    /// Postgres `ALTER DOMAIN` typed action identity. Populated only
    /// when this `DdlPlan` originated from
    /// [`crate::ast::AstStmt::AlterDomain`]; `None` for every other
    /// AST kind. Carries the per-statement list of typed
    /// [`IrDomainAlterAction`] variants so the facts-side projection
    /// can curate them into the public
    /// [`crate::facts::ddl::DomainAlterAction`] vocabulary without
    /// re-walking the AST.
    pub domain: Option<IrDomainDetail>,
    /// `ALTER INDEX` typed action identity. Populated only when this
    /// `DdlPlan` originated from [`crate::ast::AstStmt::AlterIndex`];
    /// `None` for every other AST kind (including `CREATE INDEX`,
    /// which carries no per-action discriminator). Carries the typed
    /// [`IrIndexAlterAction`] so the facts-side projection can curate
    /// it into the public
    /// [`crate::facts::ddl::IndexAlterAction`] vocabulary without
    /// re-walking the AST. Single-action — Postgres `ALTER INDEX`
    /// grammar permits one sub-action per statement.
    pub pg_index: Option<IrIndexDetail>,
    /// `ALTER TRIGGER` typed action identity. Populated only when this
    /// `DdlPlan` originated from [`crate::ast::AstStmt::AlterPgTrigger`];
    /// `None` for every other AST kind (including `CREATE TRIGGER` and
    /// `DROP TRIGGER`, which carry no per-action discriminator). Carries
    /// the typed [`IrTriggerAlterAction`] so the facts-side projection
    /// can curate it into the public
    /// [`crate::facts::ddl::TriggerAlterAction`] vocabulary without
    /// re-walking the AST. Single-action — Postgres `ALTER TRIGGER`
    /// grammar permits one sub-action per statement.
    pub pg_trigger: Option<IrTriggerDetail>,
    /// `ALTER TABLE … {ENABLE|DISABLE} TRIGGER …` typed action
    /// identity. Populated only when this `DdlPlan` originated from
    /// [`crate::ast::AstStmt::PgAlterTableTriggerState`]; `None` for
    /// every other AST kind. Carries the typed
    /// [`IrTriggerStateAction`] so the facts-side projection can
    /// curate it into the public
    /// [`crate::facts::ddl::TriggerStateAction`] vocabulary without
    /// re-walking the AST. Distinct from [`Self::pg_trigger`] —
    /// `ALTER TRIGGER` (rename / depends-on-extension) and
    /// `ALTER TABLE … TRIGGER state` are different SQL surfaces with
    /// different action vocabularies; they share the
    /// [`crate::facts::ddl::DdlFacts::trigger`] vs
    /// [`crate::facts::ddl::DdlFacts::trigger_state`] split for the
    /// same reason.
    pub pg_trigger_state: Option<IrTriggerStateDetail>,
    /// `SET` / `RESET` session-config statement typed kind identity.
    /// Populated only when this `DdlPlan` originated from
    /// [`crate::ast::AstStmt::PgSet`]; `None` for every other AST kind.
    /// Carries the typed [`IrPgSessionAction`] so the facts-side
    /// projection can curate it into the public
    /// [`crate::facts::ddl::PgSessionAction`] vocabulary without
    /// re-walking the AST.
    pub pg_session: Option<IrPgSessionDetail>,
    /// BigQuery `ASSERT expr [AS description]` typed identity.
    /// Populated only when this `DdlPlan` originated from
    /// [`crate::ast::AstStmt::BqAssert`]; `None` for every other AST
    /// kind. Carries the boolean flag for the optional `AS description`
    /// clause so the facts-side projection can expose it without
    /// re-walking the AST. New structural facts about ASSERT bodies
    /// (expression shape, referenced tables, …) attach here additively.
    pub bq_assert: Option<IrBqAssertDetail>,
    /// BigQuery `CREATE MODEL` typed identity. Populated only when
    /// this `DdlPlan` originated from
    /// [`crate::ast::AstStmt::BqCreateModel`]; `None` for every other
    /// AST kind. Carries the structural content of the optional
    /// `REMOTE WITH CONNECTION` clause and (when the AS body is a
    /// plain `SELECT`) the body's filter clauses so the facts-side
    /// projection can expose them without re-walking the AST. New
    /// structural facts about CREATE MODEL attach here additively.
    pub bq_create_model: Option<IrBqCreateModelDetail>,
    /// BigQuery `EXPORT DATA` typed identity. Populated only when
    /// this `DdlPlan` originated from
    /// [`crate::ast::AstStmt::BqExportData`]; `None` for every other
    /// AST kind. Carries the structural content of the AS body's
    /// filter clauses so the facts-side projection can expose them
    /// without re-walking the AST. New structural facts about
    /// EXPORT DATA (OPTIONS-derived URI shape, format, …) attach
    /// here additively.
    pub bq_export_data: Option<IrBqExportDataDetail>,
    /// BigQuery / BQ-style credential-bearing options surface. Populated
    /// for any DDL statement that carries an `OPTIONS(key = '<literal>',
    /// …)` clause and/or a `WITH CONNECTION` clause (EXPORT DATA,
    /// LOAD DATA, CREATE/ALTER/EXPORT MODEL, BQ-style CREATE EXTERNAL
    /// TABLE). `None` for Snowflake-style external tables and every
    /// non-BQ DDL kind. Drives the BQ-{EXPORT,LOAD,EXTTBL,MODEL}-
    /// {AWS,PWD,APIKEY,CONNSTR}-LEAK family (secret-leak rules).
    /// Same intent split as CRED-*: structural slots
    /// ([`IrBqOptionsDetail::options`]) for slot-named secrets, flat
    /// literal pool ([`IrBqOptionsDetail::all_literal_values`]) for
    /// content-pattern matching regardless of slot.
    pub bq_options: Option<IrBqOptionsDetail>,
    /// `SHOW [TERSE] <objects> [HISTORY] [LIKE …] [IN …]` typed
    /// recognition. Populated only when this `DdlPlan` originated from
    /// [`crate::ast::AstStmt::Show`]; `None` for every other AST kind.
    /// Carries the normalized object class plus the typed grants
    /// subkind / IN-scope so the facts-side projection can expose them
    /// under `ddl.show.*` without re-walking the AST.
    pub show: Option<ShowPlanIr>,
    /// Present for T-SQL `CREATE SYNONYM`; `None` for every other AST kind.
    /// Carries the referenced base object and its part count so the facts-side
    /// projection can expose `ddl.synonym.*` without re-walking the AST.
    pub synonym: Option<crate::ir::SynonymPlan>,
}

/// IR-internal typed recognition for a `SHOW` statement. The facts-side
/// projection in `crate::facts::extract` curates this into
/// [`crate::facts::ddl::ShowFacts`] at the facts boundary. Names are
/// normalized recognition primitives (upper-case class / relation /
/// kind strings); which values are risky is a policy (YAML) concern.
#[derive(Debug, Clone, PartialEq)]
pub struct ShowPlanIr {
    /// Normalized object class being listed, e.g. `TABLES`, `GRANTS`,
    /// `MASKING_POLICIES`. The long tail is the upper-cased phrase.
    pub object_class: String,
    /// `SHOW TERSE …`.
    pub terse: bool,
    /// `SHOW … HISTORY`.
    pub history: bool,
    /// Present for `SHOW [FUTURE] GRANTS …`.
    pub grants: Option<ShowGrantsIr>,
    /// Present for the `IN <scope>` filter on non-grants statements.
    pub scope: Option<ShowScopeIr>,
}

/// IR-internal typed recognition of a `SHOW [FUTURE] GRANTS …` clause.
#[derive(Debug, Clone, PartialEq)]
pub struct ShowGrantsIr {
    /// `SHOW FUTURE GRANTS …`.
    pub future: bool,
    /// Which side of the grant graph is enumerated:
    /// `CURRENT_USER` | `ON` | `TO` | `OF` | `IN`.
    pub relation: String,
    /// `SHOW GRANTS ON ACCOUNT`.
    pub on_account: bool,
    /// Kind word after the relation — object class for `ON`, principal
    /// kind (`ROLE`/`USER`/`SHARE`/`DATABASE_ROLE`/…) for `TO`/`OF`, or
    /// container kind for `IN`. Upper-cased.
    pub target_kind: Option<String>,
    /// The target / principal / container name as written, when present.
    pub name: Option<String>,
    /// Source span of [`Self::name`].
    pub name_span: Option<Span>,
}

/// IR-internal typed recognition of a SHOW `IN <scope>` filter.
#[derive(Debug, Clone, PartialEq)]
pub struct ShowScopeIr {
    /// Scope kind: `ACCOUNT` | `DATABASE` | `SCHEMA` | `TABLE` | `VIEW`
    /// | any other keyword, upper-cased.
    pub kind: String,
    /// The scope name as written, when present.
    pub name: Option<String>,
    /// Source span of [`Self::name`].
    pub name_span: Option<Span>,
}

/// IR-internal typed identity of the credential-bearing options
/// surface on BQ DDL statements. Holds raw key text and raw literal
/// content; the facts-side projection in
/// `crate::facts::extract::derive_facts_from_bq_ddl_plan` normalizes
/// keys via [`crate::facts::identity::IdentName`] and wraps literals
/// in [`crate::facts::ddl::BqLiteralValue`] at the facts boundary.
#[derive(Debug, Clone, Default)]
pub struct IrBqOptionsDetail {
    /// Every `<key> '=' '<literal>'` pair extracted from credential-
    /// bearing spans, in source order.
    pub options: Vec<IrBqOptionPair>,
    /// Every string-literal value extracted from credential-bearing
    /// spans, in source order. Includes the values already present
    /// in [`Self::options`]; duplication is intentional so content-
    /// pattern rules don't need to traverse the structured pairs.
    pub all_literal_values: Vec<String>,
}

/// IR-internal typed identity of a single `<key> = '<literal>'` option
/// pair from a BQ credential-bearing span.
#[derive(Debug, Clone)]
pub struct IrBqOptionPair {
    /// Raw key text as it appeared in source (whatever case / quoting).
    pub key_raw: String,
    /// Raw string-literal value with surrounding quotes stripped and
    /// `''` escapes unfolded.
    pub value_literal: String,
}

/// IR-side typed identity of an MSSQL `SET <option> <value>` statement.
/// Mirrors the AST closed enums verbatim; the facts layer collapses
/// them to the curated public variants at the facts boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MssqlSetOptionDetail {
    pub option_kind: MssqlSetOptionKindIr,
    pub value: MssqlSetOptionValueIr,
    /// For `SET TRANSACTION ISOLATION LEVEL <level>`: the typed level.
    pub isolation_level: Option<MssqlIsolationLevelIr>,
}

/// T-SQL transaction isolation level recognition (IR sibling of
/// [`crate::ast::AstMssqlIsolationLevel`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MssqlIsolationLevelIr {
    ReadUncommitted,
    ReadCommitted,
    RepeatableRead,
    Snapshot,
    Serializable,
}

/// IR-internal mirror of [`crate::ast::AstMssqlSetOptionKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MssqlSetOptionKindIr {
    IdentityInsert,
    NoCount,
    XactAbort,
    AnsiNulls,
    QuotedIdentifier,
    ArithAbort,
    ConcatNullYieldsNull,
    LockTimeout,
    DeadlockPriority,
    RowCount,
    TransactionIsolationLevel,
    Other,
}

/// IR-internal mirror of [`crate::ast::AstMssqlSetOptionValue`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MssqlSetOptionValueIr {
    On,
    Off,
    NumericLiteral,
    Identifier,
    Unparsed,
}

/// IR-internal typed identity of a BigQuery `ASSERT` statement.
/// Carries the structural content of the optional `AS '<description>'`
/// clause itself — rules compose existence and (future) content
/// predicates against it. Empty / `None` for ASSERTs with no AS clause.
/// The facts-side projection in
/// `crate::facts::extract::derive_facts_from_bq_ddl_plan` curates this
/// into the public [`crate::facts::ddl::BqAssertFacts`].
#[derive(Debug, Clone)]
pub struct IrBqAssertDetail {
    /// Content of the `AS '<description>'` clause when present.
    pub description: Option<IrBqAssertDescription>,
    /// Table references aggregated from every `Box<AstStmt>` subquery
    /// reachable from the ASSERT's predicate expression
    /// (`InSubquery` / `ExistsSubquery` / `QuantifiedSubquery` /
    /// `ScalarSubquery` / `SubqueryArg`). Each subquery is lowered to a
    /// [`super::plan::RelPlan`] and `tables_read` is collected per the
    /// standard query-side projection — so nested subqueries
    /// (e.g. `EXISTS (SELECT … WHERE x IN (SELECT … FROM t))`)
    /// surface transitively. Empty when the assert's expression carries
    /// no subqueries. Drives the
    /// [`crate::facts::query::QueryFacts::reads_table`] projection on
    /// the resulting [`crate::facts::StatementFacts`].
    pub inner_reads_table: Vec<crate::context::node_metadata::TableRef>,
}

/// IR-internal typed identity of a BigQuery ASSERT description clause.
#[derive(Debug, Clone)]
pub struct IrBqAssertDescription {
    /// Raw source text of the description literal (quotes included).
    pub text: String,
}

/// IR-internal typed identity of a BigQuery `CREATE MODEL` statement.
/// Carries the structural content of the optional `REMOTE WITH
/// CONNECTION conn_id` clause and (when the AS body is a simple
/// outermost SELECT) the body's filter-clause structure itself — rules
/// compose existence and (future) content predicates against either.
/// New rule consumers add fields here additively; the facts-side
/// projection in `crate::facts::extract::derive_facts_from_bq_ddl_plan`
/// curates this into the public
/// [`crate::facts::ddl::BqCreateModelFacts`].
#[derive(Debug, Clone)]
pub struct IrBqCreateModelDetail {
    /// Content of the `REMOTE WITH CONNECTION conn_id` clause when
    /// present (BQML remote model).
    pub remote_connection: Option<IrBqRemoteConnection>,
    /// Structural content of the AS body's filtering clauses, when
    /// the body is a plain `SELECT`. `None` for set-op / VALUES
    /// bodies (acceptable gap; widen additively when a leg-
    /// indexed body becomes useful).
    pub body: Option<IrBqQueryBody>,
}

/// IR-internal typed identity of a BigQuery `REMOTE WITH CONNECTION`
/// clause.
#[derive(Debug, Clone)]
pub struct IrBqRemoteConnection {
    /// Raw source text of the connection identifier.
    pub connection_text: String,
}

/// IR-internal typed identity of a BigQuery `EXPORT DATA` statement.
/// Carries the structural content of the AS body's filtering clauses
/// itself — rules compose existence and (future) content predicates
/// against the typed clauses. New rule consumers add fields here
/// additively; the facts-side projection in
/// `crate::facts::extract::derive_facts_from_bq_ddl_plan` curates
/// this into the public [`crate::facts::ddl::BqExportDataFacts`].
#[derive(Debug, Clone)]
pub struct IrBqExportDataDetail {
    /// Structural content of the AS body's filtering clauses, when
    /// the body is a plain `SELECT`. `None` for set-op / VALUES
    /// bodies (acceptable gap; widen additively when a leg-
    /// indexed body becomes useful).
    pub body: Option<IrBqQueryBody>,
}

/// IR-internal typed identity of a BigQuery query body's filtering
/// structure: the optional WHERE / HAVING / QUALIFY clauses on the
/// outermost SELECT. Per-clause Optional content is the structural
/// input; the `BQ-EXPORT-UNBOUNDED` / `BQ-MODEL-UNBOUNDED` rules
/// predicate on each clause's `{ exists: false }` independently.
/// Future rules compose orthogonally on the clause text.
#[derive(Debug, Clone)]
pub struct IrBqQueryBody {
    /// Content of the outermost SELECT's `WHERE <expr>` clause when
    /// present.
    pub where_clause: Option<IrBqFilterClause>,
    /// Content of the outermost SELECT's `HAVING <expr>` clause when
    /// present.
    pub having_clause: Option<IrBqFilterClause>,
    /// Content of the outermost SELECT's `QUALIFY <expr>` clause when
    /// present (Snowflake / BigQuery analytic-function filter).
    pub qualify_clause: Option<IrBqFilterClause>,
}

/// IR-internal typed identity of a single filtering clause
/// (WHERE / HAVING / QUALIFY) on a BigQuery query body.
#[derive(Debug, Clone)]
pub struct IrBqFilterClause {
    /// Raw source text of the filter expression (clause body, without
    /// the leading keyword).
    pub text: String,
}

/// IR-internal typed option bag for `CREATE / ALTER { USER | ROLE |
/// LOGIN }`. Mirrors [`crate::ast::types::CreatePrincipalOptions`] but
/// carries owned string content for the password literal (no
/// borrow back into source) so downstream facts/rule layers don't
/// need access to the original SQL text.
#[derive(Debug, Clone)]
pub struct PrincipalOptionsIr {
    /// Which kind of principal this statement targets.
    pub principal_kind: PrincipalKindIr,
    /// Inner content of a `PASSWORD = '<lit>'` / `IDENTIFIED BY '<lit>'`
    /// clause (no surrounding quotes). `None` if the parser saw no
    /// password clause.
    pub password_literal: Option<String>,
    /// MySQL `'user'@'host'` host literal content (no surrounding
    /// quotes). `None` for non-MySQL or unqualified forms.
    pub mysql_host: Option<String>,
    /// T-SQL `SERVER ROLE` (vs database `ROLE`).
    pub server_scope: bool,
    /// T-SQL `ADD MEMBER <p>` / `DROP MEMBER <p>` clause on ALTER.
    pub membership: Option<PrincipalMembershipIr>,
    /// T-SQL `ENABLE` / `DISABLE` action (`ALTER LOGIN sa DISABLE`).
    pub enabled_state: Option<PrincipalEnabledStateIr>,
    /// PG `CREATE/ALTER ROLE` capability keywords, in source order.
    pub role_attributes: Vec<RoleAttributeIr>,
    /// Snowflake `CREATE/ALTER USER` governance object-properties, with
    /// value spans resolved to owned content. `None` for non-Snowflake
    /// forms (and Snowflake forms carrying none of the properties).
    pub snowflake_user: Option<SnowflakeUserOptionsIr>,
    /// T-SQL `CREATE/ALTER LOGIN` password-policy options, with `ON`/`OFF`
    /// value spans resolved to `bool`. `None` when neither option is
    /// present.
    pub mssql_login: Option<MssqlLoginOptionsIr>,
}

/// IR mirror of [`crate::ast::types::AstMssqlLoginOptions`]. `ON`/`OFF`
/// value spans are resolved to `bool` (`ON` → `true`); a value that is
/// neither projects to `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MssqlLoginOptionsIr {
    pub check_policy: Option<bool>,
    pub check_expiration: Option<bool>,
}

/// IR mirror of [`crate::ast::types::AstSnowflakeUserOptions`]. Value
/// spans are resolved to owned content; numeric properties are parsed to
/// `u64`; boolean properties to `bool`. A property that fails to parse
/// (non-numeric `MINS_TO_*`, non-`TRUE`/`FALSE` boolean) projects to
/// `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnowflakeUserOptionsIr {
    pub default_role: Option<String>,
    pub default_secondary_roles: Option<SecondaryRolesModeIr>,
    pub must_change_password: Option<bool>,
    pub disabled: Option<bool>,
    pub user_type: Option<String>,
    pub mins_to_bypass_mfa: Option<u64>,
    pub days_to_expiry: Option<u64>,
    pub mins_to_unlock: Option<u64>,
    pub rsa_public_key_set: bool,
    pub rsa_public_key_2_set: bool,
    pub network_policy: Option<String>,
}

/// IR mirror of [`crate::ast::types::AstSecondaryRolesMode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecondaryRolesModeIr {
    All,
    None,
}

/// IR mirror of [`crate::ast::AstRoleAttribute`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoleAttributeIr {
    pub kind: RoleAttributeKindIr,
    pub negated: bool,
}

/// IR mirror of [`crate::ast::AstRoleAttributeKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleAttributeKindIr {
    Superuser,
    CreateDb,
    CreateRole,
    Login,
    Inherit,
    Replication,
    BypassRls,
}

/// IR-internal mirror of [`crate::ast::types::AstPrincipalMembership`],
/// with the member name owned (no borrow back into source).
#[derive(Debug, Clone)]
pub struct PrincipalMembershipIr {
    pub action: PrincipalMembershipActionIr,
    /// Member principal name text as spelled (quoting stripped at the
    /// facts projection, not here).
    pub member: String,
}

/// Whether the membership clause adds or removes the member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrincipalMembershipActionIr {
    AddMember,
    DropMember,
}

/// IR-internal mirror of [`crate::ast::types::AstPrincipalEnabledState`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrincipalEnabledStateIr {
    Enable,
    Disable,
}

/// IR-internal mirror of [`crate::ast::types::PrincipalKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrincipalKindIr {
    User,
    Role,
    Login,
    /// Redshift permission `GROUP` (see [`crate::ast::types::PrincipalKind::Group`]).
    Group,
    /// MSSQL `APPLICATION ROLE` (see
    /// [`crate::ast::types::PrincipalKind::ApplicationRole`]).
    ApplicationRole,
    /// Snowflake `DATABASE ROLE` (see
    /// [`crate::ast::types::PrincipalKind::DatabaseRole`]).
    DatabaseRole,
}

/// IR-internal mirror of [`crate::ast::AstMssqlPrincipalSource`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MssqlPrincipalSourceIr {
    FromExternalProvider,
    WithPassword,
    FromCertificate,
    FromAsymmetricKey,
    FromWindows,
    ForLogin,
    WithoutLogin,
    Unparsed,
}

impl DdlPlan {
    /// Source span of this DDL plan.
    pub fn span(&self) -> Span {
        self.span
    }

    /// Project this DDL plan's typed `(action, object)` discriminator
    /// to the matching public
    /// [`crate::facts::statement::StatementKind`].
    ///
    /// Returns `None` for `(action, object)` pairs the diff/facts
    /// engines don't yet have a [`StatementKind`](crate::facts::statement::StatementKind) variant for —
    /// callers treat `None` as "kind is opaque, suppress kind-keyed
    /// projections" rather than as an error. Expand additively as new
    /// pair-emission needs arise.
    pub fn statement_kind(&self) -> Option<crate::facts::statement::StatementKind> {
        use crate::facts::identity::ObjectKind as O;
        use crate::facts::statement::StatementKind as K;
        use DdlAction as A;
        // SHOW carries a populated `show` sibling regardless of object kind;
        // DESCRIBE shares the verb but has no sibling and stays Opaque.
        if matches!(self.action, A::Configure) && self.show.is_some() {
            return Some(K::Show);
        }
        let kind = match (self.action, &self.object_kind) {
            (A::Create, O::Table) => K::CreateTable,
            (A::Alter, O::Table) => K::AlterTable,
            (A::Drop, O::Table) => K::DropTable,
            (A::Truncate, O::Table) => K::Truncate,
            (A::Create, O::View) => K::CreateView,
            (A::Alter, O::View) => K::AlterView,
            (A::Drop, O::View) => K::DropView,
            (A::Create, O::MaterializedView) => K::CreateMaterializedView,
            (A::Alter, O::MaterializedView) => K::AlterMaterializedView,
            (A::Drop, O::MaterializedView) => K::DropMaterializedView,
            (A::Create, O::DynamicTable) => K::CreateDynamicTable,
            (A::Alter, O::DynamicTable) => K::AlterDynamicTable,
            (A::Drop, O::DynamicTable) => K::DropDynamicTable,
            (A::Create, O::Procedure) => K::CreateProcedure,
            (A::Alter, O::Procedure) => K::AlterProcedure,
            (A::Drop, O::Procedure) => K::DropProcedure,
            (A::Create, O::Function) => K::CreateFunction,
            (A::Alter, O::Function) => K::AlterFunction,
            (A::Drop, O::Function) => K::DropFunction,
            (A::Create, O::Trigger) => K::CreateTrigger,
            (A::Alter, O::Trigger) => K::AlterTrigger,
            (A::Drop, O::Trigger) => K::DropTrigger,
            (A::Create, O::Schema) => K::CreateSchema,
            (A::Alter, O::Schema) => K::AlterSchema,
            (A::Drop, O::Schema) => K::DropSchema,
            (A::Create, O::Database) => K::CreateDatabase,
            (A::Alter, O::Database) => K::AlterDatabase,
            (A::Drop, O::Database) => K::DropDatabase,
            (A::Create, O::Index) => K::CreateIndex,
            (A::Alter, O::Index) => K::AlterIndex,
            (A::Create, O::Synonym) => K::CreateSynonym,
            (A::Create, O::Stage) => K::CreateStage,
            (A::Alter, O::Stage) => K::AlterStage,
            (A::Drop, O::Stage) => K::DropStage,
            (A::Create, O::Task) => K::CreateTask,
            (A::Alter, O::Task) => K::AlterTask,
            (A::Drop, O::Task) => K::DropTask,
            (A::Create, O::Warehouse) => K::CreateWarehouse,
            (A::Alter, O::Warehouse) => K::AlterWarehouse,
            (A::Drop, O::Warehouse) => K::DropWarehouse,
            (A::Create, O::Pipe) => K::CreatePipe,
            (A::Alter, O::Pipe) => K::AlterPipe,
            (A::Drop, O::Pipe) => K::DropPipe,
            (A::Create, O::Stream) => K::CreateStream,
            (A::Alter, O::Stream) => K::AlterStream,
            (A::Drop, O::Stream) => K::DropStream,
            (A::Create, O::Role) => K::CreateRole,
            (A::Alter, O::Role) => K::AlterRole,
            (A::Drop, O::Role) => K::DropRole,
            (A::Create, O::User) => K::CreateUser,
            (A::Alter, O::User) => K::AlterUser,
            (A::Drop, O::User) => K::DropUser,
            (A::Create, O::Group) => K::CreateGroup,
            (A::Alter, O::Group) => K::AlterGroup,
            (A::Alter, O::Account) => K::AlterAccount,
            (A::Create, O::Share) => K::CreateShare,
            (A::Alter, O::Share) => K::AlterShare,
            (A::Create, O::Datashare) => K::CreateDatashare,
            (A::Alter, O::Datashare) => K::AlterDatashare,
            (A::Create, O::ExternalSchema) => K::CreateExternalSchema,
            (A::Create, O::SecurityIntegration) => K::CreateSecurityIntegration,
            (A::Alter, O::SecurityIntegration) => K::AlterSecurityIntegration,
            (A::Alter, O::ReplicationGroup) => K::AlterReplicationGroup,
            (A::Alter, O::FailoverGroup) => K::AlterFailoverGroup,
            _ => return None,
        };
        Some(kind)
    }
}

/// Typed per-element ALTER-action identity carried on
/// [`DdlPlan::schema_mutations`].
///
/// Closed enum; adding a variant is a design action. The variants
/// here cover the three ALTER actions whose downstream consumers
/// need element identity beyond a per-category boolean:
/// [`AstAlterTableActionKind::RenameTo`],
/// [`AstAlterTableActionKind::AddColumn`], and
/// [`AstAlterTableActionKind::DropColumn`]. Other ALTER variants are
/// represented at the IR layer only via their per-category aggregate
/// flags on [`super::table_plan::TableAlterFlags`].
///
/// [`AstAlterTableActionKind::RenameTo`]: crate::ast::AstAlterTableActionKind::RenameTo
/// [`AstAlterTableActionKind::AddColumn`]: crate::ast::AstAlterTableActionKind::AddColumn
/// [`AstAlterTableActionKind::DropColumn`]: crate::ast::AstAlterTableActionKind::DropColumn
#[derive(Debug, Clone)]
pub enum DdlSchemaMutation {
    /// `ALTER TABLE x RENAME TO y` — the table identity changes.
    /// `new_target` is the parsed `y` qualified name. `source` is the
    /// renamed table when it differs from the plan target (MySQL
    /// `RENAME TABLE` pairs 2+); `None` means the plan target renames.
    RenameTo {
        new_target: DdlTarget,
        source: Option<DdlTarget>,
    },
    /// `ALTER TABLE x ADD COLUMN col …` — column count grows.
    /// `column_name` is the un-normalized identifier text from the
    /// AST; normalization happens at consumer lookup time.
    AddColumn { column_name: String },
    /// `ALTER TABLE x DROP COLUMN col` — column count shrinks.
    /// `column_name` is the un-normalized identifier text from the
    /// AST.
    DropColumn { column_name: String },
}

/// Abstract verb performed by a DDL statement.
///
/// Closed enum — adding a variant is a design action, not a
/// drive-by PR. Variants are kept lean: similar verbs collapse
/// into one entry (e.g. `Configure` covers both `SET` and `USE`)
/// and only split when an emitter actually needs to discriminate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DdlAction {
    /// `CREATE …` — bring an object into existence.
    Create,
    /// `ALTER …` — modify an existing object's properties.
    Alter,
    /// `DROP …` — remove an object.
    Drop,
    /// `RENAME …` (when not folded into `ALTER`).
    Rename,
    /// `TRUNCATE …` — remove all rows without dropping the
    /// container.
    Truncate,
    /// `COMMENT ON …` — attach metadata.
    Comment,
    /// `REFRESH …` — recompute a materialized object.
    Refresh,
    /// `GRANT …` — confer privileges.
    Grant,
    /// `REVOKE …` / `DENY …` — withdraw privileges.
    Revoke,
    /// `EXEC` / `CALL` / `EXECUTE IMMEDIATE` — invoke procedural
    /// or dynamic code.
    Execute,
    /// `SET <option>` / `USE <database|schema|role>` — session or
    /// connection-state change.
    Configure,
    /// Procedural control flow: `BEGIN .. END` blocks, `IF`,
    /// `WHILE`, `FOR`, `RETURN`, `RAISE` / `SIGNAL` / `RESIGNAL`.
    ControlFlow,
    /// Transaction boundary: `BEGIN TRANSACTION`, `COMMIT`,
    /// `ROLLBACK`, `SAVEPOINT`.
    Transaction,
    /// Bulk data-loading statements (`COPY`, `BULK INSERT`).
    BulkLoad,
    /// `BACKUP DATABASE` / `BACKUP LOG` — data-protection export.
    Backup,
    /// `RESTORE DATABASE` / `RESTORE LOG` — data-protection import.
    Restore,
}

/// Database-object target of a DDL statement.
///
/// Three-part identity (`db.schema.name`) plus the source span
/// of the name token(s). Components beyond `name` are populated
/// only when the statement spelled them out — qualifier inference
/// from session/env is a consumer concern.
#[derive(Debug, Clone)]
pub struct DdlTarget {
    /// Bare object name (last identifier component).
    pub name: String,
    /// Schema component when present.
    pub schema: Option<String>,
    /// Database component when present.
    pub db: Option<String>,
    /// Source span of the (qualified) name in the original SQL.
    pub span: Span,
}

/// Typed flag bag for DDL options.
///
/// All flags default to `false`. New flags are added inline as
/// statements need them; the flags surface here
/// is the typed alternative to a string-keyed property map.
#[derive(Debug, Clone, Default)]
pub struct DdlOptions {
    /// `CREATE OR REPLACE …`.
    pub or_replace: bool,
    /// `CREATE … IF NOT EXISTS` / `DROP … IF EXISTS`.
    pub if_exists: bool,
    /// `CREATE … IF NOT EXISTS`. Distinguished from `if_exists`
    /// because `DROP IF EXISTS` and `CREATE IF NOT EXISTS` carry
    /// different signal semantics.
    pub if_not_exists: bool,
    /// `CREATE TEMPORARY …` / `CREATE TEMP …`.
    pub temporary: bool,
    /// `CREATE TRANSIENT …` (Snowflake).
    pub transient: bool,
    /// `CREATE … RECURSIVE` (PG / standard SQL).
    pub recursive: bool,
    /// `EXEC` invocation that takes a string literal/variable
    /// instead of a stored-proc name (dynamic SQL).
    pub dynamic_sql: bool,
    /// `DROP … CASCADE`. Populated by family lowerings that surface
    /// the discriminator on a typed AST node (e.g. `DROP DOMAIN x
    /// CASCADE`). Defaults to `false` for every other lowering path.
    pub cascade: bool,
    /// `DROP … RESTRICT` (the SQL default when neither CASCADE nor
    /// RESTRICT appears). Tracked separately from `!cascade` so the
    /// facts projection can distinguish "explicit RESTRICT" from
    /// "neither keyword present".
    pub restrict: bool,
}

/// Typed sibling carrier for `ALTER DOMAIN`. Lives on
/// [`DdlPlan::domain`]; `None` for every other AST kind. The action
/// list is a `Vec` for parallel-shape consistency with
/// [`crate::facts::ddl::SchemaFacts::actions`] /
/// [`crate::facts::ddl::CatalogFacts::actions`], even though
/// Postgres's `ALTER DOMAIN` grammar only permits one action per
/// statement (so the Vec has length 0 or 1 in practice).
#[derive(Debug, Clone, Default)]
pub struct IrDomainDetail {
    pub actions: Vec<IrDomainAlterAction>,
}

/// IR-side typed identity of a single `ALTER DOMAIN <action>` clause.
/// 1:1 mirror of [`crate::ast::AlterDomainAction`] variants; the
/// facts boundary in [`crate::facts::extract`] curates this 11-variant
/// enum down to the public 6-variant
/// [`crate::facts::ddl::DomainAlterAction`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrDomainAlterAction {
    SetDefault,
    DropDefault,
    SetNotNull,
    DropNotNull,
    AddConstraint,
    /// `DROP CONSTRAINT [IF EXISTS] name [RESTRICT | CASCADE]`. The
    /// `cascade` flag carries the per-action discriminator; the
    /// statement-level [`DdlOptions::cascade`] tracks `DROP DOMAIN x
    /// CASCADE`, which is a different SQL surface.
    DropConstraint {
        cascade: bool,
    },
    RenameConstraint,
    ValidateConstraint,
    OwnerTo,
    RenameTo,
    SetSchema,
}

/// Typed sibling carrier for `ALTER INDEX`. Lives on
/// [`DdlPlan::pg_index`]; `None` for every other AST kind. The
/// `action` is a single value, matching the Postgres grammar (one
/// sub-action per `ALTER INDEX` statement). Parallel-shape sibling of
/// [`IrDomainDetail`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IrIndexDetail {
    pub action: IrIndexAlterAction,
}

/// IR-side typed identity of a single `ALTER INDEX <action>` clause.
/// 1:1 mirror of [`crate::ast::AlterIndexSubAction`] variants plus the
/// top-level [`crate::ast::AlterIndexAction::AllInTablespace`] form;
/// the facts boundary in [`crate::facts::extract`] curates this
/// 8-variant enum down to the public 2-variant
/// [`crate::facts::ddl::IndexAlterAction`] (`RenameTo` + `Other`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrIndexAlterAction {
    /// `ALTER INDEX … RENAME TO …`. Drives PG-IDX-NAME-CHG.
    RenameTo,
    /// `ALTER INDEX … SET TABLESPACE …`.
    SetTablespace,
    /// `ALTER INDEX … ATTACH PARTITION …`.
    AttachPartition,
    /// `ALTER INDEX … [NO] DEPENDS ON EXTENSION …`.
    DependsOnExtension,
    /// `ALTER INDEX … SET (param = value [, …])`.
    SetParams,
    /// `ALTER INDEX … RESET (param [, …])`.
    ResetParams,
    /// `ALTER INDEX … ALTER [COLUMN] column SET STATISTICS integer`.
    AlterColumnStatistics,
    /// `ALTER INDEX ALL IN TABLESPACE name [OWNED BY role[, …]] SET
    /// TABLESPACE new_ts [NOWAIT]` — bulk tablespace move across all
    /// indexes in a source tablespace.
    AllInTablespace,
    /// T-SQL `ALTER INDEX … ON object REBUILD …`.
    Rebuild,
    /// T-SQL `ALTER INDEX … ON object REORGANIZE …`.
    Reorganize,
    /// T-SQL `ALTER INDEX … ON object DISABLE`.
    Disable,
    /// T-SQL `ALTER INDEX … ON object SET (…)`.
    SetOptions,
}

/// Typed sibling carrier for `ALTER TRIGGER`. Lives on
/// [`DdlPlan::pg_trigger`]; `None` for every other AST kind. The
/// `action` is a single value, matching the Postgres grammar (one
/// sub-action per `ALTER TRIGGER` statement). Parallel-shape sibling
/// of [`IrIndexDetail`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IrTriggerDetail {
    pub action: IrTriggerAlterAction,
}

/// IR-side typed identity of a single `ALTER TRIGGER <action>` clause.
/// 1:1 mirror of [`crate::ast::PgAlterTriggerAction`] variants; the
/// facts boundary in [`crate::facts::extract`] curates this 2-variant
/// enum down to the public 2-variant
/// [`crate::facts::ddl::TriggerAlterAction`] (`RenameTo` + `Other`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrTriggerAlterAction {
    /// `ALTER TRIGGER … RENAME TO …`. Drives PG-TRIG-NAME-CHG.
    RenameTo,
    /// `ALTER TRIGGER … [NO] DEPENDS ON EXTENSION …`.
    DependsOnExtension,
}

/// Typed sibling carrier for `ALTER TABLE … {ENABLE|DISABLE}
/// TRIGGER …`. Lives on [`DdlPlan::pg_trigger_state`]; `None` for
/// every other AST kind. Parallel-shape sibling of [`IrTriggerDetail`]
/// — different action vocabulary, different SQL surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IrTriggerStateDetail {
    pub action: IrTriggerStateAction,
}

/// IR-side typed identity of a single `ALTER TABLE … TRIGGER state`
/// action. 1:1 mirror of
/// [`crate::ast::PgAlterTableTriggerStateAction`] variants; the facts
/// boundary in [`crate::facts::extract`] curates this 4-variant enum
/// down to the public 2-variant
/// [`crate::facts::ddl::TriggerStateAction`] (`Enable` + `Disable`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrTriggerStateAction {
    /// `DISABLE TRIGGER`. Drives PG-TRIG-OFF.
    Disable,
    /// `ENABLE TRIGGER` — default firing.
    Enable,
    /// `ENABLE ALWAYS TRIGGER`.
    EnableAlways,
    /// `ENABLE REPLICA TRIGGER`.
    EnableReplica,
}

/// Typed sibling carrier for `SET` / `RESET` session-config
/// statements. Lives on [`DdlPlan::pg_session`]; `None` for every
/// other AST kind. Distinct from [`IrTriggerStateDetail`] and from
/// the DDL alter-action carriers — `SET`/`RESET` is session config,
/// not DDL semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IrPgSessionDetail {
    pub action: IrPgSessionAction,
}

/// IR-side typed identity of a `SET` / `RESET` statement. 1:1 mirror
/// of [`crate::ast::PgSetKind`]; the facts boundary curates this
/// 9-variant enum down to the public 3-variant
/// [`crate::facts::ddl::PgSessionAction`] (`SetRole` +
/// `SetSessionAuthorization` + `Other`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrPgSessionAction {
    SetRole,
    SetSessionAuthorization,
    SetSearchPath,
    SetParameter,
    ResetRole,
    ResetSessionAuthorization,
    ResetSearchPath,
    ResetParameter,
    ResetAll,
}
