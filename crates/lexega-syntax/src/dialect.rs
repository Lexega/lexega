// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! SQL Dialect abstraction
//!
//! This module defines the `Dialect` trait which describes dialect-specific
//! SQL behavior: keywords, identifier and string quoting, comment forms,
//! operators, and the grammar shape of statements that diverge between
//! dialects.
//!
//! # Philosophy: Parse Permissively
//!
//! The lexer asks the dialect how to tokenize. The parser asks it capability
//! questions — whether `||` concatenates, which `GRANT` grammar applies —
//! where one token sequence means different things in different dialects,
//! and never asks for its name. It does not reject a statement for belonging
//! to another dialect, and the formatter preserves whatever was parsed.
//! Dialect validation is left to the database at execution time.
//!
//! This approach:
//! - Avoids being an incorrect gatekeeper
//! - Handles real-world SQL that mixes dialect features
//! - Lets authoritative database errors guide users

use std::sync::Arc;

use crate::ast::AstStmt;

/// Stack-allocated ASCII uppercase copy of a word, for keyword matching
/// without the heap allocation `str::to_uppercase()` costs on every call.
///
/// SQL keywords are pure ASCII and shorter than the buffer, so a word that
/// is longer or holds a non-ASCII byte is kept as the empty string, which
/// matches no keyword.
pub(crate) struct AsciiUpper {
    buf: [u8; 64],
    len: usize,
}

impl AsciiUpper {
    #[inline]
    pub(crate) fn new(word: &str) -> Self {
        let bytes = word.as_bytes();
        let mut buf = [0u8; 64];
        if bytes.len() > buf.len() || !bytes.is_ascii() {
            return AsciiUpper { buf, len: 0 };
        }
        for (slot, byte) in buf.iter_mut().zip(bytes) {
            *slot = byte.to_ascii_uppercase();
        }
        AsciiUpper {
            buf,
            len: bytes.len(),
        }
    }

    #[inline]
    pub(crate) fn as_str(&self) -> &str {
        // The buffer holds ASCII only, which is always valid UTF-8.
        std::str::from_utf8(&self.buf[..self.len]).unwrap_or_default()
    }
}

/// One argument of a call that a dialect reads as no value
/// ([`Dialect::non_value_arguments`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NonValueArgument {
    /// Its position among the call's written arguments, from 0.
    pub position: usize,
    /// What is written there.
    pub kind: NonValueKind,
    /// The number of arguments the call must have for this one to be read
    /// so; `None` for any number.
    pub arity: Option<usize>,
}

/// What a [`NonValueArgument`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonValueKind {
    /// A data type: `CONVERT(INT, x)`.
    DataType,
    /// A date or time part, as [`Dialect::date_part`] reads it.
    DatePart,
    /// A Unicode normalization form: `NORMALIZE(s, NFKC)`.
    NormalForm,
}

/// What a routine the dialect defines does with an argument it takes
/// ([`Dialect::system_routine`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgumentUse {
    /// A name, an option or a value it reads: nothing it runs.
    Value,
    /// The name of a principal, a role, an option, an object or a file, or
    /// an option's numeric setting: never a credential, so a report shows
    /// it.
    Name,
    /// A boolean option: nothing it runs.
    Flag,
    /// SQL text it runs in the session.
    RunsSql,
    /// SQL text it sends another server to run.
    RunsSqlRemotely,
    /// An operating-system command, or text a job runs later.
    Command,
    /// A password.
    Credential,
    /// A connection string, or the name of a connection, whose secret
    /// values are credentials.
    ConnectionString,
}

impl ArgumentUse {
    /// Whether the routine runs the argument as SQL text, here or on
    /// another server.
    pub fn runs_sql(self) -> bool {
        match self {
            ArgumentUse::RunsSql | ArgumentUse::RunsSqlRemotely => true,
            ArgumentUse::Value
            | ArgumentUse::Name
            | ArgumentUse::Flag
            | ArgumentUse::Command
            | ArgumentUse::Credential
            | ArgumentUse::ConnectionString => false,
        }
    }
}

/// A parameter of a routine the dialect defines: its documented name,
/// with no `@`, and what the routine does with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemParameter {
    pub name: &'static str,
    pub reads: ArgumentUse,
}

/// One way a routine the dialect defines is called: its parameters in
/// order, how many of them every call gives, and what it does with each
/// argument past them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemForm {
    pub parameters: &'static [SystemParameter],
    pub required: usize,
    /// `None` where it takes no more.
    pub rest: Option<ArgumentUse>,
}

/// A routine the dialect defines, with each way it is called.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemRoutine {
    pub name: &'static str,
    pub forms: &'static [SystemForm],
}

/// A routine the dialect defines that renames an object
/// ([`Dialect::rename_routine`]), by the names of its parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RenameRoutine {
    /// The routine, one of [`Dialect::system_routines`].
    pub name: &'static str,
    /// The object's name as it stands; a column's, its table's name and
    /// its own.
    pub object: &'static str,
    /// The object's new name, its own part alone.
    pub new_name: &'static str,
    /// The kind of object, where the call gives one.
    pub kind: &'static str,
    /// The kind written for a column, in any case.
    pub column_kind: &'static str,
}

/// A place in a statement's grammar whose string literal names a format, a
/// setting or a description, and never a credential, a command or SQL
/// text ([`Dialect::shown_slots`]): the literal written straight after
/// `keyword`'s words, with an `=` or, for a call, a `(` between them, in a
/// statement of the kinds `statement` names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShownSlot {
    /// The statements the slot is part of.
    pub statement: SlotStatement,
    /// The words before the literal, in order.
    pub keyword: &'static [&'static str],
    /// How the literal follows the words.
    pub follows: SlotFollows,
    /// What the literal holds.
    pub holds: SlotHolds,
}

/// The statements a [`ShownSlot`] is part of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotStatement {
    /// Any statement: the slot is a call (`IDENTIFIER('…')`).
    Any,
    /// A statement that creates or alters an object.
    Definition,
    /// `COMMENT ON … IS`.
    CommentOn,
    /// A file format's, a stage's, an external table's, a pipe's, a load's
    /// or an unload's options.
    FileFormat,
    /// A load or an unload: `COPY`, `UNLOAD`, a pipe's `COPY`.
    Copy,
    /// `CREATE | ALTER WAREHOUSE`.
    Warehouse,
    /// A task's or an alert's definition.
    Schedule,
    /// `CREATE | ALTER DYNAMIC TABLE`.
    DynamicTable,
    /// `CREATE | ALTER EXTERNAL VOLUME`.
    Volume,
    /// `CREATE | ALTER NETWORK POLICY`.
    NetworkPolicy,
    /// `CREATE | ALTER NETWORK RULE`.
    NetworkRule,
    /// A user's or a role's definition, or a change to one.
    Principal,
    /// A change to the session's, the account's or a user's parameters.
    Parameters,
    /// `CREATE | ALTER STAGE`.
    Stage,
    /// `CREATE | ALTER DATABASE`.
    Database,
    /// `CREATE | ALTER API INTEGRATION`.
    ApiIntegration,
    /// `CREATE | ALTER STORAGE INTEGRATION`.
    StorageIntegration,
    /// A grant or a revoke.
    Grant,
    /// `CREATE ROW ACCESS POLICY`.
    RowAccessPolicy,
    /// A statement naming an account written as a string (MySQL's
    /// `'user'@'host'`): a user's or a role's definition, change or
    /// removal or renaming, a grant, a revoke, a `SHOW GRANTS FOR`, a `SET ROLE`
    /// or `SET PASSWORD FOR`.
    NamedAccount,
    /// A query that writes its rows to a file (`SELECT … INTO OUTFILE`).
    Query,
    /// `LOAD DATA`, or a query's `INTO OUTFILE` options.
    LoadData,
    /// A statement loading a shared library: MySQL's `CREATE FUNCTION …
    /// SONAME`, `INSTALL PLUGIN … SONAME`.
    Library,
    /// `EXECUTE AS`, alone or as a routine's or a trigger's option.
    ExecuteAs,
    /// `SETUSER`.
    Setuser,
    /// BigQuery's `EXPORT DATA`, `LOAD DATA` and external tables.
    Export,
    /// `ALTER TABLE`.
    AlterTable,
    /// PostgreSQL's `SET`.
    Set,
}

impl SlotStatement {
    /// Whether `stmt` is one of the statements this names.
    pub fn holds(self, stmt: &AstStmt) -> bool {
        match self {
            SlotStatement::Any => true,
            SlotStatement::Definition => defines_an_object(stmt),
            SlotStatement::CommentOn => matches!(stmt, AstStmt::CommentOn(_)),
            SlotStatement::FileFormat => {
                matches!(
                    stmt,
                    AstStmt::CreateFileFormat(_)
                        | AstStmt::AlterFileFormat(_)
                        | AstStmt::CreateStage(_)
                        | AstStmt::AlterStage(_)
                        | AstStmt::CreateExternalTable(_)
                        | AstStmt::CreatePipe(_)
                ) || SlotStatement::Copy.holds(stmt)
            }
            SlotStatement::Copy => matches!(
                stmt,
                AstStmt::CopyIntoTable { .. }
                    | AstStmt::CopyIntoLocation { .. }
                    | AstStmt::CreatePipe(_)
                    | AstStmt::PgCopy(_)
                    | AstStmt::RedshiftCopy { .. }
                    | AstStmt::Unload { .. }
            ),
            SlotStatement::Warehouse => matches!(
                stmt,
                AstStmt::CreateWarehouse(_) | AstStmt::AlterWarehouse(_)
            ),
            SlotStatement::Schedule => matches!(
                stmt,
                AstStmt::CreateTask(_)
                    | AstStmt::AlterTask(_)
                    | AstStmt::CreateAlert(_)
                    | AstStmt::AlterAlert(_)
            ),
            SlotStatement::DynamicTable => matches!(
                stmt,
                AstStmt::CreateDynamicTable(_) | AstStmt::AlterDynamicTable(_)
            ),
            SlotStatement::Volume => {
                matches!(stmt, AstStmt::CreateVolume(_) | AstStmt::AlterVolume(_))
            }
            SlotStatement::NetworkPolicy => matches!(
                stmt,
                AstStmt::CreateNetworkPolicy(_) | AstStmt::AlterNetworkPolicy(_)
            ),
            SlotStatement::NetworkRule => matches!(
                stmt,
                AstStmt::CreateNetworkRule(_) | AstStmt::AlterNetworkRule(_)
            ),
            SlotStatement::Principal => matches!(
                stmt,
                AstStmt::CreatePrincipal(_) | AstStmt::AlterPrincipal(_) | AstStmt::AlterUser(_)
            ),
            SlotStatement::Parameters => {
                matches!(stmt, AstStmt::AlterSession(_) | AstStmt::AlterAccount(_))
                    || SlotStatement::Principal.holds(stmt)
            }
            SlotStatement::Stage => {
                matches!(stmt, AstStmt::CreateStage(_) | AstStmt::AlterStage(_))
            }
            SlotStatement::Database => {
                matches!(stmt, AstStmt::CreateDatabase(_) | AstStmt::AlterDatabase(_))
            }
            SlotStatement::ApiIntegration => matches!(
                stmt,
                AstStmt::CreateApiIntegration(_) | AstStmt::AlterApiIntegration(_)
            ),
            SlotStatement::StorageIntegration => matches!(
                stmt,
                AstStmt::CreateStorageIntegration(_) | AstStmt::AlterStorageIntegration(_)
            ),
            SlotStatement::Grant => matches!(stmt, AstStmt::Grant(_) | AstStmt::Revoke(_)),
            SlotStatement::RowAccessPolicy => matches!(stmt, AstStmt::CreateRowAccessPolicy(_)),
            SlotStatement::NamedAccount => {
                matches!(
                    stmt,
                    AstStmt::DropPrincipal(_)
                        | AstStmt::Drop(_)
                        | AstStmt::MysqlSet(_)
                        | AstStmt::MysqlAdmin(_)
                        | AstStmt::Show(_)
                ) || SlotStatement::Principal.holds(stmt)
                    || SlotStatement::Grant.holds(stmt)
            }
            SlotStatement::Query => matches!(
                stmt,
                AstStmt::Select(_) | AstStmt::SetSelect(_) | AstStmt::ValuesQuery(_)
            ),
            SlotStatement::LoadData => {
                matches!(stmt, AstStmt::MysqlLoadData(_)) || SlotStatement::Query.holds(stmt)
            }
            SlotStatement::Library => matches!(
                stmt,
                AstStmt::MysqlCreateLoadableFunction(_) | AstStmt::MysqlAdmin(_)
            ),
            SlotStatement::ExecuteAs => matches!(
                stmt,
                AstStmt::MssqlExecuteAs(_)
                    | AstStmt::CreateProcedure(_)
                    | AstStmt::CreateFunction(_)
                    | AstStmt::CreateMssqlTrigger(_)
            ),
            SlotStatement::Setuser => matches!(stmt, AstStmt::MssqlSetuser(_)),
            SlotStatement::Export => matches!(
                stmt,
                AstStmt::BqExportData(_) | AstStmt::BqLoadData(_) | AstStmt::CreateExternalTable(_)
            ),
            SlotStatement::AlterTable => matches!(stmt, AstStmt::AlterTable(_)),
            SlotStatement::Set => matches!(stmt, AstStmt::PgSet(_)),
        }
    }
}

/// Whether `stmt` creates or alters an object.
fn defines_an_object(stmt: &AstStmt) -> bool {
    matches!(
        stmt,
        AstStmt::AlterAccount(_)
            | AstStmt::AlterAggregationPolicy(_)
            | AstStmt::AlterAlert(_)
            | AstStmt::AlterApiIntegration(_)
            | AstStmt::AlterApplication(_)
            | AstStmt::AlterApplicationPackage(_)
            | AstStmt::AlterAuthenticationPolicy(_)
            | AstStmt::AlterCatalog(_)
            | AstStmt::AlterComputePool(_)
            | AstStmt::AlterConnection(_)
            | AstStmt::AlterCortexSearchService(_)
            | AstStmt::AlterDatabase(_)
            | AstStmt::AlterDatashare(_)
            | AstStmt::AlterDomain(_)
            | AstStmt::AlterDynamicTable(_)
            | AstStmt::AlterEvent(_)
            | AstStmt::AlterExternalAccessIntegration(_)
            | AstStmt::AlterExternalLocation(_)
            | AstStmt::AlterFailoverGroup(_)
            | AstStmt::AlterFileFormat(_)
            | AstStmt::AlterForeignServer(_)
            | AstStmt::AlterFunction(_)
            | AstStmt::AlterGitRepository(_)
            | AstStmt::AlterImageRepository(_)
            | AstStmt::AlterIndex(_)
            | AstStmt::AlterJoinPolicy(_)
            | AstStmt::AlterListing(_)
            | AstStmt::AlterMaskingPolicy(_)
            | AstStmt::AlterMaterializedView(_)
            | AstStmt::AlterNetworkPolicy(_)
            | AstStmt::AlterNetworkRule(_)
            | AstStmt::AlterNotebook(_)
            | AstStmt::AlterNotificationIntegration(_)
            | AstStmt::AlterPasswordPolicy(_)
            | AstStmt::AlterPgPolicy(_)
            | AstStmt::AlterPgTrigger(_)
            | AstStmt::AlterPipe(_)
            | AstStmt::AlterPrincipal(_)
            | AstStmt::AlterProcedure(_)
            | AstStmt::AlterProjectionPolicy(_)
            | AstStmt::AlterReplicationGroup(_)
            | AstStmt::AlterResourceMonitor(_)
            | AstStmt::AlterRowAccessPolicy(_)
            | AstStmt::AlterSchema(_)
            | AstStmt::AlterSecret(_)
            | AstStmt::AlterSecurityIntegration(_)
            | AstStmt::AlterSemanticView(_)
            | AstStmt::AlterSequence(_)
            | AstStmt::AlterService(_)
            | AstStmt::AlterSessionPolicy(_)
            | AstStmt::AlterShare(_)
            | AstStmt::AlterStage(_)
            | AstStmt::AlterStorageCredential(_)
            | AstStmt::AlterStorageIntegration(_)
            | AstStmt::AlterStream(_)
            | AstStmt::AlterStreamlit(_)
            | AstStmt::AlterTable(_)
            | AstStmt::AlterTag(_)
            | AstStmt::AlterTask(_)
            | AstStmt::AlterType(_)
            | AstStmt::AlterUser(_)
            | AstStmt::AlterUserMapping(_)
            | AstStmt::AlterView(_)
            | AstStmt::AlterVolume(_)
            | AstStmt::AlterWarehouse(_)
            | AstStmt::BqAlterModel(_)
            | AstStmt::BqAlterVectorIndex(_)
            | AstStmt::BqCreateModel(_)
            | AstStmt::BqCreateSearchIndex(_)
            | AstStmt::BqCreateSnapshotTable(_)
            | AstStmt::BqCreateVectorIndex(_)
            | AstStmt::CreateAccount(_)
            | AstStmt::CreateAggregationPolicy(_)
            | AstStmt::CreateAlert(_)
            | AstStmt::CreateApiIntegration(_)
            | AstStmt::CreateApplication(_)
            | AstStmt::CreateApplicationPackage(_)
            | AstStmt::CreateAuthenticationPolicy(_)
            | AstStmt::CreateCatalog(_)
            | AstStmt::CreateComputePool(_)
            | AstStmt::CreateConnection(_)
            | AstStmt::CreateCortexSearchService(_)
            | AstStmt::CreateDataMetricFunction(_)
            | AstStmt::CreateDatabase(_)
            | AstStmt::CreateDatashare(_)
            | AstStmt::CreateDomain(_)
            | AstStmt::CreateDynamicTable(_)
            | AstStmt::CreateEvent(_)
            | AstStmt::CreateExtension(_)
            | AstStmt::CreateExternalAccessIntegration(_)
            | AstStmt::CreateExternalFunction(_)
            | AstStmt::CreateExternalLocation(_)
            | AstStmt::CreateExternalSchema(_)
            | AstStmt::CreateExternalTable(_)
            | AstStmt::CreateFileFormat(_)
            | AstStmt::CreateFlow(_)
            | AstStmt::CreateForeignServer(_)
            | AstStmt::CreateForeignTable(_)
            | AstStmt::CreateFunction(_)
            | AstStmt::CreateGitRepository(_)
            | AstStmt::CreateImageRepository(_)
            | AstStmt::CreateIndex(_)
            | AstStmt::CreateJoinPolicy(_)
            | AstStmt::CreateListing(_)
            | AstStmt::CreateManagedAccount(_)
            | AstStmt::CreateMaskingPolicy(_)
            | AstStmt::CreateMssqlTrigger(_)
            | AstStmt::CreateMysqlTrigger(_)
            | AstStmt::CreateNetworkPolicy(_)
            | AstStmt::CreateNetworkRule(_)
            | AstStmt::CreateNotebook(_)
            | AstStmt::CreateNotificationIntegration(_)
            | AstStmt::CreatePasswordPolicy(_)
            | AstStmt::CreatePgPolicy(_)
            | AstStmt::CreatePgTrigger(_)
            | AstStmt::CreatePipe(_)
            | AstStmt::CreatePrincipal(_)
            | AstStmt::CreateProcedure(_)
            | AstStmt::CreateProjectionPolicy(_)
            | AstStmt::CreateReplicationFailoverGroup(_)
            | AstStmt::CreateResourceMonitor(_)
            | AstStmt::CreateRowAccessPolicy(_)
            | AstStmt::CreateSchema(_)
            | AstStmt::CreateSecret(_)
            | AstStmt::CreateSecurityIntegration(_)
            | AstStmt::CreateSemanticView(_)
            | AstStmt::CreateSequence(_)
            | AstStmt::CreateService(_)
            | AstStmt::CreateSessionPolicy(_)
            | AstStmt::CreateShare(_)
            | AstStmt::CreateStage(_)
            | AstStmt::CreateStorageCredential(_)
            | AstStmt::CreateStorageIntegration(_)
            | AstStmt::CreateStream(_)
            | AstStmt::CreateStreamlit(_)
            | AstStmt::CreateSynonym(_)
            | AstStmt::CreateTable(_)
            | AstStmt::CreateTableFunction(_)
            | AstStmt::CreateTag(_)
            | AstStmt::CreateTask(_)
            | AstStmt::CreateType(_)
            | AstStmt::CreateUserMapping(_)
            | AstStmt::CreateView(_)
            | AstStmt::CreateVolume(_)
            | AstStmt::CreateWarehouse(_)
            | AstStmt::MssqlAlterExternalDataSource(_)
            | AstStmt::MssqlAlterExternalModel(_)
            | AstStmt::MssqlCreateExternalDataSource(_)
            | AstStmt::MssqlCreateExternalModel(_)
            | AstStmt::MssqlCreateRule(_)
            | AstStmt::MssqlCreateVectorIndex(_)
            | AstStmt::MysqlCreateLoadableFunction(_)
            | AstStmt::PgAlterRule(_)
            | AstStmt::PgAlterTablespace(_)
            | AstStmt::PgCreateAggregate(_)
            | AstStmt::PgCreateOperator(_)
            | AstStmt::PgCreateRule(_)
            | AstStmt::PgCreateTablespace(_)
            | AstStmt::PgPublication(_)
    )
}

/// How a [`ShownSlot`]'s literal follows its words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotFollows {
    /// Straight after them, or after an `=`.
    Option,
    /// As a call's first argument, after a `(`.
    Call,
    /// As an item of the list after them, or after their `=`: the items
    /// written apart by commas, in parentheses or brackets or bare.
    List,
    /// As a key of the `key = value` list in parentheses after them, or as
    /// the value of a key that names no secret.
    Properties,
    /// As the value of a `name = value` pair of the list after them, in
    /// parentheses or bare, the names written as names.
    Assignments,
    /// As the value the parser records for the option named by the words
    /// in a bulk load's option list ([`crate::ast::AstScript::bulk_options`]).
    BulkOption,
}

/// What a [`ShownSlot`]'s literal holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotHolds {
    /// A name, a format or a description, shown whole.
    Text,
    /// A file path or a URL: shown, a URL's user information and query
    /// masked (they may carry a password or a signature).
    Location,
}

const fn option(statement: SlotStatement, keyword: &'static [&'static str]) -> ShownSlot {
    ShownSlot {
        statement,
        keyword,
        follows: SlotFollows::Option,
        holds: SlotHolds::Text,
    }
}

const fn list(statement: SlotStatement, keyword: &'static [&'static str]) -> ShownSlot {
    ShownSlot {
        statement,
        keyword,
        follows: SlotFollows::List,
        holds: SlotHolds::Text,
    }
}

/// A location written straight after `keyword`.
const fn location(statement: SlotStatement, keyword: &'static [&'static str]) -> ShownSlot {
    ShownSlot {
        statement,
        keyword,
        follows: SlotFollows::Option,
        holds: SlotHolds::Location,
    }
}

/// The value of a bulk load's option named `keyword`.
const fn bulk_option(keyword: &'static [&'static str]) -> ShownSlot {
    ShownSlot {
        statement: SlotStatement::Any,
        keyword,
        follows: SlotFollows::BulkOption,
        holds: SlotHolds::Text,
    }
}

/// `COMMENT ON … IS '…'`.
const COMMENT_ON_IS: ShownSlot = option(SlotStatement::CommentOn, &["IS"]);

/// What a dialect's `SET name = value` gives its value to
/// ([`Dialect::set_assigns`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetAssigns {
    /// A variable a script declares.
    ScriptVariable,
    /// A variable of the session (Snowflake: "Variables (session)").
    SessionVariable,
    /// A configuration parameter (Databricks: "SET").
    Configuration,
}

/// A setting whose value the dialect's documentation gives as a name, a
/// format, a number, a duration, a switch or a path, never a credential:
/// a report may print the value a statement gives it
/// ([`Dialect::shown_settings`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShownSetting {
    /// Its name, matched in any case.
    pub name: &'static str,
    /// Where the dialect's documentation describes it.
    pub documented: &'static str,
}

const fn setting(name: &'static str, documented: &'static str) -> ShownSetting {
    ShownSetting { name, documented }
}

/// A data type the dialect's documentation gives other names: each names
/// the one type, with the one length or precision where none is written
/// ([`Dialect::type_synonyms`]). Every name is in lower case, its words one
/// space apart, without a length, a precision or array bounds. A name may
/// head two of them, each implying another length (Snowflake's `CHAR` is
/// `VARCHAR(1)`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TypeSynonyms {
    /// The type's name.
    pub name: &'static str,
    /// Each other name of it.
    pub aliases: &'static [&'static str],
    /// The length, precision and scale each of these names means where
    /// none is written, as `(38,0)`; empty where the documentation states
    /// none, or states one that depends on where the type is written.
    pub implied: &'static str,
    /// The scale a precision written without one means, as `0`; empty
    /// where the type takes no scale.
    pub scale: &'static str,
}

/// A routine of the dialect's own that its documentation gives other
/// names, each calling the one routine ([`Dialect::routine_synonyms`]).
/// Every name is in upper case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoutineSynonyms {
    /// The routine's name.
    pub name: &'static str,
    /// Each other name of it.
    pub others: &'static [&'static str],
    /// The number of arguments with which the other names call the
    /// routine (`IFNULL(a, b)` is `COALESCE(a, b)`); `None` where they
    /// call it with any number.
    pub arity: Option<usize>,
}

const fn routine_synonyms(name: &'static str, others: &'static [&'static str]) -> RoutineSynonyms {
    RoutineSynonyms {
        name,
        others,
        arity: None,
    }
}

const fn routine_synonyms_at(
    name: &'static str,
    arity: usize,
    others: &'static [&'static str],
) -> RoutineSynonyms {
    RoutineSynonyms {
        name,
        others,
        arity: Some(arity),
    }
}

const fn synonyms(name: &'static str, aliases: &'static [&'static str]) -> TypeSynonyms {
    TypeSynonyms {
        name,
        aliases,
        implied: "",
        scale: "",
    }
}

const fn synonyms_of(
    name: &'static str,
    implied: &'static str,
    aliases: &'static [&'static str],
) -> TypeSynonyms {
    TypeSynonyms {
        name,
        aliases,
        implied,
        scale: "",
    }
}

/// An exact numeric type: a precision written without a scale means
/// scale 0.
const fn decimals(
    name: &'static str,
    implied: &'static str,
    aliases: &'static [&'static str],
) -> TypeSynonyms {
    TypeSynonyms {
        name,
        aliases,
        implied,
        scale: "0",
    }
}

/// What a call writes as an argument, as far as telling a routine's forms
/// apart needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrittenValue {
    /// A string literal.
    Text,
    /// `TRUE` or `FALSE`.
    Flag,
    /// Anything else: a variable, a number, an expression.
    Other,
}

impl WrittenValue {
    /// What `expr` is written as, parentheses around it aside: a
    /// concatenation, or a string added to anything, is text.
    pub fn of(expr: &crate::ast::AstExpr) -> Self {
        use crate::ast::{AstExpr as E, AstLiteral, BinaryOperator};
        let text = |is_text: bool| match is_text {
            true => WrittenValue::Text,
            false => WrittenValue::Other,
        };
        match expr {
            E::Parenthesized { expr, .. } => WrittenValue::of(expr),
            E::BinaryOp {
                left,
                operator,
                right,
                ..
            } => text(
                *operator == BinaryOperator::Concat
                    || (*operator == BinaryOperator::Plus
                        && [left, right]
                            .into_iter()
                            .any(|operand| WrittenValue::of(operand) == WrittenValue::Text)),
            ),
            E::OperatorChain {
                operands,
                operators,
                ..
            } => {
                let concatenates = operators
                    .iter()
                    .any(|joined| joined.operator == BinaryOperator::Concat);
                let adds_text = operators
                    .iter()
                    .any(|joined| joined.operator == BinaryOperator::Plus)
                    && operands
                        .iter()
                        .any(|operand| WrittenValue::of(operand) == WrittenValue::Text);
                text(concatenates || adds_text)
            }
            E::Literal { literal, .. } => match literal {
                AstLiteral::String { .. }
                | AstLiteral::Adjacent { .. }
                | AstLiteral::StringWithJinja { .. } => WrittenValue::Text,
                AstLiteral::Boolean { .. } => WrittenValue::Flag,
                AstLiteral::Number { .. } | AstLiteral::Money { .. } | AstLiteral::Null { .. } => {
                    WrittenValue::Other
                }
            },
            E::FunctionCall { .. }
            | E::Case { .. }
            | E::Cast { .. }
            | E::TryCast { .. }
            | E::SafeCast { .. }
            | E::TypeCast { .. }
            | E::Collate { .. }
            | E::ScriptingVarRef { .. }
            | E::SessionVarRef { .. }
            | E::Ident { .. }
            | E::LogicalChain { .. }
            | E::ScalarSubquery { .. }
            | E::SubqueryArg { .. }
            | E::ExistsSubquery { .. }
            | E::InSubquery { .. }
            | E::QuantifiedSubquery { .. }
            | E::MatchAgainst { .. }
            | E::Spread { .. }
            | E::InList { .. }
            | E::Between { .. }
            | E::IsNull { .. }
            | E::IsPredicate { .. }
            | E::IsDistinctFrom { .. }
            | E::Like { .. }
            | E::SimilarTo { .. }
            | E::Array { .. }
            | E::RowConstructor { .. }
            | E::Placeholder { .. }
            | E::JinjaPlaceholder { .. }
            | E::JinjaConditional { .. }
            | E::DbtRef { .. }
            | E::DbtSource { .. }
            | E::DbtVar { .. }
            | E::DbtConfig { .. }
            | E::DbtThis { .. }
            | E::PositionRef { .. }
            | E::InListOpaque { .. }
            | E::ExplSnowIdent { .. }
            | E::Object { .. }
            | E::WindowFn { .. }
            | E::WindowExpr { .. }
            | E::TvfWithSchema { .. }
            | E::QualifiedStar { .. }
            | E::UnqualifiedStar { .. }
            | E::QualifiedStarFromExpr { .. }
            | E::Prior { .. }
            | E::ConnectByRoot { .. }
            | E::Extract { .. }
            | E::Position { .. }
            | E::Trim { .. }
            | E::Substring { .. }
            | E::ArraySubscript { .. }
            | E::ObjectFieldColon { .. }
            | E::ObjectFieldBracket { .. }
            | E::ObjectFieldDot { .. }
            | E::MethodCall { .. }
            | E::AtTimeZone { .. }
            | E::TypedStringLiteral { .. }
            | E::Error { .. } => WrittenValue::Other,
        }
    }
}

/// An argument as a call writes it: the parameter it is written to, where
/// written by name (with or without its `@`), and its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WrittenArgument<'a> {
    pub name: Option<&'a str>,
    pub value: WrittenValue,
}

impl SystemForm {
    /// What the form does with each of `arguments`; `None` where the call
    /// does not fit it: too few arguments, one at a position or a name the
    /// form takes none at, a string where it takes a flag, a flag where it
    /// takes neither a flag nor a value.
    fn uses(&self, arguments: &[WrittenArgument<'_>]) -> Option<Vec<ArgumentUse>> {
        if arguments.len() < self.required {
            return None;
        }
        arguments
            .iter()
            .enumerate()
            .map(|(position, argument)| {
                let reads = match argument.name {
                    Some(name) => {
                        let name = name.trim().trim_start_matches('@');
                        self.parameters
                            .iter()
                            .find(|parameter| parameter.name.eq_ignore_ascii_case(name))
                            .map(|parameter| parameter.reads)
                    }
                    None => self
                        .parameters
                        .get(position)
                        .map(|parameter| parameter.reads)
                        .or(self.rest),
                }?;
                let fits = match argument.value {
                    WrittenValue::Text => reads != ArgumentUse::Flag,
                    WrittenValue::Flag => matches!(
                        reads,
                        ArgumentUse::Flag | ArgumentUse::Value | ArgumentUse::Name
                    ),
                    WrittenValue::Other => true,
                };
                fits.then_some(reads)
            })
            .collect()
    }
}

/// The use of an argument two forms read as `a` and `b`, where both read
/// nothing it runs or takes a secret in beyond a connection's: the one
/// that reads more of it.
fn shown_alike(a: ArgumentUse, b: ArgumentUse) -> Option<ArgumentUse> {
    use ArgumentUse::{ConnectionString, Flag, Name, Value};
    let shown = |reads: ArgumentUse| matches!(reads, Value | Name | Flag | ConnectionString);
    if a == b {
        Some(a)
    } else if !(shown(a) && shown(b)) {
        None
    } else if a == ConnectionString || b == ConnectionString {
        Some(ConnectionString)
    } else {
        Some(Value)
    }
}

impl SystemRoutine {
    /// Whether a form the call with `arguments` fits reads one of them as
    /// `reads`.
    pub fn fits_reading(&self, arguments: &[WrittenArgument<'_>], reads: ArgumentUse) -> bool {
        self.forms
            .iter()
            .filter_map(|form| form.uses(arguments))
            .any(|uses| uses.contains(&reads))
    }

    /// What the routine does with each of `arguments`, the arguments of a
    /// call written in order: the use every form the call fits gives it,
    /// a value one form reads and another reads as a flag or a connection
    /// read as the one that reads more of it; `None` where two such forms
    /// give it other uses, or the call fits none.
    pub fn argument_uses(&self, arguments: &[WrittenArgument<'_>]) -> Vec<Option<ArgumentUse>> {
        let mut agreed: Option<Vec<Option<ArgumentUse>>> = None;
        for uses in self.forms.iter().filter_map(|form| form.uses(arguments)) {
            match agreed.as_mut() {
                None => agreed = Some(uses.into_iter().map(Some).collect()),
                Some(agreed) => {
                    for (held, now) in agreed.iter_mut().zip(uses) {
                        *held = held.and_then(|held| shown_alike(held, now));
                    }
                }
            }
        }
        agreed.unwrap_or_else(|| vec![None; arguments.len()])
    }

    /// What a report masks of each of `arguments`, the arguments of a call
    /// written in order, where forms the call fits read one apart: the use
    /// of the forms that masks the most of it, among those that show it,
    /// mask a connection's secrets in it or mask the string literals of
    /// SQL text in it; `None` where a form takes it as a password or a
    /// command, or the call fits no form.
    pub fn masking_uses(&self, arguments: &[WrittenArgument<'_>]) -> Vec<Option<ArgumentUse>> {
        use ArgumentUse::{
            Command, ConnectionString, Credential, Flag, Name, RunsSql, RunsSqlRemotely, Value,
        };
        let masks = |reads: ArgumentUse| match reads {
            Value | Name | Flag => Some(0),
            ConnectionString => Some(1),
            RunsSql | RunsSqlRemotely => Some(2),
            Command | Credential => None,
        };
        let mut most: Option<Vec<Option<ArgumentUse>>> = None;
        for uses in self.forms.iter().filter_map(|form| form.uses(arguments)) {
            match most.as_mut() {
                None => {
                    most = Some(
                        uses.into_iter()
                            .map(|reads| masks(reads).map(|_| reads))
                            .collect(),
                    )
                }
                Some(most) => {
                    for (held, now) in most.iter_mut().zip(uses) {
                        *held = match (*held, masks(now)) {
                            (Some(held), Some(rank)) if masks(held) >= Some(rank) => Some(held),
                            (Some(_), Some(_)) => Some(now),
                            (None, _) | (_, None) => None,
                        };
                    }
                }
            }
        }
        most.unwrap_or_else(|| vec![None; arguments.len()])
    }

    /// Whether some form of the routine runs an argument as SQL text.
    pub fn runs_sql(&self) -> bool {
        self.forms.iter().any(|form| {
            form.parameters
                .iter()
                .map(|parameter| parameter.reads)
                .chain(form.rest)
                .any(ArgumentUse::runs_sql)
        })
    }
}

impl NonValueArgument {
    const fn at(position: usize, kind: NonValueKind) -> Self {
        Self {
            position,
            kind,
            arity: None,
        }
    }
}

/// An argument a keyword introduces in a call
/// ([`Dialect::introduced_arguments`]): `PLACING r` of
/// `OVERLAY(s PLACING r)`, `USING utf8mb4` of MySQL's `CONVERT(s USING utf8mb4)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntroducedArgument {
    /// The keyword, in any case.
    pub keyword: &'static str,
    /// What follows it.
    pub value: IntroducedValue,
}

/// What follows the keyword of an [`IntroducedArgument`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntroducedValue {
    /// An expression: `PLACING r`, T-SQL's `USING 'en-US'`.
    Expr,
    /// A data type: `AS CHAR(4)`.
    DataType,
    /// A name that is no value and no column: `USING utf8mb4`, `NAME n`.
    Name,
}

const fn introduced(keyword: &'static str, value: IntroducedValue) -> IntroducedArgument {
    IntroducedArgument { keyword, value }
}

/// `OVERLAY(s PLACING r FROM a [FOR b])`.
const OVERLAY_ARGUMENTS: &[IntroducedArgument] = &[
    introduced("PLACING", IntroducedValue::Expr),
    introduced("FROM", IntroducedValue::Expr),
    introduced("FOR", IntroducedValue::Expr),
];
/// PostgreSQL's `XMLELEMENT(NAME n, …)`.
const XML_NAME_ARGUMENT: &[IntroducedArgument] = &[introduced("NAME", IntroducedValue::Name)];
/// MySQL's `CONVERT(s USING cs)` and `CHAR(n, … USING cs)`.
const CHARSET_ARGUMENT: &[IntroducedArgument] = &[introduced("USING", IntroducedValue::Name)];
/// MySQL's `WEIGHT_STRING(s AS CHAR(n))`.
const AS_TYPE_ARGUMENT: &[IntroducedArgument] = &[introduced("AS", IntroducedValue::DataType)];
/// T-SQL's `PARSE(s AS t [USING culture])` and `TRY_PARSE`.
const PARSE_ARGUMENTS: &[IntroducedArgument] = &[
    introduced("AS", IntroducedValue::DataType),
    introduced("USING", IntroducedValue::Expr),
];

const TYPE_FIRST: &[NonValueArgument] = &[NonValueArgument::at(0, NonValueKind::DataType)];
const TYPE_SECOND: &[NonValueArgument] = &[NonValueArgument::at(1, NonValueKind::DataType)];
const PART_FIRST: &[NonValueArgument] = &[NonValueArgument::at(0, NonValueKind::DatePart)];
const PART_SECOND: &[NonValueArgument] = &[NonValueArgument::at(1, NonValueKind::DatePart)];
const PART_THIRD: &[NonValueArgument] = &[NonValueArgument::at(2, NonValueKind::DatePart)];
const FORM_SECOND: &[NonValueArgument] = &[NonValueArgument::at(1, NonValueKind::NormalForm)];
/// Snowflake `TRUNC(date, part)`; `TRUNC(number, scale)` takes values.
const PART_SECOND_OF_TWO: &[NonValueArgument] = &[NonValueArgument {
    position: 1,
    kind: NonValueKind::DatePart,
    arity: Some(2),
}];
/// Databricks `DATEADD(unit, n, d)`; `DATEADD(d, n)` takes values.
const PART_FIRST_OF_THREE: &[NonValueArgument] = &[NonValueArgument {
    position: 0,
    kind: NonValueKind::DatePart,
    arity: Some(3),
}];

/// The non-value arguments of a call directly inside an ODBC `{fn …}`
/// escape, in ODBC's own grammar, whatever the dialect.
pub(crate) fn odbc_non_value_arguments(function: &str) -> &'static [NonValueArgument] {
    match AsciiUpper::new(function).as_str() {
        "CONVERT" => TYPE_SECOND,
        "TIMESTAMPADD" | "TIMESTAMPDIFF" => PART_FIRST,
        _ => &[],
    }
}

/// What a dialect's published keyword list lets a keyword be
/// ([`Dialect::keyword_class`]). A word the list does not hold is an
/// identifier anywhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeywordClass {
    /// Neither an identifier nor a select item's label, with or without
    /// `AS`.
    Reserved,
    /// Not an identifier, a table's alias or a select item's label written
    /// bare; a select item's label after `AS` (PostgreSQL's reserved
    /// `AS_LABEL` keywords).
    ReservedLabelAfterAs,
    /// Not an identifier or a table's alias; a select item's label, with or
    /// without `AS` (PostgreSQL's reserved `BARE_LABEL` keywords).
    ReservedBareLabel,
    /// An identifier and a select item's label, never a table's alias.
    NotTableAlias,
    /// An identifier and a table's alias; a select item's label only after
    /// `AS` (PostgreSQL's unreserved `AS_LABEL` keywords).
    LabelAfterAs,
    /// An identifier, an alias and a label.
    Unreserved,
}

impl KeywordClass {
    /// Whether the keyword is an unquoted identifier.
    pub(crate) fn is_identifier(self) -> bool {
        match self {
            KeywordClass::Reserved
            | KeywordClass::ReservedLabelAfterAs
            | KeywordClass::ReservedBareLabel => false,
            KeywordClass::NotTableAlias | KeywordClass::LabelAfterAs | KeywordClass::Unreserved => {
                true
            }
        }
    }

    /// Whether the keyword is a table's alias, with or without `AS`.
    pub(crate) fn is_table_alias(self) -> bool {
        match self {
            KeywordClass::Reserved
            | KeywordClass::ReservedLabelAfterAs
            | KeywordClass::ReservedBareLabel
            | KeywordClass::NotTableAlias => false,
            KeywordClass::LabelAfterAs | KeywordClass::Unreserved => true,
        }
    }

    /// Whether the keyword is a select item's label written without `AS`.
    pub(crate) fn is_bare_label(self) -> bool {
        match self {
            KeywordClass::Reserved
            | KeywordClass::ReservedLabelAfterAs
            | KeywordClass::LabelAfterAs => false,
            KeywordClass::ReservedBareLabel
            | KeywordClass::NotTableAlias
            | KeywordClass::Unreserved => true,
        }
    }
}

/// Where a word is read as the name of what precedes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LabelPosition {
    /// A column's label: a select item's, a pivot value's, a measure's.
    ColumnLabel {
        /// Whether `AS` is written before it.
        after_as: bool,
    },
    /// A table's alias, a DML target's included.
    TableAlias {
        /// Whether `AS` is written before it.
        after_as: bool,
    },
    /// The label of a block, a loop or a statement (`name:`, `<<name>>`):
    /// any word, the procedural languages' keyword lists not being the SQL
    /// one (PL/pgSQL's `<<outer>>`).
    StatementLabel,
}

/// Whether `word` can name what precedes it at `position` in `dialect`:
/// the class its keyword list gives the word ([`Dialect::keyword_class`]),
/// read by the vendor's rule. A word with no class is answered by the
/// dialect's keyword methods: for a built-in dialect, a word its list does
/// not hold can; a dialect defined outside this crate says.
pub(crate) fn can_be_label(dialect: &dyn Dialect, word: &str, position: LabelPosition) -> bool {
    let Some(class) = dialect.keyword_class(word) else {
        return match position {
            LabelPosition::ColumnLabel { after_as: false } => {
                dialect.keyword_can_be_bare_column_label(word)
            }
            LabelPosition::ColumnLabel { after_as: true } => {
                dialect.keyword_can_be_unquoted_identifier(word)
                    || dialect.keyword_can_be_bare_column_label(word)
            }
            LabelPosition::TableAlias { .. } => dialect.keyword_can_be_unquoted_alias(word),
            LabelPosition::StatementLabel => true,
        };
    };
    match position {
        LabelPosition::ColumnLabel { after_as: false } => class.is_bare_label(),
        LabelPosition::ColumnLabel { after_as: true } => class != KeywordClass::Reserved,
        LabelPosition::TableAlias { .. } => class.is_table_alias(),
        LabelPosition::StatementLabel => true,
    }
}

/// The trait's keyword answers of a built-in dialect, each read from its
/// keyword table (`$table`, a function of the upper-cased word).
macro_rules! keyword_answers {
    ($table:ident) => {
        fn keyword_class(&self, word: &str) -> Option<KeywordClass> {
            $table(AsciiUpper::new(word).as_str())
        }

        fn is_reserved_keyword(&self, word: &str) -> bool {
            self.keyword_class(word)
                .is_some_and(|class| !class.is_identifier())
        }

        fn is_keyword(&self, word: &str) -> bool {
            self.keyword_class(word).is_some()
        }

        fn keyword_can_be_unquoted_identifier(&self, word: &str) -> bool {
            self.keyword_class(word)
                .is_none_or(KeywordClass::is_identifier)
        }

        fn keyword_can_be_unquoted_alias(&self, word: &str) -> bool {
            self.keyword_class(word)
                .is_none_or(KeywordClass::is_table_alias)
        }

        fn keyword_can_be_bare_column_label(&self, word: &str) -> bool {
            self.keyword_class(word)
                .is_none_or(KeywordClass::is_bare_label)
        }
    };
}

/// Snowflake's keywords: "Reserved & limited keywords"
/// (docs.snowflake.com/en/sql-reference/reserved-keywords). A word limited only
/// as a table name or alias in `FROM` is [`KeywordClass::NotTableAlias`]; one
/// limited only in `SHOW` or as a `CREATE TABLE` column is unreserved.
/// The unreserved words are the others the grammar reads as keywords.
fn snowflake_keyword(upper: &str) -> Option<KeywordClass> {
    Some(match upper {
        "ALL" | "ALTER" | "AND" | "ANY" | "AS" | "BETWEEN" | "BY" | "CASE" | "CAST" | "CHECK"
        | "COLUMN" | "CONNECT" | "CREATE" | "CURRENT" | "CURRENT_DATE" | "CURRENT_TIME"
        | "CURRENT_TIMESTAMP" | "CURRENT_USER" | "DELETE" | "DISTINCT" | "DROP" | "ELSE"
        | "EXISTS" | "FALSE" | "FOLLOWING" | "FOR" | "FROM" | "GRANT" | "GROUP" | "HAVING"
        | "ILIKE" | "IN" | "INCREMENT" | "INSERT" | "INTERSECT" | "INTO" | "IS" | "LIKE"
        | "LOCALTIME" | "LOCALTIMESTAMP" | "MINUS" | "NOT" | "NULL" | "OF" | "ON" | "OR"
        | "ORDER" | "QUALIFY" | "REGEXP" | "REVOKE" | "RLIKE" | "ROW" | "ROWS" | "SAMPLE"
        | "SELECT" | "SET" | "SOME" | "START" | "TABLE" | "TABLESAMPLE" | "THEN" | "TO"
        | "TRIGGER" | "TRUE" | "TRY_CAST" | "UNION" | "UNIQUE" | "UPDATE" | "VALUES" | "WHEN"
        | "WHENEVER" | "WHERE" | "WINDOW" | "WITH" => KeywordClass::Reserved,
        "CROSS" | "FULL" | "INNER" | "JOIN" | "LATERAL" | "LEFT" | "NATURAL" | "RIGHT"
        | "USING" => KeywordClass::NotTableAlias,
        "ACCESS" | "ACCOUNT" | "ACTION" | "ARRAY" | "ASC" | "ASOF" | "AT" | "BEFORE" | "BEGIN"
        | "BIGINT" | "BODY" | "BOOLEAN" | "BREAK" | "CALL" | "CALLER" | "CASCADE" | "CATCH"
        | "CHAR" | "CHARACTER" | "CLUSTER" | "COMMENT" | "COMMIT" | "COMPRESSION" | "CONFLICT"
        | "CONNECTION" | "CONSTRAINT" | "CONTINUE" | "COPY" | "CREDENTIALS" | "DATABASE"
        | "DATE" | "DECIMAL" | "DECLARE" | "DEFAULT" | "DEFINE" | "DESC" | "DESCRIBE"
        | "DIRECTORY" | "DO" | "DOUBLE" | "ELSEIF" | "ENABLE" | "ENCRYPTION" | "END" | "ESCAPE"
        | "EXCEPT" | "EXCEPTION" | "EXCLUDE" | "EXECUTE" | "FILE" | "FIRST" | "FLATTEN"
        | "FLOAT" | "FOREIGN" | "FORMAT" | "FUNCTION" | "GSCLUSTER" | "IF" | "IMMEDIATE"
        | "IMMUTABLE" | "INDEX" | "INT" | "INTEGER" | "INTEGRATION" | "INTERVAL" | "ISSUE"
        | "KEY" | "LANGUAGE" | "LAST" | "LIMIT" | "LOOP" | "MASKING" | "MATCH_RECOGNIZE"
        | "MATERIALIZED" | "MEASURES" | "MERGE" | "NETWORK" | "NO" | "NOTHING" | "NOTIFY"
        | "NULLS" | "NUMBER" | "NUMERIC" | "OBJECT" | "OFFSET" | "ORGANIZATION" | "OUTER"
        | "OVER" | "OWNER" | "PARTITION" | "PATTERN" | "PIPE" | "PIVOT" | "POLICY"
        | "PRECEDING" | "PRIMARY" | "PROCEDURE" | "RAISE" | "RANGE" | "REAL" | "RECURSIVE"
        | "REFERENCES" | "RENAME" | "REPEAT" | "REPLACE" | "RESTRICT" | "RETURN" | "RETURNING"
        | "ROLE" | "ROLLBACK" | "SCHEMA" | "SECURE" | "SEQUENCE" | "SHARE" | "SHOW"
        | "SMALLINT" | "STAGE" | "STORAGE" | "STREAM" | "STRING" | "TAG" | "TASK" | "TEMPORARY"
        | "TEXT" | "TIME" | "TIMESTAMP" | "TINYINT" | "TOP" | "TRANSACTION" | "TRANSIENT"
        | "TRUNCATE" | "TRY" | "TYPE" | "UNBOUNDED" | "UNPIVOT" | "UNTIL" | "URL" | "USE"
        | "USER" | "VARCHAR" | "VARIANT" | "VIEW" | "VOLATILE" | "WAREHOUSE" | "WHILE" | "WORK" => {
            KeywordClass::Unreserved
        }
        _ => return None,
    })
}

/// PostgreSQL 17's keywords (`src/include/parser/kwlist.h`): unreserved and
/// column-name keywords are identifiers, type-or-function-name and reserved
/// keywords are not; each is a bare column label or needs `AS`, and after
/// `AS` any keyword is a column label (`ColLabel`).
fn postgres_keyword(upper: &str) -> Option<KeywordClass> {
    Some(match upper {
        "ARRAY" | "AS" | "CREATE" | "EXCEPT" | "FETCH" | "FOR" | "FROM" | "GRANT" | "GROUP"
        | "HAVING" | "INTERSECT" | "INTO" | "ISNULL" | "LIMIT" | "NOTNULL" | "OFFSET" | "ON"
        | "ORDER" | "OVERLAPS" | "RETURNING" | "TO" | "UNION" | "WHERE" | "WINDOW" | "WITH" => {
            KeywordClass::ReservedLabelAfterAs
        }
        "ALL" | "ANALYSE" | "ANALYZE" | "AND" | "ANY" | "ASC" | "ASYMMETRIC" | "AUTHORIZATION"
        | "BINARY" | "BOTH" | "CASE" | "CAST" | "CHECK" | "COLLATE" | "COLLATION" | "COLUMN"
        | "CONCURRENTLY" | "CONSTRAINT" | "CROSS" | "CURRENT_CATALOG" | "CURRENT_DATE"
        | "CURRENT_ROLE" | "CURRENT_SCHEMA" | "CURRENT_TIME" | "CURRENT_TIMESTAMP"
        | "CURRENT_USER" | "DEFAULT" | "DEFERRABLE" | "DESC" | "DISTINCT" | "DO" | "ELSE"
        | "END" | "FALSE" | "FOREIGN" | "FREEZE" | "FULL" | "ILIKE" | "IN" | "INITIALLY"
        | "INNER" | "IS" | "JOIN" | "LATERAL" | "LEADING" | "LEFT" | "LIKE" | "LOCALTIME"
        | "LOCALTIMESTAMP" | "NATURAL" | "NOT" | "NULL" | "ONLY" | "OR" | "OUTER" | "PLACING"
        | "PRIMARY" | "REFERENCES" | "RIGHT" | "SELECT" | "SESSION_USER" | "SIMILAR" | "SOME"
        | "SYMMETRIC" | "SYSTEM_USER" | "TABLE" | "TABLESAMPLE" | "THEN" | "TRAILING" | "TRUE"
        | "UNIQUE" | "USER" | "USING" | "VARIADIC" | "VERBOSE" | "WHEN" => {
            KeywordClass::ReservedBareLabel
        }
        "CHAR" | "CHARACTER" | "DAY" | "FILTER" | "HOUR" | "MINUTE" | "MONTH" | "OVER"
        | "PRECISION" | "SECOND" | "VARYING" | "WITHIN" | "WITHOUT" | "YEAR" => {
            KeywordClass::LabelAfterAs
        }
        "ABORT" | "ABSENT" | "ABSOLUTE" | "ACCESS" | "ACTION" | "ADD" | "ADMIN" | "AFTER"
        | "AGGREGATE" | "ALSO" | "ALTER" | "ALWAYS" | "ASENSITIVE" | "ASSERTION" | "ASSIGNMENT"
        | "AT" | "ATOMIC" | "ATTACH" | "ATTRIBUTE" | "BACKWARD" | "BEFORE" | "BEGIN"
        | "BETWEEN" | "BIGINT" | "BIT" | "BOOLEAN" | "BREADTH" | "BY" | "CACHE" | "CALL"
        | "CALLED" | "CASCADE" | "CASCADED" | "CATALOG" | "CHAIN" | "CHARACTERISTICS"
        | "CHECKPOINT" | "CLASS" | "CLOSE" | "CLUSTER" | "COALESCE" | "COLUMNS" | "COMMENT"
        | "COMMENTS" | "COMMIT" | "COMMITTED" | "COMPRESSION" | "CONDITIONAL" | "CONFIGURATION"
        | "CONFLICT" | "CONNECTION" | "CONSTRAINTS" | "CONTENT" | "CONTINUE" | "CONVERSION"
        | "COPY" | "COST" | "CSV" | "CUBE" | "CURRENT" | "CURSOR" | "CYCLE" | "DATA"
        | "DATABASE" | "DEALLOCATE" | "DEC" | "DECIMAL" | "DECLARE" | "DEFAULTS" | "DEFERRED"
        | "DEFINER" | "DELETE" | "DELIMITER" | "DELIMITERS" | "DEPENDS" | "DEPTH" | "DETACH"
        | "DICTIONARY" | "DISABLE" | "DISCARD" | "DOCUMENT" | "DOMAIN" | "DOUBLE" | "DROP"
        | "EACH" | "EMPTY" | "ENABLE" | "ENCODING" | "ENCRYPTED" | "ENUM" | "ERROR" | "ESCAPE"
        | "EVENT" | "EXCLUDE" | "EXCLUDING" | "EXCLUSIVE" | "EXECUTE" | "EXISTS" | "EXPLAIN"
        | "EXPRESSION" | "EXTENSION" | "EXTERNAL" | "EXTRACT" | "FAMILY" | "FINALIZE" | "FIRST"
        | "FLOAT" | "FOLLOWING" | "FORCE" | "FORMAT" | "FORWARD" | "FUNCTION" | "FUNCTIONS"
        | "GENERATED" | "GLOBAL" | "GRANTED" | "GREATEST" | "GROUPING" | "GROUPS" | "HANDLER"
        | "HEADER" | "HOLD" | "IDENTITY" | "IF" | "IMMEDIATE" | "IMMUTABLE" | "IMPLICIT"
        | "IMPORT" | "INCLUDE" | "INCLUDING" | "INCREMENT" | "INDENT" | "INDEX" | "INDEXES"
        | "INHERIT" | "INHERITS" | "INLINE" | "INOUT" | "INPUT" | "INSENSITIVE" | "INSERT"
        | "INSTEAD" | "INT" | "INTEGER" | "INTERVAL" | "INVOKER" | "ISOLATION" | "JSON"
        | "JSON_ARRAY" | "JSON_ARRAYAGG" | "JSON_EXISTS" | "JSON_OBJECT" | "JSON_OBJECTAGG"
        | "JSON_QUERY" | "JSON_SCALAR" | "JSON_SERIALIZE" | "JSON_TABLE" | "JSON_VALUE"
        | "KEEP" | "KEY" | "KEYS" | "LABEL" | "LANGUAGE" | "LARGE" | "LAST" | "LEAKPROOF"
        | "LEAST" | "LEVEL" | "LISTEN" | "LOAD" | "LOCAL" | "LOCATION" | "LOCK" | "LOCKED"
        | "LOGGED" | "MAPPING" | "MATCH" | "MATCHED" | "MATERIALIZED" | "MAXVALUE" | "MERGE"
        | "MERGE_ACTION" | "METHOD" | "MINVALUE" | "MODE" | "MOVE" | "NAME" | "NAMES"
        | "NATIONAL" | "NCHAR" | "NESTED" | "NEW" | "NEXT" | "NFC" | "NFD" | "NFKC" | "NFKD"
        | "NO" | "NONE" | "NORMALIZE" | "NORMALIZED" | "NOTHING" | "NOTIFY" | "NOWAIT"
        | "NULLIF" | "NULLS" | "NUMERIC" | "OBJECT" | "OF" | "OFF" | "OIDS" | "OLD" | "OMIT"
        | "OPERATOR" | "OPTION" | "OPTIONS" | "ORDINALITY" | "OTHERS" | "OUT" | "OVERLAY"
        | "OVERRIDING" | "OWNED" | "OWNER" | "PARALLEL" | "PARAMETER" | "PARSER" | "PARTIAL"
        | "PARTITION" | "PASSING" | "PASSWORD" | "PATH" | "PLAN" | "PLANS" | "POLICY"
        | "POSITION" | "PRECEDING" | "PREPARE" | "PREPARED" | "PRESERVE" | "PRIOR"
        | "PRIVILEGES" | "PROCEDURAL" | "PROCEDURE" | "PROCEDURES" | "PROGRAM" | "PUBLICATION"
        | "QUOTE" | "QUOTES" | "RANGE" | "READ" | "REAL" | "REASSIGN" | "RECHECK" | "RECURSIVE"
        | "REF" | "REFERENCING" | "REFRESH" | "REINDEX" | "RELATIVE" | "RELEASE" | "RENAME"
        | "REPEATABLE" | "REPLACE" | "REPLICA" | "RESET" | "RESTART" | "RESTRICT" | "RETURN"
        | "RETURNS" | "REVOKE" | "ROLE" | "ROLLBACK" | "ROLLUP" | "ROUTINE" | "ROUTINES"
        | "ROW" | "ROWS" | "RULE" | "SAVEPOINT" | "SCALAR" | "SCHEMA" | "SCHEMAS" | "SCROLL"
        | "SEARCH" | "SECURITY" | "SEQUENCE" | "SEQUENCES" | "SERIALIZABLE" | "SERVER"
        | "SESSION" | "SET" | "SETOF" | "SETS" | "SHARE" | "SHOW" | "SIMPLE" | "SKIP"
        | "SMALLINT" | "SNAPSHOT" | "SOURCE" | "SQL" | "STABLE" | "STANDALONE" | "START"
        | "STATEMENT" | "STATISTICS" | "STDIN" | "STDOUT" | "STORAGE" | "STORED" | "STRICT"
        | "STRING" | "STRIP" | "SUBSCRIPTION" | "SUBSTRING" | "SUPPORT" | "SYSID" | "SYSTEM"
        | "TABLES" | "TABLESPACE" | "TARGET" | "TEMP" | "TEMPLATE" | "TEMPORARY" | "TEXT"
        | "TIES" | "TIME" | "TIMESTAMP" | "TRANSACTION" | "TRANSFORM" | "TREAT" | "TRIGGER"
        | "TRIM" | "TRUNCATE" | "TRUSTED" | "TYPE" | "TYPES" | "UESCAPE" | "UNBOUNDED"
        | "UNCOMMITTED" | "UNCONDITIONAL" | "UNENCRYPTED" | "UNKNOWN" | "UNLISTEN" | "UNLOGGED"
        | "UNTIL" | "UPDATE" | "VACUUM" | "VALID" | "VALIDATE" | "VALIDATOR" | "VALUE"
        | "VALUES" | "VARCHAR" | "VERSION" | "VIEW" | "VIEWS" | "VOLATILE" | "WHITESPACE"
        | "WORK" | "WRAPPER" | "WRITE" | "XML" | "XMLATTRIBUTES" | "XMLCONCAT" | "XMLELEMENT"
        | "XMLEXISTS" | "XMLFOREST" | "XMLNAMESPACES" | "XMLPARSE" | "XMLPI" | "XMLROOT"
        | "XMLSERIALIZE" | "XMLTABLE" | "YES" | "ZONE" => KeywordClass::Unreserved,
        _ => return None,
    })
}

/// Amazon Redshift's "Reserved words"
/// (docs.aws.amazon.com/redshift/latest/dg/r_pg_keywords.html).
/// The unreserved words are the others the grammar reads as keywords.
fn redshift_keyword(upper: &str) -> Option<KeywordClass> {
    Some(match upper {
        "AES128" | "AES256" | "ALL" | "ALLOWOVERWRITE" | "ANALYSE" | "ANALYZE" | "AND" | "ANY"
        | "ARRAY" | "AS" | "ASC" | "AUTHORIZATION" | "AZ64" | "BACKUP" | "BETWEEN" | "BINARY"
        | "BLANKSASNULL" | "BOTH" | "BYTEDICT" | "BZIP2" | "CASE" | "CAST" | "CHECK"
        | "COLLATE" | "COLUMN" | "CONSTRAINT" | "CREATE" | "CREDENTIALS" | "CROSS"
        | "CURRENT_DATE" | "CURRENT_TIME" | "CURRENT_TIMESTAMP" | "CURRENT_USER"
        | "CURRENT_USER_ID" | "DEFAULT" | "DEFERRABLE" | "DEFLATE" | "DEFRAG" | "DELTA"
        | "DELTA32K" | "DESC" | "DISABLE" | "DISTINCT" | "DO" | "ELSE" | "EMPTYASNULL"
        | "ENABLE" | "ENCODE" | "ENCRYPT" | "ENCRYPTION" | "END" | "EXCEPT" | "EXPLICIT"
        | "FALSE" | "FOR" | "FOREIGN" | "FREEZE" | "FROM" | "FULL" | "GLOBALDICT256"
        | "GLOBALDICT64K" | "GRANT" | "GROUP" | "GZIP" | "HAVING" | "IDENTITY" | "IGNORE"
        | "ILIKE" | "IN" | "INITIALLY" | "INNER" | "INTERSECT" | "INTERVAL" | "INTO" | "IS"
        | "ISNULL" | "JOIN" | "LEADING" | "LEFT" | "LIKE" | "LIMIT" | "LOCALTIME"
        | "LOCALTIMESTAMP" | "LUN" | "LUNS" | "LZO" | "LZOP" | "MINUS" | "MOSTLY16"
        | "MOSTLY32" | "MOSTLY8" | "NATURAL" | "NEW" | "NOT" | "NOTNULL" | "NULL" | "NULLS"
        | "OFF" | "OFFLINE" | "OFFSET" | "OID" | "OLD" | "ON" | "ONLY" | "OPEN" | "OR"
        | "ORDER" | "OUTER" | "OVERLAPS" | "PARALLEL" | "PARTITION" | "PERCENT" | "PERMISSIONS"
        | "PIVOT" | "PLACING" | "PRIMARY" | "RAW" | "READRATIO" | "RECOVER" | "REFERENCES"
        | "REJECTLOG" | "RESORT" | "RESPECT" | "RESTORE" | "RIGHT" | "SELECT" | "SESSION_USER"
        | "SIMILAR" | "SNAPSHOT" | "SOME" | "SYSDATE" | "SYSTEM" | "TABLE" | "TAG" | "TDES"
        | "TEXT255" | "TEXT32K" | "THEN" | "TIMESTAMP" | "TO" | "TOP" | "TRAILING" | "TRUE"
        | "TRUNCATECOLUMNS" | "UNION" | "UNIQUE" | "UNNEST" | "UNPIVOT" | "USER" | "USING"
        | "VERBOSE" | "WALLET" | "WHEN" | "WHERE" | "WITH" | "WITHOUT" => KeywordClass::Reserved,
        "ABORT" | "ACCEPTINVCHARS" | "ADD" | "ADDQUOTES" | "ALTER" | "AUTO" | "AVRO" | "BEGIN"
        | "BIGINT" | "BINDING" | "BOOL" | "BOOLEAN" | "BPCHAR" | "BZIP" | "CALL" | "CASCADE"
        | "CATALOG" | "CHAR" | "CHARACTER" | "CLOSE" | "COALESCE" | "COMMENT" | "COMMIT"
        | "COMPOUND" | "COMPUPDATE" | "CONFLICT" | "CONNECTION" | "COPY" | "CSV" | "CURRENT"
        | "DATA" | "DATABASE" | "DATASHARE" | "DATE" | "DATEFORMAT" | "DEALLOCATE" | "DECIMAL"
        | "DECLARE" | "DELETE" | "DELIMITER" | "DISTKEY" | "DISTSTYLE" | "DOUBLE" | "DROP"
        | "ENCODING" | "ESCAPE" | "EVEN" | "EXECUTE" | "EXISTS" | "EXPLAIN" | "EXTENSION"
        | "EXTERNAL" | "EXTRACT" | "FETCH" | "FIRST" | "FIXEDWIDTH" | "FLOAT" | "FLOAT4"
        | "FLOAT8" | "FOLLOWING" | "FORMAT" | "FUNCTION" | "GEOGRAPHY" | "GEOMETRY"
        | "GREATEST" | "GROUPS" | "HEADER" | "HIVE" | "HLLSKETCH" | "IAM_ROLE" | "IF"
        | "INPUTFORMAT" | "INSERT" | "INT" | "INT2" | "INT4" | "INT8" | "INTEGER"
        | "INTERLEAVED" | "JSON" | "KEY" | "LANGUAGE" | "LAST" | "LEAST" | "LOCAL" | "LOCATION"
        | "LOCK" | "MANIFEST" | "MATERIALIZED" | "MAXERROR" | "MERGE" | "METASTORE" | "MODEL"
        | "NCHAR" | "NOTHING" | "NULLIF" | "NUMERIC" | "NVARCHAR" | "ORC" | "OUTPUTFORMAT"
        | "OVER" | "OWNER" | "PARQUET" | "POSITION" | "PRECEDING" | "PRECISION" | "PREPARE"
        | "PROCEDURE" | "RANGE" | "REAL" | "RECURSIVE" | "REFRESH" | "REGION" | "REMOVEQUOTES"
        | "RENAME" | "REPLACE" | "RESET" | "RESTRICT" | "RETURNING" | "REVOKE" | "ROLE"
        | "ROLLBACK" | "ROUNDEC" | "ROW" | "ROWS" | "RUNLENGTH" | "SCHEMA" | "SEQUENCE"
        | "SERDE" | "SERDEPROPERTIES" | "SET" | "SHOW" | "SMALLINT" | "SORTKEY" | "START"
        | "STATUPDATE" | "STORED" | "SUBSTRING" | "SUPER" | "TEMP" | "TEMPORARY" | "TEXT"
        | "TIME" | "TIMEFORMAT" | "TIMESTAMPTZ" | "TIMETZ" | "TRANSACTION" | "TRIM"
        | "TRIMBLANKS" | "TRUNCATE" | "UNBOUNDED" | "UNLOAD" | "UPDATE" | "VACUUM" | "VALUES"
        | "VARBINARY" | "VARBYTE" | "VARCHAR" | "VARYING" | "VIEW" | "WINDOW" | "WORK" | "ZSTD" => {
            KeywordClass::Unreserved
        }
        _ => return None,
    })
}

/// MySQL 8.0's keywords marked reserved in "Keywords and Reserved Words"
/// (dev.mysql.com/doc/refman/8.0/en/keywords.html).
/// The unreserved words are the others the grammar reads as keywords.
fn mysql_keyword(upper: &str) -> Option<KeywordClass> {
    Some(match upper {
        "ACCESSIBLE"
        | "ADD"
        | "ALL"
        | "ALTER"
        | "ANALYZE"
        | "AND"
        | "AS"
        | "ASC"
        | "ASENSITIVE"
        | "BEFORE"
        | "BETWEEN"
        | "BIGINT"
        | "BINARY"
        | "BLOB"
        | "BOTH"
        | "BY"
        | "CALL"
        | "CASCADE"
        | "CASE"
        | "CHANGE"
        | "CHAR"
        | "CHARACTER"
        | "CHECK"
        | "COLLATE"
        | "COLUMN"
        | "CONDITION"
        | "CONSTRAINT"
        | "CONTINUE"
        | "CONVERT"
        | "CREATE"
        | "CROSS"
        | "CUBE"
        | "CUME_DIST"
        | "CURRENT_DATE"
        | "CURRENT_TIME"
        | "CURRENT_TIMESTAMP"
        | "CURRENT_USER"
        | "CURSOR"
        | "DATABASE"
        | "DATABASES"
        | "DAY_HOUR"
        | "DAY_MICROSECOND"
        | "DAY_MINUTE"
        | "DAY_SECOND"
        | "DEC"
        | "DECIMAL"
        | "DECLARE"
        | "DEFAULT"
        | "DELAYED"
        | "DELETE"
        | "DENSE_RANK"
        | "DESC"
        | "DESCRIBE"
        | "DETERMINISTIC"
        | "DISTINCT"
        | "DISTINCTROW"
        | "DIV"
        | "DOUBLE"
        | "DROP"
        | "DUAL"
        | "EACH"
        | "ELSE"
        | "ELSEIF"
        | "EMPTY"
        | "ENCLOSED"
        | "ESCAPED"
        | "EXCEPT"
        | "EXISTS"
        | "EXIT"
        | "EXPLAIN"
        | "FALSE"
        | "FETCH"
        | "FIRST_VALUE"
        | "FLOAT"
        | "FLOAT4"
        | "FLOAT8"
        | "FOR"
        | "FORCE"
        | "FOREIGN"
        | "FROM"
        | "FULLTEXT"
        | "FUNCTION"
        | "GENERATED"
        | "GET"
        | "GRANT"
        | "GROUP"
        | "GROUPING"
        | "GROUPS"
        | "HAVING"
        | "HIGH_PRIORITY"
        | "HOUR_MICROSECOND"
        | "HOUR_MINUTE"
        | "HOUR_SECOND"
        | "IF"
        | "IGNORE"
        | "IN"
        | "INDEX"
        | "INFILE"
        | "INNER"
        | "INOUT"
        | "INSENSITIVE"
        | "INSERT"
        | "INT"
        | "INT1"
        | "INT2"
        | "INT3"
        | "INT4"
        | "INT8"
        | "INTEGER"
        | "INTERSECT"
        | "INTERVAL"
        | "INTO"
        | "IO_AFTER_GTIDS"
        | "IO_BEFORE_GTIDS"
        | "IS"
        | "ITERATE"
        | "JOIN"
        | "JSON_TABLE"
        | "KEY"
        | "KEYS"
        | "KILL"
        | "LAG"
        | "LAST_VALUE"
        | "LATERAL"
        | "LEAD"
        | "LEADING"
        | "LEAVE"
        | "LEFT"
        | "LIKE"
        | "LIMIT"
        | "LINEAR"
        | "LINES"
        | "LOAD"
        | "LOCALTIME"
        | "LOCALTIMESTAMP"
        | "LOCK"
        | "LONG"
        | "LONGBLOB"
        | "LONGTEXT"
        | "LOOP"
        | "LOW_PRIORITY"
        | "MASTER_BIND"
        | "MASTER_SSL_VERIFY_SERVER_CERT"
        | "MATCH"
        | "MAXVALUE"
        | "MEDIUMBLOB"
        | "MEDIUMINT"
        | "MEDIUMTEXT"
        | "MIDDLEINT"
        | "MINUTE_MICROSECOND"
        | "MINUTE_SECOND"
        | "MOD"
        | "MODIFIES"
        | "NATURAL"
        | "NOT"
        | "NO_WRITE_TO_BINLOG"
        | "NTH_VALUE"
        | "NTILE"
        | "NULL"
        | "NUMERIC"
        | "OF"
        | "ON"
        | "OPTIMIZE"
        | "OPTIMIZER_COSTS"
        | "OPTION"
        | "OPTIONALLY"
        | "OR"
        | "ORDER"
        | "OUT"
        | "OUTER"
        | "OUTFILE"
        | "OVER"
        | "PARTITION"
        | "PRECISION"
        | "PRIMARY"
        | "PROCEDURE"
        | "PURGE"
        | "RANGE"
        | "RANK"
        | "READ"
        | "READS"
        | "READ_WRITE"
        | "REAL"
        | "RECURSIVE"
        | "REFERENCES"
        | "REGEXP"
        | "RELEASE"
        | "RENAME"
        | "REPEAT"
        | "REPLACE"
        | "REQUIRE"
        | "RESIGNAL"
        | "RESTRICT"
        | "RETURN"
        | "REVOKE"
        | "RIGHT"
        | "RLIKE"
        | "ROW"
        | "ROWS"
        | "ROW_NUMBER"
        | "SCHEMA"
        | "SCHEMAS"
        | "SECOND_MICROSECOND"
        | "SELECT"
        | "SENSITIVE"
        | "SEPARATOR"
        | "SET"
        | "SHOW"
        | "SIGNAL"
        | "SMALLINT"
        | "SPATIAL"
        | "SPECIFIC"
        | "SQL"
        | "SQLEXCEPTION"
        | "SQLSTATE"
        | "SQLWARNING"
        | "SQL_BIG_RESULT"
        | "SQL_CALC_FOUND_ROWS"
        | "SQL_SMALL_RESULT"
        | "SSL"
        | "STARTING"
        | "STORED"
        | "STRAIGHT_JOIN"
        | "SYSTEM"
        | "TABLE"
        | "TERMINATED"
        | "THEN"
        | "TINYBLOB"
        | "TINYINT"
        | "TINYTEXT"
        | "TO"
        | "TRAILING"
        | "TRIGGER"
        | "TRUE"
        | "UNDO"
        | "UNION"
        | "UNIQUE"
        | "UNLOCK"
        | "UNSIGNED"
        | "UPDATE"
        | "USAGE"
        | "USE"
        | "USING"
        | "UTC_DATE"
        | "UTC_TIME"
        | "UTC_TIMESTAMP"
        | "VALUES"
        | "VARBINARY"
        | "VARCHAR"
        | "VARCHARACTER"
        | "VARYING"
        | "VIRTUAL"
        | "WHEN"
        | "WHERE"
        | "WHILE"
        | "WINDOW"
        | "WITH"
        | "WRITE"
        | "XOR"
        | "YEAR_MONTH"
        | "ZEROFILL" => KeywordClass::Reserved,
        "ACTION" | "ALGORITHM" | "ANY" | "AUTO_INCREMENT" | "BEGIN" | "CHARSET" | "COMMENT"
        | "COMMIT" | "CONTAINS" | "CURRENT" | "DEFINER" | "DIAGNOSTICS" | "DO" | "DUMPFILE"
        | "ELSIF" | "END" | "ENGINE" | "ERRORS" | "FOLLOWING" | "FULL" | "HANDLER" | "INVOKER"
        | "NATIONAL" | "NCHAR" | "NO" | "NVARCHAR" | "OFFSET" | "PRECEDING" | "PROCESSLIST"
        | "ROLLBACK" | "SAVEPOINT" | "SECURITY" | "SOME" | "SQL_BUFFER_RESULT" | "SQL_NO_CACHE"
        | "START" | "STATUS" | "TABLES" | "TEMPORARY" | "TRANSACTION" | "UNBOUNDED" | "UNTIL"
        | "VARIABLES" | "VIEW" | "WARNINGS" => KeywordClass::Unreserved,
        _ => return None,
    })
}

/// Transact-SQL's "Reserved Keywords" (SQL Server 2022).
/// The unreserved words are the others the grammar reads as keywords.
fn mssql_keyword(upper: &str) -> Option<KeywordClass> {
    Some(match upper {
        "ADD"
        | "ALL"
        | "ALTER"
        | "AND"
        | "ANY"
        | "AS"
        | "ASC"
        | "AUTHORIZATION"
        | "BACKUP"
        | "BEGIN"
        | "BETWEEN"
        | "BREAK"
        | "BROWSE"
        | "BULK"
        | "BY"
        | "CASCADE"
        | "CASE"
        | "CHECK"
        | "CHECKPOINT"
        | "CLOSE"
        | "CLUSTERED"
        | "COALESCE"
        | "COLLATE"
        | "COLUMN"
        | "COMMIT"
        | "COMPUTE"
        | "CONSTRAINT"
        | "CONTAINS"
        | "CONTAINSTABLE"
        | "CONTINUE"
        | "CONVERT"
        | "CREATE"
        | "CROSS"
        | "CURRENT"
        | "CURRENT_DATE"
        | "CURRENT_TIME"
        | "CURRENT_TIMESTAMP"
        | "CURRENT_USER"
        | "CURSOR"
        | "DATABASE"
        | "DBCC"
        | "DEALLOCATE"
        | "DECLARE"
        | "DEFAULT"
        | "DELETE"
        | "DENY"
        | "DESC"
        | "DISK"
        | "DISTINCT"
        | "DISTRIBUTED"
        | "DOUBLE"
        | "DROP"
        | "DUMP"
        | "ELSE"
        | "END"
        | "ERRLVL"
        | "ESCAPE"
        | "EXCEPT"
        | "EXEC"
        | "EXECUTE"
        | "EXISTS"
        | "EXIT"
        | "EXTERNAL"
        | "FETCH"
        | "FILE"
        | "FILLFACTOR"
        | "FOR"
        | "FOREIGN"
        | "FREETEXT"
        | "FREETEXTTABLE"
        | "FROM"
        | "FULL"
        | "FUNCTION"
        | "GOTO"
        | "GRANT"
        | "GROUP"
        | "HAVING"
        | "HOLDLOCK"
        | "IDENTITY"
        | "IDENTITYCOL"
        | "IDENTITY_INSERT"
        | "IF"
        | "IN"
        | "INDEX"
        | "INNER"
        | "INSERT"
        | "INTERSECT"
        | "INTO"
        | "IS"
        | "JOIN"
        | "KEY"
        | "KILL"
        | "LEFT"
        | "LIKE"
        | "LINENO"
        | "LOAD"
        | "MERGE"
        | "NATIONAL"
        | "NOCHECK"
        | "NONCLUSTERED"
        | "NOT"
        | "NULL"
        | "NULLIF"
        | "OF"
        | "OFF"
        | "OFFSETS"
        | "ON"
        | "OPEN"
        | "OPENDATASOURCE"
        | "OPENQUERY"
        | "OPENROWSET"
        | "OPENXML"
        | "OPTION"
        | "OR"
        | "ORDER"
        | "OUTER"
        | "OVER"
        | "PERCENT"
        | "PIVOT"
        | "PLAN"
        | "PRECISION"
        | "PRIMARY"
        | "PRINT"
        | "PROC"
        | "PROCEDURE"
        | "PUBLIC"
        | "RAISERROR"
        | "READ"
        | "READTEXT"
        | "RECONFIGURE"
        | "REFERENCES"
        | "REPLICATION"
        | "RESTORE"
        | "RESTRICT"
        | "RETURN"
        | "REVERT"
        | "REVOKE"
        | "RIGHT"
        | "ROLLBACK"
        | "ROWCOUNT"
        | "ROWGUIDCOL"
        | "RULE"
        | "SAVE"
        | "SCHEMA"
        | "SECURITYAUDIT"
        | "SELECT"
        | "SEMANTICKEYPHRASETABLE"
        | "SEMANTICSIMILARITYDETAILSTABLE"
        | "SEMANTICSIMILARITYTABLE"
        | "SESSION_USER"
        | "SET"
        | "SETUSER"
        | "SHUTDOWN"
        | "SOME"
        | "STATISTICS"
        | "SYSTEM_USER"
        | "TABLE"
        | "TABLESAMPLE"
        | "TEXTSIZE"
        | "THEN"
        | "TO"
        | "TOP"
        | "TRAN"
        | "TRANSACTION"
        | "TRIGGER"
        | "TRUNCATE"
        | "TRY_CONVERT"
        | "TSEQUAL"
        | "UNION"
        | "UNIQUE"
        | "UNPIVOT"
        | "UPDATE"
        | "UPDATETEXT"
        | "USE"
        | "USER"
        | "VALUES"
        | "VARYING"
        | "VIEW"
        | "WAITFOR"
        | "WHEN"
        | "WHERE"
        | "WHILE"
        | "WITH"
        | "WITHIN"
        | "WRITETEXT" => KeywordClass::Reserved,
        "ABORT"
        | "ABSOLUTE"
        | "ACTION"
        | "AES"
        | "AFTER"
        | "AGGREGATE"
        | "ANSI_NULLS"
        | "ANSI_PADDING"
        | "APPLY"
        | "AT"
        | "ATOMIC"
        | "BEFORE"
        | "BIGINT"
        | "BINARY"
        | "BIT"
        | "BOOLEAN"
        | "CALLER"
        | "CATCH"
        | "CHAR"
        | "CHARACTER"
        | "CHOOSE"
        | "COMMITTED"
        | "CONCAT_NULL_YIELDS_NULL"
        | "COUNT_BIG"
        | "CURSOR_CLOSE_ON_COMMIT"
        | "DATA"
        | "DATE"
        | "DATEADD"
        | "DATEDIFF"
        | "DATENAME"
        | "DATEPART"
        | "DATETIME"
        | "DATETIME2"
        | "DATETIMEOFFSET"
        | "DEC"
        | "DECIMAL"
        | "DELAYED_DURABILITY"
        | "DESCRIPTION"
        | "ENABLE"
        | "ENCRYPTED"
        | "EOMONTH"
        | "ERROR"
        | "EVENT"
        | "EXPAND"
        | "FAST"
        | "FILEGROUP"
        | "FILENAME"
        | "FIRST"
        | "FLOAT"
        | "FOLLOWING"
        | "FORCE"
        | "FORMAT"
        | "FORWARD_ONLY"
        | "GEOGRAPHY"
        | "GEOMETRY"
        | "GETDATE"
        | "GLOBAL"
        | "GO"
        | "GREATEST"
        | "HASH"
        | "HIERARCHYID"
        | "IGNORE"
        | "IIF"
        | "IMAGE"
        | "IMMEDIATE"
        | "INCLUDE"
        | "INCREMENT"
        | "INSENSITIVE"
        | "INT"
        | "INTEGER"
        | "ISNULL"
        | "ISOLATION"
        | "JSON"
        | "KEEP"
        | "KEEPFIXED"
        | "LANGUAGE"
        | "LAST"
        | "LEAST"
        | "LEVEL"
        | "LOCAL"
        | "LOG"
        | "LOGIN"
        | "MATCHED"
        | "MAX"
        | "MAXDOP"
        | "MAXRECURSION"
        | "MIN"
        | "MINUTE"
        | "MONEY"
        | "MONTH"
        | "NAME"
        | "NCHAR"
        | "NEWID"
        | "NEXT"
        | "NO"
        | "NOEXPAND"
        | "NOLOCK"
        | "NOWAIT"
        | "NTEXT"
        | "NUMERIC"
        | "NVARCHAR"
        | "OBJECT"
        | "OBJECT_ID"
        | "OFFSET"
        | "ONLINE"
        | "OPTIMIZE"
        | "OUTPUT"
        | "PAGLOCK"
        | "PARTITION"
        | "PATH"
        | "PRECEDING"
        | "PRIOR"
        | "RANGE"
        | "RAW"
        | "READCOMMITTED"
        | "READCOMMITTEDLOCK"
        | "READONLY"
        | "READPAST"
        | "READUNCOMMITTED"
        | "REAL"
        | "REBUILD"
        | "RECEIVE"
        | "RECURSIVE"
        | "REORGANIZE"
        | "REPEATABLE"
        | "REPEATABLEREAD"
        | "RESULT"
        | "ROBUST"
        | "ROW"
        | "ROWLOCK"
        | "ROWS"
        | "ROWVERSION"
        | "SCOPE_IDENTITY"
        | "SCROLL"
        | "SECOND"
        | "SELF"
        | "SEND"
        | "SEQUENCE"
        | "SERIALIZABLE"
        | "SERVER"
        | "SESSION"
        | "SETS"
        | "SMALLDATETIME"
        | "SMALLINT"
        | "SMALLMONEY"
        | "SNAPSHOT"
        | "SQL_VARIANT"
        | "STATIC"
        | "STRING_AGG"
        | "STUFF"
        | "SYNONYM"
        | "SYSDATETIME"
        | "SYSUTCDATETIME"
        | "TABLOCK"
        | "TABLOCKX"
        | "TEMP"
        | "TEMPORARY"
        | "TEXT"
        | "THROW"
        | "TIME"
        | "TIMESTAMP"
        | "TINYINT"
        | "TRY"
        | "TYPE"
        | "UNBOUNDED"
        | "UNCOMMITTED"
        | "UNIQUEIDENTIFIER"
        | "UPDLOCK"
        | "VARBINARY"
        | "VARCHAR"
        | "VECTOR"
        | "WINDOW"
        | "WORK"
        | "XLOCK"
        | "XML"
        | "XSINIL"
        | "YEAR"
        | "ZONE" => KeywordClass::Unreserved,
        _ => return None,
    })
}

/// GoogleSQL for BigQuery's reserved keywords ("Lexical structure and syntax").
/// The unreserved words are the others the grammar reads as keywords.
fn bigquery_keyword(upper: &str) -> Option<KeywordClass> {
    Some(match upper {
        "ALL"
        | "AND"
        | "ANY"
        | "ARRAY"
        | "AS"
        | "ASC"
        | "ASSERT_ROWS_MODIFIED"
        | "AT"
        | "BETWEEN"
        | "BY"
        | "CASE"
        | "CAST"
        | "COLLATE"
        | "CONTAINS"
        | "CREATE"
        | "CROSS"
        | "CUBE"
        | "CURRENT"
        | "DEFAULT"
        | "DEFINE"
        | "DESC"
        | "DISTINCT"
        | "ELSE"
        | "END"
        | "ENUM"
        | "ESCAPE"
        | "EXCEPT"
        | "EXCLUDE"
        | "EXISTS"
        | "EXTRACT"
        | "FALSE"
        | "FETCH"
        | "FOLLOWING"
        | "FOR"
        | "FROM"
        | "FULL"
        | "GRAPH_TABLE"
        | "GROUP"
        | "GROUPING"
        | "GROUPS"
        | "HASH"
        | "HAVING"
        | "IF"
        | "IGNORE"
        | "IN"
        | "INNER"
        | "INTERSECT"
        | "INTERVAL"
        | "INTO"
        | "IS"
        | "JOIN"
        | "LATERAL"
        | "LEFT"
        | "LIKE"
        | "LIMIT"
        | "LOOKUP"
        | "MERGE"
        | "NATURAL"
        | "NEW"
        | "NO"
        | "NOT"
        | "NULL"
        | "NULLS"
        | "OF"
        | "ON"
        | "OR"
        | "ORDER"
        | "OUTER"
        | "OVER"
        | "PARTITION"
        | "PRECEDING"
        | "PROTO"
        | "QUALIFY"
        | "RANGE"
        | "RECURSIVE"
        | "RESPECT"
        | "RIGHT"
        | "ROLLUP"
        | "ROWS"
        | "SELECT"
        | "SET"
        | "SOME"
        | "STRUCT"
        | "TABLESAMPLE"
        | "THEN"
        | "TO"
        | "TREAT"
        | "TRUE"
        | "UNBOUNDED"
        | "UNION"
        | "UNNEST"
        | "USING"
        | "WHEN"
        | "WHERE"
        | "WINDOW"
        | "WITH"
        | "WITHIN" => KeywordClass::Reserved,
        "ABORT" | "ACCESS" | "ACTION" | "ADD" | "AGGREGATE" | "ALTER" | "ANALYZE" | "ASSERT"
        | "BATCH" | "BEGIN" | "BREAK" | "CALL" | "CHECK" | "CLUSTER" | "COLUMN" | "COMMIT"
        | "CONNECTION" | "CONSTRAINT" | "CONTINUE" | "CORRESPONDING" | "CYCLE" | "DATA"
        | "DATABASE" | "DECLARE" | "DELETE" | "DESCRIBE" | "DETERMINISTIC" | "DO" | "DROP"
        | "ELSEIF" | "ELSIF" | "ENFORCED" | "ERROR" | "EXCEPTION" | "EXECUTE" | "EXPORT"
        | "EXTERNAL" | "FILES" | "FILTER" | "FOREIGN" | "FORMAT" | "FUNCTION" | "GENERATED"
        | "GRANT" | "IDENTITY" | "IMMEDIATE" | "IMPORT" | "INDEX" | "INOUT" | "INPUT"
        | "INSERT" | "INVOKER" | "ITERATE" | "KEY" | "LANGUAGE" | "LEAVE" | "LET" | "LOAD"
        | "LOG" | "LOOP" | "MATCH" | "MATCHED" | "MATERIALIZED" | "MESSAGE" | "MODEL"
        | "MODULE" | "NOTHING" | "NUMERIC" | "OFFSET" | "OPTIONS" | "ORDINAL" | "OUT"
        | "OUTPUT" | "OVERWRITE" | "PAUSED" | "PERCENT" | "PIVOT" | "POLICIES" | "POLICY"
        | "PRIMARY" | "PRIVATE" | "PRIVILEGE" | "PRIVILEGES" | "PROCEDURE" | "PROJECT"
        | "PUBLIC" | "RAISE" | "READ" | "REFERENCES" | "REMOTE" | "RENAME" | "REPEAT"
        | "REPEATABLE" | "REPLACE" | "REPLICA" | "REPORT" | "RESTRICT" | "RETURN" | "RETURNS"
        | "REVOKE" | "ROLLBACK" | "ROW" | "RUN" | "SAFE_ADD" | "SAFE_CAST" | "SAFE_DIVIDE"
        | "SAFE_MULTIPLY" | "SAFE_NEGATE" | "SAFE_OFFSET" | "SAFE_ORDINAL" | "SAFE_SUBTRACT"
        | "SCHEMA" | "SEARCH" | "SECURITY" | "SEQUENCE" | "SESSION" | "SHOW" | "SNAPSHOT"
        | "SOURCE" | "SQL" | "STORED" | "SYSTEM_TIME" | "TABLE" | "TARGET" | "TEMP"
        | "TEMPORARY" | "TIME" | "TRANSACTION" | "TRANSFORM" | "TRUNCATE" | "TYPE" | "UNDROP"
        | "UNIQUE" | "UNKNOWN" | "UNPIVOT" | "UNTIL" | "UPDATE" | "VALIDATE" | "VALUE"
        | "VALUES" | "VIEW" | "WEEK" | "WHILE" | "WRITE" | "ZONE" => KeywordClass::Unreserved,
        _ => return None,
    })
}

/// Databricks SQL's "Reserved words": identifiers anywhere, a table alias only
/// in backticks (docs.databricks.com/en/sql/language-manual/sql-ref-reserved-words.html).
/// The unreserved words are the others the grammar reads as keywords.
fn databricks_keyword(upper: &str) -> Option<KeywordClass> {
    Some(match upper {
        "ANTI" | "CROSS" | "EXCEPT" | "FULL" | "INNER" | "INTERSECT" | "JOIN" | "LATERAL"
        | "LEFT" | "MASK" | "MINUS" | "NATURAL" | "ON" | "RIGHT" | "SEMI" | "UNION" | "USING" => {
            KeywordClass::NotTableAlias
        }
        "ABORT" | "ACCESS" | "ADD" | "AFTER" | "AGGREGATE" | "ANALYZE" | "ASC"
        | "AUTHORIZATION" | "BEGIN" | "BINARY" | "BUCKET" | "BUCKETS" | "CACHE" | "CASCADE"
        | "CATALOG" | "CHANGE" | "CHECK" | "CLONE" | "CLUSTER" | "CLUSTERED" | "CODEGEN"
        | "COMMENT" | "COMMIT" | "COMPACT" | "COMPACTIONS" | "COMPUTE" | "CONSTRAINT" | "COPY"
        | "COST" | "CTE" | "DATA" | "DATABASE" | "DATABASES" | "DAY" | "DAYS" | "DBPROPERTIES"
        | "DECLARE" | "DEFINED" | "DELIMITED" | "DELTA" | "DFS" | "DIRECTORY" | "DISTRIBUTE"
        | "DIV" | "DO" | "ENABLE" | "EXCHANGE" | "EXECUTE" | "EXPORT" | "EXTENDED" | "EXTERNAL"
        | "FIELDS" | "FILEFORMAT" | "FILES" | "FIRST" | "FORMAT" | "FORMATTED" | "FUNCTION"
        | "FUNCTIONS" | "GENERATED" | "GLOBAL" | "HISTORY" | "HOUR" | "HOURS" | "IDENTITY"
        | "IGNORE" | "IMMEDIATE" | "IMPORT" | "INDEX" | "INDEXES" | "INPUTFORMAT" | "INTERVAL"
        | "KEY" | "KEYS" | "LANGUAGE" | "LAST" | "LAZY" | "LIFECYCLE" | "LIQUID" | "LIST"
        | "LOAD" | "LOCATION" | "LOCK" | "LOCKS" | "LOGICAL" | "LOOP" | "MACRO" | "MAP"
        | "MATCHED" | "MATERIALIZED" | "MINUTE" | "MINUTES" | "MONTH" | "MONTHS" | "MSCK"
        | "NAMESPACE" | "NAMESPACES" | "NULLS" | "OPTIMIZE" | "OPTION" | "OPTIONS" | "OUT"
        | "OUTPUTFORMAT" | "OVER" | "OVERLAY" | "OVERWRITE" | "OWNER" | "PARTITIONED"
        | "PARTITIONS" | "PERCENT" | "PIVOT" | "POSITION" | "PRECEDING" | "PRIVILEGES"
        | "PROCEDURE" | "PURGE" | "RECOVER" | "RECURSIVE" | "REFRESH" | "RENAME" | "REPAIR"
        | "REPEATABLE" | "REPLACE" | "RESET" | "RESPECT" | "RESTORE" | "RESTRICT" | "RETURN"
        | "RETURNS" | "REWRITE" | "ROLLBACK" | "SCHEMA" | "SCHEMAS" | "SECOND" | "SECONDS"
        | "SERDE" | "SERDEPROPERTIES" | "SHOW" | "SKEWED" | "SORT" | "SORTED" | "SOURCE"
        | "SQL" | "START" | "STATISTICS" | "STORED" | "STRATIFY" | "STRUCT" | "SYNC"
        | "TABLESAMPLE" | "TBLPROPERTIES" | "TEMP" | "TEMPORARY" | "TERMINATED" | "TIMESTAMP"
        | "TOUCH" | "TRANSACTION" | "TRANSFORM" | "TYPE" | "UNBOUNDED" | "UNCACHE" | "UNDO"
        | "UNPIVOT" | "UNSET" | "VACUUM" | "VERSION" | "VIEW" | "VOLUME" | "VOLUMES" | "WEEK"
        | "WEEKS" | "WHILE" | "WRITE" | "YEAR" | "YEARS" | "ZONE" | "ZORDER" => {
            KeywordClass::Unreserved
        }
        _ => return None,
    })
}

/// Grammar shape of a `GRANT` statement.
///
/// `GRANT` grammars diverge across dialects on several orthogonal axes
/// (securable-class qualifiers, privilege-level cardinality, IAM-role
/// principals), so the parser dispatches to a dialect-family-specific typed
/// parser keyed on this descriptor rather than branching on the dialect name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantGrammar {
    /// Snowflake-shaped default: privilege list, optional `ON`, role/user grantees.
    Standard,
    /// `<class>::securable` qualifiers plus a trailing `AS <principal>` clause (MSSQL/T-SQL).
    ClassQualifiedSecurable,
    /// `ON [<object_type>] <priv_level>` with an object-type-prefixed privilege level (MySQL).
    ObjectTypePrivilegeLevel,
    /// IAM-role grants: backtick-quoted `roles/...` roles, `ON <resource_type> <name>` (BigQuery).
    IamRole,
}

/// Grammar shape of a procedure / function parameter list.
///
/// Each variant names the parameter syntax shape; the cross-dialect parameter
/// parser dispatches on it instead of on the dialect name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcedureParamGrammar {
    /// `name TYPE [DEFAULT expr]` — name then type, no mode keyword (Snowflake/Databricks).
    NameThenType,
    /// `[name] TYPE` — type required, name optional (BigQuery).
    OptionalNameThenType,
    /// `@name TYPE [= default] [OUTPUT|OUT|READONLY]` — `@`-prefixed name, trailing mode (MSSQL/T-SQL).
    AtPrefixedTrailingMode,
    /// `[IN|OUT|INOUT|VARIADIC] [name] TYPE [DEFAULT expr]` — leading mode, name optional (PostgreSQL).
    LeadingModeOptionalName,
    /// `[IN|OUT|INOUT] name TYPE` — leading mode, name required (MySQL).
    LeadingModeRequiredName,
}

/// What `$<digits>` is in a dialect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DollarNumber {
    /// A column of a FROM item by position (Snowflake `$1`).
    PositionalColumn,
    /// A bind parameter (PostgreSQL `$1`).
    Parameter,
    /// A money literal, with an optional fraction (T-SQL `$100`, `$1.50`).
    Money,
}

/// What `&&` is in a dialect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoubleAmpersand {
    /// Whether two arrays share an element (PostgreSQL).
    ArrayOverlap,
    /// Logical AND (MySQL).
    LogicalAnd,
}

/// What `^` is in a dialect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaretOperator {
    /// Bitwise exclusive OR (MySQL, T-SQL, BigQuery, Databricks).
    BitwiseXor,
    /// Exponentiation (PostgreSQL).
    Exponent,
}

/// An operator a dialect writes as a word. Where a dialect does not have
/// the operator, the word is an identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WordOperator {
    /// Logical exclusive OR: `a XOR b` (MySQL).
    Xor,
    /// Integer division: `a DIV b` (MySQL, Databricks).
    IntegerDivide,
    /// Modulo: `a MOD b` (MySQL).
    Modulo,
    /// Postfix NULL test: `a ISNULL` (PostgreSQL, Redshift).
    IsNull,
    /// Postfix NOT NULL test: `a NOTNULL` (PostgreSQL, Redshift).
    NotNull,
}

/// Whether a dialect reads a radix prefix on an integer literal, and in what
/// letter case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RadixPrefix {
    /// No such literal: `0x41` is the number `0` and the word `x41`.
    Absent,
    /// The lower-case prefix only (`0x`, `0b`; MySQL).
    LowerCase,
    /// The prefix in either case (`0x` / `0X`).
    AnyCase,
}

/// The spellings of a number literal a dialect reads beyond decimal digits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NumberLiteralGrammar {
    /// `0x…` hexadecimal digits.
    pub hexadecimal: RadixPrefix,
    /// `0b…` binary digits.
    pub binary: RadixPrefix,
    /// `0o…` octal digits.
    pub octal: RadixPrefix,
    /// `_` between digits (`1_000_000`, `0xFFFF_FFFF`) and after a radix
    /// prefix (`0o_755`).
    pub digit_separators: bool,
    /// A type suffix written against the number: `L`, `S`, `Y` on an
    /// integer, `D`, `F`, `BD` on any number (`10L`, `1.5BD`).
    pub type_suffixes: bool,
}

impl NumberLiteralGrammar {
    /// Decimal digits only, with an optional fraction and exponent.
    pub const DECIMAL: Self = Self {
        hexadecimal: RadixPrefix::Absent,
        binary: RadixPrefix::Absent,
        octal: RadixPrefix::Absent,
        digit_separators: false,
        type_suffixes: false,
    };
}

/// The order a bare star over `JOIN … USING (…)` lists the merged columns
/// in. They come before the other columns of either side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsingColumnOrder {
    /// In the order the `USING` list is written.
    ListedOrder,
    /// In the order the left side holds them.
    LeftTableOrder,
    /// Not stated: the order is known only where every order agrees.
    NotStated,
}

/// What the column list of `CREATE TABLE t (a INT, …) AS SELECT …` is to
/// the query's columns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypedCreateAs {
    /// The list names the query's columns: the i-th name is the query's
    /// i-th column.
    NamesByPosition,
    /// Each listed name the query has no column of is a column of its own,
    /// before the query's columns; a listed name the query has a column of
    /// is that column.
    AddsColumns,
    /// Not stated: read as [`TypedCreateAs::NamesByPosition`].
    NotStated,
}

/// What the column list of `CREATE VIEW v (a, …) AS SELECT …` or `CREATE
/// TABLE t (a, …) AS SELECT …` means where it names fewer columns than the
/// query gives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShorterColumnList {
    /// It names the query's first columns; the others keep the query's
    /// names.
    NamesTheFirst,
    /// Not stated: read as naming every column of the relation.
    NotStated,
}

/// Which part of a table's name a database is, so which part `USE
/// database` sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatabaseLevel {
    /// The first of three parts, holding schemas: `database.schema.table`.
    AboveSchema,
    /// The schema: a table's name has two parts, `database.table`.
    Schema,
    /// Not stated: read as [`DatabaseLevel::AboveSchema`].
    NotStated,
}

/// Where a table `CREATE TEMPORARY TABLE` makes stands among the tables of
/// its name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemporaryTables {
    /// In the schema its name gives, the current one where it gives none,
    /// hiding a table of its name there.
    InSchema,
    /// In a schema of the session's own, which a name written without a
    /// database or schema reaches before any other, and a qualified name
    /// never does, but one qualified by `name`, the schema's name where a
    /// statement may write it (PostgreSQL's `pg_temp`). A table made under
    /// that name is temporary.
    SessionSchema { name: Option<&'static str> },
    /// Not stated: read as [`TemporaryTables::InSchema`].
    NotStated,
}

/// What an `UPDATE` or `DELETE` target writes where a CTE in scope has its
/// name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CteWriteTarget {
    /// The CTE: the statement writes the table the CTE's query reads,
    /// through the query's rows.
    WritesThroughCte,
    /// Not stated: read as a table's name.
    NotStated,
}

/// Where a name written without a schema is looked for in a session the
/// script sets no schema in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultSearchPath {
    /// In these schemas, in order; a name created without a schema goes to
    /// the first. PostgreSQL's and Redshift's `"$user", public` is
    /// `public`: the schema named for the connecting role is not one a
    /// script names. T-SQL's is the user's default schema, `dbo`;
    /// Databricks' current schema starts as `default`.
    Schemas(&'static [&'static str]),
    /// In the schema the connection puts the session in, which the script
    /// does not say: Snowflake's current schema, MySQL's current database,
    /// BigQuery's default dataset.
    SessionSchema,
    /// Not stated: read as [`DefaultSearchPath::SessionSchema`].
    NotStated,
}

/// Whether an `UPDATE` or `DELETE` names its target by one of its FROM /
/// `USING` sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteTargetSource {
    /// A source that answers to the target's name, or reads the target's
    /// table, is the target's row: `UPDATE e … FROM t e JOIN s …` writes
    /// the rows of `t` the join matches.
    NamedBySource,
    /// The target is a source of its own beside the list; a source of the
    /// target's table is another instance of it (`UPDATE t … FROM t t2 …`
    /// pairs every row of `t` with the list's rows).
    BesideSources,
    /// Not stated: read as [`WriteTargetSource::NamedBySource`].
    NotStated,
}

/// What a dialect's syntax means where engines read the same statement
/// differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyntaxMeaning {
    /// The order of the columns a `USING` join merges.
    pub using_column_order: UsingColumnOrder,
    /// What a typed column list of `CREATE TABLE … AS` names.
    pub typed_create_as: TypedCreateAs,
    /// What a column list over a query naming fewer columns than the
    /// query gives means.
    pub shorter_column_list: ShorterColumnList,
    /// Which part of a table's name a database is.
    pub database_level: DatabaseLevel,
    /// Where a temporary table stands among the tables of its name.
    pub temporary_tables: TemporaryTables,
    /// What a write's target names where a CTE has its name.
    pub cte_write_target: CteWriteTarget,
    /// Whether a write names its target by a FROM source.
    pub write_target_source: WriteTargetSource,
    /// Where a name written without a schema is looked for when the script
    /// sets no schema.
    pub default_search_path: DefaultSearchPath,
}

impl SyntaxMeaning {
    /// Nothing stated.
    pub const NOT_STATED: Self = Self {
        using_column_order: UsingColumnOrder::NotStated,
        typed_create_as: TypedCreateAs::NotStated,
        shorter_column_list: ShorterColumnList::NotStated,
        database_level: DatabaseLevel::NotStated,
        temporary_tables: TemporaryTables::NotStated,
        cte_write_target: CteWriteTarget::NotStated,
        write_target_source: WriteTargetSource::NotStated,
        default_search_path: DefaultSearchPath::NotStated,
    };
}

/// Trait defining dialect-specific SQL behavior.
///
/// Each SQL dialect (Snowflake, PostgreSQL, MySQL, etc.) has different:
/// - Reserved keywords
/// - Available functions
/// - Supported operators
/// - Identifier quoting rules
/// - Type systems
/// - Statement types
///
/// This trait encapsulates those differences to enable multi-dialect support
/// without code duplication.
pub trait Dialect: Send + Sync + std::fmt::Debug {
    /// Name of the dialect (e.g., "snowflake", "postgresql")
    fn name(&self) -> &'static str;

    // ========================================================================
    // Keyword Rules
    // ========================================================================

    /// The class the dialect's published keyword list gives `word`, compared
    /// without case: whether it is an identifier, a table's alias, a select
    /// item's label. `None` where the list does not hold the word, and for a
    /// dialect that publishes no list (the default), whose keyword methods
    /// then answer.
    fn keyword_class(&self, _word: &str) -> Option<KeywordClass> {
        None
    }

    /// Check if a word is a reserved keyword in this dialect.
    ///
    /// Reserved keywords cannot be used as unquoted identifiers.
    fn is_reserved_keyword(&self, word: &str) -> bool;

    /// Check if a word is a keyword (reserved or unreserved).
    fn is_keyword(&self, word: &str) -> bool;

    /// Whether a keyword token can be used as an unquoted identifier in this dialect.
    ///
    /// Default behavior follows the common SQL rule: non-reserved keywords may
    /// be used as unquoted identifiers, while reserved keywords may not.
    /// Dialects with stricter or more permissive behavior can override.
    fn keyword_can_be_unquoted_identifier(&self, word: &str) -> bool {
        !self.is_reserved_keyword(word)
    }

    /// Whether a keyword token can be used as an unquoted table alias.
    ///
    /// Most dialects follow identifier eligibility, but some dialects have a
    /// smaller alias-restricted subset.
    fn keyword_can_be_unquoted_alias(&self, word: &str) -> bool {
        self.keyword_can_be_unquoted_identifier(word)
    }

    /// Whether a keyword can name a select-list column without `AS` before it
    /// (`SELECT MAX(id) end FROM t`).
    ///
    /// Default: where the keyword can be an unquoted identifier. A dialect that
    /// accepts reserved words as bare column labels says which words still
    /// need `AS`.
    fn keyword_can_be_bare_column_label(&self, word: &str) -> bool {
        self.keyword_can_be_unquoted_identifier(word)
    }

    // ========================================================================
    // Identifier Rules
    // ========================================================================

    /// Character used to quote identifiers (e.g., '"' for Snowflake/PostgreSQL, '`' for MySQL)
    fn identifier_quote_char(&self) -> char;

    /// Maximum length of an identifier (None = unlimited)
    fn max_identifier_length(&self) -> Option<usize>;

    /// Whether identifiers are case-sensitive when unquoted
    fn unquoted_identifiers_case_sensitive(&self) -> bool;

    /// Extra non-alphanumeric characters allowed in unquoted identifiers (beyond `_`).
    ///
    /// Snowflake/MSSQL allow `$` and `#` in unquoted identifiers.
    /// PostgreSQL and MySQL do not — `#` is an operator/comment and `$` is for
    /// dollar-quoting/parameters.
    fn extra_identifier_chars(&self) -> &'static [char] {
        &[] // Conservative default: only alphanumeric + underscore
    }

    // ========================================================================
    // String Literal Rules
    // ========================================================================

    /// Character used to quote string literals (typically '\'')
    fn string_quote_char(&self) -> char;

    /// Whether this dialect supports double-quoted strings (Snowflake: yes, PostgreSQL: no)
    fn supports_double_quoted_strings(&self) -> bool;

    /// Whether string literals support escape sequences like \n, \t
    fn supports_string_escapes(&self) -> bool;

    /// Whether backslash escapes are active inside regular single-quoted strings.
    /// Snowflake: true (always active), MySQL: true (default NO_BACKSLASH_ESCAPES=OFF),
    /// PostgreSQL: false (only E'...' strings have backslash escapes)
    fn backslash_escapes_in_single_quoted_strings(&self) -> bool {
        false
    }

    // ========================================================================
    // Comment Rules
    // ========================================================================

    /// Whether line comments (-- ...) are supported
    fn supports_line_comments(&self) -> bool {
        true // All modern dialects support this
    }

    /// Whether block comments (/* ... */) are supported
    fn supports_block_comments(&self) -> bool {
        true // All modern dialects support this
    }

    /// Whether nested block comments are supported
    fn supports_nested_block_comments(&self) -> bool {
        false // Most dialects don't support this
    }

    /// Whether `--` line comments require a trailing space/whitespace.
    /// MySQL: true (`--<space>` is required; bare `--` is NOT a comment).
    /// Snowflake/PostgreSQL: false (-- starts a comment regardless).
    fn requires_space_after_double_dash(&self) -> bool {
        false
    }

    /// Whether `/*!...*/` (and MariaDB `/*M!...*/`) comments hold SQL the
    /// server runs: their markers are trivia and the text between is lexed
    /// as SQL. MySQL: true. Elsewhere every `/* */` is a plain comment.
    fn supports_version_comments(&self) -> bool {
        false
    }

    /// Whether `//` starts a line comment. Snowflake: true. Elsewhere `//`
    /// is two `/` tokens, and `//*` begins a block comment after a `/`.
    fn slash_slash_is_line_comment(&self) -> bool {
        false
    }

    /// Whether it is unknown if the dialect's block comments nest. A block
    /// comment that holds a `/*` is then not read as either: it is lexed as
    /// unreadable text, which strict analysis refuses.
    fn block_comment_nesting_unknown(&self) -> bool {
        false
    }

    // ========================================================================
    // Client Driver Syntax
    // ========================================================================

    /// Whether this dialect's client driver performs `&var` / `&{var}`
    /// variable substitution on SQL text before the server parses it
    /// (Snowflake's SnowSQL CLI). Gates the pre-parse substitution pass.
    /// Other clients use different sigils (psql `:var`, sqlcmd `$(var)`)
    /// and are intentionally out of scope here.
    fn supports_snowsql_substitution(&self) -> bool {
        false
    }

    // ========================================================================
    // Statement Support
    // ========================================================================

    /// Whether MERGE statements are supported
    fn supports_merge(&self) -> bool;

    /// Whether CTEs (WITH clause) are supported
    fn supports_cte(&self) -> bool;

    /// Whether LATERAL joins are supported
    fn supports_lateral(&self) -> bool;

    /// Whether window functions are supported
    fn supports_window_functions(&self) -> bool;

    /// Whether named WINDOW clauses are supported in SELECT.
    ///
    /// Example: `SELECT ... WINDOW w AS (PARTITION BY ...)`
    fn supports_named_window_clause(&self) -> bool {
        false
    }

    /// Whether QUALIFY clause is supported (Snowflake-specific)
    fn supports_qualify(&self) -> bool;

    /// Whether SAMPLE/TABLESAMPLE clause is supported (row sampling)
    fn supports_sample(&self) -> bool;

    /// Whether time travel (AT/BEFORE) is supported (Snowflake-specific)
    fn supports_time_travel(&self) -> bool;

    /// Whether PIVOT clause is supported
    fn supports_pivot(&self) -> bool;

    /// Whether UNPIVOT clause is supported
    fn supports_unpivot(&self) -> bool;

    /// Whether FLATTEN table function is supported (semi-structured data)
    fn supports_flatten(&self) -> bool;

    /// Whether VALUES can be used as a table source
    fn supports_values_as_table(&self) -> bool;

    /// Whether the given identifier should be treated as a table-valued function
    /// when appearing in FROM clause followed by `(`.
    /// Examples: UNNEST (BigQuery), GENERATE_SERIES (PostgreSQL)
    fn is_table_valued_function(&self, name: &str) -> bool;

    /// The arguments of a call of `function` that are not values: each
    /// one's position and what is written there (T-SQL's `CONVERT(INT, x)`,
    /// `DATEADD(day, 1, d)`). Empty where every argument is a value.
    fn non_value_arguments(&self, _function: &str) -> &'static [NonValueArgument] {
        &[]
    }

    /// The arguments a keyword introduces in a call of `function`, in this
    /// dialect: each keyword and what follows it (`OVERLAY(s PLACING r FROM
    /// a)`, MySQL's `CONVERT(s USING utf8mb4)`). Empty where commas
    /// separate every argument.
    fn introduced_arguments(&self, _function: &str) -> &'static [IntroducedArgument] {
        &[]
    }

    /// Whether `INTERVAL` takes MySQL's compound units (`HOUR_MINUTE`,
    /// `DAY_SECOND`, …): `INTERVAL '1:30' HOUR_MINUTE`.
    fn compound_interval_units(&self) -> bool {
        false
    }

    /// Whether a SELECT may write MySQL's select options before its list
    /// (`HIGH_PRIORITY`, `STRAIGHT_JOIN`, `SQL_CALC_FOUND_ROWS`, …).
    fn select_options(&self) -> bool {
        false
    }

    /// Whether a script may hold the client's `DELIMITER x` command, which
    /// makes `x` the statement terminator until the next one.
    fn client_delimiter_command(&self) -> bool {
        false
    }

    /// Whether a name of four or more parts names a server first, then a
    /// database, a schema and the object (T-SQL's linked servers). Where
    /// not, the parts before the last two are the database's path
    /// (BigQuery: `project.region-us.INFORMATION_SCHEMA.JOBS`).
    fn four_part_names_name_a_server(&self) -> bool {
        true
    }

    /// Whether a script may hold psql's commands that send the query
    /// written before them (`\g`, `\gexec`), read as its terminator.
    fn psql_meta_commands(&self) -> bool {
        false
    }

    /// Whether string literals written one after another are one string,
    /// their values joined (MySQL `'a' 'b'`, Databricks `"a" "b"`); where
    /// not, the second may be the first's alias (T-SQL).
    fn adjacent_string_literals_join(&self) -> bool {
        false
    }

    /// The date or time part `word` names in this dialect, as a call's
    /// unit argument or EXTRACT's field writes it: its name or plural
    /// ([`crate::ast::DatePart::from_name`]), or one of the dialect's
    /// abbreviations.
    fn date_part(&self, word: &str) -> Option<crate::ast::DatePart> {
        crate::ast::DatePart::from_name(word)
    }

    /// Whether EXCEPT can be used as a star modifier: `SELECT * EXCEPT (col1, col2)`
    /// BigQuery uses EXCEPT; Snowflake/DuckDB use EXCLUDE.
    fn except_is_star_modifier(&self) -> bool;

    /// Whether the dialect supports a projection-level trailing `EXCLUDE (cols)`
    /// clause on the SELECT list, e.g. Redshift `SELECT *, x EXCLUDE (a, b)`.
    /// Distinct from [`Self::except_is_star_modifier`], which gates EXCEPT/EXCLUDE
    /// glued to a single `*`; this gates the clause that trails the whole list.
    /// It is ambiguous with a bare column alias (`SELECT x exclude`), so it must
    /// be dialect-gated rather than parsed permissively.
    fn supports_projection_exclude(&self) -> bool;

    /// Whether DECLARE must be followed by BEGIN...END to form a scripting block.
    /// Snowflake: true  — DECLARE...BEGIN...END is required.
    /// BigQuery:  false — DECLARE, SET, IF, etc. are independent top-level statements.
    fn scripting_requires_begin(&self) -> bool;

    /// Whether a top-level DECLARE keyword starts a multi-statement scripting block
    /// (DECLARE...BEGIN...END).
    /// Snowflake/PG/MySQL: true  — DECLARE opens a block that must end with BEGIN...END.
    /// BigQuery/Databricks: false — DECLARE is a standalone statement.
    /// MSSQL: false — DECLARE is standalone; BEGIN...END blocks are separate constructs.
    /// Defaults to `scripting_requires_begin()` which is correct for most dialects.
    fn declare_starts_block(&self) -> bool {
        self.scripting_requires_begin()
    }

    /// Whether `DECLARE [OR REPLACE]` may be followed by the keyword
    /// `VARIABLE` (or `VAR`) before the variable's name (Databricks: `DECLARE
    /// VARIABLE x INT`). Where false, `VARIABLE` after `DECLARE` is a name.
    fn declare_has_variable_keyword(&self) -> bool {
        false
    }

    // ========================================================================
    // Operator Support
    // ========================================================================

    /// Whether the || operator is string concatenation (true) or logical OR (false)
    fn pipe_pipe_is_concat(&self) -> bool;

    /// Whether the dialect supports the -> and ->> operators (JSON access)
    fn supports_json_operators(&self) -> bool;

    /// Whether the dialect supports the => operator (named arguments)
    fn supports_named_args_operator(&self) -> bool;

    /// Whether the dialect supports the :: type cast operator (PostgreSQL style)
    fn supports_type_cast_operator(&self) -> bool;

    /// Whether the dialect supports DISTINCT ON (expr_list) syntax (PostgreSQL)
    fn supports_distinct_on(&self) -> bool;

    /// Whether the dialect supports RETURNING clause (PostgreSQL)
    fn supports_returning(&self) -> bool;

    /// Whether the dialect supports FOR UPDATE clause
    /// Snowflake: Only for hybrid tables
    /// PostgreSQL/Oracle: Standard feature
    fn supports_for_update(&self) -> bool;

    /// Whether the dialect supports FOR UPDATE NOWAIT
    fn supports_for_update_nowait(&self) -> bool;

    /// Whether the dialect supports FOR UPDATE WAIT n
    /// Snowflake and Oracle support this; PostgreSQL and MySQL do not
    fn supports_for_update_wait(&self) -> bool;

    // ========================================================================
    // Clause Boundary Rules
    // ========================================================================

    /// Whether a keyword acts as a clause boundary in this dialect.
    ///
    /// Clause boundary keywords terminate alias parsing and FROM clause scanning.
    /// This method handles dialect-specific keywords that are NOT universal boundaries:
    ///
    /// - `RETURNING`: clause boundary in PostgreSQL (terminates SELECT in INSERT...SELECT),
    ///   but a valid identifier/alias in Snowflake.
    /// - Future: BigQuery may need `QUALIFY` gated differently, etc.
    ///
    /// Universal clause boundaries (WHERE, GROUP, ORDER, LIMIT, JOIN keywords, etc.)
    /// are handled by the static `is_clause_keyword_lexeme` / `is_table_clause_keyword`
    /// functions and do NOT need to appear here.
    fn is_clause_boundary_keyword(&self, _word: &str) -> bool {
        false
    }

    // ========================================================================
    // Lexer-Level Tokenization Rules
    // ========================================================================

    /// Whether `#` starts a line comment (MySQL) or is an operator (Snowflake/PostgreSQL).
    fn hash_is_line_comment(&self) -> bool {
        false // Only MySQL treats # as a comment delimiter
    }

    /// Whether the dialect supports E'...' escape string literals (PostgreSQL).
    fn supports_escape_string_literals(&self) -> bool {
        false
    }

    /// Whether the dialect supports $$...$$ or $tag$...$tag$ dollar-quoted strings (PostgreSQL).
    fn supports_dollar_quoted_strings(&self) -> bool {
        false
    }

    /// Whether `$$…$$` is a string the lexer gives as words between two `$$`
    /// delimiters (`$$abc$$`, `$$ a b$$`; Snowflake). Where false, a word
    /// starting with `$$` is a name.
    fn dollar_strings_written_as_words(&self) -> bool {
        false
    }

    /// Whether a table reference in `FROM` may be written `STREAM table` or
    /// `STREAM ( table )`, a streaming read of that table (Databricks).
    /// Where false, `STREAM` is a name.
    fn stream_reads_a_table(&self) -> bool {
        false
    }

    /// Whether a select item's alias may be a string literal, after `AS`
    /// or bare (`SELECT c AS 'x'`, `SELECT c 'x'`; T-SQL, MySQL). A string
    /// after a string literal or a type name is never such an alias.
    fn string_column_alias(&self) -> bool {
        false
    }

    /// What `$<digits>` is: a column by position unless the dialect says
    /// otherwise.
    fn dollar_number(&self) -> DollarNumber {
        DollarNumber::PositionalColumn
    }

    /// Whether `$name` in an expression references a session variable
    /// (Snowflake's `SET v = …; SELECT $v`). Where false, such a word is a
    /// name.
    fn dollar_name_is_session_variable(&self) -> bool {
        false
    }

    /// What `&&` is: array overlap unless the dialect says otherwise.
    fn double_ampersand(&self) -> DoubleAmpersand {
        DoubleAmpersand::ArrayOverlap
    }

    /// What `^` is: bitwise exclusive OR unless the dialect says otherwise.
    fn caret(&self) -> CaretOperator {
        CaretOperator::BitwiseXor
    }

    /// Whether `@`, `^@`, `|/` and `?` followed by `|` or `&` are
    /// PostgreSQL's operators: `@@`, `@?`, a bare `@`, `^@`, `|/`, `?|` and
    /// `?&`. Where false, the default, a bare `@` is left unread (a
    /// Snowflake stage reference reads it) and a `?` is a placeholder
    /// whatever follows it.
    fn supports_postgres_operator_symbols(&self) -> bool {
        false
    }

    /// The operator the bare word `word` is in this dialect. `None`, the
    /// default, leaves it an identifier.
    fn word_operator(&self, _word: &str) -> Option<WordOperator> {
        None
    }

    /// The number literals the dialect reads: decimal only unless it says
    /// otherwise.
    fn number_literal_grammar(&self) -> NumberLiteralGrammar {
        NumberLiteralGrammar::DECIMAL
    }

    /// What the dialect's syntax means where engines differ: nothing
    /// stated unless the dialect says otherwise.
    fn syntax_meaning(&self) -> SyntaxMeaning {
        SyntaxMeaning::NOT_STATED
    }

    /// Whether the dialect supports national string literals prefixed with `N`,
    /// e.g. `N'text'` (MSSQL/T-SQL).
    fn supports_national_string_literals(&self) -> bool {
        false
    }

    /// Whether the dialect supports `[...]` bracket-delimited identifiers (MSSQL/T-SQL).
    /// When true, the lexer treats `[identifier]` as a quoted identifier instead of
    /// punctuation brackets.
    fn supports_bracket_identifiers(&self) -> bool {
        false
    }

    /// Whether `@` and `@@` are identifier prefixes (MSSQL/T-SQL).
    /// When true, `@name` and `@@VERSION` are lexed as single `AtVariable` identifier tokens.
    fn supports_at_sign_identifiers(&self) -> bool {
        false
    }

    /// Whether bare `@` should be lexed as the `Operator::At` token.
    /// Databricks uses `@` as a time travel separator: `events@v123`, `events@20190101`.
    /// When true, `@` produces `Operator::At` instead of `TokenKind::Unknown`.
    fn at_is_operator(&self) -> bool {
        false
    }

    /// Whether `#` and `##` are identifier prefixes for temp tables (MSSQL/T-SQL).
    /// When true, `#temp` and `##global_temp` are lexed as single `TempTable` identifier tokens.
    /// Mutually exclusive with `hash_is_line_comment()` — if `#` is a comment, it can't be an identifier.
    fn hash_is_identifier_prefix(&self) -> bool {
        false
    }

    // ========================================================================
    // Statement Grammar Shape
    //
    // These predicates gate genuine grammar-shape divergences that the
    // permissive parser cannot disambiguate from tokens alone. They describe
    // the SQL construct, not the dialect — dialect names appear only in docs.
    // ========================================================================

    /// Whether `GO` is a batch separator statement (MSSQL/T-SQL).
    fn supports_go_batch_separator(&self) -> bool {
        false
    }

    /// Whether IF/WHILE take a bare statement or `BEGIN...END` block with no
    /// `THEN`/`DO` and no `END IF`/`END WHILE` terminator (MSSQL/T-SQL), rather
    /// than the `IF...THEN...END IF` / `WHILE...DO...END WHILE` block grammar.
    fn uses_block_scoped_control_flow(&self) -> bool {
        false
    }

    /// Whether `EXEC[UTE]` invokes a stored procedure (MSSQL/T-SQL
    /// `EXEC proc @p = val`), as opposed to `EXECUTE IMMEDIATE` dynamic SQL.
    fn supports_exec_procedure_call(&self) -> bool {
        false
    }

    /// Whether `PRINT <expr>` diagnostic output is a statement (MSSQL/T-SQL).
    fn supports_print_statement(&self) -> bool {
        false
    }

    /// Whether `RECONFIGURE [WITH OVERRIDE]` is a statement (MSSQL/T-SQL).
    fn supports_reconfigure_statement(&self) -> bool {
        false
    }

    /// Whether `REVERT [WITH COOKIE = @var]` is a statement (MSSQL/T-SQL,
    /// ends an `EXECUTE AS` context switch).
    fn supports_revert_statement(&self) -> bool {
        false
    }

    /// Whether a bare `CREATE / ALTER / DROP CREDENTIAL` uses the
    /// T-SQL `WITH IDENTITY = …, SECRET = …` grammar (vs the Databricks
    /// storage-credential grammar).
    fn bare_credential_is_identity_secret(&self) -> bool {
        false
    }

    /// Whether `THROW` is an exception-raising statement (MSSQL/T-SQL).
    fn supports_throw_statement(&self) -> bool {
        false
    }

    /// Whether `RAISERROR(...)` is an error-reporting statement (MSSQL/T-SQL).
    fn supports_raiserror_statement(&self) -> bool {
        false
    }

    /// Whether `WAITFOR` is a delay/wait statement (MSSQL/T-SQL).
    fn supports_waitfor_statement(&self) -> bool {
        false
    }

    /// Whether `GOTO label` unconditional jump is a statement (MSSQL/T-SQL).
    fn supports_goto_statement(&self) -> bool {
        false
    }

    /// Whether `BULK INSERT` bulk data import is a statement (MSSQL/T-SQL).
    fn supports_bulk_insert_statement(&self) -> bool {
        false
    }

    /// Whether `label:` statement labels (jump targets) are recognized at
    /// statement level (MSSQL/T-SQL).
    fn supports_statement_labels(&self) -> bool {
        false
    }

    /// Whether `SET` requires lookahead to distinguish a session-option form
    /// (`SET NOCOUNT ON`) from a variable assignment (`SET @v = expr`)
    /// (MSSQL/T-SQL).
    fn set_distinguishes_options(&self) -> bool {
        false
    }

    /// Whether `SET name = value` configures a runtime/session parameter
    /// (PostgreSQL `SET search_path = ...`).
    fn supports_session_config_set(&self) -> bool {
        false
    }

    /// What `SET name = value`, written without `VAR` and read as an
    /// assignment, gives its value to.
    fn set_assigns(&self) -> SetAssigns {
        SetAssigns::ScriptVariable
    }

    /// Whether `EXECUTE name [(args)]` runs a prepared statement (PostgreSQL).
    fn supports_prepared_statement_execution(&self) -> bool {
        false
    }

    /// Whether a bare `EXECUTE <command-string-expr>` (no `IMMEDIATE`
    /// keyword) inside a routine body is PL/pgSQL dynamic SQL —
    /// `EXECUTE <expr> [INTO [STRICT] tgt [, …]] [USING expr [, …]]`
    /// (PostgreSQL / Redshift). This is the one genuine grammar
    /// ambiguity for `EXECUTE`: in PL/pgSQL the keyword introduces
    /// dynamic SQL, whereas elsewhere a bare `EXECUTE x` would be a
    /// prepared-statement / task surface. Dialects returning `true`
    /// let the shared EXECUTE-IMMEDIATE parser accept the missing
    /// `IMMEDIATE` keyword and the `INTO STRICT` modifier.
    fn supports_plpgsql_dynamic_execute(&self) -> bool {
        false
    }

    /// Severity-level keywords that may directly follow `RAISE` in this
    /// dialect's PL/pgSQL-style grammar — `RAISE NOTICE 'fmt' [, arg …]
    /// [USING option = expr …]`. Non-empty only for PostgreSQL-family
    /// dialects. The parser uses it to recognize the optional leading
    /// level so the message / argument / USING tail is parsed
    /// structurally rather than left as an unparsed fragment. Empty here
    /// keeps the Snowflake (`RAISE exc_name`) / BigQuery (`RAISE USING
    /// MESSAGE = expr`) grammar on its own path.
    fn raise_severity_levels(&self) -> &'static [&'static str] {
        &[]
    }

    /// Whether a function literally named `FORMAT(...)` builds a SQL
    /// string by template interpolation in this dialect — PostgreSQL /
    /// Redshift (`%I` / `%L` / `%s`) and BigQuery (printf-style). False
    /// where `FORMAT` is a value/number formatter (MySQL `FORMAT(n, d)`,
    /// T-SQL `FORMAT(val, fmt)`), so a `FORMAT` call in an EXECUTE
    /// argument is NOT a dynamic-SQL construction surface. Consumers use
    /// it to classify the argument shape; whether a shape is acceptable
    /// is their decision.
    fn format_function_builds_sql(&self) -> bool {
        false
    }

    /// SQL **identifier**-quoting builtins in this dialect — functions that
    /// escape a runtime value into a quoted identifier slot it cannot break
    /// out of (PostgreSQL/Redshift `quote_ident`, T-SQL `QUOTENAME`). Lets
    /// consumers recognize an injection-clean concatenation; whether that is
    /// acceptable is their decision. Matched case-insensitively. Empty by
    /// default.
    fn dynamic_sql_identifier_quoting_functions(&self) -> &'static [&'static str] {
        &[]
    }

    /// SQL **literal**-quoting builtins in this dialect — functions that
    /// escape a runtime value into a quoted string-literal slot
    /// (PostgreSQL/Redshift `quote_literal`/`quote_nullable`, MySQL `QUOTE`).
    /// Companion to [`Self::dynamic_sql_identifier_quoting_functions`];
    /// recognition only; the verdict is the consumer's. Empty by default.
    fn dynamic_sql_literal_quoting_functions(&self) -> &'static [&'static str] {
        &[]
    }

    /// The routines the dialect defines whose arguments the engine reads,
    /// with what each does with them: which it runs as SQL text, here or on
    /// another server, which it takes a password, a command or a connection
    /// in. Recognition only; the verdict is the rules'.
    fn system_routines(&self) -> &'static [SystemRoutine] {
        &[]
    }

    /// The routine of [`Self::system_routines`] that renames a table or a
    /// column (T-SQL `sp_rename`); `None` where the dialect has none.
    fn rename_routine(&self) -> Option<RenameRoutine> {
        None
    }

    /// The functions the dialect builds in whose arguments the engine
    /// reads, each named as a call writes it: which take a key or a
    /// passphrase. A call names one by that name alone, in any case.
    /// Recognition only; the verdict is the rules'.
    fn builtin_routines(&self) -> &'static [SystemRoutine] {
        &[]
    }

    /// The grammar places whose string literal the dialect's documentation
    /// gives a format, a setting or a description, never a credential, a
    /// command or SQL text: a report may print a literal written there.
    /// Recognition only.
    fn shown_slots(&self) -> &'static [ShownSlot] {
        &[]
    }

    /// The settings whose value the dialect's documentation gives as a
    /// name, a format, a number or a switch, never a credential: a report
    /// may print the value a `SET`, an `ALTER … SET` or a routine's `SET`
    /// clause gives one. Every other setting's value is masked. Recognition
    /// only.
    fn shown_settings(&self) -> &'static [ShownSetting] {
        &[]
    }

    /// The data types the dialect's documentation gives other names, each
    /// with those names: a type written by any of them is the one type
    /// (PostgreSQL `int4`, `integer`). Recognition only.
    fn type_synonyms(&self) -> &'static [TypeSynonyms] {
        &[]
    }

    /// The routines of its own the dialect's documentation gives other
    /// names: none here.
    fn routine_synonyms(&self) -> &'static [RoutineSynonyms] {
        &[]
    }

    /// The name [`Self::routine_synonyms`] gives the routine a call of
    /// `name` with `args` arguments calls, `name` in upper case; `None`
    /// where it is not a name of one of them at that arity.
    fn routine_name(&self, name: &str, args: usize) -> Option<&'static str> {
        self.routine_synonyms()
            .iter()
            .find(|synonyms| {
                synonyms.name == name
                    || (synonyms.others.contains(&name)
                        && synonyms.arity.is_none_or(|arity| arity == args))
            })
            .map(|synonyms| synonyms.name)
    }

    /// The name [`Self::type_synonyms`] gives the type `words` names,
    /// `words` in lower case one space apart; `None` where it is not a name
    /// of one of them.
    fn type_name(&self, words: &str) -> Option<&'static str> {
        self.type_synonym(words).map(|synonyms| synonyms.name)
    }

    /// The one of [`Self::type_synonyms`] `words` names, in lower case one
    /// space apart: the one listing it as another name, else the first
    /// one it heads; `None` where it names none of them.
    fn type_synonym(&self, words: &str) -> Option<&'static TypeSynonyms> {
        let synonyms = self.type_synonyms();
        synonyms
            .iter()
            .find(|synonyms| synonyms.aliases.contains(&words))
            .or_else(|| synonyms.iter().find(|synonyms| synonyms.name == words))
    }

    /// Whether a select item may write its alias before the expression,
    /// with an `=` between them (T-SQL `SELECT column_alias = expression`).
    fn select_alias_first(&self) -> bool {
        false
    }

    /// Whether `qualifier`, the parts a call writes before a routine's own
    /// name, each as the dialect compares such a part
    /// ([`normalize_routine_name`]), names the place the dialect's own
    /// routines are: here, none written.
    fn names_system_routines(&self, qualifier: &[&str]) -> bool {
        qualifier.is_empty()
    }

    /// The routine a call naming the parts `name` calls: one of
    /// [`Self::builtin_routines`] by its name, else one of
    /// [`Self::system_routines`], each part as the dialect compares a part
    /// of a routine's name ([`normalize_routine_name`]), named bare or in
    /// the place the dialect's own routines are
    /// ([`Self::names_system_routines`]); `None` for any other name, which
    /// names a routine of the user's.
    fn system_routine(&self, name: &[&str]) -> Option<&'static SystemRoutine> {
        let builtin = self.builtin_routines().iter().find(|known| {
            let mut parts = known.name.split('.');
            name.iter().all(|part| {
                parts
                    .next()
                    .is_some_and(|own| own.eq_ignore_ascii_case(part))
            }) && parts.next().is_none()
        });
        if builtin.is_some() {
            return builtin;
        }
        let (routine, qualifier) = name.split_last()?;
        if !self.names_system_routines(qualifier) {
            return None;
        }
        let config = NormalizationConfig::from_dialect(self.name()).with_env_overrides();
        self.system_routines().iter().find(|known| {
            config
                .routine_parts(&[known.name])
                .last()
                .map(String::as_str)
                == Some(*routine)
        })
    }

    /// Whether a function a user defines can run SQL text it is passed
    /// (PostgreSQL: a PL/pgSQL function's `EXECUTE`).
    fn user_functions_run_sql_text(&self) -> bool {
        false
    }

    /// Whether a function a user defines, called in a query, may write
    /// rows into a table (PostgreSQL, MySQL). A dialect that does not say
    /// is read as one where it may.
    fn user_functions_write(&self) -> bool {
        true
    }

    /// Whether a function or a trigger a user defines may run DDL, and so
    /// change what a table declares (MySQL forbids it). A dialect that does
    /// not say is read as one where it may.
    fn user_functions_run_ddl(&self) -> bool {
        true
    }

    /// Whether an index or unique key declared without a name takes the
    /// name of its first column, `_2`, `_3`, â¦ added where the table has an
    /// index of that name (MySQL). A dialect that does not say names it
    /// otherwise.
    fn unnamed_index_takes_column_name(&self) -> bool {
        false
    }

    /// Whether a routine whose `LANGUAGE` clause names `name` (unquoted,
    /// as the dialect folds it) is written in the dialect's SQL and its
    /// procedural form.
    fn routine_language_is_sql(&self, name: &str) -> bool {
        name.eq_ignore_ascii_case("SQL")
    }

    /// Whether a function call a `FROM` reads as a table may call a
    /// procedure, which can run SQL text it is passed (Snowflake: `SELECT …
    /// FROM TABLE(proc(…))`).
    fn table_calls_may_run_procedures(&self) -> bool {
        false
    }

    /// The schema every built-in function of the dialect is in, where a
    /// call may name it (PostgreSQL's `pg_catalog`).
    fn builtin_function_schema(&self) -> Option<&'static str> {
        None
    }

    /// Whether `COPY table FROM/TO 'file'` performs server-side bulk transfer
    /// (PostgreSQL), as opposed to Snowflake `COPY INTO`.
    fn supports_copy_to_from_table(&self) -> bool {
        false
    }

    /// Whether `COPY table FROM 's3://…'` carries an inline cloud authorization
    /// clause (`IAM_ROLE`, `CREDENTIALS '…'`, `ACCESS_KEY_ID`/`SECRET_ACCESS_KEY`)
    /// that must be captured as typed fields rather than swallowed into an
    /// opaque span (Amazon Redshift). A dialect that returns `true` is parsed
    /// by the Redshift COPY parser instead of the bare PostgreSQL `COPY` parser
    /// (see the credential-bearing-COPY invariant in `pg_copy.rs`).
    fn copy_has_inline_credentials(&self) -> bool {
        false
    }

    /// Whether `CLUSTER [table [USING index]]` is a statement (PostgreSQL).
    fn supports_cluster_statement(&self) -> bool {
        false
    }

    /// Whether `REFRESH MATERIALIZED VIEW` is a statement (PostgreSQL).
    fn supports_refresh_materialized_view(&self) -> bool {
        false
    }

    /// Whether `CREATE TRIGGER` lists the target table (`ON table`) before the
    /// timing clause (`AFTER`/`FOR`) (MSSQL/T-SQL), rather than the
    /// `BEFORE/AFTER ... ON table` ordering (PostgreSQL).
    fn trigger_lists_table_before_timing(&self) -> bool {
        false
    }

    /// Whether `CREATE TRIGGER` carries an inline statement body
    /// (`FOR EACH ROW <stmt>` / `BEGIN … END`, MySQL/MariaDB) rather than
    /// delegating to a routine (`EXECUTE { FUNCTION | PROCEDURE } fn()`,
    /// PostgreSQL). The two share the `BEFORE/AFTER … ON table` header and
    /// diverge only at the body, so — like `trigger_lists_table_before_timing`
    /// — this is a justified dialect gate (token disambiguation would need
    /// unbounded lookahead past the shared header).
    fn trigger_has_inline_body(&self) -> bool {
        false
    }

    /// Whether `CREATE VECTOR INDEX` uses a `WITH (options)` clause (MSSQL/T-SQL),
    /// rather than a trailing `OPTIONS(...)` clause (BigQuery).
    fn vector_index_uses_with_options_clause(&self) -> bool {
        false
    }

    /// Whether `CREATE/ALTER LOGIN` carries a `FROM`/`FOR` principal-source
    /// clause that must be classified before the options body (MSSQL/T-SQL).
    fn login_has_source_clause(&self) -> bool {
        false
    }

    /// Whether `DECLARE` spells a variable initializer with a bare `=`
    /// (`DECLARE @x INT = 5`) (MSSQL/T-SQL), rather than `DEFAULT`/`:=`.
    fn declare_uses_equals_initializer(&self) -> bool {
        false
    }

    /// Whether `WITH (<hint>, ...)` table hints are supported in FROM clauses
    /// (MSSQL/T-SQL).
    fn supports_table_hints(&self) -> bool {
        false
    }

    /// Whether a trailing `OPTION (<query_hint>, ...)` clause is supported
    /// (MSSQL/T-SQL).
    fn supports_query_option_clause(&self) -> bool {
        false
    }

    /// Whether pre-`LIMIT` `DISTRIBUTE BY` / `SORT BY` / `CLUSTER BY` clauses
    /// are supported in SELECT (Databricks).
    fn supports_distribute_sort_clauses(&self) -> bool {
        false
    }

    /// Whether `SELECT @v = expr` assignment-projection is supported
    /// (MSSQL/T-SQL).
    fn supports_select_variable_assignment(&self) -> bool {
        false
    }

    /// Whether statement terminators (semicolons) are optional, so open-ended
    /// scanners must stop at the next statement-start/batch-separator token
    /// (MSSQL/T-SQL).
    ///
    /// It also selects T-SQL's clause grammar for the statements whose
    /// clauses the parser reads up to where that grammar ends: `DROP`,
    /// `TRUNCATE`, a scalar `DECLARE`, `ALTER TABLE` actions, the user,
    /// login and role statements, `CREATE SCHEMA … AUTHORIZATION`, `ALTER
    /// SCHEMA … TRANSFER`, `ALTER DATABASE`, `BACKUP`, `RESTORE`, `DBCC`,
    /// the key, certificate and credential statements and `SETUSER`. Under
    /// a dialect that answers `true`, each of these ends where T-SQL's
    /// grammar for it does; under any other it runs to its terminator.
    fn uses_optional_statement_terminators(&self) -> bool {
        false
    }

    /// Whether `SELECT ... INTO new_table` creates a table (MSSQL/T-SQL and
    /// PostgreSQL), rather than assigning into scripting variables (Snowflake).
    fn select_into_creates_table(&self) -> bool {
        false
    }

    /// Whether `DROP SCHEMA` written without `CASCADE` or `RESTRICT` drops
    /// the objects the schema holds (Snowflake; MySQL, where a schema is a
    /// database), rather than being refused while it holds any.
    fn drop_schema_drops_contents(&self) -> bool {
        false
    }

    /// Whether a procedure created without `EXECUTE AS` runs with its
    /// owner's rights (Snowflake).
    fn procedure_runs_as_owner_by_default(&self) -> bool {
        false
    }

    /// Whether `SELECT ... INTO [TEMP|TEMPORARY|UNLOGGED] table` accepts a
    /// leading temp-ness qualifier keyword (PostgreSQL). MSSQL instead encodes
    /// temp-ness via the `#`/`##` identifier prefix (see `hash_is_identifier_prefix`).
    fn select_into_uses_temp_keyword(&self) -> bool {
        false
    }

    /// Whether `SELECT ... INTO table ON [PRIMARY] filegroup` accepts a
    /// trailing filegroup clause (MSSQL/T-SQL).
    fn select_into_supports_filegroup(&self) -> bool {
        false
    }

    /// Whether INSERT/REPLACE accept `LOW_PRIORITY`/`HIGH_PRIORITY`/`IGNORE`
    /// modifiers between the verb and the target (MySQL). These lex as
    /// identifiers; they are MySQL reserved words, so unquoted-lexeme
    /// matching cannot collide with a table name.
    fn supports_insert_modifiers(&self) -> bool {
        false
    }

    /// Whether the `INTO` keyword is optional in INSERT/REPLACE
    /// (`INSERT t (a) VALUES (1)`) (MySQL, BigQuery, T-SQL).
    fn supports_insert_optional_into(&self) -> bool {
        false
    }

    /// Whether the `INSERT ... SET col = expr, ...` assignment form is
    /// supported (MySQL).
    fn supports_insert_set_form(&self) -> bool {
        false
    }

    /// Whether `INSERT INTO t PARTITION (p, ...)` partition selection is
    /// supported between the target table and the column list (MySQL;
    /// Databricks' partition spec, `PARTITION (k = v, …)`).
    fn supports_insert_partition_clause(&self) -> bool {
        false
    }

    /// Whether `INSERT INTO` / `INSERT OVERWRITE` may write `TABLE` before
    /// the target, and `INSERT OVERWRITE` names its target without `INTO`
    /// (Databricks: `INSERT OVERWRITE [TABLE] t …`).
    fn supports_insert_table_keyword(&self) -> bool {
        false
    }

    /// Whether `VALUE` is accepted as a synonym for `VALUES` in
    /// INSERT/REPLACE (MySQL). `VALUE` lexes as an identifier, so target
    /// capture must stop at it only when this is set.
    fn supports_insert_value_synonym(&self) -> bool {
        false
    }

    /// Table-ref index hints: `USE|FORCE|IGNORE INDEX|KEY [FOR JOIN|ORDER BY|
    /// GROUP BY] (idx, ...)` after a table reference (MySQL). FORCE/IGNORE lex
    /// as identifiers, so alias capture must stop at them only when this is set.
    fn supports_index_hints(&self) -> bool {
        false
    }

    /// Table-ref partition selection: `tbl PARTITION (p0, p1)` between the
    /// table name and the alias (MySQL). Disambiguated from window/DDL
    /// `PARTITION BY` by the immediately-following `(`.
    fn supports_table_partition_selection(&self) -> bool {
        false
    }

    /// Comma-offset LIMIT form: `LIMIT offset, count` (MySQL).
    fn supports_limit_comma_offset(&self) -> bool {
        false
    }

    /// `INTO OUTFILE 'file' [export options]` / `INTO DUMPFILE 'file'`
    /// targets on SELECT (MySQL). OUTFILE/DUMPFILE lex as identifiers.
    fn supports_select_into_outfile(&self) -> bool {
        false
    }

    /// Whether `SELECT ... FROM ... INTO target` (trailing INTO position,
    /// after FROM/WHERE/LIMIT) is accepted in addition to the standard
    /// post-projection position (MySQL, PL/pgSQL).
    fn supports_trailing_select_into(&self) -> bool {
        false
    }

    /// `LOCK IN SHARE MODE` locking-read clause on SELECT (MySQL 5.x
    /// synonym of `FOR SHARE`). All four words lex as identifiers/keywords
    /// that otherwise start a new statement.
    fn supports_lock_in_share_mode(&self) -> bool {
        false
    }

    /// `SEPARATOR 'str'` tail inside aggregate call arguments:
    /// `GROUP_CONCAT(x ORDER BY y SEPARATOR ', ')` (MySQL).
    fn supports_group_concat_separator(&self) -> bool {
        false
    }

    /// MySQL's and PostgreSQL's `TABLE tbl [ORDER BY col] [LIMIT n [OFFSET
    /// m]]` statement — a query-bearing shorthand for `SELECT * FROM tbl ...`. Routes a leading
    /// `TABLE` keyword to the query parser (standalone, set-op operand,
    /// subquery, INSERT source, CTAS body).
    fn supports_table_query_statement(&self) -> bool {
        false
    }

    /// MySQL `SET` grammar: user/system variable assignment (`=` / `:=`,
    /// multi-assign, `GLOBAL`/`SESSION`/`LOCAL` scope, `@@scope.var`) plus
    /// the keyword-led forms (NAMES, CHARACTER SET/CHARSET, PASSWORD, ROLE,
    /// DEFAULT ROLE, TRANSACTION). Routes `SET` to the MySQL set parser.
    fn supports_mysql_set_grammar(&self) -> bool {
        false
    }

    /// `LOW_PRIORITY` / `IGNORE` (UPDATE) and `LOW_PRIORITY` / `QUICK` /
    /// `IGNORE` (DELETE) modifiers after the statement keyword (MySQL).
    /// All lex as identifiers, so target capture must stop at them only
    /// when this is set.
    fn supports_dml_modifiers(&self) -> bool {
        false
    }

    /// Multi-table UPDATE: `UPDATE t1 JOIN t2 ON ... SET ...` and the
    /// comma form `UPDATE t1, t2 SET ...` (MySQL). The target is a full
    /// table-reference list (joins + commas) rather than a single table.
    fn supports_multi_table_update(&self) -> bool {
        false
    }

    /// Multi-table DELETE: `DELETE t1, t2 FROM ...` and `DELETE t1.* FROM
    /// ...` target lists before the FROM clause (MySQL).
    fn supports_multi_table_delete(&self) -> bool {
        false
    }

    /// Whether `DELETE t …` may leave out `FROM` (SQL Server, BigQuery,
    /// Redshift).
    fn delete_from_optional(&self) -> bool {
        false
    }

    /// Single-table `UPDATE`/`DELETE` accept a trailing `ORDER BY ... LIMIT
    /// n` tail (MySQL / MariaDB).
    fn supports_update_delete_order_limit(&self) -> bool {
        false
    }

    /// The `GRANT` grammar shape this dialect uses. Defaults to the
    /// Snowflake-shaped `Standard` grammar.
    fn grant_grammar(&self) -> GrantGrammar {
        GrantGrammar::Standard
    }

    /// The procedure / function parameter grammar shape this dialect uses.
    /// Defaults to `name TYPE` (`NameThenType`).
    fn procedure_param_grammar(&self) -> ProcedureParamGrammar {
        ProcedureParamGrammar::NameThenType
    }
}

// ============================================================================
// Snowflake Dialect Implementation
// ============================================================================

/// Snowflake SQL dialect.
///
/// This is the primary (and currently only) dialect implementation.
#[derive(Debug, Clone, Copy, Default)]
pub struct SnowflakeDialect;

impl Dialect for SnowflakeDialect {
    fn slash_slash_is_line_comment(&self) -> bool {
        true
    }

    fn type_synonyms(&self) -> &'static [TypeSynonyms] {
        SNOWFLAKE_TYPE_SYNONYMS
    }
    fn drop_schema_drops_contents(&self) -> bool {
        true
    }
    fn procedure_runs_as_owner_by_default(&self) -> bool {
        true
    }
    fn routine_synonyms(&self) -> &'static [RoutineSynonyms] {
        SNOWFLAKE_ROUTINE_SYNONYMS
    }
    fn set_assigns(&self) -> SetAssigns {
        SetAssigns::SessionVariable
    }
    fn builtin_routines(&self) -> &'static [SystemRoutine] {
        SNOWFLAKE_BUILTIN_ROUTINES
    }
    fn user_functions_write(&self) -> bool {
        false // a UDF runs no DML; a procedure is called
    }
    fn shown_slots(&self) -> &'static [ShownSlot] {
        SNOWFLAKE_SHOWN_SLOTS
    }
    fn shown_settings(&self) -> &'static [ShownSetting] {
        SNOWFLAKE_SHOWN_SETTINGS
    }
    fn table_calls_may_run_procedures(&self) -> bool {
        true // `SELECT … FROM TABLE(proc(…))` selects from a stored procedure
    }
    fn builtin_function_schema(&self) -> Option<&'static str> {
        Some("INFORMATION_SCHEMA")
    }
    fn syntax_meaning(&self) -> SyntaxMeaning {
        SyntaxMeaning {
            using_column_order: UsingColumnOrder::ListedOrder,
            typed_create_as: TypedCreateAs::NamesByPosition,
            shorter_column_list: ShorterColumnList::NotStated,
            database_level: DatabaseLevel::AboveSchema,
            temporary_tables: TemporaryTables::InSchema,
            cte_write_target: CteWriteTarget::NotStated,
            write_target_source: WriteTargetSource::BesideSources,
            default_search_path: DefaultSearchPath::SessionSchema,
        }
    }

    fn name(&self) -> &'static str {
        "snowflake"
    }

    // ========================================================================
    // Keyword Rules
    // ========================================================================

    keyword_answers!(snowflake_keyword);

    // ========================================================================
    // Identifier Rules
    // ========================================================================

    fn identifier_quote_char(&self) -> char {
        '"'
    }

    fn max_identifier_length(&self) -> Option<usize> {
        Some(255) // Snowflake limit
    }

    fn unquoted_identifiers_case_sensitive(&self) -> bool {
        false // Snowflake converts unquoted identifiers to uppercase
    }

    fn extra_identifier_chars(&self) -> &'static [char] {
        &['$', '#'] // Snowflake allows $ and # in unquoted identifiers
    }

    // ========================================================================
    // String Literal Rules
    // ========================================================================

    fn string_quote_char(&self) -> char {
        '\''
    }

    fn supports_double_quoted_strings(&self) -> bool {
        false // Snowflake lexes "..." as quoted identifiers, not string literals.
              // Context-dependent string interpretation happens at execution, not tokenization.
    }

    fn supports_string_escapes(&self) -> bool {
        true // Snowflake supports \n, \t, \\, etc.
    }

    fn backslash_escapes_in_single_quoted_strings(&self) -> bool {
        true // Snowflake: backslash escapes are always active in '...' strings
    }

    // ========================================================================
    // Client Driver Syntax
    // ========================================================================

    fn supports_snowsql_substitution(&self) -> bool {
        true // SnowSQL CLI substitutes &var / &{var} before execution
    }

    // ========================================================================
    // Statement Support
    // ========================================================================

    fn supports_merge(&self) -> bool {
        true
    }

    fn supports_cte(&self) -> bool {
        true
    }

    fn supports_lateral(&self) -> bool {
        true
    }

    fn supports_window_functions(&self) -> bool {
        true
    }

    fn supports_qualify(&self) -> bool {
        true // QUALIFY is Snowflake-specific
    }

    fn supports_sample(&self) -> bool {
        true // SAMPLE clause is Snowflake-specific
    }

    fn supports_time_travel(&self) -> bool {
        true // Time travel (AT/BEFORE) is Snowflake-specific
    }

    fn supports_pivot(&self) -> bool {
        true // PIVOT is supported
    }

    fn supports_unpivot(&self) -> bool {
        true // UNPIVOT is supported
    }

    fn supports_flatten(&self) -> bool {
        true // FLATTEN table function is Snowflake-specific
    }

    fn supports_values_as_table(&self) -> bool {
        true
    }

    fn is_table_valued_function(&self, _name: &str) -> bool {
        false // Snowflake uses TABLE(func()) or LATERAL FLATTEN()
    }

    fn non_value_arguments(&self, function: &str) -> &'static [NonValueArgument] {
        match AsciiUpper::new(function).as_str() {
            "DATEADD" | "TIMEADD" | "TIMESTAMPADD" | "DATEDIFF" | "TIMEDIFF" | "TIMESTAMPDIFF"
            | "DATE_TRUNC" | "DATE_PART" => PART_FIRST,
            "LAST_DAY" => PART_SECOND,
            "TRUNC" => PART_SECOND_OF_TWO,
            _ => &[],
        }
    }

    fn date_part(&self, word: &str) -> Option<crate::ast::DatePart> {
        use crate::ast::DatePart;
        Some(match AsciiUpper::new(word).as_str() {
            "Y" | "YY" | "YYY" | "YYYY" | "YR" | "YRS" => DatePart::Year,
            "MM" | "MON" | "MONS" => DatePart::Month,
            "D" | "DD" | "DAYOFMONTH" => DatePart::Day,
            "DOW" | "DW" => DatePart::DayOfWeek,
            "WEEKDAY_ISO" | "DOW_ISO" | "DW_ISO" => DatePart::DayOfWeekIso,
            "YEARDAY" | "DOY" | "DY" => DatePart::DayOfYear,
            "W" | "WK" | "WEEKOFYEAR" | "WOY" | "WY" => DatePart::Week,
            "WEEK_ISO" | "WEEKOFYEARISO" | "WEEKOFYEAR_ISO" => DatePart::IsoWeek,
            "Q" | "QTR" | "QTRS" => DatePart::Quarter,
            "H" | "HH" | "HR" | "HRS" => DatePart::Hour,
            "M" | "MI" | "MIN" | "MINS" => DatePart::Minute,
            "S" | "SEC" | "SECS" => DatePart::Second,
            "MS" | "MSEC" => DatePart::Millisecond,
            "US" | "USEC" => DatePart::Microsecond,
            "NS" | "NSEC" | "NANOSEC" | "NSECOND" | "NANOSECS" | "NSECONDS" => DatePart::Nanosecond,
            "TZH" => DatePart::TimezoneHour,
            "TZM" => DatePart::TimezoneMinute,
            _ => return DatePart::from_name(word),
        })
    }

    fn except_is_star_modifier(&self) -> bool {
        false // Snowflake uses EXCLUDE, not EXCEPT
    }

    fn supports_projection_exclude(&self) -> bool {
        false // Snowflake EXCLUDE is star-attached, not a trailing list clause
    }

    fn scripting_requires_begin(&self) -> bool {
        true // Snowflake: DECLARE...BEGIN...END is a single block
    }

    // ========================================================================
    // Operator Support
    // ========================================================================

    fn pipe_pipe_is_concat(&self) -> bool {
        true // In Snowflake, || is string concatenation
    }

    fn supports_json_operators(&self) -> bool {
        false // Snowflake uses : for JSON access, not -> or ->>
    }

    fn supports_named_args_operator(&self) -> bool {
        true // Snowflake supports => for named arguments
    }

    fn supports_type_cast_operator(&self) -> bool {
        true // Snowflake also supports :: for type casting
    }

    fn supports_distinct_on(&self) -> bool {
        false // DISTINCT ON is PostgreSQL-specific
    }

    fn supports_returning(&self) -> bool {
        false // RETURNING is PostgreSQL-specific
    }

    fn supports_for_update(&self) -> bool {
        true // Snowflake supports FOR UPDATE for hybrid tables
    }

    fn supports_for_update_nowait(&self) -> bool {
        true // Parse permissively - let Snowflake reject at execution if invalid
    }

    fn supports_for_update_wait(&self) -> bool {
        true // Parse permissively - let Snowflake reject at execution if invalid
    }

    // "String & binary data types", dollar-quoted string constants: `$$…$$`,
    // untagged; the lexer gives it as words.
    fn dollar_strings_written_as_words(&self) -> bool {
        true
    }

    // "Variables" (SET): a session variable is referenced as `$name`.
    fn dollar_name_is_session_variable(&self) -> bool {
        true
    }
}

// ============================================================================
// Type-erased Dialect for runtime polymorphism
// ============================================================================

/// Type-erased dialect reference.
///
/// This allows passing dialects around without generic parameters.
pub type DialectRef = Arc<dyn Dialect>;

/// Resolve a dialect name string to a DialectRef.
///
/// Accepts: "snowflake" (default), "postgresql"/"postgres"/"pg",
/// "mysql", "bigquery"/"bq", "mssql"/"tsql"/"sqlserver".
///
/// Returns `None` for unrecognized values.
pub fn dialect_from_name(name: &str) -> Option<DialectRef> {
    match name.to_ascii_lowercase().as_str() {
        "snowflake" | "sf" => Some(snowflake()),
        "postgresql" | "postgres" | "pg" => Some(postgres()),
        "mysql" => Some(mysql()),
        "bigquery" | "bq" => Some(bigquery()),
        "databricks" | "dbx" | "spark" | "sparksql" => Some(databricks()),
        "mssql" | "tsql" | "sqlserver" => Some(mssql()),
        "redshift" | "rs" => Some(redshift()),
        _ => None,
    }
}

/// Create a Snowflake dialect reference.
pub fn snowflake() -> DialectRef {
    Arc::new(SnowflakeDialect)
}

// ============================================================================
// Identifier normalization
// ============================================================================
//
// Each dialect's case-sensitivity rules:
//
// | Dialect     | Unquoted identifiers         | Quoted identifiers        | Quote char        |
// |-------------|------------------------------|---------------------------|-------------------|
// | Snowflake   | Case-insensitive → UPPERCASE | Case-sensitive (preserve) | `"..."`           |
// | PostgreSQL  | Case-insensitive → lowercase | Case-sensitive (preserve) | `"..."`           |
// | Redshift    | Case-insensitive → lowercase | Case-sensitive (preserve) | `"..."`           |
// | MySQL       | Case-insensitive → UPPERCASE | Case-sensitive (preserve) | `` `...` ``       |
// | BigQuery    | Case-insensitive → UPPERCASE | Case-sensitive (preserve) | `` `...` ``       |
// | Databricks  | Case-insensitive → lowercase | Case-insensitive (fold)   | `` `...` ``       |
// | MSSQL       | Case-insensitive → UPPERCASE | Case-insensitive (fold)   | `"..."` / `[...]` |
//
// A quoted column name folds in MySQL and BigQuery too: quoting makes the
// case of a table's name significant there, never a column's.
//
// `LEXEGA_IDENTIFIER_CASE=ignore_quoted` folds quoted identifiers as well.

/// What a name names: whether quoting makes its case significant can
/// depend on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameKind {
    /// A column, or a select item's alias.
    Column,
    /// A part of a relation's name: server, database, schema, table.
    Relation,
    /// A role, user or login.
    Principal,
    /// A part of a procedure's or a function's name.
    Routine,
}

/// How unquoted identifiers are case-folded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaseFold {
    /// Fold to UPPERCASE (Snowflake, BigQuery, MySQL, MSSQL)
    Upper,
    /// Fold to lowercase (PostgreSQL, Databricks)
    Lower,
}

/// Whether quoted identifiers should be treated as case-insensitive.
/// Corresponds to Snowflake's QUOTED_IDENTIFIERS_IGNORE_CASE session parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotedHandling {
    /// Quoted identifiers are case-sensitive (default for all dialects)
    CaseSensitive,
    /// Quoted identifiers are case-insensitive (e.g., QUOTED_IDENTIFIERS_IGNORE_CASE=TRUE)
    CaseInsensitive,
}

/// Full normalization configuration derived from dialect + env overrides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NormalizationConfig {
    /// How to fold unquoted identifiers
    pub fold: CaseFold,
    /// Whether a quoted relation or principal name preserves case or is folded
    pub quoted: QuotedHandling,
    /// Whether a quoted column name preserves case or is folded
    pub quoted_columns: QuotedHandling,
    /// Whether a quoted part of a routine's name preserves case or is folded
    pub quoted_routines: QuotedHandling,
    /// Whether a quoted routine name holding dots writes a qualified name
    /// (BigQuery's `` `dataset.routine` ``)
    pub quoted_name_is_path: bool,
    /// Whether every part of a routine's reference compares as written,
    /// quoted or bare (BigQuery); otherwise its qualifier compares as a
    /// relation's parts do and its own name by `quoted_routines`
    pub routine_names_keep_case: bool,
    /// Whether `"..."` is an identifier quote (Snowflake, PostgreSQL, MSSQL)
    pub double_quote_is_identifier: bool,
    /// Whether `` `...` `` is an identifier quote (BigQuery, MySQL, Databricks)
    pub backtick_is_identifier: bool,
    /// Whether `[...]` is an identifier quote (MSSQL)
    pub bracket_is_identifier: bool,
    /// Whether a select item's alias may be written as a string literal
    /// (`AS 'x'`; MSSQL, MySQL): [`normalize_string_name`] reads such a
    /// string, `'…'` or a `"…"` that is no identifier quote, as a quoted
    /// name of its value. [`normalize_identifier`] never strips a string's
    /// quotes.
    pub string_is_identifier: bool,
}

impl Default for NormalizationConfig {
    fn default() -> Self {
        // Snowflake defaults
        Self {
            fold: CaseFold::Upper,
            quoted: QuotedHandling::CaseSensitive,
            quoted_columns: QuotedHandling::CaseSensitive,
            quoted_routines: QuotedHandling::CaseSensitive,
            quoted_name_is_path: false,
            routine_names_keep_case: false,
            double_quote_is_identifier: true,
            backtick_is_identifier: false,
            bracket_is_identifier: false,
            string_is_identifier: false,
        }
    }
}

impl NormalizationConfig {
    /// Create a normalization config for a given dialect name.
    pub fn from_dialect(name: &str) -> Self {
        match name.to_ascii_lowercase().as_str() {
            "postgresql" | "postgres" | "pg" => Self {
                fold: CaseFold::Lower,
                quoted: QuotedHandling::CaseSensitive,
                quoted_columns: QuotedHandling::CaseSensitive,
                quoted_routines: QuotedHandling::CaseSensitive,
                quoted_name_is_path: false,
                routine_names_keep_case: false,
                double_quote_is_identifier: true,
                backtick_is_identifier: false,
                bracket_is_identifier: false,
                string_is_identifier: false,
            },
            // Redshift is forked from PostgreSQL: unquoted identifiers fold to
            // lowercase, quoted identifiers preserve case, `"..."` is a quote.
            "redshift" | "rs" => Self {
                fold: CaseFold::Lower,
                quoted: QuotedHandling::CaseSensitive,
                quoted_columns: QuotedHandling::CaseSensitive,
                // A quoted name folds to lower case, as a bare one does,
                // while `enable_case_sensitive_identifier` is off (the
                // default); a routine's name follows that.
                quoted_routines: QuotedHandling::CaseInsensitive,
                quoted_name_is_path: false,
                routine_names_keep_case: false,
                double_quote_is_identifier: true,
                backtick_is_identifier: false,
                bracket_is_identifier: false,
                string_is_identifier: false,
            },
            "mysql" => Self {
                fold: CaseFold::Upper,
                // MySQL: case sensitivity depends on lower_case_table_names server
                // variable and OS. Backticks don't control case. CaseSensitive
                // is the safer default (preserves case for backtick-quoted names).
                // Column names are case-insensitive whatever their quoting.
                quoted: QuotedHandling::CaseSensitive,
                quoted_columns: QuotedHandling::CaseInsensitive,
                // Stored routine names are case-insensitive whatever their
                // quoting.
                quoted_routines: QuotedHandling::CaseInsensitive,
                quoted_name_is_path: false,
                routine_names_keep_case: false,
                double_quote_is_identifier: false, // MySQL "..." is a string literal
                backtick_is_identifier: true,
                bracket_is_identifier: false,
                string_is_identifier: true,
            },
            "bigquery" | "bq" => Self {
                fold: CaseFold::Upper,
                // BigQuery: column/alias names are case-insensitive, but table names
                // are case-sensitive by default (unless is_case_insensitive=TRUE).
                // Backticks don't control case — they're for reserved words/special chars.
                // We use CaseSensitive here so backtick-quoted table names preserve case
                // for catalog matching, which is the safer default.
                // Ref: https://cloud.google.com/bigquery/docs/reference/standard-sql/lexical#case_sensitivity
                quoted: QuotedHandling::CaseSensitive,
                quoted_columns: QuotedHandling::CaseInsensitive,
                // A routine's reference compares as written, quoted or bare
                // ("User-Defined Function names" are case-sensitive, and a
                // dataset's `isCaseInsensitive` "does not affect routine
                // references"), and a backtick-quoted path names its parts.
                // Ref: https://cloud.google.com/bigquery/docs/reference/rest/v2/datasets
                quoted_routines: QuotedHandling::CaseSensitive,
                quoted_name_is_path: true,
                routine_names_keep_case: true,
                double_quote_is_identifier: false, // BigQuery "..." is a string literal
                backtick_is_identifier: true,
                bracket_is_identifier: false,
                string_is_identifier: false,
            },
            "databricks" | "spark" => Self {
                fold: CaseFold::Lower,
                // Databricks: "Identifiers are case-insensitive when referenced"
                // Backticks are for special chars/reserved words, not case control.
                // Unity Catalog stores all object names as lowercase.
                // Ref: https://docs.databricks.com/en/sql/language-manual/sql-ref-identifiers.html
                quoted: QuotedHandling::CaseInsensitive,
                quoted_columns: QuotedHandling::CaseInsensitive,
                quoted_routines: QuotedHandling::CaseInsensitive,
                quoted_name_is_path: false,
                routine_names_keep_case: false,
                double_quote_is_identifier: false, // Databricks "..." is a string literal
                backtick_is_identifier: true,
                bracket_is_identifier: false,
                string_is_identifier: false,
            },
            "mssql" | "tsql" | "sqlserver" => Self {
                fold: CaseFold::Upper,
                // MSSQL: case sensitivity is collation-dependent, not quote-dependent.
                // [brackets] and "double quotes" are for reserved words, not case control.
                // Every name compares as the default, case-insensitive collation does.
                quoted: QuotedHandling::CaseInsensitive,
                quoted_columns: QuotedHandling::CaseInsensitive,
                quoted_routines: QuotedHandling::CaseInsensitive,
                quoted_name_is_path: false,
                routine_names_keep_case: false,
                double_quote_is_identifier: true,
                backtick_is_identifier: false,
                bracket_is_identifier: true,
                string_is_identifier: true,
            },
            // Snowflake is the default
            _ => Self::default(),
        }
    }

    /// Apply environment variable overrides (e.g., QUOTED_IDENTIFIERS_IGNORE_CASE).
    fn with_env_overrides(mut self) -> Self {
        if let Ok(raw) = std::env::var("LEXEGA_IDENTIFIER_CASE") {
            match raw.trim().to_ascii_lowercase().as_str() {
                "ignore_quoted" | "quoted_ignore_case" | "ignore-quoted" => {
                    self.quoted = QuotedHandling::CaseInsensitive;
                    self.quoted_columns = QuotedHandling::CaseInsensitive;
                    self.quoted_routines = QuotedHandling::CaseInsensitive;
                }
                _ => {}
            }
        }
        self
    }

    /// `name`, a name of `kind`, as this configuration compares it: quotes
    /// stripped, folded unless quoted and case-sensitive for its kind.
    fn normalize(&self, name: &str, kind: NameKind) -> String {
        match self.quoted_inner(name) {
            Some(inner) => self.fold_quoted(inner, kind),
            None => self.fold_unquoted(name),
        }
    }

    /// The text inside `name`'s identifier quotes, where it is quoted.
    fn quoted_inner<'a>(&self, name: &'a str) -> Option<&'a str> {
        let is_double_quoted =
            self.double_quote_is_identifier && name.starts_with('"') && name.ends_with('"');
        let is_backtick_quoted =
            self.backtick_is_identifier && name.starts_with('`') && name.ends_with('`');
        let is_bracket_quoted =
            self.bracket_is_identifier && name.starts_with('[') && name.ends_with(']');
        (name.len() >= 2 && (is_double_quoted || is_backtick_quoted || is_bracket_quoted))
            .then(|| &name[1..name.len() - 1])
    }

    /// The parts the written parts `written` of a routine's name name, each
    /// as this configuration compares it: each part of a quoted path where
    /// the dialect reads a quoted name holding dots as one
    /// ([`Self::quoted_name_is_path`]); every part but the last, a schema or
    /// a database, as a relation's part is compared, the last as a
    /// routine's own name ([`NameKind::Routine`]); each as written where
    /// the dialect compares a routine's reference so
    /// ([`Self::routine_names_keep_case`]). A part written empty (`db..p`)
    /// is kept, empty.
    fn routine_parts(&self, written: &[&str]) -> Vec<String> {
        let pieces = self.name_pieces(written);
        let last = pieces.len().saturating_sub(1);
        pieces
            .iter()
            .enumerate()
            .map(|(at, &(piece, in_path))| {
                let kind = match at == last {
                    true => NameKind::Routine,
                    false => NameKind::Relation,
                };
                let quoted = match in_path {
                    true => Some(piece),
                    false => self.quoted_inner(piece),
                };
                match (quoted, self.routine_names_keep_case) {
                    (Some(inner), true) => inner.to_string(),
                    (Some(inner), false) => self.fold_quoted(inner, kind),
                    (None, true) => piece.to_string(),
                    (None, false) => self.fold_unquoted(piece),
                }
            })
            .collect()
    }

    /// Each piece of the written parts `written` of a name, and whether it
    /// is a piece of a quoted path: a quoted part holding dots is one piece
    /// per part where the dialect reads it as a path
    /// ([`Self::quoted_name_is_path`]).
    fn name_pieces<'a>(&self, written: &[&'a str]) -> Vec<(&'a str, bool)> {
        let mut pieces: Vec<(&str, bool)> = Vec::with_capacity(written.len());
        for part in written {
            let path = self.quoted_name_is_path
                && self.backtick_is_identifier
                && part.len() >= 2
                && part.starts_with('`')
                && part.ends_with('`');
            match part.get(1..part.len().saturating_sub(1)) {
                Some(inner) if path && inner.contains('.') => {
                    pieces.extend(inner.split('.').map(|piece| (piece, true)))
                }
                Some(_) | None => pieces.push((part, false)),
            }
        }
        pieces
    }

    /// The written parts `written` of a relation's name, a quoted path
    /// written as one part per piece, each quoted as the path was
    /// (BigQuery's `` `prod.core.orders` `` is `` `prod` ``, `` `core` ``,
    /// `` `orders` ``): the parts [`Self::relation_parts`] folds.
    fn relation_written_parts(&self, written: &[&str]) -> Vec<String> {
        self.name_pieces(written)
            .into_iter()
            .map(|(piece, in_path)| match in_path {
                true => format!("`{piece}`"),
                false => piece.to_string(),
            })
            .collect()
    }

    /// The parts the written parts `written` of a relation's name name,
    /// each as this configuration compares a relation's part: a quoted
    /// path read as its parts ([`Self::name_pieces`]).
    fn relation_parts(&self, written: &[&str]) -> Vec<String> {
        self.name_pieces(written)
            .into_iter()
            .map(|(piece, in_path)| match in_path {
                true => self.fold_quoted(piece, NameKind::Relation),
                false => self.normalize(piece, NameKind::Relation),
            })
            .collect()
    }

    /// The select item alias `name`, where it may be written as a string:
    /// a string, read by [`crate::lexer::decode_string_literal`] as
    /// `dialect` writes it, is a quoted name of its value where
    /// `string_is_identifier` holds; any other name as [`Self::normalize`]
    /// reads a column's.
    fn normalize_string(&self, name: &str, dialect: &dyn Dialect) -> String {
        let identifier_quoted = (self.double_quote_is_identifier && name.starts_with('"'))
            || (self.backtick_is_identifier && name.starts_with('`'))
            || (self.bracket_is_identifier && name.starts_with('['));
        if !self.string_is_identifier || identifier_quoted {
            return self.normalize(name, NameKind::Column);
        }
        match crate::lexer::decode_string_literal(name, dialect) {
            Some(string) if string.closed => self.fold_quoted(&string.value, NameKind::Column),
            Some(_) | None => self.normalize(name, NameKind::Column),
        }
    }

    /// A quoted name's text, kept where quoted names of `kind` are
    /// case-sensitive.
    fn fold_quoted(&self, inner: &str, kind: NameKind) -> String {
        let handling = match kind {
            NameKind::Column => self.quoted_columns,
            NameKind::Relation | NameKind::Principal => self.quoted,
            NameKind::Routine => self.quoted_routines,
        };
        match handling {
            QuotedHandling::CaseSensitive => inner.to_string(),
            QuotedHandling::CaseInsensitive => self.fold_unquoted(inner),
        }
    }

    /// A name folded as the dialect folds unquoted names.
    fn fold_unquoted(&self, name: &str) -> String {
        match self.fold {
            CaseFold::Upper => name.to_ascii_uppercase(),
            CaseFold::Lower => name.to_ascii_lowercase(),
        }
    }
}

// Per-thread normalization config.
//
// Ambient rather than a parameter because `normalize_identifier()` is called
// from `Hash`/`Eq`/`PartialEq` impls whose signatures cannot carry a config.
// Each thread has its own, so an analysis never reads the dialect of one
// running on another thread.
thread_local! {
    static NORM_CONFIG: std::cell::Cell<Option<ThreadNormalization>> =
        const { std::cell::Cell::new(None) };
}

/// A thread's folding: its dialect's own configuration, the one in force,
/// which is that with the environment's overrides applied, and whether a
/// dialect scope set it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreadNormalization {
    dialect: NormalizationConfig,
    in_force: NormalizationConfig,
    scoped: bool,
}

impl ThreadNormalization {
    /// The folding a dialect scope sets for `dialect`.
    pub fn scoped(dialect: NormalizationConfig) -> Self {
        Self {
            dialect,
            in_force: dialect.with_env_overrides(),
            scoped: true,
        }
    }

    /// The dialect's own configuration.
    pub fn dialect(&self) -> NormalizationConfig {
        self.dialect
    }

    /// The configuration names are folded under.
    pub fn in_force(&self) -> NormalizationConfig {
        self.in_force
    }
}

/// The current thread's folding; `None` where nothing has set it.
pub fn thread_normalization() -> Option<ThreadNormalization> {
    NORM_CONFIG.get()
}

/// Set the current thread's folding and return the one it replaces.
/// [`normalize_identifier`] folds names under it.
pub fn replace_thread_normalization(
    folding: Option<ThreadNormalization>,
) -> Option<ThreadNormalization> {
    NORM_CONFIG.replace(folding)
}

fn read_normalization_config() -> NormalizationConfig {
    // A name folded outside every scope is folded under no stated dialect.
    // A thread already unwinding is not made to panic again.
    debug_assert!(
        NORM_CONFIG.get().is_some_and(|folding| folding.scoped) || std::thread::panicking(),
        "a name was folded with no dialect scope open"
    );
    if let Some(folding) = NORM_CONFIG.get() {
        return folding.in_force;
    }

    // Nothing set the thread's folding: the default dialect's, with the
    // environment's overrides, kept for the thread.
    let dialect = NormalizationConfig::default();
    let folding = ThreadNormalization {
        dialect,
        in_force: dialect.with_env_overrides(),
        scoped: false,
    };
    NORM_CONFIG.set(Some(folding));
    folding.in_force
}

/// Check whether the thread's folding case-folds quoted identifiers of a
/// relation or a principal: the `LEXEGA_IDENTIFIER_CASE=ignore_quoted`
/// override is set, or the dialect's own folding does so (Databricks,
/// MSSQL). Then [`normalize_identifier`] case-folds quoted identifiers too,
/// and a caller folding names by its own rules reads this to agree with it.
pub fn is_ignore_quoted_active() -> bool {
    let config = read_normalization_config();
    config.quoted == QuotedHandling::CaseInsensitive
}

/// Normalize an identifier for case-insensitive comparison, as a part of a
/// relation's name or a principal's name is compared
/// ([`normalize_identifier_as`]).
///
/// Dialect-aware: recognizes double-quote, backtick, and bracket quoting
/// styles and folds unquoted identifiers according to the active dialect
/// (UPPERCASE for Snowflake/BigQuery/MySQL/MSSQL, lowercase for PostgreSQL/Databricks).
///
/// Quoted identifiers preserve case where the dialect says so. Set
/// `LEXEGA_IDENTIFIER_CASE=ignore_quoted` to fold them as well (mirrors
/// Snowflake's QUOTED_IDENTIFIERS_IGNORE_CASE).
///
/// Returns the normalized identifier (quotes stripped if present).
#[inline]
pub fn normalize_identifier(name: &str) -> String {
    read_normalization_config().normalize(name, NameKind::Relation)
}

/// `name`, a name of `kind`, as the thread's folding compares it: quotes
/// stripped, and folded as the dialect folds an unquoted name unless it is
/// quoted where quoting makes the case of such a name significant.
#[inline]
pub fn normalize_identifier_as(name: &str, kind: NameKind) -> String {
    read_normalization_config().normalize(name, kind)
}

/// The parts the written parts `written` of a routine's name name, each as
/// the thread's folding compares it (`NormalizationConfig::routine_parts`).
pub fn normalize_routine_name(written: &[&str]) -> Vec<String> {
    read_normalization_config().routine_parts(written)
}

/// The text inside `name`'s identifier quotes, where the thread's dialect
/// reads `name` as a quoted identifier (`"x"`, `` `x` ``, `[x]`).
pub fn identifier_quoted_inner(name: &str) -> Option<&str> {
    read_normalization_config().quoted_inner(name)
}

/// The written parts `written` of a relation's name, a quoted path written
/// as one quoted part per piece under the thread's dialect
/// (`NormalizationConfig::relation_written_parts`).
pub fn relation_written_parts(written: &[&str]) -> Vec<String> {
    read_normalization_config().relation_written_parts(written)
}

/// The parts the written parts `written` of a relation's name name, each
/// as the thread's folding compares it: BigQuery's `` `project.dataset.table` ``
/// is three parts (`NormalizationConfig::relation_parts`).
pub fn normalize_relation_name(written: &[&str]) -> Vec<String> {
    read_normalization_config().relation_parts(written)
}

/// [`normalize_routine_name`] as `dialect` compares the parts, whatever the
/// thread's folding: the parser runs outside any scope.
pub(crate) fn normalize_routine_name_in(dialect: &dyn Dialect, written: &[&str]) -> Vec<String> {
    NormalizationConfig::from_dialect(dialect.name())
        .with_env_overrides()
        .routine_parts(written)
}

/// Whether `written`, a part of a routine's qualifier as `dialect` compares
/// one ([`normalize_routine_name`]), names `system`, written bare.
fn names_qualifier(dialect: &dyn Dialect, written: &str, system: &str) -> bool {
    normalize_routine_name_in(dialect, &[system, "_"])
        .first()
        .is_some_and(|folded| folded == written)
}

/// A select item's alias `name` as the thread's folding compares it, where
/// the alias may be written as a string (`'x'`, `N'x'`, MySQL's `"x"`;
/// [`NormalizationConfig::string_is_identifier`]): the string is read by
/// [`crate::lexer::decode_string_literal`] as `dialect` writes it, and its
/// value folded as a quoted column name's. Any other name as
/// [`normalize_identifier_as`] folds a column's.
pub fn normalize_string_name(name: &str, dialect: &dyn Dialect) -> String {
    read_normalization_config().normalize_string(name, dialect)
}

/// `name` normalized as [`normalize_identifier`] does inside a scope of
/// `dialect`, whatever the thread's folding: the parser runs outside any
/// scope and reads a name by its own dialect.
pub(crate) fn normalize_identifier_in(dialect: &dyn Dialect, name: &str) -> String {
    NormalizationConfig::from_dialect(dialect.name())
        .with_env_overrides()
        .normalize(name, NameKind::Relation)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snowflake_reserved_keywords() {
        let dialect = SnowflakeDialect;

        assert!(dialect.is_reserved_keyword("SELECT"));
        assert!(dialect.is_reserved_keyword("select"));
        assert!(dialect.is_reserved_keyword("FROM"));
        assert!(dialect.is_reserved_keyword("QUALIFY"));
        assert!(dialect.is_reserved_keyword("WINDOW"));
        // Reserved by ANSI in Snowflake's list.
        assert!(dialect.is_reserved_keyword("ROWS"));
        assert!(!dialect.is_reserved_keyword("my_column"));

        // Unreserved keywords should NOT be reserved
        assert!(!dialect.is_reserved_keyword("OVER"));
        assert!(!dialect.is_reserved_keyword("PARTITION"));
        assert!(!dialect.is_reserved_keyword("FIRST"));
        assert!(!dialect.is_reserved_keyword("LAST"));
        assert!(!dialect.is_reserved_keyword("ASC"));
        assert!(!dialect.is_reserved_keyword("DESC"));
        assert!(!dialect.is_reserved_keyword("LATERAL"));

        // But they SHOULD be keywords
        assert!(dialect.is_keyword("OVER"));
        assert!(dialect.is_keyword("PARTITION"));
        assert!(dialect.is_keyword("ROWS"));
        assert!(dialect.is_keyword("FIRST"));
        assert!(dialect.is_keyword("LAST"));
        assert!(dialect.is_keyword("ASC"));
        assert!(dialect.is_keyword("DESC"));
        assert!(dialect.is_keyword("LATERAL"));
        assert!(dialect.is_keyword("WINDOW"));
        assert!(dialect.is_keyword("QUALIFY"));
        assert!(dialect.is_keyword("FLATTEN"));
        assert!(dialect.is_keyword("PIVOT"));
        assert!(dialect.is_keyword("UNPIVOT"));

        // Case-insensitive
        assert!(dialect.is_keyword("over"));
        assert!(dialect.is_keyword("Partition"));

        // Still not a keyword
        assert!(!dialect.is_keyword("my_column"));
        assert!(!dialect.is_keyword("users"));
    }

    #[test]
    fn a_word_that_cannot_be_a_keyword_matches_none() {
        let d = SnowflakeDialect;
        // 65 bytes with a two-byte character across the buffer's end.
        let straddling = format!("{}é", "a".repeat(63));
        assert_eq!(straddling.len(), 65);
        assert!(!d.is_keyword(&straddling));
        assert!(!d.is_reserved_keyword(&straddling));
        // A keyword followed by enough text to overflow the buffer.
        let long = format!("SELECT{}", "x".repeat(64));
        assert!(!d.is_keyword(&long));
        assert!(!d.is_keyword("sélect"));
        assert!(d.is_keyword("select"));
    }

    #[test]
    fn test_snowflake_identifier_rules() {
        let dialect = SnowflakeDialect;

        assert_eq!(dialect.identifier_quote_char(), '"');
        assert_eq!(dialect.max_identifier_length(), Some(255));
        assert!(!dialect.unquoted_identifiers_case_sensitive());
    }

    #[test]
    fn test_snowflake_features() {
        let dialect = SnowflakeDialect;

        assert!(dialect.supports_cte());
        assert!(dialect.supports_qualify());
        assert!(dialect.supports_window_functions());
        assert!(dialect.pipe_pipe_is_concat());
        assert!(dialect.supports_named_args_operator());
        assert!(!dialect.supports_json_operators());
        assert!(dialect.supports_type_cast_operator());
    }

    #[test]
    fn test_dialect_ref() {
        let dialect = snowflake();

        assert_eq!(dialect.name(), "snowflake");
        assert!(dialect.is_reserved_keyword("SELECT"));
    }

    #[test]
    fn test_postgres_dialect() {
        let dialect = postgres();

        assert_eq!(dialect.name(), "postgresql");
        assert!(dialect.supports_lateral());
        assert!(dialect.supports_window_functions());
        assert!(dialect.pipe_pipe_is_concat());
        assert!(dialect.supports_json_operators());
        assert!(!dialect.supports_qualify());
        assert!(!dialect.supports_time_travel());
        assert!(!dialect.supports_flatten());
        assert!(dialect.supports_type_cast_operator());
    }

    #[test]
    fn test_databricks_dialect() {
        let dialect = databricks();

        assert_eq!(dialect.name(), "databricks");

        // Identifier quoting: backticks (like BigQuery/MySQL)
        assert_eq!(dialect.identifier_quote_char(), '`');

        // Double-quoted text is a string literal, as in BigQuery
        assert!(dialect.supports_double_quoted_strings());

        // Backslash escapes active in single-quoted strings
        assert!(dialect.backslash_escapes_in_single_quoted_strings());

        // # is NOT a comment (unlike BigQuery/MySQL)
        assert!(!dialect.hash_is_line_comment());

        // No @ parameter syntax
        assert!(!dialect.supports_at_sign_identifiers());

        // :: type cast operator IS supported (like Snowflake/PostgreSQL)
        assert!(dialect.supports_type_cast_operator());

        // Databricks supports EXCEPT as star modifier
        assert!(dialect.except_is_star_modifier());

        // Time travel supported (VERSION AS OF / TIMESTAMP AS OF)
        assert!(dialect.supports_time_travel());

        // Core statement support
        assert!(dialect.supports_merge());
        assert!(dialect.supports_cte());
        assert!(dialect.supports_lateral());
        assert!(dialect.supports_qualify());
        assert!(dialect.supports_pivot());
        assert!(dialect.supports_unpivot());
        assert!(dialect.supports_window_functions());
        assert!(dialect.supports_sample());

        // No FLATTEN (uses explode/posexplode instead)
        assert!(!dialect.supports_flatten());

        // || is concat
        assert!(dialect.pipe_pipe_is_concat());

        // Named args supported
        assert!(dialect.supports_named_args_operator());

        // Table-valued functions
        assert!(dialect.is_table_valued_function("explode"));
        assert!(dialect.is_table_valued_function("POSEXPLODE"));
        assert!(!dialect.is_table_valued_function("UNNEST")); // That's BigQuery

        // Alias-restricted words (Databricks reserved-words doc): identifiers,
        // never a table alias.
        assert!(!dialect.is_reserved_keyword("ANTI"));
        assert!(!dialect.is_reserved_keyword("JOIN"));
        assert!(!dialect.keyword_can_be_unquoted_alias("JOIN"));
        assert!(!dialect.is_reserved_keyword("QUALIFY"));

        // Identifier and alias eligibility differ by design.
        assert!(dialect.keyword_can_be_unquoted_identifier("QUALIFY"));
        assert!(dialect.keyword_can_be_unquoted_identifier("WINDOW"));
        assert!(!dialect.keyword_can_be_unquoted_alias("ANTI"));
        assert!(dialect.keyword_can_be_unquoted_alias("QUALIFY"));

        // Non-reserved keywords
        assert!(dialect.is_keyword("OPTIMIZE"));
        assert!(dialect.is_keyword("VACUUM"));
        assert!(dialect.is_keyword("CLONE"));
        assert!(dialect.is_keyword("CATALOG"));
        assert!(dialect.is_keyword("VOLUME"));
        assert!(dialect.is_keyword("VERSION"));
        assert!(dialect.is_keyword("ZORDER"));
    }

    #[test]
    fn test_databricks_dialect_from_name() {
        // All aliases should resolve to Databricks
        assert_eq!(
            dialect_from_name("databricks").unwrap().name(),
            "databricks"
        );
        assert_eq!(dialect_from_name("dbx").unwrap().name(), "databricks");
        assert_eq!(dialect_from_name("spark").unwrap().name(), "databricks");
        assert_eq!(dialect_from_name("sparksql").unwrap().name(), "databricks");
        assert_eq!(
            dialect_from_name("Databricks").unwrap().name(),
            "databricks"
        );
    }

    #[test]
    fn test_redshift_dialect_from_name() {
        assert_eq!(dialect_from_name("redshift").unwrap().name(), "redshift");
        assert_eq!(dialect_from_name("rs").unwrap().name(), "redshift");
        assert_eq!(dialect_from_name("Redshift").unwrap().name(), "redshift");
    }

    #[test]
    fn test_redshift_identifier_and_string_rules() {
        let dialect = redshift();

        // PostgreSQL-derived identifier handling, but Redshift's 127-byte limit.
        assert_eq!(dialect.identifier_quote_char(), '"');
        assert_eq!(dialect.max_identifier_length(), Some(127));
        assert!(!dialect.unquoted_identifiers_case_sensitive());
        assert!(dialect.extra_identifier_chars().contains(&'$'));
        assert!(!dialect.extra_identifier_chars().contains(&'#'));

        // "..." is an identifier, not a string literal.
        assert!(!dialect.supports_double_quoted_strings());
        // '...' uses '' doubling, not backslash escapes.
        assert!(!dialect.backslash_escapes_in_single_quoted_strings());
        // No E'...' escape strings, but $$...$$ procedure bodies are supported.
        assert!(!dialect.supports_escape_string_literals());
        assert!(dialect.supports_dollar_quoted_strings());
    }

    #[test]
    fn test_redshift_reserved_keywords() {
        let dialect = redshift();

        // Core SQL keywords.
        assert!(dialect.is_reserved_keyword("SELECT"));
        assert!(dialect.is_reserved_keyword("from"));

        // Redshift-specific reserved words (encoding / COPY / load vocabulary).
        assert!(dialect.is_reserved_keyword("ENCODE"));
        assert!(dialect.is_reserved_keyword("IDENTITY"));
        assert!(dialect.is_reserved_keyword("CREDENTIALS"));
        assert!(dialect.is_reserved_keyword("ALLOWOVERWRITE"));
        assert!(dialect.is_reserved_keyword("AES256"));
        assert!(dialect.is_reserved_keyword("ANALYZE"));

        // These reserved-in-Redshift words are NOT reserved → cannot be a bare alias.
        assert!(!dialect.keyword_can_be_unquoted_identifier("ENCODE"));

        // Ordinary identifiers are not reserved.
        assert!(!dialect.is_reserved_keyword("my_column"));
    }

    #[test]
    fn test_redshift_feature_flags() {
        let dialect = redshift();

        // Supported.
        assert!(dialect.supports_cte());
        assert!(dialect.supports_window_functions());
        assert!(dialect.supports_merge());
        assert!(dialect.supports_pivot());
        assert!(dialect.supports_unpivot());
        assert!(dialect.pipe_pipe_is_concat());
        assert!(dialect.supports_type_cast_operator());
        assert!(dialect.scripting_requires_begin());

        // Not supported in Redshift (diverges from PostgreSQL).
        assert!(!dialect.supports_lateral());
        assert!(!dialect.supports_distinct_on());
        assert!(!dialect.supports_returning());
        assert!(!dialect.supports_qualify());
        assert!(!dialect.supports_sample());
        assert!(!dialect.supports_time_travel());
        assert!(!dialect.supports_for_update());
        assert!(!dialect.supports_json_operators());
        assert!(!dialect.supports_named_args_operator());
    }
}

// ============================================================================
// PostgreSQL Dialect
// ============================================================================

/// PostgreSQL dialect implementation
#[derive(Debug, Clone, Copy)]
pub struct PostgresDialect;

impl Dialect for PostgresDialect {
    fn shown_slots(&self) -> &'static [ShownSlot] {
        POSTGRES_SHOWN_SLOTS
    }
    fn shown_settings(&self) -> &'static [ShownSetting] {
        POSTGRES_SHOWN_SETTINGS
    }
    fn type_synonyms(&self) -> &'static [TypeSynonyms] {
        POSTGRES_TYPE_SYNONYMS
    }
    fn routine_synonyms(&self) -> &'static [RoutineSynonyms] {
        POSTGRES_ROUTINE_SYNONYMS
    }
    fn supports_trailing_select_into(&self) -> bool {
        true
    }

    fn psql_meta_commands(&self) -> bool {
        true
    }

    fn supports_table_query_statement(&self) -> bool {
        true
    }

    fn syntax_meaning(&self) -> SyntaxMeaning {
        SyntaxMeaning {
            using_column_order: UsingColumnOrder::ListedOrder,
            typed_create_as: TypedCreateAs::NamesByPosition,
            shorter_column_list: ShorterColumnList::NamesTheFirst,
            database_level: DatabaseLevel::NotStated,
            temporary_tables: TemporaryTables::SessionSchema {
                name: Some("pg_temp"),
            },
            cte_write_target: CteWriteTarget::NotStated,
            write_target_source: WriteTargetSource::BesideSources,
            default_search_path: DefaultSearchPath::Schemas(&["public"]),
        }
    }

    // ---- Statement grammar shape (see trait docs) ----
    fn supports_session_config_set(&self) -> bool {
        true
    }
    fn supports_prepared_statement_execution(&self) -> bool {
        true
    }
    fn supports_plpgsql_dynamic_execute(&self) -> bool {
        true // EXECUTE <expr> [INTO [STRICT] tgt] [USING …] (PL/pgSQL)
    }
    fn raise_severity_levels(&self) -> &'static [&'static str] {
        &["DEBUG", "LOG", "INFO", "NOTICE", "WARNING", "EXCEPTION"]
    }
    fn format_function_builds_sql(&self) -> bool {
        true // format('… %I/%L/%s …', args) — canonical PL/pgSQL SQL-template builder
    }
    fn dynamic_sql_identifier_quoting_functions(&self) -> &'static [&'static str] {
        &["quote_ident"]
    }
    fn dynamic_sql_literal_quoting_functions(&self) -> &'static [&'static str] {
        &["quote_literal", "quote_nullable"]
    }
    fn user_functions_run_sql_text(&self) -> bool {
        true // a PL/pgSQL function's `EXECUTE` runs text it is passed
    }
    fn routine_language_is_sql(&self, name: &str) -> bool {
        name.eq_ignore_ascii_case("SQL") || name.eq_ignore_ascii_case("PLPGSQL")
    }
    fn builtin_function_schema(&self) -> Option<&'static str> {
        Some("pg_catalog")
    }
    fn system_routines(&self) -> &'static [SystemRoutine] {
        POSTGRES_SYSTEM_ROUTINES
    }
    fn names_system_routines(&self, qualifier: &[&str]) -> bool {
        match qualifier {
            [] => true,
            [schema] => names_qualifier(self, schema, "pg_catalog"),
            [_, _, ..] => false,
        }
    }
    fn supports_copy_to_from_table(&self) -> bool {
        true
    }
    fn supports_cluster_statement(&self) -> bool {
        true
    }
    fn supports_refresh_materialized_view(&self) -> bool {
        true
    }
    fn select_into_creates_table(&self) -> bool {
        true
    }
    fn select_into_uses_temp_keyword(&self) -> bool {
        true
    }
    fn procedure_param_grammar(&self) -> ProcedureParamGrammar {
        ProcedureParamGrammar::LeadingModeOptionalName
    }

    // ========================================================================
    // Core Identity
    // ========================================================================

    fn name(&self) -> &'static str {
        "postgresql"
    }

    // ========================================================================
    // Keyword Rules
    // ========================================================================

    keyword_answers!(postgres_keyword);

    // ========================================================================
    // Identifier Rules
    // ========================================================================

    fn identifier_quote_char(&self) -> char {
        '"'
    }

    fn max_identifier_length(&self) -> Option<usize> {
        // PostgreSQL NAMEDATALEN - 1 (default is 64 - 1 = 63)
        Some(63)
    }

    fn unquoted_identifiers_case_sensitive(&self) -> bool {
        // PostgreSQL folds unquoted identifiers to LOWERCASE
        // This differs from Snowflake which folds to UPPERCASE
        // The lexer/parser must handle case folding appropriately
        false
    }

    // ========================================================================
    // String Literal Rules
    // ========================================================================

    fn string_quote_char(&self) -> char {
        '\''
    }

    fn supports_double_quoted_strings(&self) -> bool {
        // PostgreSQL uses double quotes ONLY for identifiers, not strings
        false
    }

    fn supports_string_escapes(&self) -> bool {
        // PostgreSQL supports backslash escapes in E'...' strings
        true
    }

    fn backslash_escapes_in_single_quoted_strings(&self) -> bool {
        // PostgreSQL: backslash escapes only in E'...' strings, NOT in regular '...'
        // (standard_conforming_strings = on is the default since PG 9.1)
        false
    }

    // ========================================================================
    // Comment Rules
    // ========================================================================

    fn supports_nested_block_comments(&self) -> bool {
        // PostgreSQL supports nested /* */ comments
        true
    }

    // ========================================================================
    // Statement Support
    // ========================================================================

    fn supports_merge(&self) -> bool {
        // PostgreSQL 15+ supports MERGE
        true
    }

    fn supports_cte(&self) -> bool {
        // PostgreSQL has excellent CTE support including RECURSIVE
        true
    }

    fn supports_lateral(&self) -> bool {
        // PostgreSQL supports LATERAL joins
        true
    }

    fn supports_window_functions(&self) -> bool {
        // PostgreSQL has comprehensive window function support
        true
    }

    fn supports_named_window_clause(&self) -> bool {
        true
    }

    fn supports_qualify(&self) -> bool {
        // QUALIFY is Snowflake-specific; PostgreSQL uses subqueries or CTEs
        false
    }

    fn supports_sample(&self) -> bool {
        // Snowflake SAMPLE syntax not supported
        // PostgreSQL has TABLESAMPLE instead
        false
    }

    fn supports_time_travel(&self) -> bool {
        // AT/BEFORE time travel is Snowflake-specific
        false
    }

    fn supports_pivot(&self) -> bool {
        // PostgreSQL doesn't have native PIVOT (use crosstab extension)
        false
    }

    fn supports_unpivot(&self) -> bool {
        // PostgreSQL doesn't have native UNPIVOT
        false
    }

    fn supports_flatten(&self) -> bool {
        // FLATTEN is Snowflake-specific
        false
    }

    fn supports_values_as_table(&self) -> bool {
        // PostgreSQL supports VALUES as a standalone table expression
        true
    }

    fn is_table_valued_function(&self, name: &str) -> bool {
        matches!(
            name.to_ascii_uppercase().as_str(),
            "UNNEST" | "GENERATE_SERIES" | "GENERATE_SUBSCRIPTS" | "REGEXP_MATCHES"
        )
    }

    fn introduced_arguments(&self, function: &str) -> &'static [IntroducedArgument] {
        match AsciiUpper::new(function).as_str() {
            "OVERLAY" => OVERLAY_ARGUMENTS,
            "XMLELEMENT" => XML_NAME_ARGUMENT,
            _ => &[],
        }
    }

    fn non_value_arguments(&self, function: &str) -> &'static [NonValueArgument] {
        match AsciiUpper::new(function).as_str() {
            "NORMALIZE" => FORM_SECOND,
            _ => &[],
        }
    }

    fn date_part(&self, word: &str) -> Option<crate::ast::DatePart> {
        use crate::ast::DatePart;
        match AsciiUpper::new(word).as_str() {
            "DOW" => Some(DatePart::DayOfWeek),
            "DOY" => Some(DatePart::DayOfYear),
            _ => DatePart::from_name(word),
        }
    }

    fn except_is_star_modifier(&self) -> bool {
        false // PostgreSQL uses standard EXCEPT for set operations
    }

    fn supports_projection_exclude(&self) -> bool {
        false // PostgreSQL has no EXCLUDE projection clause
    }

    fn scripting_requires_begin(&self) -> bool {
        true // PL/pgSQL uses DECLARE...BEGIN...END blocks
    }

    // ========================================================================
    // Operator Support
    // ========================================================================

    fn pipe_pipe_is_concat(&self) -> bool {
        // PostgreSQL uses || for string concatenation
        true
    }

    fn supports_json_operators(&self) -> bool {
        // PostgreSQL supports -> and ->> for JSON/JSONB access
        true
    }

    fn supports_named_args_operator(&self) -> bool {
        // PostgreSQL supports named arguments with => operator
        true
    }

    fn supports_type_cast_operator(&self) -> bool {
        // PostgreSQL natively supports :: for type casting
        true
    }

    fn supports_distinct_on(&self) -> bool {
        // PostgreSQL supports DISTINCT ON (expr_list)
        true
    }

    fn supports_returning(&self) -> bool {
        // PostgreSQL supports RETURNING clause in INSERT/UPDATE/DELETE
        true
    }

    fn supports_for_update(&self) -> bool {
        // PostgreSQL has full FOR UPDATE support
        true
    }

    fn supports_for_update_nowait(&self) -> bool {
        // PostgreSQL supports FOR UPDATE NOWAIT
        true
    }

    fn supports_for_update_wait(&self) -> bool {
        // PostgreSQL doesn't support FOR UPDATE WAIT n (Snowflake/Oracle do)
        false
    }

    fn is_clause_boundary_keyword(&self, word: &str) -> bool {
        // RETURNING terminates SELECT subqueries inside INSERT/UPDATE/DELETE.
        // It must not be consumed as a table alias.
        // WINDOW introduces named window definitions (WINDOW w AS (...)).
        // It's an Identifier in the lexer, so the Identifier alias branch must check it.
        word.eq_ignore_ascii_case("RETURNING") || word.eq_ignore_ascii_case("WINDOW")
    }

    fn supports_escape_string_literals(&self) -> bool {
        true // PostgreSQL supports E'...' escape string literals
    }

    fn supports_dollar_quoted_strings(&self) -> bool {
        true // PostgreSQL supports $$...$$ and $tag$...$tag$ dollar-quoted strings
    }

    fn dollar_number(&self) -> DollarNumber {
        DollarNumber::Parameter // `$1` in PREPARE and in SQL function bodies
    }

    // "Mathematical Operators": `^` is exponentiation, `#` bitwise XOR.
    fn caret(&self) -> CaretOperator {
        CaretOperator::Exponent
    }

    // "Text Search Operators", "JSON Functions and Operators", "String
    // Functions and Operators", "Mathematical Operators".
    fn supports_postgres_operator_symbols(&self) -> bool {
        true
    }

    // "Lexical Structure": `$` opens a positional parameter or a
    // dollar-quoted string; a session setting is read with
    // `current_setting(name)`, not `$name`.
    fn dollar_name_is_session_variable(&self) -> bool {
        false
    }

    fn number_literal_grammar(&self) -> NumberLiteralGrammar {
        // "Lexical Structure: Numeric Constants" (PostgreSQL 16): `0x` / `0o`
        // / `0b` in either case, and `_` between digits or after the prefix.
        NumberLiteralGrammar {
            hexadecimal: RadixPrefix::AnyCase,
            binary: RadixPrefix::AnyCase,
            octal: RadixPrefix::AnyCase,
            digit_separators: true,
            type_suffixes: false,
        }
    }

    fn word_operator(&self, word: &str) -> Option<WordOperator> {
        match AsciiUpper::new(word).as_str() {
            "ISNULL" => Some(WordOperator::IsNull),
            "NOTNULL" => Some(WordOperator::NotNull),
            _ => None,
        }
    }
}

/// Create a PostgreSQL dialect instance
pub fn postgres() -> DialectRef {
    Arc::new(PostgresDialect)
}

// ============================================================================
// MySQL Dialect
// ============================================================================

/// MySQL dialect implementation.
///
/// MySQL has several critical tokenization differences from Snowflake/PostgreSQL:
/// - `"..."` is a string literal (not an identifier) by default (ANSI_QUOTES mode off)
/// - `` `...` `` is used for identifier quoting
/// - `#` starts a line comment
/// - `||` is logical OR (not string concatenation) unless PIPES_AS_CONCAT is set
#[derive(Debug, Clone, Copy)]
pub struct MySqlDialect;

impl Dialect for MySqlDialect {
    fn type_synonyms(&self) -> &'static [TypeSynonyms] {
        MYSQL_TYPE_SYNONYMS
    }
    fn drop_schema_drops_contents(&self) -> bool {
        true
    }
    fn routine_synonyms(&self) -> &'static [RoutineSynonyms] {
        MYSQL_ROUTINE_SYNONYMS
    }
    fn builtin_routines(&self) -> &'static [SystemRoutine] {
        MYSQL_BUILTIN_ROUTINES
    }
    fn user_functions_run_ddl(&self) -> bool {
        false // a stored function or trigger runs no statement that commits
    }
    fn unnamed_index_takes_column_name(&self) -> bool {
        true
    }
    fn shown_slots(&self) -> &'static [ShownSlot] {
        MYSQL_SHOWN_SLOTS
    }
    fn shown_settings(&self) -> &'static [ShownSetting] {
        MYSQL_SHOWN_SETTINGS
    }
    fn select_options(&self) -> bool {
        true
    }

    fn system_routines(&self) -> &'static [SystemRoutine] {
        MYSQL_SYSTEM_ROUTINES
    }

    fn names_system_routines(&self, qualifier: &[&str]) -> bool {
        // MySQL's own procedures are in the `sys` schema; one named bare is
        // the current database's.
        match qualifier {
            [schema] => names_qualifier(self, schema, "sys"),
            [] | [_, _, ..] => false,
        }
    }

    fn client_delimiter_command(&self) -> bool {
        true
    }

    fn adjacent_string_literals_join(&self) -> bool {
        true
    }

    // "JOIN Clause": the coalesced common columns come first, in the order
    // they occur in the first table. "CREATE TABLE ... SELECT": columns
    // named only in the CREATE TABLE part come first, then those named in
    // both parts or only in the SELECT. A table is `db_name.tbl_name`:
    // a database is the schema.
    fn syntax_meaning(&self) -> SyntaxMeaning {
        SyntaxMeaning {
            using_column_order: UsingColumnOrder::LeftTableOrder,
            typed_create_as: TypedCreateAs::AddsColumns,
            shorter_column_list: ShorterColumnList::NotStated,
            database_level: DatabaseLevel::Schema,
            temporary_tables: TemporaryTables::InSchema,
            cte_write_target: CteWriteTarget::NotStated,
            write_target_source: WriteTargetSource::NamedBySource,
            default_search_path: DefaultSearchPath::SessionSchema,
        }
    }

    // ---- Statement grammar shape (see trait docs) ----
    fn grant_grammar(&self) -> GrantGrammar {
        GrantGrammar::ObjectTypePrivilegeLevel
    }
    fn procedure_param_grammar(&self) -> ProcedureParamGrammar {
        ProcedureParamGrammar::LeadingModeRequiredName
    }
    fn supports_insert_modifiers(&self) -> bool {
        true
    }
    fn trigger_has_inline_body(&self) -> bool {
        true
    }
    fn supports_insert_optional_into(&self) -> bool {
        true
    }
    fn supports_insert_set_form(&self) -> bool {
        true
    }
    fn supports_insert_partition_clause(&self) -> bool {
        true
    }
    fn supports_insert_value_synonym(&self) -> bool {
        true
    }
    fn supports_index_hints(&self) -> bool {
        true
    }
    fn supports_table_partition_selection(&self) -> bool {
        true
    }
    fn supports_limit_comma_offset(&self) -> bool {
        true
    }
    fn supports_select_into_outfile(&self) -> bool {
        true
    }
    fn supports_trailing_select_into(&self) -> bool {
        true
    }
    fn supports_lock_in_share_mode(&self) -> bool {
        true
    }
    fn supports_group_concat_separator(&self) -> bool {
        true
    }
    fn supports_dml_modifiers(&self) -> bool {
        true
    }
    fn supports_multi_table_update(&self) -> bool {
        true
    }
    fn supports_multi_table_delete(&self) -> bool {
        true
    }
    fn supports_update_delete_order_limit(&self) -> bool {
        true
    }
    fn supports_mysql_set_grammar(&self) -> bool {
        true
    }
    fn supports_table_query_statement(&self) -> bool {
        true
    }
    fn supports_prepared_statement_execution(&self) -> bool {
        // MySQL: EXECUTE stmt_name [USING @var, ...] and the DROP PREPARE
        // synonym route through the shared prepared-statement parser
        // (PREPARE/DEALLOCATE already do). See the EXECUTE dispatch in
        // parser/core.rs.
        true
    }
    fn supports_named_window_clause(&self) -> bool {
        true // MySQL 8.0: SELECT ... WINDOW w AS (...) and OVER w
    }
    fn is_clause_boundary_keyword(&self, word: &str) -> bool {
        // All four are reserved words in MySQL 8.0 (never unquoted aliases).
        // WINDOW heads the named-window clause; FORCE/IGNORE head index
        // hints; LOCK heads LOCK IN SHARE MODE. All lex as identifiers, so
        // alias scanning must stop at them explicitly.
        word.eq_ignore_ascii_case("WINDOW")
            || word.eq_ignore_ascii_case("FORCE")
            || word.eq_ignore_ascii_case("IGNORE")
            || word.eq_ignore_ascii_case("LOCK")
    }
    fn dynamic_sql_literal_quoting_functions(&self) -> &'static [&'static str] {
        &["quote"] // QUOTE(str) — literal-escapes a value for safe interpolation
    }

    // ========================================================================
    // Core Identity
    // ========================================================================

    fn name(&self) -> &'static str {
        "mysql"
    }

    // ========================================================================
    // Lexer-Level Tokenization Rules
    // ========================================================================

    /// MySQL uses `@var` for session/user variables (e.g.
    /// `SET @sql = ...; PREPARE stmt FROM @sql;`) and `@@var` for
    /// system variables. Both lex as a single `AtVariable` identifier
    /// token so the expression parser can read them as references.
    fn supports_at_sign_identifiers(&self) -> bool {
        true
    }

    // ========================================================================
    // Keyword Rules
    // ========================================================================

    keyword_answers!(mysql_keyword);

    // ========================================================================
    // Identifier Rules
    // ========================================================================

    fn identifier_quote_char(&self) -> char {
        '`' // MySQL uses backticks for identifier quoting
    }

    fn max_identifier_length(&self) -> Option<usize> {
        Some(64) // MySQL identifier length limit
    }

    fn unquoted_identifiers_case_sensitive(&self) -> bool {
        // MySQL identifier case sensitivity depends on OS filesystem for table names
        // but is case-insensitive for column names. We treat as case-insensitive.
        false
    }

    // ========================================================================
    // String Literal Rules
    // ========================================================================

    fn string_quote_char(&self) -> char {
        '\''
    }

    fn supports_double_quoted_strings(&self) -> bool {
        // MySQL treats "..." as string literals by default (ANSI_QUOTES mode off).
        // With ANSI_QUOTES, "..." becomes identifier quoting.
        // We default to standard MySQL behavior: double quotes = strings.
        true
    }

    // "Schema Object Names": in a select list a column alias may be quoted
    // with identifier or string quoting characters, `AS` optional.
    fn string_column_alias(&self) -> bool {
        true
    }

    fn supports_string_escapes(&self) -> bool {
        true // MySQL supports \n, \t, \\, \', etc.
    }

    fn backslash_escapes_in_single_quoted_strings(&self) -> bool {
        true // MySQL: backslash escapes always active (default NO_BACKSLASH_ESCAPES=OFF)
    }

    // ========================================================================
    // Comment Rules
    // ========================================================================

    fn supports_nested_block_comments(&self) -> bool {
        false // MySQL does not support nested block comments
    }

    fn requires_space_after_double_dash(&self) -> bool {
        true // MySQL requires '-- ' (with space), bare '--' is NOT a comment
    }

    fn supports_version_comments(&self) -> bool {
        true // MySQL /*!50100 ... */ version comments contain executable SQL
    }

    // ========================================================================
    // Statement Support
    // ========================================================================

    fn supports_merge(&self) -> bool {
        false // MySQL uses INSERT ... ON DUPLICATE KEY UPDATE instead
    }

    fn supports_cte(&self) -> bool {
        true // MySQL 8.0+ supports CTEs including RECURSIVE
    }

    fn supports_lateral(&self) -> bool {
        true // MySQL 8.0.14+ supports LATERAL derived tables
    }

    fn supports_window_functions(&self) -> bool {
        true // MySQL 8.0+ supports window functions
    }

    fn supports_qualify(&self) -> bool {
        false // QUALIFY is Snowflake-specific
    }

    fn supports_sample(&self) -> bool {
        false // MySQL doesn't support SAMPLE/TABLESAMPLE
    }

    fn supports_time_travel(&self) -> bool {
        false // Time travel is Snowflake-specific
    }

    fn supports_pivot(&self) -> bool {
        false // MySQL doesn't have native PIVOT
    }

    fn supports_unpivot(&self) -> bool {
        false // MySQL doesn't have native UNPIVOT
    }

    fn supports_flatten(&self) -> bool {
        false // FLATTEN is Snowflake-specific
    }

    fn supports_values_as_table(&self) -> bool {
        true // MySQL 8.0.19+ supports VALUES as standalone table expression
    }

    fn is_table_valued_function(&self, _name: &str) -> bool {
        false // MySQL doesn't have standard table-valued functions in FROM
    }

    fn introduced_arguments(&self, function: &str) -> &'static [IntroducedArgument] {
        match AsciiUpper::new(function).as_str() {
            "CONVERT" | "CHAR" => CHARSET_ARGUMENT,
            "WEIGHT_STRING" => AS_TYPE_ARGUMENT,
            _ => &[],
        }
    }

    fn compound_interval_units(&self) -> bool {
        true
    }

    fn non_value_arguments(&self, function: &str) -> &'static [NonValueArgument] {
        match AsciiUpper::new(function).as_str() {
            // `CONVERT(expr, type)`
            "CONVERT" => TYPE_SECOND,
            "GET_FORMAT" => TYPE_FIRST,
            "TIMESTAMPADD" | "TIMESTAMPDIFF" => PART_FIRST,
            _ => &[],
        }
    }

    fn date_part(&self, word: &str) -> Option<crate::ast::DatePart> {
        use crate::ast::DatePart;
        // `TIMESTAMPADD(SQL_TSI_DAY, …)` names a unit with the ODBC prefix.
        DatePart::from_name(word).or_else(|| {
            let upper = AsciiUpper::new(word);
            match upper.as_str().strip_prefix("SQL_TSI_")? {
                unit @ ("MICROSECOND" | "SECOND" | "MINUTE" | "HOUR" | "DAY" | "WEEK" | "MONTH"
                | "QUARTER" | "YEAR") => DatePart::from_name(unit),
                _ => None,
            }
        })
    }

    fn except_is_star_modifier(&self) -> bool {
        false
    }

    fn supports_projection_exclude(&self) -> bool {
        false
    }

    fn scripting_requires_begin(&self) -> bool {
        true // MySQL stored procedures use BEGIN...END blocks
    }

    // ========================================================================
    // Operator Support
    // ========================================================================

    fn pipe_pipe_is_concat(&self) -> bool {
        false // In MySQL, || is logical OR by default (unless PIPES_AS_CONCAT is set)
    }

    fn supports_json_operators(&self) -> bool {
        true // MySQL supports -> and ->> for JSON column path extraction
    }

    fn supports_named_args_operator(&self) -> bool {
        false // MySQL doesn't support => for named arguments
    }

    fn supports_type_cast_operator(&self) -> bool {
        false // MySQL uses CAST() function, not :: operator
    }

    fn supports_distinct_on(&self) -> bool {
        false // DISTINCT ON is PostgreSQL-specific
    }

    fn supports_returning(&self) -> bool {
        false // MySQL doesn't support RETURNING (use LAST_INSERT_ID())
    }

    fn supports_for_update(&self) -> bool {
        true // MySQL supports FOR UPDATE (InnoDB)
    }

    fn supports_for_update_nowait(&self) -> bool {
        true // MySQL 8.0+ supports FOR UPDATE NOWAIT
    }

    fn supports_for_update_wait(&self) -> bool {
        false // MySQL doesn't support FOR UPDATE WAIT n
    }

    // ========================================================================
    // Lexer-Level Tokenization Rules
    // ========================================================================

    fn hash_is_line_comment(&self) -> bool {
        true // MySQL uses # for line comments
    }

    fn supports_escape_string_literals(&self) -> bool {
        false // MySQL doesn't have E'...' syntax
    }

    fn supports_dollar_quoted_strings(&self) -> bool {
        false // MySQL doesn't support $$...$$ dollar-quoted strings
    }

    // "Schema Object Names": `$` is a name character; a user variable is
    // `@name` ("User-Defined Variables").
    fn dollar_name_is_session_variable(&self) -> bool {
        false
    }

    fn double_ampersand(&self) -> DoubleAmpersand {
        DoubleAmpersand::LogicalAnd // `a && b` is `a AND b`
    }

    fn number_literal_grammar(&self) -> NumberLiteralGrammar {
        // "Hexadecimal Literals" and "Bit-Value Literals" (MySQL 8.0): `0x…`
        // and `0b…`, the prefix in lower case only (`0X…` is not one).
        NumberLiteralGrammar {
            hexadecimal: RadixPrefix::LowerCase,
            binary: RadixPrefix::LowerCase,
            ..NumberLiteralGrammar::DECIMAL
        }
    }

    fn word_operator(&self, word: &str) -> Option<WordOperator> {
        match AsciiUpper::new(word).as_str() {
            "XOR" => Some(WordOperator::Xor),
            "DIV" => Some(WordOperator::IntegerDivide),
            "MOD" => Some(WordOperator::Modulo),
            _ => None,
        }
    }
}

/// Create a MySQL dialect instance
pub fn mysql() -> DialectRef {
    Arc::new(MySqlDialect)
}

// ============================================================================
// BigQuery Dialect
// ============================================================================

/// BigQuery (GoogleSQL) dialect implementation.
///
/// BigQuery shares some characteristics with MySQL and some with Snowflake/PG:
/// - `` `...` `` backtick identifier quoting (like MySQL)
/// - `"..."` is a string literal (like MySQL, unlike Snowflake/PG)
/// - `#` starts a line comment (like MySQL)
/// - `||` is string/bytes/array concatenation (like Snowflake/PG, unlike MySQL)
/// - No `::` cast operator — uses CAST()/SAFE_CAST()
/// - No JSON arrow operators — uses subscript `['key']` and dot `.field` syntax
/// - QUALIFY and TABLESAMPLE supported (like Snowflake)
/// - Nested block comments NOT supported
/// - No dollar-quoted strings, no E'...' escape string literals
#[derive(Debug, Clone, Copy)]
pub struct BigQueryDialect;

impl Dialect for BigQueryDialect {
    fn delete_from_optional(&self) -> bool {
        true
    }
    fn type_synonyms(&self) -> &'static [TypeSynonyms] {
        BIGQUERY_TYPE_SYNONYMS
    }
    fn routine_synonyms(&self) -> &'static [RoutineSynonyms] {
        BIGQUERY_ROUTINE_SYNONYMS
    }
    fn builtin_routines(&self) -> &'static [SystemRoutine] {
        BIGQUERY_BUILTIN_ROUTINES
    }
    fn user_functions_write(&self) -> bool {
        false // a UDF or table function runs no DML
    }
    fn shown_slots(&self) -> &'static [ShownSlot] {
        BIGQUERY_SHOWN_SLOTS
    }
    fn four_part_names_name_a_server(&self) -> bool {
        false
    }

    fn supports_insert_optional_into(&self) -> bool {
        true
    }

    fn syntax_meaning(&self) -> SyntaxMeaning {
        SyntaxMeaning {
            using_column_order: UsingColumnOrder::NotStated,
            typed_create_as: TypedCreateAs::NamesByPosition,
            shorter_column_list: ShorterColumnList::NotStated,
            database_level: DatabaseLevel::NotStated,
            temporary_tables: TemporaryTables::SessionSchema { name: None },
            cte_write_target: CteWriteTarget::NotStated,
            write_target_source: WriteTargetSource::BesideSources,
            default_search_path: DefaultSearchPath::SessionSchema,
        }
    }

    // ---- Statement grammar shape (see trait docs) ----
    fn grant_grammar(&self) -> GrantGrammar {
        GrantGrammar::IamRole
    }
    fn procedure_param_grammar(&self) -> ProcedureParamGrammar {
        ProcedureParamGrammar::OptionalNameThenType
    }

    fn format_function_builds_sql(&self) -> bool {
        true // FORMAT("… %s/%t …", args) is printf-style and used in EXECUTE IMMEDIATE
    }

    // ========================================================================
    // Core Identity
    // ========================================================================

    fn name(&self) -> &'static str {
        "bigquery"
    }

    // ========================================================================
    // Keyword Rules
    // ========================================================================

    keyword_answers!(bigquery_keyword);

    // ========================================================================
    // Identifier Rules
    // ========================================================================

    fn identifier_quote_char(&self) -> char {
        '`' // BigQuery uses backticks for identifier quoting
    }

    fn max_identifier_length(&self) -> Option<usize> {
        Some(1024) // BigQuery allows up to 1024 characters
    }

    fn unquoted_identifiers_case_sensitive(&self) -> bool {
        // BigQuery: column names and aliases are case-insensitive
        false
    }

    // ========================================================================
    // String Literal Rules
    // ========================================================================

    fn string_quote_char(&self) -> char {
        '\''
    }

    fn supports_double_quoted_strings(&self) -> bool {
        // BigQuery allows both single and double quoted string literals
        true
    }

    fn supports_string_escapes(&self) -> bool {
        true // BigQuery supports \n, \t, \\, \', \", \`, \uhhhh, \Uhhhhhhhh, etc.
    }

    fn backslash_escapes_in_single_quoted_strings(&self) -> bool {
        true // BigQuery: backslash escapes are active in both single and double quoted strings
    }

    // ========================================================================
    // Comment Rules
    // ========================================================================

    fn supports_nested_block_comments(&self) -> bool {
        false // "Nested multiline comments aren't supported" — official docs
    }

    fn requires_space_after_double_dash(&self) -> bool {
        false // BigQuery: -- starts a comment without requiring a space
    }

    fn supports_version_comments(&self) -> bool {
        false // Version comments are MySQL-specific
    }

    // ========================================================================
    // Statement Support
    // ========================================================================

    fn supports_merge(&self) -> bool {
        true // MERGE is a reserved keyword in BigQuery
    }

    fn supports_cte(&self) -> bool {
        true // BigQuery supports WITH and RECURSIVE CTEs
    }

    fn supports_lateral(&self) -> bool {
        true // LATERAL is a reserved keyword in BigQuery
    }

    fn supports_window_functions(&self) -> bool {
        true // Full window function support with OVER/PARTITION BY
    }

    fn supports_qualify(&self) -> bool {
        true // QUALIFY is a reserved keyword in BigQuery
    }

    fn supports_named_window_clause(&self) -> bool {
        true // BigQuery: SELECT ... WINDOW window_name AS (...)
    }

    fn is_clause_boundary_keyword(&self, word: &str) -> bool {
        // WINDOW heads the named-window clause and lexes as an identifier, so
        // alias/clause scanning must stop at it explicitly.
        word.eq_ignore_ascii_case("WINDOW")
    }

    fn supports_sample(&self) -> bool {
        true // TABLESAMPLE is a reserved keyword in BigQuery
    }

    fn supports_time_travel(&self) -> bool {
        false // BigQuery uses FOR SYSTEM_TIME AS OF (different from Snowflake AT/BEFORE)
    }

    fn supports_pivot(&self) -> bool {
        true // BigQuery supports PIVOT
    }

    fn supports_unpivot(&self) -> bool {
        true // BigQuery supports UNPIVOT
    }

    fn supports_flatten(&self) -> bool {
        false // BigQuery uses UNNEST() instead of FLATTEN()
    }

    fn supports_values_as_table(&self) -> bool {
        true // BigQuery supports VALUES as table expression
    }

    fn is_table_valued_function(&self, name: &str) -> bool {
        name.eq_ignore_ascii_case("UNNEST")
    }

    fn non_value_arguments(&self, function: &str) -> &'static [NonValueArgument] {
        match AsciiUpper::new(function).as_str() {
            "DATE_DIFF" | "DATETIME_DIFF" | "TIMESTAMP_DIFF" | "TIME_DIFF" => PART_THIRD,
            "DATE_TRUNC" | "DATETIME_TRUNC" | "TIMESTAMP_TRUNC" | "TIME_TRUNC" | "LAST_DAY" => {
                PART_SECOND
            }
            "NORMALIZE" | "NORMALIZE_AND_CASEFOLD" => FORM_SECOND,
            _ => &[],
        }
    }

    fn except_is_star_modifier(&self) -> bool {
        true // BigQuery uses EXCEPT for column exclusion: SELECT * EXCEPT (col)
    }

    fn supports_projection_exclude(&self) -> bool {
        false // BigQuery EXCEPT is star-attached, not a trailing list clause
    }

    fn scripting_requires_begin(&self) -> bool {
        false // BigQuery: DECLARE, SET, IF, etc. are independent top-level statements
    }

    // ========================================================================
    // Operator Support
    // ========================================================================

    fn pipe_pipe_is_concat(&self) -> bool {
        true // In BigQuery, || is concatenation for STRING, BYTES, and ARRAY
    }

    fn supports_json_operators(&self) -> bool {
        false // BigQuery uses subscript ['key'] and dot notation, not -> / ->>
    }

    fn supports_named_args_operator(&self) -> bool {
        false // BigQuery doesn't support => for named arguments
    }

    fn supports_type_cast_operator(&self) -> bool {
        false // BigQuery uses CAST() and SAFE_CAST(), no :: operator
    }

    fn supports_distinct_on(&self) -> bool {
        false // DISTINCT ON is PostgreSQL-specific
    }

    fn supports_returning(&self) -> bool {
        false // BigQuery doesn't support RETURNING clause
    }

    fn supports_for_update(&self) -> bool {
        false // BigQuery doesn't support row-level locking
    }

    fn supports_for_update_nowait(&self) -> bool {
        false
    }

    fn supports_for_update_wait(&self) -> bool {
        false
    }

    // ========================================================================
    // Lexer-Level Tokenization Rules
    // ========================================================================

    fn hash_is_line_comment(&self) -> bool {
        true // BigQuery uses # for line comments
    }

    fn supports_at_sign_identifiers(&self) -> bool {
        true // BigQuery uses @param for named query parameters
    }

    fn supports_escape_string_literals(&self) -> bool {
        false // BigQuery doesn't have E'...' escape string prefix
    }

    fn supports_dollar_quoted_strings(&self) -> bool {
        false // BigQuery doesn't support $$...$$ dollar-quoted strings
    }

    // "Procedural language": a script variable is named bare after
    // `DECLARE`, a query parameter is `@name`, a system variable `@@name`.
    fn dollar_name_is_session_variable(&self) -> bool {
        false
    }

    fn number_literal_grammar(&self) -> NumberLiteralGrammar {
        // "Lexical structure and syntax: Integer literals" (GoogleSQL): a
        // hexadecimal integer is `0x…` or `0X…`.
        NumberLiteralGrammar {
            hexadecimal: RadixPrefix::AnyCase,
            ..NumberLiteralGrammar::DECIMAL
        }
    }
}

/// Create a BigQuery dialect instance
pub fn bigquery() -> DialectRef {
    Arc::new(BigQueryDialect)
}

// ============================================================================
// Databricks SQL Dialect Implementation
// ============================================================================

/// Databricks SQL dialect implementation.
///
/// Databricks SQL is based on Apache Spark SQL with Delta Lake extensions and
/// Unity Catalog. At the lexer level it is close to BigQuery (backtick identifiers,
/// backslash escapes), but differs in several key ways:
///
/// - `"..."` are **identifiers**, not string literals (like Snowflake/PostgreSQL)
/// - `#` is NOT a comment delimiter (unlike BigQuery/MySQL)
/// - `::` type cast operator IS supported (like Snowflake/PostgreSQL)
/// - `EXCEPT` is a set operation, NOT a star modifier (unlike BigQuery)
/// - Time travel uses `VERSION AS OF` / `TIMESTAMP AS OF` syntax
/// - Delta Lake operations: OPTIMIZE, VACUUM, DESCRIBE HISTORY, RESTORE, CLONE
/// - Unity Catalog: CREATE CATALOG, CREATE VOLUME, CREATE FUNCTION (Python/SQL)
/// - Liquid clustering: CLUSTER BY in CREATE TABLE
/// - IDENTIFIER() function for dynamic SQL
#[derive(Debug)]
pub struct DatabricksDialect;

impl Dialect for DatabricksDialect {
    fn type_synonyms(&self) -> &'static [TypeSynonyms] {
        DATABRICKS_TYPE_SYNONYMS
    }
    fn routine_synonyms(&self) -> &'static [RoutineSynonyms] {
        DATABRICKS_ROUTINE_SYNONYMS
    }
    fn set_assigns(&self) -> SetAssigns {
        SetAssigns::Configuration
    }
    fn builtin_routines(&self) -> &'static [SystemRoutine] {
        DATABRICKS_BUILTIN_ROUTINES
    }
    fn user_functions_write(&self) -> bool {
        false // a SQL or Python UDF runs no DML
    }
    fn supports_insert_partition_clause(&self) -> bool {
        true // INSERT { INTO | OVERWRITE } [TABLE] t PARTITION (k [= v], …)
    }
    fn supports_insert_table_keyword(&self) -> bool {
        true // INSERT { INTO | OVERWRITE } [TABLE] t
    }
    fn shown_slots(&self) -> &'static [ShownSlot] {
        DATABRICKS_SHOWN_SLOTS
    }
    fn shown_settings(&self) -> &'static [ShownSetting] {
        DATABRICKS_SHOWN_SETTINGS
    }
    fn adjacent_string_literals_join(&self) -> bool {
        true
    }

    // "USE DATABASE": `DATABASE` and `SCHEMA` are interchangeable; a table
    // is `catalog.schema.table`.
    fn syntax_meaning(&self) -> SyntaxMeaning {
        SyntaxMeaning {
            using_column_order: UsingColumnOrder::NotStated,
            typed_create_as: TypedCreateAs::NamesByPosition,
            shorter_column_list: ShorterColumnList::NotStated,
            database_level: DatabaseLevel::Schema,
            temporary_tables: TemporaryTables::SessionSchema { name: None },
            cte_write_target: CteWriteTarget::NotStated,
            write_target_source: WriteTargetSource::BesideSources,
            default_search_path: DefaultSearchPath::Schemas(&["default"]),
        }
    }

    // ---- Statement grammar shape (see trait docs) ----
    fn supports_distribute_sort_clauses(&self) -> bool {
        true
    }

    // "Table reference": `STREAM table_name [ table_alias ] | STREAM (
    // table_name ) [ table_alias ]`.
    fn stream_reads_a_table(&self) -> bool {
        true
    }

    // "DECLARE VARIABLE": `DECLARE [ OR REPLACE ] [ VARIABLE | VAR ]
    // variable_name [ data_type ] [ { DEFAULT | = } default_expression ]`.
    fn declare_has_variable_keyword(&self) -> bool {
        true
    }

    // ========================================================================
    // Core Identity
    // ========================================================================

    fn name(&self) -> &'static str {
        "databricks"
    }

    // ========================================================================
    // Keyword Rules
    // ========================================================================

    keyword_answers!(databricks_keyword);

    // ========================================================================
    // Identifier Rules
    // ========================================================================

    fn identifier_quote_char(&self) -> char {
        '`' // Databricks uses backticks for identifier quoting
    }

    fn max_identifier_length(&self) -> Option<usize> {
        Some(255) // Databricks allows up to 255 characters for identifiers
    }

    fn unquoted_identifiers_case_sensitive(&self) -> bool {
        false // Databricks is case-insensitive for identifiers by default
    }

    // ========================================================================
    // String Literal Rules
    // ========================================================================

    fn string_quote_char(&self) -> char {
        '\''
    }

    fn supports_double_quoted_strings(&self) -> bool {
        true // Databricks reads "..." (and r"...") as a string; identifiers are backquoted
    }

    fn supports_string_escapes(&self) -> bool {
        true // Databricks supports \n, \t, \\, etc.
    }

    fn backslash_escapes_in_single_quoted_strings(&self) -> bool {
        true // Databricks: backslash escapes are active in '...' strings
    }

    // ========================================================================
    // Comment Rules
    // ========================================================================

    fn supports_nested_block_comments(&self) -> bool {
        true // Databricks nests bracketed comments
    }

    fn requires_space_after_double_dash(&self) -> bool {
        false // Databricks: -- starts a comment without requiring a space
    }

    fn supports_version_comments(&self) -> bool {
        false // Version comments are MySQL-specific
    }

    // ========================================================================
    // Statement Support
    // ========================================================================

    fn supports_merge(&self) -> bool {
        true // MERGE INTO is widely used with Delta Lake
    }

    fn supports_cte(&self) -> bool {
        true // Databricks supports WITH and RECURSIVE CTEs
    }

    fn supports_lateral(&self) -> bool {
        true // LATERAL is supported in Databricks
    }

    fn supports_window_functions(&self) -> bool {
        true // Full window function support
    }

    fn supports_named_window_clause(&self) -> bool {
        true // Databricks supports SELECT ... WINDOW ...
    }

    fn supports_qualify(&self) -> bool {
        true // QUALIFY is supported in Databricks
    }

    fn supports_sample(&self) -> bool {
        true // TABLESAMPLE is supported in Databricks
    }

    fn supports_time_travel(&self) -> bool {
        true // Databricks supports VERSION AS OF / TIMESTAMP AS OF for Delta tables
    }

    fn supports_pivot(&self) -> bool {
        true // PIVOT is supported
    }

    fn supports_unpivot(&self) -> bool {
        true // UNPIVOT is supported
    }

    fn supports_flatten(&self) -> bool {
        false // Databricks uses explode()/posexplode() instead of FLATTEN()
    }

    fn supports_values_as_table(&self) -> bool {
        true // VALUES can be used as a table source
    }

    fn is_table_valued_function(&self, name: &str) -> bool {
        // Databricks supports explode, posexplode, inline, stack as table-generating functions
        matches!(
            AsciiUpper::new(name).as_str(),
            "EXPLODE" | "POSEXPLODE" | "INLINE" | "STACK" | "GENERATOR"
        )
    }

    fn introduced_arguments(&self, function: &str) -> &'static [IntroducedArgument] {
        match AsciiUpper::new(function).as_str() {
            "OVERLAY" => OVERLAY_ARGUMENTS,
            _ => &[],
        }
    }

    fn non_value_arguments(&self, function: &str) -> &'static [NonValueArgument] {
        match AsciiUpper::new(function).as_str() {
            "DATEADD" | "DATE_ADD" | "DATEDIFF" | "DATE_DIFF" => PART_FIRST_OF_THREE,
            "TIMESTAMPADD" | "TIMESTAMPDIFF" => PART_FIRST,
            _ => &[],
        }
    }

    fn date_part(&self, word: &str) -> Option<crate::ast::DatePart> {
        use crate::ast::DatePart;
        Some(match AsciiUpper::new(word).as_str() {
            "Y" | "YR" | "YRS" => DatePart::Year,
            "QTR" => DatePart::Quarter,
            "MON" | "MONS" => DatePart::Month,
            "W" => DatePart::Week,
            "D" => DatePart::Day,
            "DOW" => DatePart::DayOfWeek,
            "DOW_ISO" => DatePart::DayOfWeekIso,
            "DOY" => DatePart::DayOfYear,
            "H" | "HR" | "HRS" => DatePart::Hour,
            "M" | "MIN" | "MINS" => DatePart::Minute,
            "S" | "SEC" | "SECS" => DatePart::Second,
            _ => return DatePart::from_name(word),
        })
    }

    fn except_is_star_modifier(&self) -> bool {
        true // Databricks supports SELECT * EXCEPT(...) in star clause
    }

    fn supports_projection_exclude(&self) -> bool {
        false // Databricks EXCEPT is star-attached, not a trailing list clause
    }

    fn scripting_requires_begin(&self) -> bool {
        false // Databricks: DECLARE, SET, IF, etc. are independent top-level statements
    }

    // ========================================================================
    // Operator Support
    // ========================================================================

    fn pipe_pipe_is_concat(&self) -> bool {
        true // In Databricks, || is string concatenation
    }

    fn supports_json_operators(&self) -> bool {
        false // Databricks uses : (colon) for JSON field access, not -> / ->>
    }

    fn supports_named_args_operator(&self) -> bool {
        true // Databricks supports => for named parameter invocation
    }

    fn supports_type_cast_operator(&self) -> bool {
        true // Databricks supports :: for type casting (e.g., col::INT)
    }

    fn supports_distinct_on(&self) -> bool {
        false // DISTINCT ON is PostgreSQL-specific
    }

    fn supports_returning(&self) -> bool {
        false // Databricks doesn't support RETURNING clause
    }

    fn supports_for_update(&self) -> bool {
        false // Databricks doesn't support row-level locking
    }

    fn supports_for_update_nowait(&self) -> bool {
        false
    }

    fn supports_for_update_wait(&self) -> bool {
        false
    }

    fn is_clause_boundary_keyword(&self, word: &str) -> bool {
        // Databricks query organization clauses are lexed as identifiers and
        // must terminate alias scanning in FROM clause parsing.
        word.eq_ignore_ascii_case("DISTRIBUTE")
            || word.eq_ignore_ascii_case("SORT")
            || word.eq_ignore_ascii_case("CLUSTER")
            || word.eq_ignore_ascii_case("WINDOW")
    }

    // ========================================================================
    // Lexer-Level Tokenization Rules
    // ========================================================================

    fn hash_is_line_comment(&self) -> bool {
        false // Databricks uses -- for line comments, # is not a comment delimiter
    }

    fn supports_at_sign_identifiers(&self) -> bool {
        false // Databricks does not use @ for parameters
    }

    fn at_is_operator(&self) -> bool {
        true // Databricks uses @ for time travel: events@v123, events@20190101
    }

    fn supports_escape_string_literals(&self) -> bool {
        false // Databricks doesn't have E'...' escape string prefix
    }

    fn supports_dollar_quoted_strings(&self) -> bool {
        false // Databricks doesn't support $$...$$ dollar-quoted strings
    }

    // "Variables" (DECLARE VARIABLE): a session variable is named bare or
    // as `session.name` / `system.session.name`.
    fn dollar_name_is_session_variable(&self) -> bool {
        false
    }

    fn number_literal_grammar(&self) -> NumberLiteralGrammar {
        // "Integral numeric literals" and "Fractional numeric literals"
        // (Databricks SQL): decimal digits with an optional `L` / `S` / `Y`
        // or `D` / `F` / `BD` type suffix.
        NumberLiteralGrammar {
            type_suffixes: true,
            ..NumberLiteralGrammar::DECIMAL
        }
    }

    fn word_operator(&self, word: &str) -> Option<WordOperator> {
        match AsciiUpper::new(word).as_str() {
            "DIV" => Some(WordOperator::IntegerDivide), // `mod` is a function only
            _ => None,
        }
    }
}

/// Create a Databricks dialect instance
pub fn databricks() -> DialectRef {
    Arc::new(DatabricksDialect)
}

// ============================================================================
// Microsoft SQL Server (T-SQL) Dialect Implementation
// ============================================================================

/// Microsoft SQL Server (T-SQL) dialect implementation.
///
/// MSSQL has several unique characteristics among the five supported dialects:
/// - `[...]` bracket-delimited identifiers (MSSQL-specific, no other dialect)
/// - `"..."` is also an identifier (with QUOTED_IDENTIFIER ON, the default since SQL Server 2000)
/// - `+` is the traditional string concatenation operator (not `||`)
/// - `||` was added as ANSI string concatenation in SQL Server 2022+
/// - `#` is NOT a comment — it denotes temp tables (`#temp`, `##global_temp`)
/// - Nested block comments `/* ... /* ... */ ... */` are supported
/// - No `::` type cast operator — uses CAST()/CONVERT()/TRY_CONVERT()
/// - No QUALIFY clause
/// - No RETURNING clause — uses OUTPUT clause instead
/// - No FOR UPDATE — uses locking hints WITH (UPDLOCK, HOLDLOCK)
/// - MERGE, PIVOT, UNPIVOT, TABLESAMPLE all supported
/// - Rich type system: MONEY, SMALLMONEY, UNIQUEIDENTIFIER, XML, HIERARCHYID,
///   GEOGRAPHY, GEOMETRY, NCHAR, NVARCHAR, DATETIME2, DATETIMEOFFSET, SQL_VARIANT
#[derive(Debug, Clone, Copy)]
pub struct MsSqlDialect;

const fn reads(name: &'static str, reads: ArgumentUse) -> SystemParameter {
    SystemParameter { name, reads }
}

const fn value(name: &'static str) -> SystemParameter {
    reads(name, ArgumentUse::Value)
}

const fn flag(name: &'static str) -> SystemParameter {
    reads(name, ArgumentUse::Flag)
}

const fn name(name: &'static str) -> SystemParameter {
    reads(name, ArgumentUse::Name)
}

/// A procedure's one form: any of its parameters may be left out.
const fn procedure(
    parameters: &'static [SystemParameter],
    rest: Option<ArgumentUse>,
) -> SystemForm {
    SystemForm {
        parameters,
        required: 0,
        rest,
    }
}

/// A form taking exactly `parameters`.
const fn exactly(parameters: &'static [SystemParameter]) -> SystemForm {
    SystemForm {
        parameters,
        required: parameters.len(),
        rest: None,
    }
}

/// The T-SQL system procedures and rowset functions the engine reads, with
/// what each does with each argument (Transact-SQL reference, "System
/// stored procedures", "Rowset functions"). A procedure whose later
/// parameters are not listed takes no argument past those listed that is
/// read as shown.
const MSSQL_SYSTEM_ROUTINES: &[SystemRoutine] = &[
    // Cryptographic functions that take a passphrase or a password.
    SystemRoutine {
        name: "encryptbypassphrase",
        forms: &[taking(MSSQL_PASSPHRASE, 2)],
    },
    SystemRoutine {
        name: "decryptbypassphrase",
        forms: &[taking(MSSQL_PASSPHRASE, 2)],
    },
    SystemRoutine {
        name: "decryptbykeyautoasymkey",
        forms: &[taking(MSSQL_KEY_PASSWORD_SECOND, 3)],
    },
    SystemRoutine {
        name: "decryptbykeyautocert",
        forms: &[taking(MSSQL_KEY_PASSWORD_SECOND, 3)],
    },
    SystemRoutine {
        name: "decryptbyasymkey",
        forms: &[taking(MSSQL_KEY_PASSWORD_THIRD, 2)],
    },
    SystemRoutine {
        name: "decryptbycert",
        forms: &[taking(MSSQL_KEY_PASSWORD_THIRD, 2)],
    },
    SystemRoutine {
        name: "signbyasymkey",
        forms: &[taking(MSSQL_KEY_PASSWORD_THIRD, 2)],
    },
    SystemRoutine {
        name: "signbycert",
        forms: &[taking(MSSQL_KEY_PASSWORD_THIRD, 2)],
    },
    SystemRoutine {
        name: "pwdencrypt",
        forms: &[taking(&[credential("password")], 1)],
    },
    SystemRoutine {
        name: "pwdcompare",
        forms: &[taking(
            &[
                credential("clear_text_password"),
                value("password_hash"),
                value("version"),
            ],
            2,
        )],
    },
    SystemRoutine {
        name: "openquery",
        forms: &[exactly(&[
            value("linked_server"),
            reads("query", ArgumentUse::RunsSqlRemotely),
        ])],
    },
    SystemRoutine {
        name: "openrowset",
        forms: &[exactly(&[
            value("provider_name"),
            reads("datasource", ArgumentUse::ConnectionString),
            reads("query", ArgumentUse::RunsSqlRemotely),
        ])],
    },
    SystemRoutine {
        name: "opendatasource",
        forms: &[exactly(&[
            value("provider_name"),
            reads("init_string", ArgumentUse::ConnectionString),
        ])],
    },
    SystemRoutine {
        name: "sp_prepare",
        forms: &[procedure(
            &[
                value("handle"),
                value("params"),
                reads("stmt", ArgumentUse::RunsSql),
                value("options"),
            ],
            None,
        )],
    },
    SystemRoutine {
        name: "sp_prepexec",
        forms: &[procedure(
            &[
                value("handle"),
                value("params"),
                reads("stmt", ArgumentUse::RunsSql),
            ],
            None,
        )],
    },
    SystemRoutine {
        name: "sp_cursorprepare",
        forms: &[procedure(
            &[
                value("prepared_handle"),
                value("params"),
                reads("stmt", ArgumentUse::RunsSql),
                value("options"),
                value("scrollopt"),
                value("ccopt"),
            ],
            None,
        )],
    },
    SystemRoutine {
        name: "sp_cursoropen",
        forms: &[procedure(
            &[
                value("cursor"),
                reads("stmt", ArgumentUse::RunsSql),
                value("scrollopt"),
                value("ccopt"),
                value("rowcount"),
            ],
            None,
        )],
    },
    SystemRoutine {
        name: "sp_cursorprepexec",
        forms: &[procedure(
            &[
                value("prepared_handle"),
                value("cursor"),
                value("params"),
                reads("statement", ArgumentUse::RunsSql),
                value("options"),
                value("scrollopt"),
                value("ccopt"),
                value("rowcount"),
            ],
            None,
        )],
    },
    SystemRoutine {
        name: "sp_execute_external_script",
        forms: &[procedure(
            &[
                value("language"),
                reads("script", ArgumentUse::Command),
                reads("input_data_1", ArgumentUse::RunsSql),
                value("input_data_1_name"),
                value("output_data_1_name"),
                value("parallel"),
                value("params"),
            ],
            None,
        )],
    },
    SystemRoutine {
        name: "sp_executesql",
        forms: &[procedure(
            &[reads("stmt", ArgumentUse::RunsSql), value("params")],
            Some(ArgumentUse::Value),
        )],
    },
    SystemRoutine {
        name: "xp_cmdshell",
        forms: &[procedure(
            &[
                reads("command_string", ArgumentUse::Command),
                value("no_output"),
            ],
            None,
        )],
    },
    // `sp_configure`: a configuration option's name, and its value, an
    // `int` (SQL Server documentation, "sp_configure").
    SystemRoutine {
        name: "sp_configure",
        forms: &[procedure(&[name("configname"), name("configvalue")], None)],
    },
    // A database role's name and a user's, a login's or a role's
    // ("sp_addrolemember", "sp_droprolemember").
    SystemRoutine {
        name: "sp_addrolemember",
        forms: &[procedure(&[name("rolename"), name("membername")], None)],
    },
    SystemRoutine {
        name: "sp_droprolemember",
        forms: &[procedure(&[name("rolename"), name("membername")], None)],
    },
    // A login's name and a fixed server role's ("sp_addsrvrolemember",
    // "sp_dropsrvrolemember").
    SystemRoutine {
        name: "sp_addsrvrolemember",
        forms: &[procedure(&[name("loginame"), name("rolename")], None)],
    },
    SystemRoutine {
        name: "sp_dropsrvrolemember",
        forms: &[procedure(&[name("loginame"), name("rolename")], None)],
    },
    // An object's current name, its new name and its type ("sp_rename").
    SystemRoutine {
        name: "sp_rename",
        forms: &[procedure(
            &[name("objname"), name("newname"), name("objtype")],
            None,
        )],
    },
    // The linked server's name, the product, the OLE DB provider's name,
    // the data source (a server's network name, or a provider's data
    // source, whose password a report masks wherever it is written as a
    // connection string's), the location and the catalog; the provider
    // string may hold a password ("sp_addlinkedserver").
    SystemRoutine {
        name: "sp_addlinkedserver",
        forms: &[procedure(
            &[
                name("server"),
                name("srvproduct"),
                name("provider"),
                name("datasrc"),
                name("location"),
                reads("provstr", ArgumentUse::ConnectionString),
                name("catalog"),
                value("linkedstyle"),
            ],
            None,
        )],
    },
    SystemRoutine {
        name: "sp_addlinkedsrvlogin",
        forms: &[procedure(
            &[
                value("rmtsrvname"),
                value("useself"),
                value("locallogin"),
                value("rmtuser"),
                reads("rmtpassword", ArgumentUse::Credential),
            ],
            None,
        )],
    },
    SystemRoutine {
        name: "sp_add_jobstep",
        forms: &[procedure(
            &[
                value("job_id"),
                value("job_name"),
                value("step_id"),
                value("step_name"),
                value("subsystem"),
                reads("command", ArgumentUse::Command),
                reads("additional_parameters", ArgumentUse::Command),
                value("cmdexec_success_code"),
                value("on_success_action"),
                value("on_success_step_id"),
                value("on_fail_action"),
                value("on_fail_step_id"),
                value("server"),
                value("database_name"),
                value("database_user_name"),
                value("retry_attempts"),
                value("retry_interval"),
                value("os_run_priority"),
                value("output_file_name"),
                value("flags"),
                value("proxy_id"),
                value("proxy_name"),
            ],
            None,
        )],
    },
    SystemRoutine {
        name: "sp_setapprole",
        forms: &[procedure(
            &[
                value("rolename"),
                reads("password", ArgumentUse::Credential),
                value("encrypt"),
                value("fCreateCookie"),
                value("cookie"),
            ],
            None,
        )],
    },
    SystemRoutine {
        name: "sp_addapprole",
        forms: &[procedure(
            &[
                value("rolename"),
                reads("password", ArgumentUse::Credential),
            ],
            None,
        )],
    },
    SystemRoutine {
        name: "sp_approlepassword",
        forms: &[procedure(
            &[value("rolename"), reads("newpwd", ArgumentUse::Credential)],
            None,
        )],
    },
    SystemRoutine {
        name: "sp_addlogin",
        forms: &[procedure(
            &[
                value("loginame"),
                reads("passwd", ArgumentUse::Credential),
                value("defdb"),
                value("deflanguage"),
                value("sid"),
                value("encryptopt"),
            ],
            None,
        )],
    },
    SystemRoutine {
        name: "sp_password",
        forms: &[procedure(
            &[
                reads("old", ArgumentUse::Credential),
                reads("new", ArgumentUse::Credential),
                value("loginame"),
            ],
            None,
        )],
    },
    SystemRoutine {
        name: "sp_change_users_login",
        forms: &[procedure(
            &[
                value("Action"),
                value("UserNamePattern"),
                value("LoginName"),
                reads("Password", ArgumentUse::Credential),
            ],
            None,
        )],
    },
    SystemRoutine {
        name: "sp_control_dbmasterkey_password",
        forms: &[procedure(
            &[
                value("db_name"),
                reads("password", ArgumentUse::Credential),
                value("action"),
            ],
            None,
        )],
    },
    SystemRoutine {
        name: "sp_adddistributor",
        forms: &[procedure(
            &[
                value("distributor"),
                value("heartbeat_interval"),
                reads("password", ArgumentUse::Credential),
                value("from_scripting"),
            ],
            None,
        )],
    },
    SystemRoutine {
        name: "sp_changedistributor_password",
        forms: &[procedure(
            &[reads("password", ArgumentUse::Credential)],
            None,
        )],
    },
    SystemRoutine {
        name: "sp_addsubscriber",
        forms: &[procedure(
            &[
                value("subscriber"),
                value("type"),
                value("login"),
                reads("password", ArgumentUse::Credential),
            ],
            None,
        )],
    },
    SystemRoutine {
        name: "sp_changesubscriber",
        forms: &[procedure(
            &[
                value("subscriber"),
                value("type"),
                value("login"),
                reads("password", ArgumentUse::Credential),
            ],
            None,
        )],
    },
    SystemRoutine {
        name: "sp_adddistpublisher",
        forms: &[procedure(
            &[
                value("publisher"),
                value("distribution_db"),
                value("security_mode"),
                value("login"),
                reads("password", ArgumentUse::Credential),
            ],
            None,
        )],
    },
];

/// dblink's SQL argument, run on the server its connection reaches.
const REMOTE_SQL: SystemParameter = reads("sql", ArgumentUse::RunsSqlRemotely);
/// dblink's connection: a connection's name or a connection string.
const CONNECTION: SystemParameter = reads("connname", ArgumentUse::ConnectionString);
const FAIL_ON_ERROR: SystemParameter = flag("fail_on_error");

/// The functions of PostgreSQL and of its dblink extension that the engine
/// reads, with what each does with each argument (PostgreSQL documentation,
/// "dblink", "XML Functions", "Text Search Functions"). A dblink function
/// whose arguments are names and options only reads values.
const POSTGRES_SYSTEM_ROUTINES: &[SystemRoutine] = &[
    SystemRoutine {
        name: "dblink",
        forms: &[
            exactly(&[REMOTE_SQL]),
            exactly(&[REMOTE_SQL, FAIL_ON_ERROR]),
            exactly(&[CONNECTION, REMOTE_SQL]),
            exactly(&[CONNECTION, REMOTE_SQL, FAIL_ON_ERROR]),
        ],
    },
    SystemRoutine {
        name: "dblink_exec",
        forms: &[
            exactly(&[REMOTE_SQL]),
            exactly(&[REMOTE_SQL, FAIL_ON_ERROR]),
            exactly(&[CONNECTION, REMOTE_SQL]),
            exactly(&[CONNECTION, REMOTE_SQL, FAIL_ON_ERROR]),
        ],
    },
    SystemRoutine {
        name: "dblink_send_query",
        forms: &[exactly(&[CONNECTION, REMOTE_SQL])],
    },
    SystemRoutine {
        name: "dblink_open",
        forms: &[
            exactly(&[value("cursorname"), REMOTE_SQL]),
            exactly(&[value("cursorname"), REMOTE_SQL, FAIL_ON_ERROR]),
            exactly(&[CONNECTION, value("cursorname"), REMOTE_SQL]),
            exactly(&[CONNECTION, value("cursorname"), REMOTE_SQL, FAIL_ON_ERROR]),
        ],
    },
    SystemRoutine {
        name: "dblink_connect",
        forms: &[
            exactly(&[reads("connstr", ArgumentUse::ConnectionString)]),
            exactly(&[
                value("connname"),
                reads("connstr", ArgumentUse::ConnectionString),
            ]),
        ],
    },
    SystemRoutine {
        name: "dblink_connect_u",
        forms: &[
            exactly(&[reads("connstr", ArgumentUse::ConnectionString)]),
            exactly(&[
                value("connname"),
                reads("connstr", ArgumentUse::ConnectionString),
            ]),
        ],
    },
    SystemRoutine {
        name: "dblink_disconnect",
        forms: &[procedure(&[], Some(ArgumentUse::Value))],
    },
    SystemRoutine {
        name: "dblink_fetch",
        forms: &[procedure(&[], Some(ArgumentUse::Value))],
    },
    SystemRoutine {
        name: "dblink_close",
        forms: &[procedure(&[], Some(ArgumentUse::Value))],
    },
    SystemRoutine {
        name: "dblink_get_result",
        forms: &[procedure(&[], Some(ArgumentUse::Value))],
    },
    SystemRoutine {
        name: "dblink_is_busy",
        forms: &[procedure(&[], Some(ArgumentUse::Value))],
    },
    SystemRoutine {
        name: "dblink_cancel_query",
        forms: &[procedure(&[], Some(ArgumentUse::Value))],
    },
    SystemRoutine {
        name: "dblink_error_message",
        forms: &[procedure(&[], Some(ArgumentUse::Value))],
    },
    SystemRoutine {
        name: "dblink_get_connections",
        forms: &[procedure(&[], Some(ArgumentUse::Value))],
    },
    SystemRoutine {
        name: "dblink_get_notify",
        forms: &[procedure(&[], Some(ArgumentUse::Value))],
    },
    SystemRoutine {
        name: "dblink_get_pkey",
        forms: &[procedure(&[], Some(ArgumentUse::Value))],
    },
    SystemRoutine {
        name: "dblink_build_sql_insert",
        forms: &[procedure(&[], Some(ArgumentUse::Value))],
    },
    SystemRoutine {
        name: "dblink_build_sql_delete",
        forms: &[procedure(&[], Some(ArgumentUse::Value))],
    },
    SystemRoutine {
        name: "dblink_build_sql_update",
        forms: &[procedure(&[], Some(ArgumentUse::Value))],
    },
    SystemRoutine {
        name: "query_to_xml",
        forms: &[exactly(&[
            reads("query", ArgumentUse::RunsSql),
            flag("nulls"),
            flag("tableforest"),
            value("targetns"),
        ])],
    },
    SystemRoutine {
        name: "query_to_xmlschema",
        forms: &[exactly(&[
            reads("query", ArgumentUse::RunsSql),
            flag("nulls"),
            flag("tableforest"),
            value("targetns"),
        ])],
    },
    SystemRoutine {
        name: "query_to_xml_and_xmlschema",
        forms: &[exactly(&[
            reads("query", ArgumentUse::RunsSql),
            flag("nulls"),
            flag("tableforest"),
            value("targetns"),
        ])],
    },
    SystemRoutine {
        name: "ts_stat",
        forms: &[
            exactly(&[reads("sqlquery", ArgumentUse::RunsSql)]),
            exactly(&[reads("sqlquery", ArgumentUse::RunsSql), value("weights")]),
        ],
    },
    SystemRoutine {
        name: "ts_rewrite",
        forms: &[
            exactly(&[value("query"), reads("select", ArgumentUse::RunsSql)]),
            exactly(&[value("query"), value("target"), value("substitute")]),
        ],
    },
    // pgcrypto ("pgcrypto — cryptographic functions").
    SystemRoutine {
        name: "pgp_sym_encrypt",
        forms: &[taking(PG_SYMMETRIC, 2)],
    },
    SystemRoutine {
        name: "pgp_sym_encrypt_bytea",
        forms: &[taking(PG_SYMMETRIC, 2)],
    },
    SystemRoutine {
        name: "pgp_sym_decrypt",
        forms: &[taking(PG_SYMMETRIC, 2)],
    },
    SystemRoutine {
        name: "pgp_sym_decrypt_bytea",
        forms: &[taking(PG_SYMMETRIC, 2)],
    },
    SystemRoutine {
        name: "pgp_pub_decrypt",
        forms: &[taking(PG_SECRET_KEY, 2)],
    },
    SystemRoutine {
        name: "pgp_pub_decrypt_bytea",
        forms: &[taking(PG_SECRET_KEY, 2)],
    },
    SystemRoutine {
        name: "crypt",
        forms: &[taking(&[credential("password"), value("salt")], 2)],
    },
    SystemRoutine {
        name: "hmac",
        forms: &[taking(PG_KEYED, 3)],
    },
    SystemRoutine {
        name: "encrypt",
        forms: &[taking(PG_KEYED, 3)],
    },
    SystemRoutine {
        name: "decrypt",
        forms: &[taking(PG_KEYED, 3)],
    },
    SystemRoutine {
        name: "encrypt_iv",
        forms: &[taking(PG_KEYED_IV, 4)],
    },
    SystemRoutine {
        name: "decrypt_iv",
        forms: &[taking(PG_KEYED_IV, 4)],
    },
    // A large object's OID and the server file it is written to or read
    // from (PostgreSQL documentation, "Server-Side Functions" of large
    // objects).
    SystemRoutine {
        name: "lo_export",
        forms: &[exactly(&[value("loid"), name("filename")])],
    },
    SystemRoutine {
        name: "lo_import",
        forms: &[
            exactly(&[name("filename")]),
            exactly(&[name("filename"), value("loid")]),
        ],
    },
];

const PG_SYMMETRIC: &[SystemParameter] = &[value("data"), credential("psw"), value("options")];
const PG_SECRET_KEY: &[SystemParameter] = &[
    value("msg"),
    credential("key"),
    credential("psw"),
    value("options"),
];
const PG_KEYED: &[SystemParameter] = &[value("data"), credential("key"), value("type")];
const PG_KEYED_IV: &[SystemParameter] =
    &[value("data"), credential("key"), value("iv"), value("type")];

const MSSQL_PASSPHRASE: &[SystemParameter] = &[
    credential("passphrase"),
    value("text"),
    value("add_authenticator"),
    value("authenticator"),
];
const MSSQL_KEY_PASSWORD_SECOND: &[SystemParameter] = &[
    value("key_id"),
    credential("password"),
    value("ciphertext"),
    value("add_authenticator"),
    value("authenticator"),
];
const MSSQL_KEY_PASSWORD_THIRD: &[SystemParameter] =
    &[value("key_id"), value("text"), credential("password")];

/// The procedures of MySQL's `sys` schema that the engine reads (MySQL
/// reference, "The sys Schema").
const MYSQL_SYSTEM_ROUTINES: &[SystemRoutine] = &[SystemRoutine {
    name: "execute_prepared_stmt",
    forms: &[exactly(&[reads("in_query", ArgumentUse::RunsSql)])],
}];

const fn credential(name: &'static str) -> SystemParameter {
    reads(name, ArgumentUse::Credential)
}

/// A form taking `parameters`, the first `required` of them in every call.
const fn taking(parameters: &'static [SystemParameter], required: usize) -> SystemForm {
    SystemForm {
        parameters,
        required,
        rest: None,
    }
}

const SNOWFLAKE_PASSPHRASE: &[SystemParameter] = &[
    value("value"),
    credential("passphrase"),
    value("additional_authenticated_data"),
    value("encryption_method"),
];
const SNOWFLAKE_RAW_KEY: &[SystemParameter] = &[
    value("value"),
    credential("key"),
    value("iv"),
    value("additional_authenticated_data"),
    value("encryption_method"),
    value("aead_tag"),
];

/// The Snowflake functions that take a passphrase or a key (Snowflake SQL
/// reference, "Encryption functions").
const SNOWFLAKE_BUILTIN_ROUTINES: &[SystemRoutine] = &[
    SystemRoutine {
        name: "encrypt",
        forms: &[taking(SNOWFLAKE_PASSPHRASE, 2)],
    },
    SystemRoutine {
        name: "decrypt",
        forms: &[taking(SNOWFLAKE_PASSPHRASE, 2)],
    },
    SystemRoutine {
        name: "try_decrypt",
        forms: &[taking(SNOWFLAKE_PASSPHRASE, 2)],
    },
    SystemRoutine {
        name: "encrypt_raw",
        forms: &[taking(SNOWFLAKE_RAW_KEY, 3)],
    },
    SystemRoutine {
        name: "decrypt_raw",
        forms: &[taking(SNOWFLAKE_RAW_KEY, 3)],
    },
    SystemRoutine {
        name: "try_decrypt_raw",
        forms: &[taking(SNOWFLAKE_RAW_KEY, 3)],
    },
];

const MYSQL_AES: &[SystemParameter] = &[
    value("str"),
    credential("key_str"),
    value("init_vector"),
    value("kdf_name"),
    value("salt"),
    value("info"),
];
const MYSQL_KEYED: &[SystemParameter] = &[value("str"), credential("key_str")];
const MYSQL_PASSWORD: &[SystemParameter] = &[credential("str"), value("salt")];

/// The MySQL functions that take a key or a password (MySQL reference,
/// "Encryption and Compression Functions"; `ENCODE`, `DECODE`,
/// `DES_ENCRYPT`, `DES_DECRYPT`, `ENCRYPT` and `PASSWORD` in 5.7). A
/// built-in function's name is the built-in's, not a stored function's.
const MYSQL_BUILTIN_ROUTINES: &[SystemRoutine] = &[
    SystemRoutine {
        name: "aes_encrypt",
        forms: &[taking(MYSQL_AES, 2)],
    },
    SystemRoutine {
        name: "aes_decrypt",
        forms: &[taking(MYSQL_AES, 2)],
    },
    SystemRoutine {
        name: "des_encrypt",
        forms: &[taking(MYSQL_KEYED, 1)],
    },
    SystemRoutine {
        name: "des_decrypt",
        forms: &[taking(MYSQL_KEYED, 1)],
    },
    SystemRoutine {
        name: "encode",
        forms: &[taking(MYSQL_KEYED, 2)],
    },
    SystemRoutine {
        name: "decode",
        forms: &[taking(MYSQL_KEYED, 2)],
    },
    SystemRoutine {
        name: "encrypt",
        forms: &[taking(MYSQL_PASSWORD, 1)],
    },
    SystemRoutine {
        name: "password",
        forms: &[taking(MYSQL_PASSWORD, 1)],
    },
    SystemRoutine {
        name: "validate_password_strength",
        forms: &[taking(MYSQL_PASSWORD, 1)],
    },
];

const BIGQUERY_KEYSET: &[SystemParameter] = &[
    credential("keyset"),
    value("text"),
    value("additional_data"),
];

/// The BigQuery functions that take a keyset (GoogleSQL reference, "AEAD
/// encryption functions").
const BIGQUERY_BUILTIN_ROUTINES: &[SystemRoutine] = &[
    SystemRoutine {
        name: "aead.encrypt",
        forms: &[taking(BIGQUERY_KEYSET, 3)],
    },
    SystemRoutine {
        name: "aead.decrypt_bytes",
        forms: &[taking(BIGQUERY_KEYSET, 3)],
    },
    SystemRoutine {
        name: "aead.decrypt_string",
        forms: &[taking(BIGQUERY_KEYSET, 3)],
    },
    SystemRoutine {
        name: "deterministic_encrypt",
        forms: &[taking(BIGQUERY_KEYSET, 3)],
    },
    SystemRoutine {
        name: "deterministic_decrypt_bytes",
        forms: &[taking(BIGQUERY_KEYSET, 3)],
    },
    SystemRoutine {
        name: "deterministic_decrypt_string",
        forms: &[taking(BIGQUERY_KEYSET, 3)],
    },
    SystemRoutine {
        name: "keys.keyset_chain",
        forms: &[taking(
            &[value("kms_resource_name"), credential("first_level_keyset")],
            2,
        )],
    },
];

const DATABRICKS_AES: &[SystemParameter] = &[
    value("expr"),
    credential("key"),
    value("mode"),
    value("padding"),
    value("iv"),
    value("aad"),
];

/// The Databricks functions that take a key (Databricks SQL reference,
/// `aes_encrypt`, `aes_decrypt`, `try_aes_decrypt`).
const DATABRICKS_BUILTIN_ROUTINES: &[SystemRoutine] = &[
    SystemRoutine {
        name: "aes_encrypt",
        forms: &[taking(DATABRICKS_AES, 2)],
    },
    SystemRoutine {
        name: "aes_decrypt",
        forms: &[taking(DATABRICKS_AES, 2)],
    },
    SystemRoutine {
        name: "try_aes_decrypt",
        forms: &[taking(DATABRICKS_AES, 2)],
    },
];

/// Snowflake SQL reference: an object's `COMMENT` and its tags' values
/// (`WITH TAG (…)`, `SET TAG …`), `COMMENT ON … IS`, the format type
/// options of `CREATE FILE FORMAT`, a stage, an external table and `COPY
/// INTO`, `COPY`'s `ON_ERROR` and `PATTERN`, a warehouse's size and type, a
/// task's and an alert's `SCHEDULE`, a dynamic table's `TARGET_LAG`, the
/// `TIMEZONE` parameter, an external volume's and a storage integration's
/// `STORAGE_PROVIDER`, the name
/// `IDENTIFIER(…)` takes, and the IAM role an API or a storage integration
/// assumes.
const SNOWFLAKE_SHOWN_SLOTS: &[ShownSlot] = &[
    option(SlotStatement::Definition, &["COMMENT"]),
    COMMENT_ON_IS,
    // `CREATE … WITH TAG (name = 'value', …)`, `ALTER … SET TAG name =
    // 'value', …` ("Tag quotas"; a tag's value is a string of up to 256
    // characters).
    ShownSlot {
        statement: SlotStatement::Definition,
        keyword: &["TAG"],
        follows: SlotFollows::Assignments,
        holds: SlotHolds::Text,
    },
    option(SlotStatement::FileFormat, &["TYPE"]),
    option(SlotStatement::FileFormat, &["COMPRESSION"]),
    option(SlotStatement::FileFormat, &["RECORD_DELIMITER"]),
    option(SlotStatement::FileFormat, &["FIELD_DELIMITER"]),
    option(SlotStatement::FileFormat, &["FILE_EXTENSION"]),
    option(SlotStatement::FileFormat, &["DATE_FORMAT"]),
    option(SlotStatement::FileFormat, &["TIME_FORMAT"]),
    option(SlotStatement::FileFormat, &["TIMESTAMP_FORMAT"]),
    option(SlotStatement::FileFormat, &["BINARY_FORMAT"]),
    option(SlotStatement::FileFormat, &["ESCAPE"]),
    option(SlotStatement::FileFormat, &["ESCAPE_UNENCLOSED_FIELD"]),
    option(SlotStatement::FileFormat, &["FIELD_OPTIONALLY_ENCLOSED_BY"]),
    option(SlotStatement::FileFormat, &["ENCODING"]),
    option(SlotStatement::Copy, &["ON_ERROR"]),
    option(SlotStatement::Copy, &["PATTERN"]),
    option(SlotStatement::Warehouse, &["WAREHOUSE_SIZE"]),
    option(SlotStatement::Warehouse, &["WAREHOUSE_TYPE"]),
    option(SlotStatement::Schedule, &["SCHEDULE"]),
    option(SlotStatement::DynamicTable, &["TARGET_LAG"]),
    option(SlotStatement::Parameters, &["TIMEZONE"]),
    option(SlotStatement::Volume, &["STORAGE_PROVIDER"]),
    option(SlotStatement::StorageIntegration, &["STORAGE_PROVIDER"]),
    ShownSlot {
        statement: SlotStatement::Any,
        keyword: &["IDENTIFIER"],
        follows: SlotFollows::Call,
        holds: SlotHolds::Text,
    },
    // `CREATE | ALTER NETWORK POLICY`: the IPv4 addresses and ranges
    // allowed and blocked; `ALTER ACCOUNT | USER SET NETWORK_POLICY`: the
    // policy's name.
    list(SlotStatement::NetworkPolicy, &["ALLOWED_IP_LIST"]),
    list(SlotStatement::NetworkPolicy, &["BLOCKED_IP_LIST"]),
    option(SlotStatement::Parameters, &["NETWORK_POLICY"]),
    // `CREATE NETWORK RULE`: the hosts, ports and addresses it names.
    list(SlotStatement::NetworkRule, &["VALUE_LIST"]),
    // `CREATE | ALTER USER`: the role, warehouse and namespace a session
    // starts with, and the secondary roles it activates.
    option(SlotStatement::Principal, &["DEFAULT_ROLE"]),
    option(SlotStatement::Principal, &["DEFAULT_WAREHOUSE"]),
    option(SlotStatement::Principal, &["DEFAULT_NAMESPACE"]),
    list(SlotStatement::Principal, &["DEFAULT_SECONDARY_ROLES"]),
    // `COPY INTO <location>` unloads to, and loads from, a stage or a
    // cloud storage URL; a stage's `URL`.
    location(SlotStatement::Copy, &["INTO"]),
    location(SlotStatement::Copy, &["FROM"]),
    location(SlotStatement::Stage, &["URL"]),
    // `CREATE | ALTER API INTEGRATION`'s `API_AWS_ROLE_ARN` and `CREATE |
    // ALTER STORAGE INTEGRATION`'s `STORAGE_AWS_ROLE_ARN`: the Amazon
    // Resource Name of the IAM role the integration assumes.
    option(SlotStatement::ApiIntegration, &["API_AWS_ROLE_ARN"]),
    option(SlotStatement::StorageIntegration, &["STORAGE_AWS_ROLE_ARN"]),
];

/// PostgreSQL documentation: `COMMENT ON … IS`, `COPY`'s `FORMAT`,
/// `DELIMITER`, `NULL`, `QUOTE`, `ESCAPE` and `ENCODING`, `CREATE
/// DATABASE`'s encoding and locale options, `SET TIME ZONE`, and the server
/// file `COPY … TO | FROM` writes or reads.
const POSTGRES_SHOWN_SLOTS: &[ShownSlot] = &[
    location(SlotStatement::Copy, &["TO"]),
    location(SlotStatement::Copy, &["FROM"]),
    COMMENT_ON_IS,
    option(SlotStatement::Copy, &["FORMAT"]),
    option(SlotStatement::Copy, &["DELIMITER"]),
    option(SlotStatement::Copy, &["NULL"]),
    option(SlotStatement::Copy, &["QUOTE"]),
    option(SlotStatement::Copy, &["ESCAPE"]),
    option(SlotStatement::Copy, &["ENCODING"]),
    option(SlotStatement::Database, &["ENCODING"]),
    option(SlotStatement::Database, &["LOCALE"]),
    option(SlotStatement::Database, &["LC_COLLATE"]),
    option(SlotStatement::Database, &["LC_CTYPE"]),
    option(SlotStatement::Set, &["TIME", "ZONE"]),
];

/// Amazon Redshift documentation: `COMMENT ON … IS`, the data format
/// parameters of `COPY` and `UNLOAD` (`DELIMITER`, `DATEFORMAT`,
/// `TIMEFORMAT`, `REGION`), the Amazon S3 path `UNLOAD … TO` writes to and
/// `COPY … FROM` reads from, and the Amazon Resource Name of the IAM role
/// `IAM_ROLE` names ("Authorization parameters").
const REDSHIFT_SHOWN_SLOTS: &[ShownSlot] = &[
    location(SlotStatement::Copy, &["TO"]),
    location(SlotStatement::Copy, &["FROM"]),
    COMMENT_ON_IS,
    option(SlotStatement::Copy, &["DELIMITER"]),
    option(SlotStatement::Copy, &["DATEFORMAT"]),
    option(SlotStatement::Copy, &["TIMEFORMAT"]),
    option(SlotStatement::Copy, &["REGION"]),
    option(SlotStatement::Copy, &["IAM_ROLE"]),
];

/// MySQL reference: a table's, a column's and an index's `COMMENT`,
/// `LOAD DATA`'s field and line terminators, an account or a role written
/// as a string (`CREATE USER [IF NOT EXISTS] 'u'@'h'`, `DROP USER IF
/// EXISTS 'u'`, `GRANT … TO 'u'`, `SET ROLE 'r'`), its host after the `@`,
/// the server file `SELECT … INTO OUTFILE | DUMPFILE` writes and `LOAD DATA
/// [LOCAL] INFILE` reads, and the shared library `CREATE FUNCTION … SONAME`
/// and `INSTALL PLUGIN … SONAME` load.
const MYSQL_SHOWN_SLOTS: &[ShownSlot] = &[
    option(SlotStatement::Definition, &["COMMENT"]),
    option(SlotStatement::NamedAccount, &["USER"]),
    option(SlotStatement::NamedAccount, &["IF", "EXISTS"]),
    option(SlotStatement::NamedAccount, &["IF", "NOT", "EXISTS"]),
    location(SlotStatement::Query, &["OUTFILE"]),
    location(SlotStatement::Query, &["DUMPFILE"]),
    location(SlotStatement::LoadData, &["INFILE"]),
    location(SlotStatement::Library, &["SONAME"]),
    option(SlotStatement::NamedAccount, &["ROLE"]),
    option(SlotStatement::NamedAccount, &["TO"]),
    option(SlotStatement::NamedAccount, &["@"]),
    option(SlotStatement::LoadData, &["TERMINATED", "BY"]),
    option(SlotStatement::LoadData, &["ENCLOSED", "BY"]),
    option(SlotStatement::LoadData, &["ESCAPED", "BY"]),
    option(SlotStatement::LoadData, &["STARTING", "BY"]),
];

/// SQL Server documentation: `BULK INSERT`'s and `OPENROWSET(BULK …)`'s
/// format options, and the principal `EXECUTE AS` and `SETUSER` name.
const MSSQL_SHOWN_SLOTS: &[ShownSlot] = &[
    option(SlotStatement::ExecuteAs, &["AS", "LOGIN"]),
    option(SlotStatement::ExecuteAs, &["AS", "USER"]),
    option(SlotStatement::Setuser, &["SETUSER"]),
    bulk_option(&["FORMAT"]),
    bulk_option(&["FIELDTERMINATOR"]),
    bulk_option(&["ROWTERMINATOR"]),
    bulk_option(&["FIELDQUOTE"]),
    bulk_option(&["CODEPAGE"]),
    bulk_option(&["DATAFILETYPE"]),
];

/// GoogleSQL reference: the `description` and `friendly_name` options, the
/// `format` and `field_delimiter` of `EXPORT DATA`, `LOAD DATA` and
/// external tables, the Cloud Storage `uri` `EXPORT DATA` writes to and the
/// `uris` `LOAD DATA` and an external table read, the principals `GRANT`
/// and `REVOKE` name (`'user:…'`, `'allUsers'`), and those a row access
/// policy's `GRANT TO` lists.
const BIGQUERY_SHOWN_SLOTS: &[ShownSlot] = &[
    ShownSlot {
        statement: SlotStatement::Export,
        keyword: &["URI"],
        follows: SlotFollows::Option,
        holds: SlotHolds::Location,
    },
    ShownSlot {
        statement: SlotStatement::Export,
        keyword: &["URIS"],
        follows: SlotFollows::List,
        holds: SlotHolds::Location,
    },
    list(SlotStatement::Grant, &["TO"]),
    list(SlotStatement::Grant, &["FROM"]),
    list(SlotStatement::RowAccessPolicy, &["GRANT", "TO"]),
    option(SlotStatement::Definition, &["DESCRIPTION"]),
    option(SlotStatement::Definition, &["FRIENDLY_NAME"]),
    option(SlotStatement::Export, &["FORMAT"]),
    option(SlotStatement::Export, &["FIELD_DELIMITER"]),
];

/// Databricks SQL reference: an object's `COMMENT`, `COMMENT ON … IS`,
/// and the keys `ALTER TABLE … SET TBLPROPERTIES` sets, with the value of
/// each key that names no secret.
const DATABRICKS_SHOWN_SLOTS: &[ShownSlot] = &[
    option(SlotStatement::Definition, &["COMMENT"]),
    COMMENT_ON_IS,
    ShownSlot {
        statement: SlotStatement::AlterTable,
        keyword: &["TBLPROPERTIES"],
        follows: SlotFollows::Properties,
        holds: SlotHolds::Text,
    },
];

/// Snowflake documentation, "String & binary functions": `LENGTH, LEN`,
/// `SUBSTR, SUBSTRING`; "Conditional expression functions": `IFNULL` and
/// its alias `NVL` take two arguments, as `COALESCE(expr1, expr2)`.
const SNOWFLAKE_ROUTINE_SYNONYMS: &[RoutineSynonyms] = &[
    routine_synonyms("LENGTH", &["LEN"]),
    routine_synonyms("SUBSTRING", &["SUBSTR"]),
    routine_synonyms_at("COALESCE", 2, &["IFNULL", "NVL"]),
];

/// PostgreSQL documentation, "String Functions and Operators".
const POSTGRES_ROUTINE_SYNONYMS: &[RoutineSynonyms] =
    &[routine_synonyms("CHAR_LENGTH", &["CHARACTER_LENGTH"])];

/// MySQL Reference Manual, "String Functions and Operators": `LENGTH`
/// counts bytes, so it is no synonym of `CHAR_LENGTH`; "Flow Control
/// Functions": `IFNULL(expr1, expr2)`.
const MYSQL_ROUTINE_SYNONYMS: &[RoutineSynonyms] = &[
    routine_synonyms("CHAR_LENGTH", &["CHARACTER_LENGTH"]),
    routine_synonyms("SUBSTRING", &["SUBSTR", "MID"]),
    routine_synonyms_at("COALESCE", 2, &["IFNULL"]),
];

/// BigQuery documentation, "String functions"; "Conditional expressions":
/// `IFNULL(expr, null_result)`.
const BIGQUERY_ROUTINE_SYNONYMS: &[RoutineSynonyms] = &[
    routine_synonyms("CHAR_LENGTH", &["CHARACTER_LENGTH"]),
    routine_synonyms("SUBSTR", &["SUBSTRING"]),
    routine_synonyms_at("COALESCE", 2, &["IFNULL"]),
];

/// Databricks SQL reference, "Built-in functions": `len`, `char_length`
/// and `character_length` are `length`; `substr` is `substring`; `ifnull`
/// and `nvl` are `coalesce(expr1, expr2)`.
const DATABRICKS_ROUTINE_SYNONYMS: &[RoutineSynonyms] = &[
    routine_synonyms("LENGTH", &["LEN", "CHAR_LENGTH", "CHARACTER_LENGTH"]),
    routine_synonyms("SUBSTRING", &["SUBSTR"]),
    routine_synonyms_at("COALESCE", 2, &["IFNULL", "NVL"]),
];

/// Microsoft SQL Server documentation, "String functions": none. `ISNULL`
/// is no `COALESCE`: its result takes the first argument's type.
const MSSQL_ROUTINE_SYNONYMS: &[RoutineSynonyms] = &[];

/// Amazon Redshift Database Developer Guide, "LEN function": `LENGTH`,
/// `CHAR_LENGTH`, `CHARACTER_LENGTH` and `TEXTLEN` are `LEN`; "NVL and
/// COALESCE functions": `NVL` is `COALESCE`, with any number of arguments.
const REDSHIFT_ROUTINE_SYNONYMS: &[RoutineSynonyms] = &[
    routine_synonyms(
        "LEN",
        &["LENGTH", "CHAR_LENGTH", "CHARACTER_LENGTH", "TEXTLEN"],
    ),
    routine_synonyms("COALESCE", &["NVL"]),
];

/// PostgreSQL documentation, chapter "Data Types", table "Data Types": each
/// type with an alias, and `time` / `timestamp` written `without time
/// zone`, which is what either names alone; `numeric(p)` is
/// `numeric(p,0)`.
const POSTGRES_TYPE_SYNONYMS: &[TypeSynonyms] = &[
    synonyms("bigint", &["int8"]),
    synonyms("bigserial", &["serial8"]),
    synonyms("bit varying", &["varbit"]),
    synonyms("boolean", &["bool"]),
    synonyms_of("character", "(1)", &["char"]),
    synonyms("character varying", &["varchar"]),
    synonyms("double precision", &["float8"]),
    synonyms("integer", &["int", "int4"]),
    decimals("numeric", "", &["decimal"]),
    synonyms("real", &["float4"]),
    synonyms("smallint", &["int2"]),
    synonyms("smallserial", &["serial2"]),
    synonyms("serial", &["serial4"]),
    synonyms("time", &["time without time zone"]),
    synonyms("time with time zone", &["timetz"]),
    synonyms("timestamp", &["timestamp without time zone"]),
    synonyms("timestamp with time zone", &["timestamptz"]),
];

/// Snowflake documentation, "Summary of data types" and each type's page:
/// the names each type is also written by, and what each means where no
/// length or precision is written: `NUMBER` is `NUMBER(38,0)`, and so is
/// each integer name, which takes none, and `NUMBER(p)` is `NUMBER(p,0)`; `VARCHAR` is `VARCHAR(16777216)`;
/// `CHAR` is `VARCHAR(1)`; a timestamp's precision is 9. `TIMESTAMP` alone
/// names the type `TIMESTAMP_TYPE_MAPPING` sets, so it is no synonym of any.
const SNOWFLAKE_TYPE_SYNONYMS: &[TypeSynonyms] = &[
    decimals(
        "number",
        "(38,0)",
        &[
            "decimal", "dec", "numeric", "int", "integer", "bigint", "smallint", "tinyint",
            "byteint",
        ],
    ),
    synonyms(
        "float",
        &["float4", "float8", "double", "double precision", "real"],
    ),
    synonyms_of(
        "varchar",
        "(16777216)",
        &[
            "string",
            "text",
            "nvarchar",
            "nvarchar2",
            "char varying",
            "nchar varying",
        ],
    ),
    synonyms_of("varchar", "(1)", &["char", "character", "nchar"]),
    synonyms("binary", &["varbinary"]),
    synonyms_of(
        "timestamp_ntz",
        "(9)",
        &["datetime", "timestamp without time zone"],
    ),
    synonyms_of("timestamp_ltz", "(9)", &["timestamp with local time zone"]),
    synonyms_of("timestamp_tz", "(9)", &["timestamp with time zone"]),
];

/// BigQuery documentation, "Data types": the parameterized and aliased
/// names of each type; a `NUMERIC(P)` or `BIGNUMERIC(P)` has scale 0.
const BIGQUERY_TYPE_SYNONYMS: &[TypeSynonyms] = &[
    synonyms(
        "int64",
        &["int", "smallint", "integer", "bigint", "tinyint", "byteint"],
    ),
    decimals("numeric", "", &["decimal"]),
    decimals("bignumeric", "", &["bigdecimal"]),
    synonyms("bool", &["boolean"]),
];

/// MySQL Reference Manual, "Data Types" (numeric, string and Boolean
/// type overviews): the names each type is also written by, `DECIMAL`
/// being `DECIMAL(10,0)` where no precision is written and `DECIMAL(M)`
/// `DECIMAL(M,0)`. `CHAR` is `CHAR(1)` in a column but has no length cap
/// in `CAST`, so no length is implied. `REAL` is `DOUBLE` unless the `REAL_AS_FLOAT` SQL mode is set, so it is
/// no synonym; `FLOAT` is single precision.
const MYSQL_TYPE_SYNONYMS: &[TypeSynonyms] = &[
    synonyms("int", &["integer"]),
    decimals("decimal", "(10,0)", &["dec", "numeric", "fixed"]),
    synonyms("double", &["double precision"]),
    synonyms("tinyint", &["bool", "boolean"]),
    synonyms("char", &["character"]),
    synonyms("varchar", &["character varying"]),
    synonyms("nchar", &["national char", "national character"]),
    synonyms(
        "nvarchar",
        &[
            "national varchar",
            "national char varying",
            "national character varying",
        ],
    ),
];

/// Microsoft SQL Server documentation, "Data type synonyms": each
/// synonym and the system type it names; `numeric` is `decimal`, both
/// `decimal(18,0)` where no precision is written, `decimal(p,0)` where no
/// scale is. A string type's length
/// where none is written depends on where it is written (30 in `CAST`).
const MSSQL_TYPE_SYNONYMS: &[TypeSynonyms] = &[
    synonyms("varbinary", &["binary varying"]),
    synonyms("varchar", &["char varying", "character varying"]),
    synonyms("char", &["character"]),
    decimals("decimal", "(18,0)", &["dec", "numeric"]),
    synonyms("float", &["double precision"]),
    synonyms("int", &["integer"]),
    synonyms("nchar", &["national character", "national char"]),
    synonyms(
        "nvarchar",
        &["national character varying", "national char varying"],
    ),
    synonyms("ntext", &["national text"]),
    synonyms("timestamp", &["rowversion"]),
];

/// Databricks SQL reference, "Data types": each type's other names,
/// `DECIMAL` being `DECIMAL(10,0)` where no precision is written and
/// `DECIMAL(p,0)` where no scale is.
const DATABRICKS_TYPE_SYNONYMS: &[TypeSynonyms] = &[
    synonyms("bigint", &["long"]),
    synonyms("int", &["integer"]),
    synonyms("smallint", &["short"]),
    synonyms("tinyint", &["byte"]),
    synonyms("float", &["real"]),
    decimals("decimal", "(10,0)", &["dec", "numeric"]),
];

/// Amazon Redshift Database Developer Guide, "Data types", table of types
/// and their aliases, and "Character types": `CHAR` is `CHAR(1)` and
/// `BPCHAR` `CHAR(256)`; `VARCHAR` is `VARCHAR(256)`, as `TEXT` is;
/// `DECIMAL` is `DECIMAL(18,0)` where no precision is written and
/// `DECIMAL(p,0)` where no scale is.
const REDSHIFT_TYPE_SYNONYMS: &[TypeSynonyms] = &[
    synonyms("smallint", &["int2"]),
    synonyms("integer", &["int", "int4"]),
    synonyms("bigint", &["int8"]),
    decimals("decimal", "(18,0)", &["numeric"]),
    synonyms("real", &["float4"]),
    synonyms("double precision", &["float8", "float"]),
    synonyms("boolean", &["bool"]),
    synonyms_of("char", "(1)", &["character", "nchar"]),
    synonyms_of("char", "(256)", &["bpchar"]),
    synonyms_of(
        "varchar",
        "(256)",
        &["character varying", "nvarchar", "text"],
    ),
    synonyms("timestamp", &["timestamp without time zone"]),
    synonyms("timestamptz", &["timestamp with time zone"]),
    synonyms("timetz", &["time with time zone"]),
    synonyms("time", &["time without time zone"]),
    synonyms("varbyte", &["varbinary", "binary varying"]),
];

/// PostgreSQL documentation, chapter "Server Configuration": the settings
/// whose value is a schema list, a time zone, a duration, a size, a name,
/// a format, a level or a switch.
const POSTGRES_SHOWN_SETTINGS: &[ShownSetting] = &[
    setting("search_path", "runtime-config-client: Statement Behavior"),
    setting("timezone", "runtime-config-client: Locale and Formatting"),
    setting("datestyle", "runtime-config-client: Locale and Formatting"),
    setting(
        "intervalstyle",
        "runtime-config-client: Locale and Formatting",
    ),
    setting(
        "extra_float_digits",
        "runtime-config-client: Locale and Formatting",
    ),
    setting(
        "client_encoding",
        "runtime-config-client: Locale and Formatting",
    ),
    setting(
        "lc_messages",
        "runtime-config-client: Locale and Formatting",
    ),
    setting(
        "lc_monetary",
        "runtime-config-client: Locale and Formatting",
    ),
    setting("lc_numeric", "runtime-config-client: Locale and Formatting"),
    setting("lc_time", "runtime-config-client: Locale and Formatting"),
    setting(
        "statement_timeout",
        "runtime-config-client: Statement Behavior",
    ),
    setting("lock_timeout", "runtime-config-client: Statement Behavior"),
    setting(
        "idle_in_transaction_session_timeout",
        "runtime-config-client: Statement Behavior",
    ),
    setting(
        "default_transaction_isolation",
        "runtime-config-client: Statement Behavior",
    ),
    setting(
        "default_transaction_read_only",
        "runtime-config-client: Statement Behavior",
    ),
    setting(
        "default_tablespace",
        "runtime-config-client: Statement Behavior",
    ),
    setting(
        "temp_tablespaces",
        "runtime-config-client: Statement Behavior",
    ),
    setting(
        "check_function_bodies",
        "runtime-config-client: Statement Behavior",
    ),
    setting(
        "session_replication_role",
        "runtime-config-client: Statement Behavior",
    ),
    setting("row_security", "runtime-config-client: Statement Behavior"),
    setting("bytea_output", "runtime-config-client: Statement Behavior"),
    setting("xmloption", "runtime-config-client: Statement Behavior"),
    setting(
        "client_min_messages",
        "runtime-config-client: Statement Behavior",
    ),
    setting(
        "transaction_isolation",
        "runtime-config-preset / SET TRANSACTION",
    ),
    setting("work_mem", "runtime-config-resource: Memory"),
    setting(
        "max_connections",
        "runtime-config-connection: Connection Settings",
    ),
    setting("maintenance_work_mem", "runtime-config-resource: Memory"),
    setting("temp_buffers", "runtime-config-resource: Memory"),
    setting("application_name", "runtime-config-logging: What to Log"),
    setting("log_statement", "runtime-config-logging: What to Log"),
    setting("log_min_messages", "runtime-config-logging: When to Log"),
    setting(
        "log_min_duration_statement",
        "runtime-config-logging: When to Log",
    ),
    setting("synchronous_commit", "runtime-config-wal: Settings"),
    setting("standard_conforming_strings", "runtime-config-compatible"),
    setting("jit", "runtime-config-query: Other Planner Options"),
    setting(
        "random_page_cost",
        "runtime-config-query: Planner Cost Constants",
    ),
    setting(
        "effective_cache_size",
        "runtime-config-query: Planner Cost Constants",
    ),
    setting(
        "max_parallel_workers_per_gather",
        "runtime-config-resource: Asynchronous Behavior",
    ),
    setting(
        "enable_seqscan",
        "runtime-config-query: Planner Method Configuration",
    ),
    setting(
        "enable_indexscan",
        "runtime-config-query: Planner Method Configuration",
    ),
    setting(
        "enable_nestloop",
        "runtime-config-query: Planner Method Configuration",
    ),
    setting(
        "plan_cache_mode",
        "runtime-config-query: Other Planner Options",
    ),
    setting("ssl", "runtime-config-connection: SSL"),
    setting(
        "password_encryption",
        "runtime-config-connection: Authentication",
    ),
    setting(
        "listen_addresses",
        "runtime-config-connection: Connection Settings",
    ),
    setting("fsync", "runtime-config-wal: Settings"),
    setting("full_page_writes", "runtime-config-wal: Settings"),
    setting("wal_level", "runtime-config-wal: Settings"),
    setting("log_connections", "runtime-config-logging: What to Log"),
    setting("log_disconnections", "runtime-config-logging: What to Log"),
    setting(
        "log_min_error_statement",
        "runtime-config-logging: When to Log",
    ),
    setting(
        "idle_session_timeout",
        "runtime-config-client: Statement Behavior",
    ),
    setting(
        "shared_preload_libraries",
        "runtime-config-client: Shared Library Preloading",
    ),
    setting("pgaudit.log", "pgAudit: pgaudit.log"),
    setting("pgaudit.log_level", "pgAudit: pgaudit.log_level"),
];

/// Amazon Redshift Database Developer Guide, "Configuration reference":
/// the settings whose value is a schema list, a time zone, a format, a
/// name, a count or a switch.
const REDSHIFT_SHOWN_SETTINGS: &[ShownSetting] = &[
    setting("search_path", "Configuration reference: search_path"),
    setting("timezone", "Configuration reference: timezone"),
    setting("datestyle", "Configuration reference: datestyle"),
    setting(
        "statement_timeout",
        "Configuration reference: statement_timeout",
    ),
    setting("query_group", "Configuration reference: query_group"),
    setting(
        "wlm_query_slot_count",
        "Configuration reference: wlm_query_slot_count",
    ),
    setting(
        "enable_result_cache_for_session",
        "Configuration reference: enable_result_cache_for_session",
    ),
    setting(
        "extra_float_digits",
        "Configuration reference: extra_float_digits",
    ),
    setting(
        "max_concurrency_scaling_clusters",
        "Configuration reference: max_concurrency_scaling_clusters",
    ),
    setting(
        "analyze_threshold_percent",
        "Configuration reference: analyze_threshold_percent",
    ),
    setting(
        "describe_field_name_in_uppercase",
        "Configuration reference: describe_field_name_in_uppercase",
    ),
    setting(
        "enable_case_sensitive_identifier",
        "Configuration reference: enable_case_sensitive_identifier",
    ),
    setting(
        "json_parse_truncate_strings",
        "Configuration reference: json_parse_truncate_strings",
    ),
    setting(
        "application_name",
        "Configuration reference: application_name",
    ),
    setting("auto_mv", "Configuration reference: auto_mv"),
];

/// Snowflake SQL reference, "Parameters": the session parameters whose
/// value is a tag, a time zone, a format, a duration, a count or a switch,
/// and a user's switches and counts ("CREATE USER").
const SNOWFLAKE_SHOWN_SETTINGS: &[ShownSetting] = &[
    setting(
        "PASSWORD_MIN_LENGTH",
        "CREATE PASSWORD POLICY: PASSWORD_MIN_LENGTH",
    ),
    setting(
        "PASSWORD_MAX_LENGTH",
        "CREATE PASSWORD POLICY: PASSWORD_MAX_LENGTH",
    ),
    setting(
        "PASSWORD_MIN_UPPER_CASE_CHARS",
        "CREATE PASSWORD POLICY: PASSWORD_MIN_UPPER_CASE_CHARS",
    ),
    setting(
        "PASSWORD_MIN_LOWER_CASE_CHARS",
        "CREATE PASSWORD POLICY: PASSWORD_MIN_LOWER_CASE_CHARS",
    ),
    setting(
        "PASSWORD_MIN_NUMERIC_CHARS",
        "CREATE PASSWORD POLICY: PASSWORD_MIN_NUMERIC_CHARS",
    ),
    setting(
        "PASSWORD_MIN_SPECIAL_CHARS",
        "CREATE PASSWORD POLICY: PASSWORD_MIN_SPECIAL_CHARS",
    ),
    setting(
        "PASSWORD_MIN_AGE_DAYS",
        "CREATE PASSWORD POLICY: PASSWORD_MIN_AGE_DAYS",
    ),
    setting(
        "PASSWORD_MAX_AGE_DAYS",
        "CREATE PASSWORD POLICY: PASSWORD_MAX_AGE_DAYS",
    ),
    setting(
        "PASSWORD_MAX_RETRIES",
        "CREATE PASSWORD POLICY: PASSWORD_MAX_RETRIES",
    ),
    setting(
        "PASSWORD_LOCKOUT_TIME_MINS",
        "CREATE PASSWORD POLICY: PASSWORD_LOCKOUT_TIME_MINS",
    ),
    setting(
        "PASSWORD_HISTORY",
        "CREATE PASSWORD POLICY: PASSWORD_HISTORY",
    ),
    setting("QUERY_TAG", "Parameters: QUERY_TAG"),
    setting("TIMEZONE", "Parameters: TIMEZONE"),
    setting("DATE_INPUT_FORMAT", "Parameters: DATE_INPUT_FORMAT"),
    setting("DATE_OUTPUT_FORMAT", "Parameters: DATE_OUTPUT_FORMAT"),
    setting("TIME_INPUT_FORMAT", "Parameters: TIME_INPUT_FORMAT"),
    setting("TIME_OUTPUT_FORMAT", "Parameters: TIME_OUTPUT_FORMAT"),
    setting(
        "TIMESTAMP_INPUT_FORMAT",
        "Parameters: TIMESTAMP_INPUT_FORMAT",
    ),
    setting(
        "TIMESTAMP_OUTPUT_FORMAT",
        "Parameters: TIMESTAMP_OUTPUT_FORMAT",
    ),
    setting(
        "TIMESTAMP_LTZ_OUTPUT_FORMAT",
        "Parameters: TIMESTAMP_LTZ_OUTPUT_FORMAT",
    ),
    setting(
        "TIMESTAMP_NTZ_OUTPUT_FORMAT",
        "Parameters: TIMESTAMP_NTZ_OUTPUT_FORMAT",
    ),
    setting(
        "TIMESTAMP_TZ_OUTPUT_FORMAT",
        "Parameters: TIMESTAMP_TZ_OUTPUT_FORMAT",
    ),
    setting(
        "TIMESTAMP_TYPE_MAPPING",
        "Parameters: TIMESTAMP_TYPE_MAPPING",
    ),
    setting(
        "TIMESTAMP_DAY_IS_ALWAYS_24H",
        "Parameters: TIMESTAMP_DAY_IS_ALWAYS_24H",
    ),
    setting(
        "CLIENT_TIMESTAMP_TYPE_MAPPING",
        "Parameters: CLIENT_TIMESTAMP_TYPE_MAPPING",
    ),
    setting("BINARY_INPUT_FORMAT", "Parameters: BINARY_INPUT_FORMAT"),
    setting("BINARY_OUTPUT_FORMAT", "Parameters: BINARY_OUTPUT_FORMAT"),
    setting(
        "GEOGRAPHY_OUTPUT_FORMAT",
        "Parameters: GEOGRAPHY_OUTPUT_FORMAT",
    ),
    setting("WEEK_START", "Parameters: WEEK_START"),
    setting("WEEK_OF_YEAR_POLICY", "Parameters: WEEK_OF_YEAR_POLICY"),
    setting(
        "TWO_DIGIT_CENTURY_START",
        "Parameters: TWO_DIGIT_CENTURY_START",
    ),
    setting(
        "STATEMENT_TIMEOUT_IN_SECONDS",
        "Parameters: STATEMENT_TIMEOUT_IN_SECONDS",
    ),
    setting(
        "STATEMENT_QUEUED_TIMEOUT_IN_SECONDS",
        "Parameters: STATEMENT_QUEUED_TIMEOUT_IN_SECONDS",
    ),
    setting("LOCK_TIMEOUT", "Parameters: LOCK_TIMEOUT"),
    setting("AUTOCOMMIT", "Parameters: AUTOCOMMIT"),
    setting("ABORT_DETACHED_QUERY", "Parameters: ABORT_DETACHED_QUERY"),
    setting(
        "QUOTED_IDENTIFIERS_IGNORE_CASE",
        "Parameters: QUOTED_IDENTIFIERS_IGNORE_CASE",
    ),
    setting("USE_CACHED_RESULT", "Parameters: USE_CACHED_RESULT"),
    setting("ROWS_PER_RESULTSET", "Parameters: ROWS_PER_RESULTSET"),
    setting("SEARCH_PATH", "Parameters: SEARCH_PATH"),
    setting(
        "TRANSACTION_DEFAULT_ISOLATION_LEVEL",
        "Parameters: TRANSACTION_DEFAULT_ISOLATION_LEVEL",
    ),
    setting(
        "ERROR_ON_NONDETERMINISTIC_MERGE",
        "Parameters: ERROR_ON_NONDETERMINISTIC_MERGE",
    ),
    setting(
        "ERROR_ON_NONDETERMINISTIC_UPDATE",
        "Parameters: ERROR_ON_NONDETERMINISTIC_UPDATE",
    ),
    setting("JSON_INDENT", "Parameters: JSON_INDENT"),
    setting("STRICT_JSON_OUTPUT", "Parameters: STRICT_JSON_OUTPUT"),
    setting("MULTI_STATEMENT_COUNT", "Parameters: MULTI_STATEMENT_COUNT"),
    // A user's switches and counts ("CREATE USER", "Object properties").
    setting("DISABLED", "CREATE USER: DISABLED"),
    setting("MUST_CHANGE_PASSWORD", "CREATE USER: MUST_CHANGE_PASSWORD"),
    setting("DAYS_TO_EXPIRY", "CREATE USER: DAYS_TO_EXPIRY"),
    setting("MINS_TO_UNLOCK", "CREATE USER: MINS_TO_UNLOCK"),
    setting("MINS_TO_BYPASS_MFA", "CREATE USER: MINS_TO_BYPASS_MFA"),
    setting("TYPE", "CREATE USER: TYPE"),
    // The names a user's or the account's session starts with, written
    // bare as well as quoted ("CREATE USER", "Parameters: NETWORK_POLICY").
    setting("DEFAULT_ROLE", "CREATE USER: DEFAULT_ROLE"),
    setting("DEFAULT_WAREHOUSE", "CREATE USER: DEFAULT_WAREHOUSE"),
    setting("DEFAULT_NAMESPACE", "CREATE USER: DEFAULT_NAMESPACE"),
    setting(
        "DEFAULT_SECONDARY_ROLES",
        "CREATE USER: DEFAULT_SECONDARY_ROLES",
    ),
    setting("NETWORK_POLICY", "Parameters: NETWORK_POLICY"),
    // The object parameters the built-in rules read, and those documented
    // beside them ("Parameters": account, object and session parameters).
    setting(
        "DATA_RETENTION_TIME_IN_DAYS",
        "Parameters: DATA_RETENTION_TIME_IN_DAYS",
    ),
    setting(
        "MAX_DATA_EXTENSION_TIME_IN_DAYS",
        "Parameters: MAX_DATA_EXTENSION_TIME_IN_DAYS",
    ),
    setting(
        "MIN_DATA_RETENTION_TIME_IN_DAYS",
        "Parameters: MIN_DATA_RETENTION_TIME_IN_DAYS",
    ),
    setting(
        "CLIENT_SESSION_KEEP_ALIVE",
        "Parameters: CLIENT_SESSION_KEEP_ALIVE",
    ),
    setting(
        "CLIENT_SESSION_KEEP_ALIVE_HEARTBEAT_FREQUENCY",
        "Parameters: CLIENT_SESSION_KEEP_ALIVE_HEARTBEAT_FREQUENCY",
    ),
    setting(
        "PREVENT_UNLOAD_TO_INLINE_URL",
        "Parameters: PREVENT_UNLOAD_TO_INLINE_URL",
    ),
    setting(
        "REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_CREATION",
        "Parameters: REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_CREATION",
    ),
    setting(
        "REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_OPERATION",
        "Parameters: REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_OPERATION",
    ),
    setting(
        "PERIODIC_DATA_REKEYING",
        "Parameters: PERIODIC_DATA_REKEYING",
    ),
    setting(
        "ENABLE_UNREDACTED_QUERY_SYNTAX_ERROR",
        "Parameters: ENABLE_UNREDACTED_QUERY_SYNTAX_ERROR",
    ),
    setting("PIPE_EXECUTION_PAUSED", "Parameters: PIPE_EXECUTION_PAUSED"),
    setting("LOG_LEVEL", "Parameters: LOG_LEVEL"),
    setting("TRACE_LEVEL", "Parameters: TRACE_LEVEL"),
    setting("DEFAULT_DDL_COLLATION", "Parameters: DEFAULT_DDL_COLLATION"),
    setting(
        "SUSPEND_TASK_AFTER_NUM_FAILURES",
        "Parameters: SUSPEND_TASK_AFTER_NUM_FAILURES",
    ),
    setting("USER_TASK_TIMEOUT_MS", "Parameters: USER_TASK_TIMEOUT_MS"),
    setting("MAX_CONCURRENCY_LEVEL", "Parameters: MAX_CONCURRENCY_LEVEL"),
    setting(
        "ENABLE_SCHEMA_EVOLUTION",
        "CREATE TABLE: ENABLE_SCHEMA_EVOLUTION",
    ),
    setting("CHANGE_TRACKING", "CREATE TABLE: CHANGE_TRACKING"),
    // A warehouse's sizes, counts and switches ("CREATE WAREHOUSE").
    setting("AUTO_SUSPEND", "CREATE WAREHOUSE: AUTO_SUSPEND"),
    setting("AUTO_RESUME", "CREATE WAREHOUSE: AUTO_RESUME"),
    setting(
        "INITIALLY_SUSPENDED",
        "CREATE WAREHOUSE: INITIALLY_SUSPENDED",
    ),
    setting("MIN_CLUSTER_COUNT", "CREATE WAREHOUSE: MIN_CLUSTER_COUNT"),
    setting("MAX_CLUSTER_COUNT", "CREATE WAREHOUSE: MAX_CLUSTER_COUNT"),
    setting("SCALING_POLICY", "CREATE WAREHOUSE: SCALING_POLICY"),
    // A warehouse's size, type and memory option, read by the warehouse
    // rules, quoted or bare ("CREATE WAREHOUSE: Object properties").
    setting("WAREHOUSE_SIZE", "CREATE WAREHOUSE: WAREHOUSE_SIZE"),
    setting("WAREHOUSE_TYPE", "CREATE WAREHOUSE: WAREHOUSE_TYPE"),
    setting(
        "RESOURCE_CONSTRAINT",
        "CREATE WAREHOUSE: RESOURCE_CONSTRAINT",
    ),
    // The external volume a schema's or database's Iceberg tables use, by
    // name ("Parameters: EXTERNAL_VOLUME"), and a table's row timestamps
    // ("ALTER TABLE: ROW_TIMESTAMP").
    setting("EXTERNAL_VOLUME", "Parameters: EXTERNAL_VOLUME"),
    setting("ROW_TIMESTAMP", "ALTER TABLE: ROW_TIMESTAMP"),
    // Account switches and counts `INFO-SNW-ACCT-PARAM-CHG` quotes
    // ("Parameters").
    setting("ALLOW_ID_TOKEN", "Parameters: ALLOW_ID_TOKEN"),
    setting("SSO_LOGIN_PAGE", "Parameters: SSO_LOGIN_PAGE"),
    setting(
        "ENABLE_IDENTIFIER_FIRST_LOGIN",
        "Parameters: ENABLE_IDENTIFIER_FIRST_LOGIN",
    ),
    setting(
        "ALLOW_CLIENT_MFA_CACHING",
        "Parameters: ALLOW_CLIENT_MFA_CACHING",
    ),
    setting(
        "PREVENT_UNLOAD_TO_INTERNAL_STAGES",
        "Parameters: PREVENT_UNLOAD_TO_INTERNAL_STAGES",
    ),
    setting(
        "OAUTH_ADD_PRIVILEGED_ROLES_TO_BLOCKED_LIST",
        "Parameters: OAUTH_ADD_PRIVILEGED_ROLES_TO_BLOCKED_LIST",
    ),
    setting(
        "INITIAL_REPLICATION_SIZE_LIMIT_IN_TB",
        "Parameters: INITIAL_REPLICATION_SIZE_LIMIT_IN_TB",
    ),
    setting(
        "ENABLE_TRI_SECRET_AND_REKEY_OPT_OUT_FOR_IMAGE_REPOSITORY",
        "Parameters: ENABLE_TRI_SECRET_AND_REKEY_OPT_OUT_FOR_IMAGE_REPOSITORY",
    ),
    // Whether a user signs in with Duo ("CREATE USER: EXT_AUTHN_DUO").
    setting("EXT_AUTHN_DUO", "CREATE USER: EXT_AUTHN_DUO"),
    setting(
        "ENABLE_QUERY_ACCELERATION",
        "CREATE WAREHOUSE: ENABLE_QUERY_ACCELERATION",
    ),
    setting(
        "QUERY_ACCELERATION_MAX_SCALE_FACTOR",
        "CREATE WAREHOUSE: QUERY_ACCELERATION_MAX_SCALE_FACTOR",
    ),
    setting("RESOURCE_MONITOR", "CREATE WAREHOUSE: RESOURCE_MONITOR"),
    // A task's overlap switch ("CREATE TASK"), an integration's switch
    // ("CREATE … INTEGRATION": ENABLED).
    setting(
        "ALLOW_OVERLAPPING_EXECUTION",
        "CREATE TASK: ALLOW_OVERLAPPING_EXECUTION",
    ),
    setting("ENABLED", "CREATE INTEGRATION: ENABLED"),
    // A security integration's switches and role ("CREATE SECURITY
    // INTEGRATION").
    setting(
        "OAUTH_ALLOW_NON_TLS_REDIRECT_URI",
        "CREATE SECURITY INTEGRATION: OAUTH_ALLOW_NON_TLS_REDIRECT_URI",
    ),
    setting(
        "EXTERNAL_OAUTH_ANY_ROLE_MODE",
        "CREATE SECURITY INTEGRATION: EXTERNAL_OAUTH_ANY_ROLE_MODE",
    ),
    setting("RUN_AS_ROLE", "CREATE SECURITY INTEGRATION: RUN_AS_ROLE"),
    setting(
        "SAML2_SIGN_REQUEST",
        "CREATE SECURITY INTEGRATION: SAML2_SIGN_REQUEST",
    ),
    setting(
        "SYNC_PASSWORD",
        "CREATE SECURITY INTEGRATION: SYNC_PASSWORD",
    ),
    // A session policy's and a password policy's durations and counts
    // ("CREATE SESSION POLICY", "CREATE PASSWORD POLICY").
    setting(
        "SESSION_IDLE_TIMEOUT_MINS",
        "CREATE SESSION POLICY: SESSION_IDLE_TIMEOUT_MINS",
    ),
    setting(
        "SESSION_UI_IDLE_TIMEOUT_MINS",
        "CREATE SESSION POLICY: SESSION_UI_IDLE_TIMEOUT_MINS",
    ),
    setting(
        "PASSWORD_MIN_LENGTH",
        "CREATE PASSWORD POLICY: PASSWORD_MIN_LENGTH",
    ),
    setting(
        "PASSWORD_MAX_AGE_DAYS",
        "CREATE PASSWORD POLICY: PASSWORD_MAX_AGE_DAYS",
    ),
    setting(
        "PASSWORD_HISTORY",
        "CREATE PASSWORD POLICY: PASSWORD_HISTORY",
    ),
    setting(
        "PASSWORD_MAX_RETRIES",
        "CREATE PASSWORD POLICY: PASSWORD_MAX_RETRIES",
    ),
    setting(
        "PASSWORD_LOCKOUT_TIME_MINS",
        "CREATE PASSWORD POLICY: PASSWORD_LOCKOUT_TIME_MINS",
    ),
];

/// MySQL Reference Manual, "Server System Variables": the variables whose
/// value is a mode, a time zone, a character set, a level, a duration, a
/// size, a switch or a server file's path.
const MYSQL_SHOWN_SETTINGS: &[ShownSetting] = &[
    setting("sql_mode", "Server System Variables: sql_mode"),
    setting("time_zone", "Server System Variables: time_zone"),
    setting("autocommit", "Server System Variables: autocommit"),
    setting(
        "character_set_client",
        "Server System Variables: character_set_client",
    ),
    setting(
        "character_set_connection",
        "Server System Variables: character_set_connection",
    ),
    setting(
        "character_set_results",
        "Server System Variables: character_set_results",
    ),
    setting(
        "collation_connection",
        "Server System Variables: collation_connection",
    ),
    setting(
        "transaction_isolation",
        "Server System Variables: transaction_isolation",
    ),
    setting("tx_isolation", "Server System Variables: tx_isolation"),
    setting(
        "foreign_key_checks",
        "Server System Variables: foreign_key_checks",
    ),
    setting("unique_checks", "Server System Variables: unique_checks"),
    setting(
        "sql_safe_updates",
        "Server System Variables: sql_safe_updates",
    ),
    setting("sql_log_bin", "Server System Variables: sql_log_bin"),
    setting(
        "max_execution_time",
        "Server System Variables: max_execution_time",
    ),
    setting("wait_timeout", "Server System Variables: wait_timeout"),
    setting(
        "interactive_timeout",
        "Server System Variables: interactive_timeout",
    ),
    setting(
        "innodb_lock_wait_timeout",
        "InnoDB Startup Options and System Variables",
    ),
    setting(
        "group_concat_max_len",
        "Server System Variables: group_concat_max_len",
    ),
    setting(
        "max_allowed_packet",
        "Server System Variables: max_allowed_packet",
    ),
    setting(
        "net_read_timeout",
        "Server System Variables: net_read_timeout",
    ),
    setting(
        "net_write_timeout",
        "Server System Variables: net_write_timeout",
    ),
    setting(
        "sort_buffer_size",
        "Server System Variables: sort_buffer_size",
    ),
    setting("tmp_table_size", "Server System Variables: tmp_table_size"),
    setting(
        "max_heap_table_size",
        "Server System Variables: max_heap_table_size",
    ),
    setting(
        "default_storage_engine",
        "Server System Variables: default_storage_engine",
    ),
    setting("lc_time_names", "Server System Variables: lc_time_names"),
    setting(
        "div_precision_increment",
        "Server System Variables: div_precision_increment",
    ),
    setting(
        "explicit_defaults_for_timestamp",
        "Server System Variables: explicit_defaults_for_timestamp",
    ),
    setting(
        "sql_require_primary_key",
        "Server System Variables: sql_require_primary_key",
    ),
    setting(
        "event_scheduler",
        "Server System Variables: event_scheduler",
    ),
    setting("local_infile", "Server System Variables: local_infile"),
    setting(
        "log_bin_trust_function_creators",
        "Binary Logging Options and Variables",
    ),
    setting("general_log", "Server System Variables: general_log"),
    setting(
        "general_log_file",
        "Server System Variables: general_log_file",
    ),
    setting("slow_query_log", "Server System Variables: slow_query_log"),
    setting(
        "slow_query_log_file",
        "Server System Variables: slow_query_log_file",
    ),
    setting(
        "long_query_time",
        "Server System Variables: long_query_time",
    ),
    setting(
        "max_connections",
        "Server System Variables: max_connections",
    ),
    setting(
        "require_secure_transport",
        "Server System Variables: require_secure_transport",
    ),
    setting(
        "default_password_lifetime",
        "Server System Variables: default_password_lifetime",
    ),
    setting(
        "password_history",
        "Server System Variables: password_history",
    ),
    setting(
        "password_reuse_interval",
        "Server System Variables: password_reuse_interval",
    ),
    setting(
        "validate_password.policy",
        "Password Validation Options and Variables: validate_password.policy",
    ),
    setting(
        "validate_password.length",
        "Password Validation Options and Variables: validate_password.length",
    ),
];

/// Databricks SQL reference, "Configuration parameters", and the Spark SQL
/// configuration properties a session sets: those whose value is a time
/// zone, a duration, a size, a count, a policy or a switch.
const DATABRICKS_SHOWN_SETTINGS: &[ShownSetting] = &[
    setting("ANSI_MODE", "Configuration parameters: ANSI_MODE"),
    setting("TIMEZONE", "Configuration parameters: TIMEZONE"),
    setting(
        "STATEMENT_TIMEOUT",
        "Configuration parameters: STATEMENT_TIMEOUT",
    ),
    setting(
        "LEGACY_TIME_PARSER_POLICY",
        "Configuration parameters: LEGACY_TIME_PARSER_POLICY",
    ),
    setting(
        "MAX_FILE_PARTITION_BYTES",
        "Configuration parameters: MAX_FILE_PARTITION_BYTES",
    ),
    setting(
        "USE_CACHED_RESULT",
        "Configuration parameters: USE_CACHED_RESULT",
    ),
    setting(
        "spark.sql.session.timeZone",
        "Spark SQL configuration: spark.sql.session.timeZone",
    ),
    setting(
        "spark.sql.shuffle.partitions",
        "Spark SQL configuration: spark.sql.shuffle.partitions",
    ),
    setting(
        "spark.sql.ansi.enabled",
        "Spark SQL configuration: spark.sql.ansi.enabled",
    ),
    setting(
        "spark.sql.adaptive.enabled",
        "Spark SQL configuration: spark.sql.adaptive.enabled",
    ),
    setting(
        "spark.databricks.delta.retentionDurationCheck.enabled",
        "Delta Lake: VACUUM retention check",
    ),
    setting(
        "spark.databricks.io.cache.enabled",
        "Optimize performance with caching: spark.databricks.io.cache.enabled",
    ),
];

/// SQL Server documentation, "ALTER DATABASE SCOPED CONFIGURATION": the
/// configurations whose value is a count or a switch.
const MSSQL_SHOWN_SETTINGS: &[ShownSetting] = &[
    setting("MAXDOP", "ALTER DATABASE SCOPED CONFIGURATION: MAXDOP"),
    setting(
        "LEGACY_CARDINALITY_ESTIMATION",
        "ALTER DATABASE SCOPED CONFIGURATION: LEGACY_CARDINALITY_ESTIMATION",
    ),
    setting(
        "PARAMETER_SNIFFING",
        "ALTER DATABASE SCOPED CONFIGURATION: PARAMETER_SNIFFING",
    ),
    setting(
        "QUERY_OPTIMIZER_HOTFIXES",
        "ALTER DATABASE SCOPED CONFIGURATION: QUERY_OPTIMIZER_HOTFIXES",
    ),
];

impl Dialect for MsSqlDialect {
    fn delete_from_optional(&self) -> bool {
        true
    }
    fn type_synonyms(&self) -> &'static [TypeSynonyms] {
        MSSQL_TYPE_SYNONYMS
    }
    fn routine_synonyms(&self) -> &'static [RoutineSynonyms] {
        MSSQL_ROUTINE_SYNONYMS
    }
    fn user_functions_write(&self) -> bool {
        false // a T-SQL function cannot change database state
    }
    fn shown_slots(&self) -> &'static [ShownSlot] {
        MSSQL_SHOWN_SLOTS
    }
    fn shown_settings(&self) -> &'static [ShownSetting] {
        MSSQL_SHOWN_SETTINGS
    }
    fn select_alias_first(&self) -> bool {
        true // "SELECT Clause (Transact-SQL)": `column_alias = expression`
    }
    fn supports_insert_optional_into(&self) -> bool {
        true
    }
    fn system_routines(&self) -> &'static [SystemRoutine] {
        MSSQL_SYSTEM_ROUTINES
    }

    // "sp_rename": `objname`, `newname`, `objtype` (`COLUMN` for a column).
    fn rename_routine(&self) -> Option<RenameRoutine> {
        Some(RenameRoutine {
            name: "sp_rename",
            object: "objname",
            new_name: "newname",
            kind: "objtype",
            column_kind: "COLUMN",
        })
    }
    fn names_system_routines(&self, qualifier: &[&str]) -> bool {
        // The schema `sys` or `dbo`, or none written after a database
        // (`db..p`): the system procedures are found from every database
        // and run in the one named. A server may be named first.
        let system_schema = |schema: &str| {
            ["sys", "dbo"]
                .iter()
                .any(|system| names_qualifier(self, schema, system))
        };
        match qualifier {
            [] => true,
            [schema] => system_schema(schema),
            [database, schema] | [_, database, schema] => {
                (schema.is_empty() && !database.is_empty()) || system_schema(schema)
            }
            [_, _, _, _, ..] => false,
        }
    }
    fn routine_language_is_sql(&self, _name: &str) -> bool {
        false // a T-SQL routine names no language
    }
    fn syntax_meaning(&self) -> SyntaxMeaning {
        SyntaxMeaning {
            using_column_order: UsingColumnOrder::NotStated,
            typed_create_as: TypedCreateAs::NamesByPosition,
            shorter_column_list: ShorterColumnList::NotStated,
            database_level: DatabaseLevel::AboveSchema,
            temporary_tables: TemporaryTables::NotStated,
            cte_write_target: CteWriteTarget::WritesThroughCte,
            write_target_source: WriteTargetSource::NamedBySource,
            default_search_path: DefaultSearchPath::Schemas(&["dbo"]),
        }
    }

    // ---- Statement grammar shape (see trait docs) ----
    fn dynamic_sql_identifier_quoting_functions(&self) -> &'static [&'static str] {
        &["quotename"] // QUOTENAME(@id) — bracket/quote-escapes an identifier
    }
    fn supports_go_batch_separator(&self) -> bool {
        true
    }
    fn uses_block_scoped_control_flow(&self) -> bool {
        true
    }
    fn supports_exec_procedure_call(&self) -> bool {
        true
    }
    fn supports_print_statement(&self) -> bool {
        true
    }
    fn supports_reconfigure_statement(&self) -> bool {
        true
    }
    fn supports_revert_statement(&self) -> bool {
        true
    }
    fn bare_credential_is_identity_secret(&self) -> bool {
        true
    }
    fn supports_throw_statement(&self) -> bool {
        true
    }
    fn supports_raiserror_statement(&self) -> bool {
        true
    }
    fn supports_waitfor_statement(&self) -> bool {
        true
    }
    fn supports_goto_statement(&self) -> bool {
        true
    }
    fn supports_bulk_insert_statement(&self) -> bool {
        true
    }
    fn supports_statement_labels(&self) -> bool {
        true
    }
    fn set_distinguishes_options(&self) -> bool {
        true
    }
    fn trigger_lists_table_before_timing(&self) -> bool {
        true
    }
    fn vector_index_uses_with_options_clause(&self) -> bool {
        true
    }
    fn login_has_source_clause(&self) -> bool {
        true
    }
    fn declare_uses_equals_initializer(&self) -> bool {
        true
    }
    fn supports_table_hints(&self) -> bool {
        true
    }
    fn supports_query_option_clause(&self) -> bool {
        true
    }
    fn supports_select_variable_assignment(&self) -> bool {
        true
    }
    fn uses_optional_statement_terminators(&self) -> bool {
        true
    }
    fn select_into_creates_table(&self) -> bool {
        true
    }
    fn select_into_supports_filegroup(&self) -> bool {
        true
    }
    fn grant_grammar(&self) -> GrantGrammar {
        GrantGrammar::ClassQualifiedSecurable
    }
    fn procedure_param_grammar(&self) -> ProcedureParamGrammar {
        ProcedureParamGrammar::AtPrefixedTrailingMode
    }

    // ========================================================================
    // Core Identity
    // ========================================================================

    fn name(&self) -> &'static str {
        "mssql"
    }

    // ========================================================================
    // Keyword Rules
    // ========================================================================

    keyword_answers!(mssql_keyword);

    // ========================================================================
    // Identifier Rules
    // ========================================================================

    fn identifier_quote_char(&self) -> char {
        // MSSQL supports both [...] brackets and "..." (with QUOTED_IDENTIFIER ON).
        // We use '"' as the primary identifier quote char since the existing lexer
        // already handles double-quoted identifiers. Bracket identifiers are handled
        // by the separate supports_bracket_identifiers() gate.
        '"'
    }

    fn max_identifier_length(&self) -> Option<usize> {
        Some(128) // 128 chars (116 for local temp tables)
    }

    fn unquoted_identifiers_case_sensitive(&self) -> bool {
        // MSSQL is case-insensitive by default (depends on collation, but
        // the default server collation SQL_Latin1_General_CP1_CI_AS is CI)
        false
    }

    fn extra_identifier_chars(&self) -> &'static [char] {
        &['$', '#', '@'] // MSSQL allows $, #, and @ in unquoted identifiers
    }

    // ========================================================================
    // String Literal Rules
    // ========================================================================

    fn string_quote_char(&self) -> char {
        '\''
    }

    fn supports_double_quoted_strings(&self) -> bool {
        // In MSSQL with QUOTED_IDENTIFIER ON (default since SQL Server 2000),
        // "..." is an identifier, not a string literal.
        false
    }

    // "SELECT Clause": `expression [ [ AS ] column_alias ]`, the alias
    // written also as a string literal (`c AS 'x'`, `c 'x'`).
    fn string_column_alias(&self) -> bool {
        true
    }

    fn supports_string_escapes(&self) -> bool {
        // MSSQL does not support C-style backslash escapes in strings.
        // Use '' for a literal single quote within a string.
        false
    }

    fn backslash_escapes_in_single_quoted_strings(&self) -> bool {
        false // MSSQL: backslash has no special meaning in strings
    }

    // ========================================================================
    // Comment Rules
    // ========================================================================

    fn supports_nested_block_comments(&self) -> bool {
        true // T-SQL supports nested /* ... /* ... */ ... */ block comments
    }

    fn requires_space_after_double_dash(&self) -> bool {
        false // MSSQL: -- starts a comment without requiring a trailing space
    }

    fn supports_version_comments(&self) -> bool {
        false // Version comments are MySQL-specific
    }

    // ========================================================================
    // Statement Support
    // ========================================================================

    fn supports_merge(&self) -> bool {
        true // MERGE is a reserved keyword in T-SQL
    }

    fn supports_cte(&self) -> bool {
        true // CTEs supported since SQL Server 2005
    }

    fn supports_lateral(&self) -> bool {
        // MSSQL uses CROSS APPLY / OUTER APPLY instead of LATERAL
        false
    }

    fn supports_window_functions(&self) -> bool {
        true // Full window function support with OVER/PARTITION BY
    }

    fn supports_qualify(&self) -> bool {
        false // MSSQL does not support QUALIFY — use subquery with ROW_NUMBER() instead
    }

    fn supports_sample(&self) -> bool {
        true // TABLESAMPLE is a reserved keyword in T-SQL
    }

    fn supports_time_travel(&self) -> bool {
        // MSSQL uses temporal tables (FOR SYSTEM_TIME) but not Snowflake-style AT/BEFORE
        false
    }

    fn supports_pivot(&self) -> bool {
        true // PIVOT is a reserved keyword in T-SQL
    }

    fn supports_unpivot(&self) -> bool {
        true // UNPIVOT is a reserved keyword in T-SQL
    }

    fn supports_flatten(&self) -> bool {
        false // MSSQL uses CROSS APPLY with OPENJSON/STRING_SPLIT instead
    }

    fn supports_values_as_table(&self) -> bool {
        true // VALUES can be used as a table source in T-SQL
    }

    fn is_table_valued_function(&self, name: &str) -> bool {
        matches!(
            name.to_ascii_uppercase().as_str(),
            "OPENJSON"
                | "OPENXML"
                | "OPENROWSET"
                | "OPENQUERY"
                | "OPENDATASOURCE"
                | "STRING_SPLIT"
                | "GENERATE_SERIES"
                | "VECTOR_SEARCH"
                | "REGEXP_MATCHES"
        )
    }

    fn introduced_arguments(&self, function: &str) -> &'static [IntroducedArgument] {
        match AsciiUpper::new(function).as_str() {
            "PARSE" | "TRY_PARSE" => PARSE_ARGUMENTS,
            _ => &[],
        }
    }

    fn non_value_arguments(&self, function: &str) -> &'static [NonValueArgument] {
        match AsciiUpper::new(function).as_str() {
            // `CONVERT(type, expr [, style])`, `TRY_CONVERT` alike.
            "CONVERT" | "TRY_CONVERT" | "IDENTITY" => TYPE_FIRST,
            "DATEADD" | "DATEDIFF" | "DATEDIFF_BIG" | "DATEPART" | "DATENAME" | "DATETRUNC"
            | "DATE_BUCKET" => PART_FIRST,
            _ => &[],
        }
    }

    fn date_part(&self, word: &str) -> Option<crate::ast::DatePart> {
        use crate::ast::DatePart;
        Some(match AsciiUpper::new(word).as_str() {
            "YY" | "YYYY" => DatePart::Year,
            "QQ" | "Q" => DatePart::Quarter,
            "MM" | "M" => DatePart::Month,
            "DY" | "Y" => DatePart::DayOfYear,
            "DD" | "D" => DatePart::Day,
            "WK" | "WW" => DatePart::Week,
            "DW" | "W" => DatePart::DayOfWeek,
            "HH" => DatePart::Hour,
            "MI" | "N" => DatePart::Minute,
            "SS" | "S" => DatePart::Second,
            "MS" => DatePart::Millisecond,
            "MCS" => DatePart::Microsecond,
            "NS" => DatePart::Nanosecond,
            "TZOFFSET" | "TZ" => DatePart::Timezone,
            "ISOWK" | "ISOWW" => DatePart::IsoWeek,
            _ => return DatePart::from_name(word),
        })
    }

    fn except_is_star_modifier(&self) -> bool {
        false
    }

    fn supports_projection_exclude(&self) -> bool {
        false
    }

    fn scripting_requires_begin(&self) -> bool {
        true // T-SQL uses BEGIN...END blocks for scripting
    }

    fn declare_starts_block(&self) -> bool {
        false // T-SQL: DECLARE is always a standalone statement, not a block opener
    }

    // ========================================================================
    // Operator Support
    // ========================================================================

    fn pipe_pipe_is_concat(&self) -> bool {
        // SQL Server 2022+ added || as ANSI string concatenation.
        // Traditional MSSQL uses + for concat, but || is always concat (never logical OR).
        true
    }

    fn supports_json_operators(&self) -> bool {
        // MSSQL uses JSON_VALUE()/JSON_QUERY()/OPENJSON() functions.
        // Recent versions added some shorthand but we report false for -> / ->> operators.
        false
    }

    fn supports_named_args_operator(&self) -> bool {
        false // MSSQL doesn't support => for named arguments
    }

    fn supports_type_cast_operator(&self) -> bool {
        // MSSQL uses CAST()/CONVERT()/TRY_CONVERT()/TRY_CAST(), no :: operator.
        // Note: :: is the scope resolution operator in T-SQL (e.g., hierarchyid::Parse())
        false
    }

    fn supports_distinct_on(&self) -> bool {
        false // DISTINCT ON is PostgreSQL-specific
    }

    fn supports_returning(&self) -> bool {
        false // MSSQL uses OUTPUT clause instead of RETURNING
    }

    fn supports_for_update(&self) -> bool {
        false // MSSQL uses locking hints: WITH (UPDLOCK, HOLDLOCK, ROWLOCK, etc.)
    }

    fn supports_for_update_nowait(&self) -> bool {
        false // MSSQL uses NOWAIT as a locking hint, not FOR UPDATE NOWAIT
    }

    fn supports_for_update_wait(&self) -> bool {
        false
    }

    fn is_clause_boundary_keyword(&self, word: &str) -> bool {
        // OPTION(...) query hints are currently lexed as identifiers.
        // Treat OPTION as a clause boundary so it isn't consumed as a table alias.
        // WINDOW heads the named-window clause (SQL Server 2022+); it lexes as
        // an identifier, so alias/clause scanning must stop at it explicitly.
        word.eq_ignore_ascii_case("OPTION") || word.eq_ignore_ascii_case("WINDOW")
    }

    fn supports_named_window_clause(&self) -> bool {
        true // SQL Server 2022 (compat level 160+): SELECT ... WINDOW w AS (...)
    }

    // ========================================================================
    // Lexer-Level Tokenization Rules
    // ========================================================================

    fn hash_is_line_comment(&self) -> bool {
        false // # denotes temp tables in MSSQL (#temp, ##global_temp), NOT a comment
    }

    fn supports_escape_string_literals(&self) -> bool {
        false // MSSQL doesn't have E'...' escape string prefix
    }

    fn supports_dollar_quoted_strings(&self) -> bool {
        false // MSSQL doesn't support $$...$$ dollar-quoted strings
    }

    fn dollar_number(&self) -> DollarNumber {
        DollarNumber::Money // `$100` is a money constant
    }

    // "Variables (Transact-SQL)": a variable is `@name`; `$action`,
    // `$identity` and `$rowguid` are pseudo-columns.
    fn dollar_name_is_session_variable(&self) -> bool {
        false
    }

    fn number_literal_grammar(&self) -> NumberLiteralGrammar {
        // "Constants (Transact-SQL)": a binary constant is `0x` and
        // hexadecimal digits.
        NumberLiteralGrammar {
            hexadecimal: RadixPrefix::AnyCase,
            ..NumberLiteralGrammar::DECIMAL
        }
    }

    fn supports_national_string_literals(&self) -> bool {
        true // MSSQL supports N'...' Unicode string literals
    }

    fn supports_bracket_identifiers(&self) -> bool {
        true // MSSQL uses [...] for delimited identifiers
    }

    fn supports_at_sign_identifiers(&self) -> bool {
        true // MSSQL uses @var for local variables and @@var for system variables
    }

    fn hash_is_identifier_prefix(&self) -> bool {
        true // MSSQL uses #temp for local temp tables and ##temp for global temp tables
    }
}

/// Create an MSSQL (T-SQL) dialect instance
pub fn mssql() -> DialectRef {
    Arc::new(MsSqlDialect)
}

// ============================================================================
// Amazon Redshift Dialect Implementation
// ============================================================================

/// Amazon Redshift dialect implementation.
///
/// Redshift's SQL is forked from PostgreSQL 8.0.2, so it shares PostgreSQL's
/// lexical core (double-quoted identifiers, lowercase folding, `::` casts,
/// `||` concat, `$$`-quoted procedure bodies) but diverges on the dialect
/// surface in ways that matter:
///
/// - 127-byte identifier limit (vs PostgreSQL's 63); `$` allowed in identifiers
/// - Redshift's own reserved-word list (encoding/COPY/UNLOAD vocabulary:
///   `ENCODE`, `IDENTITY`, `CREDENTIALS`, `ALLOWOVERWRITE`, `AES256`, ...)
/// - No `LATERAL`, no `DISTINCT ON`, no `RETURNING`, no `QUALIFY`,
///   no `TABLESAMPLE`, no row-level `FOR UPDATE` locking
/// - `MERGE`, `PIVOT`, `UNPIVOT`, materialized views ARE supported
/// - SUPER semi-structured access uses dot/subscript, NOT `->`/`->>` operators
/// - No `E'...'` escape strings and no backslash escapes in `'...'` (like PG)
/// - Bulk I/O via `COPY ... FROM 's3://...'` and `UNLOAD (...) TO 's3://...'`
/// - PL/pgSQL stored procedures (`CREATE PROCEDURE ... AS $$ ... $$`)
#[derive(Debug, Clone, Copy, Default)]
pub struct RedshiftDialect;

impl Dialect for RedshiftDialect {
    fn delete_from_optional(&self) -> bool {
        true
    }
    fn type_synonyms(&self) -> &'static [TypeSynonyms] {
        REDSHIFT_TYPE_SYNONYMS
    }
    fn routine_synonyms(&self) -> &'static [RoutineSynonyms] {
        REDSHIFT_ROUTINE_SYNONYMS
    }
    fn user_functions_write(&self) -> bool {
        false // a SQL, Python or Lambda UDF runs no DML
    }
    fn shown_slots(&self) -> &'static [ShownSlot] {
        REDSHIFT_SHOWN_SLOTS
    }
    fn shown_settings(&self) -> &'static [ShownSetting] {
        REDSHIFT_SHOWN_SETTINGS
    }
    fn syntax_meaning(&self) -> SyntaxMeaning {
        SyntaxMeaning {
            using_column_order: UsingColumnOrder::NotStated,
            typed_create_as: TypedCreateAs::NamesByPosition,
            shorter_column_list: ShorterColumnList::NamesTheFirst,
            database_level: DatabaseLevel::NotStated,
            temporary_tables: TemporaryTables::SessionSchema { name: None },
            cte_write_target: CteWriteTarget::NotStated,
            write_target_source: WriteTargetSource::BesideSources,
            default_search_path: DefaultSearchPath::Schemas(&["public"]),
        }
    }

    // ---- Statement grammar shape (see trait docs) ----
    // Redshift inherits PostgreSQL's utility-statement grammar shapes.
    fn supports_session_config_set(&self) -> bool {
        true // SET search_path TO ..., SET query_group TO ...
    }
    fn supports_prepared_statement_execution(&self) -> bool {
        true // PREPARE / EXECUTE / DEALLOCATE
    }
    fn supports_plpgsql_dynamic_execute(&self) -> bool {
        true // Stored procedures use PL/pgSQL: EXECUTE <expr> [INTO [STRICT] tgt] [USING …]
    }
    fn raise_severity_levels(&self) -> &'static [&'static str] {
        &["DEBUG", "LOG", "INFO", "NOTICE", "WARNING", "EXCEPTION"] // inherits PG PL/pgSQL RAISE
    }
    fn format_function_builds_sql(&self) -> bool {
        true // inherits PG format('… %I/%L …', args) SQL-template builder
    }
    fn dynamic_sql_identifier_quoting_functions(&self) -> &'static [&'static str] {
        &["quote_ident"] // inherits PG quoting builtins
    }
    fn dynamic_sql_literal_quoting_functions(&self) -> &'static [&'static str] {
        &["quote_literal", "quote_nullable"]
    }
    fn routine_language_is_sql(&self, name: &str) -> bool {
        name.eq_ignore_ascii_case("SQL") || name.eq_ignore_ascii_case("PLPGSQL")
    }
    fn supports_copy_to_from_table(&self) -> bool {
        true // COPY <table> FROM 's3://...' (PostgreSQL-shaped leading clause)
    }
    fn copy_has_inline_credentials(&self) -> bool {
        true // COPY ... FROM 's3://...' IAM_ROLE / CREDENTIALS / ACCESS_KEY_ID …
    }
    fn supports_refresh_materialized_view(&self) -> bool {
        true // REFRESH MATERIALIZED VIEW mv
    }
    fn select_into_creates_table(&self) -> bool {
        true // SELECT ... INTO new_table
    }
    fn select_into_uses_temp_keyword(&self) -> bool {
        true // SELECT ... INTO TEMP|TEMPORARY new_table
    }
    fn procedure_param_grammar(&self) -> ProcedureParamGrammar {
        // Redshift PL/pgSQL procedures: the common shape is `name TYPE`, and the
        // optional-leading-mode grammar parses that plus `[IN|OUT|INOUT] name TYPE`.
        ProcedureParamGrammar::LeadingModeOptionalName
    }
    // Redshift has no CLUSTER statement (it uses sort keys), so the inherited
    // `supports_cluster_statement()` default of `false` is correct.

    // ========================================================================
    // Core Identity
    // ========================================================================

    fn name(&self) -> &'static str {
        "redshift"
    }

    // ========================================================================
    // Keyword Rules
    // ========================================================================

    keyword_answers!(redshift_keyword);

    // ========================================================================
    // Identifier Rules
    // ========================================================================

    fn identifier_quote_char(&self) -> char {
        '"'
    }

    fn max_identifier_length(&self) -> Option<usize> {
        Some(127) // Redshift identifier limit is 127 bytes
    }

    fn unquoted_identifiers_case_sensitive(&self) -> bool {
        false // Redshift folds unquoted identifiers to lowercase (like PostgreSQL)
    }

    fn extra_identifier_chars(&self) -> &'static [char] {
        &['$'] // Redshift allows `$` (but not `#`) in standard identifiers
    }

    // ========================================================================
    // String Literal Rules
    // ========================================================================

    fn string_quote_char(&self) -> char {
        '\''
    }

    fn supports_double_quoted_strings(&self) -> bool {
        false // Redshift lexes "..." as a quoted identifier, not a string literal
    }

    fn supports_string_escapes(&self) -> bool {
        false // Redshift uses '' doubling, not C-style escapes, in standard strings
    }

    fn backslash_escapes_in_single_quoted_strings(&self) -> bool {
        false // Standard '...' literals treat backslash as an ordinary character
    }

    // ========================================================================
    // Comment Rules
    // ========================================================================

    fn supports_nested_block_comments(&self) -> bool {
        false
    }

    fn block_comment_nesting_unknown(&self) -> bool {
        true
    }

    // ========================================================================
    // Statement Support
    // ========================================================================

    fn supports_merge(&self) -> bool {
        true // Redshift added MERGE INTO
    }

    fn supports_cte(&self) -> bool {
        true // WITH ... AS, including RECURSIVE
    }

    fn supports_lateral(&self) -> bool {
        false // Redshift does not support LATERAL joins
    }

    fn supports_window_functions(&self) -> bool {
        true
    }

    fn supports_qualify(&self) -> bool {
        false // No QUALIFY clause
    }

    fn supports_sample(&self) -> bool {
        false // No SAMPLE / TABLESAMPLE
    }

    fn supports_time_travel(&self) -> bool {
        false // No AT/BEFORE time travel
    }

    fn supports_pivot(&self) -> bool {
        true // Redshift supports PIVOT
    }

    fn supports_unpivot(&self) -> bool {
        true // Redshift supports UNPIVOT
    }

    fn supports_flatten(&self) -> bool {
        false // FLATTEN is Snowflake-specific
    }

    fn supports_values_as_table(&self) -> bool {
        true
    }

    fn is_table_valued_function(&self, _name: &str) -> bool {
        false // Redshift has no UNNEST/GENERATE_SERIES table function in FROM
    }

    fn non_value_arguments(&self, function: &str) -> &'static [NonValueArgument] {
        match AsciiUpper::new(function).as_str() {
            // `CONVERT(type, expr)`
            "CONVERT" => TYPE_FIRST,
            "DATEADD" | "DATEDIFF" | "DATE_PART" | "PGDATE_PART" => PART_FIRST,
            _ => &[],
        }
    }

    fn date_part(&self, word: &str) -> Option<crate::ast::DatePart> {
        use crate::ast::DatePart;
        Some(match AsciiUpper::new(word).as_str() {
            "MIL" | "MILS" => DatePart::Millennium,
            "C" | "CENT" | "CENTS" => DatePart::Century,
            "DEC" | "DECS" => DatePart::Decade,
            "Y" | "YR" | "YRS" => DatePart::Year,
            "QTR" | "QTRS" => DatePart::Quarter,
            "MON" | "MONS" => DatePart::Month,
            "W" => DatePart::Week,
            "DOW" | "DW" => DatePart::DayOfWeek,
            "DOY" | "DY" | "YEARDAY" => DatePart::DayOfYear,
            "D" => DatePart::Day,
            "H" | "HR" | "HRS" => DatePart::Hour,
            "M" | "MIN" | "MINS" => DatePart::Minute,
            "S" | "SEC" | "SECS" => DatePart::Second,
            "MS" | "MSEC" | "MSECS" | "MSECOND" | "MSECONDS" | "MILLISEC" | "MILLISECS"
            | "MILLISECON" => DatePart::Millisecond,
            "US" | "USEC" | "USECS" | "MICROSEC" | "MICROSECS" | "USECOND" | "USECONDS" => {
                DatePart::Microsecond
            }
            _ => return DatePart::from_name(word),
        })
    }

    fn except_is_star_modifier(&self) -> bool {
        false // EXCEPT is a set operation, not a star modifier
    }

    fn supports_projection_exclude(&self) -> bool {
        true // Redshift: SELECT <list> EXCLUDE (cols) trailing the projection
    }

    fn scripting_requires_begin(&self) -> bool {
        true // PL/pgSQL stored procedures use DECLARE...BEGIN...END blocks
    }

    // ========================================================================
    // Operator Support
    // ========================================================================

    fn pipe_pipe_is_concat(&self) -> bool {
        true // || is string concatenation
    }

    fn supports_json_operators(&self) -> bool {
        false // SUPER access uses dot/subscript, not -> / ->>
    }

    fn supports_named_args_operator(&self) -> bool {
        false // No => named-argument operator
    }

    fn supports_type_cast_operator(&self) -> bool {
        true // Redshift supports :: type casting
    }

    fn supports_distinct_on(&self) -> bool {
        false // DISTINCT ON is PostgreSQL-specific
    }

    fn supports_returning(&self) -> bool {
        false // Redshift does not support RETURNING
    }

    fn supports_for_update(&self) -> bool {
        false // Redshift does not support SELECT ... FOR UPDATE row locking
    }

    fn supports_for_update_nowait(&self) -> bool {
        false
    }

    fn supports_for_update_wait(&self) -> bool {
        false
    }

    // ========================================================================
    // Lexer-Level Tokenization Rules
    // ========================================================================

    fn hash_is_line_comment(&self) -> bool {
        false // # is not a comment delimiter in Redshift
    }

    fn supports_escape_string_literals(&self) -> bool {
        false // No E'...' escape string prefix
    }

    fn supports_dollar_quoted_strings(&self) -> bool {
        true // $$...$$ procedure bodies are dollar-quoted
    }

    fn dollar_number(&self) -> DollarNumber {
        DollarNumber::Parameter // `$1` in PREPARE and in SQL UDF bodies
    }

    // "PREPARE", "CREATE FUNCTION": `$` opens a positional parameter or a
    // dollar-quoted body; no `$name` variable.
    fn dollar_name_is_session_variable(&self) -> bool {
        false
    }

    fn word_operator(&self, word: &str) -> Option<WordOperator> {
        match AsciiUpper::new(word).as_str() {
            "ISNULL" => Some(WordOperator::IsNull),
            "NOTNULL" => Some(WordOperator::NotNull),
            _ => None,
        }
    }
}

/// Create an Amazon Redshift dialect instance
pub fn redshift() -> DialectRef {
    Arc::new(RedshiftDialect)
}
