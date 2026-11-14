// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Function catalog for the Relational IR.
//!
//! Function identity in the IR is an opaque [`FunctionId`] resolved against a
//! [`FunctionCatalog`] at lowering time. The catalog carries the per-dialect
//! builtin table and workspace-scoped user-defined-function entries. All
//! semantic facts (aggregate/window/scalar kind, null-strictness, determinism,
//! argument shape) come from the catalog's [`FunctionSignature`]; downstream
//! analyses do not pattern-match on function names.
//!
//! A call whose name is not found in the catalog produces
//! [`super::ResolvedFunc::Unresolved`]; strict-IR mode rejects those via
//! [`super::OpaqueReason::UnknownFunction`]. Permissive mode treats them
//! behaviourally the same as a known [`FunctionKind::Scalar`] call — the raw
//! spelling round-trips but no aggregate / window / null-strictness inference
//! is attempted.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};

use lexega_syntax::dialect::{thread_normalization, ThreadNormalization};

use crate::ast::AstFunctionReturns;
use crate::context::node_metadata::IdentKey;

// ────────────────────────────────────────────────────────────────────────
// FunctionId
// ────────────────────────────────────────────────────────────────────────

/// Opaque handle into a [`FunctionCatalog`].
///
/// Two `FunctionId`s compare equal iff they name the same catalog entry;
/// the inner `u32` has no semantic meaning outside the catalog that
/// produced it and must not be serialized or compared across sessions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FunctionId(u32);

impl fmt::Display for FunctionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "fn#{}", self.0)
    }
}

impl FunctionId {
    /// Construct a `FunctionId` from its raw numeric value. The
    /// inverse of [`fmt::Display`] when round-tripping the
    /// `fn#<id>` placeholder — used by
    /// `derived_facts::resolve_fn_placeholder` to parse the
    /// `ResolvedFunc::display_hint()` form back into a typed id
    /// for catalog lookup.
    pub fn from_index(idx: u32) -> Self {
        FunctionId(idx)
    }
}

// ────────────────────────────────────────────────────────────────────────
// FunctionKind / Determinism / ArgShape / FunctionSignature
// ────────────────────────────────────────────────────────────────────────

/// How the function participates in query shape.
///
/// Closed enum: every analysis that branches on function shape must
/// dispatch exhaustively.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FunctionKind {
    /// Plain row-wise function (`UPPER`, `COALESCE`, `+`).
    Scalar,
    /// Aggregate (`COUNT`, `SUM`, `LISTAGG`, `PERCENTILE_CONT`).
    Aggregate,
    /// Window-only (`ROW_NUMBER`, `RANK`, `LEAD`, `LAG`).
    Window,
    /// Aggregate that also admits an `OVER(…)` clause
    /// (`COUNT(*) OVER()`, `SUM(x) OVER(…)`).
    WindowAggregate,
}

/// Determinism classification.
///
/// A `Deterministic` function always produces the same output for the
/// same input; `Volatile` does not (e.g. `CURRENT_TIMESTAMP`,
/// `RANDOM`). `Stable` is PostgreSQL's middle class — deterministic
/// within a single statement but not across statements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Determinism {
    Deterministic,
    Stable,
    Volatile,
}

/// Argument-shape summary. The catalog only distinguishes fixed
/// arity from variadic so the lowerer can issue better errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArgShape {
    /// Exact arity (positional). `arity` counts positional arguments
    /// only; named arguments ride on top of the positional list.
    Fixed { arity: u8 },
    /// Variadic with a minimum positional count.
    Variadic { min_positional: u8 },
    /// Catalog entry exists but argument shape is not yet described
    /// (common for rare functions whose calling conventions we haven't
    /// catalogued). Treated as accept-anything at the lowerer.
    Unspecified,
}

/// Full per-function signature.
///
/// Single source of truth for every per-function fact any IR
/// analysis consumes. New per-function facts MUST land as new
/// fields on this struct (and be populated at catalog seed time)
/// rather than as parallel name-keyed lists in the analysis that
/// needs them. This is the "function catalog as fact store"
/// architectural rule: analyses receive a [`FunctionId`] and
/// consult [`FunctionCatalog::signature`] for the relevant field —
/// they never reach back through the resolved id to recover the
/// raw display name and pattern-match on it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FunctionSignature {
    /// Canonical display name (normalized via [`IdentKey`] rules).
    pub display_name: String,
    /// How the function participates in query shape.
    pub kind: FunctionKind,
    /// Output null behavior under the IR's three-valued logic.
    /// See [`NullBehavior`] for the full lattice. Strictness is
    /// `null_behavior == NullBehavior::Strict`.
    pub null_behavior: NullBehavior,
    /// Determinism classification.
    pub determinism: Determinism,
    /// Argument shape summary.
    pub arg_shape: ArgShape,
    /// Window function in the ranking family: `ROW_NUMBER`,
    /// `RANK`, `DENSE_RANK`, `PERCENT_RANK`, `CUME_DIST`,
    /// `NTILE`.
    pub is_ranking: bool,
    /// Returns or operates on a temporal value: `CURRENT_DATE`,
    /// `CURRENT_TIMESTAMP`, `DATEADD`, `DATEDIFF`, `DATE_TRUNC`,
    /// `TO_DATE`, `TO_TIMESTAMP`, `NOW`, `SYSDATE`, etc. Consumed
    /// by [`is_temporal_function`].
    pub is_temporal: bool,
    /// Returns a set of rows when called in a select list, so the query
    /// yields one row per returned row: `EXPLODE`, `UNNEST`,
    /// `GENERATE_SERIES`.
    pub generates_rows: bool,
    /// Called as a table in a `FROM` clause, yields rows of one value
    /// column that has no name of its own: the alias written after the
    /// call names it (`UNNEST(arr) AS e`, `GENERATE_SERIES(1, 3) AS g`).
    /// False for a function that yields columns of its own
    /// (`JSON_EACH`, `POSEXPLODE`, `FLATTEN`), after which an alias
    /// names the table, and for one not known to yield a single value.
    pub yields_one_value: bool,
    /// What an aggregate gives over no rows, where every dialect gives
    /// the same: `None` where the catalog does not state it.
    pub over_no_rows: Option<NoRowsValue>,
    /// How many rows a table function yields for each row it reads, where
    /// the catalog states it.
    pub rows_per_input: RowsPerInput,
}

/// How many rows a table function yields for each row it reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RowsPerInput {
    /// Not stated: it may yield none, as `UNNEST` of an empty array does.
    Unknown,
    /// At least one, a row of NULLs where it has nothing else: Spark's
    /// `EXPLODE_OUTER`, `POSEXPLODE_OUTER`, `INLINE_OUTER`.
    AtLeastOne,
    /// At least one where the call's `OUTER` argument is `TRUE`: Snowflake's
    /// `FLATTEN`.
    AtLeastOneWhenOuter,
}

/// The value an aggregate gives over no rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NoRowsValue {
    /// `SUM`, `MAX`, `AVG` and the like.
    Null,
    /// `COUNT`.
    Zero,
}

/// Output null behavior of a scalar function under three-valued
/// logic.
///
/// Closed enum: every consumer that reads
/// [`FunctionSignature::null_behavior`] must dispatch
/// exhaustively.
///
/// The categories form a lattice for nullability reasoning.
/// They describe how
/// the function's output relates to its inputs' nullability — not
/// what the function "does" semantically. Two functions with very
/// different semantics can share a [`NullBehavior`] (for example
/// `UPPER` and `ABS` are both [`Strict`](NullBehavior::Strict)).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NullBehavior {
    /// Result is always non-null. Examples: `COUNT`, `COUNT_IF`,
    /// `GROUPING`, `GROUPING_ID`, `ROW_NUMBER`, `RANK`,
    /// `DENSE_RANK`, `NTILE`, `PERCENT_RANK`, `CUME_DIST`. Note
    /// these are non-null *outputs*; they may still be NULL when
    /// the surrounding expression context produces NULL (a CASE
    /// branch with a `Lit::Null` ELSE, etc.) — that's a
    /// per-expression concern, not a per-function one.
    NeverNull,
    /// NULL propagates from any argument. Examples: `UPPER`,
    /// `LOWER`, `ABS`, `LENGTH`, arithmetic operators, the
    /// majority of pure scalar functions. The output is null iff
    /// any positional argument is null.
    Strict,
    /// Result is null iff *every* argument is null. Examples:
    /// `COALESCE`, `NVL`, `IFNULL`, `ISNULL`, `ZEROIFNULL`. The
    /// canonical "first non-null wins" family.
    CoalesceLike,
    /// Result is null iff every argument from index 1 onward is null;
    /// the first argument is a condition: the second is returned where
    /// it is true, the third where it is false or NULL. Examples: `IFF`,
    /// `IIF`, `IF`.
    BranchOnCondition,
    /// Result is null iff every argument from index 1 onward is null;
    /// the first argument is tested for NULL: the second is returned
    /// where it is not NULL, the third where it is. Example: `NVL2`.
    BranchOnNotNull,
    /// Result is null iff every argument is null, and is otherwise one of
    /// the arguments that is not, chosen by value: no argument is a
    /// default the others fall back to. Example: `GREATEST` and `LEAST`
    /// where a dialect skips their NULL arguments. Read as
    /// [`Unknown`](NullBehavior::Unknown) where an argument would be read
    /// as a default the others fall back to.
    NullOnlyWhenAllNull,
    /// Output null behavior is not classified. The conservative
    /// answer "may be null" is returned by every consumer.
    /// Default for catalog entries that have not been classified
    /// yet (most aggregates, dialect-specific scalars where the
    /// semantics aren't worth the effort to encode).
    Unknown,
}

// ────────────────────────────────────────────────────────────────────────
// FunctionCatalog
// ────────────────────────────────────────────────────────────────────────

/// True iff `func` is a temporal function according to the catalog.
///
/// Returns `false` for unresolved calls — the catalog can't vouch
/// for them, so the conservative answer is "no temporal influence."
pub fn is_temporal_function(func: &super::plan::ResolvedFunc, catalog: &FunctionCatalog) -> bool {
    match func {
        super::plan::ResolvedFunc::Resolved { id, .. } => catalog
            .signature(*id)
            .map(|s| s.is_temporal)
            .unwrap_or(false),
        super::plan::ResolvedFunc::Unresolved { .. } => false,
    }
}

/// True iff the catalog-declared data type is temporal (date/time
/// related): matches `TIMESTAMP*`, `DATE*`, `TIME`.
pub fn is_temporal_data_type(data_type: &str) -> bool {
    let upper = data_type.to_uppercase();
    upper.starts_with("TIMESTAMP") || upper.starts_with("DATE") || upper == "TIME"
}

/// Per-session function catalog.
///
/// The catalog owns a flat vector of signatures and a name → id lookup
/// table. [`FunctionId`] values it hands out are indices into the
/// signature vector; the types are decoupled so the lookup table can
/// carry aliases without duplicating signature storage.
///
/// A catalog is typically constructed once per lowering session via
/// [`FunctionCatalog::for_dialect`] and threaded through
/// `LowerCtx` as a shared reference.
#[derive(Debug, Clone)]
pub struct FunctionCatalog {
    /// Signature storage, indexed by [`FunctionId`]'s inner value.
    signatures: Vec<FunctionSignature>,
    /// Name lookup. Keys are [`IdentKey`]-normalized display names so
    /// Snowflake-style unquoted-uppercase rules apply by default.
    by_name: HashMap<IdentKey, FunctionId>,
    /// The columns a call of the function, as a table in a `FROM` clause,
    /// yields under the catalog's dialect, for each function whose
    /// columns the dialect names.
    yielded: HashMap<FunctionId, YieldedColumns>,
    /// Whether the dialect names the one value column of a call written
    /// with no alias after the function ([`FunctionSignature::yields_one_value`]).
    value_named_for_function: bool,
    /// The volatile functions whose every call in one statement returns
    /// one value: the current time, read once per statement.
    statement_stable: HashSet<FunctionId>,
    /// The functions the dialect documents as written with no parentheses,
    /// and how a bare word of that name reads against the columns in scope.
    bare_values: HashMap<FunctionId, BareValue>,
    /// Whether a bare word of `bare_values` is the function in the values
    /// and conditions of a script. Snowflake Scripting requires the
    /// parentheses there.
    bare_values_in_scripts: bool,
    /// What the script declares each function it defines returns, by the
    /// name it is written with, keyed as `by_name` is.
    declared: HashMap<IdentKey, AstFunctionReturns>,
    /// What some arguments of a call of the function are under the
    /// catalog's dialect, by its name, keyed as `by_name` is: a call the
    /// catalog does not resolve is met by the name it is written with.
    argument_roles: HashMap<IdentKey, ArgumentRoles>,
    /// The functions the dialect defines that `by_name` holds no signature
    /// of, by name, keyed as `by_name` is.
    builtin_names: HashSet<IdentKey>,
}

/// What some arguments of a call are, beside the values they hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ArgumentRoles {
    /// Each argument from the `from`th, counting from 0, names a key of or
    /// a path into the document the first argument is: `GET_PATH(v,
    /// 'a.b')`, `JSON_VALUE(j, '$.a')`, `json_extract_path_text(j, 'a',
    /// 'b')`; from the first, the setting or the session value the call
    /// reads (`current_setting('app.key')`).
    Path { from: usize },
    /// From the `from`th argument on, a key and the value it is given, in
    /// turn: `OBJECT_CONSTRUCT('k', v, …)`, `OBJECT_INSERT(o, 'k', v)`.
    KeyValuePairs { from: usize },
    /// From the `from`th argument on, a path into the document the first
    /// argument is and the value set at it, in turn: `JSON_SET(j, '$.k',
    /// v)`, `jsonb_set(j, '{k}', v)`. The path's last key names the value.
    PathValuePairs { from: usize },
}

/// The columns a table function yields, by name, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct YieldedColumns {
    pub(crate) names: &'static [&'static str],
    /// Whether `names` are every column a call yields, whatever its
    /// arguments.
    pub(crate) complete: bool,
}

impl FunctionCatalog {
    /// Empty catalog. Every lookup returns `None`; every call becomes
    /// [`super::ResolvedFunc::Unresolved`]. Useful for tests that
    /// don't care about catalog-backed analysis.
    pub fn empty() -> Self {
        Self {
            signatures: Vec::new(),
            by_name: HashMap::new(),
            yielded: HashMap::new(),
            value_named_for_function: false,
            statement_stable: HashSet::new(),
            bare_values: HashMap::new(),
            bare_values_in_scripts: true,
            declared: HashMap::new(),
            argument_roles: HashMap::new(),
            builtin_names: HashSet::new(),
        }
    }

    /// Build the catalog for a dialect: the seed, with what the seed's
    /// per-dialect table states for that dialect. Every dialect's catalog
    /// holds the same functions under the same [`FunctionId`]s; only what
    /// a signature says differs.
    /// The seeding covers aggregate and window-only functions across all
    /// dialects we target; scalar functions mostly remain
    /// [`super::ResolvedFunc::Unresolved`] and behave as plain scalar
    /// calls at permissive mode.
    pub fn for_dialect(dialect: CatalogDialect) -> Self {
        let mut catalog = Self::empty();
        seed_aggregates(&mut catalog);
        seed_window_only(&mut catalog);
        seed_common_scalars(&mut catalog);
        for restatement in DIALECT_SIGNATURES {
            if restatement.dialect == dialect {
                catalog.restate(restatement.function, restatement.states);
            }
        }
        for row in YIELDED_COLUMNS {
            if row.dialect == dialect {
                if let Some(id) = catalog.lookup(row.function) {
                    catalog.yielded.insert(id, row.columns);
                }
            }
        }
        catalog.seed_bare_values(dialect);
        catalog.bare_values_in_scripts = dialect != CatalogDialect::Snowflake;
        for row in ARGUMENT_ROLES {
            if row.dialects.contains(&dialect) || dialect == CatalogDialect::Default {
                catalog
                    .argument_roles
                    .insert(IdentKey::new(row.function), row.roles);
            }
        }
        catalog.value_named_for_function = value_named_for_function(dialect);
        let listed: &[&[&str]] = match dialect {
            CatalogDialect::Snowflake => &[
                SNOWFLAKE_BUILTIN_TABLE_FUNCTIONS,
                SNOWFLAKE_BUILTIN_FUNCTIONS,
            ],
            CatalogDialect::PostgreSql => &[POSTGRES_BUILTIN_FUNCTIONS, POSTGRES_ADMIN_FUNCTIONS],
            CatalogDialect::BigQuery => &[BIGQUERY_BUILTIN_FUNCTIONS],
            CatalogDialect::MsSql => &[MSSQL_BUILTIN_FUNCTIONS],
            CatalogDialect::Databricks => &[DATABRICKS_BUILTIN_FUNCTIONS],
            CatalogDialect::Redshift => &[POSTGRES_BUILTIN_FUNCTIONS, REDSHIFT_BUILTIN_FUNCTIONS],
            CatalogDialect::MySql | CatalogDialect::Default => &[],
        };
        for names in listed {
            catalog
                .builtin_names
                .extend(names.iter().map(|name| IdentKey::new(name)));
        }
        if dialect == CatalogDialect::MySql {
            catalog.builtin_names.extend(
                MYSQL_BUILTIN_FUNCTIONS
                    .iter()
                    .map(|name| IdentKey::new(name)),
            );
        }
        catalog
    }

    /// The catalog of the functions `dialect` defines and nothing else (no
    /// routine a script defines), built once per dialect for the process.
    pub(crate) fn dialect_defined(dialect: CatalogDialect) -> &'static FunctionCatalog {
        static CATALOGS: [std::sync::OnceLock<FunctionCatalog>; 8] =
            [const { std::sync::OnceLock::new() }; 8];
        let at = match dialect {
            CatalogDialect::Default => 0,
            CatalogDialect::Snowflake => 1,
            CatalogDialect::BigQuery => 2,
            CatalogDialect::PostgreSql => 3,
            CatalogDialect::Databricks => 4,
            CatalogDialect::MySql => 5,
            CatalogDialect::MsSql => 6,
            CatalogDialect::Redshift => 7,
        };
        CATALOGS[at].get_or_init(|| FunctionCatalog::for_dialect(dialect))
    }

    /// Whether the function whose name, folded as a routine's name is,
    /// is `name` is one the dialect defines: the catalog holds its
    /// signature, or knows it by name alone.
    pub fn is_builtin(&self, name: &IdentKey) -> bool {
        self.by_name.contains_key(name) || self.builtin_names.contains(name)
    }

    /// What some arguments of a call of `func` are under the catalog's
    /// dialect, where it states it.
    pub(crate) fn argument_roles(&self, func: &super::plan::ResolvedFunc) -> Option<ArgumentRoles> {
        let name = match func {
            super::plan::ResolvedFunc::Resolved { id, .. } => &self.signature(*id)?.display_name,
            super::plan::ResolvedFunc::Unresolved { raw_name, .. } => raw_name,
        };
        self.argument_roles.get(&IdentKey::new(name)).copied()
    }

    /// The columns a call of `id`, as a table in a `FROM` clause, yields
    /// under the catalog's dialect, where the dialect names them.
    pub(crate) fn yielded_columns(&self, id: FunctionId) -> Option<YieldedColumns> {
        self.yielded.get(&id).copied()
    }

    /// Whether the dialect names the one value column of a call written
    /// with no alias after the function: PostgreSQL's `unnest(a)` yields a
    /// column `unnest`.
    pub(crate) fn names_value_for_function(&self) -> bool {
        self.value_named_for_function
    }

    /// Whether every call of `id` in one statement returns one value,
    /// though the catalog marks the function volatile.
    pub(crate) fn is_statement_stable(&self, id: FunctionId) -> bool {
        self.statement_stable.contains(&id)
    }

    /// The function a bare, unquoted `name` is under the catalog's dialect,
    /// and how it reads against the columns in scope: `None` for a word the
    /// dialect documents only with parentheses, which is a column bare.
    pub(crate) fn bare_value(&self, name: &str) -> Option<(FunctionId, BareValue)> {
        let id = self.lookup(name)?;
        Some((id, *self.bare_values.get(&id)?))
    }

    /// Whether a bare word the dialect documents as a function is that
    /// function in the values and conditions of a script.
    pub(crate) fn reads_bare_values_in_scripts(&self) -> bool {
        self.bare_values_in_scripts
    }

    /// Record the bare functions of `dialect`. `Default` takes every word
    /// any dialect documents, as the function whatever the columns are
    /// where one dialect says so.
    fn seed_bare_values(&mut self, dialect: CatalogDialect) {
        for row in BARE_VALUES {
            if dialect != CatalogDialect::Default && row.dialect != dialect {
                continue;
            }
            for function in row.functions {
                let Some(id) = self.lookup(function) else {
                    continue;
                };
                let value = match self.bare_values.get(&id) {
                    Some(BareValue::Always) => BareValue::Always,
                    Some(BareValue::UnlessColumn) | None => row.value,
                };
                self.bare_values.insert(id, value);
            }
        }
    }

    /// Change what the signature registered under `function` says. A name
    /// the seed does not hold changes nothing; the table's rows are tested
    /// to name seeded functions.
    fn restate(&mut self, function: &str, states: SignatureChange) {
        let Some(signature) = self
            .by_name
            .get(&IdentKey::new(function))
            .and_then(|id| self.signatures.get_mut(id.0 as usize))
        else {
            return;
        };
        match states {
            SignatureChange::GeneratesRows(generates_rows) => {
                signature.generates_rows = generates_rows;
            }
            SignatureChange::YieldsOneValue(yields_one_value) => {
                signature.yields_one_value = yields_one_value;
            }
            SignatureChange::NullBehavior(null_behavior) => {
                signature.null_behavior = null_behavior;
            }
        }
    }

    /// Register one signature under its [`FunctionSignature::display_name`].
    /// Returns the newly allocated [`FunctionId`]. If the name is
    /// already registered, the existing id is returned unchanged — the
    /// catalog is append-only to keep `FunctionId` values stable.
    pub fn register(&mut self, sig: FunctionSignature) -> FunctionId {
        let key = IdentKey::new(&sig.display_name);
        if let Some(existing) = self.by_name.get(&key) {
            return *existing;
        }
        let id = FunctionId(
            u32::try_from(self.signatures.len())
                .expect("function catalog overflow: more than u32::MAX entries is not supported"),
        );
        self.signatures.push(sig);
        self.by_name.insert(key, id);
        id
    }

    /// Register a name alias pointing at an already-registered id.
    /// Aliases share the same signature; different names in source
    /// text will resolve to the same [`FunctionId`] and thus the same
    /// behavior. No-op when the alias already maps to `target`;
    /// panics when it maps to a *different* id, to flag a catalog
    /// construction bug early.
    pub fn alias(&mut self, alias: &str, target: FunctionId) {
        let key = IdentKey::new(alias);
        match self.by_name.get(&key) {
            Some(existing) if *existing == target => {}
            Some(existing) => panic!(
                "catalog alias {alias:?} already registered to a different id ({existing} vs {target})"
            ),
            None => {
                self.by_name.insert(key, target);
            }
        }
    }

    /// Look up a function by its source-text spelling. The spelling
    /// is normalized via [`IdentKey`] before lookup.
    pub fn lookup(&self, name: &str) -> Option<FunctionId> {
        self.by_name.get(&IdentKey::new(name)).copied()
    }

    /// Records that the script declares the function named `name` to
    /// return `returns`; the later of two declarations of one name replaces
    /// the earlier. A name the catalog resolves is not recorded: its
    /// signature stays.
    pub fn declare(&mut self, name: &str, returns: AstFunctionReturns) {
        if self.lookup(name).is_none() {
            self.declared.insert(IdentKey::new(name), returns);
        }
    }

    /// What the script declares the function a call written `name` returns;
    /// `None` for a name it does not declare. The name is met as written:
    /// a declaration of `s.f` is not met by `f`. A catalog holding no
    /// declaration answers without folding the name.
    pub fn declared_returns(&self, name: &str) -> Option<AstFunctionReturns> {
        if self.declared.is_empty() {
            return None;
        }
        self.declared.get(&IdentKey::new(name)).copied()
    }

    /// Retrieve the signature for a previously-issued id. Returns
    /// `None` only when the id was forged (not produced by this
    /// catalog's [`register`](Self::register) or [`lookup`](Self::lookup)).
    pub fn signature(&self, id: FunctionId) -> Option<&FunctionSignature> {
        self.signatures.get(id.0 as usize)
    }

    /// Convenience accessor: the [`FunctionKind`] of a resolved id.
    /// Returns `None` for forged ids; see [`signature`](Self::signature).
    pub fn kind(&self, id: FunctionId) -> Option<FunctionKind> {
        self.signatures.get(id.0 as usize).map(|s| s.kind)
    }

    /// Whether a resolved id is an aggregate or window-aggregate.
    /// Returns `false` for forged ids (conservative: an unknown id
    /// does not promote to aggregate shape).
    pub fn is_aggregate_shape(&self, id: FunctionId) -> bool {
        matches!(
            self.kind(id),
            Some(FunctionKind::Aggregate) | Some(FunctionKind::WindowAggregate)
        )
    }

    /// Whether a resolved id supports an `OVER(…)` clause. Returns
    /// `false` for forged ids.
    pub fn is_window_shape(&self, id: FunctionId) -> bool {
        matches!(
            self.kind(id),
            Some(FunctionKind::Window) | Some(FunctionKind::WindowAggregate)
        )
    }
}

/// The function catalog in force at each statement of one script: the
/// dialect's, with each function a top-level statement of the script
/// defines, declared from the start of that statement on.
#[derive(Debug, Clone)]
pub struct ScriptFunctions {
    /// The dialect's catalog: in force before the first declaration.
    dialect: Arc<FunctionCatalog>,
    /// From each declaring statement's start, ascending, the catalog with
    /// every declaration up to it.
    declared: Vec<(u32, FunctionCatalog)>,
}

impl ScriptFunctions {
    /// The catalogs of the script `fold` was folded over, for `dialect`.
    pub fn new(dialect: CatalogDialect, fold: &crate::ScriptContextFold) -> Self {
        Self::over(Arc::new(FunctionCatalog::for_dialect(dialect)), fold)
    }

    /// [`Self::new`] with the dialect's catalog `catalogs` holds, built
    /// there once for every script analysed with them.
    pub fn from_catalogs(
        catalogs: &DialectCatalogs,
        dialect: CatalogDialect,
        fold: &crate::ScriptContextFold,
    ) -> Self {
        Self::over(catalogs.for_dialect(dialect), fold)
    }

    fn over(dialect: Arc<FunctionCatalog>, fold: &crate::ScriptContextFold) -> Self {
        let mut declared: Vec<(u32, FunctionCatalog)> = Vec::new();
        for (position, name, returns) in fold.declared_functions() {
            let mut catalog = declared
                .last()
                .map_or_else(|| (*dialect).clone(), |(_, last)| last.clone());
            catalog.declare(name, *returns);
            declared.push((*position, catalog));
        }
        Self { dialect, declared }
    }

    /// The catalog of the statement starting at `position`.
    pub fn at(&self, position: u32) -> &FunctionCatalog {
        let in_force = self.declared.partition_point(|(from, _)| *from <= position);
        self.declared[..in_force]
            .last()
            .map_or(&*self.dialect, |(_, catalog)| catalog)
    }
}

/// The dialects' function catalogs, each built on first use and shared
/// by every clone. One value in
/// [`AnalysisConfig::function_catalogs`](crate::analyzer::AnalysisConfig::function_catalogs),
/// cloned into the configuration of each file of a run, has the run
/// build each catalog once.
///
/// A catalog keys names as the thread's identifier folding does when it
/// is built, so one is kept per dialect and folding.
#[derive(Debug, Clone, Default)]
pub struct DialectCatalogs {
    built: Arc<Mutex<Vec<DialectCatalog>>>,
}

/// One built catalog: the dialect and the folding it was built for.
type DialectCatalog = (
    CatalogDialect,
    Option<ThreadNormalization>,
    Arc<FunctionCatalog>,
);

impl DialectCatalogs {
    /// The catalog of `dialect` under the thread's folding.
    pub fn for_dialect(&self, dialect: CatalogDialect) -> Arc<FunctionCatalog> {
        let folding = thread_normalization();
        // A thread that panicked while holding the lock left the list
        // whole: an entry is pushed only once its catalog is built.
        let mut built = self.built.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((_, _, catalog)) = built
            .iter()
            .find(|(of, under, _)| *of == dialect && *under == folding)
        {
            return Arc::clone(catalog);
        }
        let catalog = Arc::new(FunctionCatalog::for_dialect(dialect));
        built.push((dialect, folding, Arc::clone(&catalog)));
        catalog
    }
}

/// The functions of PostgreSQL's `pg_catalog` a script calls by name that
/// the catalog holds no signature of (PostgreSQL documentation, "Functions
/// and Operators"), and those of common extensions that write no table.
const POSTGRES_BUILTIN_FUNCTIONS: &[&str] = &[
    // Strings and binary strings.
    "ascii",
    "bit_length",
    "btrim",
    "char_length",
    "character_length",
    "chr",
    "concat_ws",
    "convert",
    "convert_from",
    "convert_to",
    "decode",
    "encode",
    "format",
    "initcap",
    "left",
    "lpad",
    "md5",
    "normalize",
    "octet_length",
    "overlay",
    "position",
    "quote_ident",
    "quote_literal",
    "quote_nullable",
    "regexp_match",
    "regexp_matches",
    "regexp_split_to_array",
    "regexp_split_to_table",
    "repeat",
    "right",
    "rpad",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    "starts_with",
    "string_to_array",
    "string_to_table",
    "strpos",
    "to_ascii",
    "to_hex",
    "translate",
    "unistr",
    "get_byte",
    "set_byte",
    "get_bit",
    "set_bit",
    // Numbers.
    "cbrt",
    "degrees",
    "div",
    "exp",
    "factorial",
    "gcd",
    "lcm",
    "ln",
    "log",
    "log10",
    "pi",
    "power",
    "pow",
    "radians",
    "scale",
    "sqrt",
    "width_bucket",
    "setseed",
    "acos",
    "asin",
    "atan",
    "atan2",
    "cos",
    "cot",
    "sin",
    "tan",
    "num_nulls",
    "num_nonnulls",
    // Formatting, dates and times.
    "to_number",
    "age",
    "clock_timestamp",
    "date_bin",
    "date_part",
    "date_subtract",
    "isfinite",
    "justify_days",
    "justify_hours",
    "justify_interval",
    "make_date",
    "make_interval",
    "make_time",
    "make_timestamp",
    "make_timestamptz",
    "statement_timestamp",
    "timeofday",
    "transaction_timestamp",
    "timezone",
    // JSON.
    "to_jsonb",
    "array_to_json",
    "row_to_json",
    "json_build_array",
    "jsonb_build_array",
    "json_build_object",
    "jsonb_build_object",
    "json_object",
    "jsonb_object",
    "json_array_length",
    "jsonb_array_length",
    "json_each",
    "jsonb_each",
    "json_each_text",
    "jsonb_each_text",
    "json_extract_path",
    "jsonb_extract_path",
    "json_extract_path_text",
    "jsonb_extract_path_text",
    "json_object_keys",
    "jsonb_object_keys",
    "json_populate_record",
    "jsonb_populate_record",
    "json_populate_recordset",
    "jsonb_populate_recordset",
    "json_array_elements",
    "jsonb_array_elements",
    "json_array_elements_text",
    "jsonb_array_elements_text",
    "json_typeof",
    "jsonb_typeof",
    "json_strip_nulls",
    "jsonb_strip_nulls",
    "jsonb_set",
    "jsonb_set_lax",
    "jsonb_insert",
    "jsonb_pretty",
    "jsonb_path_exists",
    "jsonb_path_match",
    "jsonb_path_query",
    "jsonb_path_query_array",
    "jsonb_path_query_first",
    "json_to_record",
    "jsonb_to_record",
    "json_to_recordset",
    "jsonb_to_recordset",
    // Arrays and series.
    "array_dims",
    "array_fill",
    "array_length",
    "array_lower",
    "array_ndims",
    "array_positions",
    "array_remove",
    "array_replace",
    "array_to_string",
    "array_upper",
    "cardinality",
    "trim_array",
    "unnest",
    "generate_series",
    "generate_subscripts",
    // Sequences.
    "nextval",
    "currval",
    "lastval",
    "setval",
    // Session and catalog information.
    "current_database",
    "current_schemas",
    "current_setting",
    "inet_client_addr",
    "inet_server_addr",
    "version",
    "pg_backend_pid",
    "txid_current",
    "pg_current_xact_id",
    "has_table_privilege",
    "has_schema_privilege",
    "has_database_privilege",
    "has_column_privilege",
    "has_function_privilege",
    "has_sequence_privilege",
    "pg_has_role",
    "pg_typeof",
    "format_type",
    "to_regclass",
    "to_regproc",
    "to_regtype",
    "obj_description",
    "col_description",
    "pg_get_viewdef",
    "pg_get_functiondef",
    "pg_get_constraintdef",
    "pg_get_indexdef",
    "pg_table_size",
    "pg_total_relation_size",
    "pg_relation_size",
    "pg_indexes_size",
    "pg_size_pretty",
    "pg_database_size",
    "pg_column_size",
    "pg_table_is_visible",
    "pg_postmaster_start_time",
    // Administration.
    "pg_sleep",
    "pg_sleep_for",
    "pg_cancel_backend",
    "pg_terminate_backend",
    "pg_reload_conf",
    "pg_read_file",
    "pg_read_binary_file",
    "pg_ls_dir",
    "pg_stat_file",
    "lo_import",
    "lo_export",
    "lo_unlink",
    "pg_advisory_lock",
    "pg_advisory_unlock",
    "pg_try_advisory_lock",
    "pg_advisory_xact_lock",
    // Text search and network addresses.
    "to_tsvector",
    "to_tsquery",
    "plainto_tsquery",
    "phraseto_tsquery",
    "websearch_to_tsquery",
    "ts_rank",
    "ts_rank_cd",
    "ts_headline",
    "setweight",
    "host",
    "netmask",
    "network",
    "family",
    "masklen",
    "broadcast",
    "abbrev",
    // Settings, notifications, row constructors and XML.
    "set_config",
    "pg_notify",
    "row",
    "xmlelement",
    "xmlforest",
    "xmlattributes",
    "xmlconcat",
    "xmlparse",
    "xmlserialize",
    "xmlagg",
    "xpath",
    "xpath_exists",
    "xmlcomment",
    "xmlpi",
    "xmlroot",
    "xmlexists",
    "xml_is_well_formed",
    "xml_is_well_formed_document",
    "xml_is_well_formed_content",
    // JSON aggregates and constructors.
    "json_agg",
    "json_agg_strict",
    "jsonb_agg_strict",
    "json_object_agg",
    "json_object_agg_strict",
    "jsonb_object_agg_strict",
    "json_object_agg_unique",
    "jsonb_object_agg_unique",
    "json_object_agg_unique_strict",
    "jsonb_object_agg_unique_strict",
    "json_scalar",
    "json_serialize",
    "jsonb_path_exists_tz",
    "jsonb_path_match_tz",
    "jsonb_path_query_tz",
    "jsonb_path_query_array_tz",
    "jsonb_path_query_first_tz",
    // Mathematics.
    "min_scale",
    "trim_scale",
    "random_normal",
    "acosd",
    "asind",
    "atand",
    "atan2d",
    "cosd",
    "cotd",
    "sind",
    "tand",
    "sinh",
    "cosh",
    "tanh",
    "asinh",
    "acosh",
    "atanh",
    // Strings, bits and enums.
    "parse_ident",
    "pg_client_encoding",
    "bit_count",
    "enum_first",
    "enum_last",
    "enum_range",
    // Geometry and network addresses.
    "area",
    "center",
    "diameter",
    "height",
    "width",
    "isclosed",
    "isopen",
    "npoints",
    "pclose",
    "popen",
    "radius",
    "slope",
    "bound_box",
    "hostmask",
    "inet_merge",
    "inet_same_family",
    "set_masklen",
    "macaddr8_set7bit",
    // Text search.
    "array_to_tsvector",
    "get_current_ts_config",
    "numnode",
    "querytree",
    "strip",
    "json_to_tsvector",
    "jsonb_to_tsvector",
    "ts_delete",
    "ts_filter",
    "ts_rewrite",
    "tsquery_phrase",
    "tsvector_to_array",
    "ts_debug",
    "ts_lexize",
    "ts_parse",
    "ts_token_type",
    // UUIDs, arrays and ranges.
    "uuid_in",
    "uuid_extract_timestamp",
    "uuid_extract_version",
    "array_sample",
    "array_shuffle",
    "isempty",
    "lower_inc",
    "upper_inc",
    "lower_inf",
    "upper_inf",
    "range_merge",
    "range_agg",
    "range_intersect_agg",
    "int4range",
    "int8range",
    "numrange",
    "tsrange",
    "tstzrange",
    "daterange",
    "int4multirange",
    "int8multirange",
    "nummultirange",
    "tsmultirange",
    "tstzmultirange",
    "datemultirange",
    // Session, transaction and catalog information.
    "current_query",
    "inet_client_port",
    "inet_server_port",
    "pg_conf_load_time",
    "pg_current_logfile",
    "pg_my_temp_schema",
    "pg_is_other_temp_schema",
    "pg_jit_available",
    "pg_listening_channels",
    "pg_notification_queue_usage",
    "pg_trigger_depth",
    "pg_blocking_pids",
    "pg_safe_snapshot_blocking_pids",
    "pg_get_userbyid",
    "pg_get_triggerdef",
    "pg_get_ruledef",
    "pg_get_keywords",
    "pg_get_expr",
    "pg_get_partkeydef",
    "pg_get_statisticsobjdef",
    "pg_get_serial_sequence",
    "pg_get_function_arguments",
    "pg_get_function_identity_arguments",
    "pg_get_function_result",
    "pg_xact_status",
    "pg_current_snapshot",
    "pg_snapshot_xmin",
    "pg_snapshot_xmax",
    "pg_snapshot_xip",
    "pg_visible_in_snapshot",
    "txid_current_snapshot",
    "txid_snapshot_xmin",
    "txid_snapshot_xmax",
    "txid_snapshot_xip",
    "txid_visible_in_snapshot",
    "txid_status",
    "pg_tablespace_size",
    "pg_tablespace_location",
    "pg_relation_filenode",
    "pg_relation_filepath",
    "pg_filenode_relation",
    "pg_partition_root",
    "pg_partition_tree",
    "pg_partition_ancestors",
    "pg_function_is_visible",
    "pg_type_is_visible",
    // Recovery, write-ahead log and statistics.
    "pg_is_in_recovery",
    "pg_current_wal_lsn",
    "pg_current_wal_insert_lsn",
    "pg_current_wal_flush_lsn",
    "pg_walfile_name",
    "pg_wal_lsn_diff",
    "pg_last_wal_receive_lsn",
    "pg_last_wal_replay_lsn",
    "pg_last_xact_replay_timestamp",
    "pg_export_snapshot",
    "pg_sleep_until",
    "pg_stat_reset",
    "pg_stat_reset_shared",
    "pg_stat_reset_single_table_counters",
    "pg_stat_reset_single_function_counters",
    "pg_stat_reset_slru",
    "pg_stat_get_numscans",
    "pg_stat_get_tuples_inserted",
    "pg_stat_get_tuples_updated",
    "pg_stat_get_tuples_deleted",
    "pg_stat_get_live_tuples",
    "pg_stat_get_dead_tuples",
    // The common extensions' functions, which write no table: uuid-ossp
    // and pgcrypto (shipped with PostgreSQL), and PostGIS.
    "uuid_generate_v1",
    "uuid_generate_v1mc",
    "uuid_generate_v3",
    "uuid_generate_v4",
    "uuid_generate_v5",
    "uuid_nil",
    "uuid_ns_dns",
    "uuid_ns_url",
    "uuid_ns_oid",
    "uuid_ns_x500",
    "digest",
    "hmac",
    "crypt",
    "gen_salt",
    "gen_random_bytes",
    "encrypt",
    "decrypt",
    "encrypt_iv",
    "decrypt_iv",
    "pgp_sym_encrypt",
    "pgp_sym_encrypt_bytea",
    "pgp_sym_decrypt",
    "pgp_sym_decrypt_bytea",
    "pgp_pub_encrypt",
    "pgp_pub_encrypt_bytea",
    "pgp_pub_decrypt",
    "pgp_pub_decrypt_bytea",
    "pgp_key_id",
    "armor",
    "dearmor",
    "pgp_armor_headers",
    "postgis_version",
    "postgis_full_version",
    "geometrytype",
    "box2d",
    "box3d",
    "st_3ddistance",
    "st_3dintersects",
    "st_area",
    "st_asbinary",
    "st_asewkb",
    "st_asewkt",
    "st_asgeojson",
    "st_asgml",
    "st_askml",
    "st_asmvt",
    "st_asmvtgeom",
    "st_assvg",
    "st_astext",
    "st_astwkb",
    "st_azimuth",
    "st_boundary",
    "st_buffer",
    "st_buildarea",
    "st_centroid",
    "st_chaikinsmoothing",
    "st_closestpoint",
    "st_clusterdbscan",
    "st_clusterkmeans",
    "st_collect",
    "st_collectionextract",
    "st_concavehull",
    "st_contains",
    "st_containsproperly",
    "st_convexhull",
    "st_coorddim",
    "st_coveredby",
    "st_covers",
    "st_crosses",
    "st_delaunaytriangles",
    "st_difference",
    "st_dimension",
    "st_disjoint",
    "st_distance",
    "st_distancesphere",
    "st_distancespheroid",
    "st_dump",
    "st_dumppoints",
    "st_dumprings",
    "st_dwithin",
    "st_endpoint",
    "st_envelope",
    "st_equals",
    "st_estimatedextent",
    "st_expand",
    "st_extent",
    "st_exteriorring",
    "st_force2d",
    "st_force3d",
    "st_forcerhr",
    "st_frechetdistance",
    "st_generatepoints",
    "st_geogfromtext",
    "st_geogfromwkb",
    "st_geographyfromtext",
    "st_geohash",
    "st_geometryfromtext",
    "st_geometryn",
    "st_geometrytype",
    "st_geomfromewkb",
    "st_geomfromewkt",
    "st_geomfromgeojson",
    "st_geomfromgml",
    "st_geomfromkml",
    "st_geomfromtext",
    "st_geomfromwkb",
    "st_hasarc",
    "st_hausdorffdistance",
    "st_interiorringn",
    "st_intersection",
    "st_intersects",
    "st_isclosed",
    "st_isempty",
    "st_isring",
    "st_issimple",
    "st_isvalid",
    "st_isvalidreason",
    "st_length",
    "st_length2d",
    "st_linefromtext",
    "st_lineinterpolatepoint",
    "st_linelocatepoint",
    "st_linemerge",
    "st_linesubstring",
    "st_longestline",
    "st_m",
    "st_makeenvelope",
    "st_makeline",
    "st_makepoint",
    "st_makepointm",
    "st_makepolygon",
    "st_makevalid",
    "st_maxdistance",
    "st_memunion",
    "st_multi",
    "st_ndims",
    "st_npoints",
    "st_nrings",
    "st_numgeometries",
    "st_numinteriorrings",
    "st_numpoints",
    "st_offsetcurve",
    "st_orderingequals",
    "st_overlaps",
    "st_perimeter",
    "st_point",
    "st_pointfromtext",
    "st_pointn",
    "st_pointonsurface",
    "st_polygon",
    "st_polygonize",
    "st_project",
    "st_relate",
    "st_reverse",
    "st_rotate",
    "st_scale",
    "st_segmentize",
    "st_setsrid",
    "st_shortestline",
    "st_simplify",
    "st_simplifypreservetopology",
    "st_snaptogrid",
    "st_split",
    "st_srid",
    "st_startpoint",
    "st_subdivide",
    "st_summary",
    "st_symdifference",
    "st_tileenvelope",
    "st_touches",
    "st_transform",
    "st_translate",
    "st_unaryunion",
    "st_union",
    "st_voronoipolygons",
    "st_within",
    "st_wkbtosql",
    "st_wkttosql",
    "st_x",
    "st_xmax",
    "st_xmin",
    "st_y",
    "st_ymax",
    "st_ymin",
    "st_z",
    "st_zmax",
    "st_zmin",
    // The contrib modules shipped with PostgreSQL whose functions write no
    // table: pg_trgm, fuzzystrmatch, unaccent, hstore, citext, ltree,
    // tablefunc, cube and earthdistance.
    "similarity",
    "show_trgm",
    "word_similarity",
    "strict_word_similarity",
    "show_limit",
    "set_limit",
    "soundex",
    "difference",
    "levenshtein",
    "levenshtein_less_equal",
    "metaphone",
    "dmetaphone",
    "dmetaphone_alt",
    "daitch_mokotoff",
    "unaccent",
    "hstore",
    "akeys",
    "avals",
    "skeys",
    "svals",
    "hstore_to_array",
    "hstore_to_matrix",
    "hstore_to_json",
    "hstore_to_jsonb",
    "hstore_to_json_loose",
    "hstore_to_jsonb_loose",
    "slice",
    "exist",
    "defined",
    "delete",
    "citext",
    "subltree",
    "subpath",
    "nlevel",
    "index",
    "text2ltree",
    "ltree2text",
    "lca",
    "normal_rand",
    "crosstab",
    "crosstab2",
    "crosstab3",
    "crosstab4",
    "connectby",
    "cube",
    "cube_dim",
    "cube_ll_coord",
    "cube_ur_coord",
    "cube_is_point",
    "cube_distance",
    "cube_subset",
    "cube_union",
    "cube_inter",
    "cube_enlarge",
    "cube_size",
    "earth",
    "earth_distance",
    "ll_to_earth",
    "latitude",
    "longitude",
    "earth_box",
    "gc_to_sec",
    "sec_to_gc",
    // Advisory locks, which lock no table and write none.
    "pg_advisory_lock_shared",
    "pg_advisory_unlock_shared",
    "pg_advisory_unlock_all",
    "pg_advisory_xact_lock_shared",
    "pg_try_advisory_lock_shared",
    "pg_try_advisory_xact_lock",
    "pg_try_advisory_xact_lock_shared",
    // Input validation, backend cancel / terminate and config reload, backup
    // and recovery control, replication slots and origins, collations, index
    // maintenance and server files.
    "pg_input_is_valid",
    "pg_input_error_info",
    "pg_log_backend_memory_contexts",
    "pg_rotate_logfile",
    "pg_create_restore_point",
    "pg_backup_start",
    "pg_backup_stop",
    "pg_switch_wal",
    "pg_walfile_name_offset",
    "pg_split_walfile_name",
    "pg_is_wal_replay_paused",
    "pg_get_wal_replay_pause_state",
    "pg_promote",
    "pg_wal_replay_pause",
    "pg_wal_replay_resume",
    "pg_log_standby_snapshot",
    "pg_create_physical_replication_slot",
    "pg_create_logical_replication_slot",
    "pg_drop_replication_slot",
    "pg_copy_physical_replication_slot",
    "pg_copy_logical_replication_slot",
    "pg_logical_slot_get_changes",
    "pg_logical_slot_peek_changes",
    "pg_logical_slot_get_binary_changes",
    "pg_logical_slot_peek_binary_changes",
    "pg_replication_slot_advance",
    "pg_sync_replication_slots",
    "pg_replication_origin_create",
    "pg_replication_origin_drop",
    "pg_replication_origin_oid",
    "pg_replication_origin_session_setup",
    "pg_replication_origin_session_reset",
    "pg_replication_origin_session_is_setup",
    "pg_replication_origin_session_progress",
    "pg_replication_origin_xact_setup",
    "pg_replication_origin_xact_reset",
    "pg_replication_origin_advance",
    "pg_replication_origin_progress",
    "pg_logical_emit_message",
    "pg_column_compression",
    "pg_column_toast_chunk_id",
    "pg_size_bytes",
    "pg_collation_actual_version",
    "pg_database_collation_actual_version",
    "pg_import_system_collations",
    "brin_summarize_new_values",
    "brin_summarize_range",
    "brin_desummarize_range",
    "gin_clean_pending_list",
    "pg_ls_logdir",
    "pg_ls_waldir",
    "pg_ls_logicalmapdir",
    "pg_ls_logicalsnapdir",
    "pg_ls_replslotdir",
    "pg_ls_archive_statusdir",
    "pg_ls_tmpdir",
    // The contrib modules intarray, pgstattuple, pg_prewarm and
    // pg_stat_statements.
    "icount",
    "sort",
    "sort_asc",
    "sort_desc",
    "uniq",
    "idx",
    "subarray",
    "intset",
    "pgstattuple",
    "pgstattuple_approx",
    "pgstatindex",
    "pgstatginindex",
    "pgstathashindex",
    "pg_relpages",
    "pg_prewarm",
    "autoprewarm_start_worker",
    "autoprewarm_dump_now",
    "pg_stat_statements",
    "pg_stat_statements_info",
    "pg_stat_statements_reset",
];

/// The functions MySQL 8 defines that the catalog holds no signature of
/// (MySQL 8.0 Reference Manual, "Built-In Function and Operator
/// Reference"). None writes a table.
const MYSQL_BUILTIN_FUNCTIONS: &[&str] = &[
    // Control flow, comparison and casts.
    "if",
    "ifnull",
    "nullif",
    "coalesce",
    "greatest",
    "least",
    "interval",
    "isnull",
    "strcmp",
    "cast",
    "convert",
    // Dates and times.
    "adddate",
    "addtime",
    "convert_tz",
    "curdate",
    "current_date",
    "current_time",
    "current_timestamp",
    "curtime",
    "date",
    "date_add",
    "date_format",
    "date_sub",
    "datediff",
    "day",
    "dayname",
    "dayofmonth",
    "dayofweek",
    "dayofyear",
    "extract",
    "from_days",
    "from_unixtime",
    "get_format",
    "hour",
    "last_day",
    "localtime",
    "localtimestamp",
    "makedate",
    "maketime",
    "microsecond",
    "minute",
    "month",
    "monthname",
    "now",
    "period_add",
    "period_diff",
    "quarter",
    "sec_to_time",
    "second",
    "str_to_date",
    "subdate",
    "subtime",
    "sysdate",
    "time",
    "time_format",
    "time_to_sec",
    "timediff",
    "timestamp",
    "timestampadd",
    "timestampdiff",
    "to_days",
    "to_seconds",
    "unix_timestamp",
    "utc_date",
    "utc_time",
    "utc_timestamp",
    "week",
    "weekday",
    "weekofyear",
    "year",
    "yearweek",
    // Strings.
    "ascii",
    "bin",
    "bit_length",
    "char",
    "char_length",
    "character_length",
    "concat",
    "concat_ws",
    "elt",
    "export_set",
    "field",
    "find_in_set",
    "format",
    "from_base64",
    "hex",
    "insert",
    "instr",
    "lcase",
    "left",
    "length",
    "load_file",
    "locate",
    "lower",
    "lpad",
    "ltrim",
    "make_set",
    "match",
    "mid",
    "oct",
    "octet_length",
    "ord",
    "position",
    "quote",
    "regexp_instr",
    "regexp_like",
    "regexp_replace",
    "regexp_substr",
    "repeat",
    "replace",
    "reverse",
    "right",
    "rpad",
    "rtrim",
    "soundex",
    "space",
    "substr",
    "substring",
    "substring_index",
    "to_base64",
    "trim",
    "ucase",
    "unhex",
    "upper",
    "weight_string",
    // Numbers and bits.
    "abs",
    "acos",
    "asin",
    "atan",
    "atan2",
    "bit_count",
    "ceil",
    "ceiling",
    "conv",
    "cos",
    "cot",
    "crc32",
    "degrees",
    "exp",
    "floor",
    "ln",
    "log",
    "log10",
    "log2",
    "mod",
    "pi",
    "pow",
    "power",
    "radians",
    "rand",
    "round",
    "sign",
    "sin",
    "sqrt",
    "tan",
    "truncate",
    // Aggregates and windows.
    "any_value",
    "avg",
    "bit_and",
    "bit_or",
    "bit_xor",
    "count",
    "group_concat",
    "grouping",
    "json_arrayagg",
    "json_objectagg",
    "max",
    "min",
    "std",
    "stddev",
    "stddev_pop",
    "stddev_samp",
    "sum",
    "var_pop",
    "var_samp",
    "variance",
    "cume_dist",
    "dense_rank",
    "first_value",
    "lag",
    "last_value",
    "lead",
    "nth_value",
    "ntile",
    "percent_rank",
    "rank",
    "row_number",
    // Encryption and compression.
    "aes_decrypt",
    "aes_encrypt",
    "compress",
    "md5",
    "random_bytes",
    "sha",
    "sha1",
    "sha2",
    "statement_digest",
    "statement_digest_text",
    "uncompress",
    "uncompressed_length",
    "validate_password_strength",
    // Information.
    "benchmark",
    "charset",
    "coercibility",
    "collation",
    "connection_id",
    "current_role",
    "current_user",
    "database",
    "found_rows",
    "icu_version",
    "last_insert_id",
    "roles_graphml",
    "row_count",
    "schema",
    "session_user",
    "system_user",
    "user",
    "version",
    // JSON.
    "json_array",
    "json_array_append",
    "json_array_insert",
    "json_contains",
    "json_contains_path",
    "json_depth",
    "json_extract",
    "json_insert",
    "json_keys",
    "json_length",
    "json_merge",
    "json_merge_patch",
    "json_merge_preserve",
    "json_object",
    "json_overlaps",
    "json_pretty",
    "json_quote",
    "json_remove",
    "json_replace",
    "json_schema_valid",
    "json_schema_validation_report",
    "json_search",
    "json_set",
    "json_storage_free",
    "json_storage_size",
    "json_table",
    "json_type",
    "json_unquote",
    "json_valid",
    "json_value",
    // Locks, addresses, UUIDs and the rest.
    "get_lock",
    "is_free_lock",
    "is_used_lock",
    "release_all_locks",
    "release_lock",
    "bin_to_uuid",
    "default",
    "inet_aton",
    "inet_ntoa",
    "inet6_aton",
    "inet6_ntoa",
    "is_ipv4",
    "is_ipv4_compat",
    "is_ipv4_mapped",
    "is_ipv6",
    "is_uuid",
    "name_const",
    "sleep",
    "uuid",
    "uuid_short",
    "uuid_to_bin",
    "values",
    "format_bytes",
    "format_pico_time",
    "ps_current_thread_id",
    "ps_thread_id",
    "gtid_subset",
    "gtid_subtract",
    "source_pos_wait",
    "master_pos_wait",
    "wait_for_executed_gtid_set",
    // Spatial.
    "geomcollection",
    "geometrycollection",
    "linestring",
    "multilinestring",
    "multipoint",
    "multipolygon",
    "point",
    "polygon",
    "mbrcontains",
    "mbrcoveredby",
    "mbrcovers",
    "mbrdisjoint",
    "mbrequals",
    "mbrintersects",
    "mbroverlaps",
    "mbrtouches",
    "mbrwithin",
    "st_area",
    "st_asbinary",
    "st_asgeojson",
    "st_astext",
    "st_aswkb",
    "st_aswkt",
    "st_buffer",
    "st_buffer_strategy",
    "st_centroid",
    "st_collect",
    "st_contains",
    "st_convexhull",
    "st_crosses",
    "st_difference",
    "st_dimension",
    "st_disjoint",
    "st_distance",
    "st_distance_sphere",
    "st_endpoint",
    "st_envelope",
    "st_equals",
    "st_exteriorring",
    "st_frechetdistance",
    "st_geohash",
    "st_geomcollfromtext",
    "st_geomcollfromwkb",
    "st_geometryn",
    "st_geometrytype",
    "st_geomfromgeojson",
    "st_geomfromtext",
    "st_geomfromwkb",
    "st_hausdorffdistance",
    "st_interiorringn",
    "st_intersection",
    "st_intersects",
    "st_isclosed",
    "st_isempty",
    "st_issimple",
    "st_isvalid",
    "st_latfromgeohash",
    "st_latitude",
    "st_length",
    "st_linefromtext",
    "st_linefromwkb",
    "st_lineinterpolatepoint",
    "st_lineinterpolatepoints",
    "st_longfromgeohash",
    "st_longitude",
    "st_makeenvelope",
    "st_mlinefromtext",
    "st_mlinefromwkb",
    "st_mpointfromtext",
    "st_mpointfromwkb",
    "st_mpolyfromtext",
    "st_mpolyfromwkb",
    "st_numgeometries",
    "st_numinteriorring",
    "st_numinteriorrings",
    "st_numpoints",
    "st_overlaps",
    "st_pointatdistance",
    "st_pointfromgeohash",
    "st_pointfromtext",
    "st_pointfromwkb",
    "st_pointn",
    "st_polyfromtext",
    "st_polyfromwkb",
    "st_simplify",
    "st_srid",
    "st_startpoint",
    "st_swapxy",
    "st_symdifference",
    "st_touches",
    "st_transform",
    "st_union",
    "st_validate",
    "st_within",
    "st_x",
    "st_y",
];

/// Snowflake's scalar, aggregate and window functions, by the names its
/// SQL function reference gives them. The hash functions of each list are
/// left out: what they hash may be a secret, so no argument of theirs is
/// shown as a built-in's is.
const SNOWFLAKE_BUILTIN_FUNCTIONS: &[&str] = &[
    "ABS",
    "ACOS",
    "ACOSH",
    "ADD_MONTHS",
    "ALL_USER_NAMES",
    "ANY_VALUE",
    "APPROX_COUNT_DISTINCT",
    "APPROX_PERCENTILE",
    "APPROX_TOP_K",
    "ARRAYAGG",
    "ARRAYS_OVERLAP",
    "ARRAYS_TO_OBJECT",
    "ARRAY_AGG",
    "ARRAY_APPEND",
    "ARRAY_CAT",
    "ARRAY_COMPACT",
    "ARRAY_CONSTRUCT",
    "ARRAY_CONSTRUCT_COMPACT",
    "ARRAY_CONTAINS",
    "ARRAY_DISTINCT",
    "ARRAY_EXCEPT",
    "ARRAY_FLATTEN",
    "ARRAY_GENERATE_RANGE",
    "ARRAY_INSERT",
    "ARRAY_INTERSECTION",
    "ARRAY_MAX",
    "ARRAY_MIN",
    "ARRAY_POSITION",
    "ARRAY_PREPEND",
    "ARRAY_REMOVE",
    "ARRAY_REMOVE_AT",
    "ARRAY_SIZE",
    "ARRAY_SLICE",
    "ARRAY_SORT",
    "ARRAY_TO_STRING",
    "ARRAY_UNION_AGG",
    "ARRAY_UNIQUE_AGG",
    "ASCII",
    "ASIN",
    "ASINH",
    "AS_ARRAY",
    "AS_BINARY",
    "AS_BOOLEAN",
    "AS_CHAR",
    "AS_DATE",
    "AS_DECIMAL",
    "AS_DOUBLE",
    "AS_INTEGER",
    "AS_NUMBER",
    "AS_OBJECT",
    "AS_REAL",
    "AS_TIME",
    "AS_TIMESTAMP_LTZ",
    "AS_TIMESTAMP_NTZ",
    "AS_TIMESTAMP_TZ",
    "AS_VARCHAR",
    "ATAN",
    "ATAN2",
    "ATANH",
    "AVG",
    "BASE64_DECODE_BINARY",
    "BASE64_DECODE_STRING",
    "BASE64_ENCODE",
    "BETWEEN",
    "BITAND",
    "BITAND_AGG",
    "BITNOT",
    "BITOR",
    "BITOR_AGG",
    "BITSHIFTLEFT",
    "BITSHIFTRIGHT",
    "BITXOR",
    "BITXOR_AGG",
    "BIT_LENGTH",
    "BOOLAND",
    "BOOLAND_AGG",
    "BOOLNOT",
    "BOOLOR",
    "BOOLOR_AGG",
    "BOOLXOR",
    "BOOLXOR_AGG",
    "CASE",
    "CAST",
    "CBRT",
    "CEIL",
    "CEILING",
    "CHAR",
    "CHARINDEX",
    "CHECK_JSON",
    "CHECK_XML",
    "CHR",
    "COALESCE",
    "COLLATE",
    "COLLATION",
    "COMPRESS",
    "CONCAT",
    "CONCAT_WS",
    "CONDITIONAL_CHANGE_EVENT",
    "CONDITIONAL_TRUE_EVENT",
    "CONTAINS",
    "CONVERT_TIMEZONE",
    "CORR",
    "COS",
    "COSH",
    "COT",
    "COUNT",
    "COUNT_IF",
    "COVAR_POP",
    "COVAR_SAMP",
    "CUME_DIST",
    "CURRENT_ACCOUNT",
    "CURRENT_CLIENT",
    "CURRENT_DATABASE",
    "CURRENT_DATE",
    "CURRENT_REGION",
    "CURRENT_ROLE",
    "CURRENT_SCHEMA",
    "CURRENT_SCHEMAS",
    "CURRENT_SESSION",
    "CURRENT_STATEMENT",
    "CURRENT_TIME",
    "CURRENT_TIMESTAMP",
    "CURRENT_TRANSACTION",
    "CURRENT_USER",
    "CURRENT_VERSION",
    "CURRENT_WAREHOUSE",
    "DATE",
    "DATEADD",
    "DATEDIFF",
    "DATEFROMPARTS",
    "DATE_FROM_PARTS",
    "DATE_PART",
    "DATE_TRUNC",
    "DAY",
    "DAYNAME",
    "DAYOFMONTH",
    "DAYOFWEEK",
    "DAYOFWEEKISO",
    "DAYOFYEAR",
    "DECODE",
    "DECOMPRESS_BINARY",
    "DECOMPRESS_STRING",
    "DEGREES",
    "DENSE_RANK",
    "DIV0",
    "DIV0NULL",
    "EDITDISTANCE",
    "ENDSWITH",
    "EQUAL_NULL",
    "EXP",
    "EXTRACT",
    "FACTORIAL",
    "FIRST_VALUE",
    "FLATTEN",
    "FLOOR",
    "GENERATOR",
    "GET",
    "GETBIT",
    "GETDATE",
    "GETVARIABLE",
    "GET_DDL",
    "GET_IGNORE_CASE",
    "GET_PATH",
    "GREATEST",
    "GREATEST_IGNORE_NULLS",
    "GROUPING",
    "GROUPING_ID",
    "HAVERSINE",
    "HEX_DECODE_BINARY",
    "HEX_DECODE_STRING",
    "HEX_ENCODE",
    "HOUR",
    "IFF",
    "IFNULL",
    "ILIKE",
    "INITCAP",
    "INSERT",
    "IS_ARRAY",
    "IS_BINARY",
    "IS_BOOLEAN",
    "IS_CHAR",
    "IS_DATE",
    "IS_DECIMAL",
    "IS_DOUBLE",
    "IS_INTEGER",
    "IS_NULL_VALUE",
    "IS_OBJECT",
    "IS_REAL",
    "IS_ROLE_IN_SESSION",
    "IS_TIME",
    "IS_TIMESTAMP_LTZ",
    "IS_TIMESTAMP_NTZ",
    "IS_TIMESTAMP_TZ",
    "IS_VARCHAR",
    "KURTOSIS",
    "LAG",
    "LAST_DAY",
    "LAST_VALUE",
    "LEAD",
    "LEAST",
    "LEFT",
    "LEN",
    "LENGTH",
    "LIKE",
    "LISTAGG",
    "LN",
    "LOCALTIME",
    "LOCALTIMESTAMP",
    "LOG",
    "LOWER",
    "LPAD",
    "LTRIM",
    "MAX",
    "MAX_BY",
    "MEDIAN",
    "MIN",
    "MINUTE",
    "MIN_BY",
    "MOD",
    "MODE",
    "MONTH",
    "MONTHNAME",
    "MONTHS_BETWEEN",
    "NEXT_DAY",
    "NORMAL",
    "NTH_VALUE",
    "NTILE",
    "NULLIF",
    "NULLIFZERO",
    "NVL",
    "NVL2",
    "OBJECT_AGG",
    "OBJECT_CONSTRUCT",
    "OBJECT_CONSTRUCT_KEEP_NULL",
    "OBJECT_DELETE",
    "OBJECT_INSERT",
    "OBJECT_KEYS",
    "OBJECT_PICK",
    "OCTET_LENGTH",
    "PARSE_IP",
    "PARSE_JSON",
    "PARSE_URL",
    "PARSE_XML",
    "PERCENTILE_CONT",
    "PERCENTILE_DISC",
    "PERCENT_RANK",
    "PI",
    "POSITION",
    "POW",
    "POWER",
    "PREVIOUS_DAY",
    "QUARTER",
    "RADIANS",
    "RANDOM",
    "RANDSTR",
    "RANK",
    "RATIO_TO_REPORT",
    "REGEXP",
    "REGEXP_COUNT",
    "REGEXP_INSTR",
    "REGEXP_LIKE",
    "REGEXP_REPLACE",
    "REGEXP_SUBSTR",
    "REGEXP_SUBSTR_ALL",
    "REGR_AVGX",
    "REGR_AVGY",
    "REGR_COUNT",
    "REGR_INTERCEPT",
    "REGR_R2",
    "REGR_SLOPE",
    "REGR_SXX",
    "REGR_SXY",
    "REGR_SYY",
    "REPEAT",
    "REPLACE",
    "REVERSE",
    "RIGHT",
    "RLIKE",
    "ROUND",
    "ROW_NUMBER",
    "RPAD",
    "RTRIM",
    "RTRIMMED_LENGTH",
    "SECOND",
    "SEQ1",
    "SEQ2",
    "SEQ4",
    "SEQ8",
    "SIGN",
    "SIN",
    "SINH",
    "SKEW",
    "SOUNDEX",
    "SPACE",
    "SPLIT",
    "SPLIT_PART",
    "SPLIT_TO_TABLE",
    "SQRT",
    "SQUARE",
    "STARTSWITH",
    "STDDEV",
    "STDDEV_POP",
    "STDDEV_SAMP",
    "STRIP_NULL_VALUE",
    "STRTOK",
    "STRTOK_SPLIT_TO_TABLE",
    "STRTOK_TO_ARRAY",
    "ST_ASTEXT",
    "ST_DISTANCE",
    "ST_MAKEPOINT",
    "ST_POINT",
    "SUBSTR",
    "SUBSTRING",
    "SUM",
    "SYSDATE",
    "SYSTIMESTAMP",
    "TAN",
    "TANH",
    "TIMEADD",
    "TIMEDIFF",
    "TIMEFROMPARTS",
    "TIMESTAMPADD",
    "TIMESTAMPDIFF",
    "TIMESTAMPFROMPARTS",
    "TIMESTAMP_FROM_PARTS",
    "TIMESTAMP_LTZ_FROM_PARTS",
    "TIMESTAMP_NTZ_FROM_PARTS",
    "TIMESTAMP_TZ_FROM_PARTS",
    "TIME_FROM_PARTS",
    "TIME_SLICE",
    "TO_ARRAY",
    "TO_BINARY",
    "TO_BOOLEAN",
    "TO_CHAR",
    "TO_DATE",
    "TO_DECIMAL",
    "TO_DOUBLE",
    "TO_GEOGRAPHY",
    "TO_JSON",
    "TO_NUMBER",
    "TO_NUMERIC",
    "TO_OBJECT",
    "TO_TIME",
    "TO_TIMESTAMP",
    "TO_TIMESTAMP_LTZ",
    "TO_TIMESTAMP_NTZ",
    "TO_TIMESTAMP_TZ",
    "TO_VARCHAR",
    "TO_VARIANT",
    "TO_XML",
    "TRANSLATE",
    "TRIM",
    "TRUNC",
    "TRUNCATE",
    "TRY_BASE64_DECODE_BINARY",
    "TRY_BASE64_DECODE_STRING",
    "TRY_CAST",
    "TRY_HEX_DECODE_BINARY",
    "TRY_HEX_DECODE_STRING",
    "TRY_PARSE_JSON",
    "TRY_TO_BINARY",
    "TRY_TO_BOOLEAN",
    "TRY_TO_DATE",
    "TRY_TO_DECIMAL",
    "TRY_TO_DOUBLE",
    "TRY_TO_NUMBER",
    "TRY_TO_NUMERIC",
    "TRY_TO_TIME",
    "TRY_TO_TIMESTAMP",
    "TRY_TO_TIMESTAMP_LTZ",
    "TRY_TO_TIMESTAMP_NTZ",
    "TRY_TO_TIMESTAMP_TZ",
    "TYPEOF",
    "UNICODE",
    "UNIFORM",
    "UPPER",
    "UUID_STRING",
    "VARIANCE",
    "VARIANCE_POP",
    "VARIANCE_SAMP",
    "VAR_POP",
    "VAR_SAMP",
    "WEEK",
    "WEEKISO",
    "WEEKOFYEAR",
    "WIDTH_BUCKET",
    "XMLGET",
    "YEAR",
    "YEAROFWEEK",
    "YEAROFWEEKISO",
    "ZEROIFNULL",
    "ZIPF",
];

/// BigQuery's functions, by the names its function reference gives them.
const BIGQUERY_BUILTIN_FUNCTIONS: &[&str] = &[
    "ABS",
    "ACOS",
    "ACOSH",
    "ANY_VALUE",
    "APPROX_COUNT_DISTINCT",
    "APPROX_QUANTILES",
    "APPROX_TOP_COUNT",
    "APPROX_TOP_SUM",
    "ARRAY",
    "ARRAY_AGG",
    "ARRAY_CONCAT",
    "ARRAY_CONCAT_AGG",
    "ARRAY_LENGTH",
    "ARRAY_REVERSE",
    "ARRAY_TO_STRING",
    "ASCII",
    "ASIN",
    "ASINH",
    "ATAN",
    "ATAN2",
    "ATANH",
    "AVG",
    "BIT_AND",
    "BIT_COUNT",
    "BIT_OR",
    "BIT_XOR",
    "BYTE_LENGTH",
    "CAST",
    "CBRT",
    "CEIL",
    "CEILING",
    "CHARACTER_LENGTH",
    "CHAR_LENGTH",
    "CHR",
    "COALESCE",
    "CODE_POINTS_TO_BYTES",
    "CODE_POINTS_TO_STRING",
    "COLLATE",
    "CONCAT",
    "CONTAINS_SUBSTR",
    "CORR",
    "COS",
    "COSH",
    "COT",
    "COUNT",
    "COUNTIF",
    "COVAR_POP",
    "COVAR_SAMP",
    "CUME_DIST",
    "CURRENT_DATE",
    "CURRENT_DATETIME",
    "CURRENT_TIME",
    "CURRENT_TIMESTAMP",
    "DATE",
    "DATETIME",
    "DATETIME_ADD",
    "DATETIME_DIFF",
    "DATETIME_SUB",
    "DATETIME_TRUNC",
    "DATE_ADD",
    "DATE_BUCKET",
    "DATE_DIFF",
    "DATE_FROM_UNIX_DATE",
    "DATE_SUB",
    "DATE_TRUNC",
    "DENSE_RANK",
    "DIV",
    "ENDS_WITH",
    "EXP",
    "EXTRACT",
    "FIRST_VALUE",
    "FLOOR",
    "FORMAT",
    "FORMAT_DATE",
    "FORMAT_DATETIME",
    "FORMAT_TIME",
    "FORMAT_TIMESTAMP",
    "FROM_BASE32",
    "FROM_BASE64",
    "FROM_HEX",
    "GENERATE_ARRAY",
    "GENERATE_DATE_ARRAY",
    "GENERATE_TIMESTAMP_ARRAY",
    "GENERATE_UUID",
    "GREATEST",
    "HLL_COUNT_EXTRACT",
    "HLL_COUNT_INIT",
    "HLL_COUNT_MERGE",
    "IEEE_DIVIDE",
    "IF",
    "IFNULL",
    "INITCAP",
    "INSTR",
    "IS_INF",
    "IS_NAN",
    "JSON_ARRAY",
    "JSON_ARRAY_APPEND",
    "JSON_ARRAY_INSERT",
    "JSON_EXTRACT",
    "JSON_EXTRACT_ARRAY",
    "JSON_EXTRACT_SCALAR",
    "JSON_EXTRACT_STRING_ARRAY",
    "JSON_OBJECT",
    "JSON_QUERY",
    "JSON_QUERY_ARRAY",
    "JSON_REMOVE",
    "JSON_SET",
    "JSON_STRIP_NULLS",
    "JSON_TYPE",
    "JSON_VALUE",
    "JSON_VALUE_ARRAY",
    "LAG",
    "LAST_DAY",
    "LAST_VALUE",
    "LAX_BOOL",
    "LAX_FLOAT64",
    "LAX_INT64",
    "LAX_STRING",
    "LEAD",
    "LEAST",
    "LEFT",
    "LENGTH",
    "LN",
    "LOG",
    "LOG10",
    "LOGICAL_AND",
    "LOGICAL_OR",
    "LOWER",
    "LPAD",
    "LTRIM",
    "MAX",
    "MAX_BY",
    "MIN",
    "MIN_BY",
    "MOD",
    "NET_HOST",
    "NET_IP_FROM_STRING",
    "NET_PUBLIC_SUFFIX",
    "NET_REG_DOMAIN",
    "NORMALIZE",
    "NORMALIZE_AND_CASEFOLD",
    "NTH_VALUE",
    "NTILE",
    "NULLIF",
    "OCTET_LENGTH",
    "PARSE_BIGNUMERIC",
    "PARSE_DATE",
    "PARSE_DATETIME",
    "PARSE_JSON",
    "PARSE_NUMERIC",
    "PARSE_TIME",
    "PARSE_TIMESTAMP",
    "PERCENTILE_CONT",
    "PERCENTILE_DISC",
    "PERCENT_RANK",
    "POW",
    "POWER",
    "RAND",
    "RANGE_BUCKET",
    "RANK",
    "REGEXP_CONTAINS",
    "REGEXP_EXTRACT",
    "REGEXP_EXTRACT_ALL",
    "REGEXP_INSTR",
    "REGEXP_REPLACE",
    "REGEXP_SUBSTR",
    "REPEAT",
    "REPLACE",
    "REVERSE",
    "RIGHT",
    "ROUND",
    "ROW_NUMBER",
    "RPAD",
    "RTRIM",
    "SAFE_ADD",
    "SAFE_CAST",
    "SAFE_CONVERT_BYTES_TO_STRING",
    "SAFE_DIVIDE",
    "SAFE_MULTIPLY",
    "SAFE_NEGATE",
    "SAFE_SUBTRACT",
    "SESSION_USER",
    "SIGN",
    "SIN",
    "SINH",
    "SOUNDEX",
    "SPLIT",
    "SQRT",
    "STARTS_WITH",
    "STDDEV",
    "STDDEV_POP",
    "STDDEV_SAMP",
    "STRING",
    "STRING_AGG",
    "STRPOS",
    "STRUCT",
    "ST_ASTEXT",
    "ST_DISTANCE",
    "ST_GEOGFROMTEXT",
    "ST_GEOGPOINT",
    "ST_X",
    "ST_Y",
    "SUBSTR",
    "SUBSTRING",
    "SUM",
    "TAN",
    "TANH",
    "TIME",
    "TIMESTAMP",
    "TIMESTAMP_ADD",
    "TIMESTAMP_DIFF",
    "TIMESTAMP_MICROS",
    "TIMESTAMP_MILLIS",
    "TIMESTAMP_SECONDS",
    "TIMESTAMP_SUB",
    "TIMESTAMP_TRUNC",
    "TIME_ADD",
    "TIME_DIFF",
    "TIME_SUB",
    "TIME_TRUNC",
    "TO_BASE32",
    "TO_BASE64",
    "TO_CODE_POINTS",
    "TO_HEX",
    "TO_JSON",
    "TO_JSON_STRING",
    "TRANSLATE",
    "TRIM",
    "TRUNC",
    "UNICODE",
    "UNIX_DATE",
    "UNIX_MICROS",
    "UNIX_MILLIS",
    "UNIX_SECONDS",
    "UNNEST",
    "UPPER",
    "VARIANCE",
    "VAR_POP",
    "VAR_SAMP",
];

/// SQL Server's functions, by the names its function reference gives them.
const MSSQL_BUILTIN_FUNCTIONS: &[&str] = &[
    "ABS",
    "ACOS",
    "APPROX_COUNT_DISTINCT",
    "APP_NAME",
    "ASCII",
    "ASIN",
    "ATAN",
    "ATN2",
    "AVG",
    "CAST",
    "CEILING",
    "CHAR",
    "CHARINDEX",
    "CHOOSE",
    "COALESCE",
    "COLUMNPROPERTY",
    "COL_LENGTH",
    "COL_NAME",
    "COMPRESS",
    "CONCAT",
    "CONCAT_WS",
    "CONVERT",
    "COS",
    "COT",
    "COUNT",
    "COUNT_BIG",
    "CUME_DIST",
    "CURRENT_TIMESTAMP",
    "CURRENT_USER",
    "DATALENGTH",
    "DATEADD",
    "DATEDIFF",
    "DATEDIFF_BIG",
    "DATEFROMPARTS",
    "DATENAME",
    "DATEPART",
    "DATETIME2FROMPARTS",
    "DATETIMEFROMPARTS",
    "DATETIMEOFFSETFROMPARTS",
    "DATETRUNC",
    "DATE_BUCKET",
    "DAY",
    "DB_ID",
    "DB_NAME",
    "DECOMPRESS",
    "DEGREES",
    "DENSE_RANK",
    "DIFFERENCE",
    "EOMONTH",
    "ERROR_LINE",
    "ERROR_MESSAGE",
    "ERROR_NUMBER",
    "ERROR_PROCEDURE",
    "ERROR_SEVERITY",
    "ERROR_STATE",
    "EXP",
    "FIRST_VALUE",
    "FLOOR",
    "FORMAT",
    "FORMATMESSAGE",
    "GENERATE_SERIES",
    "GETDATE",
    "GETUTCDATE",
    "GREATEST",
    "GROUPING",
    "GROUPING_ID",
    "HOST_NAME",
    "IDENT_CURRENT",
    "IIF",
    "ISDATE",
    "ISJSON",
    "ISNULL",
    "ISNUMERIC",
    "JSON_ARRAY",
    "JSON_MODIFY",
    "JSON_OBJECT",
    "JSON_QUERY",
    "JSON_VALUE",
    "LAG",
    "LAST_VALUE",
    "LEAD",
    "LEAST",
    "LEFT",
    "LEN",
    "LOG",
    "LOG10",
    "LOWER",
    "LTRIM",
    "MAX",
    "MIN",
    "MONTH",
    "NCHAR",
    "NEWID",
    "NEWSEQUENTIALID",
    "NTILE",
    "NULLIF",
    "OBJECT_ID",
    "OBJECT_NAME",
    "OBJECT_SCHEMA_NAME",
    "OPENJSON",
    "PARSE",
    "PARSENAME",
    "PATINDEX",
    "PERCENTILE_CONT",
    "PERCENTILE_DISC",
    "PERCENT_RANK",
    "PI",
    "POWER",
    "QUOTENAME",
    "RADIANS",
    "RAND",
    "RANK",
    "REPLACE",
    "REPLICATE",
    "REVERSE",
    "RIGHT",
    "ROUND",
    "ROWCOUNT_BIG",
    "ROW_NUMBER",
    "RTRIM",
    "SCHEMA_ID",
    "SCHEMA_NAME",
    "SCOPE_IDENTITY",
    "SIGN",
    "SIN",
    "SMALLDATETIMEFROMPARTS",
    "SOUNDEX",
    "SPACE",
    "SQRT",
    "SQUARE",
    "STDEV",
    "STDEVP",
    "STR",
    "STRING_AGG",
    "STRING_ESCAPE",
    "STRING_SPLIT",
    "STUFF",
    "SUBSTRING",
    "SUM",
    "SUSER_NAME",
    "SUSER_SNAME",
    "SWITCHOFFSET",
    "SYSDATETIME",
    "SYSDATETIMEOFFSET",
    "SYSTEM_USER",
    "SYSUTCDATETIME",
    "TAN",
    "TIMEFROMPARTS",
    "TODATETIMEOFFSET",
    "TRANSLATE",
    "TRIM",
    "TRY_CAST",
    "TRY_CONVERT",
    "TRY_PARSE",
    "TYPE_ID",
    "TYPE_NAME",
    "UNICODE",
    "UPPER",
    "USER_ID",
    "USER_NAME",
    "VAR",
    "VARP",
    "YEAR",
];

/// Databricks' functions, by the names its built-in function reference
/// gives them.
const DATABRICKS_BUILTIN_FUNCTIONS: &[&str] = &[
    "ABS",
    "ACOS",
    "ACOSH",
    "ADD_MONTHS",
    "AGGREGATE",
    "ANY",
    "ANY_VALUE",
    "APPROX_COUNT_DISTINCT",
    "APPROX_PERCENTILE",
    "ARRAY",
    "ARRAYS_OVERLAP",
    "ARRAYS_ZIP",
    "ARRAY_AGG",
    "ARRAY_APPEND",
    "ARRAY_COMPACT",
    "ARRAY_CONTAINS",
    "ARRAY_DISTINCT",
    "ARRAY_EXCEPT",
    "ARRAY_INTERSECT",
    "ARRAY_JOIN",
    "ARRAY_MAX",
    "ARRAY_MIN",
    "ARRAY_POSITION",
    "ARRAY_REMOVE",
    "ARRAY_REPEAT",
    "ARRAY_SIZE",
    "ARRAY_SORT",
    "ARRAY_UNION",
    "ASCII",
    "ASIN",
    "ASINH",
    "ATAN",
    "ATAN2",
    "ATANH",
    "AVG",
    "BASE64",
    "BIN",
    "BIT_LENGTH",
    "BROUND",
    "CARDINALITY",
    "CAST",
    "CBRT",
    "CEIL",
    "CEILING",
    "CHAR",
    "CHARACTER_LENGTH",
    "CHAR_LENGTH",
    "CHR",
    "COALESCE",
    "COLLECT_LIST",
    "COLLECT_SET",
    "CONCAT",
    "CONCAT_WS",
    "CONTAINS",
    "CONV",
    "CORR",
    "COS",
    "COSH",
    "COT",
    "COUNT",
    "COUNT_IF",
    "COVAR_POP",
    "COVAR_SAMP",
    "CUME_DIST",
    "CURRENT_CATALOG",
    "CURRENT_DATABASE",
    "CURRENT_DATE",
    "CURRENT_SCHEMA",
    "CURRENT_TIMESTAMP",
    "CURRENT_USER",
    "DATE",
    "DATEADD",
    "DATEDIFF",
    "DATE_ADD",
    "DATE_DIFF",
    "DATE_FORMAT",
    "DATE_PART",
    "DATE_SUB",
    "DATE_TRUNC",
    "DAY",
    "DAYOFMONTH",
    "DAYOFWEEK",
    "DAYOFYEAR",
    "DECODE",
    "DEGREES",
    "DENSE_RANK",
    "ELEMENT_AT",
    "ENDSWITH",
    "EXISTS",
    "EXP",
    "EXPLODE",
    "EXPLODE_OUTER",
    "EXPM1",
    "EXTRACT",
    "FACTORIAL",
    "FILTER",
    "FIRST",
    "FIRST_VALUE",
    "FLATTEN",
    "FLOOR",
    "FORALL",
    "FORMAT_NUMBER",
    "FORMAT_STRING",
    "FROM_JSON",
    "FROM_UNIXTIME",
    "FROM_UTC_TIMESTAMP",
    "GET_JSON_OBJECT",
    "GREATEST",
    "HEX",
    "HOUR",
    "IF",
    "IFNULL",
    "INITCAP",
    "INLINE",
    "INSTR",
    "ISNAN",
    "ISNOTNULL",
    "ISNULL",
    "JSON_TUPLE",
    "KURTOSIS",
    "LAG",
    "LAST",
    "LAST_DAY",
    "LAST_VALUE",
    "LCASE",
    "LEAD",
    "LEAST",
    "LEFT",
    "LEN",
    "LENGTH",
    "LEVENSHTEIN",
    "LN",
    "LOCATE",
    "LOG",
    "LOG10",
    "LOG1P",
    "LOG2",
    "LOWER",
    "LPAD",
    "LTRIM",
    "MAKE_DATE",
    "MAKE_TIMESTAMP",
    "MAP",
    "MAP_CONCAT",
    "MAP_FROM_ARRAYS",
    "MAP_KEYS",
    "MAP_VALUES",
    "MAX",
    "MAX_BY",
    "MEAN",
    "MEDIAN",
    "MIN",
    "MINUTE",
    "MIN_BY",
    "MOD",
    "MONTH",
    "MONTHS_BETWEEN",
    "NAMED_STRUCT",
    "NANVL",
    "NEXT_DAY",
    "NOW",
    "NTH_VALUE",
    "NTILE",
    "NULLIF",
    "NVL",
    "NVL2",
    "OCTET_LENGTH",
    "PARSE_URL",
    "PERCENTILE",
    "PERCENTILE_APPROX",
    "PERCENT_RANK",
    "PI",
    "PMOD",
    "POSEXPLODE",
    "POSITION",
    "POW",
    "POWER",
    "QUARTER",
    "RADIANS",
    "RAND",
    "RANDN",
    "RANGE",
    "RANK",
    "REGEXP",
    "REGEXP_EXTRACT",
    "REGEXP_EXTRACT_ALL",
    "REGEXP_LIKE",
    "REGEXP_REPLACE",
    "REPEAT",
    "REPLACE",
    "REVERSE",
    "RIGHT",
    "RINT",
    "RLIKE",
    "ROUND",
    "ROW_NUMBER",
    "RPAD",
    "RTRIM",
    "SECOND",
    "SEQUENCE",
    "SHIFTLEFT",
    "SHIFTRIGHT",
    "SIGN",
    "SIGNUM",
    "SIN",
    "SINH",
    "SIZE",
    "SKEWNESS",
    "SLICE",
    "SORT_ARRAY",
    "SPACE",
    "SPLIT",
    "SPLIT_PART",
    "SQRT",
    "STACK",
    "STARTSWITH",
    "STD",
    "STDDEV",
    "STDDEV_POP",
    "STDDEV_SAMP",
    "STRUCT",
    "SUBSTR",
    "SUBSTRING",
    "SUBSTRING_INDEX",
    "SUM",
    "TAN",
    "TANH",
    "TIMESTAMP",
    "TIMESTAMPADD",
    "TIMESTAMPDIFF",
    "TO_DATE",
    "TO_JSON",
    "TO_TIMESTAMP",
    "TO_UNIX_TIMESTAMP",
    "TO_UTC_TIMESTAMP",
    "TRANSFORM",
    "TRANSLATE",
    "TRIM",
    "TRUNC",
    "TRY_CAST",
    "TRY_DIVIDE",
    "TRY_ELEMENT_AT",
    "TYPEOF",
    "UCASE",
    "UNBASE64",
    "UNHEX",
    "UNIX_TIMESTAMP",
    "UPPER",
    "UUID",
    "VARIANCE",
    "VAR_POP",
    "VAR_SAMP",
    "WEEKDAY",
    "WEEKOFYEAR",
    "WIDTH_BUCKET",
    "YEAR",
    "ZIP_WITH",
];

/// Amazon Redshift's functions beside PostgreSQL's, by the names its SQL
/// function reference gives them.
const REDSHIFT_BUILTIN_FUNCTIONS: &[&str] = &[
    "ABS",
    "ACOS",
    "ADD_MONTHS",
    "APPROXIMATE",
    "ASCII",
    "ASIN",
    "ATAN",
    "ATAN2",
    "AVG",
    "BPCHARCMP",
    "BTRIM",
    "BTTEXT_PATTERN_CMP",
    "CBRT",
    "CEIL",
    "CEILING",
    "CHARACTER_LENGTH",
    "CHARINDEX",
    "CHAR_LENGTH",
    "CHR",
    "COALESCE",
    "CONCAT",
    "CONVERT",
    "CONVERT_TIMEZONE",
    "COS",
    "COT",
    "COUNT",
    "CUME_DIST",
    "CURRENT_DATE",
    "CURRENT_SCHEMA",
    "CURRENT_USER",
    "DATEADD",
    "DATEDIFF",
    "DATE_ADD",
    "DATE_CMP",
    "DATE_DIFF",
    "DATE_PART",
    "DATE_TRUNC",
    "DECODE",
    "DEGREES",
    "DENSE_RANK",
    "DEXP",
    "DLOG1",
    "DLOG10",
    "EXP",
    "EXTRACT",
    "FIRST_VALUE",
    "FLOOR",
    "GETDATE",
    "GREATEST",
    "INITCAP",
    "INTERVAL_CMP",
    "IS_VALID_JSON",
    "IS_VALID_JSON_ARRAY",
    "JSON_ARRAY_LENGTH",
    "JSON_EXTRACT_ARRAY_ELEMENT_TEXT",
    "JSON_EXTRACT_PATH_TEXT",
    "JSON_PARSE",
    "JSON_SERIALIZE",
    "LAG",
    "LAST_DAY",
    "LAST_VALUE",
    "LEAD",
    "LEAST",
    "LEFT",
    "LEN",
    "LENGTH",
    "LISTAGG",
    "LN",
    "LOG",
    "LOWER",
    "LPAD",
    "LTRIM",
    "MAX",
    "MEDIAN",
    "MIN",
    "MOD",
    "MONTHS_BETWEEN",
    "NEXT_DAY",
    "NTH_VALUE",
    "NTILE",
    "NULLIF",
    "NVL",
    "NVL2",
    "OCTET_LENGTH",
    "PERCENTILE_CONT",
    "PERCENTILE_DISC",
    "PERCENT_RANK",
    "PI",
    "POSITION",
    "POWER",
    "QUOTE_IDENT",
    "QUOTE_LITERAL",
    "RADIANS",
    "RANDOM",
    "RANK",
    "RATIO_TO_REPORT",
    "REGEXP_COUNT",
    "REGEXP_INSTR",
    "REGEXP_REPLACE",
    "REGEXP_SUBSTR",
    "REPEAT",
    "REPLACE",
    "REPLICATE",
    "REVERSE",
    "RIGHT",
    "ROUND",
    "ROW_NUMBER",
    "RPAD",
    "RTRIM",
    "SIGN",
    "SIN",
    "SPLIT_PART",
    "SQRT",
    "STDDEV",
    "STDDEV_POP",
    "STDDEV_SAMP",
    "STRPOS",
    "STRTOL",
    "SUBSTR",
    "SUBSTRING",
    "SUM",
    "SYSDATE",
    "TAN",
    "TIMEOFDAY",
    "TIMESTAMP_CMP",
    "TO_CHAR",
    "TO_DATE",
    "TO_NUMBER",
    "TO_TIMESTAMP",
    "TRANSLATE",
    "TRIM",
    "TRUNC",
    "UPPER",
    "VARIANCE",
    "VAR_POP",
    "VAR_SAMP",
];

/// PostgreSQL's large-object, sequence and session functions.
const POSTGRES_ADMIN_FUNCTIONS: &[&str] = &[
    "current_setting",
    "currval",
    "lastval",
    "lo_close",
    "lo_create",
    "lo_export",
    "lo_get",
    "lo_import",
    "lo_open",
    "lo_put",
    "lo_unlink",
    "nextval",
    "pg_cancel_backend",
    "pg_sleep",
    "pg_terminate_backend",
    "set_config",
    "setval",
];

/// The table functions Snowflake defines that the catalog holds no
/// signature of (Snowflake documentation, "Table functions"), the
/// `INFORMATION_SCHEMA` ones among them.
const SNOWFLAKE_BUILTIN_TABLE_FUNCTIONS: &[&str] = &[
    "RESULT_SCAN",
    "INFER_SCHEMA",
    "VALIDATE",
    "VALIDATE_PIPE_LOAD",
    "GET_OBJECT_REFERENCES",
    "QUERY_HISTORY",
    "QUERY_HISTORY_BY_SESSION",
    "QUERY_HISTORY_BY_USER",
    "QUERY_HISTORY_BY_WAREHOUSE",
    "LOGIN_HISTORY",
    "LOGIN_HISTORY_BY_USER",
    "TASK_HISTORY",
    "TASK_DEPENDENTS",
    "CURRENT_TASK_GRAPHS",
    "COMPLETE_TASK_GRAPHS",
    "SERVERLESS_TASK_HISTORY",
    "COPY_HISTORY",
    "PIPE_USAGE_HISTORY",
    "WAREHOUSE_LOAD_HISTORY",
    "WAREHOUSE_METERING_HISTORY",
    "AUTOMATIC_CLUSTERING_HISTORY",
    "DATABASE_STORAGE_USAGE_HISTORY",
    "STAGE_STORAGE_USAGE_HISTORY",
    "DATA_TRANSFER_HISTORY",
    "REPLICATION_USAGE_HISTORY",
    "MATERIALIZED_VIEW_REFRESH_HISTORY",
    "SEARCH_OPTIMIZATION_HISTORY",
    "DYNAMIC_TABLE_REFRESH_HISTORY",
    "DYNAMIC_TABLES",
    "DYNAMIC_TABLE_GRAPH_HISTORY",
    "EXTERNAL_TABLE_FILES",
    "EXTERNAL_TABLE_FILE_REGISTRATION_HISTORY",
    "STAGE_DIRECTORY_FILE_REGISTRATION_HISTORY",
    "EXTERNAL_FUNCTIONS_HISTORY",
    "NOTIFICATION_HISTORY",
    "ALERT_HISTORY",
    "REST_EVENT_HISTORY",
    "POLICY_REFERENCES",
    "TAG_REFERENCES",
    "TAG_REFERENCES_ALL_COLUMNS",
    "TAG_REFERENCES_WITH_LINEAGE",
];

/// Dialect selector for [`FunctionCatalog::for_dialect`]. Kept as a
/// dedicated type so the catalog module does not couple to the full
/// [`crate::dialect::Dialect`] surface — the catalog cares only about
/// which signatures a dialect states differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CatalogDialect {
    /// No dialect: every function the seed knows, from whichever engine,
    /// each with the signature the seed gives it. For a caller that has no
    /// dialect at hand.
    Default,
    Snowflake,
    BigQuery,
    PostgreSql,
    Databricks,
    MySql,
    MsSql,
    Redshift,
}

impl CatalogDialect {
    /// The catalog dialect of the lexer dialect that reports `name`. It is
    /// keyed on exactly what [`crate::dialect::Dialect::name`] returns: an
    /// alias the command line accepts (`postgres`, `pg`) or another casing
    /// is not such a name and gives `Default`, as any other name does.
    pub fn from_dialect_name(name: &str) -> Self {
        match name {
            "snowflake" => Self::Snowflake,
            "bigquery" => Self::BigQuery,
            "postgresql" => Self::PostgreSql,
            "databricks" => Self::Databricks,
            "mysql" => Self::MySql,
            "mssql" => Self::MsSql,
            "redshift" => Self::Redshift,
            _ => Self::Default,
        }
    }
}

// ────────────────────────────────────────────────────────────────────────
// Builtin seeding
// ────────────────────────────────────────────────────────────────────────

/// How a bare word that is a function's name reads where the dialect
/// documents the function with no parentheses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BareValue {
    /// The function whatever columns are in scope: a reserved word, which
    /// no unquoted column can be named.
    Always,
    /// A column a source in scope is known to hold wins; otherwise the
    /// function.
    UnlessColumn,
}

/// The functions `dialect` documents with no parentheses, each read as
/// `value` when written bare.
struct BareValues {
    dialect: CatalogDialect,
    value: BareValue,
    functions: &'static [&'static str],
}

/// The bare functions of each dialect; a word not listed is a column when
/// written bare. `Default` has no rows: it takes the union.
const BARE_VALUES: &[BareValues] = &[
    BareValues {
        dialect: CatalogDialect::Snowflake,
        value: BareValue::Always,
        functions: &[
            "CURRENT_DATE",
            "CURRENT_TIME",
            "CURRENT_TIMESTAMP",
            "LOCALTIME",
            "LOCALTIMESTAMP",
            "CURRENT_USER",
        ],
    },
    BareValues {
        dialect: CatalogDialect::MsSql,
        value: BareValue::Always,
        functions: &[
            "CURRENT_TIMESTAMP",
            "CURRENT_DATE",
            "CURRENT_USER",
            "SESSION_USER",
            "SYSTEM_USER",
            "USER",
            "CURRENT_TIME",
        ],
    },
    BareValues {
        dialect: CatalogDialect::PostgreSql,
        value: BareValue::Always,
        functions: &[
            "CURRENT_DATE",
            "CURRENT_TIME",
            "CURRENT_TIMESTAMP",
            "LOCALTIME",
            "LOCALTIMESTAMP",
            "CURRENT_USER",
            "SESSION_USER",
            "USER",
            "CURRENT_ROLE",
            "CURRENT_CATALOG",
            "CURRENT_SCHEMA",
            "SYSTEM_USER",
        ],
    },
    BareValues {
        dialect: CatalogDialect::MySql,
        value: BareValue::Always,
        functions: &[
            "CURRENT_DATE",
            "CURRENT_TIME",
            "CURRENT_TIMESTAMP",
            "LOCALTIME",
            "LOCALTIMESTAMP",
            "UTC_DATE",
            "UTC_TIME",
            "UTC_TIMESTAMP",
            "CURRENT_USER",
        ],
    },
    BareValues {
        dialect: CatalogDialect::Redshift,
        value: BareValue::Always,
        functions: &[
            "SYSDATE",
            "CURRENT_DATE",
            "CURRENT_USER",
            "USER",
            "CURRENT_USER_ID",
            "SESSION_USER",
            "CURRENT_TIME",
            "CURRENT_TIMESTAMP",
            "LOCALTIME",
            "LOCALTIMESTAMP",
        ],
    },
    BareValues {
        dialect: CatalogDialect::BigQuery,
        value: BareValue::UnlessColumn,
        functions: &[
            "CURRENT_DATE",
            "CURRENT_DATETIME",
            "CURRENT_TIME",
            "CURRENT_TIMESTAMP",
        ],
    },
    BareValues {
        dialect: CatalogDialect::Databricks,
        value: BareValue::UnlessColumn,
        functions: &[
            "CURRENT_DATE",
            "CURRENT_TIMESTAMP",
            "CURRENT_USER",
            "SESSION_USER",
            "USER",
        ],
    },
];

/// One thing a dialect's signature of a seeded function says differently
/// from the seed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SignatureChange {
    GeneratesRows(bool),
    YieldsOneValue(bool),
    NullBehavior(NullBehavior),
}

/// What `function` returns for NULL arguments under `dialect`.
const fn for_null(
    dialect: CatalogDialect,
    function: &'static str,
    returns: NullBehavior,
) -> DialectSignature {
    DialectSignature {
        dialect,
        function,
        states: SignatureChange::NullBehavior(returns),
    }
}

/// `function`, as `dialect` has it.
struct DialectSignature {
    dialect: CatalogDialect,
    function: &'static str,
    states: SignatureChange,
}

/// Where a dialect's function differs from the seed's signature of that
/// name. [`FunctionCatalog::for_dialect`] applies a dialect's rows over
/// the seed; `Default` has none.
const DIALECT_SIGNATURES: &[DialectSignature] = &[
    // Spark's `json_object_keys` returns the keys as one array.
    DialectSignature {
        dialect: CatalogDialect::Databricks,
        function: "JSON_OBJECT_KEYS",
        states: SignatureChange::GeneratesRows(false),
    },
    DialectSignature {
        dialect: CatalogDialect::Databricks,
        function: "JSON_OBJECT_KEYS",
        states: SignatureChange::YieldsOneValue(false),
    },
    // SQL Server's `GENERATE_SERIES` yields a column named `value`; an
    // alias after it names the table.
    DialectSignature {
        dialect: CatalogDialect::MsSql,
        function: "GENERATE_SERIES",
        states: SignatureChange::YieldsOneValue(false),
    },
    // `concat` skips a NULL argument, or takes it as an empty string.
    for_null(
        CatalogDialect::PostgreSql,
        "CONCAT",
        NullBehavior::NeverNull,
    ),
    for_null(CatalogDialect::MsSql, "CONCAT", NullBehavior::NeverNull),
    // `GREATEST` and `LEAST` ignore NULL arguments: NULL only where every
    // argument is, and no argument is a default as a `COALESCE`'s is.
    for_null(
        CatalogDialect::PostgreSql,
        "GREATEST",
        NullBehavior::NullOnlyWhenAllNull,
    ),
    for_null(
        CatalogDialect::PostgreSql,
        "LEAST",
        NullBehavior::NullOnlyWhenAllNull,
    ),
    for_null(
        CatalogDialect::MsSql,
        "GREATEST",
        NullBehavior::NullOnlyWhenAllNull,
    ),
    for_null(
        CatalogDialect::MsSql,
        "LEAST",
        NullBehavior::NullOnlyWhenAllNull,
    ),
    for_null(
        CatalogDialect::Databricks,
        "GREATEST",
        NullBehavior::NullOnlyWhenAllNull,
    ),
    for_null(
        CatalogDialect::Databricks,
        "LEAST",
        NullBehavior::NullOnlyWhenAllNull,
    ),
    for_null(
        CatalogDialect::Redshift,
        "GREATEST",
        NullBehavior::NullOnlyWhenAllNull,
    ),
    for_null(
        CatalogDialect::Redshift,
        "LEAST",
        NullBehavior::NullOnlyWhenAllNull,
    ),
    // `TO_JSON(NULL)` is the JSON value `null`, which is not SQL NULL.
    for_null(CatalogDialect::BigQuery, "TO_JSON", NullBehavior::Unknown),
];

/// The columns `function`, called as a table in a `FROM` clause, yields
/// under `dialect`.
struct DialectColumns {
    dialect: CatalogDialect,
    function: &'static str,
    columns: YieldedColumns,
}

/// Every column the function yields: `names`.
const fn columns(
    dialect: CatalogDialect,
    function: &'static str,
    names: &'static [&'static str],
) -> DialectColumns {
    DialectColumns {
        dialect,
        function,
        columns: YieldedColumns {
            names,
            complete: true,
        },
    }
}

/// `names`, and for some arguments columns of other names.
const fn some_columns(
    dialect: CatalogDialect,
    function: &'static str,
    names: &'static [&'static str],
) -> DialectColumns {
    DialectColumns {
        dialect,
        function,
        columns: YieldedColumns {
            names,
            complete: false,
        },
    }
}

/// What some arguments of `function` are, in each of `dialects`.
struct DialectArguments {
    dialects: &'static [CatalogDialect],
    function: &'static str,
    roles: ArgumentRoles,
}

const fn path_from(
    dialects: &'static [CatalogDialect],
    function: &'static str,
    from: usize,
) -> DialectArguments {
    DialectArguments {
        dialects,
        function,
        roles: ArgumentRoles::Path { from },
    }
}

const fn path_pairs_from(
    dialects: &'static [CatalogDialect],
    function: &'static str,
    from: usize,
) -> DialectArguments {
    DialectArguments {
        dialects,
        function,
        roles: ArgumentRoles::PathValuePairs { from },
    }
}

const fn pairs_from(
    dialects: &'static [CatalogDialect],
    function: &'static str,
    from: usize,
) -> DialectArguments {
    DialectArguments {
        dialects,
        function,
        roles: ArgumentRoles::KeyValuePairs { from },
    }
}

/// The functions each dialect's documentation gives a key or a path into a
/// document, or keys and values in turn; `Default` has every row.
const ARGUMENT_ROLES: &[DialectArguments] = {
    use CatalogDialect::{BigQuery, Databricks, MsSql, MySql, PostgreSql, Redshift, Snowflake};
    &[
        // Snowflake.
        path_from(&[Snowflake], "GET_PATH", 1),
        path_from(&[Snowflake], "GET", 1),
        path_from(
            &[Snowflake, Redshift, PostgreSql],
            "JSON_EXTRACT_PATH_TEXT",
            1,
        ),
        // Snowflake's constructors, read so under any dialect a file is
        // read as.
        pairs_from(
            &[
                Snowflake, BigQuery, Databricks, MsSql, MySql, PostgreSql, Redshift,
            ],
            "OBJECT_CONSTRUCT",
            0,
        ),
        pairs_from(
            &[
                Snowflake, BigQuery, Databricks, MsSql, MySql, PostgreSql, Redshift,
            ],
            "OBJECT_CONSTRUCT_KEEP_NULL",
            0,
        ),
        pairs_from(
            &[
                Snowflake, BigQuery, Databricks, MsSql, MySql, PostgreSql, Redshift,
            ],
            "OBJECT_INSERT",
            1,
        ),
        // `GETVARIABLE(name)`: the session variable's value.
        path_from(&[Snowflake], "GETVARIABLE", 0),
        // `SYS_CONTEXT(namespace, property)`: the property's value.
        path_from(&[Snowflake], "SYS_CONTEXT", 1),
        // PostgreSQL.
        path_from(&[PostgreSql], "JSON_EXTRACT_PATH", 1),
        path_from(&[PostgreSql], "JSONB_EXTRACT_PATH", 1),
        path_from(&[PostgreSql], "JSONB_EXTRACT_PATH_TEXT", 1),
        pairs_from(&[PostgreSql], "JSON_BUILD_OBJECT", 0),
        pairs_from(&[PostgreSql], "JSONB_BUILD_OBJECT", 0),
        // `current_setting(setting_name [, missing_ok])`: the setting's value.
        path_from(&[PostgreSql, Redshift], "CURRENT_SETTING", 0),
        // SQL Server's `SESSION_CONTEXT(N'key')`: the value set for the key.
        path_from(&[MsSql], "SESSION_CONTEXT", 0),
        // BigQuery, SQL Server and MySQL.
        path_from(&[BigQuery, MsSql, MySql], "JSON_VALUE", 1),
        path_from(&[BigQuery, MsSql], "JSON_QUERY", 1),
        path_from(&[BigQuery, MySql], "JSON_EXTRACT", 1),
        path_from(&[BigQuery], "JSON_EXTRACT_SCALAR", 1),
        path_from(&[BigQuery], "JSON_VALUE_ARRAY", 1),
        path_from(&[BigQuery], "JSON_QUERY_ARRAY", 1),
        pairs_from(&[BigQuery, MySql], "JSON_OBJECT", 0),
        // Databricks.
        path_from(&[Databricks], "GET_JSON_OBJECT", 1),
        path_from(&[Databricks], "JSON_TUPLE", 1),
        pairs_from(&[Databricks], "MAP", 0),
        pairs_from(&[Databricks], "NAMED_STRUCT", 0),
        // The functions that set a value at a path into a JSON document.
        path_pairs_from(&[MySql, BigQuery], "JSON_SET", 1),
        path_pairs_from(&[MySql], "JSON_INSERT", 1),
        path_pairs_from(&[MySql], "JSON_REPLACE", 1),
        path_pairs_from(&[MySql, BigQuery], "JSON_ARRAY_APPEND", 1),
        path_pairs_from(&[MySql, BigQuery], "JSON_ARRAY_INSERT", 1),
        path_pairs_from(&[PostgreSql], "JSONB_SET", 1),
        path_pairs_from(&[PostgreSql], "JSONB_SET_LAX", 1),
        path_pairs_from(&[PostgreSql], "JSONB_INSERT", 1),
        path_pairs_from(&[MsSql], "JSON_MODIFY", 1),
    ]
};

/// The columns each dialect's documentation names for its table functions.
/// A function whose columns depend on its arguments (Spark's `inline`,
/// `stack`, `json_tuple`) or are declared in the call (`JSON_TABLE`'s
/// `COLUMNS`) has no row.
const YIELDED_COLUMNS: &[DialectColumns] = &[
    // Snowflake: FLATTEN, SPLIT_TO_TABLE, STRTOK_SPLIT_TO_TABLE.
    columns(
        CatalogDialect::Snowflake,
        "FLATTEN",
        &["SEQ", "KEY", "PATH", "INDEX", "VALUE", "THIS"],
    ),
    columns(
        CatalogDialect::Snowflake,
        "SPLIT_TO_TABLE",
        &["SEQ", "INDEX", "VALUE"],
    ),
    columns(
        CatalogDialect::Snowflake,
        "STRTOK_SPLIT_TO_TABLE",
        &["SEQ", "INDEX", "VALUE"],
    ),
    // SQL Server: `STRING_SPLIT` adds `ordinal` when its third argument
    // enables it; `OPENJSON` with no `WITH` schema; `GENERATE_SERIES`.
    some_columns(CatalogDialect::MsSql, "STRING_SPLIT", &["VALUE"]),
    columns(CatalogDialect::MsSql, "OPENJSON", &["KEY", "VALUE", "TYPE"]),
    columns(CatalogDialect::MsSql, "GENERATE_SERIES", &["VALUE"]),
    // PostgreSQL: the functions whose result columns are named by `OUT`
    // parameters.
    columns(CatalogDialect::PostgreSql, "JSON_EACH", &["KEY", "VALUE"]),
    columns(
        CatalogDialect::PostgreSql,
        "JSON_EACH_TEXT",
        &["KEY", "VALUE"],
    ),
    columns(CatalogDialect::PostgreSql, "JSONB_EACH", &["KEY", "VALUE"]),
    columns(
        CatalogDialect::PostgreSql,
        "JSONB_EACH_TEXT",
        &["KEY", "VALUE"],
    ),
    columns(
        CatalogDialect::PostgreSql,
        "JSON_ARRAY_ELEMENTS",
        &["VALUE"],
    ),
    columns(
        CatalogDialect::PostgreSql,
        "JSON_ARRAY_ELEMENTS_TEXT",
        &["VALUE"],
    ),
    columns(
        CatalogDialect::PostgreSql,
        "JSONB_ARRAY_ELEMENTS",
        &["VALUE"],
    ),
    columns(
        CatalogDialect::PostgreSql,
        "JSONB_ARRAY_ELEMENTS_TEXT",
        &["VALUE"],
    ),
    // Spark: over a map, `explode` yields `key` and `value` instead.
    some_columns(CatalogDialect::Databricks, "EXPLODE", &["COL"]),
    some_columns(CatalogDialect::Databricks, "EXPLODE_OUTER", &["COL"]),
    some_columns(CatalogDialect::Databricks, "POSEXPLODE", &["POS", "COL"]),
    some_columns(
        CatalogDialect::Databricks,
        "POSEXPLODE_OUTER",
        &["POS", "COL"],
    ),
];

/// The words that name a value a `CONNECT BY` traversal makes for each row
/// it returns, in every dialect: the row's depth and whether it is a leaf or
/// closes a cycle.
const HIERARCHY_VALUES: &[&str] = &["LEVEL", "CONNECT_BY_ISLEAF", "CONNECT_BY_ISCYCLE"];

/// Whether `name`, a column's name, names a value a `CONNECT BY`
/// traversal makes ([`HIERARCHY_VALUES`]).
pub(crate) fn names_hierarchy_value(name: &IdentKey) -> bool {
    HIERARCHY_VALUES
        .iter()
        .any(|word| &IdentKey::new_as(word, crate::ir::normalize::NameKind::Column) == name)
}

/// Whether `dialect` names the one value column of a table function
/// written with no alias after the function, as PostgreSQL does.
const fn value_named_for_function(dialect: CatalogDialect) -> bool {
    match dialect {
        CatalogDialect::PostgreSql => true,
        CatalogDialect::Default
        | CatalogDialect::Snowflake
        | CatalogDialect::BigQuery
        | CatalogDialect::Databricks
        | CatalogDialect::MySql
        | CatalogDialect::MsSql
        | CatalogDialect::Redshift => false,
    }
}

fn agg(name: &str, arg_shape: ArgShape) -> FunctionSignature {
    FunctionSignature {
        display_name: name.to_string(),
        kind: FunctionKind::Aggregate,
        // Most aggregates skip NULL inputs rather than propagating
        // them, but their *output* nullability for an empty group
        // is dialect-dependent. Default to `Unknown` and let
        // specific aggregates (`COUNT`, `GROUPING`, etc.) override
        // to `NeverNull` when their output is provably non-null.
        null_behavior: NullBehavior::Unknown,
        determinism: Determinism::Deterministic,
        arg_shape,
        is_ranking: false,
        is_temporal: false,
        generates_rows: false,
        yields_one_value: false,
        over_no_rows: None,
        rows_per_input: RowsPerInput::Unknown,
    }
}

/// `sig`, stated NULL over no rows.
fn null_over_no_rows(sig: FunctionSignature) -> FunctionSignature {
    FunctionSignature {
        over_no_rows: Some(NoRowsValue::Null),
        ..sig
    }
}

fn window_only(name: &str, arg_shape: ArgShape) -> FunctionSignature {
    FunctionSignature {
        display_name: name.to_string(),
        kind: FunctionKind::Window,
        // Per-function override below in `seed_window_only` for
        // RANK-family non-null outputs. Default conservative.
        null_behavior: NullBehavior::Unknown,
        determinism: Determinism::Deterministic,
        arg_shape,
        is_ranking: false,
        is_temporal: false,
        generates_rows: false,
        yields_one_value: false,
        over_no_rows: None,
        rows_per_input: RowsPerInput::Unknown,
    }
}

fn scalar(name: &str, null_behavior: NullBehavior, arg_shape: ArgShape) -> FunctionSignature {
    FunctionSignature {
        display_name: name.to_string(),
        kind: FunctionKind::Scalar,
        null_behavior,
        determinism: Determinism::Deterministic,
        arg_shape,
        is_ranking: false,
        is_temporal: false,
        generates_rows: false,
        yields_one_value: false,
        over_no_rows: None,
        rows_per_input: RowsPerInput::Unknown,
    }
}

fn scalar_volatile(name: &str, arg_shape: ArgShape) -> FunctionSignature {
    FunctionSignature {
        display_name: name.to_string(),
        kind: FunctionKind::Scalar,
        // Volatile builtins (`CURRENT_TIMESTAMP`, `RANDOM`, …) all
        // produce non-null output by SQL spec.
        null_behavior: NullBehavior::NeverNull,
        determinism: Determinism::Volatile,
        arg_shape,
        is_ranking: false,
        is_temporal: false,
        generates_rows: false,
        yields_one_value: false,
        over_no_rows: None,
        rows_per_input: RowsPerInput::Unknown,
    }
}

fn seed_aggregates(catalog: &mut FunctionCatalog) {
    // Core SQL aggregates — present in every dialect we support.
    let fixed1 = ArgShape::Fixed { arity: 1 };
    let variadic0 = ArgShape::Variadic { min_positional: 0 };
    let unspec = ArgShape::Unspecified;

    let count = catalog.register(FunctionSignature {
        display_name: "COUNT".to_string(),
        // COUNT admits both `COUNT(*)` (zero positional args in IR)
        // and `COUNT(expr)` (one arg).
        // Model as variadic-min-0 so the lowerer doesn't issue a
        // spurious arity error for the `*` form.
        kind: FunctionKind::Aggregate,
        // COUNT returns 0 for an empty group — never NULL.
        null_behavior: NullBehavior::NeverNull,
        determinism: Determinism::Deterministic,
        arg_shape: variadic0,
        is_ranking: false,
        is_temporal: false,
        generates_rows: false,
        yields_one_value: false,
        over_no_rows: Some(NoRowsValue::Zero),
        rows_per_input: RowsPerInput::Unknown,
    });
    // `COUNT_IF` is a Snowflake/Databricks spelling with the same shape.
    // Like `COUNT`, returns 0 for an empty match set — never NULL.
    catalog.register(FunctionSignature {
        display_name: "COUNT_IF".to_string(),
        kind: FunctionKind::Aggregate,
        null_behavior: NullBehavior::NeverNull,
        determinism: Determinism::Deterministic,
        arg_shape: fixed1,
        is_ranking: false,
        is_temporal: false,
        generates_rows: false,
        yields_one_value: false,
        over_no_rows: Some(NoRowsValue::Zero),
        rows_per_input: RowsPerInput::Unknown,
    });
    let _ = count; // kept for clarity; aliasing intentional next line
    for name in ["SUM", "AVG", "MIN", "MAX", "ANY_VALUE"] {
        catalog.register(null_over_no_rows(agg(name, fixed1)));
    }

    // Statistical aggregates.
    for name in [
        "STDDEV",
        "STDDEV_POP",
        "STDDEV_SAMP",
        "VAR_POP",
        "VAR_SAMP",
        "VARIANCE",
        "VARIANCE_POP",
        "VARIANCE_SAMP",
        "KURTOSIS",
        "SKEWNESS",
    ] {
        catalog.register(null_over_no_rows(agg(name, fixed1)));
    }
    // Two-argument statistical aggregates.
    let fixed2 = ArgShape::Fixed { arity: 2 };
    for name in [
        "CORR",
        "COVAR_POP",
        "COVAR_SAMP",
        "REGR_SLOPE",
        "REGR_INTERCEPT",
        "REGR_R2",
    ] {
        catalog.register(null_over_no_rows(agg(name, fixed2)));
    }
    // It counts pairs; the catalog does not state its value over no rows.
    catalog.register(agg("REGR_COUNT", fixed2));
    for name in ["REGR_AVGX", "REGR_AVGY", "REGR_SXX", "REGR_SYY", "REGR_SXY"] {
        catalog.register(null_over_no_rows(agg(name, fixed2)));
    }

    // Approximate aggregates (Snowflake / BigQuery / Databricks).
    for name in [
        "APPROX_COUNT_DISTINCT",
        "APPROX_DISTINCT",
        "HLL",
        "HLL_ACCUMULATE",
        "HLL_COMBINE",
        "HLL_ESTIMATE",
        "HLL_EXPORT",
        "HLL_IMPORT",
        "APPROX_TOP_K",
        "APPROX_PERCENTILE",
        "TDIGEST",
    ] {
        catalog.register(agg(name, unspec));
    }

    // Ordered-set / hypothetical-set aggregates (`WITHIN GROUP`).
    for name in ["PERCENTILE_CONT", "PERCENTILE_DISC", "MEDIAN", "MODE"] {
        catalog.register(null_over_no_rows(agg(name, unspec)));
    }

    // Collection aggregates.
    for name in [
        "LISTAGG",
        "STRING_AGG",
        "GROUP_CONCAT",
        "ARRAY_AGG",
        "ARRAY_UNION_AGG",
        "ARRAY_CONCAT_AGG",
        "OBJECT_AGG",
        "BUILD_OBJECT_AGG",
        "MAP_AGG",
        "JSON_ARRAYAGG",
        "JSON_OBJECTAGG",
        "JSONB_AGG",
        "JSONB_OBJECT_AGG",
        "XMLAGG",
    ] {
        catalog.register(agg(name, unspec));
    }

    // Boolean / bitwise aggregates.
    for name in [
        "BIT_AND",
        "BIT_OR",
        "BIT_XOR",
        "BOOL_AND",
        "BOOL_OR",
        "EVERY",
        "LOGICAL_AND",
        "LOGICAL_OR",
        "BITMAP_CONSTRUCT_AGG",
        "BITMAP_OR_AGG",
    ] {
        catalog.register(agg(name, fixed1));
    }

    // MSSQL / dialect-specific.
    catalog.register(agg("CHECKSUM_AGG", fixed1));

    // First / last value aggregates (Spark / Databricks / BigQuery / MySQL).
    // `FIRST` and `LAST` are window-aggregates in most dialects: they can
    // appear both with GROUP BY (aggregate context) and with OVER (window
    // context). `WindowAggregate` covers both.
    catalog.register(FunctionSignature {
        display_name: "FIRST".to_string(),
        kind: FunctionKind::WindowAggregate,
        null_behavior: NullBehavior::Unknown,
        determinism: Determinism::Deterministic,
        arg_shape: ArgShape::Unspecified,
        is_ranking: false,
        is_temporal: false,
        generates_rows: false,
        yields_one_value: false,
        over_no_rows: None,
        rows_per_input: RowsPerInput::Unknown,
    });
    catalog.register(FunctionSignature {
        display_name: "LAST".to_string(),
        kind: FunctionKind::WindowAggregate,
        null_behavior: NullBehavior::Unknown,
        determinism: Determinism::Deterministic,
        arg_shape: ArgShape::Unspecified,
        is_ranking: false,
        is_temporal: false,
        generates_rows: false,
        yields_one_value: false,
        over_no_rows: None,
        rows_per_input: RowsPerInput::Unknown,
    });

    // MAX_BY / MIN_BY: two-argument aggregates returning the value of
    // the first argument at the row where the second argument is max/min.
    // Snowflake, BigQuery, Databricks.
    catalog.register(agg("MAX_BY", ArgShape::Fixed { arity: 2 }));
    catalog.register(agg("MIN_BY", ArgShape::Fixed { arity: 2 }));
}

fn seed_window_only(catalog: &mut FunctionCatalog) {
    let fixed0 = ArgShape::Fixed { arity: 0 };
    let unspec = ArgShape::Unspecified;

    // Rank-family: integer position within the window — never null.
    // `PERCENT_RANK` and `CUME_DIST` return non-null floats by spec.
    // All six are marked `is_ranking = true` so consumers can detect
    // ranking patterns (e.g. ROW_NUMBER without ORDER BY) without
    // consulting a hardcoded name list.
    for name in [
        "ROW_NUMBER",
        "RANK",
        "DENSE_RANK",
        "PERCENT_RANK",
        "CUME_DIST",
    ] {
        let mut sig = window_only(name, fixed0);
        sig.null_behavior = NullBehavior::NeverNull;
        sig.is_ranking = true;
        catalog.register(sig);
    }
    // `NTILE(n)`: bucket index — never null when the window has rows.
    let mut ntile = window_only("NTILE", unspec);
    ntile.null_behavior = NullBehavior::NeverNull;
    ntile.is_ranking = true;
    catalog.register(ntile);
    // Value-positional window functions: result null iff the
    // underlying value at the offset is null (or the offset is
    // out-of-range and no DEFAULT is supplied). Conservatively
    // strict over the value argument.
    for name in [
        "LEAD",
        "LAG",
        "FIRST_VALUE",
        "LAST_VALUE",
        "NTH_VALUE",
        "RATIO_TO_REPORT",
    ] {
        let mut sig = window_only(name, unspec);
        sig.null_behavior = NullBehavior::Strict;
        catalog.register(sig);
    }
}

/// ODBC canonical scalar-function name → the native name this catalog
/// registers (`{fn UCASE(x)}` → `UPPER`). Consulted ONLY for `{fn …}`-escaped
/// calls whose raw spelling does not resolve directly; bare `UCASE(x)`
/// outside an escape is not native SQL and stays unresolved. Names whose
/// ODBC spelling already matches a registered name (ABS, NOW, IFNULL, …)
/// resolve directly and need no entry.
pub(crate) fn odbc_canonical_function_target(raw_name: &str) -> Option<&'static str> {
    match raw_name.to_ascii_uppercase().as_str() {
        "UCASE" => Some("UPPER"),
        "LCASE" => Some("LOWER"),
        "CURDATE" => Some("CURRENT_DATE"),
        "CURTIME" => Some("CURRENT_TIME"),
        "DAYOFMONTH" => Some("DAY"),
        "TRUNCATE" => Some("TRUNC"),
        _ => None,
    }
}

fn seed_common_scalars(catalog: &mut FunctionCatalog) {
    let unspec = ArgShape::Unspecified;
    let fixed1 = ArgShape::Fixed { arity: 1 };
    let fixed2 = ArgShape::Fixed { arity: 2 };

    // ── NULL-handling: COALESCE-family ─────────────────────────
    // Result null iff every argument is null.
    for name in ["COALESCE", "NVL", "IFNULL", "ISNULL"] {
        catalog.register(scalar(name, NullBehavior::CoalesceLike, unspec));
    }
    // `ZEROIFNULL(x)` is `COALESCE(x, 0)` per Snowflake/Teradata
    // spec — the implicit `0` is non-null, so the result is
    // *always* non-null. Classify accordingly so
    // `ZEROIFNULL(nullable) > k` is provably not a
    // silent-null-drop pattern.
    catalog.register(scalar("ZEROIFNULL", NullBehavior::NeverNull, fixed1));

    // ── NULL-handling: conditional ternaries ───────────────────
    // Result null iff every value branch (args[1..]) is null. The first
    // argument selects the branch: that of `IFF`, `IIF` and `IF` is a
    // condition, `NVL2`'s is tested for NULL.
    for name in ["IFF", "IIF", "IF"] {
        catalog.register(scalar(
            name,
            NullBehavior::BranchOnCondition,
            ArgShape::Fixed { arity: 3 },
        ));
    }
    catalog.register(scalar(
        "NVL2",
        NullBehavior::BranchOnNotNull,
        ArgShape::Fixed { arity: 3 },
    ));

    // ── NULL-handling: misc ────────────────────────────────────
    // `NULLIF(a, b)` returns NULL when `a == b`, else `a`. Result
    // can be null even when both args non-null, so classification
    // is `Unknown` (conservative).
    catalog.register(scalar("NULLIF", NullBehavior::Unknown, fixed2));

    // ── Strict scalars: NULL propagates from any argument ─────
    catalog.register(scalar("GREATEST", NullBehavior::Strict, unspec));
    catalog.register(scalar("LEAST", NullBehavior::Strict, unspec));

    // String functions.
    for name in [
        "UPPER", "LOWER", "LENGTH", "LEN", "TRIM", "LTRIM", "RTRIM", "REVERSE",
    ] {
        catalog.register(scalar(name, NullBehavior::Strict, fixed1));
    }
    for name in ["CONCAT", "SUBSTRING", "SUBSTR", "REPLACE", "SPLIT_PART"] {
        catalog.register(scalar(name, NullBehavior::Strict, unspec));
    }

    // Numeric.
    for name in ["ABS", "CEIL", "CEILING", "FLOOR", "ROUND", "TRUNC", "SIGN"] {
        catalog.register(scalar(name, NullBehavior::Strict, unspec));
    }
    catalog.register(scalar("MOD", NullBehavior::Strict, fixed2));

    // Date / time core. Marked `is_temporal = true` so consumers can
    // recognise temporal predicates without a hardcoded function-
    // name list.
    for name in [
        "DATEADD",
        "DATE_ADD",
        "DATEDIFF",
        "DATE_DIFF",
        "DATE_TRUNC",
        "EXTRACT",
        "TO_DATE",
        "TO_TIME",
        "TO_TIMESTAMP",
        "TO_CHAR",
        "TIMEADD",
        "TIMEDIFF",
    ] {
        let mut sig = scalar(name, NullBehavior::Strict, unspec);
        sig.is_temporal = true;
        catalog.register(sig);
    }
    let mut date_sub = scalar("DATE_SUB", NullBehavior::Strict, fixed2);
    date_sub.is_temporal = true;
    catalog.register(date_sub);
    for name in ["YEAR", "MONTH", "DAY", "HOUR", "MINUTE", "SECOND"] {
        let mut sig = scalar(name, NullBehavior::Strict, fixed1);
        sig.is_temporal = true;
        catalog.register(sig);
    }
    let mut convert_tz = scalar("CONVERT_TIMEZONE", NullBehavior::Strict, unspec);
    convert_tz.is_temporal = true;
    catalog.register(convert_tz);

    // Spark / Databricks lateral scalars. `EXPLODE` in a select list
    // yields a row per element.
    let mut explode = scalar("EXPLODE", NullBehavior::Strict, fixed1);
    explode.generates_rows = true;
    catalog.register(explode);
    catalog.register(scalar("FROM_JSON", NullBehavior::Strict, fixed2));

    // Snowflake type-checking predicates: NULL → NULL by spec.
    for name in [
        "IS_OBJECT",
        "IS_ARRAY",
        "IS_INTEGER",
        "IS_FLOAT",
        "IS_BOOLEAN",
        "IS_VARCHAR",
        "IS_NULL_VALUE",
        "IS_BINARY",
        "IS_DATE",
        "IS_TIME",
        "IS_TIMESTAMP_LTZ",
        "IS_TIMESTAMP_NTZ",
        "IS_TIMESTAMP_TZ",
    ] {
        catalog.register(scalar(name, NullBehavior::Strict, fixed1));
    }

    // Semi-structured serialization.
    catalog.register(scalar("TO_JSON", NullBehavior::Strict, fixed1));

    // ── Volatile builtins ──────────────────────────────────────
    // All return non-null values (current time, random, UUID). The
    // current-time family additionally carries `is_temporal = true`
    // so consumers can distinguish them from the
    // non-temporal volatiles (`RANDOM`, `UUID_STRING`). The current time
    // is read once per statement: each call in it returns one value.
    for name in [
        "CURRENT_TIMESTAMP",
        "CURRENT_DATE",
        "CURRENT_TIME",
        "NOW",
        "SYSDATE",
        "LOCALTIME",
        "LOCALTIMESTAMP",
        "GETDATE",
    ] {
        let mut sig = scalar_volatile(name, unspec);
        sig.is_temporal = true;
        let id = catalog.register(sig);
        catalog.statement_stable.insert(id);
    }
    // The current time under other dialects' spellings.
    for name in ["UTC_DATE", "UTC_TIME", "UTC_TIMESTAMP", "CURRENT_DATETIME"] {
        let mut sig = scalar_volatile(name, unspec);
        sig.is_temporal = true;
        let id = catalog.register(sig);
        catalog.statement_stable.insert(id);
    }
    // The session's user, role and place: one value for the session, and
    // NULL for some (PostgreSQL's `current_schema` with an empty search
    // path, Snowflake's `CURRENT_USER` in a shared view).
    for name in [
        "CURRENT_USER",
        "SESSION_USER",
        "USER",
        "SYSTEM_USER",
        "CURRENT_ROLE",
        "CURRENT_CATALOG",
        "CURRENT_SCHEMA",
        "CURRENT_USER_ID",
    ] {
        let mut sig = scalar(name, NullBehavior::Unknown, unspec);
        sig.determinism = Determinism::Stable;
        catalog.register(sig);
    }
    for name in ["RANDOM", "RAND", "UUID_STRING", "GEN_RANDOM_UUID"] {
        catalog.register(scalar_volatile(name, unspec));
    }

    // ── Never-null deterministic scalars ───────────────────────
    // `OBJECT_CONSTRUCT` / `ARRAY_CONSTRUCT` always return a
    // non-null container. Sequence generators always yield an
    // integer. `UNIFORM` / `ZIPF` always yield a value.
    catalog.register(scalar(
        "OBJECT_CONSTRUCT",
        NullBehavior::NeverNull,
        ArgShape::Variadic { min_positional: 0 },
    ));
    catalog.register(scalar(
        "ARRAY_CONSTRUCT",
        NullBehavior::NeverNull,
        ArgShape::Variadic { min_positional: 0 },
    ));
    for name in ["SEQ4", "SEQ8", "SEQ1", "SEQ2"] {
        catalog.register(scalar(
            name,
            NullBehavior::NeverNull,
            ArgShape::Fixed { arity: 0 },
        ));
    }
    catalog.register(scalar(
        "UNIFORM",
        NullBehavior::NeverNull,
        ArgShape::Variadic { min_positional: 2 },
    ));
    catalog.register(scalar("ZIPF", NullBehavior::NeverNull, unspec));
    // GROUPING / GROUPING_ID return 0/1 indicators — never null.
    catalog.register(scalar("GROUPING", NullBehavior::NeverNull, unspec));
    catalog.register(scalar("GROUPING_ID", NullBehavior::NeverNull, unspec));

    // ── Try-cast / try-parse: explicitly nullable on failure ──
    // These return NULL when the conversion fails — null behavior
    // is genuinely conditional and not classifiable as Strict.
    // The temporal try-cast helpers carry `is_temporal = true`.
    for name in [
        "TRY_PARSE_JSON",
        "TRY_TO_NUMBER",
        "TRY_TO_DECIMAL",
        "TRY_TO_DOUBLE",
        "TRY_CAST",
    ] {
        catalog.register(scalar(name, NullBehavior::Unknown, unspec));
    }
    for name in ["TRY_TO_DATE", "TRY_TO_TIMESTAMP"] {
        let mut sig = scalar(name, NullBehavior::Unknown, unspec);
        sig.is_temporal = true;
        catalog.register(sig);
    }

    // ── Regex / string functions whose null behavior is dialect-
    // dependent (REGEXP_SUBSTR returns NULL on no-match, etc.). ─
    for name in [
        "REGEXP_SUBSTR",
        "REGEXP_REPLACE",
        "REGEXP_COUNT",
        "REGEXP_INSTR",
        "REGEXP_LIKE",
        "RLIKE",
        "TO_VARCHAR",
    ] {
        catalog.register(scalar(name, NullBehavior::Unknown, unspec));
    }

    // ── Semi-structured access / manipulation ─────────────────
    // Path access on null base returns null; on missing key
    // returns null too. Conservative.
    for name in [
        "PARSE_JSON",
        "GET_PATH",
        "GET",
        "ARRAY_SIZE",
        "ARRAY_APPEND",
        "ARRAY_PREPEND",
        "ARRAY_CONTAINS",
        "ARRAY_POSITION",
        "ARRAY_SLICE",
        "ARRAY_CAT",
        "ARRAY_DISTINCT",
        "ARRAY_INTERSECTION",
        "ARRAY_COMPACT",
        "ARRAY_FLATTEN",
        "ARRAY_TO_STRING",
        "ARRAYS_OVERLAP",
        "STRTOK_TO_ARRAY",
        "AS_OBJECT",
        "AS_ARRAY",
        "AS_INTEGER",
        "AS_FLOAT",
        "AS_BOOLEAN",
        "AS_VARCHAR",
        "AS_BINARY",
        "OBJECT_KEYS",
        "OBJECT_INSERT",
        "OBJECT_DELETE",
        "OBJECT_PICK",
        "STRIP_NULL_VALUE",
        "MAP_CONTAINS_KEY",
        "MAP_KEYS",
        "MAP_VALUES",
        "MAP_SIZE",
        "MAP_ENTRIES",
        "MAP_DELETE",
        "MAP_INSERT",
        "MAP_PICK",
    ] {
        catalog.register(scalar(name, NullBehavior::Unknown, unspec));
    }

    // ── DECODE: Oracle's CASE-like; conditional null behavior ──
    catalog.register(scalar("DECODE", NullBehavior::Unknown, unspec));

    // ── MATCH_RECOGNIZE context functions ──────────────────────
    catalog.register(scalar(
        "MATCH_NUMBER",
        NullBehavior::NeverNull,
        ArgShape::Fixed { arity: 0 },
    ));
    catalog.register(scalar("PREV", NullBehavior::Unknown, unspec));
    catalog.register(scalar(
        "CLASSIFIER",
        NullBehavior::Unknown,
        ArgShape::Fixed { arity: 0 },
    ));

    // ── Table-valued functions in scalar position ──────────────
    // `OUTER => TRUE` makes it yield a row of NULLs for an empty input.
    catalog.register(FunctionSignature {
        rows_per_input: RowsPerInput::AtLeastOneWhenOuter,
        ..scalar("FLATTEN", NullBehavior::Unknown, unspec)
    });
    catalog.register(scalar("GENERATOR", NullBehavior::Unknown, unspec));
    // Those that split a string or expand a document into rows: Snowflake's,
    // SQL Server's, and MySQL's `JSON_TABLE`.
    for name in [
        "SPLIT_TO_TABLE",
        "STRTOK_SPLIT_TO_TABLE",
        "STRING_SPLIT",
        "OPENJSON",
        "JSON_TABLE",
    ] {
        catalog.register(scalar(name, NullBehavior::Unknown, unspec));
    }

    // ── Set-returning functions callable in a select list ──────
    // PostgreSQL's, then Spark's generators beside `EXPLODE`. What each
    // yields for a NULL argument is not classified; Spark's outer ones yield
    // a row of NULLs for an empty or NULL input.
    let (unknown, at_least_one) = (RowsPerInput::Unknown, RowsPerInput::AtLeastOne);
    for (name, rows_per_input) in [
        ("UNNEST", unknown),
        ("GENERATE_SERIES", unknown),
        ("GENERATE_SUBSCRIPTS", unknown),
        ("REGEXP_SPLIT_TO_TABLE", unknown),
        ("REGEXP_MATCHES", unknown),
        ("JSON_ARRAY_ELEMENTS", unknown),
        ("JSON_ARRAY_ELEMENTS_TEXT", unknown),
        ("JSONB_ARRAY_ELEMENTS", unknown),
        ("JSONB_ARRAY_ELEMENTS_TEXT", unknown),
        ("JSON_EACH", unknown),
        ("JSON_EACH_TEXT", unknown),
        ("JSONB_EACH", unknown),
        ("JSONB_EACH_TEXT", unknown),
        ("JSON_OBJECT_KEYS", unknown),
        ("JSONB_OBJECT_KEYS", unknown),
        ("EXPLODE_OUTER", at_least_one),
        ("POSEXPLODE", unknown),
        ("POSEXPLODE_OUTER", at_least_one),
        ("INLINE", unknown),
        ("INLINE_OUTER", at_least_one),
        ("STACK", unknown),
        ("STRING_TO_TABLE", unknown),
        ("JSONB_PATH_QUERY", unknown),
    ] {
        let mut sig = scalar(name, NullBehavior::Unknown, unspec);
        sig.generates_rows = true;
        sig.rows_per_input = rows_per_input;
        catalog.register(sig);
    }
    // PostgreSQL's that it does not declare immutable, or whose class is
    // not confirmed here: stable, which claims the less.
    for name in [
        "JSONB_PATH_QUERY_TZ",
        "JSON_POPULATE_RECORDSET",
        "JSONB_POPULATE_RECORDSET",
        "JSON_TO_RECORDSET",
        "JSONB_TO_RECORDSET",
        "TS_DEBUG",
        "TS_PARSE",
        "TS_TOKEN_TYPE",
        "ACLEXPLODE",
        "PG_OPTIONS_TO_TABLE",
        "TXID_SNAPSHOT_XIP",
        "PG_SNAPSHOT_XIP",
    ] {
        let mut sig = scalar(name, NullBehavior::Unknown, unspec);
        sig.determinism = Determinism::Stable;
        sig.generates_rows = true;
        catalog.register(sig);
    }
    // Those that return a set of one base value: BigQuery's `UNNEST`,
    // whose alias is the element, and the PostgreSQL functions declared
    // `setof` a base type, whose one column takes the table alias's name.
    for name in ONE_VALUE_FUNCTIONS {
        catalog.restate(name, SignatureChange::YieldsOneValue(true));
    }
    // Spark's generator `json_tuple` yields one row per input row: the
    // named fields' values.
    catalog.register(scalar("JSON_TUPLE", NullBehavior::Unknown, unspec));
}

/// The seeded functions that, called as a table, yield one value column
/// the call's alias names.
const ONE_VALUE_FUNCTIONS: [&str; 12] = [
    "UNNEST",
    "GENERATE_SERIES",
    "GENERATE_SUBSCRIPTS",
    "REGEXP_SPLIT_TO_TABLE",
    "STRING_TO_TABLE",
    "JSON_ARRAY_ELEMENTS",
    "JSON_ARRAY_ELEMENTS_TEXT",
    "JSONB_ARRAY_ELEMENTS",
    "JSONB_ARRAY_ELEMENTS_TEXT",
    "JSON_OBJECT_KEYS",
    "JSONB_OBJECT_KEYS",
    "JSONB_PATH_QUERY",
];

// ────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::AstFunctionReturns;
    use std::collections::BTreeSet;

    /// The per-script catalog of `sql`, parsed as PostgreSQL, and where
    /// each of its statements starts.
    fn script_functions(sql: &str) -> (ScriptFunctions, Vec<u32>) {
        let script = crate::parse_sql_with_dialect(sql, crate::dialect::postgres().as_ref())
            .expect("parses");
        let fold = crate::build_script_context_fold(&script, sql);
        let starts = script.stmts.iter().map(|stmt| stmt.span().start).collect();
        (
            ScriptFunctions::new(CatalogDialect::PostgreSql, &fold),
            starts,
        )
    }

    /// A dialect's catalog is built once for every clone of the
    /// catalogs, and again under another folding, whose names it keys as
    /// that folding does.
    #[test]
    fn dialect_catalogs_build_each_catalog_once_per_folding() {
        let catalogs = DialectCatalogs::default();
        let per_file = catalogs.clone();
        let snowflake = {
            let _folding = crate::ir::normalize::set_normalization_dialect("snowflake");
            let built = catalogs.for_dialect(CatalogDialect::Snowflake);
            assert!(Arc::ptr_eq(
                &built,
                &per_file.for_dialect(CatalogDialect::Snowflake)
            ));
            assert!(!Arc::ptr_eq(
                &built,
                &per_file.for_dialect(CatalogDialect::MySql)
            ));
            built
        };
        let _folding = crate::ir::normalize::set_normalization_dialect("postgresql");
        let refolded = per_file.for_dialect(CatalogDialect::Snowflake);
        assert!(!Arc::ptr_eq(&snowflake, &refolded));
        assert!(refolded.lookup("count").is_some());
        assert!(Arc::ptr_eq(
            &refolded,
            &catalogs.for_dialect(CatalogDialect::Snowflake)
        ));
    }

    #[test]
    fn a_script_declares_a_function_from_its_statement_on() {
        let _folding = crate::ir::normalize::default_folding();
        let (functions, starts) = script_functions(
            "SELECT f(1); \
             CREATE FUNCTION f(x int) RETURNS SETOF int LANGUAGE sql AS $$ SELECT 1 $$; \
             SELECT f(2); \
             CREATE OR REPLACE FUNCTION f(x int) RETURNS int LANGUAGE sql AS $$ SELECT 1 $$; \
             SELECT f(3)",
        );
        let declared: Vec<Option<AstFunctionReturns>> = starts
            .iter()
            .map(|start| functions.at(*start).declared_returns("f"))
            .collect();
        assert_eq!(
            declared,
            [
                None,
                Some(AstFunctionReturns::Set),
                Some(AstFunctionReturns::Set),
                Some(AstFunctionReturns::Scalar),
                Some(AstFunctionReturns::Scalar),
            ]
        );
    }

    #[test]
    fn a_declared_name_is_met_as_written() {
        let _folding = crate::ir::normalize::default_folding();
        let (functions, starts) = script_functions(
            "CREATE FUNCTION s.g(x int) RETURNS TABLE (n int) LANGUAGE sql AS $$ SELECT 1 $$; \
             SELECT 1",
        );
        let catalog = functions.at(starts[1]);
        assert_eq!(
            catalog.declared_returns("s.g"),
            Some(AstFunctionReturns::Table)
        );
        assert_eq!(
            catalog.declared_returns("S.G"),
            Some(AstFunctionReturns::Table)
        );
        assert_eq!(catalog.declared_returns("g"), None);
    }

    #[test]
    fn a_seeded_function_keeps_its_signature() {
        let _folding = crate::ir::normalize::default_folding();
        let (functions, starts) = script_functions(
            "CREATE FUNCTION generate_series(x int) RETURNS int LANGUAGE sql AS $$ SELECT 1 $$; \
             SELECT 1",
        );
        let catalog = functions.at(starts[1]);
        assert_eq!(catalog.declared_returns("generate_series"), None);
        let id = catalog.lookup("generate_series").expect("seeded");
        assert!(catalog.signature(id).expect("signature").generates_rows);
    }

    #[test]
    fn a_declared_iif_or_if_reads_the_seed_unless_qualified() {
        let _folding = crate::ir::normalize::default_folding();
        for name in ["iif", "if"] {
            let (functions, starts) = script_functions(&format!(
                "CREATE FUNCTION {name}(b bool, x int, y int) RETURNS SETOF int \
                 LANGUAGE sql AS $$ SELECT 1 $$; \
                 CREATE FUNCTION dbo.{name}(b bool, x int, y int) RETURNS SETOF int \
                 LANGUAGE sql AS $$ SELECT 1 $$; \
                 SELECT 1"
            ));
            let catalog = functions.at(starts[2]);
            // Unqualified: the seed's signature.
            assert_eq!(catalog.declared_returns(name), None, "{name}");
            let id = catalog.lookup(name).expect("seeded");
            assert_eq!(
                catalog.signature(id).expect("signature").null_behavior,
                NullBehavior::BranchOnCondition,
                "{name}"
            );
            // Qualified: the declaration.
            let qualified = format!("dbo.{name}");
            assert_eq!(catalog.lookup(&qualified), None, "{qualified}");
            assert_eq!(
                catalog.declared_returns(&qualified),
                Some(AstFunctionReturns::Set),
                "{qualified}"
            );
        }
    }

    #[test]
    fn empty_catalog_returns_none_for_lookup() {
        let _folding = crate::ir::normalize::default_folding();
        let cat = FunctionCatalog::empty();
        assert!(cat.lookup("COUNT").is_none());
    }

    #[test]
    fn register_allocates_sequential_ids() {
        let _folding = crate::ir::normalize::default_folding();
        let mut cat = FunctionCatalog::empty();
        let id_a = cat.register(agg("A", ArgShape::Fixed { arity: 1 }));
        let id_b = cat.register(agg("B", ArgShape::Fixed { arity: 1 }));
        assert_ne!(id_a, id_b);
        assert_eq!(cat.lookup("A"), Some(id_a));
        assert_eq!(cat.lookup("B"), Some(id_b));
    }

    #[test]
    fn register_is_idempotent_on_same_name() {
        let _folding = crate::ir::normalize::default_folding();
        let mut cat = FunctionCatalog::empty();
        let id1 = cat.register(agg("A", ArgShape::Fixed { arity: 1 }));
        let id2 = cat.register(agg("A", ArgShape::Fixed { arity: 2 }));
        // Second registration must return the SAME id; signatures are
        // append-only so ids stay stable across calls.
        assert_eq!(id1, id2);
    }

    #[test]
    fn lookup_is_case_insensitive_via_ident_key() {
        let _folding = crate::ir::normalize::default_folding();
        let mut cat = FunctionCatalog::empty();
        let id = cat.register(agg("COUNT", ArgShape::Variadic { min_positional: 0 }));
        assert_eq!(cat.lookup("count"), Some(id));
        assert_eq!(cat.lookup("Count"), Some(id));
        assert_eq!(cat.lookup("COUNT"), Some(id));
    }

    #[test]
    fn alias_points_to_existing_id() {
        let _folding = crate::ir::normalize::default_folding();
        let mut cat = FunctionCatalog::empty();
        let id = cat.register(agg("COUNT", ArgShape::Variadic { min_positional: 0 }));
        cat.alias("CARD", id);
        assert_eq!(cat.lookup("CARD"), Some(id));
    }

    #[test]
    #[should_panic(expected = "already registered to a different id")]
    fn alias_conflict_panics() {
        let _folding = crate::ir::normalize::default_folding();
        let mut cat = FunctionCatalog::empty();
        let a = cat.register(agg("A", ArgShape::Fixed { arity: 1 }));
        let _b = cat.register(agg("B", ArgShape::Fixed { arity: 1 }));
        // Trying to point "A" at B's id must fail — the name is
        // already mapped to A's id.
        let b_id = cat.lookup("B").unwrap();
        assert_ne!(a, b_id);
        cat.alias("A", b_id);
    }

    #[test]
    fn default_catalog_knows_core_aggregates() {
        let _folding = crate::ir::normalize::default_folding();
        let cat = FunctionCatalog::for_dialect(CatalogDialect::Default);
        for name in ["COUNT", "SUM", "AVG", "MIN", "MAX", "LISTAGG", "ARRAY_AGG"] {
            let id = cat
                .lookup(name)
                .unwrap_or_else(|| panic!("default catalog missing aggregate {name}"));
            assert!(
                cat.is_aggregate_shape(id),
                "catalog marks {name} as non-aggregate"
            );
            assert!(
                !cat.is_window_shape(id),
                "catalog marks {name} as window-shape"
            );
        }
    }

    #[test]
    fn default_catalog_knows_window_only_functions() {
        let _folding = crate::ir::normalize::default_folding();
        let cat = FunctionCatalog::for_dialect(CatalogDialect::Default);
        for name in ["ROW_NUMBER", "RANK", "LEAD", "LAG", "NTILE"] {
            let id = cat
                .lookup(name)
                .unwrap_or_else(|| panic!("default catalog missing window fn {name}"));
            assert!(cat.is_window_shape(id));
            assert!(!cat.is_aggregate_shape(id));
        }
    }

    #[test]
    fn the_seeded_functions_that_generate_rows() {
        let _folding = crate::ir::normalize::default_folding();
        let cat = FunctionCatalog::for_dialect(CatalogDialect::Default);
        let generating: Vec<&str> = cat
            .signatures
            .iter()
            .filter(|sig| sig.generates_rows)
            .map(|sig| sig.display_name.as_str())
            .collect();
        assert_eq!(
            generating,
            vec![
                "EXPLODE",
                "UNNEST",
                "GENERATE_SERIES",
                "GENERATE_SUBSCRIPTS",
                "REGEXP_SPLIT_TO_TABLE",
                "REGEXP_MATCHES",
                "JSON_ARRAY_ELEMENTS",
                "JSON_ARRAY_ELEMENTS_TEXT",
                "JSONB_ARRAY_ELEMENTS",
                "JSONB_ARRAY_ELEMENTS_TEXT",
                "JSON_EACH",
                "JSON_EACH_TEXT",
                "JSONB_EACH",
                "JSONB_EACH_TEXT",
                "JSON_OBJECT_KEYS",
                "JSONB_OBJECT_KEYS",
                "EXPLODE_OUTER",
                "POSEXPLODE",
                "POSEXPLODE_OUTER",
                "INLINE",
                "INLINE_OUTER",
                "STACK",
                "STRING_TO_TABLE",
                "JSONB_PATH_QUERY",
                "JSONB_PATH_QUERY_TZ",
                "JSON_POPULATE_RECORDSET",
                "JSONB_POPULATE_RECORDSET",
                "JSON_TO_RECORDSET",
                "JSONB_TO_RECORDSET",
                "TS_DEBUG",
                "TS_PARSE",
                "TS_TOKEN_TYPE",
                "ACLEXPLODE",
                "PG_OPTIONS_TO_TABLE",
                "TXID_SNAPSHOT_XIP",
                "PG_SNAPSHOT_XIP",
            ]
        );
        // None claims a result for a NULL argument, and none is volatile.
        for sig in cat.signatures.iter().filter(|sig| sig.generates_rows) {
            if sig.display_name != "EXPLODE" {
                assert_eq!(
                    sig.null_behavior,
                    NullBehavior::Unknown,
                    "{}",
                    sig.display_name
                );
            }
            assert_ne!(
                sig.determinism,
                Determinism::Volatile,
                "{}",
                sig.display_name
            );
        }
        // A table function of a `FROM` clause is not one of them.
        for name in [
            "FLATTEN",
            "GENERATOR",
            "SPLIT_TO_TABLE",
            "STRTOK_SPLIT_TO_TABLE",
            "STRING_SPLIT",
            "OPENJSON",
            "JSON_TABLE",
        ] {
            let id = cat.lookup(name).expect("seeded");
            assert!(
                !cat.signature(id).expect("signature").generates_rows,
                "{name}"
            );
        }
    }

    #[test]
    fn the_seeded_functions_whose_alias_names_their_one_column() {
        let _folding = crate::ir::normalize::default_folding();
        let cat = FunctionCatalog::for_dialect(CatalogDialect::Default);
        let one_value: Vec<&str> = cat
            .signatures
            .iter()
            .filter(|sig| sig.yields_one_value)
            .map(|sig| sig.display_name.as_str())
            .collect();
        assert_eq!(
            one_value,
            vec![
                "UNNEST",
                "GENERATE_SERIES",
                "GENERATE_SUBSCRIPTS",
                "REGEXP_SPLIT_TO_TABLE",
                "JSON_ARRAY_ELEMENTS",
                "JSON_ARRAY_ELEMENTS_TEXT",
                "JSONB_ARRAY_ELEMENTS",
                "JSONB_ARRAY_ELEMENTS_TEXT",
                "JSON_OBJECT_KEYS",
                "JSONB_OBJECT_KEYS",
                "STRING_TO_TABLE",
                "JSONB_PATH_QUERY",
            ]
        );
        // Each generates rows; a generator of several columns is none.
        for sig in cat.signatures.iter().filter(|sig| sig.yields_one_value) {
            assert!(sig.generates_rows, "{}", sig.display_name);
        }
        for name in [
            "JSON_EACH",
            "POSEXPLODE",
            "INLINE",
            "STACK",
            "EXPLODE",
            "FLATTEN",
        ] {
            assert!(!seeded(&cat, name).yields_one_value, "{name}");
        }
        // A dialect whose function of the name yields a named column, or
        // no rows at all.
        let tsql = FunctionCatalog::for_dialect(CatalogDialect::MsSql);
        assert!(!seeded(&tsql, "GENERATE_SERIES").yields_one_value);
        let spark = FunctionCatalog::for_dialect(CatalogDialect::Databricks);
        assert!(!seeded(&spark, "JSON_OBJECT_KEYS").yields_one_value);
        let postgres = FunctionCatalog::for_dialect(CatalogDialect::PostgreSql);
        assert!(seeded(&postgres, "GENERATE_SERIES").yields_one_value);
        assert!(seeded(&postgres, "JSON_OBJECT_KEYS").yields_one_value);
    }

    const DIALECTS: [CatalogDialect; 8] = [
        CatalogDialect::Default,
        CatalogDialect::Snowflake,
        CatalogDialect::BigQuery,
        CatalogDialect::PostgreSql,
        CatalogDialect::Databricks,
        CatalogDialect::MySql,
        CatalogDialect::MsSql,
        CatalogDialect::Redshift,
    ];

    fn seeded<'c>(cat: &'c FunctionCatalog, name: &str) -> &'c FunctionSignature {
        let id = cat.lookup(name).expect("seeded");
        cat.signature(id).expect("signature")
    }

    #[test]
    fn the_catalog_is_built_for_its_dialect() {
        let _folding = crate::ir::normalize::default_folding();
        for dialect in DIALECTS {
            let cat = FunctionCatalog::for_dialect(dialect);
            // Spark's `json_object_keys` returns one array.
            assert_eq!(
                seeded(&cat, "JSON_OBJECT_KEYS").generates_rows,
                dialect != CatalogDialect::Databricks,
                "{dialect:?}"
            );
        }
    }

    #[test]
    fn what_an_aggregate_gives_over_no_rows_is_stated_in_every_dialect() {
        let _folding = crate::ir::normalize::default_folding();
        for dialect in DIALECTS {
            let cat = FunctionCatalog::for_dialect(dialect);
            for name in ["SUM", "MAX", "AVG", "STDDEV", "CORR", "MEDIAN"] {
                assert_eq!(
                    seeded(&cat, name).over_no_rows,
                    Some(NoRowsValue::Null),
                    "{name} {dialect:?}"
                );
            }
            for name in ["COUNT", "COUNT_IF"] {
                assert_eq!(
                    seeded(&cat, name).over_no_rows,
                    Some(NoRowsValue::Zero),
                    "{name} {dialect:?}"
                );
            }
            for name in [
                "ARRAY_AGG",
                "LISTAGG",
                "BIT_AND",
                "BOOL_OR",
                "REGR_COUNT",
                "UPPER",
            ] {
                assert_eq!(seeded(&cat, name).over_no_rows, None, "{name} {dialect:?}");
            }
        }
    }

    #[test]
    fn the_table_functions_that_yield_a_row_for_every_input_row_are_stated() {
        let _folding = crate::ir::normalize::default_folding();
        for dialect in DIALECTS {
            let cat = FunctionCatalog::for_dialect(dialect);
            let rows = |name| seeded(&cat, name).rows_per_input;
            assert_eq!(
                rows("FLATTEN"),
                RowsPerInput::AtLeastOneWhenOuter,
                "{dialect:?}"
            );
            for name in ["EXPLODE_OUTER", "POSEXPLODE_OUTER", "INLINE_OUTER"] {
                assert_eq!(rows(name), RowsPerInput::AtLeastOne, "{name} {dialect:?}");
                assert!(seeded(&cat, name).generates_rows, "{name} {dialect:?}");
            }
            for name in [
                "UNNEST",
                "EXPLODE",
                "POSEXPLODE",
                "OPENJSON",
                "GENERATE_SERIES",
            ] {
                assert_eq!(rows(name), RowsPerInput::Unknown, "{name} {dialect:?}");
            }
        }
    }

    #[test]
    fn what_a_function_returns_for_null_is_stated_per_dialect() {
        let _folding = crate::ir::normalize::default_folding();
        use CatalogDialect as D;
        use NullBehavior as N;
        type Difference<'a> = (&'a str, N, &'a [(D, N)]);
        // Every function some dialect differs on, and where.
        let differs: [Difference<'_>; 4] = [
            (
                "CONCAT",
                N::Strict,
                &[(D::PostgreSql, N::NeverNull), (D::MsSql, N::NeverNull)],
            ),
            (
                "GREATEST",
                N::Strict,
                &[
                    (D::PostgreSql, N::NullOnlyWhenAllNull),
                    (D::MsSql, N::NullOnlyWhenAllNull),
                    (D::Databricks, N::NullOnlyWhenAllNull),
                    (D::Redshift, N::NullOnlyWhenAllNull),
                ],
            ),
            (
                "LEAST",
                N::Strict,
                &[
                    (D::PostgreSql, N::NullOnlyWhenAllNull),
                    (D::MsSql, N::NullOnlyWhenAllNull),
                    (D::Databricks, N::NullOnlyWhenAllNull),
                    (D::Redshift, N::NullOnlyWhenAllNull),
                ],
            ),
            ("TO_JSON", N::Strict, &[(D::BigQuery, N::Unknown)]),
        ];
        for dialect in DIALECTS {
            let cat = FunctionCatalog::for_dialect(dialect);
            for (name, seed, restated) in differs {
                let expected = restated
                    .iter()
                    .find(|(there, _)| *there == dialect)
                    .map_or(seed, |(_, returns)| *returns);
                assert_eq!(
                    seeded(&cat, name).null_behavior,
                    expected,
                    "{name} under {dialect:?}"
                );
            }
            // Functions no dialect differs on. The `ISNULL` that is a call
            // has two arguments.
            assert_eq!(
                seeded(&cat, "UPPER").null_behavior,
                N::Strict,
                "{dialect:?}"
            );
            assert_eq!(
                seeded(&cat, "ISNULL").null_behavior,
                N::CoalesceLike,
                "{dialect:?}"
            );
            // `IFF`, `IIF` and `IF` branch on a condition, `NVL2` on a test
            // of NULL.
            for name in ["IFF", "IIF", "IF"] {
                assert_eq!(
                    seeded(&cat, name).null_behavior,
                    N::BranchOnCondition,
                    "{name} under {dialect:?}"
                );
            }
            assert_eq!(
                seeded(&cat, "NVL2").null_behavior,
                N::BranchOnNotNull,
                "{dialect:?}"
            );
        }
        // The table restates the NULL behaviour of these and no other.
        let restated: BTreeSet<&str> = DIALECT_SIGNATURES
            .iter()
            .filter(|row| matches!(row.states, SignatureChange::NullBehavior(_)))
            .map(|row| row.function)
            .collect();
        let listed: BTreeSet<&str> = differs.iter().map(|(name, _, _)| *name).collect();
        assert_eq!(restated, listed);
    }

    #[test]
    fn a_dialect_restates_only_what_the_seed_lists_for_it() {
        let _folding = crate::ir::normalize::default_folding();
        let default = FunctionCatalog::for_dialect(CatalogDialect::Default);
        for dialect in DIALECTS {
            let cat = FunctionCatalog::for_dialect(dialect);
            // The same functions under the same ids.
            assert_eq!(cat.by_name, default.by_name, "{dialect:?}");
            // Whatever order the rows are in, and however many name one
            // function.
            let restated: BTreeSet<&str> = cat
                .signatures
                .iter()
                .zip(&default.signatures)
                .filter(|(own, seed)| own != seed)
                .map(|(own, _)| own.display_name.as_str())
                .collect();
            let listed: BTreeSet<&str> = DIALECT_SIGNATURES
                .iter()
                .filter(|restatement| restatement.dialect == dialect)
                .map(|restatement| restatement.function)
                .collect();
            assert_eq!(restated, listed, "{dialect:?}");
        }
        // `Default` is the seed as written.
        assert!(DIALECT_SIGNATURES
            .iter()
            .all(|restatement| restatement.dialect != CatalogDialect::Default));
    }

    #[test]
    fn every_restated_function_is_seeded() {
        let _folding = crate::ir::normalize::default_folding();
        let seed = FunctionCatalog::for_dialect(CatalogDialect::Default);
        for restatement in DIALECT_SIGNATURES {
            let signature = seed
                .lookup(restatement.function)
                .and_then(|id| seed.signature(id));
            assert_eq!(
                signature.map(|signature| signature.display_name.as_str()),
                Some(restatement.function),
                "{:?} restates {}, which the seed does not hold under that name",
                restatement.dialect,
                restatement.function
            );
        }
    }

    #[test]
    fn every_bare_function_is_seeded() {
        let _folding = crate::ir::normalize::default_folding();
        let seed = FunctionCatalog::for_dialect(CatalogDialect::Default);
        for row in BARE_VALUES {
            assert_ne!(row.dialect, CatalogDialect::Default);
            for function in row.functions {
                let signature = seed.lookup(function).and_then(|id| seed.signature(id));
                assert_eq!(
                    signature.map(|signature| signature.display_name.as_str()),
                    Some(*function),
                    "{:?} writes {function} bare, which the seed does not hold",
                    row.dialect
                );
            }
        }
    }

    #[test]
    fn a_user_or_role_is_neither_temporal_nor_never_null() {
        let _folding = crate::ir::normalize::default_folding();
        let seed = FunctionCatalog::for_dialect(CatalogDialect::Default);
        for name in [
            "CURRENT_USER",
            "SESSION_USER",
            "USER",
            "SYSTEM_USER",
            "CURRENT_ROLE",
            "CURRENT_CATALOG",
            "CURRENT_SCHEMA",
            "CURRENT_USER_ID",
        ] {
            let signature = seeded(&seed, name);
            assert!(!signature.is_temporal, "{name}");
            assert_ne!(signature.null_behavior, NullBehavior::NeverNull, "{name}");
        }
    }

    #[test]
    fn a_dialect_names_the_columns_of_its_table_functions() {
        let _folding = crate::ir::normalize::default_folding();
        let seed = FunctionCatalog::for_dialect(CatalogDialect::Default);
        for row in YIELDED_COLUMNS {
            let signature = seed.lookup(row.function).and_then(|id| seed.signature(id));
            assert_eq!(
                signature.map(|signature| signature.display_name.as_str()),
                Some(row.function),
                "{:?} names columns of {}, which the seed does not hold under that name",
                row.dialect,
                row.function
            );
            assert_ne!(row.dialect, CatalogDialect::Default, "{}", row.function);
        }
        let columns = |dialect: CatalogDialect, name: &str| {
            let cat = FunctionCatalog::for_dialect(dialect);
            cat.yielded_columns(cat.lookup(name).expect("seeded"))
                .map(|columns| (columns.names, columns.complete))
        };
        assert_eq!(
            columns(CatalogDialect::Snowflake, "FLATTEN"),
            Some((&["SEQ", "KEY", "PATH", "INDEX", "VALUE", "THIS"][..], true))
        );
        assert_eq!(columns(CatalogDialect::Default, "FLATTEN"), None);
        assert_eq!(columns(CatalogDialect::Snowflake, "STRING_SPLIT"), None);
        // `ordinal` too, where the third argument enables it.
        assert_eq!(
            columns(CatalogDialect::MsSql, "STRING_SPLIT"),
            Some((&["VALUE"][..], false))
        );
        assert_eq!(columns(CatalogDialect::PostgreSql, "UNNEST"), None);
        for dialect in DIALECTS {
            assert_eq!(
                FunctionCatalog::for_dialect(dialect).names_value_for_function(),
                dialect == CatalogDialect::PostgreSql,
                "{dialect:?}"
            );
        }
    }

    #[test]
    fn every_spark_generator_is_catalogued() {
        let _folding = crate::ir::normalize::default_folding();
        let spark = FunctionCatalog::for_dialect(CatalogDialect::Databricks);
        // The generator functions a `LATERAL VIEW` takes.
        for name in [
            "EXPLODE",
            "EXPLODE_OUTER",
            "POSEXPLODE",
            "POSEXPLODE_OUTER",
            "INLINE",
            "INLINE_OUTER",
            "STACK",
            "JSON_TUPLE",
        ] {
            assert_eq!(
                seeded(&spark, name).determinism,
                Determinism::Deterministic,
                "{name}"
            );
        }
        // `json_tuple` yields one row per input row.
        assert!(!seeded(&spark, "JSON_TUPLE").generates_rows);
    }

    #[test]
    fn a_lexer_dialect_names_its_catalog() {
        use crate::dialect;
        // Every dialect the lexer crate constructs. It exposes no list of
        // them: a new one is added here, with its variant and its arm of
        // `from_dialect_name`.
        for (dialect, expected) in [
            (dialect::snowflake(), CatalogDialect::Snowflake),
            (dialect::bigquery(), CatalogDialect::BigQuery),
            (dialect::postgres(), CatalogDialect::PostgreSql),
            (dialect::databricks(), CatalogDialect::Databricks),
            (dialect::mysql(), CatalogDialect::MySql),
            (dialect::mssql(), CatalogDialect::MsSql),
            (dialect::redshift(), CatalogDialect::Redshift),
        ] {
            let named = CatalogDialect::from_dialect_name(dialect.name());
            assert_eq!(named, expected, "{}", dialect.name());
            // By an arm of its own, not by falling through.
            assert_ne!(named, CatalogDialect::Default, "{}", dialect.name());
        }
        // An alias the command line accepts, and another casing.
        for name in ["postgres", "pg", "PostgreSQL", "tsql", "spark"] {
            assert_eq!(
                CatalogDialect::from_dialect_name(name),
                CatalogDialect::Default,
                "{name}"
            );
        }
    }

    #[test]
    fn a_seeded_set_returning_call_is_resolved() {
        const RESOLVED_CALL_RULE: &str = r#"
rules:
  - id: TEST-CALL-RESOLVED
    risk_level: info
    message: "a select item is a call to a function the catalog knows"
    triggers:
      query.scopes:
        exists:
          projections:
            exists:
              all_of:
                - expr.kind: func_call
                - expr.func_call.catalog_resolved: true
"#;
        let custom = crate::rules::load_v1_rules(RESOLVED_CALL_RULE).expect("rule parses");
        let config = crate::analyzer::AnalysisConfig {
            dialect: Some(crate::dialect::postgres()),
            custom_rules: Some(
                crate::rules::build_v1_rule_corpus(custom, true)
                    .expect("rules merge")
                    .into(),
            ),
            ..Default::default()
        };
        let fires = |sql: &str| {
            crate::api::analyze_risk_with_policy_config(sql, &config)
                .expect("analyzes")
                .entries()
                .any(|finding| finding.rule_id() == Some("TEST-CALL-RESOLVED"))
        };
        assert!(fires("SELECT id, generate_series(1, n) FROM t"));
        assert!(!fires("SELECT id, my_series(1, n) FROM t"));
    }

    #[test]
    fn a_call_of_iif_or_if_is_published_as_the_catalogs() {
        const BUILT_IN_CALL_RULE: &str = r#"
rules:
  - id: TEST-CALL-BUILT-IN
    risk_level: info
    message: "a select item is a deterministic call the catalog knows"
    triggers:
      query.scopes:
        exists:
          projections:
            exists:
              all_of:
                - expr.kind: func_call
                - expr.func_call.catalog_resolved: true
                - expr.func_call.is_deterministic: true
                - expr.func_call.name.raw:
                    in: [IIF, IF]
"#;
        let fires = |sql: &str, dialect: crate::dialect::DialectRef| {
            let custom = crate::rules::load_v1_rules(BUILT_IN_CALL_RULE).expect("rule parses");
            let config = crate::analyzer::AnalysisConfig {
                dialect: Some(dialect),
                custom_rules: Some(
                    crate::rules::build_v1_rule_corpus(custom, true)
                        .expect("rules merge")
                        .into(),
                ),
                ..Default::default()
            };
            crate::api::analyze_risk_with_policy_config(sql, &config)
                .expect("analyzes")
                .entries()
                .any(|finding| finding.rule_id() == Some("TEST-CALL-BUILT-IN"))
        };
        for (sql, dialect) in [
            (
                "SELECT iif(a > 0, 'p', 'n') FROM t",
                crate::dialect::mssql(),
            ),
            ("SELECT if(a > 0, 'p', 'n') FROM t", crate::dialect::mysql()),
            (
                "SELECT IF(a > 0, 'p', 'n') FROM t",
                crate::dialect::bigquery(),
            ),
            (
                "SELECT if(a > 0, 'p', 'n') FROM t",
                crate::dialect::databricks(),
            ),
        ] {
            assert!(fires(sql, dialect.clone()), "{sql} in {}", dialect.name());
        }
        // A function the catalog does not know.
        assert!(!fires(
            "SELECT iif2(a > 0, 'p', 'n') FROM t",
            crate::dialect::mssql()
        ));
    }

    #[test]
    fn classifier_claims_no_not_null() {
        let _folding = crate::ir::normalize::default_folding();
        for dialect in DIALECTS {
            let cat = FunctionCatalog::for_dialect(dialect);
            assert_ne!(
                seeded(&cat, "CLASSIFIER").null_behavior,
                NullBehavior::NeverNull,
                "{dialect:?}"
            );
        }
    }

    #[test]
    fn forged_id_returns_none_and_conservative_shape() {
        let _folding = crate::ir::normalize::default_folding();
        let cat = FunctionCatalog::for_dialect(CatalogDialect::Default);
        let forged = FunctionId(u32::MAX);
        assert!(cat.signature(forged).is_none());
        assert!(cat.kind(forged).is_none());
        assert!(!cat.is_aggregate_shape(forged));
        assert!(!cat.is_window_shape(forged));
    }
}
