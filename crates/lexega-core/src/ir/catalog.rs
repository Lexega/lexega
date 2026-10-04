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

use std::collections::HashMap;
use std::fmt;

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
    pub(crate) fn from_index(idx: u32) -> Self {
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
    /// Result is null iff every argument from index 1 onward is
    /// null. The first argument is the test expression — it
    /// selects which value branch is taken but does not contribute
    /// its null status to the output value. Examples: `IFF`,
    /// `NVL2`, `IF` (the function form, not the SQL `IF`
    /// statement).
    ConditionalAfterFirst,
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
}

impl FunctionCatalog {
    /// Empty catalog. Every lookup returns `None`; every call becomes
    /// [`super::ResolvedFunc::Unresolved`]. Useful for tests that
    /// don't care about catalog-backed analysis.
    pub fn empty() -> Self {
        Self {
            signatures: Vec::new(),
            by_name: HashMap::new(),
        }
    }

    /// Build the default catalog for a dialect. The
    /// seeding covers aggregate and window-only functions across all
    /// dialects we target; scalar functions mostly remain
    /// [`super::ResolvedFunc::Unresolved`] and behave as plain scalar
    /// calls at permissive mode.
    pub fn for_dialect(_dialect: CatalogDialect) -> Self {
        let mut catalog = Self::empty();
        seed_aggregates(&mut catalog);
        seed_window_only(&mut catalog);
        seed_common_scalars(&mut catalog);
        catalog
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

/// Dialect selector for [`FunctionCatalog::for_dialect`]. Kept as a
/// dedicated type so the catalog module does not couple to the full
/// [`crate::dialect::Dialect`] surface — the catalog cares only about
/// which builtin tables to seed.
///
/// `Default` is treated as the cross-dialect superset (every
/// aggregate / window function we know about, regardless of which
/// engine it originates from). Per-dialect pruning is a later
/// refinement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CatalogDialect {
    Default,
    Snowflake,
    BigQuery,
    PostgreSql,
    Databricks,
    MySql,
    MsSql,
}

// ────────────────────────────────────────────────────────────────────────
// Builtin seeding
// ────────────────────────────────────────────────────────────────────────

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
    });
    let _ = count; // kept for clarity; aliasing intentional next line
    catalog.register(agg("SUM", fixed1));
    catalog.register(agg("AVG", fixed1));
    catalog.register(agg("MIN", fixed1));
    catalog.register(agg("MAX", fixed1));
    catalog.register(agg("ANY_VALUE", fixed1));

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
        catalog.register(agg(name, fixed1));
    }
    // Two-argument statistical aggregates.
    for name in [
        "CORR",
        "COVAR_POP",
        "COVAR_SAMP",
        "REGR_SLOPE",
        "REGR_INTERCEPT",
        "REGR_R2",
        "REGR_COUNT",
        "REGR_AVGX",
        "REGR_AVGY",
        "REGR_SXX",
        "REGR_SYY",
        "REGR_SXY",
    ] {
        catalog.register(agg(name, ArgShape::Fixed { arity: 2 }));
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
        catalog.register(agg(name, unspec));
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
    });
    catalog.register(FunctionSignature {
        display_name: "LAST".to_string(),
        kind: FunctionKind::WindowAggregate,
        null_behavior: NullBehavior::Unknown,
        determinism: Determinism::Deterministic,
        arg_shape: ArgShape::Unspecified,
        is_ranking: false,
        is_temporal: false,
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
    // Result null iff every value branch (args[1..]) is null.
    // First arg is the test expression — selects the branch.
    catalog.register(scalar(
        "IFF",
        NullBehavior::ConditionalAfterFirst,
        ArgShape::Fixed { arity: 3 },
    ));
    catalog.register(scalar(
        "NVL2",
        NullBehavior::ConditionalAfterFirst,
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

    // Spark / Databricks lateral scalars.
    catalog.register(scalar("EXPLODE", NullBehavior::Strict, fixed1));
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
    // non-temporal volatiles (`RANDOM`, `UUID_STRING`).
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
    catalog.register(scalar("FLATTEN", NullBehavior::Unknown, unspec));
    catalog.register(scalar("GENERATOR", NullBehavior::Unknown, unspec));
}

// ────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_catalog_returns_none_for_lookup() {
        let cat = FunctionCatalog::empty();
        assert!(cat.lookup("COUNT").is_none());
    }

    #[test]
    fn register_allocates_sequential_ids() {
        let mut cat = FunctionCatalog::empty();
        let id_a = cat.register(agg("A", ArgShape::Fixed { arity: 1 }));
        let id_b = cat.register(agg("B", ArgShape::Fixed { arity: 1 }));
        assert_ne!(id_a, id_b);
        assert_eq!(cat.lookup("A"), Some(id_a));
        assert_eq!(cat.lookup("B"), Some(id_b));
    }

    #[test]
    fn register_is_idempotent_on_same_name() {
        let mut cat = FunctionCatalog::empty();
        let id1 = cat.register(agg("A", ArgShape::Fixed { arity: 1 }));
        let id2 = cat.register(agg("A", ArgShape::Fixed { arity: 2 }));
        // Second registration must return the SAME id; signatures are
        // append-only so ids stay stable across calls.
        assert_eq!(id1, id2);
    }

    #[test]
    fn lookup_is_case_insensitive_via_ident_key() {
        let mut cat = FunctionCatalog::empty();
        let id = cat.register(agg("COUNT", ArgShape::Variadic { min_positional: 0 }));
        assert_eq!(cat.lookup("count"), Some(id));
        assert_eq!(cat.lookup("Count"), Some(id));
        assert_eq!(cat.lookup("COUNT"), Some(id));
    }

    #[test]
    fn alias_points_to_existing_id() {
        let mut cat = FunctionCatalog::empty();
        let id = cat.register(agg("COUNT", ArgShape::Variadic { min_positional: 0 }));
        cat.alias("CARD", id);
        assert_eq!(cat.lookup("CARD"), Some(id));
    }

    #[test]
    #[should_panic(expected = "already registered to a different id")]
    fn alias_conflict_panics() {
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
    fn forged_id_returns_none_and_conservative_shape() {
        let cat = FunctionCatalog::for_dialect(CatalogDialect::Default);
        let forged = FunctionId(u32::MAX);
        assert!(cat.signature(forged).is_none());
        assert!(cat.kind(forged).is_none());
        assert!(!cat.is_aggregate_shape(forged));
        assert!(!cat.is_window_shape(forged));
    }
}
