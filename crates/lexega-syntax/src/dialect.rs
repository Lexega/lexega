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

/// Stack-allocated ASCII uppercase copy of a word, for keyword matching
/// without the heap allocation `str::to_uppercase()` costs on every call.
///
/// SQL keywords are pure ASCII and shorter than the buffer, so a word that
/// is longer or holds a non-ASCII byte is kept as the empty string, which
/// matches no keyword.
struct AsciiUpper {
    buf: [u8; 64],
    len: usize,
}

impl AsciiUpper {
    #[inline]
    fn new(word: &str) -> Self {
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
    fn as_str(&self) -> &str {
        // The buffer holds ASCII only, which is always valid UTF-8.
        std::str::from_utf8(&self.buf[..self.len]).unwrap_or_default()
    }
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

    /// Whether `/*!...*/` version comments should be tagged as executable content.
    /// MySQL: true (version comments contain conditional SQL).
    /// Snowflake/PostgreSQL: false (all `/* */` are plain block comments).
    fn supports_version_comments(&self) -> bool {
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
    fn uses_optional_statement_terminators(&self) -> bool {
        false
    }

    /// Whether `SELECT ... INTO new_table` creates a table (MSSQL/T-SQL and
    /// PostgreSQL), rather than assigning into scripting variables (Snowflake).
    fn select_into_creates_table(&self) -> bool {
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
    /// (`INSERT t (a) VALUES (1)`) (MySQL).
    fn supports_insert_optional_into(&self) -> bool {
        false
    }

    /// Whether the `INSERT ... SET col = expr, ...` assignment form is
    /// supported (MySQL).
    fn supports_insert_set_form(&self) -> bool {
        false
    }

    /// Whether `INSERT INTO t PARTITION (p, ...)` partition selection is
    /// supported between the target table and the column list (MySQL).
    fn supports_insert_partition_clause(&self) -> bool {
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
    /// post-projection position (MySQL).
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

    /// MySQL `TABLE tbl [ORDER BY col] [LIMIT n [OFFSET m]]` statement — a
    /// query-bearing shorthand for `SELECT * FROM tbl ...`. Routes a leading
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
    fn name(&self) -> &'static str {
        "snowflake"
    }

    // ========================================================================
    // Keyword Rules
    // ========================================================================

    fn is_reserved_keyword(&self, word: &str) -> bool {
        // Snowflake reserved keywords (subset - expand as needed)
        matches!(
            AsciiUpper::new(word).as_str(),
            "SELECT"
                | "FROM"
                | "WHERE"
                | "JOIN"
                | "ON"
                | "AS"
                | "AND"
                | "OR"
                | "NOT"
                | "IN"
                | "IS"
                | "NULL"
                | "TRUE"
                | "FALSE"
                | "CASE"
                | "WHEN"
                | "THEN"
                | "ELSE"
                | "END"
                | "CREATE"
                | "DROP"
                | "ALTER"
                | "TABLE"
                | "VIEW"
                | "INDEX"
                | "DATABASE"
                | "SCHEMA"
                | "INSERT"
                | "UPDATE"
                | "DELETE"
                | "MERGE"
                | "TRUNCATE"
                | "ORDER"
                | "BY"
                | "GROUP"
                | "HAVING"
                | "DISTINCT"
                | "ALL"
                | "LIMIT"
                | "OFFSET"
                | "UNION"
                | "INTERSECT"
                | "EXCEPT"
                | "WITH"
                | "RECURSIVE"
                | "QUALIFY"
                | "WINDOW"
        )
    }

    fn is_keyword(&self, word: &str) -> bool {
        // Snowflake reserved + unreserved keywords
        // Unreserved keywords have syntactic meaning but CAN be used as unquoted identifiers.
        // https://docs.snowflake.com/en/sql-reference/reserved-keywords
        self.is_reserved_keyword(word)
            || matches!(
                AsciiUpper::new(word).as_str(),
                // Join modifiers
                "INNER" | "OUTER" | "LEFT" | "RIGHT" | "FULL" | "CROSS" | "NATURAL" | "LATERAL"
            | "ASOF"
            // Window / analytic
            | "OVER" | "PARTITION" | "ROWS" | "RANGE" | "UNBOUNDED" | "PRECEDING" | "FOLLOWING"
            | "CURRENT" | "ROW" | "WINDOW"
            // Ordering
            | "ASC" | "DESC" | "NULLS" | "FIRST" | "LAST"
            // Snowflake-specific clauses
            | "QUALIFY" | "SAMPLE" | "TABLESAMPLE" | "PIVOT" | "UNPIVOT" | "FLATTEN"
            | "MATCH_RECOGNIZE" | "MEASURES" | "DEFINE" | "PATTERN" | "EXCLUDE"
            // DDL / object types
            | "IF" | "EXISTS" | "REPLACE" | "TEMPORARY" | "TRANSIENT" | "SECURE" | "RECURSIVE"
            | "VOLATILE" | "IMMUTABLE" | "MATERIALIZED"
            | "STAGE" | "FUNCTION" | "PROCEDURE" | "SEQUENCE" | "STREAM" | "TASK" | "PIPE"
            | "INTEGRATION" | "FILE" | "FORMAT" | "WAREHOUSE" | "SHARE" | "ROLE" | "USER"
            | "NETWORK" | "POLICY" | "TAG" | "MASKING" | "GRANT" | "REVOKE"
            // Table / column constraints
            | "PRIMARY" | "FOREIGN" | "KEY" | "REFERENCES" | "UNIQUE" | "CHECK" | "CONSTRAINT"
            | "CASCADE" | "RESTRICT" | "NO" | "ACTION" | "CLUSTER"
            // DML helpers
            | "INTO" | "VALUES" | "SET" | "DEFAULT" | "USING" | "RETURNING"
            | "DO" | "NOTHING" | "CONFLICT"
            // Expressions / functions
            | "CAST" | "LIKE" | "ILIKE" | "RLIKE" | "REGEXP" | "ESCAPE" | "BETWEEN"
            | "ANY" | "SOME" | "INTERVAL" | "AT" | "BEFORE"
            // Built-in temporal keywords
            | "CURRENT_DATE" | "CURRENT_TIME" | "CURRENT_TIMESTAMP" | "CURRENT_USER"
            | "LOCALTIME" | "LOCALTIMESTAMP"
            // Scripting / control flow
            | "BEGIN" | "END" | "DECLARE" | "RETURN" | "FOR" | "WHILE" | "REPEAT" | "UNTIL"
            | "LOOP" | "BREAK" | "CONTINUE" | "TRY" | "CATCH" | "RAISE" | "EXCEPTION"
            | "ELSEIF"
            | "CALL" | "EXECUTE" | "IMMEDIATE"
            // Transaction
            | "COMMIT" | "ROLLBACK" | "START" | "TRANSACTION" | "WORK"
            // COPY / stage
            | "COPY" | "URL" | "STORAGE" | "CREDENTIALS" | "ENCRYPTION" | "DIRECTORY"
            // Type keywords
            | "BOOLEAN" | "VARCHAR" | "CHAR" | "CHARACTER" | "STRING" | "TEXT"
            | "NUMBER" | "NUMERIC" | "DECIMAL" | "INTEGER" | "INT" | "BIGINT"
            | "SMALLINT" | "TINYINT" | "FLOAT" | "DOUBLE" | "REAL"
            | "DATE" | "TIME" | "TIMESTAMP" | "VARIANT" | "OBJECT" | "ARRAY"
            // Misc
            | "COMMENT" | "RENAME" | "COLUMN" | "SHOW" | "DESCRIBE" | "USE" | "TOP"
            | "LANGUAGE" | "BODY" | "OWNER" | "CALLER" | "ENABLE" | "TYPE"
            | "COMPRESSION" | "NOTIFY" | "ACCESS"
            )
    }

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
        assert!(!dialect.is_reserved_keyword("my_column"));

        // Unreserved keywords should NOT be reserved
        assert!(!dialect.is_reserved_keyword("OVER"));
        assert!(!dialect.is_reserved_keyword("PARTITION"));
        assert!(!dialect.is_reserved_keyword("ROWS"));
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

        // Double-quoted strings are identifiers, NOT string literals (unlike BigQuery)
        assert!(!dialect.supports_double_quoted_strings());

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

        // Alias-restricted words (Databricks reserved-words doc)
        assert!(dialect.is_reserved_keyword("ANTI"));
        assert!(dialect.is_reserved_keyword("JOIN"));
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

    fn is_reserved_keyword(&self, word: &str) -> bool {
        // PostgreSQL reserved keywords (core subset)
        // Full list: https://www.postgresql.org/docs/current/sql-keywords-appendix.html
        matches!(
            AsciiUpper::new(word).as_str(),
            "SELECT"
                | "FROM"
                | "WHERE"
                | "JOIN"
                | "ON"
                | "AS"
                | "AND"
                | "OR"
                | "NOT"
                | "NULL"
                | "TRUE"
                | "FALSE"
                | "IN"
                | "IS"
                | "LIKE"
                | "BETWEEN"
                | "CASE"
                | "WHEN"
                | "THEN"
                | "ELSE"
                | "END"
                | "EXISTS"
                | "ALL"
                | "ANY"
                | "SOME"
                | "UNION"
                | "INTERSECT"
                | "EXCEPT"
                | "ORDER"
                | "GROUP"
                | "HAVING"
                | "LIMIT"
                | "OFFSET"
                | "FETCH"
                | "FOR"
                | "WITH"
                | "INSERT"
                | "UPDATE"
                | "DELETE"
                | "CREATE"
                | "ALTER"
                | "DROP"
                | "TABLE"
                | "VIEW"
                | "INDEX"
                | "SCHEMA"
                | "DATABASE"
                | "GRANT"
                | "REVOKE"
                | "RETURNING"
                | "LATERAL"
                | "TABLESAMPLE"
                | "DISTINCT"
                | "ONLY"
                | "INTO"
                | "VALUES"
                | "SET"
                | "DEFAULT"
        )
    }

    fn is_keyword(&self, word: &str) -> bool {
        // PostgreSQL reserved + non-reserved keywords
        self.is_reserved_keyword(word)
            || matches!(
                AsciiUpper::new(word).as_str(),
                "ARRAY"
                    | "AGGREGATE"
                    | "CAST"
                    | "COALESCE"
                    | "NULLIF"
                    | "GREATEST"
                    | "LEAST"
                    | "SUBSTRING"
                    | "TRIM"
                    | "OVERLAY"
                    | "POSITION"
                    | "EXTRACT"
                    | "CURRENT_DATE"
                    | "CURRENT_TIME"
                    | "CURRENT_TIMESTAMP"
                    | "LOCALTIME"
                    | "LOCALTIMESTAMP"
                    | "CURRENT_USER"
                    | "SESSION_USER"
                    | "USER"
                    | "CURRENT_CATALOG"
                    | "CURRENT_SCHEMA"
                    | "XMLATTRIBUTES"
                    | "XMLCONCAT"
                    | "XMLELEMENT"
                    | "XMLEXISTS"
                    | "XMLFOREST"
                    | "INTERVAL"
                    | "ROWS"
                    | "RANGE"
                    | "PRECEDING"
                    | "FOLLOWING"
                    | "CURRENT"
                    | "ROW"
                    | "OVER"
                    | "PARTITION"
                    | "WINDOW"
                    | "FIRST"
                    | "LAST"
                    | "NULLS"
                    | "ASC"
                    | "DESC"
                    | "USING"
                    | "NATURAL"
                    | "CROSS"
                    | "INNER"
                    | "OUTER"
                    | "LEFT"
                    | "RIGHT"
                    | "FULL"
                    | "PRIMARY"
                    | "FOREIGN"
                    | "KEY"
                    | "REFERENCES"
                    | "UNIQUE"
                    | "CHECK"
                    | "CONSTRAINT"
                    | "CASCADE"
                    | "RESTRICT"
                    | "NO"
                    | "ACTION"
                    | "DEFERRABLE"
                    | "INITIALLY"
                    | "DEFERRED"
                    | "IMMEDIATE"
                    | "TEMP"
                    | "TEMPORARY"
                    | "UNLOGGED"
                    | "IF"
                    | "RECURSIVE"
                    | "MATERIALIZED"
                    | "CONCURRENTLY"
                    | "CONFLICT"
                    | "NOTHING"
                    | "DO"
                    | "VACUUM"
                    | "ANALYZE"
                    | "ANALYSE"
                    | "EXPLAIN"
                    | "LISTEN"
                    | "NOTIFY"
                    | "UNLISTEN"
                    | "LOCK"
                    | "SHARE"
                    | "EXCLUSIVE"
                    | "BERNOULLI"
                    | "SYSTEM"
                    | "REPEATABLE"
            )
    }

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

    fn is_reserved_keyword(&self, word: &str) -> bool {
        // MySQL reserved keywords (core subset)
        // Full list: https://dev.mysql.com/doc/refman/8.0/en/keywords.html
        matches!(
            AsciiUpper::new(word).as_str(),
            "SELECT"
                | "FROM"
                | "WHERE"
                | "JOIN"
                | "ON"
                | "AS"
                | "AND"
                | "OR"
                | "NOT"
                | "NULL"
                | "TRUE"
                | "FALSE"
                | "IN"
                | "IS"
                | "LIKE"
                | "BETWEEN"
                | "CASE"
                | "WHEN"
                | "THEN"
                | "ELSE"
                | "END"
                | "EXISTS"
                | "ALL"
                | "ANY"
                | "SOME"
                | "UNION"
                | "INTERSECT"
                | "EXCEPT"
                | "ORDER"
                | "GROUP"
                | "HAVING"
                | "LIMIT"
                | "OFFSET"
                | "FOR"
                | "WITH"
                | "INSERT"
                | "UPDATE"
                | "DELETE"
                | "REPLACE"
                | "CREATE"
                | "ALTER"
                | "DROP"
                | "TABLE"
                | "VIEW"
                | "INDEX"
                | "SCHEMA"
                | "DATABASE"
                | "GRANT"
                | "REVOKE"
                | "INTO"
                | "VALUES"
                | "SET"
                | "DEFAULT"
                | "IF"
                | "ELSEIF"
                | "ELSIF"
                | "WHILE"
                | "DO"
                | "REPEAT"
                | "UNTIL"
                | "LOOP"
                | "LEAVE"
                | "ITERATE"
                | "RETURN"
                | "DECLARE"
                | "CURSOR"
                | "HANDLER"
                | "CONDITION"
                | "SIGNAL"
                | "RESIGNAL"
                | "GET"
                | "DIAGNOSTICS"
                | "DISTINCT"
                | "STRAIGHT_JOIN"
                | "HIGH_PRIORITY"
                | "SQL_SMALL_RESULT"
                | "SQL_BIG_RESULT"
                | "SQL_BUFFER_RESULT"
                | "SQL_NO_CACHE"
                | "SQL_CALC_FOUND_ROWS"
                | "FORCE"
                | "USE"
                | "IGNORE"
                | "PARTITION"
                | "DUAL"
                | "OUTFILE"
                | "DUMPFILE"
                | "LOAD"
                | "INFILE"
                | "TERMINATED"
                | "ENCLOSED"
                | "ESCAPED"
                | "LINES"
                | "WINDOW"
                | "OVER"
                | "ROWS"
                | "RANGE"
                | "GROUPS"
                | "PRECEDING"
                | "FOLLOWING"
                | "UNBOUNDED"
                | "CURRENT"
                | "ROW"
                | "RECURSIVE"
                | "LATERAL"
        )
    }

    fn is_keyword(&self, word: &str) -> bool {
        self.is_reserved_keyword(word)
            || matches!(
                AsciiUpper::new(word).as_str(),
                "ENGINE"
                    | "CHARSET"
                    | "COLLATE"
                    | "AUTO_INCREMENT"
                    | "COMMENT"
                    | "UNSIGNED"
                    | "ZEROFILL"
                    | "BINARY"
                    | "CHARACTER"
                    | "NATIONAL"
                    | "NCHAR"
                    | "NVARCHAR"
                    | "VARYING"
                    | "PRIMARY"
                    | "FOREIGN"
                    | "KEY"
                    | "REFERENCES"
                    | "UNIQUE"
                    | "CHECK"
                    | "CONSTRAINT"
                    | "CASCADE"
                    | "RESTRICT"
                    | "NO"
                    | "ACTION"
                    | "TEMPORARY"
                    | "IF"
                    | "ALGORITHM"
                    | "DEFINER"
                    | "INVOKER"
                    | "SECURITY"
                    | "SQL"
                    | "CONTAINS"
                    | "READS"
                    | "MODIFIES"
                    | "DETERMINISTIC"
                    | "BEGIN"
                    | "COMMIT"
                    | "ROLLBACK"
                    | "SAVEPOINT"
                    | "START"
                    | "TRANSACTION"
                    | "EXPLAIN"
                    | "DESCRIBE"
                    | "SHOW"
                    | "LOCK"
                    | "UNLOCK"
                    | "TABLES"
                    | "STATUS"
                    | "VARIABLES"
                    | "WARNINGS"
                    | "ERRORS"
                    | "PROCESSLIST"
                    | "ASC"
                    | "DESC"
                    | "USING"
                    | "NATURAL"
                    | "CROSS"
                    | "INNER"
                    | "OUTER"
                    | "LEFT"
                    | "RIGHT"
                    | "FULL"
            )
    }

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

    fn is_reserved_keyword(&self, word: &str) -> bool {
        // BigQuery reserved keywords (from official docs)
        // https://docs.cloud.google.com/bigquery/docs/reference/standard-sql/lexical#reserved_keywords
        matches!(
            AsciiUpper::new(word).as_str(),
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
                | "WITHIN"
        )
    }

    fn is_keyword(&self, word: &str) -> bool {
        self.is_reserved_keyword(word)
            || matches!(
                AsciiUpper::new(word).as_str(),
                // Non-reserved keywords used in BigQuery
                "ABORT" | "ACCESS" | "ACTION" | "ADD" | "AGGREGATE" | "ALTER" | "ANALYZE"
            | "ASSERT" | "BATCH" | "BEGIN"
            | "BREAK" | "CALL" | "CHECK" | "CLUSTER" | "COLUMN" | "COMMIT" | "CONNECTION"
            | "CONSTRAINT" | "CONTINUE" | "CORRESPONDING" | "CYCLE"
            | "DATA" | "DATABASE" | "DECLARE" | "DELETE" | "DESCRIBE" | "DETERMINISTIC"
            | "DO" | "DROP"
            | "ELSEIF" | "ELSIF" | "ENFORCED" | "ERROR" | "EXCEPTION" | "EXECUTE" | "EXPORT" | "EXTERNAL"
            | "FILES" | "FILTER" | "FOREIGN" | "FORMAT" | "FUNCTION"
            | "GENERATED" | "GRANT"
            | "IDENTITY" | "IMMEDIATE" | "IMPORT" | "INDEX" | "INOUT" | "INPUT" | "INSERT"
            | "INVOKER" | "ITERATE"
            | "KEY"
            | "LANGUAGE" | "LEAVE" | "LET" | "LOAD" | "LOG" | "LOOP"
            | "MATCH" | "MATCHED" | "MATERIALIZED" | "MESSAGE" | "MODEL" | "MODULE"
            | "NOTHING" | "NUMERIC"
            | "OPTIONS" | "OUT" | "OUTPUT" | "OVERWRITE"
            | "PAUSED" | "PERCENT" | "PIVOT" | "POLICIES" | "POLICY" | "PRIMARY"
            | "PRIVATE" | "PRIVILEGE" | "PRIVILEGES" | "PROCEDURE" | "PROJECT" | "PUBLIC"
            | "RAISE" | "READ" | "REFERENCES" | "REMOTE" | "RENAME" | "REPEAT" | "REPEATABLE"
            | "REPLACE" | "REPLICA" | "REPORT" | "RESTRICT" | "RETURN" | "RETURNS"
            | "REVOKE" | "ROLLBACK" | "ROW"
            | "RUN"
            | "SAFE_CAST" | "SCHEMA" | "SEARCH" | "SECURITY" | "SEQUENCE" | "SESSION"
            | "SHOW" | "SNAPSHOT" | "SOURCE" | "SQL" | "STORED" | "SYSTEM_TIME"
            | "TABLE" | "TARGET" | "TEMP" | "TEMPORARY" | "TIME" | "TRANSACTION"
            | "TRANSFORM" | "TRUNCATE" | "TYPE"
            | "UNDROP" | "UNIQUE" | "UNKNOWN" | "UNPIVOT" | "UNTIL" | "UPDATE"
            | "VALIDATE" | "VALUE" | "VALUES" | "VIEW"
            | "WEEK" | "WHILE" | "WRITE"
            | "ZONE"
            // Common BigQuery built-in function-like keywords
            | "SAFE_DIVIDE" | "SAFE_MULTIPLY" | "SAFE_NEGATE" | "SAFE_ADD" | "SAFE_SUBTRACT"
            | "SAFE_OFFSET" | "SAFE_ORDINAL" | "OFFSET" | "ORDINAL"
            // Join/query keywords
            | "ASC" | "DESC" | "LIMIT" | "CROSS" | "INNER"
            | "LEFT" | "RIGHT" | "FULL" | "NATURAL" | "USING"
            )
    }

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
    // ---- Statement grammar shape (see trait docs) ----
    fn supports_distribute_sort_clauses(&self) -> bool {
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

    fn is_reserved_keyword(&self, word: &str) -> bool {
        // Databricks "Reserved words" list (alias-restricted words).
        // Docs: https://docs.databricks.com/en/sql/language-manual/sql-ref-reserved-words.html
        matches!(
            AsciiUpper::new(word).as_str(),
            "ANTI"
                | "CROSS"
                | "EXCEPT"
                | "FULL"
                | "INNER"
                | "INTERSECT"
                | "JOIN"
                | "LATERAL"
                | "LEFT"
                | "MINUS"
                | "NATURAL"
                | "ON"
                | "RIGHT"
                | "SEMI"
                | "UNION"
                | "USING"
        )
    }

    fn keyword_can_be_unquoted_identifier(&self, _word: &str) -> bool {
        // Databricks docs: identifiers are not formally disallowed in general.
        true
    }

    fn keyword_can_be_unquoted_alias(&self, word: &str) -> bool {
        // Databricks docs: these table-alias words require backticks.
        !self.is_reserved_keyword(word)
    }

    fn is_keyword(&self, word: &str) -> bool {
        self.is_reserved_keyword(word)
            || matches!(
                AsciiUpper::new(word).as_str(),
                // Non-reserved keywords commonly used in Databricks SQL
                "ABORT"
                    | "ACCESS"
                    | "ADD"
                    | "AFTER"
                    | "AGGREGATE"
                    | "ANALYZE"
                    | "ASC"
                    | "AUTHORIZATION"
                    | "BEGIN"
                    | "BINARY"
                    | "BUCKET"
                    | "BUCKETS"
                    | "CACHE"
                    | "CASCADE"
                    | "CATALOG"
                    | "CHANGE"
                    | "CHECK"
                    | "CLONE"
                    | "CLUSTER"
                    | "CLUSTERED"
                    | "CODEGEN"
                    | "COMMENT"
                    | "COMMIT"
                    | "COMPACT"
                    | "COMPACTIONS"
                    | "COMPUTE"
                    | "CONSTRAINT"
                    | "COPY"
                    | "COST"
                    | "CTE"
                    | "DATA"
                    | "DATABASE"
                    | "DATABASES"
                    | "DAY"
                    | "DAYS"
                    | "DBPROPERTIES"
                    | "DECLARE"
                    | "DEFINED"
                    | "DELTA"
                    | "DELIMITED"
                    | "DFS"
                    | "DIRECTORY"
                    | "DISTRIBUTE"
                    | "DIV"
                    | "DO"
                    | "ENABLE"
                    | "EXCHANGE"
                    | "EXECUTE"
                    | "EXPORT"
                    | "EXTENDED"
                    | "EXTERNAL"
                    | "FIELDS"
                    | "FILEFORMAT"
                    | "FILES"
                    | "FIRST"
                    | "FORMAT"
                    | "FORMATTED"
                    | "FUNCTION"
                    | "FUNCTIONS"
                    | "GENERATED"
                    | "GLOBAL"
                    | "HISTORY"
                    | "HOUR"
                    | "HOURS"
                    | "IDENTITY"
                    | "IGNORE"
                    | "IMMEDIATE"
                    | "IMPORT"
                    | "INDEX"
                    | "INDEXES"
                    | "INPUTFORMAT"
                    | "INTERVAL"
                    | "KEY"
                    | "KEYS"
                    | "LANGUAGE"
                    | "LAST"
                    | "LAZY"
                    | "LIFECYCLE"
                    | "LIQUID"
                    | "LIST"
                    | "LOAD"
                    | "LOCATION"
                    | "LOCK"
                    | "LOCKS"
                    | "LOGICAL"
                    | "LOOP"
                    | "MACRO"
                    | "MAP"
                    | "MATCHED"
                    | "MATERIALIZED"
                    | "MINUTE"
                    | "MINUTES"
                    | "MONTH"
                    | "MONTHS"
                    | "MSCK"
                    | "NAMESPACE"
                    | "NAMESPACES"
                    | "NULLS"
                    | "OPTIMIZE"
                    | "OPTION"
                    | "OPTIONS"
                    | "OUT"
                    | "OUTPUTFORMAT"
                    | "OVER"
                    | "OVERLAY"
                    | "OVERWRITE"
                    | "OWNER"
                    | "PARTITIONED"
                    | "PARTITIONS"
                    | "PERCENT"
                    | "PIVOT"
                    | "POSITION"
                    | "PRECEDING"
                    | "PRIVILEGES"
                    | "PROCEDURE"
                    | "PURGE"
                    | "RECOVER"
                    | "RECURSIVE"
                    | "REFRESH"
                    | "RENAME"
                    | "REPAIR"
                    | "REPEATABLE"
                    | "REPLACE"
                    | "RESET"
                    | "RESPECT"
                    | "RESTORE"
                    | "RESTRICT"
                    | "RETURN"
                    | "RETURNS"
                    | "REWRITE"
                    | "ROLLBACK"
                    | "SCHEMA"
                    | "SCHEMAS"
                    | "SECOND"
                    | "SECONDS"
                    | "SERDE"
                    | "SERDEPROPERTIES"
                    | "SHOW"
                    | "SKEWED"
                    | "SORT"
                    | "SORTED"
                    | "SOURCE"
                    | "SQL"
                    | "START"
                    | "STATISTICS"
                    | "STORED"
                    | "STRATIFY"
                    | "STRUCT"
                    | "SYNC"
                    | "TABLESAMPLE"
                    | "TEMP"
                    | "TEMPORARY"
                    | "TERMINATED"
                    | "TIMESTAMP"
                    | "TBLPROPERTIES"
                    | "TOUCH"
                    | "TRANSACTION"
                    | "TRANSFORM"
                    | "TYPE"
                    | "UNCACHE"
                    | "UNBOUNDED"
                    | "UNDO"
                    | "UNSET"
                    | "UNPIVOT"
                    | "VACUUM"
                    | "VIEW"
                    | "VOLUME"
                    | "VOLUMES"
                    | "VERSION"
                    | "WEEK"
                    | "WEEKS"
                    | "WHILE"
                    | "WRITE"
                    | "YEAR"
                    | "YEARS"
                    | "ZONE"
                    | "ZORDER"
            )
    }

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
        false // Databricks treats "..." as identifiers (like Snowflake/PostgreSQL)
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
        false // Databricks does not support nested block comments
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

impl Dialect for MsSqlDialect {
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

    fn is_reserved_keyword(&self, word: &str) -> bool {
        // T-SQL reserved keywords (from official Microsoft docs)
        // https://learn.microsoft.com/en-us/sql/t-sql/language-elements/reserved-keywords-transact-sql
        matches!(
            AsciiUpper::new(word).as_str(),
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
                | "IDENTITY_INSERT"
                | "IDENTITYCOL"
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
                | "WRITETEXT"
        )
    }

    fn is_keyword(&self, word: &str) -> bool {
        self.is_reserved_keyword(word)
            || matches!(
                AsciiUpper::new(word).as_str(),
                // Non-reserved keywords commonly used in T-SQL
                "ABORT" | "ABSOLUTE" | "ACTION" | "AES" | "AFTER" | "AGGREGATE"
            | "ANSI_NULLS" | "ANSI_PADDING" | "APPLY" | "AT" | "ATOMIC"
            | "BEFORE" | "BIGINT" | "BINARY" | "BIT" | "BOOLEAN"
            | "CALLER" | "CATCH" | "CHAR" | "CHARACTER" | "CLUSTERED" | "COMMITTED"
            | "CONCAT_NULL_YIELDS_NULL" | "CONSTRAINT" | "COUNT_BIG"
            | "CURSOR_CLOSE_ON_COMMIT"
            | "DATA" | "DATE" | "DATETIME" | "DATETIME2" | "DATETIMEOFFSET"
            | "DEC" | "DECIMAL" | "DELAYED_DURABILITY" | "DESCRIPTION"
            | "ENABLE" | "ENCRYPTED" | "ERROR" | "EVENT" | "EXPAND"
            | "FAST" | "FILEGROUP" | "FILENAME" | "FIRST" | "FLOAT" | "FOLLOWING"
            | "FORCE" | "FORMAT" | "FORWARD_ONLY"
            | "GEOGRAPHY" | "GEOMETRY" | "GLOBAL" | "GO"
            | "HASH" | "HIERARCHYID"
            | "IGNORE" | "IMAGE" | "IMMEDIATE" | "INCLUDE" | "INCREMENT"
            | "INSENSITIVE" | "INT" | "INTEGER" | "ISOLATION"
            | "JSON"
            | "KEEP" | "KEEPFIXED"
            | "LANGUAGE" | "LAST" | "LEVEL" | "LOCAL" | "LOG" | "LOGIN"
            | "MATCHED" | "MAX" | "MAXDOP" | "MAXRECURSION" | "MIN" | "MINUTE"
            | "MONEY" | "MONTH"
            | "NAME" | "NCHAR" | "NEXT" | "NO" | "NOEXPAND" | "NOLOCK" | "NONCLUSTERED"
            | "NOWAIT" | "NTEXT" | "NUMERIC" | "NVARCHAR"
            | "OBJECT" | "OFFSET" | "ONLINE" | "OPTIMIZE" | "OUTPUT"
            | "PAGLOCK" | "PARTITION" | "PATH" | "PRECEDING" | "PRIOR"
            | "RANGE" | "RAW" | "READCOMMITTED" | "READCOMMITTEDLOCK" | "READONLY"
            | "READPAST" | "READUNCOMMITTED" | "REAL" | "REBUILD" | "RECEIVE"
            | "RECURSIVE" | "REORGANIZE" | "REPEATABLEREAD" | "REPEATABLE"
            | "RESULT" | "ROBUST" | "ROW" | "ROWLOCK" | "ROWS" | "ROWVERSION"
            | "SCROLL" | "SECOND" | "SELF" | "SEND" | "SEQUENCE"
            | "SERIALIZABLE" | "SERVER" | "SESSION" | "SETS"
            | "SMALLDATETIME" | "SMALLINT" | "SMALLMONEY" | "SNAPSHOT" | "SQL_VARIANT"
            | "STATIC" | "SYNONYM"
            | "TABLOCK" | "TABLOCKX" | "TEMP" | "TEMPORARY" | "TEXT" | "THROW"
            | "TIME" | "TIMESTAMP" | "TINYINT" | "TRY" | "TYPE"
            | "UNBOUNDED" | "UNCOMMITTED" | "UNIQUEIDENTIFIER" | "UPDLOCK"
            | "VARBINARY" | "VARCHAR" | "VECTOR"
            | "WINDOW" | "WORK" | "XLOCK" | "XML" | "XSINIL"
            | "YEAR" | "ZONE"
            // Common T-SQL built-in function-like keywords
            | "ISNULL" | "NEWID" | "SCOPE_IDENTITY" | "OBJECT_ID" | "GETDATE"
            | "SYSDATETIME" | "SYSUTCDATETIME" | "DATEDIFF" | "DATEADD" | "DATENAME"
            | "DATEPART" | "EOMONTH" | "STUFF" | "STRING_AGG"
            | "IIF" | "CHOOSE" | "GREATEST" | "LEAST"
            )
    }

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

    fn is_reserved_keyword(&self, word: &str) -> bool {
        // Amazon Redshift reserved words (authoritative list).
        // https://docs.aws.amazon.com/redshift/latest/dg/r_pg_keywords.html
        matches!(
            AsciiUpper::new(word).as_str(),
            "AES128"
                | "AES256"
                | "ALL"
                | "ALLOWOVERWRITE"
                | "ANALYSE"
                | "ANALYZE"
                | "AND"
                | "ANY"
                | "ARRAY"
                | "AS"
                | "ASC"
                | "AUTHORIZATION"
                | "AZ64"
                | "BACKUP"
                | "BETWEEN"
                | "BINARY"
                | "BLANKSASNULL"
                | "BOTH"
                | "BYTEDICT"
                | "BZIP2"
                | "CASE"
                | "CAST"
                | "CHECK"
                | "COLLATE"
                | "COLUMN"
                | "CONSTRAINT"
                | "CREATE"
                | "CREDENTIALS"
                | "CROSS"
                | "CURRENT_DATE"
                | "CURRENT_TIME"
                | "CURRENT_TIMESTAMP"
                | "CURRENT_USER"
                | "CURRENT_USER_ID"
                | "DEFAULT"
                | "DEFERRABLE"
                | "DEFLATE"
                | "DEFRAG"
                | "DELTA"
                | "DELTA32K"
                | "DESC"
                | "DISABLE"
                | "DISTINCT"
                | "DO"
                | "ELSE"
                | "EMPTYASNULL"
                | "ENABLE"
                | "ENCODE"
                | "ENCRYPT"
                | "ENCRYPTION"
                | "END"
                | "EXCEPT"
                | "EXPLICIT"
                | "FALSE"
                | "FOR"
                | "FOREIGN"
                | "FREEZE"
                | "FROM"
                | "FULL"
                | "GLOBALDICT256"
                | "GLOBALDICT64K"
                | "GRANT"
                | "GROUP"
                | "GZIP"
                | "HAVING"
                | "IDENTITY"
                | "IGNORE"
                | "ILIKE"
                | "IN"
                | "INITIALLY"
                | "INNER"
                | "INTERSECT"
                | "INTERVAL"
                | "INTO"
                | "IS"
                | "ISNULL"
                | "JOIN"
                | "LANGUAGE"
                | "LEADING"
                | "LEFT"
                | "LIKE"
                | "LIMIT"
                | "LOCALTIME"
                | "LOCALTIMESTAMP"
                | "LUN"
                | "LUNS"
                | "LZO"
                | "LZOP"
                | "MINUS"
                | "MOSTLY16"
                | "MOSTLY32"
                | "MOSTLY8"
                | "NATURAL"
                | "NEW"
                | "NOT"
                | "NOTNULL"
                | "NULL"
                | "NULLS"
                | "OFF"
                | "OFFLINE"
                | "OFFSET"
                | "OID"
                | "OLD"
                | "ON"
                | "ONLY"
                | "OPEN"
                | "OR"
                | "ORDER"
                | "OUTER"
                | "OVERLAPS"
                | "PARALLEL"
                | "PARTITION"
                | "PERCENT"
                | "PERMISSIONS"
                | "PIVOT"
                | "PLACING"
                | "PRIMARY"
                | "RAW"
                | "READRATIO"
                | "RECOVER"
                | "REFERENCES"
                | "REJECTLOG"
                | "RESORT"
                | "RESPECT"
                | "RESTORE"
                | "RIGHT"
                | "SELECT"
                | "SESSION_USER"
                | "SIMILAR"
                | "SNAPSHOT"
                | "SOME"
                | "SYSDATE"
                | "SYSTEM"
                | "TABLE"
                | "TAG"
                | "TDES"
                | "TEXT255"
                | "TEXT32K"
                | "THEN"
                | "TIMESTAMP"
                | "TO"
                | "TOP"
                | "TRAILING"
                | "TRUE"
                | "TRUNCATECOLUMNS"
                | "UNION"
                | "UNIQUE"
                | "UNNEST"
                | "UNPIVOT"
                | "USING"
                | "VERBOSE"
                | "WALLET"
                | "WHEN"
                | "WHERE"
                | "WITH"
                | "WITHOUT"
        )
    }

    fn is_keyword(&self, word: &str) -> bool {
        // Redshift reserved words plus non-reserved keywords that carry
        // syntactic meaning (DDL options, COPY/UNLOAD clauses, scripting,
        // type names) but may still appear as unquoted identifiers.
        self.is_reserved_keyword(word)
            || matches!(
                AsciiUpper::new(word).as_str(),
                // Statement / command words
                "ALTER" | "DROP" | "INSERT" | "UPDATE" | "DELETE" | "MERGE" | "TRUNCATE"
            | "COPY" | "UNLOAD" | "VACUUM" | "CALL" | "EXECUTE" | "PREPARE" | "DEALLOCATE"
            | "EXPLAIN" | "SET" | "SHOW" | "RESET" | "COMMENT" | "REVOKE" | "REFRESH"
            | "BEGIN" | "COMMIT" | "ROLLBACK" | "ABORT" | "START" | "TRANSACTION" | "WORK"
            | "LOCK" | "DECLARE" | "FETCH" | "CLOSE"
            // Object / DDL keywords
            | "DATABASE" | "SCHEMA" | "VIEW" | "MATERIALIZED" | "PROCEDURE" | "FUNCTION"
            | "SEQUENCE" | "USER" | "ROLE" | "EXTERNAL" | "MODEL" | "DATASHARE"
            | "TEMP" | "TEMPORARY" | "LOCAL" | "IF" | "EXISTS" | "REPLACE" | "CASCADE"
            | "RESTRICT" | "RENAME" | "ADD" | "OWNER" | "CONNECTION" | "BINDING"
            // Table layout / storage options
            | "DISTSTYLE" | "DISTKEY" | "SORTKEY" | "COMPOUND" | "INTERLEAVED"
            | "AUTO" | "EVEN" | "KEY" | "ENCODING" | "RUNLENGTH" | "ZSTD"
            // COPY / UNLOAD option keywords
            | "IAM_ROLE" | "REGION" | "FORMAT" | "MANIFEST" | "DELIMITER" | "FIXEDWIDTH"
            | "ACCEPTINVCHARS" | "MAXERROR" | "DATEFORMAT" | "TIMEFORMAT" | "HEADER"
            | "PARQUET" | "ORC" | "AVRO" | "CSV" | "JSON" | "BZIP" | "COMPUPDATE"
            | "STATUPDATE" | "ESCAPE" | "ADDQUOTES" | "REMOVEQUOTES" | "EMPTYASNULL"
            | "ROUNDEC" | "TRIMBLANKS" | "EXTENSION" | "PARTITION"
            // External (Spectrum) keywords
            | "DATA" | "CATALOG" | "HIVE" | "METASTORE" | "STORED" | "LOCATION"
            | "INPUTFORMAT" | "OUTPUTFORMAT" | "SERDE" | "SERDEPROPERTIES" | "ROW"
            // Window / analytic ("PARTITION" listed under COPY/UNLOAD options)
            | "OVER" | "ROWS" | "RANGE" | "PRECEDING" | "FOLLOWING"
            | "UNBOUNDED" | "CURRENT" | "FIRST" | "LAST" | "WINDOW"
            // Joins / set ops helpers
            | "INTERSECT" | "EXCEPT" | "USING" | "NATURAL" | "CROSS" | "INNER"
            | "LEFT" | "RIGHT" | "FULL" | "RECURSIVE" | "VALUES"
            // DML helpers
            | "NOTHING" | "CONFLICT" | "RETURNING" | "GROUPS"
            // Expressions / functions
            | "COALESCE" | "NULLIF" | "GREATEST" | "LEAST" | "EXTRACT" | "POSITION"
            | "SUBSTRING" | "TRIM" | "BETWEEN" | "INTERVAL"
            // Type keywords
            | "BOOLEAN" | "BOOL" | "SMALLINT" | "INT2" | "INTEGER" | "INT" | "INT4"
            | "BIGINT" | "INT8" | "DECIMAL" | "NUMERIC" | "REAL" | "FLOAT4"
            | "DOUBLE" | "PRECISION" | "FLOAT" | "FLOAT8" | "CHAR" | "CHARACTER"
            | "NCHAR" | "BPCHAR" | "VARCHAR" | "NVARCHAR" | "VARYING" | "TEXT"
            | "DATE" | "TIME" | "TIMETZ" | "TIMESTAMPTZ" | "GEOMETRY" | "GEOGRAPHY"
            | "HLLSKETCH" | "SUPER" | "VARBYTE" | "VARBINARY" | "BINARY"
            // Constraints
            | "CONSTRAINT" | "PRIMARY" | "FOREIGN" | "REFERENCES" | "CHECK" | "UNIQUE"
            )
    }

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
        false // Redshift does not support nested block comments
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
}

/// Create an Amazon Redshift dialect instance
pub fn redshift() -> DialectRef {
    Arc::new(RedshiftDialect)
}
