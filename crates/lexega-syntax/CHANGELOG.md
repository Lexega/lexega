# Changelog

`lexega-syntax` is versioned in lockstep with the Lexega engine. Entries
describe behaviour visible to users of the crate: what parses, what the AST
carries, and how formatting changes.

## 3.1.0

### Changed

- `//` starts a line comment only where `Dialect::slash_slash_is_line_comment` is true (Snowflake); elsewhere it is two `/` tokens.
- In MySQL, an executable comment (`/*!`, `/*!NNNNN`, MariaDB `/*M!`) is lexed as its markers, `TriviaKind::MysqlVersionComment` trivia for the opener and for the `*/`, and the SQL between them as tokens.
- Databricks block comments nest. A block comment holding `/*` in a dialect whose `Dialect::block_comment_nesting_unknown` is true (Redshift) is lexed as an `Unknown` token.

### Breaking

- `SyntaxCte` has a new field, `materialized`.
- `BodyRole` has a new variant, `Pipe`: `AstStmt::bodies` gives a pipe chain's statements (`a ->> b`) as a body.

### Added

- `Dialect::slash_slash_is_line_comment` and `Dialect::block_comment_nesting_unknown`, both false by default.
- `SyntaxCte::materialized`: PostgreSQL's `[NOT] MATERIALIZED` tokens, which `WITH x AS [NOT] MATERIALIZED (…)` now parses with.
- A privilege's column list (`SELECT (a, b)`) is part of its span, and SQL Server's `ON t (a, b)` securable parses; such grants read as typed grants, not `Unparsed`.
- `AstAlterTableActionKind::DropColumnMask` also holds SQL Server's `ALTER COLUMN … DROP MASKED`.

## 3.0.0

More SQL parses, object names are read one way everywhere, and the tree records more of what a statement writes. The breaking changes are to struct literals and exhaustive `match`es on the tree.

### Breaking

**Names.**
- Every position that takes an object name is an `AstObjectRef` with a `name_kind`, whose `parts` are `AstNamePart`s: write targets, the names in `DROP`, `TRUNCATE`, `ALTER TABLE`, `COPY INTO` and `CREATE TABLE` / `VIEW`, and the names of stages, tags and policies. The `target_table_span`, `name_span` and `target_name_span` fields moved into it.
- A table function called in `FROM` has its name's parts there too: check `AstTableRef::table_function` to tell it from a table.
- The identifier normalizer lives here: `dialect::normalize_identifier`, `normalize_identifier_as(name, NameKind)`, `NormalizationConfig`. Names are folded only inside a scoped folding (`ThreadNormalization::scoped`); a debug build panics without one.

**Expressions.**
- `a + b + c` is one `AstExpr::OperatorChain`, not nested `BinaryOp`s.
- `INTERSECT` binds tighter than `UNION`, `EXCEPT` and `MINUS`.
- A call's date part, data type or normal form is an `AstFunctionArg::NonValue` or `DataType`, and a table argument is `AstFunctionArg::Table`.
- `odbc_fn` on `AstExpr::FunctionCall`, `Extract` and `Position` is an `Option<Span>` in place of a `bool`.

**Statements.**
- `AstStmt::Declare` holds `variables`, one `AstDeclaredVariable` each.
- `AstCreateFunctionStmt.returns` is `Option<AstReturnsClause>`. `AstCreateProcedureStmt` has `language`, `verb` and `body_statements`; a T-SQL `ALTER PROCEDURE` or `ALTER FUNCTION` that restates the body parses as the `Create` statement with its `verb`.
- `AstInsert`, `AstReplaceInto` and `AstMultiInsertIntoClause` have `columns`.
- `AstTruncate` has `tables` (`AstTruncateTable`) and `only_span`, and `build_truncate` takes them. `AstCreateTable::like_elements` holds `AstTableLikeItem`s, and `AstCreateTable` has `if_not_exists_span`.
- `AstUnloadSource::Table` gains `query`. `AstStmt::CopyIntoLocation`, `Unload` and `RedshiftCopy` have `location_url_span`, and `CopyIntoTable` has `from_location_url_span`.
- The four T-SQL key statements hold `password_literal_spans` in place of `password_present`.
- `AstGroupElementKind` has `EmptySet`; `Cube`, `Rollup` and `GroupingSets` are struct variants that carry their parentheses, and `GroupingSets` holds `AstGroupingSet`s. `AstSelect::post_locking_extension_clauses` holds `AstQueryOptions` in place of `Span`s, as `option_clauses` of `AstUpdate`, `AstDelete` and `AstMerge` do.

**`ALTER TABLE` actions.**
- New `ChangeColumn`, `AlterColumnList` and `NamedAction` (with its `AstNamedTableAction`: an action that was kept as `Unknown` or `GovernanceSpan` and whose leading words say what it is).
- A column alteration or drop written without `COLUMN`, or as a later item of a list, is an `AlterColumn`, `RenameColumn` or `DropColumn` whose `column_span`, `alter_span` or `drop_span` is `None`.
- `AddColumn` has `if_not_exists_span` and `parenthesized`. `AlterColumn` records its new type (`altered_type`) and default. An altered column's `operation_span` and a dropped column's `columns_span` start at their first word.
- `AstAlterViewActionKind::AlterColumn` has `policy_unset`. `AstAlterMaterializedViewActionKind` has the row access policy actions, `AlterColumn`, `RenameColumn`, `RenameTo`, and the secure, comment and tag actions.

**Secrets.**
- `AstScript::redaction_spans` holds only the secrets a syntax position names; `lexega-core` finds the rest. `parser::user_mapping::is_secret_option_key` is removed.

**New variants and fields.**
- New `AstStmt` variants, including `Perform`, `Savepoint`, `MssqlTriggerState`, `MysqlAdmin`, `MysqlCreateLoadableFunction`, `ExecuteTask`, `PsqlGexec`, `MssqlCreateRule` and `SqlcmdCommand`.
- New variants of `AstExpr`, `AstLiteral`, `AstFunctionArg`, `AstJoinKind`, `BinaryOperator`, `Operator`, `TriviaKind` (`CopyData`), `TokenKind` (the template `filter` and `call` blocks), `AstMssqlSecurityObjectKind` and `NewlineStyle`. `TokenKind::Identifier` gains `word_operator`.
- New fields on `AstScript`, `LexResult`, `AstIdentifier`, `AstSelect`, `AstSelectItem`, `AstJoin`, `AstTableRef`, `AstDelete`, `AstMerge`, `AstCallArg`, `AstProcedureParam`, `AstDropTarget`, `AstCreateTable`, `AstCreateTableColumn`, `AstCreateTableConstraint`, `AstAlterTable`, `AstAlterTableColumnDef`, `AstMysqlLoadData`, `AstPgSet`, `AstPgCopy`, `AstCreateMssqlTrigger`, `AstCreateAuthenticationPolicy`, `AstSnowflakeUserOptions`, `CreatePrincipalOptions` and `AstAlterEvent`, and on the `Assign`, `GetDiagnostics`, `AddConstraint` and `DeclareTable` variants.
- `dialect::SyntaxMeaning` has `temporary_tables` (`TemporaryTables`), `shorter_column_list` (`ShorterColumnList`), `cte_write_target` (`CteWriteTarget`), `write_target_source` (`WriteTargetSource`) and `default_search_path`. `SqlcmdAction::Client` carries `named`. `NormalizationConfig` has `quoted_routines`, `quoted_name_is_path` and `routine_names_keep_case`.

### More SQL parses

- **T-SQL:** scripts without semicolons, with `GO` a batch separator only on a line of its own; sqlcmd command lines (`AstStmt::SqlcmdCommand`); cursor `FETCH` orientations; `ENABLE` / `DISABLE TRIGGER`; `SAVE TRAN`; `INSERT … EXEC`; `EXEC p @q OUT`; join hints and a query's `OPTION (…)`; `OUTPUT … INTO`; `DELETE` and `INSERT` without `FROM` / `INTO`; `SELECT alias = value`; a procedure body without `BEGIN … END`; `DROP DATABASE ENCRYPTION KEY`.
- **PostgreSQL and PL/pgSQL:** `PERFORM`, `GET DIAGNOSTICS`, `SELECT … INTO [STRICT]`, `EXIT … WHEN`, `CREATE RULE`, `MERGE … RETURNING`, `TABLE t`, assignments to a record field or an element, `SET search_path`, `[NO] INHERIT`, `ONLY`, `TRUNCATE a, b`, named `CALL` arguments, and `COPY … FROM STDIN` with its data rows (one `TriviaKind::CopyData`; `\copy` too).
- **MySQL:** the client's `DELIMITER`, administration statements, loadable functions, `DO`, `@v := expr`, multi-table `DELETE`, index definitions in `CREATE TABLE`, and `LOAD DATA`'s `REPLACE` and `SET`.
- **Databricks:** `LATERAL VIEW`, `SEMI` and `ANTI` joins, `INSERT OVERWRITE`.
- **Snowflake and BigQuery:** `EXECUTE TASK`, `CONNECT_BY_ROOT`, `INSERT` without `INTO`, `MERGE … INSERT ROW`.
- **Every dialect:** `GROUP BY ()`, a view's body in parentheses, positional binds (`:1`), bitwise operators, `GRANT` and `REVOKE` over several objects and grantees, and control flow in an `EXCEPTION` handler.
- Column definitions, table constraints and routine parameters hold the expressions they write: defaults, computed columns, checks.

**Recovery.** A statement that does not parse ends at its `;`, or after an unclosed parenthesis at a `;` that a statement follows or a T-SQL batch separator. A statement read only up to a token the parser cannot place is recorded in `AstScript::cut_statements`.

### New

- **Dialect facts:** `Dialect::system_routine` and `system_routines` (the dialect's own routines that take a name, a command, a credential or SQL text); `type_synonyms`, `type_name` and `routine_synonyms`; `shown_slots` and `shown_settings` (the places each dialect documents as holding no secret); `set_assigns`, `builtin_routines`, `rename_routine`, `routine_language_is_sql`; `normalize_routine_name` and `normalize_relation_name`.
- **Secrets:** `secrets::{is_secret_name, string_literal_content, url_password_ranges, connection_string_entries, connection_call_strings}`. `AstScript::redaction_spans` also covers Redshift `COPY` / `UNLOAD` credentials, the password of a URL in any string literal, connection strings, and every password of an `OPEN … KEY`.
- **What a report must not quote as written:** `AstScript::{comment_spans, secret_places, setting_values, template_blocks, bulk_options, held_names, read_bodies}` and `LexResult::dollar_quotes`.
- **Literals:** `lexer::decode_string_literal`; `Span::overlaps`.

### Formatting

`NewlineStyle::Auto` is the default, so CRLF input formats to CRLF. A config file that leaves an option out gets the default's value. A `${NAME}` deployment marker in a name formats as written. `verify_formatting_safe_with_dialect` refuses output that adds or loses a T-SQL batch separator. New: `FormattedContext::copied_spans`, `verify_copied_spans` and `Printer::end_line`.

Building needs Rust 1.99.

## 2.0.0

First published version. The lexer, parser, AST/CST and formatter that power
Lexega 2.0, covering Snowflake, T-SQL, BigQuery, PostgreSQL, Redshift,
Databricks and MySQL across 337 statement kinds.
