# Changelog

The rule corpus is versioned in lockstep with the Lexega engine. Entries
describe rules added, removed or renamed, and changes in what a rule matches.

## 3.1.0

**Added.** Thirteen new rules. The corpus now has 97 critical, 85 high, 288 medium, 194 low and 306 info rules.

*Critical*
- `DB-REPLACE` and `SCHEMA-REPLACE`: `CREATE OR REPLACE DATABASE` and `CREATE OR REPLACE SCHEMA`, which drop everything the old database or schema held.
- `TBL-SWAP`: `ALTER TABLE … SWAP WITH`.
- `GRT-UNMASK`: SQL Server's `GRANT UNMASK`, on the database, a schema, a table or its columns.
- `MSSQL-XP-REGISTRY-WRITE`: `xp_regwrite`, `xp_regdeletekey`, `xp_regdeletevalue`, the multi-string procedures and their `xp_instance_` forms.
- `MYSQL-GRT-SUPER`: `GRANT SUPER`.

*High*
- `MSSQL-XP-REGISTRY-READ`: `xp_regread`, `xp_regenumkeys`, `xp_regenumvalues` and their `xp_instance_` forms.
- `MSSQL-XP-FILESYSTEM`: `xp_dirtree`, `xp_fileexist` and `xp_subdirs`.
- `MSSQL-STARTUP-PROC`: `sp_procoption`, except when it sets the option to `off` or `false`.
- `MYSQL-GRT-FILE`: `GRANT FILE`.
- `MYSQL-LOAD-FILE`: a call of `LOAD_FILE()` anywhere in a statement.

*Medium*
- `MSSQL-DBMAIL-EGRESS`: `sp_send_dbmail` with `@query` or `@file_attachments`.
- `MYSQL-GRT-PROCESS`: `GRANT PROCESS`.

Each SQL Server rule catches its procedure however the name is qualified, quoted or capitalized.

**Changed.** `TBL-REPLACE`'s message now says that `CREATE OR REPLACE TABLE` drops every row the old table held. `DML-WRITE-UNBOUNDED`'s message now says that `id = id` leaves out only the rows where `id` is NULL.

**Catches more.**
- `DML-WRITE-UNBOUNDED` catches a `WHERE` made only of constants that is always true, such as `WHERE 1 + 1 = 2` or MySQL's `WHERE 1`.
- `DML-WRITE-UNBOUNDED` catches `LIMIT 18446744073709551615`, MySQL's way of writing "no limit".
- `DML-WRITE-UNBOUNDED` catches `WHERE id = id`, which matches every row that has an `id`. It also catches conditions that cover every value of a column, such as `WHERE x >= 5 OR x < 5`. It used to catch these only on a column the catalog marks `NOT NULL`. `WHERE x IS NOT NULL` still counts as a filter.
- `TBL-MASK-RMV` catches SQL Server's `ALTER COLUMN … DROP MASKED`.
- `GRT-TO-PUBLIC` and the other grant rules catch column-level grants, such as `GRANT SELECT (a, b) ON t TO PUBLIC`. Lexega used to read these grants only in part.

## 3.0.0

Levels are retuned, a cause is reported by one rule, and rule files can hold lists. A policy or exception that names a rule should be checked against the sections below; the rule reference lists every rule at its level.

**Levels are retuned.** 544 of the 927 rules that v2.0.0 also has change level. 209 leave the default `--min-severity high` view and 9 enter it. 205 move to `info`, and an info rule reports context, not findings. The rules now number 91 critical, 80 high, 286 medium, 194 low and 306 info. 77 messages are rewritten to say what the statement does, and the 54 that ended in "Positive … signal" drop that phrase.

**Removed.** `SNW-PWDPOL-EXPIRY-STALE`, `SNW-PWDPOL-LOCKOUT-WEAK` and `MSSQL-EXTMDL-RMT` matched the same statements as `SNW-PWDPOL-EXPIRY-LONG`, `SNW-PWDPOL-LOCKOUT-SHORT` and `MSSQL-EXTMDL-NEW`. Each remaining rule lists the removed id in `former_ids`, so a policy, an exception or a rule-file entry that names it still applies.

### Rule files

- A file can hold `lists:` next to `rules:`: named lists of `values` and `*` `patterns`. `in_list` and `not_in_list` test a string field against one, ignoring ASCII case. A file can define a list, or `extend` or `replace` a built-in one.
- Two lists are built in. `credential_dummies` holds `""`, `REPLACE_ME`, `CHANGEME`, `CHANGE_ME`, `PLACEHOLDER`, `TODO`, `DUMMY`, `XXX` and `TBD`. `credential_references` holds `${*}`, `{{*}}`, `$(*)`, `vault:*`, `arn:aws:secretsmanager:*` and `arn:aws:ssm:*`.
- `all_in_field` holds when every item of a list is also in another list field of the same element.

### One finding per cause

These rules no longer match what a more specific rule reports for the same cause. A policy that names one should also name the rule that covers it.

- **Dynamic SQL.** A call that is not a literal, fully quoted or bound raises one rule, at the statement that runs the SQL and never at the routine's `CREATE`:
  - `DYNSQL-CONCAT` for a concatenated or `FORMAT` argument;
  - `DYNSQL-PARAM-TEXT` (new) for a routine's parameter run as written;
  - for any other argument, `PROC-DYNSQL` in a procedure body and `UDF-DYNSQL` in a function body, else `DYNSQL-NO-PARAM` where the call can bind and `DYNSQL` where it cannot.

  `DYNSQL-QUOTE-MISMATCH`, `DYNSQL-LITERAL-QUOTER-IDENT` and `DYNSQL-CROSS-SERVER` also report at the call. `DYNSQL-PARAM-CLEAN` (info) reports a text built only from literals, quoted values and variables the script only ever sets to its own literals; the statements such a text holds are analyzed and reported where it runs.
- `DIFF-WHERE-RMV` is covered by `DIFF-WRITE-WHERE-RMV`; `DIFF-LIMIT-RMV` and `DIFF-QUALIFY-RMV` by their `-MULTI` rules.
- `Q-NONDET` by `Q-AGG-NONDET` and `Q-WIN-NONDET`; `Q-SUBQ-SCALAR` by `Q-SUBQ-CORR-SEL` for a correlated subquery.
- `Q-JOIN-DISTINCT-MASK` by `Q-JOIN-DISTINCT-MASK-CENH`; `Q-JOIN-TEMPORAL-CENH` by `Q-MULTI-TEMPORAL-CENH`.
- A window without `PARTITION BY` is reported by the first that applies of `Q-WIN-UNBOUNDED-CENH`, `Q-WIN-NOPART-CENH` and `Q-WIN-NOPART`.
- An aggregate with no effective `WHERE` is reported by the first that applies of `Q-AGG-EXPLODE-CENH`, `Q-AGG-NOFILT-CENH` and `Q-AGG-NOFILT`; `Q-TBL-UNBOUNDED-CENH` keeps the large unfiltered queries that aggregate nothing.
- `BQ-MODEL-EXPORT` by `BQ-MODEL-EXPORT-EXTSTORE` for a cloud storage URI.
- `DIFF-TBL-ADD` and `DIFF-TBL-RMV` no longer match table functions (`DIFF-TVF-ADD`, `DIFF-TVF-RMV`). `DB-DROP` no longer matches `DROP DATABASE ENCRYPTION KEY` (`MSSQL-DEK-DROP`). `DBX-EXTLOC-URL-CHG` no longer matches a rename (`DBX-EXTLOC-NAME-CHG`).

### New rules

**Critical**
- `TBL-OVERWRITE`: an `INSERT OVERWRITE` that names no partition replaces every row of its table.
- `DYNSQL-PARAM-TEXT`: a procedure or function runs one of its parameters, written alone, as SQL.
- `PG-LO-FILE-ACCESS`: a query calls `lo_export` or `lo_import`.
- `MYSQL-UDF-SONAME`: `CREATE FUNCTION … SONAME 'lib'`.
- `VIEW-RAP-RMV`, `VIEW-RAP-RMV-ALL`, `VIEW-MASK-RMV`, `VIEW-AGGPOL-RMV`: an `ALTER VIEW` or `ALTER MATERIALIZED VIEW` drops a row access policy or all of them, unsets a column's masking or projection policy, or unsets an aggregation or join policy.

**High**
- `SNW-USER-NETPOL-UNSET`: `ALTER USER … UNSET NETWORK_POLICY`.
- `MSSQL-DEK-DROP`: `DROP DATABASE ENCRYPTION KEY`.
- `RS-UNLOAD-CLASSIFIED`: a Redshift `UNLOAD` writes a classified column to S3. `SNW-EXPORT-CLASSIFIED` and `SNW-EXPORT-UNBOUNDED` stay `COPY INTO <location>` rules.

**Medium**
- `SCHEMA-DROP-RESTRICT`: a `DROP SCHEMA` that is refused while the schema holds any object. `SCHEMA-DROP` (critical) now matches only a drop that removes the schema's objects.
- `PG-RLS-ROLE-ALL-ROWS`: a PostgreSQL policy that is always true for the roles it names. `RAP-ALLOW-ALL` and `PG-RLS-WEAK-CHECK` (critical) match such a policy only when it names no role or `PUBLIC`.
- `Q-FLOW-TAINT-WRITE`: a write puts a tagged value into a column without that tag.
- `RS-UNLOAD-UNBOUNDED`: a Redshift `UNLOAD` whose query reads a table with no `WHERE`.
- `SNW-USER-KEY-SET`, `SNW-USER-ENABLE`: `ALTER USER` sets an RSA public key, or `DISABLED = FALSE`.
- `VIEW-SECURE-RMV`: an `ALTER VIEW` removes `SECURE`.
- `DIFF-TRIG-RMV`, `DIFF-TVF-ARG-CHG`, `DIFF-MODEL-BUILD-CHG`, `DIFF-WRITE-TARGET-CHG`: a change removes a trigger, changes a table function's arguments, changes how a dbt model is built, or makes a statement write another object.

**Low**
- `USER-PWD-SET`: `ALTER USER` or `ALTER ROLE` sets a password, whatever the value.
- `DBX-EXTLOC-NAME-CHG`: `ALTER EXTERNAL LOCATION … RENAME TO`.
- `DIFF-COL-RENAME`: a change renames an output column that keeps its value.

**Info**
- `VIEW-RAP-ADD`, `VIEW-MASK-ADD`, `DIFF-TVF-ADD`, `DIFF-TVF-RMV`, `DIFF-QUALIFY-CHG`.

`DIFF-NULL-EXPANSION`, `DIFF-LINEAGE-LOSS`, `DIFF-TAINT-PROPAGATION` and `DIFF-CONSTRAINT-RELAX` never matched in v2.0.0 and now fire, comparing each side's output columns by name.

### Changed rules

**Credentials.**
- The leak rules (`CRED-AWS-LEAK`, `CRED-PWD-LEAK`, `CRED-APIKEY-LEAK`, the BigQuery leak rules, `MSSQL-LINKEDSRV-LOGIN-CRED`, the T-SQL `*-INLINE-PASSWORD` rules) skip a value either built-in list matches.
- `CRED-DUMMY-VALUE` moves from info to medium, matches a dummy in any casing, and covers T-SQL key statements, BigQuery `OPTIONS`, storage credentials and `sp_addlinkedsrvlogin`.
- `CRED-PWD-LEAK`, `CRED-CONNSTR-LEAK`, `BQ-{EXPORT,LOAD,EXTTBL,MODEL}-PWD-LEAK` and `BQ-{EXPORT,LOAD,EXTTBL,MODEL}-CONNSTR-LEAK` read the password of a URL's user information. `MSSQL-OPENROWSET-INLINE-CRED` and `MSSQL-OPENDATASOURCE-INLINE-CRED` read a connection string's password entry. A URL whose user information holds no password no longer matches.
- `CRED-INLINE-AUTH` skips a role the cluster assumes (`iam_role`, `aws_iam_role`).

**Grants and policies.**
- `GRT-SYSROLE-EXP` matches a grant that gives an admin role to another role; `GRANT ROLE custom TO ROLE SYSADMIN` no longer matches.
- `GRT-TO-PUBLIC` matches a grant to Databricks' `account users`, and its message names no account.
- `GRT-ALL-PRIV` skips a grant on a function or procedure, and `PG-DEFAULT-PRIV-ALL` one on functions, routines or types.
- `PG-RLS-DROP` and `PG-RLS-CASCADE-DROP` are high.
- `SNW-AUTHPOL-MFA-OFF` matches a policy that allows password authentication without MFA.
- `SNW-AGGPOL-NOCONST`, `SNW-AGGPOL-NOCONST-CHG`, `SNW-JOINPOL-PERMISSIVE` and `SNW-PROJPOL-ENFORCE-OFF` match a body whose default result removes the constraint; a `CASE` that exempts one role and constrains the rest does not match.
- `PROC-EXECAS-OWNER` also matches a procedure that runs as its owner by the dialect's default, such as a Snowflake procedure created without `EXECUTE AS`.

**Tables and writes.**
- `DML-WRITE-UNBOUNDED` skips a write that a join, a row cap or the query it writes through bounds, and a write to a temporary table or a table variable.
- `TBL-DROP` and `TBL-TRUNCATE` skip a temporary table. `TBL-REPLACE` skips a temporary table and a Databricks `CREATE OR REFRESH` pipeline declaration. `SNW-TBL-RETENTION-ZERO` skips a transient table.
- `CAT-TBL-UNKNOWN` reports each missing table once per statement, the targets it writes included.

**Queries.**
- `Q-JOIN-LEFT-FILT` also matches a later join that drops the rows an outer join padded.
- `Q-AGG-EXPLODE-CENH` fires only where the catalog shows the join keys have no unique constraint.
- `Q-NULL-NOTIN` matches a `NOT IN` subquery that is one of several `AND`ed conditions.
- `Q-JOIN-FANOUT-CENH` no longer matches a semi or anti join. `Q-JOIN-DISTINCT-MASK`, its `-CENH` rule and `Q-JOIN-TEMPORAL-CENH` skip a query whose per-row calls are all built-ins.

**SQL Server, PostgreSQL and routines.**
- `MSSQL-SPCONFIG-XPCMDSHELL`, `MSSQL-SPCONFIG-OLE-AUTOMATION`, `MSSQL-SPCONFIG-ADHOC-QUERIES`, `MSSQL-SPCONFIG-XDB-CHAINING` and `MSSQL-SPCONFIG-CLR` match an `sp_configure` call that turns the option on, not one that displays it.
- `PG-COPY-TO` matches a `COPY … TO` a server file; `COPY … TO STDOUT` no longer matches, and `COPY … TO PROGRAM` is `PG-COPY-PROGRAM`.
- The procedure, function and `DYNSQL` rules match T-SQL `ALTER PROCEDURE` / `ALTER FUNCTION` and a T-SQL or MySQL trigger's body. `TRIG-NEW`, `PG-TRIG-OFF` and `INFO-PG-TRIG-ON` match T-SQL's trigger statements.
- `DYNSQL-CROSS-SERVER` also matches `OPENQUERY`, `OPENROWSET`, `dblink_send_query` and `dblink_open`.

**Diff.**
- `DIFF-PROJ-CHG` also covers the value a write puts in a column, and no longer fires on the columns after one that was inserted, removed or reordered.
- `DIFF-AGG-ARG-*` raise one finding per changed aggregate input. `VIEW-CHG` also matches `ALTER MATERIALIZED VIEW`. `TRIG-DROP` matches a `DROP TRIGGER` in `diff`.

**Messages.** The `DIFF-*` messages name the column, join, table or function they are about. `CAT-TBL-UNKNOWN` names the table as written and where it was looked for, and `CAT-COL-UNKNOWN` and `CAT-COL-AMBIGUOUS` name the column. The messages of `Q-NULL-NEQ`, `Q-PROP-CONTRA`, `Q-SUBQ-CORR-SEL`, `Q-SUBQ-SCALAR`, `Q-FLOW-DROP-REF`, `Q-FLOW-RENAME-REF` and `Q-FLOW-COL-DROP` are reworded.

## 2.0.0

First published version.
