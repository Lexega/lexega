# lexega-syntax

SQL lexer, parser, AST/CST and byte-exact formatter for the dialects data
teams actually run: Snowflake, T-SQL (SQL Server), BigQuery, PostgreSQL,
Redshift, Databricks and MySQL.

`lexega-syntax` is the front-end of [Lexega](https://lexega.com), a
pre-execution SQL governance engine. It is published on its own so that
anyone building SQL tooling in Rust can parse what Lexega parses.

## What it covers

- **337 statement kinds**, typed. Beyond DML and query syntax: the full
  governance DDL surface — grants, roles, users, masking / row-access / tag /
  network / session / authentication / password policies, shares, stages,
  integrations, tasks, streams, external volumes, audits, credentials.
- **Scripting**: `BEGIN … END` blocks, `IF` / `WHILE` / `FOR` / `LOOP`,
  cursors, exception handlers, `DECLARE`, labels, procedure bodies; the inner
  statements are full AST nodes, not opaque text.
- **Dynamic SQL**: `EXECUTE IMMEDIATE`, `EXEC (...)`, procedure calls such
  as `sp_executesql`, and `PREPARE` / `EXECUTE`, with argument shapes lifted
  into typed expressions.
- **Dialect-driven lexing**: the dialect decides keywords, operators and
  quoting; the parser is permissive and does not branch on dialect for
  statement types. ODBC / JDBC escape sequences are desugared.
- **Jinja-aware**: dbt-style `{{ … }}` / `{% … %}` blocks are tokens, so
  templated SQL parses without rendering.
- **AST for structure, CST for text**: every token keeps its span and trivia.
  The formatter emits from the CST and never regenerates text, so formatting
  is byte-exact outside the whitespace it changes.
- **Secret spans**: credential literals (passwords, keys, `CREDENTIALS = (...)`
  blocks) are recorded as redaction spans at parse time so consumers can mask
  them from any output.
- **Bounded recursion**: a depth and stack budget turns pathological nesting
  into a clean parse error instead of a stack overflow.

## Usage

```rust
use lexega_syntax::{dialect_from_name, parse_sql_with_dialect};
use lexega_syntax::{format_sql_with_config, FormatterConfig};

let dialect = dialect_from_name("snowflake").unwrap();
let script = parse_sql_with_dialect(
    "GRANT SELECT ON ALL TABLES IN SCHEMA s TO ROLE public;",
    dialect.as_ref(),
)?;
assert_eq!(script.stmts.len(), 1);

let formatted = format_sql_with_config(
    "select a,b from t where x=1",
    &FormatterConfig::default(),
)?;
```

`FormatterConfig` controls keyword and identifier case, indentation, comma
style, clause layout and dialect; `tests/` contains fixtures for every
statement family and a formatting round-trip check (`verify_formatting_safe`)
that fails if formatting changes anything other than whitespace.

Dialect names accepted by `dialect_from_name`: `snowflake`, `postgresql`,
`mysql`, `bigquery`, `databricks`, `mssql`, `redshift` (with the usual
aliases such as `pg`, `tsql`, `spark`).

## Features

- `schema` — derives `schemars::JsonSchema` on the AST types.

## Licence

`lexega-syntax` is Fair Source, offered under the
[Business Source License 1.1](LICENSE) (`BUSL-1.1`). You may use, modify and
redistribute it, in production too, for any purpose except a Competing Use —
making it available in a commercial product that substitutes for the
software or for Lexega. Each version becomes available under the Apache
License 2.0 four years after its release.

Lexega is a trademark of Lexega LLC. The licence does not grant trademark
rights.

## Contributing

Development happens in Lexega's private monorepo; the public repository is
its mirror and is updated with every Lexega release. Issues and pull requests
are welcome there. Pull requests are applied upstream with attribution and
appear in the next mirrored release; contributors sign a contributor licence
agreement on their first pull request.

Run the test suite with `cargo test`. New statement kinds need a parser
module, an AST node, formatter support and fixtures under `tests/fixtures/`.
