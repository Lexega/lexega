# Lexega

Lexega analyzes SQL before it runs. This repository holds its open edition:
the SQL front-end, the recognition engine, the rule corpus and the `lexega`
command line, for Snowflake, T-SQL (SQL Server), BigQuery, PostgreSQL,
Redshift, Databricks and MySQL.

```sh
lexega analyze models/ -r --min-severity medium
lexega analyze --format sarif query.sql > results.sarif
lexega review origin/main..HEAD --pr-comment
lexega fmt query.sql
```

## What is here

| Path | Contents |
|------|----------|
| [`crates/lexega-syntax`](crates/lexega-syntax) | Lexer, parser, AST/CST and byte-exact formatter. |
| [`crates/lexega-core`](crates/lexega-core) | The recognition engine: relational plan, statement fact base, rule evaluator, reports. |
| [`crates/lexega-cli`](crates/lexega-cli) | The `lexega` binary and the catalog extractors `catalog pull` runs. |
| [`rules`](rules) | The built-in rule corpus, as YAML data. |

Each has its own README, changelog and licence file. The four are released
together, under one version number.

## Install

Every release carries `lexega` for Linux, macOS and Windows, on x64 and
ARM64, at <https://github.com/Lexega/releases/releases/latest>:
`lexega-linux-x64`, `lexega-linux-arm64`, `lexega-darwin-x64`,
`lexega-darwin-arm64`, `lexega-windows-x64.exe`, `lexega-windows-arm64.exe`.
`CHECKSUMS.sha256` covers each file, and each binary has an SBOM beside it.

To build it from this repository, with Rust 1.91 or later:

```sh
cargo build --release --bin lexega
```

The binary is `target/release/lexega`. The catalog extractors are Go modules
under [`crates/lexega-cli/sidecars`](crates/lexega-cli/sidecars); build one
with `go build` in its directory.

## Depth

`lexega` analyzes each statement with the facts its own structure determines.
Rules that predicate on facts needing analysis across scopes, statements or
scripts stay silent or report less precisely, and every report says how many
rules that affects. Jinja and dbt templates are analyzed as written. Options
that need a capability this build does not have (a policy gate, template
rendering, cross-script analysis) are refused by name.
[`crates/lexega-cli`](crates/lexega-cli#depth) has the details, and
[`rules`](rules#depth) says which rules are affected.

Those analyses, policy enforcement and template rendering are part of the
Lexega product: <https://lexega.com>.

## Development

```sh
cargo test
cargo clippy --workspace --lib --bins
cargo doc --workspace --no-deps
```

`.cargo/config.toml` sets the stack sizes the deep-nesting fixtures need, so
run cargo from inside this repository.

## Licence

Fair Source under the [Business Source License 1.1](LICENSE) (`BUSL-1.1`):
free to use, modify and redistribute, in production too, for any purpose
except a Competing Use. Each version becomes available under the Apache
License 2.0 four years after its release. Each unit carries the same terms
in its own licence file, the one packaged with it:
[`lexega-syntax`](crates/lexega-syntax/LICENSE),
[`lexega-core`](crates/lexega-core/LICENSE),
[`lexega-cli`](crates/lexega-cli/LICENSE), [`rules`](rules/LICENSE).

Lexega is a trademark of Lexega LLC. The licence does not grant trademark
rights.

## Security

See [SECURITY.md](SECURITY.md).

## Contributing

This repository is a per-release mirror of a private monorepo and is updated
with every Lexega release. Issues and pull requests are welcome here. Pull
requests are applied upstream with attribution and appear in the next
mirrored release; contributors sign a contributor licence agreement on their
first pull request.
