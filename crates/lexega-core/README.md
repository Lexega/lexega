# lexega-core

The recognition engine behind [Lexega](https://lexega.com): it lowers parsed
SQL to a relational plan, projects each statement onto a typed fact base, and
evaluates a YAML rule corpus against those facts.

It builds on [`lexega-syntax`](../lexega-syntax) for lexing, parsing and the
AST, and covers Snowflake, T-SQL, BigQuery, PostgreSQL, Redshift, Databricks
and MySQL.

## What it does

- **Plan and lowering** — every statement kind the parser recognises lowers to
  a typed plan: a relational-algebra tree for query-bearing statements, a typed
  DDL plan for everything else.
- **Fact base** — one `StatementFacts` per statement: what it reads and writes,
  its predicates, joins and projections, the DDL it performs, the privileges it
  grants, the policies it defines, the dynamic SQL it executes.
- **Rules** — predicates over the fact base, written as YAML data. The built-in
  corpus ships with the crate; custom rules use the same format.
- **Reports** — findings with source positions, plus SARIF and GitLab SAST
  output.

## Usage

```rust
let report = lexega_core::api::analyze_risk("GRANT ALL ON DATABASE prod TO ROLE PUBLIC;")?;
for signal in &report.signals {
    println!("{signal:?}");
}
```

`lexega_core::api` holds the function-style entry points; each is a method
of `Engine` run on `Engine::recognition()`.

## Depth

`Engine::recognition()` produces every fact a statement's own structure
determines. Facts that need semantic analysis across scopes, statements or
scripts — nullability, lineage, taint, constraint propagation, dynamic-SQL
argument resolution, cross-statement schema state — are supplied by a
`Reasoning` provider; without one they stay at their defaults, and a rule
that reads one stays silent or reports more coarsely.
`facts::reasoning::REASONING_FIELDS` lists those facts, and every compiled
rule says whether it reads one (`rule.triggers.reads_reasoning()`).
A report produced without a provider says how many of the rules it evaluated
read one, in `summary.analysis_depth`.

## Licence

Fair Source under the [Business Source License 1.1](LICENSE): free for any use
other than offering a competing product or service, converting to Apache-2.0
four years after each version is first published. "Lexega" is a trademark of
Lexega LLC.

## Contributing

The public repository is a per-release mirror of a private monorepo. Pull
requests are welcome and are applied upstream with attribution; a contributor
licence agreement is required.
