# Lexega rule corpus

The built-in rules of [Lexega](https://lexega.com): 930 predicates over the
facts [`lexega-core`](../crates/lexega-core) extracts from a SQL statement,
written as data in [`builtin_rules.yaml`](builtin_rules.yaml).

`lexega-core` compiles this file into the engine at build time, and
`lexega analyze` evaluates it against every statement. A custom rule file
(`--custom-rules`) has the same format; it can add rules, and change the
severity or message of one of these or switch it off.

## A rule

```yaml
- id: GRT-WITH-OPT
  risk_level: high
  message: "Avoid WITH GRANT OPTION. This allows the grantee to re-grant privileges and can lead to privilege escalation."
  triggers:
    all_of:
      - kind: grant
      - privilege.with_grant_option: true
```

| Key | Meaning |
|-----|---------|
| `id` | Stable identifier, reported with every finding. |
| `risk_level` | `info`, `low`, `medium`, `high` or `critical`. |
| `message` | The finding text. `{path}` slots are filled from the facts. |
| `triggers` | The predicate: fact paths combined with `all_of`, `any_of`, `not` and quantifiers over lists. |
| `emission` | `once` per statement (the default) or `per_witness`, one finding per matching element. |
| `per_statement` | Keep each finding of the rule separate instead of merging them in a report. |
| `former_ids` | Identifiers the rule was published under before. They still resolve to it. |
| `enabled` | `false` switches the rule off. |

`lexega analyze --list-signals` prints the predicate syntax, and
`--explain-facts` prints the facts a statement produces. The schema of the
file is <https://lexega.com/schemas/v1/custom_rules.schema.json>.

## What is in it

By severity: 129 critical, 232 high, 286 medium, 182 low, 101 info.

An identifier starts with what the rule looks at: a platform (`SNW-`
Snowflake, `MSSQL-`, `PG-` PostgreSQL, `DBX-` Databricks, `BQ-` BigQuery,
`MYSQL-`, `RS-` Redshift), an object or statement family (`GRT-` grants,
`TBL-`, `MASK-`, `RAP-`, `DML-`, `Q-` queries, `DYNSQL-`, `CRED-`), or
`INFO-` for informational findings. A `-CENH` suffix marks a rule that needs
a catalog snapshot (`--catalog`).

## Depth

Every rule is evaluated. What a rule can see depends on the facts the engine
fills.

- 52 rules read a fact that needs analysis across scopes, statements or
  scripts. `lexega-core` on its own leaves those facts at their defaults, so
  these rules stay silent or report less precisely, and every report says how
  many rules that affects.
- 73 rules (`DIFF-*`) predicate on `diff` facts: what changed between two
  versions of a script. Nothing in `lexega-core` or `lexega-cli` produces
  those facts, so these rules do not fire there.

## Licence

Fair Source under the [Business Source License 1.1](LICENSE): free for any use
other than offering a competing product or service, converting to Apache-2.0
four years after each version is first published. "Lexega" is a trademark of
Lexega LLC.

## Contributing

The public repository is a per-release mirror of a private monorepo. Pull
requests are welcome and are applied upstream with attribution; a contributor
licence agreement is required.

A rule is data: adding or changing one means editing `builtin_rules.yaml`,
never engine code.
