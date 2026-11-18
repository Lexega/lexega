# Lexega rule corpus

The built-in rules of [Lexega](https://lexega.com): 970 predicates over the
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
| `risk_level` | `info`, `low`, `medium`, `high` or `critical`. An `info` rule reports context beside the findings, not a finding. |
| `message` | The finding text. `{path}` slots are filled from the facts. |
| `triggers` | The predicate: fact paths combined with `all_of`, `any_of`, `not` and quantifiers over lists. |
| `emission` | `once` per statement or `per_witness`, one finding per matching element. The default is `per_witness` where the triggers hold an `each:` quantifier, and `once` otherwise. |
| `per_statement` | Keep each finding of the rule separate instead of merging them in a report. |
| `former_ids` | Identifiers the rule was published under before. They still resolve to it. |
| `enabled` | `false` switches the rule off. |

`lexega analyze --rule-syntax` prints the predicate syntax, and
`--explain-facts` prints the facts a statement produces. The schema of the
file is <https://lexega.com/schemas/v2/custom_rules.schema.json>.

## Lists

A rule file may declare named lists of values and patterns beside `rules:`,
and a file may hold only `lists:`. A rule tests a string field against them
with `in_list` and `not_in_list`, each taking a list name or a list of names:

```yaml
lists:
  deploy_refs:
    values: [SET_BY_DEPLOY]
    patterns: ["{{*secrets.*}}"]
rules:
  - id: MY-HARDCODED-PASSWORD
    risk_level: high
    message: "Hardcoded password"
    triggers:
      all_of:
        - kind: create_stage
        - ddl.stage.credentials:
            exists:
              all_of:
                - key.normalized: { in: [PASSWORD] }
                - value_literal: { exists: true }
                - value_literal:
                    not_in_list: [credential_dummies, credential_references, deploy_refs]
```

Items must be strings (quote a number such as `1234`). A `*` in a pattern
matches any run of characters, and a pattern of only `*` is rejected.
Matching ignores ASCII case. Both operators read strings only: an absent or
non-string value makes both false. List names are unique in a file, and a rule naming a list that
does not exist is rejected, as is a file with neither `rules:` nor `lists:`.

Two lists are built in, and the inline-secret rules (`CRED-AWS-LEAK`,
`CRED-PWD-LEAK`, `CRED-APIKEY-LEAK`, `CRED-CONNSTR-LEAK`, `CRED-DUMMY-VALUE`, the BigQuery `*-PWD-LEAK`,
`*-APIKEY-LEAK` and `*-CONNSTR-LEAK` rules, `MSSQL-LINKEDSRV-LOGIN-CRED`, `MSSQL-OPENROWSET-INLINE-CRED`,
`MSSQL-OPENDATASOURCE-INLINE-CRED` and the T-SQL `*-INLINE-PASSWORD` rules) read them. A password
inside a URL (`s3://user:password@bucket`) or a connection string (`PWD=…`) is tested on its own:

| List | Holds |
|------|-------|
| `credential_dummies` | Placeholders: the empty string, `REPLACE_ME`, `CHANGEME`, `CHANGE_ME`, `PLACEHOLDER`, `TODO`, `DUMMY`, `XXX`, `TBD`. A dummy is reported as `CRED-DUMMY-VALUE`, not as a leak. |
| `credential_references` | Patterns for a reference to a secret held elsewhere: `${*}`, `{{*}}`, `$(*)`, `vault:*`, `arn:aws:secretsmanager:*`, `arn:aws:ssm:*`. A reference is no leak and no dummy. |

A file changes a built-in list with `extend` (add values and patterns) or
`replace` (swap its contents; an empty body empties it), which applies to the
built-in rules too, with `--no-builtin` as well:

```yaml
lists:
  credential_references:
    extend:
      patterns: ["vault://*"]
  credential_dummies:
    replace:
      values: ["", CHANGEME]
```

A custom message that fills a slot from a credential field
(`{mssql_key_management.password_literals}`) prints the value unmasked.

Defining a list under a built-in name is rejected: use `extend` or `replace`,
and drop `lists:` from a copy of the built-in file. Name your own lists for what
they hold and do not start them with `credential_` or another family word, which the
built-in list names use.

Accepted false negatives of the defaults: a value that matches a default
pattern is not reported even when it carries a literal secret, as in
`'${DB_PASSWORD:-S3cret}'` (a shell-style default) and
`'{{ var("db_password", "S3cret") }}'` (a dbt default argument), wherever the
text stays unrendered. A team that wants them reported replaces
`credential_references` with a list that leaves out `${*}` and `{{*}}`.

## What is in it

By severity: 97 critical, 85 high, 288 medium, 194 low, 306 info.

An identifier starts with what the rule looks at: a platform (`SNW-`
Snowflake, `MSSQL-`, `PG-` PostgreSQL, `DBX-` Databricks, `BQ-` BigQuery,
`MYSQL-`, `RS-` Redshift), an object or statement family (`GRT-` grants,
`TBL-`, `MASK-`, `RAP-`, `DML-`, `Q-` queries, `DYNSQL-`, `CRED-`), or
`INFO-` for a rule first published as informational; the prefix does not set its level. A `-CENH` suffix marks a rule that needs
a catalog snapshot (`--catalog`).

## Depth

Every rule is evaluated. What a rule can see depends on the facts the engine
fills.

- 57 rules read a fact that needs analysis across scopes, statements or
  scripts. `lexega-core` on its own leaves those facts at their defaults, so
  these rules stay silent or report less precisely, and every report says how
  many rules that affects. They are listed below.
- 81 rules (`DIFF-*`) predicate on `diff` facts: what changed between two
  versions of a script. Nothing in `lexega-core` or `lexega-cli` produces
  those facts, so these rules do not fire there.

<details>
<summary>The 57 rules that read a fact needing analysis</summary>

- `DML-MERGE-DELETE`
- `DML-MERGE-DELETE-BY-SOURCE`
- `DML-WRITE-UNBOUNDED`
- `DYNSQL`
- `DYNSQL-CONCAT`
- `DYNSQL-LITERAL-QUOTER-IDENT`
- `DYNSQL-NO-PARAM`
- `DYNSQL-PARAM-CLEAN`
- `DYNSQL-PARAM-TEXT`
- `DYNSQL-QUOTE-MISMATCH`
- `GRT-ACCESS-EXP`
- `GRT-ACCESS-EXP-HI`
- `GRT-BROAD-PRIV`
- `GRT-BROAD-PRIV-HI`
- `GRT-SYSROLE-EXP`
- `INFO-Q-PRED-TEMPORAL`
- `PROC-DYNSQL`
- `Q-AGG-EXPLODE-CENH`
- `Q-AGG-HICARD`
- `Q-AGG-MANYDIM`
- `Q-AGG-NOFILT`
- `Q-AGG-NOFILT-CENH`
- `Q-AGG-NONDET`
- `Q-FLOW-COL-DROP`
- `Q-FLOW-DROP-REF`
- `Q-FLOW-RENAME-REF`
- `Q-FLOW-TAINT`
- `Q-FLOW-TAINT-WRITE`
- `Q-JOIN-DISTINCT-MASK`
- `Q-JOIN-DISTINCT-MASK-CENH`
- `Q-JOIN-FANOUT-CENH`
- `Q-JOIN-FKVIOL-CENH`
- `Q-JOIN-LEFT-FILT`
- `Q-JOIN-NULL-CENH`
- `Q-JOIN-TEMPORAL-CENH`
- `Q-MULTI-TEMPORAL-CENH`
- `Q-NONDET`
- `Q-NULL-COUNT-CENH`
- `Q-NULL-EQ`
- `Q-NULL-NEQ`
- `Q-NULL-NOTIN`
- `Q-PRED-CONTRA`
- `Q-PRED-RANGE`
- `Q-PRED-REDUNDANT`
- `Q-PRED-TAUTOLOGY`
- `Q-PROP-CONTRA`
- `Q-SCAN-1TBL`
- `Q-SCAN-NOFILT`
- `Q-SUBQ-REPEAT`
- `Q-TBL-UNBOUNDED-CENH`
- `Q-WIN-HICARD-CENH`
- `Q-WIN-NONDET`
- `Q-WIN-NOPART`
- `Q-WIN-NOPART-CENH`
- `RS-UNLOAD-CLASSIFIED`
- `SNW-EXPORT-CLASSIFIED`
- `UDF-DYNSQL`

</details>

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
