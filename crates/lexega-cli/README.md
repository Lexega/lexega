# lexega-cli

The command line for [Lexega](https://lexega.com): format, analyze and review
SQL before it runs. It installs one binary, `lexega`, built on
[`lexega-core`](../lexega-core) and [`lexega-syntax`](../lexega-syntax), and
covers Snowflake, T-SQL, BigQuery, PostgreSQL, Redshift, Databricks and MySQL.

## Commands

| Command | What it does |
|---------|--------------|
| `lexega analyze <FILE\|DIR>` | Analyze a file, standard input or a directory (`-r`) against the built-in rule corpus and any custom rules. Output as text, JSON, YAML, Markdown, SARIF or GitLab SAST. |
| `lexega review <BASE..HEAD>` | Analyze the SQL files a commit range changes, as of its head commit. `--pr-comment` posts the result to the pull or merge request. |
| `lexega ci` | CI entry point: `review` on pull-request events, `analyze` on pushes, picked from the pipeline's own environment. |
| `lexega catalog` | Pull, inspect and diff catalog snapshots; `analyze --catalog` reads one. |
| `lexega fmt` | Format SQL. |

```sh
lexega analyze models/ -r --min-severity medium
lexega analyze --format sarif query.sql > results.sarif
lexega review origin/main..HEAD --pr-comment
```

## Depth

`lexega` analyzes each statement with the facts its own structure determines.
Rules that predicate on facts needing analysis across scopes, statements or
scripts stay silent or report less precisely, and every report says how many
rules that affects: the text and Markdown output carry a note, the JSON and
YAML summary an `analysis_depth` object, a SARIF run a tool notification, and
a GitLab SAST report a scan message. Jinja and dbt templates are analyzed as
written and reported as not rendered.

Options that need a capability this build does not have — a policy gate,
template rendering, cross-script analysis — are refused with a message naming
the capability, and are left out of `--help`. `LEXEGA_CI=1` asks for a run
gated by a policy, so it is refused too.

## Exit status

`analyze`, `review` and `ci` exit 0 when the analysis ran, whatever it found:
this build reports findings and has no policy gate to fail a run on them. They
exit 1 on an error, and on a statement that `--strict` rejects.

`fmt --check` exits 1 when a file would be reformatted, and `fmt --verify-only`
when formatting a file cannot be proven safe. `catalog pull` exits with its
extractor's status.

## Network access

`lexega` opens no network connection of its own. A run reaches the network
only when an option asks for it, and only through these programs:

| Option | Program | Reaches |
|--------|---------|---------|
| `catalog pull` | a catalog extractor from [`sidecars/`](sidecars) | the warehouse or workspace you name, with the credentials you pass |
| an `s3://`, `gs://` or `az://` location | `aws`, `gsutil`, `az` | your cloud storage, with that tool's own configuration |
| an `http(s)://` location | `curl` | that URL |
| `--pr-comment` | `curl` | the API of the CI platform the run is in (GitHub, GitLab, Azure DevOps, Bitbucket) |

`review` and `ci` run `git` against the local repository only.

## Catalog extractors

[`sidecars/`](sidecars) holds the programs `catalog pull` runs, one Go module
per platform so that each carries only its own dependencies:

| Extractor | Platform | Connects with |
|-----------|----------|---------------|
| `lexega-sf-catalog` | Snowflake | the Snowflake Go driver |
| `lexega-dbx-catalog` | Databricks | HTTPS `GET` requests to the workspace's Unity Catalog and SCIM APIs; no third-party dependency |
| `lexega-mssql-catalog` | SQL Server | the Microsoft SQL Server Go driver |

An extractor connects to one warehouse or workspace and reads metadata —
system views, `SHOW` output, and the platform's catalog and identity APIs,
never rows of your tables — then writes the snapshot `analyze --catalog`
reads. It issues no statement that writes.

Build one with `go build` in its directory. `catalog pull` runs the extractor
beside the `lexega` binary or on `PATH`, or the one `--sidecar` names; when
that file sits inside its Go module and is older than the source, it is
rebuilt with `go build` first.

Each extractor embeds the license notices for the Go modules it links and
prints them with `licenses`. After a dependency change, `go run notices.go`
in `sidecars/` regenerates them; an extractor's tests fail while its notices
are out of date.

## Extending it

The command drivers take an `Extension` (`lexega_cli::extension`): the session
that renders and analyzes sources, the policy gate, the template renderer `fmt`
uses, capability checks and additional commands. `lexega_cli::run` runs a
command line against one; `lexega_cli::recognition::Recognition` is the
extension this crate's binary uses.

## Licence

Business Source License 1.1 — see [LICENSE](LICENSE). Each version converts to
Apache-2.0 four years after its release.

`lexega --licenses` prints the notices for the third-party code the binary
contains ([THIRD_PARTY_LICENSES.txt](THIRD_PARTY_LICENSES.txt)); each catalog
extractor prints its own with `licenses`.
