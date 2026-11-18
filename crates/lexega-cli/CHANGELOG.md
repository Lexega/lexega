# Changelog

## 3.1.0

### Added

- `io::write_new_uri` writes to a local path, `s3://`, `gs://` or `az://` only where nothing is there yet, and says whether it wrote or found something already there.
- `io::HttpClient` (and `io::shared_http_client`) makes HTTP requests with rustls, the operating system's certificate store and the proxy the standard environment variables name, follows no redirect, and streams the response body (`io::HttpRequest`, `io::HttpResponse`, `io::HttpMethod`).

### Changed

- `io::HttpClient` fetches `https://` inputs and posts `--pr-comment`. `curl` is no longer run.

### Fixed

- `analyze --mode runtime` writes its decision to standard output unless `--decision-out` names a file. `--decision-out -` also means standard output.
- `--explain-findings` lists a finding raised in SQL a statement runs (an `EXECUTE IMMEDIATE` body) under the statement that holds it.

## 3.0.0

Reports say "finding", info-level rules report context, values are masked unless shown safe, and files are named by their path in the repository. Several usage mistakes that passed quietly in 2.0.0 now exit 1.

### Breaking

**Reports.**
- A report's `signals` is `findings`. In a batch summary, `files_with_signals`, `signals` and `top_risky_files[].signal_count` are `files_with_findings`, `findings` and `finding_count`. `--explain-signals` and `--list-signals` are `--explain-findings` and `--rule-syntax`; the old flags still work.
- Entries of info-level rules are context: kept only with `--min-severity info`, under a "Context" heading, not counted as findings, and not written as SARIF results or GitLab SAST vulnerabilities.
- A string or number of the analysed SQL prints only where it is shown to hold no secret; every other value prints as `'****'`. Comments inside a statement are left out of every preview.
- Every report names a file by its path from the git repository the run starts in, else from the working directory, however the path was typed. v2.0.0 used absolute paths for folder runs. Policy exceptions written with repository paths now apply to folder runs and to `ci` alike; a run started outside a repository names files from the working directory, so they do not match there.
- SARIF and GitLab SAST fingerprints change once, for a finding whose file is named differently or whose preview changed. A preview collapses whitespace before it is cut, so re-indenting a statement keeps its fingerprint.
- Top Matched Rules counts every occurrence of a rule (`top_matched_rules[].count`).
- Columns count characters, and SARIF counts UTF-16 code units.

**Policies.**
- A policy sees every finding and context entry; `--min-severity` only filters what a run shows.
- `review --policy` makes one decision per changed file, and needs `--env` and a `--decision-out` directory. v2.0.0 made one decision for the whole range.

**Exit codes and `--strict`.**
- `analyze`, `review` and `ci` exit 1 on an option given twice with different values, on `--stdin` with a path, on an unknown strict mode or dialect, on `--decision-out` without `--policy`, on a `--report-out` or `--decision-out` web address, and on `--explain-findings`, `--explain-facts` or `--verbose` with a batch.
- `--strict` fails a source whose template did not render (`E_STRICT_NOT_ANALYZED`), a batch with a path it could not read, a run whose SQL files are all dbt macro files, and a sqlcmd command that runs what the analysis does not read (`E_STRICT_NOT_READ`, where v2.0.0 gave `E_STRICT_OPAQUE`).
- `--no-builtin` with no custom rules runs no rules. v2.0.0 ran every built-in rule.
- `fmt` uses the default for every option `.lexega.toml` leaves out, so run `fmt -w` once after upgrading. `fmt` refuses `--write` when it renders templates.

**Extension API.**
- `Session::plan_batch` takes and returns `BatchFile`s. `Session` has `renders_templates` and `compares_changes`. `PolicyGate::decide` takes a `SourceCase`, and `PolicySetup` has `rules`. `FormatRenderer::render` takes the path the source was read from.
- `BatchPlan` gains `change` and loses `dbt_project_path`. `ChangeRange` gains `renamed_from` and `paths`; `git::ChangedSqlFiles` gains `renamed_from`; `git::get_changed_sql_files` fails with a `RangeError`.
- `io::collect_sql_files` takes every path of the run and its `template::ProjectsOnDisk`, and returns one `FoundFiles` per path. `SessionOptions`, `FormatRenderOptions` and `cmd_fmt::format_batch` carry the `ProjectsOnDisk`. `SkipReason` has `UnreadableDirectory`, its `MacroDirectory` carries the `MacroPathOwner`, and it is no longer `Copy`.
- `io::load_catalog_index_from_uri` and `load_catalog_index_from_uri_with_overlay` take the run's dialect. `usage::print_review_usage` takes the `Extension`.
- `output::get_signal_location`, `print_signal_explanation` and `usage::print_signal_catalog` are `get_finding_location`, `print_finding_explanation` and `print_rule_syntax`.
- `types::BatchProcessingConfig` and `artifacts::OutputFileFormat` are no longer public.

### Fixed

- `analyze` reads every path it is given as one batch; v2.0.0 analyzed only the last. A named file that cannot be read fails the run, and the rest is still reported.
- `review` reads `main...feature` the way git does, refuses a path that matches no file, and compares a moved file with its old path. `ci` on `pull_request_target` reviews the pull request's head, and `ci DIR` reads the directory recursively.
- Two files whose decision file names would be the same each get their own file; v2.0.0 wrote one over the other.
- `--pr-comment` and `az://` uploads stage their files in a private directory.
- `--scan-embedded` analyzes every fragment in the run's `--dialect`, and places each finding at its line and column in its file.
- Files and standard input are decoded by their byte-order mark, UTF-16 included.
- `lexega diff` and `lexega init` say they are part of the full build.

### New

- **Reports say what was not analyzed:** templates analyzed as written or that failed to render (`batch_summary.rendering`, `batch_summary.notes`), a change a `review` did not compare, each file skipped as a dbt macro file with the `dbt_project.yml` that decided, and each sqlcmd command that runs what the analysis did not read. The text and Markdown summaries are not all clear then.
- **dbt projects decide their own macro files:** a scan skips a file as a macro file where its project's `macro-paths` say so, not by a folder named `macros`. A project's tests and analyses are analyzed.
- **Options:** `--default-schema` (or `default_schema` in `.lexega.toml`'s `[session]` table) sets where a table named without a schema is looked for. `--report-out` writes the format its extension or `--report-artifact-format` names. `--custom-rules` reads the file's `masking:` policy. `--` ends the options.
- **A batch's text report goes to stdout,** and `-q` no longer hides it.
- **Extension API:** provided methods `Session::{not_compared, render_file, analyze_removed}` and `Extension::{reads_dialect, rendering_offer, comparison_offer}`; `io::{SessionCatalogs, rule_corpus, resolve_default_schema}`, `types::GivenOptions`, `git::{CommitRange, changes_sql_files, projects_holding_macros}`; `SessionOptions::{masking, default_schema, change}`.

Building needs Rust 1.99.

## 2.0.0

First published version.
