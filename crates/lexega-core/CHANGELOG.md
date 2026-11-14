# Changelog

## 3.0.0

Rule results are findings, info-level rules report context, reports mask values unless shown safe, and each statement has one fact record. The fact fields a rule reads are listed in full by the rules schema, version 2, at `schemas/v2/`; this entry names what changes for code that links the crate.

### Breaking

**Names.**
- `rules::Signal` is `rules::Finding`, `SignalEvidence` is `FindingEvidence`, `EngineSignal` is `EngineFinding`. `analyzer::AnalysisSignal` is `AnalysisFinding`, `SignalSource` is `FindingSource`, `StatementSignals` is `StatementTrace`.
- Report fields are written under their new keys and still read under the old ones. `RISK_SCHEMA_VERSION` is 2. Fields that were never filled, `positive_signals` among them, are removed.

**Reports.**
- An info-level rule's entries go in `AnalysisReport.context`. They are not counted as findings and are not written as SARIF results or GitLab SAST vulnerabilities.
- A string or number from the analysed SQL prints only where it is shown to hold no secret; every other value prints as `'****'` in previews, statement prefixes, SARIF snippets, traces and facts. `redact_secrets_for_display` takes the dialect.
- Positions: `RiskEvidence::RuleMatch` has `position`; `location` and `column_number` count characters, and SARIF `startColumn` counts UTF-16 units. `LineIndex::get_column_number` is removed in favour of `LineIndex::position` and `offset_at`.
- `analyzer::ToolRun` gains `run_notes`, `macro_files`, `skipped_files` and `unrendered_files`.

**Facts.**
- A statement has one `StatementFacts`, which every family that reads it fills. A custom rule matches a statement once; 2.0.0 evaluated a DDL or GRANT statement twice. A `CALL` is always kind `call`.
- `ScopeFacts::lateral_flattens` is replaced by `table_functions`. Three or more operands at one precedence form one `OperatorChain`.
- `ScriptContext::enclosing` is a list, outermost first.
- `DiffEvent::NullabilityChanged`'s sides and `OutputColumnFact::sources` are optional.
- An exhaustive `match` on `StatementKind`, `DiffEvent`, `DynamicSqlSurface`, `ScalarOp`, `BinOpKind`, `UnaryOpKind`, `Lit`, `ConstraintFactArm`, `EnclosingKind`, `MfaEnrollmentLevel` or `SecurityObjectKind` needs the new variants.
- `facts::extract::minimal_ddl_statement` is no longer public.
- The policy facts `has_no_aggregation_constraint`, `has_join_not_required` and `has_enforcement_disabled` hold only for the body's default result.

**Rule files.**
- `V1RulesFile`'s `lists` and `rules` are both optional. `LoadError` has ten new variants, and `CompileError` has `UnknownStatementKind`.
- A rule's `any_of` gives the witnesses of every matching arm, and a message placeholder naming an object prints the object's name, not JSON.

**Engine, configuration and catalogs.**
- `Engine::apply_dialect` and `set_normalization_dialect` return a `DialectScope`; names are folded under it until it is dropped, and folding a name outside one panics in a debug build. The normalizer moved to `lexega-syntax` and is re-exported at the same paths.
- `AnalysisConfig::custom_rules` is an `Option<Arc<[Rule]>>` (build it with `Some(rules.into())`). A configuration written out field by field also needs `function_catalogs` and `masking`.
- `CatalogIndex::from_snapshot` takes `impl Into<Arc<CatalogSnapshot>>`. `CatalogSnapshot::enrich_column_tags` and `from_source_column_tags` take a `CatalogProvider`. `ModelCatalog::get` is `resolve(&TableRef)`.
- `VariableContext::load_from_snowsql_config` and `strict_mode_from_env` return a `Result`. `NewlineStyle::Auto` is the default, so `format_sql` keeps CRLF line endings.

**The reasoning seam.**
- `QueryReasoning`, `Reasoning`, `ScriptReasoning`, `ScriptInputs`, `QueryInputs` and `CatalogCtx` change. `QueryReasoning` gains `output_constraints`, `output_unique` and `output_catalog_tags`; `Reasoning` gains `routines_elsewhere` and `rows_of_either`; `ScriptInputs` gains `earlier` and `temporary_drops`; `CatalogCtx` gains `output_columns` and `placeholders`.
- `ScriptReasoning::call_site_calls` is `DynamicSqlClassifier::call_site_calls`, and `CallSite` carries the `parameters` of the routine holding the call. `Reasoning::dynamic_sql_literal_bodies` is `ScriptReasoning::dynamic_sql_literal_bodies` and takes no source file. `DynamicSqlClassifier::variable_shape` is removed.
- `ScriptReasoning::exported_columns` takes `&QueryFacts`; `attach_stale_references` takes the `TablePlaces` and counts positions across nested statements; `inter_procedural_calls` takes the routine's parameters. `DynamicBodyOutcome::findings` pairs each finding with the span of the statement that runs the body.
- `ir::dynamic_sql::rank` and `lattice_join` rank an undecided shape above the shapes shown clean.

**`ir` types.**
- `RelPlan::{Insert, Update, Delete, Merge}` gain `target_node` and `target_read_columns`; `Update` and `Delete` have `target_row`, `Delete` has `deleted_sources`, `Merge` has `only`. `CteRef`, `DerivedTable`, `Filter`, `Window`, `Aggregate`, `Join`, `ColumnOrigin` and `ScalarExpr` change.
- `ddl_plan::DdlSchemaMutation` gains `RenameColumn`, `SwapWith`, `SetColumnTags`, `UnsetColumnTags`, `ColumnsUnread` and `NamesUnread`. `ir::catalog::NullBehavior` gains `NullOnlyWhenAllNull`. `SqlType` has `params`.
- `IrLowerInputs` has `placeholder_spans` and `meaning`. `DdlPlan` can no longer be built outside the crate. `LoweredBodySink::rel` and `ddl` take the span of the body statement.
- The stage lowerings take an `ir::StageLocation`, the `CREATE` / `ALTER STAGE` and storage-credential lowerings take the placeholder spans, and `lower_unload_to_stage_plan` takes the query's span and source. `collect_openrowset_calls` and `collect_opendatasource_calls` return `RemoteSourceArg`s. `IrBqOptionsDetail::all_literal_values` holds `IrBqLiteral`s. The four T-SQL key functions take the statement's source text, and their facts gain `password_literals`. `MssqlExecArgFacts` has a field that is not serialized, so it cannot be written out field by field.
- `CatalogContext` gains `column_exposure` and `column_value_tags`; `PredicateFact` gains `field_path` and `variable`.

**Extraction and templates.**
- `ExtractedSql::dialect_hint` is removed, so a Databricks `%sql` cell is read in the caller's dialect. `origin_line` and `origin_col` are replaced by `origin: TextPosition` and `placed`. `extract::extract_sql_from_file` returns `Option<Result<…>>` and refuses a `.ipynb` file that is not a notebook.
- A `RenderArtifacts` written out field by field needs `session_sql`. `ast::AstCreateProcedureStmt` has `language`.

### New

- **Reports:** `AnalysisReport::{entries, separate_context, retain_at_least, recount}`; `Engine::analyze_for_comparison` and `ScriptAnalysis` (`statement_facts`, `findings_of`, `masked_sql`, `finding_preview`); `rules::rule_holds`.
- **Rule files:** `lists:` with `ScalarOp::{InList, NotInList, AllInField}`; `masking:` with `shown_column_tags`; `rules::{ValueList, ValueLists, ListChanges, MaskingPolicy, ShownColumnTag}`; `load_v1_rules_from_toml`. An entry under a former rule id applies to the rule that absorbed it.
- **Scripts run in order:** `Engine::analyze_script_carrying` with `CarriedRelations`; `for_each_statement_run` and `ScriptReading`; `ModelCatalog::{as_of, defer, make}`.
- **Query facts:** `output_columns`, `written_columns`, `target_rows`, `tables_used`, `function_calls`; `JoinEvent::dropped_padded_columns`; `source_span` on table reads and writes; `DynamicSqlCall::argument_parameter`.
- **DDL facts:** `ddl.table.temporary`, `ddl.options.if_not_exists`, `ddl.view.{secure, action}` and the view policy changes, `ddl.principal.password_set`, `ddl.function.loadable_library`, `DdlFacts::trigger_body`, and the URL and connection-string password facts on stages, storage credentials and `OPENROWSET`.
- **Diff events:** `ColumnRenamed`, `write_target_changed`, `qualify_changed`, `model_config_changed`; `within` and `source_span` on clause, join and window events.
- **Templates:** `template::{ProjectPaths, ProjectTree, ProjectsOnDisk, SourceMap}`, `macro_path_owners`, `is_macro_file`; `RenderArtifacts::session_sql`.
- **Configuration:** `AnalysisConfig::{masking, function_catalogs, session_db, session_schema}`; `ir::DialectCatalogs`.

### Behaviour

**Masking.** Every report surface quotes a script through one decision per literal, and it fails closed. A value is shown where the run shows it holds no secret: a date or number written straight into its column, a value compared with a column no statement writes, a type's length, a setting the dialect documents as holding none. A column named for a credential masks what is written into or compared with it. After a statement whose writes the run cannot read, such as a call of a procedure it does not define, later comparisons are masked too. Text no reader parsed prints only its keywords and punctuation.

**Tables across statements.** With or without a catalog, a table or view a script makes, alters, renames or drops is read by the statements after it as the script left it, its columns and their tags included. A bare name resolves along the session's search path. Triggers, table inheritance and routines that may write are followed. Under `analyze_script_carrying`, a script reads what the scripts before it left.

**Writes.** A write's bound reads its joins and row caps, and a table is temporary only where every path makes it so. The summary counts the tables the query of a `CREATE TABLE … AS` or of a view reads.

**Dynamic SQL.** The SQL a routine of the dialect runs (`OPENQUERY`, dblink's functions, `sp_executesql` and the like) is analysed as an `EXECUTE`'s. Each literal a variable may hold is analysed where a statement runs it. An unread sqlcmd command counts as skipped and fails strict mode with `E_STRICT_NOT_READ`.

Building needs Rust 1.99.

## 2.0.0

First published version.
