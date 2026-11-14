// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_core::api::analyze_risk;

#[test]
fn risk_does_not_emit_partial_extraction_warning_for_table_function() {
    // Parser supports TABLE() syntax; semantic extraction should not treat it as "incomplete".
    let sql = "SELECT * FROM TABLE(my_udtf(10))";
    let report = analyze_risk(sql).expect("risk analysis should succeed");

    assert!(
        report.skipped_details.is_empty(),
        "Unexpected skipped statement details: {:?}",
        report.skipped_details
    );

    // Table function itself is not counted as a table read.
    assert_eq!(report.summary.tables_read, 0);
}

#[test]
fn risk_extracts_tables_from_mixed_from_items_with_lateral_table_function() {
    // This ensures table-function FROM items don't break extraction of other FROM tables.
    let sql = "SELECT * FROM orders, LATERAL TABLE(get_order_items(orders.order_id))";
    let report = analyze_risk(sql).expect("risk analysis should succeed");

    assert!(
        report.skipped_details.is_empty(),
        "Unexpected skipped statement details: {:?}",
        report.skipped_details
    );

    assert_eq!(
        report.summary.tables_read, 1,
        "Expected to read from orders"
    );
}

#[test]
fn merge_into_identifier_is_counted_as_a_write_even_if_object_is_dynamic() {
    // IDENTIFIER() constructs are explicitly modeled by the parser (AstObjectRef.identifier_arg).
    // We can't resolve the exact object deterministically, but we should not drop the write.
    let sql = r#"
MERGE INTO IDENTIFIER('prod.analytics.users') t
USING staging.user_updates s
ON t.user_id = s.user_id
WHEN MATCHED THEN UPDATE SET email = s.email;
"#;

    let report = analyze_risk(sql).expect("risk analysis should succeed");

    assert!(
        report.summary.tables_written >= 1,
        "Expected MERGE write to be detected"
    );
    assert!(
        report.summary.tables_read >= 1,
        "Expected MERGE USING source to be detected"
    );
}

/// Each published table function of the first scope, and the rules the
/// statement raises.
fn table_functions_and_rules(
    sql: &str,
    config: &lexega_core::analyzer::AnalysisConfig,
) -> (Vec<lexega_core::facts::TableFunctionEvent>, Vec<String>) {
    use lexega_core::analyzer::RuleMatch;
    let report = lexega_core::api::analyze_risk_with_policy_config(sql, config).expect("analyzes");
    let functions = report.statement_traces[0]
        .facts
        .as_ref()
        .and_then(|f| f.query.as_ref())
        .map(|q| q.scopes[0].table_functions.clone())
        .unwrap_or_default();
    let rules = report
        .findings
        .iter()
        .map(|m| match m {
            RuleMatch::Analysis(g) => g.matched_rule.clone(),
        })
        .collect();
    (functions, rules)
}

fn traced(dialect: lexega_core::dialect::DialectRef) -> lexega_core::analyzer::AnalysisConfig {
    lexega_core::analyzer::AnalysisConfig {
        trace_mode: true,
        dialect: Some(dialect),
        ..Default::default()
    }
}

#[test]
fn a_table_function_says_whether_the_dialect_has_it_built_in() {
    use lexega_core::dialect::{bigquery, mssql, mysql, postgres, snowflake};
    use lexega_core::facts::FunctionOrigin::{BuiltIn, User};
    let cases = [
        (
            "SELECT DISTINCT s.value FROM t r CROSS APPLY STRING_SPLIT(r.c, ',') s",
            traced(mssql()),
            BuiltIn,
        ),
        (
            "SELECT DISTINCT j.value FROM t r OUTER APPLY OPENJSON(r.c) j",
            traced(mssql()),
            BuiltIn,
        ),
        (
            "SELECT DISTINCT f.value FROM t r, LATERAL FLATTEN(input => r.c) f",
            traced(snowflake()),
            BuiltIn,
        ),
        (
            "SELECT DISTINCT s.value FROM t r, LATERAL SPLIT_TO_TABLE(r.c, ',') s",
            traced(snowflake()),
            BuiltIn,
        ),
        (
            "SELECT DISTINCT tag FROM t r, UNNEST(r.c) AS tag",
            traced(bigquery()),
            BuiltIn,
        ),
        (
            "SELECT DISTINCT e.value FROM t r CROSS JOIN LATERAL jsonb_array_elements(r.c) e",
            traced(postgres()),
            BuiltIn,
        ),
        (
            "SELECT DISTINCT j.a FROM t r, JSON_TABLE(r.c, '$[*]' COLUMNS (a INT PATH '$')) AS j",
            traced(mysql()),
            BuiltIn,
        ),
        (
            "SELECT DISTINCT c.id FROM t c CROSS APPLY dbo.orders_for(c.id) o",
            traced(mssql()),
            User,
        ),
        (
            "SELECT DISTINCT c.id FROM t c, TABLE(my_tvf(c.id)) o",
            traced(snowflake()),
            User,
        ),
        (
            "SELECT DISTINCT c.id FROM t c, my_fn(c.id) o",
            traced(postgres()),
            User,
        ),
    ];
    for (sql, config, origin) in &cases {
        let (functions, rules) = table_functions_and_rules(sql, config);
        assert_eq!(functions.len(), 1, "{sql}: {functions:?}");
        assert_eq!(functions[0].origin, *origin, "{sql}");
        // A user's function called per left row reads rows of its own, so
        // DISTINCT over it may mask a fan-out.
        assert_eq!(
            rules.iter().any(|r| r == "Q-JOIN-DISTINCT-MASK"),
            *origin == User,
            "{sql}: {rules:?}"
        );
    }
    // The verdict is the rule's: excluding the user's calls instead
    // reverses it.
    let custom = lexega_core::rules::load_v1_rules(
        r#"
rules:
  - id: Q-JOIN-DISTINCT-MASK
    risk_level: medium
    message: "DISTINCT over a join."
    triggers:
      query.scopes:
        each:
          all_of:
            - has_distinct: true
            - joins:
                exists:
                  right_source: correlated_table_function
            - table_functions:
                exists:
                  origin: built_in
"#,
    )
    .expect("rules parse");
    let flipped = lexega_core::analyzer::AnalysisConfig {
        custom_rules: Some(
            lexega_core::rules::build_v1_rule_corpus(custom, true)
                .expect("corpus")
                .into(),
        ),
        ..traced(mssql())
    };
    let (_, rules) = table_functions_and_rules(cases[0].0, &flipped);
    assert!(
        rules.iter().any(|r| r == "Q-JOIN-DISTINCT-MASK"),
        "{rules:?}"
    );
    let (_, rules) = table_functions_and_rules(cases[7].0, &flipped);
    assert!(
        !rules.iter().any(|r| r == "Q-JOIN-DISTINCT-MASK"),
        "{rules:?}"
    );
}

#[test]
fn a_table_function_says_whether_the_select_list_reads_its_columns() {
    use lexega_core::dialect::{bigquery, mssql, postgres, snowflake};
    // Each case: whether each call's columns are selected, and whether
    // DISTINCT may mask a fan-out. A select list that reads none of a
    // call's columns undoes the rows the call adds per left row, as
    // EXISTS would; one that reads them lists the call's values.
    let cases = [
        (
            "SELECT DISTINCT e.id FROM t e, LATERAL FLATTEN(input => e.payload) f \
             WHERE f.value = 'x'",
            traced(snowflake()),
            vec![false],
            true,
        ),
        (
            "SELECT DISTINCT r.id FROM t r CROSS JOIN LATERAL jsonb_array_elements(r.c) e \
             WHERE e.value = '1'",
            traced(postgres()),
            vec![false],
            true,
        ),
        (
            "SELECT DISTINCT e.id FROM t e CROSS APPLY OPENJSON(e.payload) j",
            traced(mssql()),
            vec![false],
            true,
        ),
        (
            "SELECT DISTINCT r.* FROM t r, LATERAL FLATTEN(input => r.c) f",
            traced(snowflake()),
            vec![false],
            true,
        ),
        (
            "SELECT DISTINCT f.value::string AS tag FROM t r, LATERAL FLATTEN(input => r.c) f",
            traced(snowflake()),
            vec![true],
            false,
        ),
        (
            "SELECT DISTINCT * FROM t r, LATERAL FLATTEN(input => r.c) f",
            traced(snowflake()),
            vec![true],
            false,
        ),
        (
            "SELECT DISTINCT f.* FROM t r, LATERAL FLATTEN(input => r.c) f",
            traced(snowflake()),
            vec![true],
            false,
        ),
        (
            "SELECT DISTINCT ROW_NUMBER() OVER (PARTITION BY f.value ORDER BY r.id) \
             FROM t r, LATERAL FLATTEN(input => r.c) f",
            traced(snowflake()),
            vec![true],
            false,
        ),
        (
            "SELECT DISTINCT (SELECT MAX(u.id) FROM u WHERE u.k = f.value) \
             FROM t r, LATERAL FLATTEN(input => r.c) f",
            traced(snowflake()),
            vec![true],
            false,
        ),
        (
            "SELECT DISTINCT f.value FROM t r, LATERAL FLATTEN(input => r.c) f, \
             LATERAL FLATTEN(input => f.value) g",
            traced(snowflake()),
            vec![true, false],
            true,
        ),
        // The second call's values are the first's elements' values.
        (
            "SELECT DISTINCT g.value FROM t r, LATERAL FLATTEN(input => r.c) f, \
             LATERAL FLATTEN(input => f.value) g",
            traced(snowflake()),
            vec![true, true],
            false,
        ),
        (
            "SELECT DISTINCT u2 FROM t a, UNNEST(a.c) AS u1, UNNEST(u1.y) AS u2",
            traced(bigquery()),
            vec![true, true],
            false,
        ),
        // A user's function: DISTINCT may mask its fan-out whatever is selected.
        (
            "SELECT DISTINCT c.id, o.x FROM t c CROSS APPLY dbo.orders_for(c.id) o",
            traced(mssql()),
            vec![true],
            true,
        ),
    ];
    for (sql, config, selected, masks) in &cases {
        let (functions, rules) = table_functions_and_rules(sql, config);
        let found: Vec<bool> = functions.iter().map(|f| f.columns_selected).collect();
        assert_eq!(&found, selected, "{sql}");
        assert_eq!(
            rules.iter().any(|r| r == "Q-JOIN-DISTINCT-MASK"),
            *masks,
            "{sql}: {rules:?}"
        );
    }
    // The verdict is the rule's: counting a call whose columns are
    // selected reverses it.
    let custom = lexega_core::rules::load_v1_rules(
        r#"
rules:
  - id: Q-JOIN-DISTINCT-MASK
    risk_level: medium
    message: "DISTINCT over a join."
    triggers:
      query.scopes:
        each:
          all_of:
            - has_distinct: true
            - table_functions:
                exists:
                  columns_selected: true
"#,
    )
    .expect("rules parse");
    let flipped = lexega_core::analyzer::AnalysisConfig {
        custom_rules: Some(
            lexega_core::rules::build_v1_rule_corpus(custom, true)
                .expect("corpus")
                .into(),
        ),
        ..traced(snowflake())
    };
    let (_, rules) = table_functions_and_rules(cases[0].0, &flipped);
    assert!(
        !rules.iter().any(|r| r == "Q-JOIN-DISTINCT-MASK"),
        "{rules:?}"
    );
    let (_, rules) = table_functions_and_rules(cases[4].0, &flipped);
    assert!(
        rules.iter().any(|r| r == "Q-JOIN-DISTINCT-MASK"),
        "{rules:?}"
    );
}

#[test]
fn a_bare_name_of_a_table_functions_column_is_a_read_of_the_call() {
    use lexega_core::dialect::{databricks, mssql, mysql, postgres, snowflake};
    // Each case: whether the call's columns are selected, and whether
    // DISTINCT may mask a fan-out. A column the call yields, named without
    // its alias, is the call's.
    let cases = [
        (
            "SELECT DISTINCT value FROM t o CROSS APPLY STRING_SPLIT(o.tags, ',')",
            traced(mssql()),
            true,
            false,
        ),
        (
            "SELECT DISTINCT o.id, value FROM t o CROSS APPLY STRING_SPLIT(o.tags, ',') s",
            traced(mssql()),
            true,
            false,
        ),
        (
            "SELECT DISTINCT [value] FROM t o CROSS APPLY OPENJSON(o.doc)",
            traced(mssql()),
            true,
            false,
        ),
        (
            "SELECT DISTINCT value FROM t o, LATERAL FLATTEN(input => o.tags)",
            traced(snowflake()),
            true,
            false,
        ),
        (
            "SELECT DISTINCT index, value::string FROM t o, TABLE(FLATTEN(o.tags)) f",
            traced(snowflake()),
            true,
            false,
        ),
        (
            "SELECT DISTINCT value FROM t o, jsonb_array_elements(o.doc)",
            traced(postgres()),
            true,
            false,
        ),
        (
            "SELECT DISTINCT unnest FROM t o, unnest(o.tags)",
            traced(postgres()),
            true,
            false,
        ),
        (
            "SELECT DISTINCT col FROM t o LATERAL VIEW explode(o.tags)",
            traced(databricks()),
            true,
            false,
        ),
        // A name no column of the call has is not the call's.
        (
            "SELECT DISTINCT o.id FROM t o, LATERAL FLATTEN(input => o.tags) \
             WHERE value = 1",
            traced(snowflake()),
            false,
            true,
        ),
        // The columns a call declares are its columns.
        (
            "SELECT DISTINCT a FROM t o, JSON_TABLE(o.doc, '$[*]' COLUMNS (a INT PATH '$')) AS j",
            traced(mysql()),
            true,
            false,
        ),
        (
            "SELECT DISTINCT a FROM t o CROSS APPLY OPENJSON(o.doc) WITH (a INT '$.a')",
            traced(mssql()),
            true,
            false,
        ),
        (
            "SELECT DISTINCT o.id FROM t o CROSS APPLY OPENJSON(o.doc) WITH (a INT '$.a') j \
             WHERE a = 1",
            traced(mssql()),
            false,
            true,
        ),
    ];
    for (sql, config, selected, masks) in &cases {
        let (functions, rules) = table_functions_and_rules(sql, config);
        let found: Vec<bool> = functions.iter().map(|f| f.columns_selected).collect();
        assert_eq!(found, vec![*selected], "{sql}");
        assert_eq!(
            rules.iter().any(|r| r == "Q-JOIN-DISTINCT-MASK"),
            *masks,
            "{sql}: {rules:?}"
        );
    }
}

#[test]
fn each_select_list_says_what_it_reads_of_its_own_calls() {
    use lexega_core::dialect::{postgres, snowflake};
    // Each case: whether each call's columns are selected, and whether
    // DISTINCT may mask a fan-out.
    let cases = [
        // A set operation's branches each have a select list: a star in
        // one reads the calls of that one.
        (
            "SELECT DISTINCT r.id FROM t r, LATERAL FLATTEN(input => r.c) f \
             UNION SELECT * FROM u, LATERAL FLATTEN(input => u.c) g",
            traced(snowflake()),
            vec![false, true],
            true,
        ),
        // A lateral subquery's column the list reads is the call's value.
        (
            "SELECT DISTINCT r.id, x.v FROM t r, LATERAL FLATTEN(input => r.c) f, \
             LATERAL (SELECT f.value AS v) x",
            traced(snowflake()),
            vec![true],
            false,
        ),
        (
            "SELECT DISTINCT r.id, x.v FROM t r, unnest(r.c) u, LATERAL (SELECT u AS v) x",
            traced(postgres()),
            vec![true],
            false,
        ),
        (
            "SELECT DISTINCT r.id FROM t r, LATERAL FLATTEN(input => r.c) f, \
             LATERAL (SELECT f.value AS v) x",
            traced(snowflake()),
            vec![false],
            true,
        ),
        // A star that leaves out every column of the call reads none.
        (
            "SELECT DISTINCT * EXCLUDE (seq, key, path, index, value, this) \
             FROM t r, LATERAL FLATTEN(input => r.c) f",
            traced(snowflake()),
            vec![false],
            true,
        ),
        (
            "SELECT DISTINCT r.id, f.* EXCLUDE (seq, key, path, index, value, this) \
             FROM t r, LATERAL FLATTEN(input => r.c) f",
            traced(snowflake()),
            vec![false],
            true,
        ),
        (
            "SELECT DISTINCT * EXCLUDE (seq, key, path) FROM t r, LATERAL FLATTEN(input => r.c) f",
            traced(snowflake()),
            vec![true],
            false,
        ),
        // QUALIFY reads the call; the select list does not.
        (
            "SELECT DISTINCT r.id FROM t r, LATERAL FLATTEN(input => r.c) f \
             QUALIFY ROW_NUMBER() OVER (PARTITION BY r.id ORDER BY f.index) = 1",
            traced(snowflake()),
            vec![false],
            true,
        ),
    ];
    for (sql, config, selected, masks) in &cases {
        let (functions, rules) = table_functions_and_rules(sql, config);
        let found: Vec<bool> = functions.iter().map(|f| f.columns_selected).collect();
        assert_eq!(&found, selected, "{sql}");
        assert_eq!(
            rules.iter().any(|r| r == "Q-JOIN-DISTINCT-MASK"),
            *masks,
            "{sql}: {rules:?}"
        );
    }
}

#[test]
fn a_databricks_lateral_view_joins_its_generator_to_each_row_before_it() {
    use lexega_core::analyzer::RuleMatch;
    use lexega_core::catalog::{CatalogIndex, CatalogSnapshot};
    use lexega_core::facts::{FunctionOrigin, JoinSource};
    let snapshot: CatalogSnapshot = serde_json::from_str(
        r#"{"schema_version": 2, "databases": [
            {"name": "ZZ", "schemas": [{"name": "DBO", "tables": [
                {"name": "ZZ_REAL", "kind": "Table", "columns": [{"name": "ID", "data_type": "INT", "nullable": true}, {"name": "C", "data_type": "ARRAY<INT>", "nullable": true}]}
            ]}]}
        ]}"#,
    )
    .expect("snapshot");
    let catalog = CatalogIndex::from_snapshot(snapshot).expect("index");
    let config = traced(lexega_core::dialect::databricks());
    let analyse = |sql: &str| {
        lexega_core::api::analyze_risk_with_policy_config_and_catalog_index(sql, &config, &catalog)
            .expect("analyzes")
    };
    // Each case: whether the select list reads the generator's columns,
    // and whether DISTINCT may mask a fan-out.
    for (sql, selected, masks) in [
        (
            "SELECT DISTINCT x FROM zz.dbo.zz_real r LATERAL VIEW explode(r.c) v AS x",
            true,
            false,
        ),
        (
            "SELECT DISTINCT x FROM zz.dbo.zz_real r LATERAL VIEW OUTER explode(r.c) v AS x",
            true,
            false,
        ),
        (
            "SELECT DISTINCT r.id FROM zz.dbo.zz_real r LATERAL VIEW explode(r.c) v AS x \
             WHERE x = 1",
            false,
            true,
        ),
        (
            "SELECT DISTINCT r.id, p, e FROM zz.dbo.zz_real r \
             LATERAL VIEW posexplode(r.c) v AS p, e",
            true,
            false,
        ),
        // `json_tuple` is one of the dialect's generators.
        (
            "SELECT DISTINCT a FROM zz.dbo.zz_real r LATERAL VIEW json_tuple(r.c, 'a') v AS a",
            true,
            false,
        ),
    ] {
        let report = analyse(sql);
        assert_eq!(report.summary.statements_analyzed, 1, "{sql}");
        assert!(report.skipped_details.is_empty(), "{sql}");
        let query = report.statement_traces[0]
            .facts
            .as_ref()
            .and_then(|f| f.query.as_ref())
            .expect("query facts");
        let joins: Vec<JoinSource> = query.scopes[0]
            .joins
            .iter()
            .map(|j| j.right_source)
            .collect();
        assert_eq!(joins, [JoinSource::CorrelatedTableFunction], "{sql}");
        let functions = &query.scopes[0].table_functions;
        assert_eq!(functions.len(), 1, "{sql}");
        assert_eq!(functions[0].origin, FunctionOrigin::BuiltIn, "{sql}");
        assert_eq!(functions[0].columns_selected, selected, "{sql}");
        // The generator is written after `LATERAL`.
        assert!(functions[0].lateral, "{sql}");
        let rules: Vec<&str> = report
            .findings
            .iter()
            .map(|m| match m {
                RuleMatch::Analysis(g) => g.matched_rule.as_str(),
            })
            .collect();
        assert_eq!(
            rules.contains(&"Q-JOIN-DISTINCT-MASK"),
            masks,
            "{sql}: {rules:?}"
        );
        // The column aliases name the generator's columns.
        assert!(!rules.contains(&"CAT-COL-UNKNOWN"), "{sql}: {rules:?}");
    }
    // A column of the table the generator reads is resolved there.
    let report =
        analyse("SELECT r.id, x FROM zz.dbo.zz_real r LATERAL VIEW explode(r.nope) v AS x");
    assert!(
        report.findings.iter().any(|m| match m {
            RuleMatch::Analysis(g) => g.matched_rule == "CAT-COL-UNKNOWN",
        }),
        "{:?}",
        report.findings
    );
}

#[test]
fn a_recursive_anchors_distinct_masks_no_join_of_the_step() {
    use lexega_core::analyzer::RuleMatch;
    let cases = [
        // The anchor's DISTINCT is over the anchor's rows; the join is the step's.
        (
            "WITH RECURSIVE r(p) AS (SELECT DISTINCT id FROM archive UNION ALL \
             SELECT o.user_id FROM orders o JOIN r ON r.p = o.user_id) SELECT p FROM r",
            false,
        ),
        (
            "WITH RECURSIVE r AS (SELECT DISTINCT id FROM archive UNION ALL \
             SELECT o.user_id FROM orders o JOIN r ON r.id = o.user_id) SELECT id FROM r",
            false,
        ),
        (
            "WITH RECURSIVE r(p) AS (SELECT DISTINCT UPPER(z.email) AS u FROM zz z UNION ALL \
             SELECT o.user_id FROM orders o JOIN r ON r.p = o.user_id) SELECT p FROM r",
            false,
        ),
        // The anchor's DISTINCT is over the anchor's own join.
        (
            "WITH RECURSIVE r(p) AS (SELECT DISTINCT u.id FROM users u \
             JOIN orders o ON o.user_id = u.id UNION ALL \
             SELECT r.p FROM r WHERE r.p < 0) SELECT p FROM r",
            true,
        ),
        (
            "SELECT DISTINCT u.id FROM users u JOIN orders o ON o.user_id = u.id",
            true,
        ),
    ];
    for (sql, masks) in cases {
        let report = analyze_risk(sql).expect("analyzes");
        let rules: Vec<&str> = report
            .findings
            .iter()
            .map(|m| match m {
                RuleMatch::Analysis(g) => g.matched_rule.as_str(),
            })
            .collect();
        assert_eq!(
            rules.contains(&"Q-JOIN-DISTINCT-MASK"),
            masks,
            "{sql}: {rules:?}"
        );
    }
}
