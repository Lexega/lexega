// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Test various JOIN pattern recognition including edge cases
//! Verifies that keywords can be used as identifiers except when they start join patterns

use lexega_syntax::{ast::*, format_sql, parse_stmt_from_str};

fn parse_select(sql: &str) -> AstSelect {
    let stmt = parse_stmt_from_str(sql).expect("Failed to parse");
    match stmt {
        AstStmt::Select(select) => select.as_ref().clone(),
        _ => panic!("Expected SELECT statement"),
    }
}

#[test]
fn test_asof_join() {
    // Basic ASOF JOIN without MATCH_CONDITION
    let sql = "SELECT * FROM t1 ASOF JOIN t2 ON t1.id = t2.id";
    let select = parse_select(sql);
    assert_eq!(select.from.len(), 1);
    assert_eq!(select.from[0].joins.len(), 1);
    assert!(select.from[0].joins[0].asof_keyword_span.is_some());
    assert!(select.from[0].joins[0].match_condition.is_none());
}

#[test]
fn test_asof_join_with_match_condition() {
    // ASOF JOIN with MATCH_CONDITION - the full syntax
    let sql = "SELECT * FROM t1 ASOF JOIN t2 MATCH_CONDITION(t1.ts >= t2.ts) ON t1.id = t2.id";
    let select = parse_select(sql);
    assert_eq!(select.from.len(), 1);
    assert_eq!(select.from[0].joins.len(), 1);
    let join = &select.from[0].joins[0];
    assert!(join.asof_keyword_span.is_some());
    assert!(join.match_condition.is_some());
}

#[test]
fn test_asof_join_match_condition_using() {
    // ASOF JOIN with MATCH_CONDITION and USING clause
    let sql =
        "SELECT * FROM t1 ASOF JOIN t2 MATCH_CONDITION(t1.timestamp >= t2.timestamp) USING (id)";
    let select = parse_select(sql);
    assert_eq!(select.from.len(), 1);
    assert_eq!(select.from[0].joins.len(), 1);
    let join = &select.from[0].joins[0];
    assert!(join.asof_keyword_span.is_some());
    assert!(join.match_condition.is_some());
}

#[test]
fn test_asof_join_match_condition_only() {
    // ASOF JOIN with only MATCH_CONDITION (no ON or USING)
    let sql = "SELECT * FROM t1 ASOF JOIN t2 MATCH_CONDITION(t1.ts > t2.ts)";
    let select = parse_select(sql);
    assert_eq!(select.from.len(), 1);
    assert_eq!(select.from[0].joins.len(), 1);
    let join = &select.from[0].joins[0];
    assert!(join.asof_keyword_span.is_some());
    assert!(join.match_condition.is_some());
}

#[test]
fn test_match_condition_case_insensitive() {
    // MATCH_CONDITION should be case-insensitive
    let sql = "SELECT * FROM t1 ASOF JOIN t2 match_condition(t1.x <= t2.x)";
    let select = parse_select(sql);
    let join = &select.from[0].joins[0];
    assert!(join.match_condition.is_some());
}

#[test]
fn test_asof_as_alias() {
    // ASOF should work as an alias when not followed by JOIN
    let sql = "SELECT * FROM table1 AS asof";
    let select = parse_select(sql);
    assert_eq!(select.from.len(), 1);
    assert!(select.from[0].alias.is_some());
}

#[test]
fn test_outer_as_alias() {
    // OUTER should work as an alias
    // Note: Standalone "OUTER JOIN" (without LEFT/RIGHT/FULL) is NOT valid Snowflake syntax
    let sql = "SELECT * FROM table1 AS outer";
    let select = parse_select(sql);
    assert_eq!(select.from.len(), 1);
    assert!(select.from[0].alias.is_some());
}

#[test]
fn test_natural_left_outer_join() {
    // NATURAL LEFT OUTER JOIN should parse correctly
    let sql = "SELECT * FROM t1 NATURAL LEFT OUTER JOIN t2";
    let select = parse_select(sql);
    assert_eq!(select.from.len(), 1);
    assert_eq!(select.from[0].joins.len(), 1);
}

#[test]
fn test_left_directed_join() {
    // LEFT DIRECTED JOIN should parse
    let sql = "SELECT * FROM t1 LEFT DIRECTED JOIN t2 ON t1.id = t2.id";
    let select = parse_select(sql);
    assert_eq!(select.from.len(), 1);
    assert_eq!(select.from[0].joins.len(), 1);
}

/// Whether `sql` parses, in `dialect`, as one query whose first table has an alias.
fn first_table_has_alias(sql: &str, dialect: &dyn lexega_syntax::Dialect) -> bool {
    lexega_syntax::parse_sql_with_dialect(sql, dialect).is_ok_and(|script| {
        matches!(
            script.stmts.as_slice(),
            [AstStmt::Select(select)] if select.from.first().is_some_and(|t| t.alias.is_some())
        )
    })
}

#[test]
fn a_join_keyword_is_no_table_alias() {
    // Snowflake: "Cannot be used as table name or alias in a FROM clause".
    for word in ["inner", "left", "natural", "cross"] {
        let sql = format!("SELECT * FROM table1 AS {word}");
        assert!(
            !first_table_has_alias(&sql, &lexega_syntax::SnowflakeDialect),
            "{sql}"
        );
    }
}

#[test]
fn connect_and_start_are_a_table_alias_where_the_dialect_does_not_reserve_them() {
    for word in ["connect", "start"] {
        let sql = format!("SELECT * FROM table1 AS {word}");
        // Snowflake reserves both.
        assert!(
            !first_table_has_alias(&sql, &lexega_syntax::SnowflakeDialect),
            "{sql}"
        );
        assert!(
            first_table_has_alias(&sql, &lexega_syntax::PostgresDialect),
            "{sql}"
        );
    }
}

#[test]
fn test_asof_match_condition_formatter() {
    // Test that formatter outputs MATCH_CONDITION correctly
    let sql = "SELECT * FROM t1 ASOF JOIN t2 MATCH_CONDITION(t1.ts >= t2.ts) ON t1.id = t2.id";
    let formatted = format_sql(sql).expect("Failed to format");
    assert!(formatted.contains("MATCH_CONDITION"));
    assert!(formatted.contains(">="));
    assert!(formatted.contains("ASOF"));
    println!("Formatted SQL:\n{}", formatted);
}

#[test]
fn test_match_condition_not_consumed_as_alias() {
    // Ensure MATCH_CONDITION(expr) is not treated as a table alias
    let sql = "SELECT * FROM t1 ASOF JOIN t2 MATCH_CONDITION(t1.x >= t2.x) ON t1.id = t2.id";
    let select = parse_select(sql);
    let join = &select.from[0].joins[0];

    // The right table should NOT have MATCH_CONDITION as its alias
    assert!(
        select.from[0].joins[0].right.alias.is_none(),
        "MATCH_CONDITION should not be consumed as table alias"
    );

    // Instead, it should be in the match_condition field
    assert!(
        join.match_condition.is_some(),
        "MATCH_CONDITION should be parsed as join condition"
    );
}

#[test]
fn a_derived_table_before_using_keeps_its_join_constraint() {
    for (sql, alias) in [
        (
            "SELECT * FROM users b LEFT JOIN (SELECT user_id AS id FROM orders) a USING (id)",
            true,
        ),
        (
            "SELECT * FROM users b LEFT JOIN (SELECT user_id AS id FROM orders) USING (id)",
            false,
        ),
    ] {
        let select = parse_select(sql);
        let join = &select.from[0].joins[0];
        let AstJoinConstraint::Using(columns) = &join.constraint else {
            panic!("{sql}: expected USING, got {:?}", join.constraint);
        };
        assert_eq!(columns.len(), 1, "{sql}");
        assert_eq!(join.right.alias.is_some(), alias, "{sql}");
        assert!(join.right.result_alias.is_none(), "{sql}");
        assert!(join.right.result_alias_columns.is_none(), "{sql}");
    }

    // An alias with a column list after a wrapper clause is still one.
    let select = parse_select(
        "SELECT * FROM (SELECT k, c, v FROM t) PIVOT (SUM(v) FOR c IN ('a', 'b')) AS p (k, a, b) \
         JOIN u USING (k)",
    );
    let pivoted = &select.from[0];
    assert!(pivoted.result_alias.is_some());
    let listed = pivoted.result_alias_columns.as_ref().map(|c| c.len());
    assert_eq!(listed, Some(3));
    assert!(matches!(
        pivoted.joins[0].constraint,
        AstJoinConstraint::Using(_)
    ));
}

#[test]
fn a_join_written_inside_another_takes_the_condition_that_follows_it() {
    use lexega_syntax::dialect::{bigquery, databricks, mssql, mysql, postgres, snowflake};
    use lexega_syntax::{
        format_sql_with_config, parse_sql_with_dialect, verify_formatting_safe_with_dialect,
        FormatterConfig,
    };

    fn condition<'s>(sql: &'s str, join: &AstJoin) -> &'s str {
        let AstJoinConstraint::On(expr) = &join.constraint else {
            panic!("{sql}: expected ON, got {:?}", join.constraint);
        };
        let span = expr.span();
        &sql[span.start as usize..span.end as usize]
    }

    let sql = "SELECT * FROM a JOIN b JOIN c JOIN d ON c.x = d.x ON b.x = c.x ON a.y = b.y";
    for dialect in [
        snowflake(),
        postgres(),
        mysql(),
        bigquery(),
        databricks(),
        mssql(),
    ] {
        let script = parse_sql_with_dialect(sql, &*dialect).expect("parses");
        assert!(script.cut_statements.is_empty(), "{}", dialect.name());
        let [AstStmt::Select(select)] = script.stmts.as_slice() else {
            panic!(
                "{}: expected one SELECT: {:?}",
                dialect.name(),
                script.stmts
            );
        };
        let [outer] = select.from[0].joins.as_slice() else {
            panic!("{}: expected one join", dialect.name());
        };
        assert_eq!(condition(sql, outer), "a.y = b.y");
        assert!(outer.right.paren_group.is_none());
        let [middle] = outer.right.joins.as_slice() else {
            panic!("{}: expected one nested join", dialect.name());
        };
        assert_eq!(condition(sql, middle), "b.x = c.x");
        let [inner] = middle.right.joins.as_slice() else {
            panic!("{}: expected one innermost join", dialect.name());
        };
        assert_eq!(condition(sql, inner), "c.x = d.x");

        let config = FormatterConfig {
            dialect: dialect.clone(),
            ..FormatterConfig::default()
        };
        let formatted = format_sql_with_config(sql, &config).expect("formats");
        assert_eq!(
            formatted.split_whitespace().collect::<Vec<_>>().join(" "),
            sql
        );
        verify_formatting_safe_with_dialect(sql, &formatted, config.dialect.as_ref())
            .expect("round-trips");
    }

    // With no condition after them, the joins stay in the chain they are in.
    let select = parse_select("SELECT * FROM a JOIN b JOIN c ON b.x = c.x");
    let [first, second] = select.from[0].joins.as_slice() else {
        panic!("expected two joins in the chain");
    };
    assert!(matches!(first.constraint, AstJoinConstraint::None));
    assert!(first.right.joins.is_empty());
    assert!(matches!(second.constraint, AstJoinConstraint::On(_)));
    let select = parse_select("SELECT * FROM a JOIN b JOIN c JOIN d");
    assert_eq!(select.from[0].joins.len(), 3);
    assert!(select.from[0]
        .joins
        .iter()
        .all(|j| j.right.joins.is_empty()));
}

/// The first join of the first FROM item of `sql`, read in `dialect`.
fn first_join(sql: &str, dialect: &str) -> AstJoin {
    let dialect = lexega_syntax::dialect_from_name(dialect).expect("dialect");
    let script = lexega_syntax::parse_sql_with_dialect(sql, dialect.as_ref()).expect("parses");
    let Some(AstStmt::Select(select)) = script.stmts.first() else {
        panic!("not a SELECT: {sql}: {:?}", script.stmts);
    };
    let FromItemKind::TableRef(table) = &select.from[0].kind else {
        panic!("no table: {sql}");
    };
    (*table.joins[0]).clone()
}

#[test]
fn a_semi_or_anti_join_and_straight_join_are_read_where_the_dialect_has_them() {
    for (dialect, sql, kind, straight) in [
        (
            "databricks",
            "SELECT email FROM a x LEFT SEMI JOIN u y USING (email)",
            AstJoinKind::LeftSemi,
            false,
        ),
        (
            "databricks",
            "SELECT x.id FROM u x SEMI JOIN o y ON x.id = y.user_id",
            AstJoinKind::LeftSemi,
            false,
        ),
        (
            "databricks",
            "SELECT email FROM a x LEFT ANTI JOIN u y USING (email)",
            AstJoinKind::LeftAnti,
            false,
        ),
        (
            "databricks",
            "SELECT x.id FROM u x ANTI JOIN o y ON x.id = y.user_id",
            AstJoinKind::LeftAnti,
            false,
        ),
        (
            "mysql",
            "SELECT x.id FROM u x STRAIGHT_JOIN o y ON y.user_id = x.id",
            AstJoinKind::Inner,
            true,
        ),
    ] {
        let join = first_join(sql, dialect);
        assert_eq!(format!("{:?}", join.kind), format!("{kind:?}"), "{sql}");
        assert_eq!(join.straight_join_span.is_some(), straight, "{sql}");
    }
    // Where the word may be an alias it is one.
    let join = first_join("SELECT * FROM t semi JOIN u ON true", "snowflake");
    assert!(matches!(join.kind, AstJoinKind::Inner), "{:?}", join.kind);
}

#[test]
fn a_semi_or_anti_join_and_straight_join_format_as_written() {
    use lexega_syntax::{
        format_sql_with_config, verify_formatting_safe_with_dialect, FormatterConfig,
    };
    for (dialect, sql) in [
        (
            "databricks",
            "SELECT email FROM a x LEFT SEMI JOIN u y USING (email)",
        ),
        (
            "databricks",
            "SELECT x.id FROM u x ANTI JOIN o y ON x.id = y.user_id",
        ),
        (
            "mysql",
            "SELECT x.id FROM u x STRAIGHT_JOIN o y ON y.user_id = x.id",
        ),
    ] {
        let config = FormatterConfig {
            dialect: lexega_syntax::dialect_from_name(dialect).expect("dialect"),
            ..FormatterConfig::default()
        };
        let formatted = format_sql_with_config(sql, &config).expect("formats");
        verify_formatting_safe_with_dialect(sql, &formatted, config.dialect.as_ref())
            .unwrap_or_else(|e| panic!("{sql}: {e}\n{formatted}"));
        let text = |text: &str| text.split_whitespace().collect::<String>();
        assert_eq!(text(&formatted), text(sql), "{sql}");
    }
}

#[test]
fn a_join_group_led_by_a_parenthesised_query_is_a_join_group() {
    // `( (SELECT …) d JOIN a USING (k) )`: the query the inner `)` closes is
    // the group's first table, not the outer parentheses' subquery.
    let sql = "SELECT email FROM users k NATURAL JOIN ( (SELECT * FROM elsewhere) d JOIN archive a USING (email) )";
    let join = first_join(sql, "postgresql");
    assert!(
        matches!(join.kind, AstJoinKind::NaturalInner),
        "{:?}",
        join.kind
    );
    let group = join.right.paren_group.as_ref().expect("a join group");
    assert_eq!(group.inner_join_count, 1);
    assert!(
        join.right.subquery.is_some(),
        "the group's first table is the query"
    );
}

#[test]
fn an_alias_after_a_join_group_names_the_group() {
    use lexega_syntax::{
        format_sql_with_config, verify_formatting_safe_with_dialect, FormatterConfig,
    };
    let sql =
        "SELECT * FROM (users u JOIN orders o ON u.id = o.user_id) AS j (c1, c2) WHERE c1 = 1";
    let dialect = lexega_syntax::dialect_from_name("postgresql").expect("dialect");
    let script = lexega_syntax::parse_sql_with_dialect(sql, dialect.as_ref()).expect("parses");
    let Some(AstStmt::Select(select)) = script.stmts.first() else {
        panic!("not a SELECT: {:?}", script.stmts);
    };
    let FromItemKind::TableRef(table) = &select.from[0].kind else {
        panic!("no table");
    };
    let group = table.paren_group.as_ref().expect("a join group");
    let text = |span: lexega_syntax::Span| &sql[span.start as usize..span.end as usize];
    // The group is the derived table `(SELECT * FROM <group>) AS j (c1, c2)`.
    assert_eq!(table.alias.as_ref().map(|a| text(a.span)), Some("j"));
    let columns: Vec<&str> = table
        .alias_columns
        .as_deref()
        .into_iter()
        .flatten()
        .map(|c| text(c.span))
        .collect();
    assert_eq!(columns, ["c1", "c2"]);
    assert_eq!(group.alias_span.map(text), Some("AS j (c1, c2)"));
    let Some(AstStmt::Select(body)) = table.subquery.as_deref() else {
        panic!("the group's SELECT *: {:?}", table.subquery);
    };
    assert!(matches!(body.projection.kind, AstProjectionKind::Star(_)));
    let FromItemKind::TableRef(first) = &body.from[0].kind else {
        panic!("the group's tables");
    };
    assert_eq!(first.alias.as_ref().map(|a| text(a.span)), Some("u"));
    assert_eq!(first.joins.len(), 1, "the group's join");

    for sql in [
        sql,
        "INSERT INTO a (id, email) SELECT j.* FROM ( users u2 JOIN orders o ON o.user_id = u2.id ) j",
        "SELECT * FROM (a JOIN b ON a.x = b.x) g JOIN c ON c.y = g.y",
    ] {
        let config = FormatterConfig {
            dialect: lexega_syntax::dialect_from_name("postgresql").expect("dialect"),
            ..FormatterConfig::default()
        };
        let formatted = format_sql_with_config(sql, &config).expect("formats");
        verify_formatting_safe_with_dialect(sql, &formatted, config.dialect.as_ref())
            .unwrap_or_else(|e| panic!("{sql}: {e}\n{formatted}"));
    }
}

#[test]
fn a_tsql_join_hint_is_read_before_join_and_formats_as_written() {
    use lexega_syntax::{
        format_sql_with_config, verify_formatting_safe_with_dialect, FormatterConfig,
    };
    for (sql, kind, hint, hint_text) in [
        (
            "SELECT s.c FROM dbo.S s INNER MERGE JOIN dbo.T t ON t.id = s.id",
            AstJoinKind::Inner,
            AstJoinHintKind::Merge,
            "MERGE",
        ),
        (
            "SELECT s.c FROM dbo.S s INNER HASH JOIN dbo.T t ON t.id = s.id",
            AstJoinKind::Inner,
            AstJoinHintKind::Hash,
            "HASH",
        ),
        (
            "SELECT s.c FROM dbo.S s inner loop join dbo.T t ON t.id = s.id",
            AstJoinKind::Inner,
            AstJoinHintKind::Loop,
            "loop",
        ),
        (
            "SELECT s.c FROM dbo.S s INNER REMOTE JOIN dbo.T t ON t.id = s.id",
            AstJoinKind::Inner,
            AstJoinHintKind::Remote,
            "REMOTE",
        ),
        (
            "SELECT s.c FROM dbo.S s LEFT OUTER LOOP JOIN dbo.T t ON t.id = s.id",
            AstJoinKind::LeftOuter,
            AstJoinHintKind::Loop,
            "LOOP",
        ),
        (
            "SELECT s.c FROM dbo.S s LEFT HASH JOIN dbo.T t ON t.id = s.id",
            AstJoinKind::LeftOuter,
            AstJoinHintKind::Hash,
            "HASH",
        ),
        (
            "SELECT s.c FROM dbo.S s RIGHT OUTER MERGE JOIN dbo.T t ON t.id = s.id",
            AstJoinKind::RightOuter,
            AstJoinHintKind::Merge,
            "MERGE",
        ),
        (
            "SELECT s.c FROM dbo.S s FULL OUTER HASH JOIN dbo.T t ON t.id = s.id",
            AstJoinKind::FullOuter,
            AstJoinHintKind::Hash,
            "HASH",
        ),
        (
            "SELECT s.c FROM dbo.S s FULL REMOTE JOIN dbo.T t ON t.id = s.id",
            AstJoinKind::FullOuter,
            AstJoinHintKind::Remote,
            "REMOTE",
        ),
        (
            "SELECT s.c FROM dbo.S AS s INNER /* a */ HASH /* b */ JOIN dbo.T AS t ON t.id = s.id",
            AstJoinKind::Inner,
            AstJoinHintKind::Hash,
            "HASH",
        ),
    ] {
        let join = first_join(sql, "mssql");
        assert_eq!(format!("{:?}", join.kind), format!("{kind:?}"), "{sql}");
        let read = join.join_hint.expect("a join hint");
        assert_eq!(read.kind, hint, "{sql}");
        assert_eq!(
            &sql[read.span.start as usize..read.span.end as usize],
            hint_text,
            "{sql}"
        );
        let config = FormatterConfig {
            dialect: lexega_syntax::dialect_from_name("mssql").expect("dialect"),
            ..FormatterConfig::default()
        };
        let formatted = format_sql_with_config(sql, &config).expect("formats");
        verify_formatting_safe_with_dialect(sql, &formatted, config.dialect.as_ref())
            .unwrap_or_else(|e| panic!("{sql}: {e}\n{formatted}"));
        let again = format_sql_with_config(&formatted, &config).expect("formats");
        assert_eq!(again, formatted, "{sql}");
    }
    // Without a join type the word is the table's alias.
    let join = first_join("SELECT * FROM a hash JOIN b ON 1 = 1", "mssql");
    assert!(join.join_hint.is_none());
}
