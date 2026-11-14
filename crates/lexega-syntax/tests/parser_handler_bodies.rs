// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_syntax::ast::BodyRole;
use lexega_syntax::dialect::{bigquery, postgres, snowflake, DialectRef};
use lexega_syntax::{parse_sql_with_dialect, AstStmt};

/// The statements of the first exception handler found anywhere in `stmts`.
fn first_handler_body(stmts: &[AstStmt]) -> Option<&[AstStmt]> {
    for stmt in stmts {
        for body in stmt.bodies() {
            if body.role == BodyRole::ExceptionHandler {
                return Some(body.stmts);
            }
            if let Some(found) = first_handler_body(body.stmts) {
                return Some(found);
            }
        }
        if let AstStmt::DoBlock(d) = stmt {
            if let Some(found) = d
                .body_stmt
                .as_deref()
                .and_then(|s| first_handler_body(std::slice::from_ref(s)))
            {
                return Some(found);
            }
        }
    }
    None
}

fn handler_body_of(src: &str, dialect: DialectRef) -> Vec<AstStmt> {
    let script = parse_sql_with_dialect(src, dialect.as_ref())
        .unwrap_or_else(|e| panic!("did not parse: {e:?}\n{src}"));
    first_handler_body(&script.stmts)
        .unwrap_or_else(|| panic!("no exception handler in the tree\n{src}"))
        .to_vec()
}

/// True when `stmt` or a statement it holds is a `DROP TABLE`.
fn holds_drop(stmt: &AstStmt) -> bool {
    matches!(stmt, AstStmt::Drop(_)) || stmt.bodies().iter().any(|b| b.stmts.iter().any(holds_drop))
}

fn snowflake_handler(stmt: &str) -> Vec<AstStmt> {
    handler_body_of(
        &format!("BEGIN SELECT 1; EXCEPTION WHEN OTHER THEN {stmt} END;"),
        snowflake(),
    )
}

fn pg_handler(stmt: &str) -> Vec<AstStmt> {
    handler_body_of(
        &format!("DO $$ BEGIN PERFORM 1; EXCEPTION WHEN OTHERS THEN {stmt} END $$;"),
        postgres(),
    )
}

fn bq_handler(stmt: &str) -> Vec<AstStmt> {
    handler_body_of(
        &format!("BEGIN SELECT 1; EXCEPTION WHEN ERROR THEN {stmt} END;"),
        bigquery(),
    )
}

macro_rules! handler_case {
    ($name:ident, $reader:ident, $sql:expr, $variant:pat) => {
        #[test]
        fn $name() {
            let body = $reader($sql);
            assert_eq!(body.len(), 1, "handler body: {body:#?}");
            assert!(matches!(&body[0], $variant), "handler body: {body:#?}");
        }
    };
}

handler_case!(
    snowflake_handler_if,
    snowflake_handler,
    "IF (x > 1) THEN DROP TABLE t; END IF;",
    AstStmt::If(_)
);
handler_case!(
    snowflake_handler_case,
    snowflake_handler,
    "CASE WHEN x = 1 THEN DROP TABLE t; ELSE RETURN 1; END CASE;",
    AstStmt::CaseStmt(_)
);
handler_case!(
    snowflake_handler_while,
    snowflake_handler,
    "WHILE (x < 3) DO x := x + 1; END WHILE;",
    AstStmt::While(_)
);
handler_case!(
    snowflake_handler_for,
    snowflake_handler,
    "FOR i IN 1 TO 3 DO x := x + 1; END FOR;",
    AstStmt::For(_)
);
handler_case!(
    snowflake_handler_loop,
    snowflake_handler,
    "LOOP x := x + 1; BREAK; END LOOP;",
    AstStmt::Loop(_)
);
handler_case!(
    snowflake_handler_repeat,
    snowflake_handler,
    "REPEAT x := x + 1; UNTIL (x > 3) END REPEAT;",
    AstStmt::Repeat(_)
);
handler_case!(
    snowflake_handler_nested_block,
    snowflake_handler,
    "BEGIN DROP TABLE t; END;",
    AstStmt::Block(_)
);
handler_case!(
    snowflake_handler_raise,
    snowflake_handler,
    "RAISE;",
    AstStmt::Raise { .. }
);
handler_case!(
    snowflake_handler_return,
    snowflake_handler,
    "RETURN 'failed';",
    AstStmt::Return { .. }
);
handler_case!(
    snowflake_handler_assignment,
    snowflake_handler,
    "x := 1;",
    AstStmt::Assign { .. }
);

handler_case!(
    pg_handler_if,
    pg_handler,
    "IF x > 1 THEN DROP TABLE t; END IF;",
    AstStmt::If(_)
);
handler_case!(
    pg_handler_case,
    pg_handler,
    "CASE WHEN x = 1 THEN DROP TABLE t; ELSE RETURN; END CASE;",
    AstStmt::CaseStmt(_)
);
handler_case!(
    pg_handler_while,
    pg_handler,
    "WHILE x < 3 LOOP x := x + 1; END LOOP;",
    AstStmt::While(_)
);
handler_case!(
    pg_handler_for,
    pg_handler,
    "FOR i IN 1..3 LOOP x := x + 1; END LOOP;",
    AstStmt::For(_)
);
handler_case!(
    pg_handler_loop,
    pg_handler,
    "LOOP x := x + 1; EXIT; END LOOP;",
    AstStmt::Loop(_)
);
handler_case!(
    pg_handler_foreach,
    pg_handler,
    "FOREACH v IN ARRAY arr LOOP x := x + v; END LOOP;",
    AstStmt::ForEach(_)
);
handler_case!(
    pg_handler_nested_block,
    pg_handler,
    "BEGIN DROP TABLE t; END;",
    AstStmt::Block(_)
);
handler_case!(
    pg_handler_raise,
    pg_handler,
    "RAISE EXCEPTION 'failed';",
    AstStmt::Raise { .. }
);
handler_case!(
    pg_handler_return,
    pg_handler,
    "RETURN;",
    AstStmt::Return { .. }
);
handler_case!(
    pg_handler_assignment,
    pg_handler,
    "x := 1;",
    AstStmt::Assign { .. }
);

handler_case!(
    bigquery_handler_if,
    bq_handler,
    "IF x > 1 THEN DROP TABLE t; END IF;",
    AstStmt::If(_)
);
handler_case!(
    bigquery_handler_case,
    bq_handler,
    "CASE WHEN x = 1 THEN DROP TABLE t; ELSE RETURN; END CASE;",
    AstStmt::CaseStmt(_)
);
handler_case!(
    bigquery_handler_while,
    bq_handler,
    "WHILE x < 3 DO SET x = x + 1; END WHILE;",
    AstStmt::While(_)
);
handler_case!(
    bigquery_handler_loop,
    bq_handler,
    "LOOP SET x = x + 1; BREAK; END LOOP;",
    AstStmt::Loop(_)
);
handler_case!(
    bigquery_handler_repeat,
    bq_handler,
    "REPEAT SET x = x + 1; UNTIL x > 3 END REPEAT;",
    AstStmt::Repeat(_)
);
handler_case!(
    bigquery_handler_for,
    bq_handler,
    "FOR r IN (SELECT 1 AS a) DO SET x = r.a; END FOR;",
    AstStmt::For(_)
);
handler_case!(
    bigquery_handler_nested_block,
    bq_handler,
    "BEGIN DROP TABLE t; END;",
    AstStmt::Block(_)
);
handler_case!(
    bigquery_handler_raise,
    bq_handler,
    "RAISE USING MESSAGE = 'failed';",
    AstStmt::Raise { .. }
);
handler_case!(
    bigquery_handler_return,
    bq_handler,
    "RETURN;",
    AstStmt::Return { .. }
);

#[test]
fn drop_inside_handler_if_is_in_the_tree() {
    for body in [
        snowflake_handler("IF (x > 1) THEN DROP TABLE t; END IF;"),
        pg_handler("IF x > 1 THEN DROP TABLE t; END IF;"),
    ] {
        assert!(body.iter().any(holds_drop), "handler body: {body:#?}");
    }
}
