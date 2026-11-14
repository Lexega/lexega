// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! A dynamic table's policy clause with no name in it is one unparsed
//! statement, and the statements after it are read.

use lexega_syntax::{parse_sql_with_dialect, AstStmt};

#[test]
fn a_dynamic_tables_policy_with_no_name_is_not_read() {
    for policy in ["ROW ACCESS POLICY 1 ON (c)", "AGGREGATION POLICY 1"] {
        let sql = format!(
            "CREATE DYNAMIC TABLE dt TARGET_LAG = '1 hour' WAREHOUSE = wh WITH {policy} \
             AS SELECT c FROM t; SELECT 1;"
        );
        let script = parse_sql_with_dialect(&sql, &*lexega_syntax::dialect::snowflake())
            .unwrap_or_else(|e| panic!("{sql}: {e:?}"));
        assert!(
            matches!(script.stmts.first(), Some(AstStmt::OpaqueContent { .. })),
            "{sql}: {:?}",
            script.stmts
        );
        assert!(
            matches!(script.stmts.last(), Some(AstStmt::Select(_))),
            "{sql}: {:?}",
            script.stmts
        );
    }
}
