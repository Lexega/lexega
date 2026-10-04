// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Snowflake ASOF JOIN must format byte-exact with and without an ON/USING
//! clause.
//!
//! `… ASOF JOIN t2 MATCH_CONDITION(…)` with no trailing ON/USING must not gain
//! a trailing `)`. Guard both shapes.

use lexega_syntax::{
    dialect, format_sql_with_config, verify_formatting_safe_with_dialect, FormatterConfig,
};

fn roundtrip_sf(sql: &str) {
    let mut config = FormatterConfig::default();
    config.dialect = dialect::snowflake();
    let out = format_sql_with_config(sql, &config).expect("should format");
    verify_formatting_safe_with_dialect(sql, &out, config.dialect.as_ref())
        .expect("should preserve tokens (no stray paren)");
}

#[test]
fn test_asof_join_no_on_clause() {
    roundtrip_sf("SELECT * FROM t1 ASOF JOIN t2 MATCH_CONDITION(t1.ts >= t2.ts)");
}

#[test]
fn test_asof_join_with_on_clause() {
    roundtrip_sf("SELECT * FROM t1 ASOF JOIN t2 MATCH_CONDITION(t1.ts >= t2.ts) ON t1.k = t2.k");
}

#[test]
fn test_asof_join_with_using_clause() {
    roundtrip_sf("SELECT * FROM t1 ASOF JOIN t2 MATCH_CONDITION(t1.ts >= t2.ts) USING (k)");
}

#[test]
fn test_asof_join_then_more_joins() {
    roundtrip_sf("SELECT * FROM a ASOF JOIN b MATCH_CONDITION(a.t >= b.t) JOIN c ON c.id = a.id");
}

#[test]
fn test_asof_join_preserves_inner_spacing() {
    roundtrip_sf(
        "SELECT * FROM left_table l ASOF JOIN right_table r MATCH_CONDITION( l.c3 >= r.c3 )",
    );
}
