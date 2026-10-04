// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_core::api::analyze_query_facts;

#[test]
fn repro_uncorrelated_same_name() {
    let sql = "
        WITH source AS (SELECT * FROM raw.events),
             max_date AS (
               SELECT *
               FROM source
               WHERE snapshot_date = (SELECT max(snapshot_date) FROM source)
             )
        SELECT * FROM max_date
    ";
    let signals = analyze_query_facts(sql).expect("analysis should succeed");
    let ids: Vec<_> = signals.iter().map(|s| s.rule_id.as_str()).collect();
    println!("ids: {:?}", ids);
    assert!(
        !ids.contains(&"Q-SUBQ-CORR-SEL"),
        "expected NO Q-SUBQ-CORR-SEL (subquery is uncorrelated; both `source` refs are to the same CTE, inner scope shadows outer). Got: {:?}",
        ids
    );
}

#[test]
fn repro_with_different_names() {
    // No name collision at all. If THIS fires, the bug is in
    // compute_correlation's produced/referenced calculation, not
    // in column-name shadowing.
    let sql = "
        WITH outer_cte AS (SELECT * FROM raw.events),
             max_date AS (
               SELECT *
               FROM outer_cte
               WHERE snapshot_date = (SELECT max(snapshot_date) FROM outer_cte)
             )
        SELECT * FROM max_date
    ";
    let signals = analyze_query_facts(sql).expect("analysis should succeed");
    let ids: Vec<_> = signals.iter().map(|s| s.rule_id.as_str()).collect();
    println!("ids (different names): {:?}", ids);
    assert!(
        !ids.contains(&"Q-SUBQ-CORR-SEL"),
        "subquery references the same CTE in its own FROM; not correlated. Got: {:?}",
        ids
    );
}

#[test]
fn repro_with_different_table_in_subquery() {
    // Subquery references a different table — even less ambiguous.
    let sql = "
        SELECT *
        FROM raw.events
        WHERE snapshot_date = (SELECT MAX(snapshot_date) FROM raw.snapshots)
    ";
    let signals = analyze_query_facts(sql).expect("analysis should succeed");
    let ids: Vec<_> = signals.iter().map(|s| s.rule_id.as_str()).collect();
    println!("ids (different tables): {:?}", ids);
    assert!(
        !ids.contains(&"Q-SUBQ-CORR-SEL"),
        "subquery references a different table; not correlated. Got: {:?}",
        ids
    );
}
