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
    let findings = analyze_query_facts(sql).expect("analysis should succeed");
    let ids: Vec<_> = findings.iter().map(|s| s.rule_id.as_str()).collect();
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
    let findings = analyze_query_facts(sql).expect("analysis should succeed");
    let ids: Vec<_> = findings.iter().map(|s| s.rule_id.as_str()).collect();
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
    let findings = analyze_query_facts(sql).expect("analysis should succeed");
    let ids: Vec<_> = findings.iter().map(|s| s.rule_id.as_str()).collect();
    println!("ids (different tables): {:?}", ids);
    assert!(
        !ids.contains(&"Q-SUBQ-CORR-SEL"),
        "subquery references a different table; not correlated. Got: {:?}",
        ids
    );
}

#[test]
fn a_correlated_subquery_nested_in_another_subquery_is_reported() {
    let ids = |sql: &str| -> Vec<String> {
        let findings = analyze_query_facts(sql).expect("analysis should succeed");
        findings.into_iter().map(|s| s.rule_id).collect()
    };
    let middle = "SELECT MAX(o.amount) FROM orders o WHERE o.user_id";
    // The inner subquery reads `o.email` of the block around it.
    let correlated = "(SELECT MAX(u.id) FROM users u WHERE u.email = o.email)";
    let scalar = format!("SELECT ({middle} = {correlated}) AS m FROM accounts q");
    let found = ids(&scalar);
    assert!(
        found.iter().any(|id| id == "Q-SUBQ-CORR-SEL"),
        "{scalar}: {found:?}"
    );
    let listed = format!(
        "SELECT ({middle} IN (SELECT u.id FROM users u WHERE u.email = o.email)) AS m FROM accounts q"
    );
    let found = ids(&listed);
    assert!(
        found.iter().any(|id| id == "Q-SUBQ-CORR-WHERE"),
        "{listed}: {found:?}"
    );
    assert!(
        !found.iter().any(|id| id == "Q-SUBQ-CORR-SEL"),
        "{listed}: {found:?}"
    );
    // A subquery nested in another that reads nothing of a block out.
    let free = format!("SELECT ({middle} = (SELECT MAX(u.id) FROM users u)) AS m FROM accounts q");
    let found = ids(&free);
    assert!(
        !found.iter().any(|id| id.starts_with("Q-SUBQ-CORR")),
        "{free}: {found:?}"
    );
}
