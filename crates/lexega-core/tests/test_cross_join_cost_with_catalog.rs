// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Test cross-join warnings with catalog row-count estimates.
/// Uses the unified YAML rule Q-JOIN-CROSS-CENH (covers both explicit
/// `CROSS JOIN` and implicit comma-FROM) gated on a catalog-attested
/// cartesian-product estimate >= 10M rows.
use lexega_core::analyzer::RuleMatch;
use lexega_core::api::{analyze_risk, analyze_risk_with_catalog_path};
use std::fs;

#[test]
fn test_cross_join_explicit_with_row_counts() {
    // Create catalog with row count estimates
    let catalog_json = r#"{
        "schema_version": 2,
        "generated_at": "2025-01-01T00:00:00Z",
        "source": "test",
        "databases": [
            {
                "name": {"name": "db1"},
                "schemas": [
                    {
                        "name": {"name": "schema1"},
                        "tables": [
                            {
                                "name": {"name": "large_table"},
                                "kind": "Table",
                                "columns": [
                                    {
                                        "name": {"name": "id"},
                                        "data_type": "NUMBER",
                                        "nullable": false
                                    },
                                    {
                                        "name": {"name": "value"},
                                        "data_type": "VARCHAR",
                                        "nullable": false
                                    }
                                ],
                                "row_count_estimate": 1000000
                            },
                            {
                                "name": {"name": "small_table"},
                                "kind": "Table",
                                "columns": [
                                    {
                                        "name": {"name": "id"},
                                        "data_type": "NUMBER",
                                        "nullable": false
                                    },
                                    {
                                        "name": {"name": "name"},
                                        "data_type": "VARCHAR",
                                        "nullable": false
                                    }
                                ],
                                "row_count_estimate": 500
                            }
                        ]
                    }
                ]
            }
        ]
    }"#;

    let sql = r#"
        SELECT *
        FROM db1.schema1.large_table
        CROSS JOIN db1.schema1.small_table;
    "#;

    // Write catalog to temp file
    let catalog_path = "/tmp/test_cross_join_catalog.json";
    fs::write(catalog_path, catalog_json).expect("Failed to write catalog");

    // Analyze with catalog
    let report =
        analyze_risk_with_catalog_path(sql, Some(catalog_path)).expect("Analysis should succeed");

    // Debug: print all signals
    println!("All signals:");
    for signal in &report.signals {
        println!("  {:?}", signal);
    }

    // Verify cross join warning is present (now from YAML rule Q-JOIN-CROSS-CENH)
    let governance_signals: Vec<_> = report
        .signals
        .iter()
        .filter(|f| matches!(f, RuleMatch::Analysis(_)))
        .collect();

    println!("Found {} governance signals", governance_signals.len());

    // Find the cross join signal (rule Q-JOIN-CROSS-CENH)
    let cross_join_signal = governance_signals
        .iter()
        .find(|f| {
            let RuleMatch::Analysis(gs) = f;
            gs.matched_rule == "Q-JOIN-CROSS-CENH" || gs.message.contains("CROSS JOIN")
        })
        .expect("Should find CROSS JOIN warning (Q-JOIN-CROSS-CENH)");

    // Verify message contains row count estimates
    let RuleMatch::Analysis(gs) = cross_join_signal;
    println!("Governance signal message: {}", gs.message);

    // Unified Q-JOIN-CROSS-CENH message template:
    // "Cross join between {left} and {right} on a catalog-attested
    //  cartesian product of {product} rows. May cause performance
    //  issues on large tables."
    assert!(
        gs.message.contains("Cross join") || gs.message.contains("CROSS JOIN"),
        "Should mention cross join: {}",
        gs.message
    );

    // Check for table names in the message
    assert!(
        gs.message.contains("large_table") || gs.message.contains("db1.schema1.large_table"),
        "Should mention large_table in message: {}",
        gs.message
    );
    assert!(
        gs.message.contains("small_table") || gs.message.contains("db1.schema1.small_table"),
        "Should mention small_table in message: {}",
        gs.message
    );

    // Check for product estimate (1M × 500 = 500M)
    assert!(
        gs.message.contains("500000000")
            || gs.message.contains("500.0M")
            || gs.message.contains("500M"),
        "Should show cross product estimate (~500M rows) in message: {}",
        gs.message
    );
}

#[test]
fn test_comma_join_with_multiple_tables() {
    // Create catalog with row count estimates
    let catalog_json = r#"{
        "schema_version": 2,
        "generated_at": "2025-01-01T00:00:00Z",
        "source": "test",
        "databases": [
            {
                "name": {"name": "db1"},
                "schemas": [
                    {
                        "name": {"name": "schema1"},
                        "tables": [
                            {
                                "name": {"name": "table_a"},
                                "kind": "Table",
                                "columns": [
                                    {
                                        "name": {"name": "id"},
                                        "data_type": "NUMBER",
                                        "nullable": false
                                    }
                                ],
                                "row_count_estimate": 100000
                            },
                            {
                                "name": {"name": "table_b"},
                                "kind": "Table",
                                "columns": [
                                    {
                                        "name": {"name": "id"},
                                        "data_type": "NUMBER",
                                        "nullable": false
                                    }
                                ],
                                "row_count_estimate": 500000
                            },
                            {
                                "name": {"name": "table_c"},
                                "kind": "Table",
                                "columns": [
                                    {
                                        "name": {"name": "id"},
                                        "data_type": "NUMBER",
                                        "nullable": false
                                    }
                                ],
                                "row_count_estimate": 500
                            }
                        ]
                    }
                ]
            }
        ]
    }"#;

    let sql = r#"
        SELECT *
        FROM db1.schema1.table_a,
             db1.schema1.table_b,
             db1.schema1.table_c;
    "#;

    // Write catalog to temp file
    let catalog_path = "/tmp/test_comma_join_catalog.json";
    fs::write(catalog_path, catalog_json).expect("Failed to write catalog");

    // Analyze with catalog
    let report =
        analyze_risk_with_catalog_path(sql, Some(catalog_path)).expect("Analysis should succeed");

    // Debug: print all signals
    println!("All signals:");
    for signal in &report.signals {
        println!("  {:?}", signal);
    }

    // Verify comma-join warning is present (now from the unified
    // Q-JOIN-CROSS-CENH rule — comma-FROM lowers to `Join { kind: Cross,
    // implicit: true }` which the unified rule matches on `kind: cross`).
    let governance_signals: Vec<_> = report
        .signals
        .iter()
        .filter(|f| matches!(f, RuleMatch::Analysis(_)))
        .collect();

    println!("Found {} governance signals", governance_signals.len());

    let comma_join_signal = governance_signals
        .iter()
        .find(|f| {
            let RuleMatch::Analysis(gs) = f;
            gs.matched_rule == "Q-JOIN-CROSS-CENH"
        })
        .expect("Should find cross-join warning on comma-FROM (Q-JOIN-CROSS-CENH)");

    // Verify message contains expected content
    let RuleMatch::Analysis(gs) = comma_join_signal;
    println!("Governance signal message: {}", gs.message);

    assert!(
        gs.message.contains("Cross join") || gs.message.contains("CROSS JOIN"),
        "Should mention cross join: {}",
        gs.message
    );

    // The unified rule fires per-Join witness. A 3-way comma-FROM
    // lowers to nested cross joins (`Join(Join(a, b), c)`). Per-
    // witness `cartesian_estimate` is computed for each pair:
    //   inner pair a×b = 100k × 500k = 50,000,000,000 (50B)
    //   outer pair b×c = 500k × 500   =    250,000,000 (250M)
    // Both clear the 10M gate. The first signal found is one of
    // these; verify the per-pair-product string is interpolated.
    assert!(
        gs.message.contains("50000000000") || gs.message.contains("250000000"),
        "Should show a per-pair cartesian product in message: {}",
        gs.message
    );
}

#[test]
fn test_cross_join_without_catalog_stays_silent() {
    // The unified Q-JOIN-CROSS-CENH rule is catalog-gated: without
    // catalog row counts the per-join `cartesian_estimate` is `None`
    // and the `gte: 10000000` predicate fails. This is the rule's
    // documented contract — speculative warnings on syntax alone are
    // out of scope; the rule fires only when cost evidence backs it.
    let sql = r#"
        SELECT *
        FROM large_table
        CROSS JOIN small_table;
    "#;

    let report = analyze_risk(sql).expect("Analysis should succeed");

    println!("All signals:");
    for signal in &report.signals {
        println!("  {:?}", signal);
    }

    let cross_join_fired = report
        .signals
        .iter()
        .any(|f| matches!(f, RuleMatch::Analysis(gs) if gs.matched_rule == "Q-JOIN-CROSS-CENH"));
    assert!(
        !cross_join_fired,
        "Q-JOIN-CROSS-CENH must stay silent without catalog row counts"
    );
}
