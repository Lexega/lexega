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
