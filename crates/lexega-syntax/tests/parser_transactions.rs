// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

// Transaction control statement tests
// Tests for BEGIN TRANSACTION, COMMIT, ROLLBACK
use lexega_syntax::parse_sql;

#[test]
fn test_begin_transaction_commit() {
    let src = r#"
BEGIN
    BEGIN TRANSACTION;
    UPDATE table1 SET col = 1;
    COMMIT;
    RETURN 'done';
END;
"#;
    let script = parse_sql(src);
    assert!(
        script.is_ok(),
        "failed to parse BEGIN TRANSACTION and COMMIT"
    );
}
