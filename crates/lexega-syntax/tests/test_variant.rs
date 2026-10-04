// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

#[test]
fn test_create_policy_variant() {
    use lexega_syntax::try_parse_script_from_str;
    let sql =
        "CREATE ROW ACCESS POLICY test_policy AS (user_id INTEGER) RETURNS BOOLEAN -> user_id = 1;";
    let script = try_parse_script_from_str(sql).unwrap();
    assert_eq!(script.stmts.len(), 1);

    match &script.stmts[0] {
        lexega_syntax::AstStmt::CreateRowAccessPolicy(p) => {
            println!("✓ Parsed as CreateRowAccessPolicy");
            println!("  Policy name span: {:?}", p.policy_name_span);
            println!("  Parameters count: {}", p.parameters.len());
        }
        other => panic!(
            "Expected CreateRowAccessPolicy, got {:?}",
            std::mem::discriminant(other)
        ),
    }
}
