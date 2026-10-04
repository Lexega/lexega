// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Tests for PostgreSQL utility statements:
/// LISTEN, NOTIFY, UNLISTEN, LOCK TABLE, CREATE RULE,
/// CREATE AGGREGATE, CREATE OPERATOR, ALTER SYSTEM,
/// DROP OWNED, REASSIGN OWNED, DISCARD, CLUSTER,
/// PUBLICATION, SUBSCRIPTION
use lexega_syntax::{format_sql, verify_formatting_safe};

fn fmt(sql: &str) -> String {
    format_sql(sql).unwrap_or_else(|e| panic!("format_sql failed: {e}\nInput: {sql}"))
}

fn roundtrip(sql: &str) {
    let formatted = fmt(sql);
    verify_formatting_safe(sql, &formatted)
        .unwrap_or_else(|e| panic!("verify failed: {e}\nInput: {sql}\nFormatted: {formatted}"));
}

// ── LISTEN ─────────────────────────────────────────────────────────────

#[test]
fn test_listen_basic() {
    roundtrip("LISTEN my_channel;");
}

#[test]
fn test_listen_quoted_channel() {
    roundtrip("LISTEN \"MyChannel\";");
}

// ── NOTIFY ─────────────────────────────────────────────────────────────

#[test]
fn test_notify_basic() {
    roundtrip("NOTIFY my_channel;");
}

#[test]
fn test_notify_with_payload() {
    roundtrip("NOTIFY my_channel, 'hello world';");
}

#[test]
fn test_notify_quoted_channel() {
    roundtrip("NOTIFY \"Events\";");
}

// ── UNLISTEN ───────────────────────────────────────────────────────────

#[test]
fn test_unlisten_channel() {
    roundtrip("UNLISTEN my_channel;");
}

#[test]
fn test_unlisten_all() {
    roundtrip("UNLISTEN *;");
}

// ── LOCK TABLE ─────────────────────────────────────────────────────────

#[test]
fn test_lock_table_access_share() {
    roundtrip("LOCK TABLE t IN ACCESS SHARE MODE;");
}

#[test]
fn test_lock_table_row_exclusive_nowait() {
    roundtrip("LOCK TABLE t IN ROW EXCLUSIVE MODE NOWAIT;");
}

#[test]
fn test_lock_table_share() {
    roundtrip("LOCK TABLE t IN SHARE MODE;");
}

#[test]
fn test_lock_table_multi_table() {
    roundtrip("LOCK TABLE s.t1, s.t2 IN SHARE MODE;");
}

#[test]
fn test_lock_table_exclusive() {
    roundtrip("LOCK TABLE t IN EXCLUSIVE MODE;");
}

#[test]
fn test_lock_table_access_exclusive() {
    roundtrip("LOCK TABLE t IN ACCESS EXCLUSIVE MODE;");
}

#[test]
fn test_lock_table_share_row_exclusive() {
    roundtrip("LOCK TABLE t IN SHARE ROW EXCLUSIVE MODE;");
}

#[test]
fn test_lock_table_row_share() {
    roundtrip("LOCK TABLE t IN ROW SHARE MODE;");
}

#[test]
fn test_lock_table_share_update_exclusive() {
    roundtrip("LOCK TABLE t IN SHARE UPDATE EXCLUSIVE MODE;");
}

// ── CREATE RULE ────────────────────────────────────────────────────────

#[test]
fn test_create_rule_do_nothing() {
    roundtrip("CREATE RULE rule1 AS ON INSERT TO t DO NOTHING;");
}

#[test]
fn test_create_rule_do_instead() {
    roundtrip("CREATE RULE rule1 AS ON SELECT TO t DO INSTEAD NOTHING;");
}

#[test]
fn test_create_rule_or_replace_where() {
    roundtrip("CREATE OR REPLACE RULE rule1 AS ON UPDATE TO t WHERE (old.x <> new.x) DO NOTHING;");
}

#[test]
fn test_create_rule_with_action() {
    roundtrip(
        "CREATE RULE rule1 AS ON INSERT TO t DO ALSO INSERT INTO audit_log VALUES (NEW.id, now());",
    );
}

// ── CREATE AGGREGATE ───────────────────────────────────────────────────

#[test]
fn test_create_aggregate_basic() {
    roundtrip(
        "CREATE AGGREGATE my_sum (integer) (SFUNC = int4pl, STYPE = integer, INITCOND = '0');",
    );
}

#[test]
fn test_create_aggregate_order_by() {
    roundtrip("CREATE AGGREGATE my_percentile (float8 ORDER BY float8) (SFUNC = ordered_set_transition, STYPE = internal, FINALFUNC = percentile_disc_final);");
}

// ── CREATE OPERATOR ────────────────────────────────────────────────────

#[test]
fn test_create_operator_basic() {
    roundtrip(
        "CREATE OPERATOR === (LEFTARG = box, RIGHTARG = box, FUNCTION = area_equal_function, COMMUTATOR = ===);",
    );
}

#[test]
fn test_create_operator_schema() {
    roundtrip("CREATE OPERATOR myschema.=== (LEFTARG = text, RIGHTARG = text, FUNCTION = my_eq);");
}

// ── ALTER SYSTEM ───────────────────────────────────────────────────────

#[test]
fn test_alter_system_set_string() {
    roundtrip("ALTER SYSTEM SET wal_level = 'replica';");
}

#[test]
fn test_alter_system_set_number() {
    roundtrip("ALTER SYSTEM SET max_connections = 200;");
}

#[test]
fn test_alter_system_reset() {
    roundtrip("ALTER SYSTEM RESET wal_level;");
}

#[test]
fn test_alter_system_reset_all() {
    roundtrip("ALTER SYSTEM RESET ALL;");
}

// ── DROP OWNED ─────────────────────────────────────────────────────────

#[test]
fn test_drop_owned_basic() {
    roundtrip("DROP OWNED BY old_user;");
}

#[test]
fn test_drop_owned_cascade() {
    roundtrip("DROP OWNED BY old_user CASCADE;");
}

#[test]
fn test_drop_owned_multi_role_restrict() {
    roundtrip("DROP OWNED BY role1, role2 RESTRICT;");
}

// ── REASSIGN OWNED ─────────────────────────────────────────────────────

#[test]
fn test_reassign_owned_basic() {
    roundtrip("REASSIGN OWNED BY old_user TO new_user;");
}

#[test]
fn test_reassign_owned_multi_role() {
    roundtrip("REASSIGN OWNED BY role1, role2 TO admin;");
}

// ── DISCARD ────────────────────────────────────────────────────────────

#[test]
fn test_discard_all() {
    roundtrip("DISCARD ALL;");
}

#[test]
fn test_discard_plans() {
    roundtrip("DISCARD PLANS;");
}

#[test]
fn test_discard_sequences() {
    roundtrip("DISCARD SEQUENCES;");
}

#[test]
fn test_discard_temp() {
    roundtrip("DISCARD TEMP;");
}

#[test]
fn test_discard_temporary() {
    roundtrip("DISCARD TEMPORARY;");
}

// ── CLUSTER ────────────────────────────────────────────────────────────

#[test]
fn test_cluster_table() {
    roundtrip("CLUSTER my_table;");
}

#[test]
fn test_cluster_table_using_index() {
    roundtrip("CLUSTER my_table USING my_index;");
}

#[test]
fn test_cluster_bare() {
    roundtrip("CLUSTER;");
}

#[test]
fn test_cluster_verbose() {
    roundtrip("CLUSTER VERBOSE my_table;");
}

// ── PUBLICATION ────────────────────────────────────────────────────────

#[test]
fn test_create_publication_all_tables() {
    roundtrip("CREATE PUBLICATION my_pub FOR ALL TABLES;");
}

#[test]
fn test_create_publication_for_table() {
    roundtrip("CREATE PUBLICATION my_pub FOR TABLE t1, t2;");
}

#[test]
fn test_create_publication_with_where() {
    roundtrip("CREATE PUBLICATION my_pub FOR TABLE t1 WHERE (status = 'active');");
}

#[test]
fn test_alter_publication_add_table() {
    roundtrip("ALTER PUBLICATION my_pub ADD TABLE t3;");
}

#[test]
fn test_alter_publication_drop_table() {
    roundtrip("ALTER PUBLICATION my_pub DROP TABLE t2;");
}

#[test]
fn test_alter_publication_set_table() {
    roundtrip("ALTER PUBLICATION my_pub SET TABLE t1, t4;");
}

#[test]
fn test_drop_publication() {
    roundtrip("DROP PUBLICATION my_pub;");
}

#[test]
fn test_drop_publication_if_exists() {
    roundtrip("DROP PUBLICATION IF EXISTS my_pub;");
}

// ── SUBSCRIPTION ───────────────────────────────────────────────────────

#[test]
fn test_create_subscription_basic() {
    roundtrip(
        "CREATE SUBSCRIPTION my_sub CONNECTION 'host=publisher dbname=mydb' PUBLICATION my_pub;",
    );
}

#[test]
fn test_create_subscription_with_options() {
    roundtrip(
        "CREATE SUBSCRIPTION my_sub CONNECTION 'host=publisher dbname=mydb' PUBLICATION my_pub WITH (copy_data = false, create_slot = false);",
    );
}

#[test]
fn test_alter_subscription_set_publication() {
    roundtrip("ALTER SUBSCRIPTION my_sub SET PUBLICATION new_pub;");
}

#[test]
fn test_alter_subscription_disable() {
    roundtrip("ALTER SUBSCRIPTION my_sub DISABLE;");
}

#[test]
fn test_alter_subscription_enable() {
    roundtrip("ALTER SUBSCRIPTION my_sub ENABLE;");
}

#[test]
fn test_alter_subscription_set_options() {
    roundtrip("ALTER SUBSCRIPTION my_sub SET (slot_name = 'new_slot');");
}

#[test]
fn test_drop_subscription() {
    roundtrip("DROP SUBSCRIPTION my_sub;");
}

#[test]
fn test_drop_subscription_if_exists() {
    roundtrip("DROP SUBSCRIPTION IF EXISTS my_sub;");
}

// ── MULTI-STATEMENT ────────────────────────────────────────────────────

#[test]
fn test_multi_listen_notify() {
    roundtrip("LISTEN ch1;\nNOTIFY ch1, 'test';\nUNLISTEN ch1;");
}

#[test]
fn test_multi_discard_cluster() {
    roundtrip("DISCARD ALL;\nCLUSTER my_table USING idx;");
}

#[test]
fn test_multi_drop_reassign() {
    roundtrip("DROP OWNED BY old_user CASCADE;\nREASSIGN OWNED BY old_user TO new_user;");
}

#[test]
fn test_multi_pub_sub() {
    roundtrip(
        "CREATE PUBLICATION p FOR ALL TABLES;\nCREATE SUBSCRIPTION s CONNECTION 'host=h' PUBLICATION p;",
    );
}
