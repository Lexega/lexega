// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! The shapes Snowflake policies and tags are written in, each read whole as the name it is.

mod name_shapes;

use lexega_syntax::dialect;
use name_shapes::reads_whole;

#[test]
fn snowflake_alter_account_set_authentication_policy_name() {
    reads_whole(
        &dialect::snowflake(),
        &["ALTER ACCOUNT SET AUTHENTICATION POLICY «IDENTIFIER('d1.s1.auth_std')»;"],
    );
}

#[test]
fn snowflake_alter_aggregation_policy_policy_name() {
    reads_whole(
        &dialect::snowflake(),
        &["ALTER AGGREGATION POLICY «IDENTIFIER('d1.s1.ap_min')» SET COMMENT = 'x';"],
    );
}

#[test]
fn snowflake_create_aggregation_policy_policy_name() {
    reads_whole(
        &dialect::snowflake(),
        &[
            "CREATE AGGREGATION POLICY «IDENTIFIER('d1.s1.ap_min')» AS () RETURNS AGGREGATION_CONSTRAINT -> AGGREGATION_CONSTRAINT(MIN_GROUP_SIZE => 5);",
        ],
    );
}

#[test]
fn snowflake_drop_aggregation_policy_policy_name() {
    reads_whole(
        &dialect::snowflake(),
        &["DROP AGGREGATION POLICY «IDENTIFIER('d1.s1.ap_min')»;"],
    );
}

#[test]
fn snowflake_alter_aggregation_policy_rename_to_name() {
    reads_whole(
        &dialect::snowflake(),
        &["ALTER AGGREGATION POLICY gov.sec.ap_min RENAME TO «IDENTIFIER('d1.s1.ap2')»;"],
    );
}

#[test]
fn snowflake_alter_authentication_policy_policy_name() {
    reads_whole(
        &dialect::snowflake(),
        &[
            "ALTER AUTHENTICATION POLICY «IDENTIFIER('d1.s1.auth_std')» SET CLIENT_TYPES = ('SNOWFLAKE_UI');",
        ],
    );
}

#[test]
fn snowflake_create_authentication_policy_policy_name() {
    reads_whole(
        &dialect::snowflake(),
        &[
            "CREATE AUTHENTICATION POLICY «IDENTIFIER('d1.s1.auth_std')» MFA_ENROLLMENT = REQUIRED;",
        ],
    );
}

#[test]
fn snowflake_alter_join_policy_policy_name() {
    reads_whole(
        &dialect::snowflake(),
        &["ALTER JOIN POLICY «IDENTIFIER('d1.s1.jp_req')» SET COMMENT = 'x';"],
    );
}

#[test]
fn snowflake_create_join_policy_policy_name() {
    reads_whole(
        &dialect::snowflake(),
        &[
            "CREATE JOIN POLICY «IDENTIFIER('d1.s1.jp_req')» AS () RETURNS JOIN_CONSTRAINT -> JOIN_CONSTRAINT(JOIN_REQUIRED => TRUE);",
        ],
    );
}

#[test]
fn snowflake_drop_join_policy_policy_name() {
    reads_whole(
        &dialect::snowflake(),
        &["DROP JOIN POLICY «IDENTIFIER('d1.s1.jp_req')»;"],
    );
}

#[test]
fn snowflake_alter_masking_policy_policy_name() {
    reads_whole(
        &dialect::snowflake(),
        &[
            "ALTER MASKING POLICY «d1.stage.mask_email» SET COMMENT = 'x';",
            "ALTER MASKING POLICY «IDENTIFIER('d1.s1.mask_email')» SET COMMENT = 'x';",
        ],
    );
}

#[test]
fn snowflake_create_masking_policy_policy_name() {
    reads_whole(
        &dialect::snowflake(),
        &[
            "CREATE MASKING POLICY «d1.stage.mask_email» AS (val STRING) RETURNS STRING -> CASE WHEN CURRENT_ROLE() = 'ADMIN' THEN val ELSE '***' END;",
            "CREATE MASKING POLICY «IDENTIFIER('d1.s1.mask_email')» AS (val STRING) RETURNS STRING -> CASE WHEN CURRENT_ROLE() = 'ADMIN' THEN val ELSE '***' END;",
        ],
    );
}

#[test]
fn snowflake_drop_masking_policy_policy_name() {
    reads_whole(
        &dialect::snowflake(),
        &["DROP MASKING POLICY «IDENTIFIER('d1.s1.mask_email')»;"],
    );
}

#[test]
fn snowflake_alter_masking_policy_rename_to_name() {
    reads_whole(
        &dialect::snowflake(),
        &[
            "ALTER MASKING POLICY gov.pii.mask_email RENAME TO «d1.stage.mask_email2»;",
            "ALTER MASKING POLICY gov.pii.mask_email RENAME TO «IDENTIFIER('d1.s1.mask_email2')»;",
        ],
    );
}

#[test]
fn snowflake_alter_masking_policy_set_tag_name() {
    reads_whole(
        &dialect::snowflake(),
        &[
            "ALTER MASKING POLICY gov.pii.mask_email SET TAG «IDENTIFIER('d1.s1.sensitivity')» = 'high';",
        ],
    );
}

#[test]
fn snowflake_alter_masking_policy_unset_tag_name() {
    reads_whole(
        &dialect::snowflake(),
        &["ALTER MASKING POLICY gov.pii.mask_email UNSET TAG «IDENTIFIER('d1.s1.sensitivity')»;"],
    );
}

#[test]
fn snowflake_alter_network_policy_policy_name() {
    reads_whole(
        &dialect::snowflake(),
        &["ALTER NETWORK POLICY «IDENTIFIER('np_corp')» SET ALLOWED_IP_LIST = ('10.0.0.0/8');"],
    );
}

#[test]
fn snowflake_drop_network_policy_policy_name() {
    reads_whole(
        &dialect::snowflake(),
        &["DROP NETWORK POLICY «IDENTIFIER('np_corp')»;"],
    );
}

#[test]
fn snowflake_alter_projection_policy_policy_name() {
    reads_whole(
        &dialect::snowflake(),
        &["ALTER PROJECTION POLICY «IDENTIFIER('d1.s1.pp_hide')» SET COMMENT = 'x';"],
    );
}

#[test]
fn snowflake_create_projection_policy_policy_name() {
    reads_whole(
        &dialect::snowflake(),
        &[
            "CREATE PROJECTION POLICY «IDENTIFIER('d1.s1.pp_hide')» AS () RETURNS PROJECTION_CONSTRAINT -> PROJECTION_CONSTRAINT(ALLOW => false);",
        ],
    );
}

#[test]
fn snowflake_drop_projection_policy_policy_name() {
    reads_whole(
        &dialect::snowflake(),
        &["DROP PROJECTION POLICY «IDENTIFIER('d1.s1.pp_hide')»;"],
    );
}

#[test]
fn snowflake_alter_projection_policy_rename_to_name() {
    reads_whole(
        &dialect::snowflake(),
        &["ALTER PROJECTION POLICY gov.sec.pp_hide RENAME TO «IDENTIFIER('d1.s1.pp2')»;"],
    );
}

#[test]
fn snowflake_alter_projection_policy_set_tag_name() {
    reads_whole(
        &dialect::snowflake(),
        &[
            "ALTER PROJECTION POLICY gov.sec.pp_hide SET TAG «IDENTIFIER('d1.s1.sensitivity')» = 'high';",
        ],
    );
}

#[test]
fn snowflake_alter_password_policy_policy_name() {
    reads_whole(
        &dialect::snowflake(),
        &["ALTER PASSWORD POLICY «IDENTIFIER('d1.s1.pwp_std')» SET PASSWORD_MAX_AGE_DAYS = 30;"],
    );
}

#[test]
fn snowflake_create_password_policy_policy_name() {
    reads_whole(
        &dialect::snowflake(),
        &["CREATE PASSWORD POLICY «IDENTIFIER('d1.s1.pwp_std')» PASSWORD_MIN_LENGTH = 14;"],
    );
}

#[test]
fn snowflake_drop_password_policy_policy_name() {
    reads_whole(
        &dialect::snowflake(),
        &["DROP PASSWORD POLICY «IDENTIFIER('d1.s1.pwp_std')»;"],
    );
}

#[test]
fn snowflake_alter_row_access_policy_policy_name() {
    reads_whole(
        &dialect::snowflake(),
        &["ALTER ROW ACCESS POLICY «IDENTIFIER('d1.s1.rap_region')» SET COMMENT = 'x';"],
    );
}

#[test]
fn snowflake_create_row_access_policy_policy_name() {
    reads_whole(
        &dialect::snowflake(),
        &[
            "CREATE ROW ACCESS POLICY «IDENTIFIER('d1.s1.rap_region')» AS (region STRING) RETURNS BOOLEAN -> region = 'EU';",
        ],
    );
}

#[test]
fn snowflake_drop_row_access_policy_policy_name() {
    reads_whole(
        &dialect::snowflake(),
        &[
            "DROP ROW ACCESS POLICY «d1.stage.rap_region»;",
            "DROP ROW ACCESS POLICY «IDENTIFIER('d1.s1.rap_region')»;",
        ],
    );
}

#[test]
fn snowflake_alter_row_access_policy_rename_to_name() {
    reads_whole(
        &dialect::snowflake(),
        &["ALTER ROW ACCESS POLICY gov.sec.rap_region RENAME TO «IDENTIFIER('d1.s1.rap2')»;"],
    );
}

#[test]
fn snowflake_alter_session_policy_policy_name() {
    reads_whole(
        &dialect::snowflake(),
        &[
            "ALTER SESSION POLICY «IDENTIFIER('d1.s1.sess_std')» SET SESSION_IDLE_TIMEOUT_MINS = 60;",
        ],
    );
}

#[test]
fn snowflake_create_session_policy_policy_name() {
    reads_whole(
        &dialect::snowflake(),
        &["CREATE SESSION POLICY «IDENTIFIER('d1.s1.sess_std')» SESSION_IDLE_TIMEOUT_MINS = 30;"],
    );
}

#[test]
fn snowflake_drop_session_policy_policy_name() {
    reads_whole(
        &dialect::snowflake(),
        &["DROP SESSION POLICY «IDENTIFIER('d1.s1.sess_std')»;"],
    );
}

#[test]
fn snowflake_alter_tag_tag_name() {
    reads_whole(
        &dialect::snowflake(),
        &["ALTER TAG «IDENTIFIER('d1.s1.sensitivity')» SET COMMENT = 'x';"],
    );
}

#[test]
fn snowflake_create_tag_tag_name() {
    reads_whole(
        &dialect::snowflake(),
        &["CREATE TAG «IDENTIFIER('d1.s1.sensitivity')» ALLOWED_VALUES 'low', 'high';"],
    );
}

#[test]
fn snowflake_alter_tag_rename_to_name() {
    reads_whole(
        &dialect::snowflake(),
        &["ALTER TAG gov.tags.sensitivity RENAME TO «IDENTIFIER('d1.s1.sens2')»;"],
    );
}

#[test]
fn snowflake_alter_tag_set_masking_policy_name() {
    reads_whole(
        &dialect::snowflake(),
        &["ALTER TAG gov.tags.sensitivity SET MASKING POLICY «IDENTIFIER('d1.s1.mask_email')»;"],
    );
}

#[test]
fn snowflake_undrop_tag_tag_name() {
    reads_whole(
        &dialect::snowflake(),
        &["UNDROP TAG «IDENTIFIER('d1.s1.sensitivity')»;"],
    );
}

#[test]
fn snowflake_alter_tag_unset_masking_policy_name() {
    reads_whole(
        &dialect::snowflake(),
        &["ALTER TAG gov.tags.sensitivity UNSET MASKING POLICY «IDENTIFIER('d1.s1.mask_email')»;"],
    );
}

#[test]
fn snowflake_alter_user_set_authentication_policy_name() {
    reads_whole(
        &dialect::snowflake(),
        &["ALTER USER alice SET AUTHENTICATION POLICY «IDENTIFIER('d1.s1.auth_std')»;"],
    );
}
