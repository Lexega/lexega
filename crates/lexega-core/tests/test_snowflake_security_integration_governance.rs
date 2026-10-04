// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for Snowflake CREATE/ALTER SECURITY INTEGRATION property-value
//! governance rules (SNW-SECINTG-* property cluster). The name=value
//! pairs are captured into `integration.variant.set_properties`; rules
//! predicate on the quote-stripped, upper-cased `value_normalized`. The
//! danger verdict (which values/roles are insecure) lives in YAML.

use lexega_core::analyzer::RuleMatch;
use lexega_core::api::analyze_risk;
use std::collections::HashSet;

fn analyze_and_get_rules(sql: &str) -> HashSet<String> {
    match analyze_risk(sql) {
        Ok(report) => report
            .signals
            .iter()
            .filter_map(|f| match f {
                RuleMatch::Analysis(g) => Some(g.matched_rule.clone()),
            })
            .collect(),
        Err(e) => {
            eprintln!("Parse error: {:?}", e);
            HashSet::new()
        }
    }
}

// ── OAUTH_ALLOW_NON_TLS_REDIRECT_URI = TRUE ─────────────────────────

#[test]
fn oauth_non_tls_redirect_flags() {
    let rules = analyze_and_get_rules(
        "CREATE SECURITY INTEGRATION custom_oauth \
         TYPE = OAUTH OAUTH_CLIENT = CUSTOM \
         OAUTH_REDIRECT_URI = 'http://localhost/cb' \
         OAUTH_ALLOW_NON_TLS_REDIRECT_URI = TRUE ENABLED = TRUE;",
    );
    assert!(rules.contains("SNW-SECINTG-OAUTH-NON-TLS-REDIRECT"));
}

#[test]
fn oauth_non_tls_redirect_unquoted_lowercase_flags() {
    let rules = analyze_and_get_rules(
        "CREATE SECURITY INTEGRATION custom_oauth TYPE = OAUTH \
         OAUTH_CLIENT = CUSTOM OAUTH_ALLOW_NON_TLS_REDIRECT_URI = true;",
    );
    assert!(rules.contains("SNW-SECINTG-OAUTH-NON-TLS-REDIRECT"));
}

#[test]
fn oauth_non_tls_redirect_false_does_not_flag() {
    let rules = analyze_and_get_rules(
        "CREATE SECURITY INTEGRATION custom_oauth TYPE = OAUTH \
         OAUTH_CLIENT = CUSTOM OAUTH_ALLOW_NON_TLS_REDIRECT_URI = FALSE;",
    );
    assert!(!rules.contains("SNW-SECINTG-OAUTH-NON-TLS-REDIRECT"));
}

// ── EXTERNAL_OAUTH_ANY_ROLE_MODE = ENABLE ───────────────────────────

#[test]
fn extoauth_any_role_enable_flags() {
    let rules = analyze_and_get_rules(
        "CREATE SECURITY INTEGRATION ext TYPE = EXTERNAL_OAUTH \
         EXTERNAL_OAUTH_TYPE = OKTA \
         EXTERNAL_OAUTH_ISSUER = 'https://idp.example.com' \
         EXTERNAL_OAUTH_ANY_ROLE_MODE = 'ENABLE';",
    );
    assert!(rules.contains("SNW-SECINTG-EXTOAUTH-ANY-ROLE"));
}

#[test]
fn extoauth_any_role_enable_via_alter_flags() {
    let rules = analyze_and_get_rules(
        "ALTER SECURITY INTEGRATION ext SET EXTERNAL_OAUTH_ANY_ROLE_MODE = 'ENABLE';",
    );
    assert!(rules.contains("SNW-SECINTG-EXTOAUTH-ANY-ROLE"));
}

#[test]
fn extoauth_any_role_enable_for_privilege_does_not_flag() {
    let rules = analyze_and_get_rules(
        "ALTER SECURITY INTEGRATION ext SET EXTERNAL_OAUTH_ANY_ROLE_MODE = 'ENABLE_FOR_PRIVILEGE';",
    );
    assert!(!rules.contains("SNW-SECINTG-EXTOAUTH-ANY-ROLE"));
}

#[test]
fn extoauth_any_role_disable_does_not_flag() {
    let rules = analyze_and_get_rules(
        "ALTER SECURITY INTEGRATION ext SET EXTERNAL_OAUTH_ANY_ROLE_MODE = 'DISABLE';",
    );
    assert!(!rules.contains("SNW-SECINTG-EXTOAUTH-ANY-ROLE"));
}

// ── RUN_AS_ROLE = <privileged system role> ──────────────────────────

#[test]
fn scim_run_as_accountadmin_flags() {
    let rules = analyze_and_get_rules(
        "CREATE SECURITY INTEGRATION scim TYPE = SCIM \
         SCIM_CLIENT = 'OKTA' RUN_AS_ROLE = 'ACCOUNTADMIN';",
    );
    assert!(rules.contains("SNW-SECINTG-SCIM-RUN-AS-PRIV"));
}

#[test]
fn scim_run_as_provisioner_does_not_flag() {
    let rules = analyze_and_get_rules(
        "CREATE SECURITY INTEGRATION scim TYPE = SCIM \
         SCIM_CLIENT = 'OKTA' RUN_AS_ROLE = 'GENERIC_SCIM_PROVISIONER';",
    );
    assert!(!rules.contains("SNW-SECINTG-SCIM-RUN-AS-PRIV"));
}

// ── SAML2_SIGN_REQUEST = FALSE ──────────────────────────────────────

#[test]
fn saml_sign_request_off_flags() {
    let rules = analyze_and_get_rules(
        "CREATE SECURITY INTEGRATION saml TYPE = SAML2 \
         SAML2_ISSUER = 'https://idp.example.com' \
         SAML2_SSO_URL = 'https://idp.example.com/sso' \
         SAML2_PROVIDER = 'OKTA' SAML2_X509_CERT = 'MIIBcert' \
         SAML2_SIGN_REQUEST = FALSE;",
    );
    assert!(rules.contains("SNW-SECINTG-SAML-SIGN-REQUEST-OFF"));
}

#[test]
fn saml_sign_request_on_does_not_flag() {
    let rules = analyze_and_get_rules(
        "CREATE SECURITY INTEGRATION saml TYPE = SAML2 \
         SAML2_ISSUER = 'https://idp.example.com' \
         SAML2_SIGN_REQUEST = TRUE;",
    );
    assert!(!rules.contains("SNW-SECINTG-SAML-SIGN-REQUEST-OFF"));
}

// ── SYNC_PASSWORD = TRUE ────────────────────────────────────────────

#[test]
fn scim_sync_password_flags() {
    let rules = analyze_and_get_rules(
        "CREATE SECURITY INTEGRATION scim TYPE = SCIM \
         SCIM_CLIENT = 'OKTA' RUN_AS_ROLE = 'GENERIC_SCIM_PROVISIONER' \
         SYNC_PASSWORD = TRUE;",
    );
    assert!(rules.contains("SNW-SECINTG-SCIM-SYNC-PASSWORD"));
}

// ── A securely-configured integration stays quiet ───────────────────

#[test]
fn secure_integration_emits_no_property_rules() {
    let rules = analyze_and_get_rules(
        "CREATE SECURITY INTEGRATION ext TYPE = EXTERNAL_OAUTH \
         EXTERNAL_OAUTH_TYPE = OKTA \
         EXTERNAL_OAUTH_ISSUER = 'https://idp.example.com' \
         EXTERNAL_OAUTH_ANY_ROLE_MODE = 'DISABLE';",
    );
    for r in [
        "SNW-SECINTG-OAUTH-NON-TLS-REDIRECT",
        "SNW-SECINTG-EXTOAUTH-ANY-ROLE",
        "SNW-SECINTG-SCIM-RUN-AS-PRIV",
        "SNW-SECINTG-SAML-SIGN-REQUEST-OFF",
        "SNW-SECINTG-SCIM-SYNC-PASSWORD",
    ] {
        assert!(!rules.contains(r), "unexpected {r}");
    }
}
