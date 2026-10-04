// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Built-in fact-based rule corpus.
//!
//! Rules are **data**, not code. The YAML file is the source of truth.
//! To add or change a rule, edit `rules/builtin_rules.yaml` at the repo
//! root — never define rules as Rust functions.
//!
//! The same YAML schema serves customer rule files; load_v1_rules in
//! `super::loader` is the one customer-facing parse path.

use std::collections::HashMap;
use std::sync::OnceLock;

use super::engine::Rule;
use super::loader::{load_v1_rules_from_json, LoadError};

/// Build-time-precompiled corpus, transcoded from `builtin_rules.yaml` to
/// JSON by `build.rs`. Parsing JSON on startup is far faster than parsing
/// the YAML text. Parsed once on first use.
const BUILTIN_V1_RULES_JSON: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/builtin_rules.json"));

/// YAML source — the single source of truth. Embedded only in test
/// builds; the parity test asserts the precompiled JSON blob loads to an
/// identical corpus so the transcode can never silently diverge.
#[cfg(test)]
const BUILTIN_V1_RULES_YAML: &str = include_str!("../../../../rules/builtin_rules.yaml");

static BUILTIN_V1_RULES: OnceLock<Result<Vec<Rule>, LoadError>> = OnceLock::new();

/// Return the built-in fact-based rule corpus.
///
/// Loaded once on first call from `BUILTIN_V1_RULES_JSON` and cached
/// for the lifetime of the process. The `Err` arm only fires when the
/// embedded JSON is malformed — strictly a build-time programming
/// error, since it is generated from the corpus at build time and
/// every fact-pipeline integration test exercises this path. Callers
/// propagate the `LoadError` upward (`merge_full_rule_corpus`,
/// `build_v1_rule_corpus`, every public `analyze_*_facts` entry
/// point) rather than crash the analyzer with a panic.
pub fn all_builtin_rules() -> Result<&'static [Rule], LoadError> {
    BUILTIN_V1_RULES
        .get_or_init(|| {
            load_v1_rules_from_json(BUILTIN_V1_RULES_JSON).and_then(|rs| rs.into_strict_rules())
        })
        .as_ref()
        .map(|v| v.as_slice())
        .map_err(|e| e.clone())
}

/// The built-in corpus as JSON bytes, for surfaces that navigate the raw
/// rule structure directly instead of the compiled `Rule` corpus. The
/// corpus is embedded once; this is that copy.
pub fn builtin_corpus_json() -> &'static [u8] {
    BUILTIN_V1_RULES_JSON
}

static BUILTIN_ALIAS_MAP: OnceLock<HashMap<String, &'static str>> = OnceLock::new();

/// Resolve a rule id a policy or exception may reference to the current
/// canonical id. If `id` is a former (deprecated) id of a built-in
/// rule, return that rule's live `id`; otherwise return `id` unchanged,
/// so callers can canonicalize any referenced id unconditionally.
///
/// Lookup is case-insensitive, matching how policies/exceptions compare
/// rule ids. Only built-in aliases resolve — renaming a shipped rule
/// keeps existing policy/exception files working without edits. Output
/// (reports, SARIF, decision artifacts) always uses the canonical id;
/// a former id never appears there.
pub fn canonical_rule_id(id: &str) -> &str {
    let map = BUILTIN_ALIAS_MAP.get_or_init(|| {
        let mut m = HashMap::new();
        if let Ok(rules) = all_builtin_rules() {
            for r in rules {
                for former in &r.former_ids {
                    m.insert(former.to_ascii_uppercase(), r.id.as_str());
                }
            }
        }
        m
    });
    map.get(&id.to_ascii_uppercase()).copied().unwrap_or(id)
}

/// The deprecated ids a built-in rule was previously published under —
/// surfaced as SARIF `deprecatedIds` so code-scanning dashboards can
/// re-key existing alerts across a rename. Empty when the id is unknown
/// or never had an alias.
pub fn former_ids_for(canonical_id: &str) -> &'static [String] {
    all_builtin_rules()
        .ok()
        .and_then(|rules| rules.iter().find(|r| r.id == canonical_id))
        .map(|r| r.former_ids.as_slice())
        .unwrap_or(&[])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The precompiled JSON blob must load to exactly the same corpus as
    /// parsing the YAML source directly. If the build-time transcode ever
    /// drops or mangles a field, this fails — so the runtime never quietly
    /// analyzes with a corpus that differs from `builtin_rules.yaml`.
    #[test]
    fn precompiled_json_matches_yaml_source() {
        use super::super::loader::load_v1_rules;
        use std::collections::BTreeMap;

        let dbg = |rs: &[Rule]| -> BTreeMap<String, String> {
            rs.iter()
                .map(|r| (r.id.clone(), format!("{r:?}")))
                .collect()
        };

        let from_json = all_builtin_rules().expect("precompiled JSON corpus loads");
        let from_yaml = load_v1_rules(BUILTIN_V1_RULES_YAML)
            .and_then(|rs| rs.into_strict_rules())
            .expect("YAML source corpus loads");

        let json_map = dbg(from_json);
        let yaml_map = dbg(&from_yaml);
        assert_eq!(
            json_map.len(),
            yaml_map.len(),
            "rule count differs: JSON {} vs YAML {}",
            json_map.len(),
            yaml_map.len()
        );
        for (id, y) in &yaml_map {
            match json_map.get(id) {
                Some(j) => {
                    assert_eq!(
                        j, y,
                        "rule {id} differs between precompiled JSON and YAML source"
                    )
                }
                None => {
                    panic!("rule {id} present in YAML source but missing from precompiled JSON")
                }
            }
        }
    }

    #[test]
    fn canonical_rule_id_resolves_former_ids() {
        // The dialect-neutral role rules were renamed PG-ROLE-* -> ROLE-*;
        // a former id resolves to the current canonical id.
        assert_eq!(canonical_rule_id("PG-ROLE-NEW"), "ROLE-NEW");
        assert_eq!(canonical_rule_id("PG-ROLE-CHG"), "ROLE-CHG");
        assert_eq!(canonical_rule_id("PG-ROLE-DROP"), "ROLE-DROP");
        // Case-insensitive, matching policy/exception id comparison.
        assert_eq!(canonical_rule_id("pg-role-new"), "ROLE-NEW");
        // A current id resolves to itself; an unknown id passes through.
        assert_eq!(canonical_rule_id("ROLE-NEW"), "ROLE-NEW");
        assert_eq!(canonical_rule_id("NOT-A-RULE"), "NOT-A-RULE");
        // A genuinely PG-specific rule is not a former id — prefix kept.
        assert_eq!(canonical_rule_id("PG-ROLE-SUPERUSER"), "PG-ROLE-SUPERUSER");
    }

    #[test]
    fn former_ids_for_reports_aliases() {
        assert_eq!(former_ids_for("ROLE-NEW"), &["PG-ROLE-NEW".to_string()]);
        assert!(former_ids_for("GRT-TO-PUBLIC").is_empty());
        assert!(former_ids_for("NOT-A-RULE").is_empty());
    }

    #[test]
    fn no_former_id_shadows_a_live_id() {
        // The loader enforces this, but assert it on the live corpus so a
        // future rename that shadows an active rule also fails here.
        let rules = all_builtin_rules().expect("built-in corpus loads");
        let live: std::collections::HashSet<&str> = rules.iter().map(|r| r.id.as_str()).collect();
        for r in rules {
            for f in &r.former_ids {
                assert!(
                    !live.contains(f.as_str()),
                    "former id {f} shadows a live id"
                );
            }
        }
    }

    #[test]
    fn builtin_corpus_loads_with_expected_rule_ids() {
        let rules = all_builtin_rules().expect("built-in corpus loads");
        let ids: Vec<&str> = rules.iter().map(|r| r.id.as_str()).collect();
        // Privilege-family rule IDs.
        assert!(ids.contains(&"GRT-WITH-OPT"));
        assert!(ids.contains(&"GRT-ALL-PRIV"));
        assert!(ids.contains(&"GRT-TO-PUBLIC"));
        assert!(ids.contains(&"GRT-TO-SHARE"));
        assert!(ids.contains(&"GRT-OWNER-XFER"));
        // Effective-access expansion family — catalog-derived.
        assert!(ids.contains(&"GRT-SYSROLE-EXP"));
        assert!(ids.contains(&"GRT-ACCESS-EXP-HI"));
        assert!(ids.contains(&"GRT-ACCESS-EXP"));
        // Substrate-enabled privilege rule.
        assert!(ids.contains(&"PRIV-ON-FUTURE"));
        // Databricks Unity Catalog GRANT/REVOKE rules.
        assert!(ids.contains(&"DBX-GRT-CAT-ALLPRIV"));
        assert!(ids.contains(&"DBX-GRT-CAT-MANAGE"));
        assert!(ids.contains(&"DBX-GRT-CAT-MODIFY"));
        assert!(ids.contains(&"DBX-GRT-SCHEMA-MANAGE"));
        assert!(ids.contains(&"DBX-GRT-SCHEMA-MODIFY"));
        assert!(ids.contains(&"DBX-GRT-VOL-MANAGE"));
        assert!(ids.contains(&"DBX-GRT-EXTUSE-LOC"));
        assert!(ids.contains(&"DBX-GRT-EXTUSE-SCHEMA"));
        assert!(ids.contains(&"DBX-GRT-EXTLOC-WRFILES"));
        assert!(ids.contains(&"DBX-GRT-EXTLOC-RDFILES"));
        assert!(ids.contains(&"DBX-GRT-CRED-CREATE"));
        assert!(ids.contains(&"DBX-GRT-EXTLOC-CREATE"));
        assert!(ids.contains(&"DBX-GRT-SHARE-SETPERM"));
        assert!(ids.contains(&"DBX-RVK-CAT-ALLPRIV"));
        assert!(ids.contains(&"DBX-RVK-CAT-MANAGE"));
        // Query-family rule IDs.
        // Q-JOIN-CROSS-IMPL collapsed into unified Q-JOIN-CROSS-CENH that
        // matches both explicit `CROSS JOIN` and implicit comma-FROM
        // with a catalog-attested cartesian-product threshold gate.
        assert!(ids.contains(&"Q-JOIN-CROSS-CENH"));
        assert!(ids.contains(&"Q-SCAN-NOFILT"));
        assert!(ids.contains(&"Q-SCAN-1TBL"));
        assert!(ids.contains(&"Q-WIN-NOPART"));
        assert!(ids.contains(&"Q-WIN-RANK-NOORD"));
        assert!(ids.contains(&"Q-NULL-NOTIN"));
        assert!(ids.contains(&"Q-AGG-NOFILT"));
        assert!(ids.contains(&"Q-SUBQ-CORR-SEL"));
        assert!(ids.contains(&"Q-SUBQ-CORR-WHERE"));
        assert!(ids.contains(&"Q-AGG-NONDET"));
        assert!(ids.contains(&"Q-WIN-NONDET"));
        assert!(ids.contains(&"Q-NONDET"));
        assert!(ids.contains(&"Q-WIN-MULTIPART"));
        // Catalog-aware rules.
        assert!(ids.contains(&"Q-TBL-UNBOUNDED-CENH"));
        assert!(ids.contains(&"Q-TBL-SELSTAR-WIDE-CENH"));
        assert!(ids.contains(&"Q-AGG-NOFILT-CENH"));
        assert!(ids.contains(&"Q-WIN-NOPART-CENH"));
        assert!(ids.contains(&"Q-WIN-UNBOUNDED-CENH"));
        assert!(ids.contains(&"Q-WIN-HICARD-CENH"));
        assert!(ids.contains(&"Q-JOIN-TYPEMIS-CENH"));
        assert!(ids.contains(&"Q-JOIN-NULL-CENH"));
        assert!(ids.contains(&"Q-FLOW-TAINT"));
        assert!(ids.contains(&"Q-NULL-COUNT-CENH"));
        // Catalog-substrate extensions.
        assert!(ids.contains(&"Q-VIEW-REF-CENH"));
        assert!(ids.contains(&"Q-AGG-HICARD"));
        assert!(ids.contains(&"Q-NULL-NEQ"));
        assert!(ids.contains(&"Q-JOIN-FKVIOL-CENH"));
        assert!(ids.contains(&"Q-AGG-EXPLODE-CENH"));
        // Principal-attachment family — fires on AUTHPOL bind / unbind
        // via ALTER USER / ALTER ACCOUNT.
        assert!(ids.contains(&"SNW-AUTHPOL-ON"));
        assert!(ids.contains(&"SNW-AUTHPOL-OFF"));
        // Table DDL family (CREATE / ALTER / DROP TABLE, TRUNCATE,
        // DROP ALL ROW ACCESS POLICIES).
        assert!(ids.contains(&"TBL-DROP"));
        assert!(ids.contains(&"TBL-TRUNCATE"));
        assert!(ids.contains(&"TBL-REPLACE"));
        assert!(ids.contains(&"TBL-RENAME"));
        assert!(ids.contains(&"TBL-COL-ADD"));
        assert!(ids.contains(&"TBL-COL-DROP"));
        assert!(ids.contains(&"TBL-MASK-ADD"));
        assert!(ids.contains(&"TBL-MASK-RMV"));
        assert!(ids.contains(&"TBL-RAP-ADD"));
        assert!(ids.contains(&"TBL-RAP-RMV"));
        assert!(ids.contains(&"TBL-RAP-RMV-ALL"));
        assert!(ids.contains(&"TBL-AGGPOL-RMV"));
        assert!(ids.contains(&"TBL-TAG-ADD"));
        assert!(ids.contains(&"TBL-TAG-RMV"));
        // DML write-scope rules.
        assert!(ids.contains(&"DML-WRITE-UNBOUNDED"));
        assert!(ids.contains(&"DML-WRITE-XSCHEMA"));
        assert!(ids.contains(&"DML-WRITE-MULTITBL"));
        // Databricks/Delta table-maintenance family.
        assert!(ids.contains(&"DBX-TBL-OPT"));
        assert!(ids.contains(&"DBX-VACUUM-ZERO"));
        assert!(ids.contains(&"DBX-VACUUM-LOWRET"));
        assert!(ids.contains(&"INFO-DBX-TBL-HIST"));
        assert!(ids.contains(&"INFO-DBX-TBL-REPAIR"));
        assert!(ids.contains(&"INFO-DBX-TBL-CLUSTER-CFG"));
        assert!(ids.contains(&"DBX-TBL-RESTORE"));
        assert!(ids.contains(&"DBX-MERGE-SCHEMA-EVO"));
        assert!(ids.contains(&"DBX-TBL-CACHE"));
        assert!(ids.contains(&"INFO-DBX-TBL-CACHE-LAZY"));
        assert!(ids.contains(&"DBX-TBL-UNCACHE"));
        // Volume / external-location / connection / flow lifecycle
        // rules.
        assert!(ids.contains(&"DBX-VOL-NEW"));
        assert!(ids.contains(&"DBX-VOL-OWNER-CHG"));
        assert!(ids.contains(&"DBX-VOL-DROP"));
        assert!(ids.contains(&"DBX-VOL-NAME-CHG"));
        assert!(ids.contains(&"DBX-VOL-TAG-CHG"));
        assert!(ids.contains(&"DBX-VOL-TAG-RMV"));
        assert!(ids.contains(&"DBX-EXTLOC-NEW"));
        assert!(ids.contains(&"DBX-EXTLOC-URL-CHG"));
        assert!(ids.contains(&"DBX-EXTLOC-CRED-CHG"));
        assert!(ids.contains(&"DBX-EXTLOC-OWNER-CHG"));
        assert!(ids.contains(&"DBX-EXTLOC-DROP"));
        assert!(ids.contains(&"DBX-CONN-NEW"));
        assert!(ids.contains(&"DBX-CONN-DROP"));
        assert!(ids.contains(&"DBX-CONN-OWNER-CHG"));
        assert!(ids.contains(&"DBX-CONN-NAME-CHG"));
        assert!(ids.contains(&"DBX-CONN-CHG"));
        assert!(ids.contains(&"DBX-CRED-DROP"));
        assert!(ids.contains(&"DBX-FLOW-NEW"));
        // PG-DOMAIN-* — Postgres DOMAIN DDL governance (typed
        // AlterDomainAction + DropDomain cascade).
        assert!(ids.contains(&"PG-DOMAIN-DROP"));
        assert!(ids.contains(&"PG-DOMAIN-CASCADE-DROP"));
        assert!(ids.contains(&"PG-DOMAIN-CHG"));
        assert!(ids.contains(&"PG-DOMAIN-NAME-CHG"));
        assert!(ids.contains(&"PG-DOMAIN-OWNER-CHG"));
        assert!(ids.contains(&"PG-DOMAIN-NOTNULL-DROP"));
        assert!(ids.contains(&"PG-DOMAIN-CONSTR-DROP"));
        assert!(ids.contains(&"PG-DOMAIN-CONSTR-CASCADE-DROP"));
        // PG-COPY-* — Postgres `COPY` data-movement utility.
        assert!(ids.contains(&"PG-COPY-FROM"));
        assert!(ids.contains(&"PG-COPY-TO"));
        assert!(ids.contains(&"PG-COPY-PROGRAM"));
        // PG-IDX-* — `CREATE INDEX` / `ALTER INDEX` lifecycle (typed
        // `AstCreateIndex` + `AstAlterIndex`; PG-IDX-REBUILD via
        // typed `AstReindex`).
        assert!(ids.contains(&"INFO-PG-IDX-NEW"));
        assert!(ids.contains(&"PG-IDX-NAME-CHG"));
        assert!(ids.contains(&"PG-IDX-CHG"));
    }

    #[test]
    fn builtin_corpus_has_unique_rule_ids() {
        let rules = all_builtin_rules().expect("built-in corpus loads");
        let mut sorted: Vec<&str> = rules.iter().map(|r| r.id.as_str()).collect();
        sorted.sort();
        let len_before = sorted.len();
        sorted.dedup();
        assert_eq!(sorted.len(), len_before, "built-in rule IDs must be unique");
    }
}
