// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Rule evaluation engine.
//!
//! Per-statement flow: `derive_facts → evaluate_rules → drop facts`.
//! Each rule's compiled predicate runs against `StatementFacts`;
//! matches become `Signal` records.

use crate::facts::{RiskLevel, StatementFacts};
use crate::lexer::token::Span;

use super::compile::{CompiledPredicate, EvalResult, WitnessCandidate};
use super::signal::{EmissionMode, FactWitness, RuleExplanation, Signal, SignalEvidence};

/// A loaded, compiled rule. Cloneable; shares the underlying predicate
/// closure across clones via `Arc` (inside `CompiledPredicate`).
#[derive(Debug, Clone)]
pub struct Rule {
    pub id: String,
    /// Deprecated identifiers this rule was previously published under.
    /// Output (reports, SARIF, decision artifacts) always uses the
    /// current `id`; policies and exceptions that still reference a
    /// former id resolve to this rule via `canonical_rule_id`. Empty for
    /// the vast majority of rules.
    pub former_ids: Vec<String>,
    pub description: String,
    pub risk_level: RiskLevel,
    pub enabled: bool,
    pub triggers: CompiledPredicate,
    pub message_template: Option<MessageTemplate>,
    pub emission: EmissionMode,
    /// When `true`, the analyzer's deduplication pass keeps each
    /// emitted signal as its own entry instead of merging signals from
    /// the same rule. Customer-facing compliance/review rules that
    /// produce per-occurrence artifacts (`SNW-UNKNOWN`) set this; most
    /// rules leave it `false` so dedup collapses duplicates.
    pub per_statement: bool,
}

/// Message template — a string with `{path.to.field}` interpolation
/// slots. Simple literal-replacement renderer (no path validation
/// against the schema).
#[derive(Debug, Clone)]
pub struct MessageTemplate {
    pub raw: String,
}

impl MessageTemplate {
    pub fn new(raw: impl Into<String>) -> Self {
        Self { raw: raw.into() }
    }

    /// Render the template against `StatementFacts` + an optional
    /// per-witness sub-fact (`witness.<sub-path>` interpolation source
    /// when in `per_witness` emission mode).
    pub fn render(
        &self,
        facts_value: &serde_json::Value,
        witness: Option<&serde_json::Value>,
    ) -> String {
        render_template(&self.raw, facts_value, witness)
    }
}

/// Evaluate every rule against one statement's facts. Returns the
/// signals that fired (one per matching rule with `emission: once`,
/// or one per witness with `emission: per_witness`).
pub fn evaluate_rules(facts: &StatementFacts, rules: &[Rule]) -> Vec<Signal> {
    let facts_value = serde_json::to_value(facts).unwrap_or(serde_json::Value::Null);
    // Fact-family dispatch: skip rules whose required families are
    // absent from this statement. A rule's `root_mask` is a sound
    // over-approximation, so a disjoint intersection proves NoMatch
    // (see `compile::predicate_root_mask`).
    let present_mask = super::compile::facts_present_mask(&facts_value);
    let kind_idx = facts.kind as usize;
    let mut out = Vec::new();
    for rule in rules {
        if !rule.enabled {
            continue;
        }
        // Statement-kind gate first (typed `facts.kind`, no serialization),
        // then the fact-family mask. Either proving NoMatch skips the rule.
        if rule.triggers.kind_gate().skips(kind_idx) {
            continue;
        }
        let mask = rule.triggers.root_mask();
        if mask != 0 && mask & present_mask == 0 {
            continue;
        }
        match rule.triggers.evaluate_value(&facts_value) {
            EvalResult::NoMatch => {}
            EvalResult::Match { witnesses } => {
                emit_for_match(rule, &facts_value, witnesses, None, &mut out);
            }
        }
    }
    out
}

/// Per-rule explain-mode evaluation outcome. Produced by
/// [`evaluate_rules_with_explain`] for every enabled rule —
/// including the ones that didn't fire — so callers wiring
/// `--explain-signals` / verbose / trace mode can render rejection
/// reasons against the same surface they render matches.
#[derive(Debug, Clone)]
pub struct EvaluatedRule {
    pub rule_id: String,
    pub matched: bool,
    pub explanation: RuleExplanation,
    /// One signal per emission this rule produced (zero when
    /// `matched == false`, one when emission is `Once` and the rule
    /// matched, possibly many when emission is `PerWitness`).
    pub signals: Vec<Signal>,
}

/// Evaluate every rule with introspection enabled. Returns one
/// [`EvaluatedRule`] per enabled rule so the caller sees what fired
/// AND what didn't, with typed-then-rendered rejection paths on the
/// [`RuleExplanation`] surface.
///
/// This is the explain-mode counterpart to [`evaluate_rules`]. Hot
/// path callers should keep using [`evaluate_rules`]; this one runs
/// the explain trace under every rule and is intended for `--verbose`
/// / `--trace` / `--explain-signals` flows where extra evaluation
/// work is acceptable.
pub fn evaluate_rules_with_explain(facts: &StatementFacts, rules: &[Rule]) -> Vec<EvaluatedRule> {
    let facts_value = serde_json::to_value(facts).unwrap_or(serde_json::Value::Null);
    let mut out = Vec::new();
    for rule in rules {
        if !rule.enabled {
            continue;
        }
        let (result, explanation) = rule.triggers.evaluate_value_with_explain(&facts_value);
        let mut signals = Vec::new();
        let matched = match result {
            EvalResult::NoMatch => false,
            EvalResult::Match { witnesses } => {
                emit_for_match(
                    rule,
                    &facts_value,
                    witnesses,
                    Some(&explanation),
                    &mut signals,
                );
                true
            }
        };
        out.push(EvaluatedRule {
            rule_id: rule.id.clone(),
            matched,
            explanation,
            signals,
        });
    }
    out
}

fn emit_for_match(
    rule: &Rule,
    facts_value: &serde_json::Value,
    candidates: Vec<WitnessCandidate>,
    explanation: Option<&RuleExplanation>,
    out: &mut Vec<Signal>,
) {
    match rule.emission {
        EmissionMode::Once => {
            let first_value = candidates.first().map(|c| c.value.clone());
            let message = render_message(rule, facts_value, first_value.as_ref());
            out.push(Signal {
                rule_id: rule.id.clone(),
                evidence: SignalEvidence {
                    witnesses: candidates.iter().map(project_witness).collect(),
                },
                source_span: signal_span(facts_value, candidates.first()),
                risk_level: rule.risk_level,
                message,
                explanation: explanation.cloned(),
            });
        }
        EmissionMode::PerWitness => {
            // Per-witness emission fans out only on `each:`-tagged
            // candidates. Intermediate `exists:` quantifiers along
            // the predicate path also contribute candidates (so the
            // customer-facing `signal.evidence` renders the full
            // match trail), but they MUST NOT multiply the emission
            // count.
            //
            // Chained `each:` (e.g.
            // `query.scopes: each: window_functions: each: ...`)
            // tags both the outer and inner matches as
            // `from_each: true`. The finding the user must locate is
            // the *leaf* — the inner `each:` witness whose span
            // points at the specific window function, not the scope
            // that contains it. Filter candidates to leaf paths
            // (those whose path is not a prefix of any other
            // from_each candidate's path) so emission fires once per
            // leaf finding, not once per nesting level.
            //
            // If no `each:`-tagged candidate exists (rule shape
            // uses `exists:` only but is configured `per_witness`),
            // fall back to emitting one signal anchored at the
            // first collected candidate so the rule still fires.
            let from_each_paths: Vec<&str> = candidates
                .iter()
                .filter(|c| c.from_each)
                .map(|c| c.path.as_str())
                .collect();
            let each_candidates: Vec<&WitnessCandidate> = candidates
                .iter()
                .filter(|c| c.from_each && is_leaf_each_path(&c.path, &from_each_paths))
                .collect();
            if each_candidates.is_empty() {
                let anchor = candidates.first();
                let message = render_message(rule, facts_value, anchor.map(|c| &c.value));
                out.push(Signal {
                    rule_id: rule.id.clone(),
                    evidence: SignalEvidence {
                        witnesses: candidates.iter().map(project_witness).collect(),
                    },
                    source_span: anchor.and_then(|c| extract_span(&c.value)),
                    risk_level: rule.risk_level,
                    message,
                    explanation: explanation.cloned(),
                });
                return;
            }
            for candidate in each_candidates {
                let message = render_message(rule, facts_value, Some(&candidate.value));
                out.push(Signal {
                    rule_id: rule.id.clone(),
                    evidence: SignalEvidence {
                        witnesses: vec![project_witness(candidate)],
                    },
                    source_span: extract_span(&candidate.value),
                    risk_level: rule.risk_level,
                    message,
                    explanation: explanation.cloned(),
                });
            }
        }
    }
}

/// Is `path` a leaf among `all_each_paths` — i.e., does no other
/// path in the set start with `path` followed by a descent
/// separator (either `.` for array-index / field descent, or `@` for
/// the `any_of[N]` arm marker the compiler emits)?
///
/// Used by [`emit_for_match`]'s `PerWitness` branch to collapse
/// chained `each:` candidates onto their innermost finding. The
/// outer-scope `each:` and the inner finding-level `each:` both tag
/// their matches as `from_each: true`, but only the inner one points
/// at the specific bug span — the outer is context. Filtering to
/// paths with no longer-prefixed sibling drops the context candidates.
///
/// Both `.` AND `@` separators must be considered: when a rule uses
/// `each: ... any_of: [each: ...]` the compiler inserts `@any_of[N]`
/// directly after the parent path without a leading `.`, so checking
/// `.`-prefix alone wrongly treats the outer `each:` candidate as a
/// leaf and emits a duplicate signal anchored at its (outer) span.
fn is_leaf_each_path(path: &str, all_each_paths: &[&str]) -> bool {
    let dot_prefix = format!("{}.", path);
    let any_of_prefix = format!("{}@", path);
    !all_each_paths.iter().any(|other| {
        *other != path && (other.starts_with(&dot_prefix) || other.starts_with(&any_of_prefix))
    })
}

/// Project the engine-internal [`WitnessCandidate`] onto the public
/// schema-stable [`FactWitness`]. Drops engine-only bookkeeping
/// (`from_each`) so it never reaches the customer surface — the
/// boundary where internal evaluation state ends and the public
/// `Signal` payload begins.
fn project_witness(candidate: &WitnessCandidate) -> FactWitness {
    FactWitness {
        path: candidate.path.clone(),
        value: candidate.value.clone(),
    }
}

fn render_message(
    rule: &Rule,
    facts_value: &serde_json::Value,
    witness: Option<&serde_json::Value>,
) -> String {
    match &rule.message_template {
        Some(tmpl) => tmpl.render(facts_value, witness),
        None => rule.description.clone(),
    }
}

fn signal_span(
    facts_value: &serde_json::Value,
    first_candidate: Option<&WitnessCandidate>,
) -> Option<Span> {
    if let Some(c) = first_candidate {
        if let Some(sp) = extract_span(&c.value) {
            return Some(sp);
        }
    }
    extract_span(facts_value)
}

fn extract_span(v: &serde_json::Value) -> Option<Span> {
    let obj = v.as_object()?;
    let span_val = obj.get("source_span")?;
    if span_val.is_null() {
        return None;
    }
    let map = span_val.as_object()?;
    let start = map.get("start")?.as_u64()? as u32;
    let end = map.get("end")?.as_u64()? as u32;
    Some(Span { start, end })
}

// ─────────────────────────────────────────────────────────────────────
// Template rendering — `{path.to.field}` interpolation.
// ─────────────────────────────────────────────────────────────────────

fn render_template(
    raw: &str,
    facts_value: &serde_json::Value,
    witness: Option<&serde_json::Value>,
) -> String {
    let mut out = String::with_capacity(raw.len());
    let bytes = raw.as_bytes();
    let mut i = 0;
    let mut literal_start = 0; // start of the pending literal run
    while i < bytes.len() {
        // `{`/`}` are ASCII, so they never collide with a UTF-8
        // lead/continuation byte — byte-scanning is safe and every
        // slice index below lands on a char boundary.
        if bytes[i] == b'{' {
            // Find matching `}`. No nested braces in v1.
            if let Some(end) = raw[i + 1..].find('}') {
                // Flush literal text verbatim (preserves multi-byte UTF-8).
                out.push_str(&raw[literal_start..i]);
                let path_str = &raw[i + 1..i + 1 + end];
                let resolved = resolve(facts_value, witness, path_str);
                out.push_str(&render_value(resolved.as_ref()));
                i += end + 2;
                literal_start = i;
                continue;
            }
        }
        i += 1;
    }
    out.push_str(&raw[literal_start..]);
    out
}

fn resolve<'a>(
    facts: &'a serde_json::Value,
    witness: Option<&'a serde_json::Value>,
    path: &str,
) -> Option<serde_json::Value> {
    let mut segments = path.split('.');
    let head = segments.next()?;
    let mut current: &serde_json::Value = if head == "witness" {
        witness?
    } else {
        facts.get(head)?
    };
    for seg in segments {
        if let Ok(idx) = seg.parse::<usize>() {
            current = current.as_array().and_then(|a| a.get(idx))?;
        } else {
            current = current.as_object().and_then(|m| m.get(seg))?;
        }
    }
    Some(current.clone())
}

fn render_value(v: Option<&serde_json::Value>) -> String {
    match v {
        None => String::new(),
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(serde_json::Value::Number(n)) => n.to_string(),
        Some(serde_json::Value::Bool(b)) => b.to_string(),
        Some(serde_json::Value::Null) => String::new(),
        Some(other) => serde_json::to_string(other).unwrap_or_default(),
    }
}

// ─────────────────────────────────────────────────────────────────────
// Used externally — re-export so callers see one engine surface.
// ─────────────────────────────────────────────────────────────────────

pub use super::signal::Signal as EngineSignal;

#[allow(dead_code)]
fn _ru_explanation_smoke(_e: RuleExplanation) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facts::{AlgebraFacts, ScriptContext, StatementFacts, StatementKind};
    use crate::rules::compile::compile;
    use crate::rules::predicate::parse_predicate;

    fn empty_facts(kind: StatementKind) -> StatementFacts {
        StatementFacts {
            kind,
            source_span: None,
            query: None,
            ddl: None,
            privilege: None,
            policy: None,
            integration: None,
            policy_attachment: None,
            use_stmt: None,
            pg_copy: None,

            mssql_backup: None,

            mssql_restore: None,
            mssql_dbcc: None,
            mssql_key_management: None,
            mssql_security_policy: None,
            mssql_key_backup: None,
            mssql_assembly: None,
            mssql_add_signature: None,
            mssql_service_master_key: None,
            pg_default_privileges: None,
            comment: None,
            handler: None,
            mssql_exec: None,
            impersonation: None,
            audit: None,
            security_object: None,
            execute_immediate_from: None,
            dynamic_sql_calls: Vec::new(),
            algebra: AlgebraFacts::default(),
            script_context: ScriptContext::default(),
            diff: None,
        }
    }

    fn rule(id: &str, yaml: &str) -> Rule {
        let val: serde_json::Value = serde_yaml_ng::from_str(yaml).expect("yaml parses");
        let parsed = parse_predicate(&val).expect("predicate parses");
        let compiled = compile(&parsed).expect("predicate compiles");
        Rule {
            id: id.to_string(),
            former_ids: Vec::new(),
            description: format!("test rule {}", id),
            risk_level: RiskLevel::High,
            enabled: true,
            triggers: compiled,
            message_template: None,
            emission: EmissionMode::Once,
            per_statement: false,
        }
    }

    #[test]
    fn rule_fires_on_match() {
        let facts = empty_facts(StatementKind::Grant);
        let r = rule("R1", "kind: grant");
        let signals = evaluate_rules(&facts, &[r]);
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].rule_id, "R1");
    }

    #[test]
    fn disabled_rule_does_not_fire() {
        let facts = empty_facts(StatementKind::Grant);
        let mut r = rule("R1", "kind: grant");
        r.enabled = false;
        assert!(evaluate_rules(&facts, &[r]).is_empty());
    }

    #[test]
    fn rule_does_not_fire_on_mismatch() {
        let facts = empty_facts(StatementKind::Select);
        let r = rule("R1", "kind: grant");
        assert!(evaluate_rules(&facts, &[r]).is_empty());
    }

    #[test]
    fn template_renders_facts_path() {
        let facts = empty_facts(StatementKind::Grant);
        let mut r = rule("R1", "kind: grant");
        r.message_template = Some(MessageTemplate::new("statement: {kind}"));
        let signals = evaluate_rules(&facts, &[r]);
        assert_eq!(signals[0].message, "statement: grant");
    }

    #[test]
    fn template_preserves_multibyte_utf8() {
        // Regression: literal runs were copied byte-by-byte as `char`,
        // Latin-1-re-encoding multi-byte UTF-8 (em-dash e2 80 94 became
        // the mojibake c3 a2 c2 80 c2 94).
        let facts = empty_facts(StatementKind::Grant);
        let mut r = rule("R1", "kind: grant");
        let msg = "risk — “quoted” café";
        r.message_template = Some(MessageTemplate::new(msg));
        let signals = evaluate_rules(&facts, &[r]);
        assert_eq!(signals[0].message, msg);
    }

    #[test]
    fn template_preserves_utf8_around_placeholder() {
        // Multi-byte literals on both sides of a `{}` placeholder must
        // survive the literal-run flush byte-exact.
        let facts = empty_facts(StatementKind::Grant);
        let mut r = rule("R1", "kind: grant");
        r.message_template = Some(MessageTemplate::new("café — {kind} — ☕"));
        let signals = evaluate_rules(&facts, &[r]);
        assert_eq!(signals[0].message, "café — grant — ☕");
    }

    // ─────────────────────────────────────────────────────────────────
    // Leaf-each filter
    // ─────────────────────────────────────────────────────────────────

    #[test]
    fn is_leaf_each_path_drops_prefix_paths() {
        // Chained each:: outer scope "query.scopes.0" is a prefix of
        // inner window "query.scopes.0.window_functions.0", so the
        // outer is dropped as context and the inner survives as a
        // leaf finding.
        let paths = vec![
            "query.scopes.0",
            "query.scopes.0.window_functions.0",
            "query.scopes.0.window_functions.1",
            "query.scopes.1",
            "query.scopes.1.window_functions.0",
        ];
        assert!(!is_leaf_each_path("query.scopes.0", &paths));
        assert!(!is_leaf_each_path("query.scopes.1", &paths));
        assert!(is_leaf_each_path(
            "query.scopes.0.window_functions.0",
            &paths
        ));
        assert!(is_leaf_each_path(
            "query.scopes.0.window_functions.1",
            &paths
        ));
        assert!(is_leaf_each_path(
            "query.scopes.1.window_functions.0",
            &paths
        ));
    }

    #[test]
    fn is_leaf_each_path_single_level_all_leaves() {
        let paths = vec!["diff.events.0", "diff.events.1", "diff.events.2"];
        for p in &paths {
            assert!(is_leaf_each_path(p, &paths));
        }
    }

    #[test]
    fn is_leaf_each_path_handles_prefix_collision() {
        // "x.10" is NOT a child of "x.1" (the separator check needs
        // the `.` to follow the prefix). Both are leaves.
        let paths = vec!["x.1", "x.10", "x.100"];
        for p in &paths {
            assert!(is_leaf_each_path(p, &paths));
        }
    }

    // ─────────────────────────────────────────────────────────────────
    // Explain-mode end-to-end.
    // ─────────────────────────────────────────────────────────────────

    #[test]
    fn evaluate_rules_with_explain_reports_match_and_rejection() {
        let facts = empty_facts(StatementKind::Grant);
        let rules = vec![
            rule("MATCH", "kind: grant"),
            rule("REJECT", "kind: select"),
            rule("PATH_GONE", "query.has_where: false"),
        ];
        let results = evaluate_rules_with_explain(&facts, &rules);
        assert_eq!(results.len(), 3);

        let matched = results.iter().find(|r| r.rule_id == "MATCH").unwrap();
        assert!(matched.matched);
        assert_eq!(matched.signals.len(), 1);
        assert_eq!(matched.signals[0].rule_id, "MATCH");
        // Signal carries the explanation populated by the engine.
        assert!(matched.signals[0].explanation.is_some());

        let rejected = results.iter().find(|r| r.rule_id == "REJECT").unwrap();
        assert!(!rejected.matched);
        assert!(rejected.signals.is_empty());
        assert!(rejected
            .explanation
            .unmatched_paths
            .iter()
            .any(|e| e.contains("\"grant\"") && e.contains("\"select\"")));

        let path_gone = results.iter().find(|r| r.rule_id == "PATH_GONE").unwrap();
        assert!(!path_gone.matched);
        assert!(path_gone
            .explanation
            .unmatched_paths
            .iter()
            .any(|e| e.contains("path did not resolve")));
    }

    #[test]
    fn evaluate_rules_skips_disabled_in_explain_mode() {
        let facts = empty_facts(StatementKind::Grant);
        let mut r = rule("DISABLED", "kind: grant");
        r.enabled = false;
        let results = evaluate_rules_with_explain(&facts, &[r]);
        assert!(results.is_empty());
    }

    #[test]
    fn signal_explanation_only_populated_in_explain_mode() {
        let facts = empty_facts(StatementKind::Grant);
        let r = rule("X", "kind: grant");
        // Hot-path entry point never sets explanation.
        let signals = evaluate_rules(&facts, &[r.clone()]);
        assert_eq!(signals.len(), 1);
        assert!(signals[0].explanation.is_none());
        // Explain-mode entry point sets it.
        let results = evaluate_rules_with_explain(&facts, &[r]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].signals.len(), 1);
        assert!(results[0].signals[0].explanation.is_some());
    }

    /// Parity guarantee for the fact-family dispatch index: across the
    /// full builtin corpus over a broad statement battery, every rule
    /// the index SKIPS must genuinely be `NoMatch`. If this holds, the
    /// indexed hot path emits exactly the signals the unindexed path
    /// would — skipping never drops a finding.
    /// Collect real `StatementFacts` across fact families by running each
    /// family driver (with fact capture) over a broad statement battery.
    /// Shared by the family-mask and kind-gate dispatch parity tests so
    /// both attack the same corpus with no second-source drift.
    fn collect_battery_facts() -> Vec<StatementFacts> {
        let corpus = crate::rules::all_builtin_rules().expect("builtin corpus loads");

        // (sql, dialect-name) battery spanning the fact families. Each
        // family driver pushes the facts for the statements it handles.
        let battery: &[(&str, &str)] = &[
            // privilege
            ("GRANT ALL PRIVILEGES ON DATABASE db TO ROLE r", "snowflake"),
            ("GRANT SELECT ON t TO PUBLIC", "snowflake"),
            ("REVOKE OWNERSHIP ON TABLE t FROM ROLE r", "snowflake"),
            ("GRANT ROLE admin TO USER u", "snowflake"),
            // query
            ("SELECT * FROM t WHERE 1=1", "snowflake"),
            ("SELECT a, (SELECT max(x) FROM s WHERE s.id=t.id) FROM t", "snowflake"),
            ("INSERT INTO t SELECT * FROM staging", "snowflake"),
            ("UPDATE t SET a=1 WHERE b IS NULL", "snowflake"),
            ("DELETE FROM t", "snowflake"),
            (
                "MERGE INTO t USING s ON t.id=s.id WHEN MATCHED THEN UPDATE SET t.a=s.a",
                "snowflake",
            ),
            (
                "SELECT row_number() OVER (PARTITION BY a ORDER BY b) FROM t",
                "snowflake",
            ),
            // ddl: table / view / db / schema / warehouse
            ("CREATE TABLE t (a INT, b STRING)", "snowflake"),
            ("ALTER TABLE t ADD COLUMN c INT", "snowflake"),
            ("DROP TABLE t", "snowflake"),
            ("TRUNCATE TABLE t", "snowflake"),
            ("CREATE VIEW v AS SELECT * FROM t", "snowflake"),
            ("CREATE DATABASE d", "snowflake"),
            ("CREATE SCHEMA s", "snowflake"),
            ("CREATE WAREHOUSE w WITH WAREHOUSE_SIZE='XSMALL'", "snowflake"),
            ("CREATE STAGE st URL='s3://bucket/'", "snowflake"),
            ("CREATE STREAM strm ON TABLE t", "snowflake"),
            (
                "CREATE TASK tk WAREHOUSE=w SCHEDULE='1 minute' AS SELECT 1",
                "snowflake",
            ),
            // ddl: procedure / function with dynamic SQL inside
            (
                "CREATE PROCEDURE p() RETURNS STRING LANGUAGE SQL AS $$ BEGIN EXECUTE IMMEDIATE 'DROP TABLE ' || x; END $$",
                "snowflake",
            ),
            (
                "CREATE FUNCTION f(a INT) RETURNS INT AS $$ a+1 $$",
                "snowflake",
            ),
            // comment / use
            ("COMMENT ON TABLE t IS 'hi'", "snowflake"),
            ("USE ROLE accountadmin", "snowflake"),
            // policy
            (
                "CREATE MASKING POLICY m AS (v STRING) RETURNS STRING -> v",
                "snowflake",
            ),
            // mssql exec / dynamic sql
            ("EXEC xp_cmdshell 'dir'", "mssql"),
            ("EXEC sp_executesql @sql", "mssql"),
            (
                "CREATE PROCEDURE dbo.p @r NVARCHAR(200) AS BEGIN EXEC('SELECT '+@r); END",
                "mssql",
            ),
            // postgres copy
            ("COPY t FROM '/tmp/x.csv'", "postgresql"),
            // policy DDL + a bq model statement so the largest In-list kind
            // gates are exercised on a MATCHING kind, not only skipped.
            (
                "CREATE PASSWORD POLICY pp PASSWORD_MIN_LENGTH = 10",
                "snowflake",
            ),
            ("CREATE MODEL m OPTIONS(model_type='linear_reg') AS SELECT 1", "bigquery"),
        ];

        let mut all_facts: Vec<StatementFacts> = Vec::new();
        for (sql, dname) in battery {
            let dialect = crate::dialect::dialect_from_name(dname);
            let script = match &dialect {
                Some(d) => crate::parse_sql_with_dialect(sql, d.as_ref()),
                None => crate::parse_sql(sql),
            };
            let Ok(script) = script else { continue };
            // Run every family driver with a retaining fact sink; each
            // records facts only for the statements it recognizes.
            let fold = crate::build_script_context_fold(&script, sql);
            let reasoning = crate::facts::reasoning::RecognitionOnly;
            let mut script_reasoning = crate::facts::reasoning::Reasoning::for_script(
                &reasoning,
                crate::facts::reasoning::ScriptInputs {
                    script: &script,
                    source: sql,
                    dialect_name: dname,
                    fold: &fold,
                    catalog: None,
                    model_catalog: None,
                },
            );
            let mut metrics = crate::analyzer::MetricsCollector::new();
            let mut sink = crate::StatementFactsSink::new(&mut metrics, &[], true);
            let _ = crate::evaluate_ddl_rules_for_script(
                &script,
                sql,
                &fold,
                corpus,
                &reasoning,
                script_reasoning.as_ref(),
                Some(&mut sink),
                None,
            );
            let _ = crate::evaluate_query_rules_for_script(
                &script,
                sql,
                &fold,
                None,
                None,
                corpus,
                &reasoning,
                script_reasoning.as_mut(),
                Some(&mut sink),
                None,
            );
            let _ = crate::evaluate_privilege_rules_for_script(
                &script,
                sql,
                &fold,
                None,
                corpus,
                &reasoning,
                Some(&mut sink),
                None,
            );
            let _ = crate::evaluate_policy_attachment_rules_for_script(
                &script,
                sql,
                &fold,
                corpus,
                Some(&mut sink),
                None,
            );
            let (_, retained, _) = sink.finish();
            all_facts.extend(retained.unwrap_or_default());
        }
        all_facts
    }

    /// Parity guarantee for the fact-family dispatch mask: across the full
    /// builtin corpus over the battery, every rule the family mask SKIPS
    /// must genuinely be `NoMatch` — skipping never drops a finding.
    #[test]
    fn dispatch_index_never_skips_a_matching_rule() {
        use crate::rules::compile::facts_present_mask;

        let corpus = crate::rules::all_builtin_rules().expect("builtin corpus loads");
        let all_facts = collect_battery_facts();
        assert!(!all_facts.is_empty(), "battery collected no facts");

        let mut skips = 0usize;
        for facts in &all_facts {
            let value = serde_json::to_value(facts).unwrap_or(serde_json::Value::Null);
            let present = facts_present_mask(&value);
            for rule in corpus {
                if !rule.enabled {
                    continue;
                }
                let mask = rule.triggers.root_mask();
                if mask != 0 && mask & present == 0 {
                    skips += 1;
                    assert_eq!(
                        rule.triggers.evaluate_value(&value),
                        EvalResult::NoMatch,
                        "rule {} skipped by family mask but matches \
                         (root_mask={:#x} present_mask={:#x})",
                        rule.id,
                        mask,
                        present,
                    );
                }
            }
        }
        assert!(skips > 0, "battery exercised no family-mask skips");
    }

    /// Parity guarantee for the statement-kind dispatch gate: every rule
    /// the kind gate SKIPS for a statement must genuinely be `NoMatch` on
    /// it. This is the soundness invariant, pinned against the real corpus.
    #[test]
    fn kind_gate_never_skips_a_matching_rule() {
        let corpus = crate::rules::all_builtin_rules().expect("builtin corpus loads");
        let all_facts = collect_battery_facts();
        assert!(!all_facts.is_empty(), "battery collected no facts");

        let mut kind_skips = 0usize;
        for facts in &all_facts {
            let value = serde_json::to_value(facts).unwrap_or(serde_json::Value::Null);
            let kind_idx = facts.kind as usize;
            for rule in corpus {
                if !rule.enabled {
                    continue;
                }
                if rule.triggers.kind_gate().skips(kind_idx) {
                    kind_skips += 1;
                    assert_eq!(
                        rule.triggers.evaluate_value(&value),
                        EvalResult::NoMatch,
                        "rule {} skipped by kind gate but matches (kind={:?})",
                        rule.id,
                        facts.kind,
                    );
                }
            }
        }
        assert!(kind_skips > 0, "battery exercised no kind-gate skips");
    }

    /// The two dispatch indices must compose: a rule skipped by EITHER the
    /// family mask OR the kind gate (the hot-path skip predicate) must be
    /// `NoMatch` on that statement.
    #[test]
    fn combined_dispatch_skip_implies_no_match() {
        use crate::rules::compile::facts_present_mask;

        let corpus = crate::rules::all_builtin_rules().expect("builtin corpus loads");
        let all_facts = collect_battery_facts();

        for facts in &all_facts {
            let value = serde_json::to_value(facts).unwrap_or(serde_json::Value::Null);
            let present = facts_present_mask(&value);
            let kind_idx = facts.kind as usize;
            for rule in corpus {
                if !rule.enabled {
                    continue;
                }
                let mask = rule.triggers.root_mask();
                let family_skip = mask != 0 && mask & present == 0;
                let kind_skip = rule.triggers.kind_gate().skips(kind_idx);
                if family_skip || kind_skip {
                    assert_eq!(
                        rule.triggers.evaluate_value(&value),
                        EvalResult::NoMatch,
                        "rule {} skipped (family={family_skip} kind={kind_skip}) but matches",
                        rule.id,
                    );
                }
            }
        }
    }

    /// The kind gate must skip in the hot path but NOT in explain mode —
    /// explain must still evaluate every enabled rule so callers see why a
    /// non-firing rule didn't fire.
    #[test]
    fn kind_gate_skip_stays_out_of_explain_mode() {
        let facts = empty_facts(StatementKind::Select);
        // gate Only({Grant}) — skipped on a Select statement in the hot path.
        let r = rule("X", "kind: grant");

        assert!(
            evaluate_rules(&facts, std::slice::from_ref(&r)).is_empty(),
            "hot path must skip a kind-gated rule"
        );

        let evaluated = evaluate_rules_with_explain(&facts, std::slice::from_ref(&r));
        assert_eq!(
            evaluated.len(),
            1,
            "explain mode must still evaluate the kind-gated rule"
        );
        assert!(!evaluated[0].matched);
    }
}
