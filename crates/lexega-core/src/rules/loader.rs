// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Loader for v1 fact-based YAML rule files.
//!
//! Two entries share one schema: the built-in file, whose `lists:` are
//! the built-in lists, and customer rule files, whose `lists:` define,
//! extend or replace lists over the built-in ones. Built-ins are always
//! **full** rules; the customer YAML may additionally contain **partial
//! overrides** that re-state a built-in `id` with a different
//! `risk_level` / `message` / `enabled` flag and inherit `triggers` from
//! the built-in.
//!
//! YAML schema:
//!
//! ```yaml
//! rules:
//!   # Full rule — `triggers` present. May create a brand-new rule or
//!   # wholly replace a built-in with the same id.
//!   - id: <stable-id>
//!     risk_level: high
//!     message: "..."
//!     triggers:
//!       <predicate>
//!     enabled: true        # optional; default true
//!     emission: once       # optional; default derived from triggers
//!
//!   # Partial override — `triggers` absent. Must match a built-in `id`
//!   # at merge time. May set any of `risk_level` / `message` / `enabled`.
//!   - id: <existing-builtin-id>
//!     risk_level: low
//! ```
//!
//! Classification & validation happens here at load time; merging the
//! resulting [`LoadedRuleset`] against the built-in corpus happens in
//! [`crate::rules::build_v1_rule_corpus`].

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use crate::facts::RiskLevel;

use super::builtin_rules::{
    builtin_corpus_json, builtin_list_rule_ids, builtin_lists, canonical_rule_id,
};
use super::compile::{compile_with_lists, CompileError};
use super::engine::{MessageTemplate, Rule};
use super::finding::EmissionMode;
use super::lists::{apply_file_lists, define_builtin_lists, ListChanges, ValueLists};
use super::predicate::{names_a_list, parse_predicate, Predicate, Quantifier, RelationalMatch};
use super::schema::{MaskingPolicy, V1ListEntry, V1Lists, V1RuleEntry, V1RulesFile};

/// Typed error for v1 rule-file load failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadError {
    /// Top-level YAML syntax / shape error.
    Yaml(String),
    /// Top-level syntax / shape error deserializing a rule file in JSON
    /// form, the build-time precompiled built-in corpus included.
    Json(String),
    /// Top-level syntax / shape error deserializing a rule file in TOML
    /// form.
    Toml(String),
    /// `triggers:` predicate could not be parsed for the named rule.
    PredicateParse { rule_id: String, message: String },
    /// `triggers:` predicate parsed but failed to compile to a closure.
    PredicateCompile { rule_id: String, message: String },
    /// Two rule entries share the same `id`.
    DuplicateRuleId(String),
    /// Entry has `triggers` (so it's a full rule definition) but is
    /// missing one of the other required full-rule fields. The
    /// `missing_field` is one of `"risk_level"` or `"message"`.
    IncompleteFullRule {
        rule_id: String,
        missing_field: &'static str,
    },
    /// Entry has no `triggers` (so it's a partial override) but sets
    /// one of the fields that partial overrides are not allowed to
    /// touch: `emission` or `per_statement`. `triggers` itself is
    /// classified out of this variant — its presence makes the entry
    /// Full, not Partial.
    DisallowedFieldOnPartialOverride {
        rule_id: String,
        field: &'static str,
    },
    /// Partial override entry that sets none of the override-able
    /// fields (`risk_level`, `message`, `enabled`). A pure `id`-only
    /// entry is a no-op restate of the built-in and almost certainly a
    /// typo for either a full rule (forgot the body) or an intended
    /// override (forgot the field).
    EmptyPartialOverride { rule_id: String },
    /// A partial override (no `triggers`) declared `former_ids`.
    /// Deprecated-id aliases belong to a rule's canonical definition,
    /// not to an override of it.
    FormerIdsOnPartialOverride { rule_id: String },
    /// A `former_ids` entry duplicates a live rule `id`. A deprecated id
    /// must not shadow a rule that is still active, or a reference would
    /// be ambiguous.
    FormerIdCollidesWithLiveId { former_id: String, rule_id: String },
    /// Two rules claim the same `former_ids` entry — a deprecated id can
    /// only resolve to one canonical rule.
    DuplicateFormerId { former_id: String },
    /// `extend` or `replace` named a list no built-in list defines.
    UnknownBuiltinList { list: String },
    /// A list entry defines a name a built-in list already holds.
    RedefinedBuiltinList { list: String },
    /// A list's `values` or `patterns` holds an item that is not a string.
    ListValueNotString {
        list: String,
        field: ListField,
        value: String,
    },
    /// A list entry is not exactly one of a definition, `extend`, `replace`.
    ListEntryShape {
        list: String,
        problem: ListShapeProblem,
    },
    /// A list pattern is empty or made only of `*`.
    InvalidListPattern { list: String, pattern: String },
    /// A list name appears twice under `lists:`.
    DuplicateList { list: String },
    /// A rule's `in_list` / `not_in_list` names a list that does not exist.
    UnknownList { rule_id: String, list: String },
    /// The file has neither `rules:` nor `lists:`; a mistyped top-level
    /// key would otherwise load as an empty file.
    NoRulesOrLists,
    /// The built-in rule corpus, whose lists a customer file builds on,
    /// failed to load.
    BuiltinCorpus(Box<LoadError>),
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Yaml(msg) => write!(f, "rule file yaml error: {}", msg),
            Self::Json(msg) => write!(f, "rule file json error: {}", msg),
            Self::Toml(msg) => write!(f, "rule file toml error: {}", msg),
            Self::PredicateParse { rule_id, message } => write!(
                f,
                "rule '{}': triggers predicate parse error: {}",
                rule_id, message
            ),
            Self::PredicateCompile { rule_id, message } => write!(
                f,
                "rule '{}': triggers predicate compile error: {}",
                rule_id, message
            ),
            Self::DuplicateRuleId(id) => write!(f, "duplicate rule id: '{}'", id),
            Self::IncompleteFullRule {
                rule_id,
                missing_field,
            } => write!(
                f,
                "rule '{}': has `triggers` (full rule shape) but is missing required field `{}`",
                rule_id, missing_field
            ),
            Self::DisallowedFieldOnPartialOverride { rule_id, field } => write!(
                f,
                "rule '{}': partial override (no `triggers`) cannot set `{}` — partial overrides may only set `risk_level`, `message`, and `enabled`",
                rule_id, field
            ),
            Self::EmptyPartialOverride { rule_id } => write!(
                f,
                "rule '{}': partial override sets none of `risk_level`, `message`, `enabled` — nothing to override",
                rule_id
            ),
            Self::FormerIdsOnPartialOverride { rule_id } => write!(
                f,
                "rule '{}': partial override (no `triggers`) cannot set `former_ids` — deprecated-id aliases belong to the canonical rule definition",
                rule_id
            ),
            Self::FormerIdCollidesWithLiveId { former_id, rule_id } => write!(
                f,
                "rule '{}': former id '{}' collides with a live rule id",
                rule_id, former_id
            ),
            Self::DuplicateFormerId { former_id } => {
                write!(f, "former id '{}' is claimed by more than one rule", former_id)
            }
            Self::UnknownBuiltinList { list } => write!(
                f,
                "list '{}': `extend` and `replace` need a built-in list of that name",
                list
            ),
            Self::RedefinedBuiltinList { list } => write!(
                f,
                "list '{}' is a built-in list: use `extend` or `replace`; a copied built-in rule file must drop its `lists:`",
                list
            ),
            Self::ListValueNotString { list, field, value } => write!(
                f,
                "list '{}': `{}` items must be quoted strings, found {}",
                list, field, value
            ),
            Self::ListEntryShape { list, problem } => {
                write!(f, "list '{}' {}", list, problem)
            }
            Self::DuplicateList { list } => write!(f, "list '{}' is declared twice", list),
            Self::UnknownList { rule_id, list } => {
                write!(f, "rule '{}': unknown list '{}'", rule_id, list)
            }
            Self::NoRulesOrLists => {
                f.write_str("rule file has none of `rules:`, `lists:` or `masking:`")
            }
            Self::BuiltinCorpus(err) => {
                write!(f, "built-in rule corpus failed to load: {}", err)
            }
            Self::InvalidListPattern { list, pattern } => write!(
                f,
                "list '{}': pattern '{}' is empty or matches every value",
                list, pattern
            ),
        }
    }
}

impl std::error::Error for LoadError {}

/// Which item list of a list entry an error is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListField {
    Values,
    Patterns,
}

impl std::fmt::Display for ListField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Values => "values",
            Self::Patterns => "patterns",
        })
    }
}

/// How a list entry fails to be exactly one definition, `extend` or `replace`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListShapeProblem {
    /// More than one of definition, `extend`, `replace`.
    MoreThanOne,
    /// A definition or `extend` with no values and no patterns.
    NoEntries,
    /// `extend` or `replace` where only definitions are allowed.
    NotADefinition,
}

impl std::fmt::Display for ListShapeProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MoreThanOne => {
                f.write_str("holds more than one of a definition, `extend` and `replace`")
            }
            Self::NoEntries => f.write_str("has no values and no patterns"),
            Self::NotADefinition => f.write_str("must define `values` and/or `patterns`"),
        }
    }
}

/// A partial override of a built-in rule. Holds only the override-able
/// fields the customer YAML provided; whichever fields are `None` are
/// inherited from the built-in at merge time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialRuleOverride {
    /// Must match a built-in rule's `id` at merge time.
    pub id: String,
    /// New severity, or `None` to inherit the built-in's.
    pub risk_level: Option<RiskLevel>,
    /// New customer-facing message, or `None` to inherit.
    pub message: Option<String>,
    /// New enabled flag, or `None` to inherit. Set to `Some(false)` to
    /// suppress a built-in via the override path.
    pub enabled: Option<bool>,
}

/// One classified entry from a loaded rule YAML.
#[derive(Debug, Clone)]
pub enum LoadedEntry {
    /// A fully-specified rule. May still override a built-in with the
    /// same `id` (whole-rule replacement, last-write-wins).
    Full(Rule),
    /// A partial override that inherits the built-in's `triggers` (and
    /// other engine-shape fields) and only changes severity / message /
    /// enabled.
    Partial(PartialRuleOverride),
}

impl LoadedEntry {
    /// The id this entry will merge against.
    pub fn id(&self) -> &str {
        match self {
            Self::Full(r) => &r.id,
            Self::Partial(p) => &p.id,
        }
    }
}

/// A file entry that names an id a built-in rule was published under
/// before; the entry applies to the rule that absorbed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormerIdOverride {
    /// The id as the file writes it.
    pub former_id: String,
    /// The built-in rule's current id.
    pub canonical_id: String,
}

/// The entries of `entries` that name a former id, in order.
fn former_id_overrides(entries: &[LoadedEntry]) -> Vec<FormerIdOverride> {
    entries
        .iter()
        .filter_map(|entry| {
            let canonical = canonical_rule_id(entry.id());
            (canonical != entry.id()).then(|| FormerIdOverride {
                former_id: entry.id().to_string(),
                canonical_id: canonical.to_string(),
            })
        })
        .collect()
}

/// Parsed-and-classified rule file. Each entry is either a full rule
/// or a partial override that requires resolution against the built-in
/// corpus. See [`crate::rules::build_v1_rule_corpus`].
#[derive(Debug, Clone, Default)]
pub struct LoadedRuleset {
    entries: Vec<LoadedEntry>,
    lists: ValueLists,
    list_changes: ListChanges,
    former_id_overrides: Vec<FormerIdOverride>,
    masking: MaskingPolicy,
}

impl LoadedRuleset {
    /// Construct a ruleset from already-materialized full rules. Used
    /// by callers that hold `Vec<Rule>` (e.g. in-process integrations)
    /// and want to feed them through [`crate::rules::build_v1_rule_corpus`]
    /// alongside built-ins. The ruleset takes no list table and never
    /// changes a list.
    pub fn from_full_rules(rules: Vec<Rule>) -> Self {
        let entries: Vec<LoadedEntry> = rules.into_iter().map(LoadedEntry::Full).collect();
        Self {
            former_id_overrides: former_id_overrides(&entries),
            entries,
            ..Self::default()
        }
    }

    /// The lists a loaded file's rules resolved against: the built-in
    /// lists with the file's definitions, extensions and replacements
    /// applied. Empty for a ruleset built by [`Self::from_full_rules`]
    /// or `default()`.
    pub fn lists(&self) -> &ValueLists {
        &self.lists
    }

    /// The lists the file defined, and the built-in lists it changed.
    pub fn list_changes(&self) -> &ListChanges {
        &self.list_changes
    }

    /// True when the file extends or replaces a built-in list.
    pub fn changes_builtin_lists(&self) -> bool {
        !self.list_changes.changed_builtins.is_empty()
    }

    /// The entries that name a former id, in file order.
    pub fn former_id_overrides(&self) -> &[FormerIdOverride] {
        &self.former_id_overrides
    }

    /// The file's masking policy; empty where it states none.
    pub fn masking(&self) -> &MaskingPolicy {
        &self.masking
    }

    pub fn entries(&self) -> &[LoadedEntry] {
        &self.entries
    }

    pub fn into_entries(self) -> Vec<LoadedEntry> {
        self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Materialize this ruleset as `Vec<Rule>`, rejecting any partial
    /// overrides.
    pub fn into_strict_rules(self) -> Result<Vec<Rule>, LoadError> {
        strict_rules(self.entries)
    }
}

/// The entries as full rules; a partial override is an error.
fn strict_rules(entries: Vec<LoadedEntry>) -> Result<Vec<Rule>, LoadError> {
    entries
        .into_iter()
        .map(|entry| match entry {
            LoadedEntry::Full(r) => Ok(r),
            LoadedEntry::Partial(p) => Err(LoadError::IncompleteFullRule {
                rule_id: p.id,
                missing_field: "triggers",
            }),
        })
        .collect()
}

/// The built-in rule file, loaded: its rules, its lists, and the ids
/// of the rules that name a list.
#[derive(Debug)]
pub(crate) struct BuiltinCorpus {
    pub(crate) rules: Vec<Rule>,
    pub(crate) lists: ValueLists,
    pub(crate) list_rule_ids: BTreeSet<String>,
}

/// Parse a v1 rule-file YAML string and produce a classified
/// [`LoadedRuleset`].
///
/// The file's rules resolve against the built-in lists with the file's
/// own `lists:` applied over them. The returned entries preserve source
/// order — rule evaluation order matches authoring order, which lets
/// customers reason about emission interleaving without consulting an
/// implicit sort key.
pub fn load_v1_rules(yaml: &str) -> Result<LoadedRuleset, LoadError> {
    build_ruleset_from_file(parse_yaml_file(yaml)?)
}

/// [`load_v1_rules`] for a rule file in JSON form.
pub fn load_v1_rules_from_json(json: &[u8]) -> Result<LoadedRuleset, LoadError> {
    build_ruleset_from_file(parse_json_file(json)?)
}

/// [`load_v1_rules`] for a rule file in TOML form: `[[rules]]` tables with
/// the same fields, `triggers` a nested table.
pub fn load_v1_rules_from_toml(text: &str) -> Result<LoadedRuleset, LoadError> {
    build_ruleset_from_file(parse_toml_file(text)?)
}

/// Load the built-in corpus from the build-time-precompiled JSON blob
/// (see `build.rs`). The built-in corpus is deserialized on every
/// process start, where YAML parsing dominated startup — so the corpus
/// is transcoded to JSON at build time and parsed from that blob at
/// runtime instead.
pub(crate) fn load_builtin_rules_json(json: &[u8]) -> Result<BuiltinCorpus, LoadError> {
    load_builtin_file(parse_json_file(json)?)
}

/// [`load_builtin_rules_json`] for the YAML source.
#[cfg(test)]
pub(crate) fn load_builtin_rules_yaml(yaml: &str) -> Result<BuiltinCorpus, LoadError> {
    load_builtin_file(parse_yaml_file(yaml)?)
}

/// The built-in rules that name a list, compiled against `lists`, by id.
pub(crate) fn recompile_builtin_list_rules(
    lists: &ValueLists,
) -> Result<HashMap<String, Rule>, LoadError> {
    recompile_list_rules(
        parse_json_file(builtin_corpus_json())?,
        builtin_list_rule_ids()?,
        lists,
    )
}

/// The full rules of `file` whose id is in `ids`, compiled against
/// `lists`, by id. Only a full rule names a list.
fn recompile_list_rules(
    file: V1RulesFile,
    ids: &BTreeSet<String>,
    lists: &ValueLists,
) -> Result<HashMap<String, Rule>, LoadError> {
    file.rules
        .into_iter()
        .flatten()
        .filter(|entry| ids.contains(&entry.id))
        .filter_map(|mut entry| {
            let triggers = entry.triggers.take()?;
            Some(classify_full(entry, triggers, lists).map(|(rule, _)| (rule.id.clone(), rule)))
        })
        .collect()
}

fn parse_yaml_file(yaml: &str) -> Result<V1RulesFile, LoadError> {
    serde_yaml_ng::from_str(yaml).map_err(|e| LoadError::Yaml(e.to_string()))
}

fn parse_json_file(json: &[u8]) -> Result<V1RulesFile, LoadError> {
    serde_json::from_slice(json).map_err(|e| LoadError::Json(e.to_string()))
}

fn parse_toml_file(text: &str) -> Result<V1RulesFile, LoadError> {
    toml::from_str(text).map_err(|e| LoadError::Toml(e.to_string()))
}

/// The file's rule entries, its list entries by name, and its masking
/// policy.
#[allow(clippy::type_complexity)] // the three parts a rule file holds
fn file_parts(
    file: V1RulesFile,
) -> Result<
    (
        Vec<V1RuleEntry>,
        BTreeMap<String, V1ListEntry>,
        MaskingPolicy,
    ),
    LoadError,
> {
    let V1RulesFile {
        lists,
        rules,
        masking,
    } = file;
    if rules.is_none() && lists.is_none() && masking.is_none() {
        return Err(LoadError::NoRulesOrLists);
    }
    let lists = lists.map(V1Lists::into_map).transpose()?;
    Ok((
        rules.unwrap_or_default(),
        lists.unwrap_or_default(),
        masking.unwrap_or_default(),
    ))
}

/// The built-in file: its own `lists:` are the built-in lists, so it
/// never reads the cached built-in table.
fn load_builtin_file(file: V1RulesFile) -> Result<BuiltinCorpus, LoadError> {
    let (rules, lists, _) = file_parts(file)?;
    let lists = define_builtin_lists(lists)?;
    let ClassifiedRules {
        entries,
        list_rule_ids,
    } = classify_rules(rules, &lists)?;
    Ok(BuiltinCorpus {
        rules: strict_rules(entries)?,
        lists,
        list_rule_ids,
    })
}

/// A customer file: the built-in lists, then the file's definitions,
/// extensions and replacements; its rules resolve against the result.
fn build_ruleset_from_file(file: V1RulesFile) -> Result<LoadedRuleset, LoadError> {
    let (rules, lists, masking) = file_parts(file)?;
    let builtin = builtin_lists().map_err(|e| LoadError::BuiltinCorpus(Box::new(e)))?;
    let (lists, list_changes) = apply_file_lists(builtin, lists)?;
    let entries = classify_rules(rules, &lists)?.entries;
    let former_id_overrides = former_id_overrides(&entries);
    Ok(LoadedRuleset {
        entries,
        lists,
        list_changes,
        former_id_overrides,
        masking,
    })
}

/// Classified entries, and the ids of the full rules that name a list.
struct ClassifiedRules {
    entries: Vec<LoadedEntry>,
    list_rule_ids: BTreeSet<String>,
}

/// Classify each entry (full rule vs partial override), compiling full
/// rules against `lists`, and enforce the id / former-id invariants.
fn classify_rules(
    rules: Vec<V1RuleEntry>,
    lists: &ValueLists,
) -> Result<ClassifiedRules, LoadError> {
    let mut seen_ids = HashSet::with_capacity(rules.len());
    let mut entries = Vec::with_capacity(rules.len());
    let mut list_rule_ids = BTreeSet::new();
    // (former_id, declaring_rule_id) — validated once every live id is
    // known, so a former id can be checked against the whole corpus.
    let mut former_claims: Vec<(String, String)> = Vec::new();

    for mut entry in rules {
        if !seen_ids.insert(entry.id.clone()) {
            return Err(LoadError::DuplicateRuleId(entry.id));
        }
        for former in &entry.former_ids {
            former_claims.push((former.clone(), entry.id.clone()));
        }

        // Classification is `triggers`-driven. Presence of `triggers`
        // means full rule (with the other required fields enforced
        // post-classification); absence means partial override.
        let loaded = match entry.triggers.take() {
            Some(triggers) => {
                let (rule, parsed) = classify_full(entry, triggers, lists)?;
                if names_a_list(&parsed) {
                    list_rule_ids.insert(rule.id.clone());
                }
                LoadedEntry::Full(rule)
            }
            None => {
                if !entry.former_ids.is_empty() {
                    return Err(LoadError::FormerIdsOnPartialOverride { rule_id: entry.id });
                }
                classify_partial(
                    entry.id,
                    entry.risk_level,
                    entry.message,
                    entry.enabled,
                    entry.emission,
                    entry.per_statement,
                )?
            }
        };
        entries.push(loaded);
    }

    // A former id may neither shadow a live rule id nor be claimed by two
    // rules — either would make a policy/exception reference ambiguous.
    let mut seen_formers = HashSet::with_capacity(former_claims.len());
    for (former, declaring) in former_claims {
        if seen_ids.contains(&former) {
            return Err(LoadError::FormerIdCollidesWithLiveId {
                former_id: former,
                rule_id: declaring,
            });
        }
        if !seen_formers.insert(former.clone()) {
            return Err(LoadError::DuplicateFormerId { former_id: former });
        }
    }

    Ok(ClassifiedRules {
        entries,
        list_rule_ids,
    })
}

/// A full rule (its `triggers` taken out of `entry`) compiled against
/// `lists`, with its parsed predicate.
fn classify_full(
    entry: V1RuleEntry,
    triggers: serde_json::Value,
    lists: &ValueLists,
) -> Result<(Rule, Predicate), LoadError> {
    let V1RuleEntry {
        id,
        former_ids,
        risk_level,
        message,
        enabled,
        emission,
        per_statement,
        triggers: _,
    } = entry;
    let risk_level = risk_level.ok_or_else(|| LoadError::IncompleteFullRule {
        rule_id: id.clone(),
        missing_field: "risk_level",
    })?;
    let message = message.ok_or_else(|| LoadError::IncompleteFullRule {
        rule_id: id.clone(),
        missing_field: "message",
    })?;

    let parsed = parse_predicate(&triggers).map_err(|e| LoadError::PredicateParse {
        rule_id: id.clone(),
        message: format!("{}", e),
    })?;
    let compiled = compile_with_lists(&parsed, lists).map_err(|e| match e {
        CompileError::UnknownList { list } => LoadError::UnknownList {
            rule_id: id.clone(),
            list,
        },
        CompileError::Parse(_)
        | CompileError::Internal(_)
        | CompileError::UnknownRootField { .. }
        | CompileError::UnknownStatementKind { .. } => LoadError::PredicateCompile {
            rule_id: id.clone(),
            message: format!("{}", e),
        },
    })?;

    // A rule containing an `each:` quantifier anywhere in its trigger
    // AST is per-witness by intent — the quantifier name IS the emission
    // decision. Honor an explicit `emission:` override if the rule
    // author set one; otherwise derive from the predicate shape.
    let resolved_emission = emission.unwrap_or_else(|| {
        if predicate_has_each_quantifier(&parsed) {
            EmissionMode::PerWitness
        } else {
            EmissionMode::Once
        }
    });

    let rule = Rule {
        id,
        former_ids,
        description: message.clone(),
        risk_level,
        enabled: enabled.unwrap_or(true),
        triggers: compiled,
        message_template: Some(MessageTemplate::new(message)),
        emission: resolved_emission,
        per_statement: per_statement.unwrap_or(false),
    };
    Ok((rule, parsed))
}

fn classify_partial(
    id: String,
    risk_level: Option<RiskLevel>,
    message: Option<String>,
    enabled: Option<bool>,
    emission: Option<EmissionMode>,
    per_statement: Option<bool>,
) -> Result<LoadedEntry, LoadError> {
    // Partial overrides can ONLY change severity / message / enabled.
    // Rejecting `emission` / `per_statement` at load time keeps the
    // semantics narrow: the built-in's predicate-shape decisions are
    // inherited verbatim. A customer who wants to change emission
    // semantics restates the full rule.
    if emission.is_some() {
        return Err(LoadError::DisallowedFieldOnPartialOverride {
            rule_id: id,
            field: "emission",
        });
    }
    if per_statement.is_some() {
        return Err(LoadError::DisallowedFieldOnPartialOverride {
            rule_id: id,
            field: "per_statement",
        });
    }
    if risk_level.is_none() && message.is_none() && enabled.is_none() {
        return Err(LoadError::EmptyPartialOverride { rule_id: id });
    }
    Ok(LoadedEntry::Partial(PartialRuleOverride {
        id,
        risk_level,
        message,
        enabled,
    }))
}

/// Walk the parsed predicate AST and return `true` if any
/// [`Quantifier::Each`] node is present. Used at load time to derive
/// the default emission mode: a rule whose trigger uses `each:`
/// somewhere intends per-witness emission, full stop. Customer rule
/// authors only need to choose the quantifier — the engine reads
/// emission semantics from that single decision.
fn predicate_has_each_quantifier(predicate: &Predicate) -> bool {
    match predicate {
        Predicate::AllOf(preds) | Predicate::AnyOf(preds) => {
            preds.iter().any(predicate_has_each_quantifier)
        }
        Predicate::Not(inner) => predicate_has_each_quantifier(inner),
        Predicate::Scalar(_) => false,
        Predicate::Relational(RelationalMatch { quantifier, .. }) => match quantifier {
            Quantifier::Each(_) => true,
            Quantifier::Exists(inner) | Quantifier::All(inner) | Quantifier::None(inner) => {
                predicate_has_each_quantifier(inner)
            }
            Quantifier::Count(_) => false,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn first_full_rule(rs: LoadedRuleset) -> Rule {
        match rs.into_entries().into_iter().next() {
            Some(LoadedEntry::Full(r)) => r,
            other => panic!("expected Full entry, got {:?}", other),
        }
    }

    #[test]
    fn loads_minimal_rule() {
        let yaml = r#"
rules:
  - id: TEST-1
    risk_level: high
    message: "test"
    triggers:
      kind: grant
"#;
        let rs = load_v1_rules(yaml).expect("loads");
        assert_eq!(rs.len(), 1);
        let rule = first_full_rule(rs);
        assert_eq!(rule.id, "TEST-1");
        assert!(rule.enabled);
        assert_eq!(rule.emission, EmissionMode::Once);
        assert!(rule.former_ids.is_empty());
    }

    #[test]
    fn loads_former_ids() {
        let yaml = r#"
rules:
  - id: ROLE-NEW-T
    former_ids: [OLD-ROLE-NEW, ANCIENT-ROLE-NEW]
    risk_level: medium
    message: "test"
    triggers:
      kind: create_role
"#;
        let rule = first_full_rule(load_v1_rules(yaml).expect("loads"));
        assert_eq!(
            rule.former_ids,
            vec!["OLD-ROLE-NEW".to_string(), "ANCIENT-ROLE-NEW".to_string()]
        );
    }

    #[test]
    fn rejects_former_id_colliding_with_live_id() {
        let yaml = r#"
rules:
  - id: LIVE-RULE
    risk_level: high
    message: "a"
    triggers:
      kind: grant
  - id: OTHER-RULE
    former_ids: [LIVE-RULE]
    risk_level: high
    message: "b"
    triggers:
      kind: revoke
"#;
        assert!(matches!(
            load_v1_rules(yaml),
            Err(LoadError::FormerIdCollidesWithLiveId { .. })
        ));
    }

    #[test]
    fn rejects_duplicate_former_id() {
        let yaml = r#"
rules:
  - id: RULE-A
    former_ids: [SHARED-OLD]
    risk_level: high
    message: "a"
    triggers:
      kind: grant
  - id: RULE-B
    former_ids: [SHARED-OLD]
    risk_level: high
    message: "b"
    triggers:
      kind: revoke
"#;
        assert!(matches!(
            load_v1_rules(yaml),
            Err(LoadError::DuplicateFormerId { .. })
        ));
    }

    #[test]
    fn rejects_former_ids_on_partial_override() {
        let yaml = r#"
rules:
  - id: SOME-BUILTIN
    former_ids: [OLD-ID]
    risk_level: low
"#;
        assert!(matches!(
            load_v1_rules(yaml),
            Err(LoadError::FormerIdsOnPartialOverride { .. })
        ));
    }

    #[test]
    fn rejects_duplicate_rule_id() {
        let yaml = r#"
rules:
  - id: TEST-DUP
    risk_level: high
    message: "first"
    triggers:
      kind: grant
  - id: TEST-DUP
    risk_level: high
    message: "second"
    triggers:
      kind: revoke
"#;
        let err = load_v1_rules(yaml).expect_err("rejects dup");
        assert_eq!(err, LoadError::DuplicateRuleId("TEST-DUP".to_string()));
    }

    #[test]
    fn surfaces_per_rule_predicate_parse_error() {
        let yaml = r#"
rules:
  - id: TEST-EMPTY-PRED
    risk_level: high
    message: "empty"
    triggers: {}
"#;
        let err = load_v1_rules(yaml).expect_err("rejects empty predicate");
        match err {
            LoadError::PredicateParse { rule_id, .. } => {
                assert_eq!(rule_id, "TEST-EMPTY-PRED");
            }
            other => panic!("expected PredicateParse, got {:?}", other),
        }
    }

    #[test]
    fn rule_naming_an_unknown_list_is_rejected() {
        let yaml = r#"
rules:
  - id: TEST-LIST
    risk_level: high
    message: "m"
    triggers:
      query.x: { in_list: nope }
"#;
        let err = load_v1_rules(yaml).expect_err("rejects unknown list");
        assert_eq!(
            err,
            LoadError::UnknownList {
                rule_id: "TEST-LIST".to_string(),
                list: "nope".to_string()
            }
        );
    }

    /// Facts of `USE ROLE <role>`.
    fn use_role_facts(role: &str) -> crate::facts::StatementFacts {
        serde_json::from_value(serde_json::json!({
            "kind": "use",
            "use_stmt": {"kind": "role", "target": {"raw": role, "normalized": role}},
            "algebra": crate::facts::AlgebraFacts::default(),
            "script_context": crate::facts::ScriptContext::default(),
        }))
        .expect("facts deserialize")
    }

    #[test]
    fn lists_only_file_loads() {
        let defines = load_v1_rules("lists:\n  my_list: {values: [a]}\n").expect("loads");
        assert!(defines.is_empty());
        assert!(!defines.changes_builtin_lists());
        assert_eq!(defines.list_changes().defined, ["my_list"]);
        assert!(defines.lists().get("my_list").is_some_and(|l| l.holds("A")));
        assert!(defines.lists().get("credential_dummies").is_some());

        let extends =
            load_v1_rules("lists:\n  credential_references: {extend: {values: [From_Pipeline]}}\n")
                .expect("loads");
        assert!(extends.is_empty());
        assert!(extends.changes_builtin_lists());
        assert_eq!(
            extends.list_changes().changed_builtins,
            ["credential_references"]
        );
        let references = extends
            .lists()
            .get("credential_references")
            .expect("built-in list present");
        assert!(references.holds("from_pipeline"));
        assert!(references.holds("vault:kv/db#pw"));
    }

    #[test]
    fn custom_rule_names_a_builtin_list() {
        let yaml = r#"
rules:
  - id: TEST-DUMMY-ROLE
    risk_level: low
    message: "dummy role"
    triggers:
      use_stmt.target.raw: { in_list: credential_dummies }
"#;
        let rules = load_v1_rules(yaml)
            .and_then(LoadedRuleset::into_strict_rules)
            .expect("loads");
        let fired = |role: &str| {
            crate::rules::evaluate_rules(&use_role_facts(role), &rules)
                .into_iter()
                .map(|f| f.rule_id)
                .collect::<Vec<_>>()
        };
        assert_eq!(fired("REPLACE_ME"), ["TEST-DUMMY-ROLE"]);
        assert_eq!(fired("replace_me"), ["TEST-DUMMY-ROLE"]);
        assert!(fired("analyst").is_empty());
    }

    #[test]
    fn unknown_list_in_a_custom_rule() {
        let yaml = r#"
lists:
  my_list: {values: [a]}
rules:
  - id: TEST-OWN-LIST
    risk_level: low
    message: "own list"
    triggers:
      use_stmt.target.raw: { in_list: my_list }
  - id: TEST-MISSPELT-LIST
    risk_level: low
    message: "misspelt list"
    triggers:
      use_stmt.target.raw: { not_in_list: [my_list, credential_reference] }
"#;
        assert_eq!(
            load_v1_rules(yaml).expect_err("rejects unknown list"),
            LoadError::UnknownList {
                rule_id: "TEST-MISSPELT-LIST".to_string(),
                list: "credential_reference".to_string()
            }
        );
    }

    #[test]
    fn rebuild_resolves_against_the_file_table() {
        let corpus_yaml = r#"
lists:
  refs: {patterns: ["vault:*"]}
rules:
  - id: LIST-RULE
    risk_level: high
    message: "not a reference"
    triggers:
      use_stmt.target.raw: { not_in_list: refs }
  - id: PLAIN-RULE
    risk_level: low
    message: "use"
    triggers:
      kind: use
"#;
        let corpus = load_builtin_rules_yaml(corpus_yaml).expect("test corpus loads");
        let extension: BTreeMap<String, V1ListEntry> =
            serde_yaml_ng::from_str("refs: {extend: {values: [From_Pipeline]}}")
                .expect("list yaml parses");
        let (table, _) = apply_file_lists(&corpus.lists, extension).expect("extension applies");
        let rebuilt = recompile_list_rules(
            parse_yaml_file(corpus_yaml).expect("test corpus parses"),
            &corpus.list_rule_ids,
            &table,
        )
        .expect("rebuilds");
        assert_eq!(
            rebuilt.keys().collect::<Vec<_>>(),
            [&"LIST-RULE".to_string()]
        );

        let holds = |rule: &Rule, role: &str| {
            rule.triggers
                .evaluate_value(&serde_json::json!({"use_stmt": {"target": {"raw": role}}}))
                .is_match()
        };
        let cached = corpus
            .rules
            .iter()
            .find(|r| r.id == "LIST-RULE")
            .expect("cached rule");
        let rebuilt = &rebuilt["LIST-RULE"];
        assert!(holds(cached, "from_pipeline"));
        assert!(!holds(rebuilt, "from_pipeline"));
        assert!(!holds(cached, "vault:kv/x"));
        assert!(!holds(rebuilt, "vault:kv/x"));
        assert!(holds(rebuilt, "S3cret!"));
    }

    #[test]
    fn builtin_corpus_error_names_the_corpus() {
        let err = LoadError::BuiltinCorpus(Box::new(LoadError::Json("bad".to_string())));
        assert!(err.to_string().contains("built-in rule corpus"), "{err}");
    }

    #[test]
    fn surfaces_yaml_top_level_error() {
        let yaml = "this is not yaml: : :";
        let err = load_v1_rules(yaml).expect_err("rejects malformed YAML");
        assert!(matches!(err, LoadError::Yaml(_)));
    }

    #[test]
    fn a_json_or_toml_file_loads_the_rule_a_yaml_file_does() {
        let yaml = "rules:\n  - id: R-ONE\n    risk_level: low\n    message: m\n    former_ids: [R-OLD]\n    triggers:\n      all_of:\n        - kind: {in: [grant, revoke]}\n        - privilege.target.kind: schema\n";
        let json = r#"{"rules": [{"id": "R-ONE", "risk_level": "low", "message": "m", "former_ids": ["R-OLD"], "triggers": {"all_of": [{"kind": {"in": ["grant", "revoke"]}}, {"privilege.target.kind": "schema"}]}}]}"#;
        let toml = "[[rules]]\nid = \"R-ONE\"\nrisk_level = \"low\"\nmessage = \"m\"\nformer_ids = [\"R-OLD\"]\n\n[[rules.triggers.all_of]]\nkind = { in = [\"grant\", \"revoke\"] }\n\n[[rules.triggers.all_of]]\n\"privilege.target.kind\" = \"schema\"\n";
        let grants_on_a_schema =
            serde_json::json!({"kind": "grant", "privilege": {"target": {"kind": "schema"}}});
        let selects = serde_json::json!({"kind": "select"});
        for (format, loaded) in [
            ("yaml", load_v1_rules(yaml)),
            ("json", load_v1_rules_from_json(json.as_bytes())),
            ("toml", load_v1_rules_from_toml(toml)),
        ] {
            let rule = first_full_rule(loaded.expect("loads"));
            assert_eq!(rule.id, "R-ONE", "{format}");
            assert_eq!(rule.former_ids, ["R-OLD"], "{format}");
            assert!(
                rule.triggers.evaluate_value(&grants_on_a_schema).is_match(),
                "{format}"
            );
            assert!(
                !rule.triggers.evaluate_value(&selects).is_match(),
                "{format}"
            );
        }
    }

    #[test]
    fn surfaces_toml_top_level_error() {
        let err = load_v1_rules_from_toml("rules = [").expect_err("rejects malformed TOML");
        assert!(matches!(err, LoadError::Toml(_)));
    }

    #[test]
    fn empty_rules_section_loads_to_empty_ruleset() {
        let yaml = "rules: []";
        let rs = load_v1_rules(yaml).expect("loads");
        assert!(rs.is_empty());
    }

    #[test]
    fn enabled_default_is_true_on_full_rule() {
        let yaml = r#"
rules:
  - id: TEST-ENABLED-DEFAULT
    risk_level: low
    message: "default enabled"
    triggers:
      kind: grant
"#;
        let rs = load_v1_rules(yaml).expect("loads");
        assert!(first_full_rule(rs).enabled);
    }

    #[test]
    fn enabled_false_is_respected_on_full_rule() {
        let yaml = r#"
rules:
  - id: TEST-DISABLED
    risk_level: low
    message: "explicitly disabled"
    enabled: false
    triggers:
      kind: grant
"#;
        let rs = load_v1_rules(yaml).expect("loads");
        assert!(!first_full_rule(rs).enabled);
    }

    #[test]
    fn each_quantifier_implies_per_witness_emission() {
        let yaml = r#"
rules:
  - id: TEST-EACH
    risk_level: medium
    message: "fan out per matching event"
    triggers:
      diff.events:
        each:
          kind: aggregate_added
"#;
        let rs = load_v1_rules(yaml).expect("loads");
        assert_eq!(first_full_rule(rs).emission, EmissionMode::PerWitness);
    }

    #[test]
    fn preserves_source_order() {
        let yaml = r#"
rules:
  - id: A
    risk_level: low
    message: "a"
    triggers:
      kind: grant
  - id: B
    risk_level: low
    message: "b"
    triggers:
      kind: grant
  - id: C
    risk_level: low
    message: "c"
    triggers:
      kind: grant
"#;
        let rs = load_v1_rules(yaml).expect("loads");
        let ids: Vec<&str> = rs.entries().iter().map(|e| e.id()).collect();
        assert_eq!(ids, vec!["A", "B", "C"]);
    }

    // ── Partial-override classification tests ───────────────────────

    #[test]
    fn entry_without_triggers_is_classified_as_partial_override() {
        let yaml = r#"
rules:
  - id: SOME-BUILTIN
    risk_level: low
"#;
        let rs = load_v1_rules(yaml).expect("partial loads");
        match &rs.entries()[0] {
            LoadedEntry::Partial(p) => {
                assert_eq!(p.id, "SOME-BUILTIN");
                assert_eq!(p.risk_level, Some(RiskLevel::Low));
                assert_eq!(p.message, None);
                assert_eq!(p.enabled, None);
            }
            other => panic!("expected Partial, got {:?}", other),
        }
    }

    #[test]
    fn full_rule_missing_risk_level_is_rejected_at_load() {
        let yaml = r#"
rules:
  - id: HAS-TRIGGERS-NO-RL
    message: "broken full rule"
    triggers:
      kind: grant
"#;
        match load_v1_rules(yaml).expect_err("rejects incomplete full") {
            LoadError::IncompleteFullRule {
                rule_id,
                missing_field,
            } => {
                assert_eq!(rule_id, "HAS-TRIGGERS-NO-RL");
                assert_eq!(missing_field, "risk_level");
            }
            other => panic!("expected IncompleteFullRule, got {:?}", other),
        }
    }

    #[test]
    fn full_rule_missing_message_is_rejected_at_load() {
        let yaml = r#"
rules:
  - id: HAS-TRIGGERS-NO-MSG
    risk_level: high
    triggers:
      kind: grant
"#;
        match load_v1_rules(yaml).expect_err("rejects incomplete full") {
            LoadError::IncompleteFullRule {
                rule_id,
                missing_field,
            } => {
                assert_eq!(rule_id, "HAS-TRIGGERS-NO-MSG");
                assert_eq!(missing_field, "message");
            }
            other => panic!("expected IncompleteFullRule, got {:?}", other),
        }
    }

    #[test]
    fn partial_override_rejecting_emission_field() {
        let yaml = r#"
rules:
  - id: PARTIAL-WITH-EMISSION
    risk_level: low
    emission: per_witness
"#;
        match load_v1_rules(yaml).expect_err("rejects emission on partial") {
            LoadError::DisallowedFieldOnPartialOverride { rule_id, field } => {
                assert_eq!(rule_id, "PARTIAL-WITH-EMISSION");
                assert_eq!(field, "emission");
            }
            other => panic!("expected DisallowedFieldOnPartialOverride, got {:?}", other),
        }
    }

    #[test]
    fn partial_override_rejecting_per_statement_field() {
        let yaml = r#"
rules:
  - id: PARTIAL-WITH-PER-STMT
    risk_level: low
    per_statement: true
"#;
        match load_v1_rules(yaml).expect_err("rejects per_statement on partial") {
            LoadError::DisallowedFieldOnPartialOverride { rule_id, field } => {
                assert_eq!(rule_id, "PARTIAL-WITH-PER-STMT");
                assert_eq!(field, "per_statement");
            }
            other => panic!("expected DisallowedFieldOnPartialOverride, got {:?}", other),
        }
    }

    #[test]
    fn partial_override_with_only_id_is_rejected() {
        let yaml = r#"
rules:
  - id: ID-ONLY
"#;
        match load_v1_rules(yaml).expect_err("rejects id-only entry") {
            LoadError::EmptyPartialOverride { rule_id } => assert_eq!(rule_id, "ID-ONLY"),
            other => panic!("expected EmptyPartialOverride, got {:?}", other),
        }
    }

    #[test]
    fn into_strict_rules_rejects_partial_entries() {
        let yaml = r#"
rules:
  - id: NORMAL
    risk_level: low
    message: "ok"
    triggers:
      kind: grant
  - id: PARTIAL
    risk_level: low
"#;
        let rs = load_v1_rules(yaml).expect("loads");
        match rs
            .into_strict_rules()
            .expect_err("strict materialization rejects partial")
        {
            LoadError::IncompleteFullRule {
                rule_id,
                missing_field,
            } => {
                assert_eq!(rule_id, "PARTIAL");
                assert_eq!(missing_field, "triggers");
            }
            other => panic!("unexpected error: {:?}", other),
        }
    }
}
