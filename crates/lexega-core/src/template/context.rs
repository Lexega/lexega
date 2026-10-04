// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Variable context management for template rendering
//!
//! Supports loading variables from multiple sources with priority ordering:
//! 1. CLI flags (--var key=value) - highest priority
//! 2. Variable file (--var-file vars.json)
//! 3. Environment allowlist (`--var-env NAME`)
//! 4. SnowSQL config (`[variables]` section)
//! 5. Config file (`.lexega.toml` `[template.vars]`)
//! 6. dbt profile (profiles.yml) - lowest priority

use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Variable context for template rendering
#[derive(Debug, Clone, Default)]
pub struct VariableContext {
    /// Variables from all sources (merged with priority)
    variables: HashMap<String, Value>,

    /// Track which source each variable came from (for debugging)
    sources: HashMap<String, VariableSource>,
}

/// Source of a template variable
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VariableSource {
    Cli,
    VarFile,
    EnvAllowlist,
    SnowsqlConfig,
    ConfigFile,
    DbtProfile,
}

impl VariableSource {
    pub fn priority(&self) -> u8 {
        match self {
            VariableSource::Cli => 0, // Highest priority
            VariableSource::VarFile => 1,
            // Allowlisted environment values: below the explicit per-invocation
            // inputs, above every static config file — in CI the environment is
            // the deployment target's actual truth.
            VariableSource::EnvAllowlist => 2,
            // SnowSQL `[variables]`: below the explicit Lexega flags, matching
            // SnowSQL's own `-D`-overrides-config precedence.
            VariableSource::SnowsqlConfig => 3,
            VariableSource::ConfigFile => 4,
            VariableSource::DbtProfile => 5, // Lowest priority
        }
    }
}

/// Configuration for dbt integration
#[derive(Debug, Clone, Deserialize)]
pub struct DbtConfig {
    /// dbt profile name (from profiles.yml)
    pub profile: Option<String>,

    /// dbt target name (e.g., "dev", "prod")
    pub target: Option<String>,
}

/// Template configuration from .lexega.toml
#[derive(Debug, Clone, Deserialize)]
pub struct TemplateConfig {
    /// Template variables
    #[serde(default)]
    pub vars: HashMap<String, Value>,

    /// dbt configuration
    #[serde(default)]
    pub dbt: Option<DbtConfig>,

    /// Deployment-variable substitution (`[template.substitution]`)
    #[serde(default)]
    pub substitution: Option<SubstitutionSettings>,
}

/// `[template.substitution]` in .lexega.toml — which built-in marker syntaxes
/// the deployment-variable pre-pass recognizes.
///
/// The file is found in the tree being analyzed, so it only chooses among
/// the built-in syntaxes. Which environment variables are read and which
/// delimiters make a marker are decided on the command line: a file that
/// could name either would let the analyzed tree read the environment into
/// a report, or mark runnable SQL as a variable and hide it from analysis.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SubstitutionSettings {
    /// Preset names (`"dollar-brace"`, `"dollar-paren"`). `None` keeps the
    /// default (`["dollar-brace"]`); an explicit `[]` disables the presets.
    pub presets: Option<Vec<String>>,

    /// Parsed only so [`Self::command_line_only_keys`] can report it.
    #[serde(default)]
    env: Option<toml::Value>,

    /// Parsed only so [`Self::command_line_only_keys`] can report it.
    #[serde(default)]
    custom: Option<toml::Value>,
}

impl SubstitutionSettings {
    /// The keys this table sets that a configuration file may not.
    pub fn command_line_only_keys(&self) -> Vec<CommandLineOnlyKey> {
        let mut keys = Vec::new();
        if self.env.is_some() {
            keys.push(CommandLineOnlyKey::Env);
        }
        if self.custom.is_some() {
            keys.push(CommandLineOnlyKey::Custom);
        }
        keys
    }
}

/// A `[template.substitution]` key whose setting belongs to the command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandLineOnlyKey {
    /// `env` — environment variables to read values from.
    Env,
    /// `custom` — delimiter pairs beyond the presets.
    Custom,
}

impl CommandLineOnlyKey {
    /// The key as written in the table.
    pub fn name(self) -> &'static str {
        match self {
            CommandLineOnlyKey::Env => "env",
            CommandLineOnlyKey::Custom => "custom",
        }
    }
}

/// Root configuration structure
#[derive(Debug, Clone, Deserialize)]
pub struct LexegaConfig {
    #[serde(default)]
    pub template: Option<TemplateConfig>,
}

/// Render a variable value as substitution text — a JSON string emits its
/// contents (no quotes), everything else its canonical form.
pub(crate) fn value_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Error during variable context loading
#[derive(Debug, Clone)]
pub struct ContextError {
    pub message: String,
}

impl ContextError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ContextError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ContextError {}

impl VariableContext {
    /// Create an empty context
    pub fn new() -> Self {
        Self::default()
    }

    /// Get a variable value
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.variables.get(key)
    }

    /// Get a variable value, falling back to the first ASCII-case-insensitive
    /// key match when no exact key exists. An exact match always wins.
    pub(crate) fn get_ci(&self, key: &str) -> Option<&Value> {
        self.get(key).or_else(|| {
            self.variables
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(key))
                .map(|(_, v)| v)
        })
    }

    /// Set a variable value with source tracking
    pub fn set(&mut self, key: String, value: Value, source: VariableSource) {
        // Only override if new source has higher priority
        if let Some(existing_source) = self.sources.get(&key) {
            if source.priority() > existing_source.priority() {
                // Existing source has higher priority, don't override
                return;
            }
        }

        self.variables.insert(key.clone(), value);
        self.sources.insert(key, source);
    }

    /// Get all variables
    pub fn variables(&self) -> &HashMap<String, Value> {
        &self.variables
    }

    /// Get the source of a variable
    pub fn source_of(&self, key: &str) -> Option<VariableSource> {
        self.sources.get(key).copied()
    }

    /// Load from CLI arguments (--var key=value)
    pub fn load_from_cli_args(&mut self, args: &[String]) -> Result<(), ContextError> {
        for arg in args {
            let parts: Vec<&str> = arg.splitn(2, '=').collect();
            if parts.len() != 2 {
                return Err(ContextError::new(format!(
                    "Invalid variable format '{}'. Expected 'key=value'",
                    arg
                )));
            }

            let key = parts[0].to_string();
            let value_str = parts[1];

            // Try to parse as JSON, fall back to string
            let value = match serde_json::from_str(value_str) {
                Ok(v) => v,
                Err(_) => Value::String(value_str.to_string()),
            };

            self.set(key, value, VariableSource::Cli);
        }

        Ok(())
    }

    /// Load values for an explicit allowlist of environment variable names
    /// (`--var-env NAME`). Values stay strings
    /// (environment values are text, never JSON-coerced); a name absent from
    /// the environment is silently skipped — the substitution pass's
    /// unresolved-marker degradation reports it.
    pub fn load_from_env_allowlist(&mut self, names: &[String]) {
        for name in names {
            if let Ok(value) = std::env::var(name) {
                self.set(
                    name.clone(),
                    Value::String(value),
                    VariableSource::EnvAllowlist,
                );
            }
        }
    }

    /// Load variables from the `[variables]` section of a SnowSQL config file
    /// (`~/.snowsql/config`, INI-style). ONLY `[variables]` is read; every other
    /// section — including `[connections]` credentials — is ignored. This is the
    /// native source for SnowSQL `&var` substitution.
    ///
    /// SnowSQL only substitutes when `variable_substitution` is enabled, so an
    /// explicit `variable_substitution = false` in `[options]` discards this
    /// config's variables (they would be inert at the warehouse).
    pub fn load_from_snowsql_config(&mut self, path: &Path) -> Result<(), ContextError> {
        let content = fs::read_to_string(path).map_err(|e| {
            ContextError::new(format!(
                "Failed to read SnowSQL config {}: {}",
                path.display(),
                e
            ))
        })?;
        self.load_snowsql_variables_section(&content);
        Ok(())
    }

    /// Parse the `[variables]` section out of SnowSQL INI config text. Malformed
    /// lines are skipped (no hard error — matches the lexer's permissive spirit).
    /// Keys are lowercased (configparser semantics; SnowSQL names are
    /// case-insensitive). A bare value is JSON-coerced like `--var` (so `n=5` is a
    /// number); an explicitly quoted value stays a string. A whitespace-preceded
    /// `#`/`;` starts an inline comment; one glued to the value is literal.
    fn load_snowsql_variables_section(&mut self, content: &str) {
        let mut in_variables = false;
        let mut in_options = false;
        // `[options]` may follow `[variables]`, so collect first and only commit
        // if substitution isn't explicitly disabled.
        let mut substitution_disabled = false;
        let mut pending: Vec<(String, Value)> = Vec::new();
        for line in content.lines() {
            let trimmed = line.trim();
            // Full-line INI comments and blank lines.
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
                continue;
            }
            // Section header (case-insensitive).
            if let Some(inner) = trimmed.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
                let name = inner.trim();
                in_variables = name.eq_ignore_ascii_case("variables");
                in_options = name.eq_ignore_ascii_case("options");
                continue;
            }
            let Some((key, value)) = trimmed.split_once('=') else {
                continue;
            };
            let key = key.trim();
            if key.is_empty() {
                continue;
            }
            if in_options {
                // Honor an explicit `variable_substitution = false`.
                if key.eq_ignore_ascii_case("variable_substitution") {
                    let (v, _) = strip_ini_quotes(strip_inline_comment(value).trim());
                    if matches!(
                        v.to_ascii_lowercase().as_str(),
                        "false" | "0" | "off" | "no"
                    ) {
                        substitution_disabled = true;
                    }
                }
                continue;
            }
            if !in_variables {
                continue;
            }
            let (value, quoted) = strip_ini_quotes(strip_inline_comment(value).trim());
            // Explicitly quoted → literal string; bare → JSON-coerce (numbers /
            // bools) to match `--var`, falling back to a string.
            let parsed = if quoted {
                Value::String(value.to_string())
            } else {
                serde_json::from_str(value).unwrap_or_else(|_| Value::String(value.to_string()))
            };
            pending.push((key.to_ascii_lowercase(), parsed));
        }
        if substitution_disabled {
            return;
        }
        for (key, value) in pending {
            self.set(key, value, VariableSource::SnowsqlConfig);
        }
    }

    /// Load from .lexega.toml config file
    pub fn load_from_config_file(&mut self, path: &Path) -> Result<(), ContextError> {
        let content = fs::read_to_string(path).map_err(|e| {
            ContextError::new(format!(
                "Failed to read config file {}: {}",
                path.display(),
                e
            ))
        })?;

        let config: LexegaConfig = toml::from_str(&content).map_err(|e| {
            ContextError::new(format!(
                "Failed to parse config file {} as TOML: {}",
                path.display(),
                e
            ))
        })?;

        if let Some(template) = config.template {
            for (key, value) in template.vars {
                self.set(key, value, VariableSource::ConfigFile);
            }

            // If dbt config present, try to load from profiles.yml
            if let Some(dbt_config) = template.dbt {
                self.load_from_dbt_profile(dbt_config)?;
            }
        }

        Ok(())
    }

    /// Load from dbt profiles.yml
    fn load_from_dbt_profile(&mut self, dbt_config: DbtConfig) -> Result<(), ContextError> {
        // Find dbt profiles directory
        let profiles_path = if let Ok(dbt_profiles_dir) = std::env::var("DBT_PROFILES_DIR") {
            PathBuf::from(dbt_profiles_dir).join("profiles.yml")
        } else {
            #[cfg(feature = "cli")]
            {
                if let Some(home) = dirs::home_dir() {
                    home.join(".dbt").join("profiles.yml")
                } else {
                    return Err(ContextError::new(
                        "Could not locate dbt profiles directory. Set DBT_PROFILES_DIR or ensure ~/.dbt exists"
                    ));
                }
            }
            #[cfg(not(feature = "cli"))]
            {
                return Err(ContextError::new(
                    "Could not locate dbt profiles directory. Set DBT_PROFILES_DIR or ensure ~/.dbt exists"
                ));
            }
        };

        if !profiles_path.exists() {
            return Err(ContextError::new(format!(
                "dbt profiles.yml not found at {}",
                profiles_path.display()
            )));
        }

        let content = fs::read_to_string(&profiles_path)
            .map_err(|e| ContextError::new(format!("Failed to read dbt profiles.yml: {}", e)))?;

        let profiles: serde_json::Value = serde_yaml_ng::from_str(&content)
            .map_err(|e| ContextError::new(format!("Failed to parse dbt profiles.yml: {}", e)))?;

        // Extract variables from the specified profile and target
        let profile_name = dbt_config
            .profile
            .as_deref()
            .ok_or_else(|| ContextError::new("dbt profile name not specified in config"))?;

        let target_name = dbt_config.target.as_deref().unwrap_or("dev");

        let profile = profiles.get(profile_name).ok_or_else(|| {
            ContextError::new(format!(
                "Profile '{}' not found in profiles.yml",
                profile_name
            ))
        })?;

        let outputs = profile.get("outputs").ok_or_else(|| {
            ContextError::new(format!(
                "No 'outputs' section in profile '{}'",
                profile_name
            ))
        })?;

        let target = outputs.get(target_name).ok_or_else(|| {
            ContextError::new(format!(
                "Target '{}' not found in profile '{}'",
                target_name, profile_name
            ))
        })?;

        // Extract vars if present
        if let Some(vars) = target.get("vars") {
            if let Some(vars_obj) = vars.as_object() {
                for (key, value) in vars_obj {
                    self.set(key.clone(), value.clone(), VariableSource::DbtProfile);
                }
            }
        }

        Ok(())
    }

    /// Auto-discover and load from .lexega.toml in current directory or ancestors
    pub fn load_from_auto_config(&mut self) -> Result<(), ContextError> {
        let mut current = std::env::current_dir()
            .map_err(|e| ContextError::new(format!("Failed to get current directory: {}", e)))?;

        loop {
            let config_path = current.join(".lexega.toml");
            if config_path.exists() {
                return self.load_from_config_file(&config_path);
            }

            if !current.pop() {
                break;
            }
        }

        // No config file found - not an error
        Ok(())
    }

    /// Merge another context into this one, respecting priority
    pub fn merge(&mut self, other: Self) {
        for (key, value) in other.variables {
            let source = other
                .sources
                .get(&key)
                .copied()
                .unwrap_or(VariableSource::ConfigFile);
            self.set(key, value, source);
        }
    }
}

/// Strip one whitespace-preceded inline `#`/`;` comment from a raw INI value
/// (configparser's `inline_comment_prefixes` convention). A `#`/`;` glued to the
/// value (no preceding space) is kept literally.
fn strip_inline_comment(s: &str) -> &str {
    let b = s.as_bytes();
    let mut i = 1;
    while i < b.len() {
        if (b[i] == b'#' || b[i] == b';') && b[i - 1].is_ascii_whitespace() {
            return &s[..i];
        }
        i += 1;
    }
    s
}

/// Strip one layer of matching surrounding single/double quotes. Returns the
/// inner text and whether a quote pair was removed.
fn strip_ini_quotes(s: &str) -> (&str, bool) {
    let b = s.as_bytes();
    if b.len() >= 2 && (b[0] == b'"' || b[0] == b'\'') && b[0] == b[b.len() - 1] {
        (&s[1..s.len() - 1], true)
    } else {
        (s, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_variable_priority() {
        let mut ctx = VariableContext::new();

        // Lower priority first
        ctx.set(
            "region".to_string(),
            Value::String("EU".to_string()),
            VariableSource::DbtProfile,
        );
        assert_eq!(ctx.get("region"), Some(&Value::String("EU".to_string())));

        // Higher priority overrides
        ctx.set(
            "region".to_string(),
            Value::String("US".to_string()),
            VariableSource::Cli,
        );
        assert_eq!(ctx.get("region"), Some(&Value::String("US".to_string())));

        // Lower priority doesn't override
        ctx.set(
            "region".to_string(),
            Value::String("ASIA".to_string()),
            VariableSource::ConfigFile,
        );
        assert_eq!(ctx.get("region"), Some(&Value::String("US".to_string())));
    }

    #[test]
    fn test_env_allowlist_loading() {
        // Unique name so parallel tests can't collide on it.
        let name = "LEXEGA_TEST_ENV_ALLOWLIST_ELT_DB";
        std::env::set_var(name, "ELT");
        let mut ctx = VariableContext::new();
        ctx.load_from_env_allowlist(&[name.to_string(), "LEXEGA_TEST_ENV_ABSENT".to_string()]);
        assert_eq!(ctx.get(name), Some(&Value::String("ELT".to_string())));
        assert_eq!(ctx.source_of(name), Some(VariableSource::EnvAllowlist));
        // Absent names are silently skipped.
        assert_eq!(ctx.get("LEXEGA_TEST_ENV_ABSENT"), None);
        // Explicit --var beats the environment; environment beats config file.
        ctx.set(
            name.to_string(),
            Value::String("CLI".to_string()),
            VariableSource::Cli,
        );
        assert_eq!(ctx.get(name), Some(&Value::String("CLI".to_string())));
        std::env::remove_var(name);
    }

    #[test]
    fn test_env_allowlist_beats_config_file() {
        let name = "LEXEGA_TEST_ENV_ALLOWLIST_PRIORITY";
        std::env::set_var(name, "FROM_ENV");
        let mut ctx = VariableContext::new();
        ctx.set(
            name.to_string(),
            Value::String("FROM_CONFIG".to_string()),
            VariableSource::ConfigFile,
        );
        ctx.load_from_env_allowlist(&[name.to_string()]);
        assert_eq!(ctx.get(name), Some(&Value::String("FROM_ENV".to_string())));
        std::env::remove_var(name);
    }

    #[test]
    fn test_substitution_settings_toml() {
        let toml_str = r#"
[template.substitution]
presets = ["dollar-brace", "dollar-paren"]
env = ["ELT_DB"]

[[template.substitution.custom]]
prefix = "%%"
suffix = "%%"
"#;
        let config: LexegaConfig = toml::from_str(toml_str).expect("valid toml");
        let sub = config
            .template
            .expect("template section")
            .substitution
            .expect("substitution section");
        assert_eq!(
            sub.presets,
            Some(vec!["dollar-brace".to_string(), "dollar-paren".to_string()])
        );
        assert_eq!(
            sub.command_line_only_keys(),
            vec![CommandLineOnlyKey::Env, CommandLineOnlyKey::Custom]
        );
    }

    #[test]
    fn test_substitution_settings_presets_alone() {
        let config: LexegaConfig =
            toml::from_str("[template.substitution]\npresets = [\"dollar-paren\"]\n")
                .expect("valid toml");
        let sub = config
            .template
            .expect("template section")
            .substitution
            .expect("substitution section");
        assert_eq!(sub.presets, Some(vec!["dollar-paren".to_string()]));
        assert!(sub.command_line_only_keys().is_empty());
    }

    #[test]
    fn test_cli_args_parsing() {
        let mut ctx = VariableContext::new();
        let args = vec![
            "region=US".to_string(),
            "active=true".to_string(),
            "count=42".to_string(),
        ];

        ctx.load_from_cli_args(&args).unwrap();

        assert_eq!(ctx.get("region"), Some(&Value::String("US".to_string())));
        assert_eq!(ctx.get("active"), Some(&Value::Bool(true)));
        assert_eq!(ctx.get("count"), Some(&Value::Number(42.into())));
    }

    #[test]
    fn test_cli_args_invalid_format() {
        let mut ctx = VariableContext::new();
        let args = vec!["invalid".to_string()];

        let result = ctx.load_from_cli_args(&args);
        assert!(result.is_err());
    }

    #[test]
    fn snowsql_config_reads_only_variables_section() {
        let config = "\
[connections]
accountname = myaccount
password = hunter2

[options]
variable_substitution = True

[variables]
tablename=CENUSTRACKONE
db=PROD
";
        let mut ctx = VariableContext::new();
        ctx.load_snowsql_variables_section(config);

        assert_eq!(
            ctx.get("tablename"),
            Some(&Value::String("CENUSTRACKONE".to_string()))
        );
        assert_eq!(ctx.get("db"), Some(&Value::String("PROD".to_string())));
        // Credential and option keys must never leak in as variables.
        assert_eq!(ctx.get("accountname"), None);
        assert_eq!(ctx.get("password"), None);
        assert_eq!(ctx.get("variable_substitution"), None);
    }

    #[test]
    fn snowsql_config_strips_matching_quotes() {
        let config = "[variables]\nq1=\"DOUBLE\"\nq2='SINGLE'\nbare=PLAIN\nmismatch=\"x'\n";
        let mut ctx = VariableContext::new();
        ctx.load_snowsql_variables_section(config);

        assert_eq!(ctx.get("q1"), Some(&Value::String("DOUBLE".to_string())));
        assert_eq!(ctx.get("q2"), Some(&Value::String("SINGLE".to_string())));
        assert_eq!(ctx.get("bare"), Some(&Value::String("PLAIN".to_string())));
        // Non-matching quotes are not stripped.
        assert_eq!(
            ctx.get("mismatch"),
            Some(&Value::String("\"x'".to_string()))
        );
    }

    #[test]
    fn snowsql_config_yields_to_cli_var() {
        // `-D`/`--var` (Cli) must override a config `[variables]` entry; the
        // config in turn overrides a dbt-profile value.
        let mut ctx = VariableContext::new();
        ctx.set(
            "db".to_string(),
            Value::String("FROM_DBT".to_string()),
            VariableSource::DbtProfile,
        );
        ctx.load_snowsql_variables_section("[variables]\ndb=FROM_CONFIG\n");
        assert_eq!(
            ctx.get("db"),
            Some(&Value::String("FROM_CONFIG".to_string()))
        );

        ctx.set(
            "db".to_string(),
            Value::String("FROM_CLI".to_string()),
            VariableSource::Cli,
        );
        assert_eq!(ctx.get("db"), Some(&Value::String("FROM_CLI".to_string())));
    }

    #[test]
    fn snowsql_config_honors_variable_substitution_false() {
        // `[options]` may appear after `[variables]`; an explicit false discards
        // the section's variables (SnowSQL would not substitute them).
        let mut ctx = VariableContext::new();
        ctx.load_snowsql_variables_section(
            "[variables]\nx=A\n[options]\nvariable_substitution = False\n",
        );
        assert_eq!(ctx.get("x"), None);

        // Enabled (or absent) keeps them.
        let mut on = VariableContext::new();
        on.load_snowsql_variables_section(
            "[options]\nvariable_substitution=true\n[variables]\nx=A\n",
        );
        assert_eq!(on.get("x"), Some(&Value::String("A".to_string())));
    }

    #[test]
    fn snowsql_config_coerces_bare_scalars_like_var() {
        let mut ctx = VariableContext::new();
        ctx.load_snowsql_variables_section(
            "[variables]\ncount=5\nratio=1.5\nflag=true\nname=PROD\nquoted=\"5\"\n",
        );
        assert_eq!(ctx.get("count"), Some(&Value::Number(5.into())));
        assert_eq!(ctx.get("flag"), Some(&Value::Bool(true)));
        assert_eq!(ctx.get("name"), Some(&Value::String("PROD".to_string())));
        // An explicitly quoted scalar stays a string.
        assert_eq!(ctx.get("quoted"), Some(&Value::String("5".to_string())));
        assert!(matches!(ctx.get("ratio"), Some(Value::Number(_))));
    }

    #[test]
    fn snowsql_config_lowercases_keys_and_strips_inline_comments() {
        let mut ctx = VariableContext::new();
        ctx.load_snowsql_variables_section(
            "[variables]\nDB=PROD\ngrantee=PUBLIC ; role note\nTbl=CUSTOMERS  # the table\nglued=a#b\n",
        );
        assert_eq!(ctx.get("db"), Some(&Value::String("PROD".to_string())));
        assert_eq!(
            ctx.get("grantee"),
            Some(&Value::String("PUBLIC".to_string()))
        );
        assert_eq!(
            ctx.get("tbl"),
            Some(&Value::String("CUSTOMERS".to_string()))
        );
        // A `#` glued to the value (no preceding space) is literal.
        assert_eq!(ctx.get("glued"), Some(&Value::String("a#b".to_string())));
    }

    #[test]
    fn snowsql_config_last_case_variant_wins_deterministically() {
        // configparser collapses `DB` and `db`; lowercasing makes the later line
        // win by file order instead of HashMap iteration order.
        let mut ctx = VariableContext::new();
        ctx.load_snowsql_variables_section("[variables]\nDB=first\ndb=second\n");
        assert_eq!(ctx.get("db"), Some(&Value::String("second".to_string())));
    }
}
