// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! The recognition build: every source is analyzed with the facts its own
//! structure determines, and templates are analyzed as written.

use std::path::Path;
use std::process;
use std::sync::Arc;

use lexega_core::analyzer::{AnalysisConfig, AnalysisReport};
use lexega_core::dialect::DialectRef;
use lexega_core::ir::DialectCatalogs;
use lexega_core::rules::Rule;
use lexega_core::template::{
    has_jinja_syntax, render_substituted, RenderArtifacts, SubstitutionConfig, UnresolvedVariables,
    VariableContext,
};
use lexega_core::Engine;

use crate::extension::{
    Capability, Extension, FormatRenderOptions, FormatRenderer, PolicyGate, PolicySetup, Session,
    SessionOptions,
};
use crate::io::{load_variable_context, resolve_dialect, SessionCatalogs};
use crate::usage::print_top_usage;

/// Why a template comes back unrendered.
const NOT_RENDERED: &str = "this build does not render templates";

/// Commands this build refuses by name, each with what it does.
const FULL_BUILD_COMMANDS: &[(&str, &str)] = &[
    ("diff", "Semantic diff between two commits"),
    (
        "init",
        "Project setup (a baseline report, a policy and a CI workflow)",
    ),
    ("policy", "Policy enforcement"),
    ("policy-lint", "Policy file validation"),
    ("dashboard", "The local results dashboard"),
    ("mcp", "The MCP server that gates SQL for AI agents"),
    ("license", "License management"),
];

/// The extension of the recognition build. It provides no [`Capability`].
pub struct Recognition;

impl Extension for Recognition {
    fn version(&self) -> String {
        format!("lexega {} (recognition)", env!("CARGO_PKG_VERSION"))
    }

    fn tool_name(&self) -> &'static str {
        "lexega"
    }

    fn offers(&self, _capability: Capability) -> bool {
        false
    }

    fn authorize(&self, _program: &str, needs: &[Capability]) {
        let mut missing: Vec<Capability> = Vec::new();
        for capability in needs {
            if !missing.contains(capability) {
                missing.push(*capability);
            }
        }
        if missing.is_empty() {
            return;
        }
        eprintln!("Error: this run uses features this build does not include:");
        for capability in &missing {
            eprintln!("  - {}", capability.label());
        }
        eprintln!();
        eprintln!("They are part of the full build: https://lexega.com");
        process::exit(1);
    }

    fn open_session(&self, options: SessionOptions<'_>) -> Result<Box<dyn Session>, String> {
        Ok(Box::new(RecognitionSession::open(options)?))
    }

    fn policy_gate(&self, _setup: &PolicySetup<'_>) -> Result<Box<dyn PolicyGate>, String> {
        Err("this build has no policy gate".to_string())
    }

    fn format_renderer(
        &self,
        _options: &FormatRenderOptions<'_>,
    ) -> Result<Box<dyn FormatRenderer>, String> {
        Ok(Box::new(Unrendered))
    }

    fn reads_dialect(&self, command: &str) -> bool {
        FULL_BUILD_COMMANDS.iter().any(|(name, _)| *name == command)
    }

    fn run_command(&self, command: &str, _args: &[String]) -> bool {
        let Some((_, what)) = FULL_BUILD_COMMANDS
            .iter()
            .find(|(name, _)| *name == command)
        else {
            return false;
        };
        eprintln!("Error: `{}` is not a command of this build.", command);
        eprintln!();
        eprintln!("{} is part of the full build: https://lexega.com", what);
        process::exit(1);
    }

    fn usage(&self, program: &str) {
        print_top_usage(program);
    }
}

/// The `fmt` renderer of a build that renders no templates.
struct Unrendered;

impl FormatRenderer for Unrendered {
    fn render(&mut self, _path: Option<&Path>, _source: &str) -> Result<String, String> {
        Err(NOT_RENDERED.to_string())
    }
}

/// A session over the recognition engine.
pub struct RecognitionSession {
    vars: VariableContext,
    substitution: SubstitutionConfig,
    unresolved: UnresolvedVariables,
    custom_rules: Option<Arc<[Rule]>>,
    masking: Arc<lexega_core::rules::MaskingPolicy>,
    /// The dialects' function catalogs every analysis of the run reads.
    function_catalogs: DialectCatalogs,
    trace_mode: bool,
    verbose_mode: bool,
    catalog: Option<SessionCatalogs>,
    /// Where a table named without a database or schema is looked for,
    /// where the run says.
    default_schema: Option<lexega_core::ir::SessionContext>,
    dialect: Option<DialectRef>,
}

impl RecognitionSession {
    pub fn open(options: SessionOptions<'_>) -> Result<Self, String> {
        let vars = load_variable_context(
            options.jinja_vars,
            options.jinja_var_files,
            options.snowsql_configs,
            options.env_allowlist,
        )
        .map_err(|e| format!("Error loading variables: {}", e))?;
        let dialect = options.dialect_name.and_then(resolve_dialect);
        let catalog = match options.catalog_path {
            Some(path) => Some(
                SessionCatalogs::load(path, options.catalog_provider, &[], &dialect)
                    .map_err(|e| format!("Failed to load catalog: {}", e))?,
            ),
            None => None,
        };
        Ok(Self {
            vars,
            substitution: options.substitution.clone(),
            unresolved: UnresolvedVariables::default(),
            custom_rules: options.custom_rules.map(Arc::from),
            masking: options.masking,
            function_catalogs: DialectCatalogs::default(),
            trace_mode: options.trace_mode,
            verbose_mode: options.verbose_mode,
            catalog,
            default_schema: options.default_schema.cloned(),
            dialect: None,
        })
    }
}

impl Session for RecognitionSession {
    fn dialect(&self) -> Option<DialectRef> {
        self.dialect.clone()
    }

    fn set_dialect(&mut self, dialect: Option<DialectRef>) {
        if let Some(catalog) = self.catalog.as_mut() {
            catalog.select(&dialect);
        }
        self.dialect = dialect;
    }

    fn renders_templates(&self) -> bool {
        false
    }

    fn compares_changes(&self) -> bool {
        false
    }

    fn render(&self, input: &str) -> Result<RenderArtifacts, String> {
        render_substituted(
            input,
            &self.dialect,
            &self.substitution,
            Some(&self.vars),
            |unresolved| {
                if let Some(warning) = self.unresolved.warning(unresolved) {
                    eprintln!("{}", warning);
                }
            },
            |sql| {
                Ok(if has_jinja_syntax(sql) {
                    RenderArtifacts::not_rendered(sql.to_string(), NOT_RENDERED.to_string())
                } else {
                    RenderArtifacts::raw(sql.to_string())
                })
            },
        )
    }

    fn analyze(
        &self,
        render: &RenderArtifacts,
        source_file: Option<&str>,
    ) -> Result<AnalysisReport, String> {
        let session = self.default_schema.as_ref();
        let config = AnalysisConfig {
            custom_rules: self.custom_rules.clone(),
            masking: self.masking.clone(),
            function_catalogs: self.function_catalogs.clone(),
            trace_mode: self.trace_mode,
            verbose_mode: self.verbose_mode,
            session_db: session.and_then(|session| session.db.clone()),
            session_schema: session.and_then(|session| session.schema.clone()),
            dialect: self.dialect.clone(),
        };
        let catalog = self
            .catalog
            .as_ref()
            .map(SessionCatalogs::current)
            .transpose()?;
        Engine::recognition()
            .analyze_risk_with_source_map(render, &config, catalog.map(Arc::as_ref), source_file)
            .map_err(|e| format!("Analysis error: {}", e))
    }
}
