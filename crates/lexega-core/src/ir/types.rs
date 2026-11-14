// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Cross-cutting IR types that don't belong to a single analysis.

/// The database and schema an unqualified table reference resolves in at a
/// point of a script, used to qualify it during lowering and analysis.
///
/// Each part is the one the last `USE` before that point names (`USE
/// DATABASE`, `USE SCHEMA`, `USE <db>.<schema>`, …), else the one the run
/// starts in (`AnalysisConfig`'s `session_db` / `session_schema`), else
/// none.
#[derive(Debug, Clone, Default)]
pub struct SessionContext {
    pub db: Option<String>,
    pub schema: Option<String>,
    /// Where `schema` is `None`: the schemas a name written without one is
    /// looked for in, in order, the first holding the name answering it,
    /// and the first where such a name is created. Empty where they are not
    /// known: any schema may hold the name.
    pub search_path: Vec<String>,
}

impl SessionContext {
    /// Read an env var with trimming, returning None if empty or unset.
    fn read_env(name: &str) -> Option<String> {
        std::env::var(name)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }

    /// Create SessionContext from environment variables.
    ///
    /// Precedence: `LEXEGA_CTX_DB` > `SNOWFLAKE_DB` (backward compat).
    /// Same for schema: `LEXEGA_CTX_SCHEMA` > `SNOWFLAKE_SCHEMA`.
    pub fn from_env() -> Self {
        let db = Self::read_env("LEXEGA_CTX_DB").or_else(|| Self::read_env("SNOWFLAKE_DB"));

        let schema =
            Self::read_env("LEXEGA_CTX_SCHEMA").or_else(|| Self::read_env("SNOWFLAKE_SCHEMA"));

        Self {
            db,
            schema,
            search_path: Vec::new(),
        }
    }

    /// The session a run names by `written`: `SCHEMA` or
    /// `DATABASE.SCHEMA`, each part as SQL writes it; `None` for a name of
    /// an empty part, or of more than two parts.
    pub fn named(written: &str) -> Option<Self> {
        let written = written.trim();
        let parts = super::lower::split_dotted_name(written);
        // The splitter drops an empty last part; a trailing dot writes one.
        if written.ends_with('.') || parts.iter().any(|part| part.trim().is_empty()) {
            return None;
        }
        let (db, schema) = match parts.as_slice() {
            [schema] => (None, schema.clone()),
            [db, schema] => (Some(db.clone()), schema.clone()),
            [] | [_, _, _, ..] => return None,
        };
        Some(Self {
            db,
            schema: Some(schema),
            search_path: Vec::new(),
        })
    }

    /// Place a relation's name, written with `db` and `schema` where it
    /// names them, in this session: a name without a database takes the
    /// session's database, and one without a database or schema also takes
    /// its schema (`schema.name` keeps the schema it names).
    pub fn place(&self, db: &mut Option<String>, schema: &mut Option<String>) {
        if db.is_some() {
            return;
        }
        if schema.is_none() {
            schema.clone_from(&self.schema);
        }
        db.clone_from(&self.db);
    }
}
