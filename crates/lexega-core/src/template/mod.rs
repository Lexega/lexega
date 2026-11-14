// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Source preparation ahead of analysis.
//!
//! Client and deployment substitution is a pair of line-preserving
//! pre-passes: deployment-pipeline variables ([`deployvars::preprocess`],
//! `${VAR}` and friends) first, then SnowSQL `&var`
//! ([`snowsql::preprocess`]). Each leaves a [`PlaceholderRecord`] for
//! every variable it could not resolve.
//!
//! [`RenderArtifacts`] is what analysis consumes: the text to analyze
//! together with its provenance — a [`SourceMap`] from rendered lines
//! back to template lines when a template was rendered, the placeholder
//! counts that feed analysis confidence, and the dependencies a render
//! discovered.

pub mod artifacts;
pub mod context;
pub mod deployvars;
pub mod records;
pub mod snowsql;
pub mod source_map;
pub mod spans;

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::rc::Rc;

use serde::Deserialize;

/// Detect Jinja template syntax (`{{ … }}`, `{% … %}`, `{# … #}`).
///
/// The single detection predicate for every render surface. A strict
/// superset of the lexer's `has_statement_jinja` flag (which is set only
/// when a literal `{{` / `{%` is lexed), so no site needs to tokenize
/// just to answer "is this a template?".
pub fn has_jinja_syntax(content: &str) -> bool {
    content.contains("{{") || content.contains("{%") || content.contains("{#")
}

/// `text`, a YAML file of a dbt project or its profiles, read as dbt reads
/// each of them (dbt_common's `load_yaml_text`, PyYAML's `SafeLoader`):
/// where a mapping names a key twice, its later entry stands, in the place
/// of the first;
/// a merge key (`<<: *defaults`, `<<: [*a, *b]`) gives its mapping the
/// entries of the mappings it names that it does not write itself, an
/// earlier one's over a later one's, as `SafeConstructor.flatten_mapping`
/// does. A document holding no merge key and read strictly is kept as it
/// reads; only one the strict reading refuses, or one holding a merge key,
/// is read again so. What the strict reading gives where that fails.
pub fn load_yaml_text<T: serde::de::DeserializeOwned>(
    text: &str,
) -> Result<T, serde_yaml_ng::Error> {
    let merging = serde_yaml_ng::from_str::<LastKeyWins>(text)
        .ok()
        .filter(|LastKeyWins(value)| holds_merge_key(value));
    let strict = match serde_yaml_ng::from_str::<T>(text) {
        Ok(read) if merging.is_none() => return Ok(read),
        strict => strict,
    };
    let read = match merging {
        Some(LastKeyWins(value)) => Ok(value),
        None => serde_yaml_ng::from_str::<LastKeyWins>(text).map(|LastKeyWins(value)| value),
    };
    let reread = read
        .and_then(|mut value| {
            // A merged mapping may hold a merge key of its own.
            while holds_merge_key(&value) {
                value.apply_merge()?;
            }
            serde_yaml_ng::to_string(&value)
        })
        .and_then(|merged| serde_yaml_ng::from_str::<T>(&merged));
    // Where the merges do not apply (a merge key naming no mapping, which
    // PyYAML refuses), what the strict reading gives.
    reread.or(strict)
}

/// [`load_yaml_text`] of a document read as a [`serde_yaml_ng::Value`]: one
/// whose strict reading holds no merge key is read once.
pub fn load_yaml_value(text: &str) -> Result<serde_yaml_ng::Value, serde_yaml_ng::Error> {
    match serde_yaml_ng::from_str::<serde_yaml_ng::Value>(text) {
        Ok(value) if !holds_merge_key(&value) => Ok(value),
        Ok(_) | Err(_) => load_yaml_text(text),
    }
}

/// Whether a mapping in `value` names the merge key `<<`.
fn holds_merge_key(value: &serde_yaml_ng::Value) -> bool {
    match value {
        serde_yaml_ng::Value::Mapping(mapping) => mapping
            .iter()
            .any(|(key, value)| key.as_str() == Some("<<") || holds_merge_key(value)),
        serde_yaml_ng::Value::Sequence(items) => items.iter().any(holds_merge_key),
        serde_yaml_ng::Value::Tagged(tagged) => holds_merge_key(&tagged.value),
        serde_yaml_ng::Value::Null
        | serde_yaml_ng::Value::Bool(_)
        | serde_yaml_ng::Value::Number(_)
        | serde_yaml_ng::Value::String(_) => false,
    }
}

/// A YAML value whose mappings keep the last entry of a key named twice.
struct LastKeyWins(serde_yaml_ng::Value);

impl<'de> Deserialize<'de> for LastKeyWins {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer
            .deserialize_any(LastKeyWinsVisitor)
            .map(LastKeyWins)
    }
}

struct LastKeyWinsVisitor;

impl<'de> serde::de::Visitor<'de> for LastKeyWinsVisitor {
    type Value = serde_yaml_ng::Value;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("any YAML value")
    }

    fn visit_bool<E: serde::de::Error>(self, b: bool) -> Result<Self::Value, E> {
        Ok(serde_yaml_ng::Value::Bool(b))
    }

    fn visit_i64<E: serde::de::Error>(self, i: i64) -> Result<Self::Value, E> {
        Ok(serde_yaml_ng::Value::Number(i.into()))
    }

    fn visit_u64<E: serde::de::Error>(self, u: u64) -> Result<Self::Value, E> {
        Ok(serde_yaml_ng::Value::Number(u.into()))
    }

    fn visit_f64<E: serde::de::Error>(self, f: f64) -> Result<Self::Value, E> {
        Ok(serde_yaml_ng::Value::Number(f.into()))
    }

    fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Self::Value, E> {
        Ok(serde_yaml_ng::Value::String(s.to_owned()))
    }

    fn visit_string<E: serde::de::Error>(self, s: String) -> Result<Self::Value, E> {
        Ok(serde_yaml_ng::Value::String(s))
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(serde_yaml_ng::Value::Null)
    }

    fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(serde_yaml_ng::Value::Null)
    }

    fn visit_some<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        LastKeyWins::deserialize(deserializer).map(|LastKeyWins(value)| value)
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut items = Vec::new();
        while let Some(LastKeyWins(item)) = seq.next_element()? {
            items.push(item);
        }
        Ok(serde_yaml_ng::Value::Sequence(items))
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut mapping = serde_yaml_ng::Mapping::new();
        while let Some((LastKeyWins(key), LastKeyWins(value))) = map.next_entry()? {
            mapping.insert(key, value);
        }
        Ok(serde_yaml_ng::Value::Mapping(mapping))
    }

    fn visit_enum<A: serde::de::EnumAccess<'de>>(self, data: A) -> Result<Self::Value, A::Error> {
        use serde::de::VariantAccess;
        let (tag, contents): (String, A::Variant) = data.variant()?;
        if tag.is_empty() {
            return Err(serde::de::Error::custom("empty YAML tag is not allowed"));
        }
        let LastKeyWins(value) = contents.newtype_variant()?;
        Ok(serde_yaml_ng::Value::Tagged(Box::new(
            serde_yaml_ng::value::TaggedValue {
                tag: serde_yaml_ng::value::Tag::new(tag),
                value,
            },
        )))
    }
}

/// The file that makes a directory the root of a dbt project.
pub const PROJECT_FILE: &str = "dbt_project.yml";

/// The directories a dbt project's `dbt_project.yml` names, each from the
/// project's root, as dbt-core reads them: a key left out, or null, is
/// dbt's default.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(from = "PathKeys")]
pub struct ProjectPaths {
    /// `model-paths`, else `models`.
    pub model_paths: Vec<String>,
    /// `macro-paths`, else `macros`.
    pub macro_paths: Vec<String>,
    /// `snapshot-paths`, else `snapshots`.
    pub snapshot_paths: Vec<String>,
    /// `test-paths`, else `tests`.
    pub test_paths: Vec<String>,
    /// `analysis-paths`, else `analyses`.
    pub analysis_paths: Vec<String>,
    /// `seed-paths`, else `seeds`.
    pub seed_paths: Vec<String>,
    /// `packages-install-path`, else `dbt_packages`.
    pub packages_install_path: String,
}

/// The path keys of a `dbt_project.yml` as written.
#[derive(Default, Deserialize)]
struct PathKeys {
    #[serde(rename = "model-paths", default, deserialize_with = "path_list")]
    model_paths: Option<Vec<String>>,
    #[serde(rename = "macro-paths", default, deserialize_with = "path_list")]
    macro_paths: Option<Vec<String>>,
    #[serde(rename = "snapshot-paths", default, deserialize_with = "path_list")]
    snapshot_paths: Option<Vec<String>>,
    #[serde(rename = "test-paths", default, deserialize_with = "path_list")]
    test_paths: Option<Vec<String>>,
    #[serde(rename = "analysis-paths", default, deserialize_with = "path_list")]
    analysis_paths: Option<Vec<String>>,
    #[serde(rename = "seed-paths", default, deserialize_with = "path_list")]
    seed_paths: Option<Vec<String>>,
    #[serde(rename = "packages-install-path", default)]
    packages_install_path: Option<String>,
}

/// A key naming a list of directories; null stands for the key left out.
fn path_list<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Vec<String>>, D::Error> {
    deserializer.deserialize_option(PathList)
}

struct PathList;

impl<'de> serde::de::Visitor<'de> for PathList {
    type Value = Option<Vec<String>>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a list of paths")
    }

    fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_some<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_seq(self)
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut paths = Vec::new();
        while let Some(path) = seq.next_element::<String>()? {
            paths.push(path);
        }
        Ok(Some(paths))
    }
}

impl From<PathKeys> for ProjectPaths {
    fn from(keys: PathKeys) -> Self {
        let or = |paths: Option<Vec<String>>, default: &str| {
            paths.unwrap_or_else(|| vec![default.to_string()])
        };
        ProjectPaths {
            model_paths: or(keys.model_paths, "models"),
            macro_paths: or(keys.macro_paths, "macros"),
            snapshot_paths: or(keys.snapshot_paths, "snapshots"),
            test_paths: or(keys.test_paths, "tests"),
            analysis_paths: or(keys.analysis_paths, "analyses"),
            seed_paths: or(keys.seed_paths, "seeds"),
            packages_install_path: keys
                .packages_install_path
                .unwrap_or_else(|| "dbt_packages".to_string()),
        }
    }
}

impl Default for ProjectPaths {
    fn default() -> Self {
        PathKeys::default().into()
    }
}

impl ProjectPaths {
    /// The paths `project_file`, the text of a `dbt_project.yml`, names,
    /// or why it does not read: the key and its line and column.
    pub fn parse(project_file: &str) -> Result<Self, serde_yaml_ng::Error> {
        load_yaml_text(project_file)
    }

    /// The paths `project_file`, the text of a `dbt_project.yml`, names;
    /// dbt's defaults where there is no file or it does not read.
    pub fn read(project_file: Option<&str>) -> Self {
        project_file
            .and_then(|text| Self::parse(text).ok())
            .unwrap_or_default()
    }

    /// The paths the `dbt_project.yml` in `root` names, read from disk.
    pub fn at(root: &Path) -> Self {
        Self::read(
            std::fs::read_to_string(root.join(PROJECT_FILE))
                .ok()
                .as_deref(),
        )
    }

    /// Whether `relative`, a path from the project's root, lies under one
    /// of its macro paths.
    pub fn holds_macro(&self, relative: &Path) -> bool {
        let relative = lexically_normal(relative);
        self.macro_paths
            .iter()
            .any(|dir| relative.starts_with(lexically_normal(Path::new(dir))))
    }
}

/// The dbt projects of a tree of files: the working tree, or a commit's.
pub trait ProjectTree {
    /// The paths of the project whose root is `dir`; `None` where `dir`
    /// holds no `dbt_project.yml`.
    fn project_at(&self, dir: &Path) -> Option<ProjectPaths>;

    /// Every project the tree has read, by root.
    fn projects(&self) -> Vec<(PathBuf, ProjectPaths)>;
}

/// Whether `file` holds macros: a project's path makes it a macro file
/// ([`macro_path_owner`]).
pub fn is_macro_file(tree: &impl ProjectTree, file: &Path) -> bool {
    macro_path_owner(tree, file).is_some()
}

/// The dbt project whose path makes a file a macro file, by its root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MacroPathOwner {
    /// One of the project's macro paths holds the file.
    Project(PathBuf),
    /// The default macro path of a package in the project's packages
    /// install path that holds no `dbt_project.yml` of its own.
    InstalledPackage(PathBuf),
}

impl MacroPathOwner {
    /// The root of the project whose path decided.
    pub fn root(&self) -> &Path {
        match self {
            MacroPathOwner::Project(root) | MacroPathOwner::InstalledPackage(root) => root,
        }
    }
}

/// What one project's paths make of a file.
enum Held {
    /// A model, snapshot, test or analysis path holds it: a SQL node.
    Node,
    /// A macro file.
    Macro(MacroPathOwner),
}

/// Where a file stands to the project whose paths are asked about it.
#[derive(Clone, Copy)]
enum Standing {
    /// The project is the nearest one above the file.
    Inside,
    /// The file is in no project.
    Outside,
}

/// The project whose path makes `file` a macro file, if one does: the first
/// of [`macro_path_owners`], by root.
pub fn macro_path_owner(tree: &impl ProjectTree, file: &Path) -> Option<MacroPathOwner> {
    macro_path_owners(tree, file).into_iter().next()
}

/// The projects whose paths make `file` a macro file, by root; none where
/// it is not one.
///
/// The nearest project above `file` decides its files alone: its packages
/// install path, then its model, snapshot, test and analysis paths, which
/// keep a file SQL, then its macro paths; no other project's path claims
/// them. A file in no project is a macro file of every project whose macro
/// path holds it, wherever that path points, unless a project's model,
/// snapshot, test or analysis path holds it; a macro path or packages
/// install path that resolves to its project's root or a directory above
/// holds no such file.
pub fn macro_path_owners(tree: &impl ProjectTree, file: &Path) -> Vec<MacroPathOwner> {
    let file = lexically_normal(file);
    let enclosing = file
        .ancestors()
        .skip(1)
        .find_map(|dir| Some((dir.to_path_buf(), tree.project_at(dir)?)));
    if let Some((root, paths)) = enclosing {
        return match held(tree, &root, &paths, &file, Standing::Inside) {
            Some(Held::Macro(owner)) => vec![owner],
            Some(Held::Node) | None => Vec::new(),
        };
    }
    let mut owners = Vec::new();
    for (root, paths) in tree.projects() {
        match held(tree, &root, &paths, &file, Standing::Outside) {
            Some(Held::Node) => return Vec::new(),
            Some(Held::Macro(owner)) => owners.push(owner),
            None => {}
        }
    }
    owners.sort_by(|a, b| a.root().cmp(b.root()));
    owners
}

/// What the project at `root`, of `paths`, makes of `file`, a lexically
/// normal path standing to it as `standing` says: `None` where none of its
/// paths holds it.
fn held(
    tree: &impl ProjectTree,
    root: &Path,
    paths: &ProjectPaths,
    file: &Path,
    standing: Standing,
) -> Option<Held> {
    // A path at the project's root or above holds no file outside it.
    let claims = |dir: &Path| match standing {
        Standing::Inside => true,
        Standing::Outside => !root.starts_with(dir),
    };
    let install = lexically_normal(&root.join(&paths.packages_install_path));
    if let Some(in_install) = file
        .strip_prefix(&install)
        .ok()
        .filter(|_| claims(&install))
    {
        // The package directory, then the file's path in it.
        let mut parts = in_install.components();
        let bare_package_macro = parts.next().is_some_and(|package| {
            tree.project_at(&install.join(package)).is_none()
                && ProjectPaths::default().holds_macro(parts.as_path())
        });
        return bare_package_macro
            .then(|| Held::Macro(MacroPathOwner::InstalledPackage(root.to_path_buf())));
    }
    let under = |dir: &String| file.starts_with(lexically_normal(&root.join(dir)));
    if paths
        .model_paths
        .iter()
        .chain(&paths.snapshot_paths)
        .chain(&paths.test_paths)
        .chain(&paths.analysis_paths)
        .any(under)
    {
        return Some(Held::Node);
    }
    paths
        .macro_paths
        .iter()
        .filter(|dir| claims(&lexically_normal(&root.join(dir))))
        .any(under)
        .then(|| Held::Macro(MacroPathOwner::Project(root.to_path_buf())))
}

/// The working tree's dbt projects as one run reads them: each
/// `dbt_project.yml` is read once, however many callers ask, and a clone
/// shares the reading.
#[derive(Debug, Default, Clone)]
pub struct ProjectsOnDisk {
    read: Rc<RefCell<BTreeMap<PathBuf, Option<ProjectPaths>>>>,
}

impl ProjectTree for ProjectsOnDisk {
    fn project_at(&self, dir: &Path) -> Option<ProjectPaths> {
        if let Some(read) = self.read.borrow().get(dir) {
            return read.clone();
        }
        // A `dbt_project.yml` that does not read makes a project of dbt's
        // defaults.
        let read = dir
            .join(PROJECT_FILE)
            .exists()
            .then(|| ProjectPaths::at(dir));
        self.read
            .borrow_mut()
            .insert(dir.to_path_buf(), read.clone());
        read
    }

    fn projects(&self) -> Vec<(PathBuf, ProjectPaths)> {
        self.read
            .borrow()
            .iter()
            .filter_map(|(root, paths)| Some((root.clone(), paths.clone()?)))
            .collect()
    }
}

/// `path` with each `.` part dropped and each `..` part taking the part
/// before it away, read without the file system.
pub fn lexically_normal(path: &Path) -> PathBuf {
    let mut normal = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => match normal.components().next_back() {
                Some(Component::Normal(_)) => {
                    normal.pop();
                }
                // `..` at the root is the root.
                Some(Component::RootDir | Component::Prefix(_)) => {}
                Some(Component::ParentDir | Component::CurDir) | None => normal.push(component),
            },
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                normal.push(component)
            }
        }
    }
    normal
}

/// Run the substitution pre-passes over `source`, then `render` the
/// substituted text. The pre-passes' unresolved references go to
/// `unresolved` and fold into the returned placeholder statistics, so
/// they lower analysis confidence.
pub fn render_substituted<E>(
    source: &str,
    dialect: &Option<crate::dialect::DialectRef>,
    substitution: &SubstitutionConfig,
    vars: Option<&VariableContext>,
    unresolved: impl FnOnce(&[PlaceholderRecord]),
    render: impl FnOnce(&str) -> Result<RenderArtifacts, E>,
) -> Result<RenderArtifacts, E> {
    let deploy = deployvars::preprocess(source, dialect, substitution, vars);
    unresolved(&deploy.placeholders);
    let deploy_stats =
        crate::analyzer::compute_placeholder_stats(&deploy.sql, &deploy.placeholders);
    let prepared = snowsql::preprocess(&deploy.sql, dialect, vars);
    let snow_stats =
        crate::analyzer::compute_placeholder_stats(&prepared.sql, &prepared.placeholders);
    let mut artifacts = render(&prepared.sql)?;
    artifacts.placeholders.absorb(&snow_stats);
    artifacts.placeholders.absorb(&deploy_stats);
    // Later stage first — its offsets are the ones most likely to index
    // the analyzed text; each attach is gated on byte-identity.
    artifacts.extend_placeholder_spans_if_current(&prepared.sql, &prepared.placeholders);
    artifacts.extend_placeholder_spans_if_current(&deploy.sql, &deploy.placeholders);
    Ok(artifacts)
}

pub use artifacts::RenderArtifacts;
pub use context::{
    CommandLineOnlyKey, ContextError, SnowsqlConfigRead, SubstitutionSettings, VariableContext,
    VariableSource,
};
pub use deployvars::{
    DeployVarsPrep, SubstitutionConfig, SubstitutionConfigError, SubstitutionSyntax,
    UnresolvedVariables,
};
pub use records::{DependencyKind, DependencyRecord, PlaceholderKind, PlaceholderRecord};
pub use source_map::{LineSource, RunOrigin, SourceMap, SourceMapStats};

#[cfg(test)]
mod tests {
    use super::*;

    // A project's path keys read as dbt-core reads them: a key left out or
    // null, or a file that does not read, is dbt's default.
    #[test]
    fn a_projects_path_keys_read_with_dbts_defaults() {
        let defaults = ProjectPaths {
            model_paths: vec!["models".to_string()],
            macro_paths: vec!["macros".to_string()],
            snapshot_paths: vec!["snapshots".to_string()],
            test_paths: vec!["tests".to_string()],
            analysis_paths: vec!["analyses".to_string()],
            seed_paths: vec!["seeds".to_string()],
            packages_install_path: "dbt_packages".to_string(),
        };
        for text in [
            None,
            Some("name: p\n"),
            Some("macro-paths: null\n"),
            Some("a: [\n"),
        ] {
            assert_eq!(ProjectPaths::read(text), defaults, "{text:?}");
        }
        let custom = ProjectPaths::read(Some(
            "name: p\nmodel-paths: [transform]\nmacro-paths: [m1, ./m2/]\nsnapshot-paths: [snaps]\ntest-paths: [checks]\nanalysis-paths: [adhoc, more]\npackages-install-path: vendor\n",
        ));
        assert_eq!(custom.model_paths, ["transform"]);
        assert_eq!(custom.snapshot_paths, ["snaps"]);
        assert_eq!(custom.test_paths, ["checks"]);
        assert_eq!(custom.analysis_paths, ["adhoc", "more"]);
        assert_eq!(custom.packages_install_path, "vendor");
        assert!(custom.holds_macro(Path::new("m1/a.sql")));
        assert!(custom.holds_macro(Path::new("m2/sub/b.sql")));
        assert!(!custom.holds_macro(Path::new("macros/c.sql")));
        assert!(!custom.holds_macro(Path::new("m10/d.sql")));
    }

    // A path key that is not a list is refused, by its name and where it
    // is written, as dbt refuses the project.
    #[test]
    fn a_path_key_that_is_not_a_list_is_refused_where_it_is_written() {
        for (key, text) in [
            ("macro-paths", "name: p\nmacro-paths: \"my_macros\"\n"),
            ("model-paths", "name: p\nmodel-paths: models\n"),
            ("snapshot-paths", "name: p\nsnapshot-paths: snaps\n"),
            ("test-paths", "name: p\ntest-paths: tests\n"),
            ("analysis-paths", "name: p\nanalysis-paths: analyses\n"),
        ] {
            let refused = ProjectPaths::parse(text)
                .expect_err("a string is not a list")
                .to_string();
            for said in [key, "expected a list of paths", "line 2 column"] {
                assert!(refused.contains(said), "{key}: {refused}");
            }
        }
    }

    /// The projects of a tree, by root, each from its `dbt_project.yml`.
    struct Projects(BTreeMap<PathBuf, ProjectPaths>);

    impl ProjectTree for Projects {
        fn project_at(&self, dir: &Path) -> Option<ProjectPaths> {
            self.0.get(dir).cloned()
        }

        fn projects(&self) -> Vec<(PathBuf, ProjectPaths)> {
            self.0
                .iter()
                .map(|(root, paths)| (root.clone(), paths.clone()))
                .collect()
        }
    }

    // A macro path holds macros wherever it points: under the project,
    // beside it, or in a package it installs.
    #[test]
    fn a_macro_path_holds_its_files_wherever_it_points() {
        let tree = Projects(BTreeMap::from([
            (
                PathBuf::from("/up/proj"),
                ProjectPaths::read(Some("name: p\nmacro-paths: [macros, ../shared/macros]\n")),
            ),
            (
                PathBuf::from("/up/proj/dbt_packages/pkg"),
                ProjectPaths::read(Some("name: pkg\nmacro-paths: [pmacros]\n")),
            ),
        ]));
        for (file, holds) in [
            ("/up/proj/macros/a.sql", true),
            ("/up/shared/macros/b.sql", true),
            ("/up/shared/macros/deep/c.sql", true),
            ("/up/shared/models/d.sql", false),
            ("/up/proj/models/e.sql", false),
            ("/up/proj/dbt_packages/bare/macros/f.sql", true),
            ("/up/proj/dbt_packages/pkg/pmacros/g.sql", true),
            ("/up/proj/dbt_packages/pkg/macros/h.sql", false),
            ("/elsewhere/macros/i.sql", false),
        ] {
            assert_eq!(is_macro_file(&tree, Path::new(file)), holds, "{file}");
        }
    }

    // The project a file is in decides it alone: another project's macro
    // path (`../b/models/common`, `..`) never claims it, and its own model,
    // snapshot, test and analysis paths keep it SQL whatever its macro
    // paths say. A file in no project is a macro file of the first project,
    // by root, whose macro path holds it, unless a project's model path
    // holds it; a macro path or packages install path at its project's
    // root or above (`.`, `..`, `/`) holds no such file.
    #[test]
    fn the_project_a_file_is_in_decides_it_and_a_macro_path_claims_only_loose_files() {
        let read = |text: &str| ProjectPaths::read(Some(text));
        let tree = Projects(BTreeMap::from([
            (
                PathBuf::from("/r/a"),
                read("name: a\nmacro-paths: [macros, ../b/models/common, ../loose/macros]\n"),
            ),
            (PathBuf::from("/r/b"), read("name: b\n")),
            (
                PathBuf::from("/r/p"),
                read("name: p\nmacro-paths: [macros, '..', '.']\n"),
            ),
            (
                PathBuf::from("/r/q"),
                read("name: q\nmodel-paths: [models, ../loose/models]\n"),
            ),
            (
                PathBuf::from("/r/z"),
                read("name: z\nmacro-paths: [../loose/macros]\n"),
            ),
            (
                PathBuf::from("/r/t"),
                read(
                    "name: t\nmacro-paths: ['.']\ntest-paths: [checks]\nanalysis-paths: [adhoc]\n",
                ),
            ),
            (
                PathBuf::from("/r/u/v"),
                read("name: v\nmacro-paths: ['../..', '../../../r/u/v/..', /, ../v]\n"),
            ),
            (
                PathBuf::from("/r/k"),
                read("name: k\npackages-install-path: '..'\n"),
            ),
            (
                PathBuf::from("/r/m"),
                read("name: m\npackages-install-path: /\n"),
            ),
            (
                PathBuf::from("/r/i"),
                read("name: i\npackages-install-path: ../vendor\n"),
            ),
        ]));
        let project = |root: &str| Some(MacroPathOwner::Project(PathBuf::from(root)));
        let package = |root: &str| Some(MacroPathOwner::InstalledPackage(PathBuf::from(root)));
        for (file, owner) in [
            ("/r/b/models/common/c.sql", None),
            ("/r/q/models/m.sql", None),
            ("/r/q/macros/qm.sql", project("/r/q")),
            ("/r/p/models/pm.sql", None),
            ("/r/p/snapshots/s.sql", None),
            ("/r/p/macros/pmac.sql", project("/r/p")),
            ("/r/p/analyses/an.sql", None),
            ("/r/p/tests/pt.sql", None),
            ("/r/p/other/po.sql", project("/r/p")),
            ("/r/t/checks/c.sql", None),
            ("/r/t/adhoc/a.sql", None),
            ("/r/t/tests/t.sql", project("/r/t")),
            ("/r/t/analyses/an.sql", project("/r/t")),
            ("/r/u/v/x.sql", project("/r/u/v")),
            ("/r/u/w.sql", None),
            ("/w.sql", None),
            ("/r/a/macros/am.sql", project("/r/a")),
            ("/r/loose.sql", None),
            ("/r/loose/macros/l.sql", project("/r/a")),
            ("/r/loose/models/lm.sql", None),
            ("/elsewhere/e.sql", None),
            ("/r/loosepkg/macros/lp.sql", None),
            ("/elsewhere/macros/e.sql", None),
            ("/r/vendor/pkg/macros/vm.sql", package("/r/i")),
        ] {
            assert_eq!(macro_path_owner(&tree, Path::new(file)), owner, "{file}");
        }
        // A loose macro file is every holding project's; an enclosed one only
        // its own project's.
        let roots = |file: &str| -> Vec<PathBuf> {
            macro_path_owners(&tree, Path::new(file))
                .iter()
                .map(|owner| owner.root().to_path_buf())
                .collect()
        };
        assert_eq!(
            roots("/r/loose/macros/l.sql"),
            ["/r/a", "/r/z"].map(PathBuf::from)
        );
        assert_eq!(roots("/r/p/macros/pmac.sql"), [PathBuf::from("/r/p")]);
        assert_eq!(roots("/r/b/models/common/c.sql"), Vec::<PathBuf>::new());
    }

    // A document read as a value reads as `load_yaml_text` reads it: plain,
    // a key named twice, merge keys, a merge key under a tag, and one that
    // does not read.
    #[test]
    fn a_document_read_as_a_value_reads_as_the_text_reading_gives_it() {
        let documents = [
            "models:\n  - name: m\n    config:\n      schema: s\n",
            "a: 1\na: 2\nb: [x, y]\n",
            "d: &d\n  x: 1\n  y: 2\ne:\n  <<: *d\n  y: 3\n",
            "d: &d\n  x: 1\nf: &f\n  z: 2\ne:\n  <<: [*d, *f]\n  x: 0\n  x: 4\n",
            "t: !custom\n  <<: {x: 1}\n",
            "a: [unclosed\n",
            "",
        ];
        for text in documents {
            let as_value = load_yaml_value(text).map_err(|error| error.to_string());
            let as_text =
                load_yaml_text::<serde_yaml_ng::Value>(text).map_err(|error| error.to_string());
            assert_eq!(as_value, as_text, "{text:?}");
        }
    }
}
