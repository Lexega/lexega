// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Named value lists declared under `lists:` in a rule file.
//!
//! Values and patterns are stored ASCII-upper-cased, and a probe is
//! folded the same way, so matching ignores ASCII case.

use std::collections::BTreeMap;

use serde_json::Value;

use super::compile::glob_match;
use super::loader::{ListField, ListShapeProblem, LoadError};
use super::schema::{V1ListBody, V1ListEntry};

/// The values and glob patterns of one list.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ValueList {
    values: Vec<String>,
    patterns: Vec<String>,
}

impl ValueList {
    /// True when `value` equals a list value or matches a list pattern,
    /// ignoring ASCII case.
    pub fn holds(&self, value: &str) -> bool {
        let folded = value.to_ascii_uppercase();
        self.values.contains(&folded) || self.patterns.iter().any(|p| glob_match(p, &folded))
    }
}

/// Named lists, by name.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ValueLists {
    lists: BTreeMap<String, ValueList>,
}

impl ValueLists {
    /// The list called `name`; names are exact.
    pub fn get(&self, name: &str) -> Option<&ValueList> {
        self.lists.get(name)
    }

    /// List names in sorted order.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.lists.keys().map(String::as_str)
    }
}

/// What a file's `lists:` did to the built-in table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListChanges {
    /// Lists the file defines, sorted.
    pub defined: Vec<String>,
    /// Built-in lists the file extends or replaces, sorted.
    pub changed_builtins: Vec<String>,
}

/// How an entry changes the table, once its shape is known.
#[derive(Clone, Copy)]
enum Change {
    Extend,
    Replace,
}

/// An entry once its shape is known.
enum Shape {
    Definition(V1ListBody),
    Change(Change, V1ListBody),
}

fn has_entries(body: &V1ListBody) -> bool {
    body.values.as_deref().is_some_and(|v| !v.is_empty())
        || body.patterns.as_deref().is_some_and(|p| !p.is_empty())
}

fn shape(list: &str, entry: V1ListEntry) -> Result<Shape, LoadError> {
    let V1ListEntry {
        values,
        patterns,
        extend,
        replace,
    } = entry;
    let definition =
        (values.is_some() || patterns.is_some()).then_some(V1ListBody { values, patterns });
    let problem = |problem| LoadError::ListEntryShape {
        list: list.to_string(),
        problem,
    };
    let non_empty = |body: V1ListBody| {
        if has_entries(&body) {
            Ok(body)
        } else {
            Err(problem(ListShapeProblem::NoEntries))
        }
    };
    match (definition, extend, replace) {
        (Some(body), None, None) => non_empty(body).map(Shape::Definition),
        (None, Some(body), None) => non_empty(body).map(|b| Shape::Change(Change::Extend, b)),
        (None, None, Some(body)) => Ok(Shape::Change(Change::Replace, body)),
        (None, None, None) => Err(problem(ListShapeProblem::NoEntries)),
        (Some(_), Some(_), _) | (Some(_), None, Some(_)) | (None, Some(_), Some(_)) => {
            Err(problem(ListShapeProblem::MoreThanOne))
        }
    }
}

/// Fold string items to upper case, rejecting any other YAML type.
fn fold_items(
    list: &str,
    field: ListField,
    items: Option<&[Value]>,
) -> Result<Vec<String>, LoadError> {
    items
        .into_iter()
        .flatten()
        .map(|item| match item {
            Value::String(s) => Ok(s.to_ascii_uppercase()),
            other => Err(LoadError::ListValueNotString {
                list: list.to_string(),
                field,
                value: other.to_string(),
            }),
        })
        .collect()
}

fn build_list(list: &str, body: &V1ListBody) -> Result<ValueList, LoadError> {
    let values = fold_items(list, ListField::Values, body.values.as_deref())?;
    let patterns = fold_items(list, ListField::Patterns, body.patterns.as_deref())?;
    if let Some(bad) = patterns.iter().find(|p| p.chars().all(|c| c == '*')) {
        return Err(LoadError::InvalidListPattern {
            list: list.to_string(),
            pattern: bad.clone(),
        });
    }
    Ok(ValueList { values, patterns })
}

/// Build the built-in table: every entry must be a definition.
pub(crate) fn define_builtin_lists(
    entries: BTreeMap<String, V1ListEntry>,
) -> Result<ValueLists, LoadError> {
    let mut lists = BTreeMap::new();
    for (name, entry) in entries {
        match shape(&name, entry)? {
            Shape::Definition(body) => {
                let list = build_list(&name, &body)?;
                lists.insert(name, list);
            }
            Shape::Change(..) => {
                return Err(LoadError::ListEntryShape {
                    list: name,
                    problem: ListShapeProblem::NotADefinition,
                })
            }
        }
    }
    Ok(ValueLists { lists })
}

/// The built-ins, layered with the file's definitions, extensions and
/// replacements.
pub(crate) fn apply_file_lists(
    builtin: &ValueLists,
    entries: BTreeMap<String, V1ListEntry>,
) -> Result<(ValueLists, ListChanges), LoadError> {
    let mut table = builtin.clone();
    let mut changes = ListChanges::default();
    for (name, entry) in entries {
        match shape(&name, entry)? {
            Shape::Definition(body) => {
                if builtin.lists.contains_key(&name) {
                    return Err(LoadError::RedefinedBuiltinList { list: name });
                }
                let list = build_list(&name, &body)?;
                table.lists.insert(name.clone(), list);
                changes.defined.push(name);
            }
            Shape::Change(change, body) => {
                let new = build_list(&name, &body)?;
                let target = table
                    .lists
                    .get_mut(&name)
                    .ok_or_else(|| LoadError::UnknownBuiltinList { list: name.clone() })?;
                match change {
                    Change::Extend => {
                        target.values.extend(new.values);
                        target.patterns.extend(new.patterns);
                    }
                    Change::Replace => *target = new,
                }
                changes.changed_builtins.push(name);
            }
        }
    }
    Ok((table, changes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::loader::{load_v1_rules, load_v1_rules_from_json};

    fn entries(yaml: &str) -> BTreeMap<String, V1ListEntry> {
        serde_yaml_ng::from_str(yaml).expect("test yaml parses")
    }

    fn builtin() -> ValueLists {
        define_builtin_lists(entries(
            "credential_references: {patterns: [\"vault:*\"]}\n\
             credential_dummies: {values: [REPLACE_ME, \"\"]}\n",
        ))
        .expect("built-in lists define")
    }

    fn apply(yaml: &str) -> Result<(ValueLists, ListChanges), LoadError> {
        apply_file_lists(&builtin(), entries(yaml))
    }

    fn shape_of(result: Result<(ValueLists, ListChanges), LoadError>) -> ListShapeProblem {
        match result {
            Err(LoadError::ListEntryShape { problem, .. }) => problem,
            other => panic!("expected a shape error, got {other:?}"),
        }
    }

    #[test]
    fn definition_extend_and_replace_resolve() {
        let (table, changes) = apply(
            "my_list: {values: [Set_By_Deploy]}\n\
             credential_references: {extend: {patterns: [\"{{*secrets.*}}\"]}}\n",
        )
        .expect("loads");
        let get = |n: &str| table.get(n).expect("list exists");
        assert!(get("my_list").holds("set_by_deploy"));
        assert!(get("credential_references").holds("VAULT:kv/x"));
        assert!(get("credential_references").holds("{{ secrets.pw }}"));
        assert!(!get("credential_references").holds("S3cret!"));
        assert_eq!(
            changes,
            ListChanges {
                defined: vec!["my_list".to_string()],
                changed_builtins: vec!["credential_references".to_string()],
            }
        );
        assert_eq!(
            table.names().collect::<Vec<_>>(),
            ["credential_dummies", "credential_references", "my_list"]
        );
    }

    #[test]
    fn replace_swaps_contents() {
        let (table, _) =
            apply("credential_dummies: {replace: {values: [CHANGEME]}}").expect("loads");
        let dummies = table.get("credential_dummies").expect("list exists");
        assert!(dummies.holds("changeme"));
        assert!(!dummies.holds("REPLACE_ME"));

        let (table, _) = apply("credential_dummies: {replace: {}}").expect("loads");
        let dummies = table.get("credential_dummies").expect("list exists");
        assert!(!dummies.holds("changeme"));
        assert!(!dummies.holds(""));
    }

    #[test]
    fn non_string_value_is_rejected() {
        assert!(matches!(
            apply("my_list: {values: [1234]}"),
            Err(LoadError::ListValueNotString { list, field: ListField::Values, .. }) if list == "my_list"
        ));
        assert!(matches!(
            apply("my_list: {patterns: [null]}"),
            Err(LoadError::ListValueNotString { list, field: ListField::Patterns, .. }) if list == "my_list"
        ));
    }

    #[test]
    fn star_only_or_empty_pattern_is_rejected() {
        for pattern in ["\"*\"", "\"**\"", "\"\""] {
            let result = apply(&format!("my_list: {{patterns: [{pattern}]}}"));
            assert!(
                matches!(result, Err(LoadError::InvalidListPattern { .. })),
                "{pattern}: {result:?}"
            );
        }
    }

    #[test]
    fn entry_shapes() {
        assert_eq!(
            shape_of(apply("l: {values: [a], extend: {values: [b]}}")),
            ListShapeProblem::MoreThanOne
        );
        assert_eq!(
            shape_of(apply("l: {values: []}")),
            ListShapeProblem::NoEntries
        );
        assert_eq!(
            shape_of(apply("credential_dummies: {extend: {values: []}}")),
            ListShapeProblem::NoEntries
        );
        assert_eq!(
            shape_of(apply(
                "credential_dummies: {extend: {values: [a]}, replace: {values: [b]}}"
            )),
            ListShapeProblem::MoreThanOne
        );
        assert_eq!(
            shape_of(apply("credential_dummies: {extend: {}}")),
            ListShapeProblem::NoEntries
        );
        let builtin_with_extend = define_builtin_lists(entries("l: {extend: {values: [a]}}"));
        assert_eq!(
            shape_of(builtin_with_extend.map(|t| (t, ListChanges::default()))),
            ListShapeProblem::NotADefinition
        );
    }

    #[test]
    fn unknown_builtin_extend_is_rejected() {
        assert_eq!(
            apply("no_such: {extend: {values: [a]}}").unwrap_err(),
            LoadError::UnknownBuiltinList {
                list: "no_such".to_string()
            }
        );
        assert_eq!(
            apply("no_such: {replace: {values: [a]}}").unwrap_err(),
            LoadError::UnknownBuiltinList {
                list: "no_such".to_string()
            }
        );
    }

    #[test]
    fn copied_builtin_file_is_rejected_with_advice() {
        let err = apply("credential_dummies: {values: [X]}").unwrap_err();
        assert_eq!(
            err,
            LoadError::RedefinedBuiltinList {
                list: "credential_dummies".to_string()
            }
        );
        assert!(err.to_string().contains("drop its `lists:`"));
    }

    #[test]
    fn duplicate_inside_extend_is_harmless() {
        let (table, _) =
            apply("credential_dummies: {extend: {values: [dup, DUP, Dup]}}").expect("loads");
        let dummies = table.get("credential_dummies").expect("list exists");
        assert!(dummies.holds("dup"));
        assert!(dummies.holds("REPLACE_ME"));
    }

    #[test]
    fn items_inside_extend_and_replace_are_validated() {
        for body in ["extend", "replace"] {
            assert!(
                matches!(
                    apply(&format!(
                        "credential_dummies: {{{body}: {{values: [1234]}}}}"
                    )),
                    Err(LoadError::ListValueNotString {
                        field: ListField::Values,
                        ..
                    })
                ),
                "{body} non-string"
            );
            assert!(
                matches!(
                    apply(&format!(
                        "credential_dummies: {{{body}: {{patterns: [\"*\"]}}}}"
                    )),
                    Err(LoadError::InvalidListPattern { .. })
                ),
                "{body} star-only"
            );
        }
    }

    #[test]
    fn lists_only_file_loads_and_empty_file_does_not() {
        assert!(load_v1_rules("lists:\n  my_list: {values: [a]}\n").is_ok());
        assert!(load_v1_rules("rules: []\n").is_ok());
        assert_eq!(
            load_v1_rules("rule: []\n").unwrap_err(),
            LoadError::NoRulesOrLists
        );
    }

    #[test]
    fn duplicate_list_name_is_rejected_in_yaml_and_json() {
        let yaml = "lists:\n  my_list: {values: [a]}\n  my_list: {values: [b]}\n";
        let duplicate = LoadError::DuplicateList {
            list: "my_list".to_string(),
        };
        assert_eq!(load_v1_rules(yaml).unwrap_err(), duplicate);
        let json = br#"{"lists":{"my_list":{"values":["a"]},"my_list":{"values":["b"]}}}"#;
        assert_eq!(load_v1_rules_from_json(json).unwrap_err(), duplicate);
    }
}
