// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! V1 rule-file wire types + JSON Schema generator.
//!
//! Defines the YAML/JSON shape of a v1 fact-based rules file:
//! [`V1RulesFile`] + [`V1RuleEntry`]. Both deserialize under all
//! builds; under `--features schema` they also derive `JsonSchema`
//! for the customer-facing IDE schema.
//!
//! The `triggers:` slot is typed as `serde_json::Value` because the
//! v1 predicate DSL uses `<field.path>: <op-block>` keys keyed by
//! the actual fields on [`crate::facts::StatementFacts`]. Its schema
//! is built by walking the schemars-derived `StatementFacts` tree at
//! schema-generation time — every valid path becomes an explicit
//! property on the `triggers` object, so IDE auto-complete works and
//! invalid paths surface as schema errors without a runtime evaluation.

use serde::Deserialize;

use crate::facts::RiskLevel;

use super::signal::EmissionMode;

/// Wire version of the v1 rules file format. Bump on any breaking
/// schema change; the embedded `schema_version` const lets customer
/// tooling pin to a specific revision.
pub const V1_RULES_SCHEMA_VERSION: u32 = 1;

/// A custom rules file. Each entry under `rules:` either defines a
/// new rule or overrides settings on an existing built-in rule.
#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct V1RulesFile {
    /// List of rule entries. Rules are evaluated in the order they
    /// appear in the file.
    pub rules: Vec<V1RuleEntry>,
}

/// A single rule entry. Each entry either defines a new rule or
/// overrides settings on an existing built-in rule of the same `id`.
///
/// **To define a new rule:** provide `id`, `risk_level`, `message`,
/// and `triggers`.
///
/// **To override a built-in:** omit `triggers` and set only the
/// fields you want to change. Any combination of `risk_level`,
/// `message`, and `enabled` is allowed; the built-in's other
/// settings are kept as-is. Overrides cannot change a rule's
/// `triggers`, `emission`, or `per_statement` — those stay tied to
/// the built-in. Overriding an `id` that does not match any built-in
/// is rejected at load time.
#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct V1RuleEntry {
    /// Stable rule identifier (e.g. `GRT-WITH-OPT`). Policies and
    /// exceptions reference rules by this id.
    pub id: String,
    /// Identifiers this rule was previously published under. A policy or
    /// exception that still references an old id continues to resolve to
    /// this rule; reports and SARIF always use the current `id`. Only
    /// valid on a full rule definition, and an id here may not collide
    /// with any live rule id. Defaults to none.
    #[serde(default)]
    pub former_ids: Vec<String>,
    /// Severity attached to every signal this rule fires. Required
    /// when defining a new rule. When overriding a built-in, omit to
    /// keep the built-in's severity.
    #[serde(default)]
    pub risk_level: Option<RiskLevel>,
    /// Message shown with each signal this rule fires. Supports
    /// `{path.to.field}` placeholders that are filled in with values
    /// from the matched statement. Required when defining a new
    /// rule. When overriding a built-in, omit to keep the built-in's
    /// message.
    #[serde(default)]
    pub message: Option<String>,
    /// Set to `false` to disable this rule. Defaults to `true`. To
    /// turn off a built-in, set this to `false` in an override entry
    /// (one whose `id` matches the built-in and that has no
    /// `triggers`).
    #[serde(default)]
    pub enabled: Option<bool>,
    /// How many signals fire per matched statement. Defaults to
    /// `once`. Cannot be set when overriding a built-in.
    #[serde(default)]
    pub emission: Option<EmissionMode>,
    /// When `true`, every signal this rule fires is kept as its own
    /// finding instead of being merged with similar findings of the
    /// same rule. Use for compliance-style rules where each
    /// occurrence is a separate review item (for example,
    /// `SNW-UNKNOWN`, where each unrecognized statement is its own
    /// item). Defaults to `false`. Cannot be set when overriding a
    /// built-in.
    #[serde(default)]
    pub per_statement: Option<bool>,
    /// The conditions that decide whether this rule fires on a SQL
    /// statement. See the `Predicate` definition for the available
    /// fields, operators, and combinators. Required when defining a
    /// new rule. Omit when overriding a built-in — the built-in's
    /// triggers are reused as-is.
    #[serde(default)]
    #[cfg_attr(
        feature = "schema",
        schemars(schema_with = "predicate_schema_optional")
    )]
    pub triggers: Option<serde_json::Value>,
}

// ──────────────────────────────────────────────────────────────────────
// Schema generation. Feature-gated.
// ──────────────────────────────────────────────────────────────────────

#[cfg(feature = "schema")]
mod schema_gen {
    use std::collections::{BTreeMap, HashSet, VecDeque};

    use schemars::gen::SchemaGenerator;
    use schemars::schema::{
        ArrayValidation, InstanceType, ObjectValidation, RootSchema, Schema, SchemaObject,
        SingleOrVec, SubschemaValidation,
    };
    use schemars::Map;
    use serde_json::Value;

    use super::{V1RulesFile, V1_RULES_SCHEMA_VERSION};

    /// Recursion limit when walking the facts schema. Each struct
    /// descent counts one step; recursive types (expression trees)
    /// terminate as `Opaque` once the limit is hit.
    const MAX_WALK_DEPTH: usize = 14;

    /// Build the JSON Schema for the v1 predicate DSL.
    ///
    /// Wired into [`super::V1RuleEntry::triggers`] via
    /// `#[schemars(schema_with = "predicate_schema_optional")]`.
    pub fn predicate_schema(generator: &mut SchemaGenerator) -> Schema {
        register_predicate_definitions(generator);
        Schema::Object(ref_obj("Predicate"))
    }

    /// Variant of [`predicate_schema`] that also accepts `null`.
    /// `V1RuleEntry::triggers` is `Option<...>` because absent
    /// `triggers` marks a partial override that inherits the built-in's
    /// predicate; the JSON schema for the field must permit the null /
    /// missing case to match that semantics.
    pub fn predicate_schema_optional(generator: &mut SchemaGenerator) -> Schema {
        register_predicate_definitions(generator);
        Schema::Object(SchemaObject {
            subschemas: Some(Box::new(SubschemaValidation {
                any_of: Some(vec![
                    Schema::Object(typed_instance(InstanceType::Null)),
                    Schema::Object(ref_obj("Predicate")),
                ]),
                ..Default::default()
            })),
            ..Default::default()
        })
    }

    /// Top-level schema bin entry point. Produces the full
    /// `custom_rules.schema.json` artifact.
    pub fn generate_v1_rules_schema() -> RootSchema {
        let settings = schemars::gen::SchemaSettings::draft07();
        let mut generator = settings.into_generator();
        let mut root = generator.root_schema_for::<V1RulesFile>();
        // `predicate_schema` was invoked transitively by `root_schema_for`
        // because `V1RuleEntry::triggers` carries
        // `#[schemars(schema_with = "predicate_schema")]`. Definitions
        // (Predicate, PredicatePathMatch, all walked fact paths) are
        // now in `root.definitions`.
        prune_unreferenced_definitions(&mut root);
        root
    }

    /// Re-exported so consumers (and downstream tooling tests) can pin
    /// the schema-version constant without going through the bin.
    pub fn schema_version() -> u32 {
        V1_RULES_SCHEMA_VERSION
    }

    // ────────────────────────────────────────────────────────────────
    // Definition registration: build the predicate DSL definitions
    // once per generator pass.
    // ────────────────────────────────────────────────────────────────

    fn register_predicate_definitions(generator: &mut SchemaGenerator) {
        let walk = enumerate_paths(generator);

        // Generic predicate-DSL primitives.
        register(generator, "PredicateLiteral", literal_def());
        register(generator, "PredicateScalarOpBlock", scalar_op_block_def());
        register(
            generator,
            "PredicateVecScalarOpBlock",
            vec_scalar_op_block_def(),
        );
        register(generator, "PredicateCountOpBlock", count_op_block_def());
        register(generator, "PredicateRangeBlock", range_block_def());
        register(generator, "PredicateOpaqueValue", opaque_value_def());
        register(generator, "PredicateScalarValue", scalar_value_def());
        register(generator, "PredicateVecValue", vec_value_def());
        register(
            generator,
            "PredicateQuantifierOpBlock",
            quantifier_op_block_generic(),
        );

        // Top-level entry points for StatementFacts root. Kept as
        // separate defs so the customer-facing entry stays the simple
        // `Predicate` reference.
        let stmt_paths = walk
            .paths_by_root
            .get("StatementFacts")
            .cloned()
            .unwrap_or_default();
        register(generator, "Predicate", predicate_def_top());
        register(generator, "PredicateCombinator", combinator_def_top());
        register(
            generator,
            "PredicatePathMatch",
            path_match_def_top(&stmt_paths),
        );

        // Per-element-type definitions. For each Vec<struct> element
        // type reachable from `StatementFacts`, we emit:
        //   - `{T}Predicate` — the per-element predicate (combinator
        //     and path-match inlined; no separate `*Combinator{T}` /
        //     `*PathMatch{T}` defs to clutter the schema).
        //   - `{T}Quantifier` — the relational quantifier op-block
        //     whose nested predicates root at `{T}` (referenced from
        //     every `Vec<{T}>` path value).
        for (root_name, paths) in &walk.paths_by_root {
            if root_name == "StatementFacts" {
                continue;
            }
            register(
                generator,
                &format!("{}Predicate", root_name),
                element_predicate_def(root_name, paths),
            );
            register(
                generator,
                &format!("{}Quantifier", root_name),
                element_quantifier_def(root_name),
            );
        }

        // Enum types: keep their schemars-generated definitions in
        // the schema so they're directly referenceable as
        // `{EnumType}` (no `Of{EnumType}` wrapper). The walker has
        // already populated `generator.definitions_mut()` with each
        // type's schema. We just need to make sure the pruner keeps
        // them — the per-path inline op-block schemas reference them
        // by `$ref`, so they'll survive the pruning step.
        let _ = &walk.enum_types;
    }

    fn register(generator: &mut SchemaGenerator, name: &str, def: SchemaObject) {
        generator
            .definitions_mut()
            .insert(name.to_string(), Schema::Object(def));
    }

    // ── Top-level Predicate (StatementFacts root) ───────────────────

    fn vacuous_predicate_branch() -> SchemaObject {
        SchemaObject {
            instance_type: Some(SingleOrVec::Single(Box::new(InstanceType::Object))),
            object: Some(Box::new(ObjectValidation {
                max_properties: Some(0),
                ..Default::default()
            })),
            metadata: Some(Box::new(meta(
                "Empty match. Always passes — useful inside `exists:` when \
                 you only care that at least one item is present.",
            ))),
            ..Default::default()
        }
    }

    fn predicate_def_top() -> SchemaObject {
        let mut s = description(
            "Rule trigger. Combine field matches with `all_of` / \
             `any_of` / `not`, or write one or more `<field>: <value>` \
             entries (multiple entries are joined by AND). Write `{}` \
             to mean \"always match\".",
        );
        s.subschemas = Some(Box::new(SubschemaValidation {
            one_of: Some(vec![
                Schema::Object(ref_obj("PredicateCombinator")),
                Schema::Object(ref_obj("PredicatePathMatch")),
                Schema::Object(vacuous_predicate_branch()),
            ]),
            ..Default::default()
        }));
        s
    }

    fn combinator_def_top() -> SchemaObject {
        let predicate_ref = || Schema::Object(ref_obj("Predicate"));
        let all_of = obj_with_single_required("all_of", Schema::Object(array_of(predicate_ref())));
        let any_of = obj_with_single_required("any_of", Schema::Object(array_of(predicate_ref())));
        let not_branch = obj_with_single_required("not", predicate_ref());

        let mut s = description(
            "Combine other matches with AND (`all_of`), OR (`any_of`), \
             or negate (`not`). Pick exactly one.",
        );
        s.subschemas = Some(Box::new(SubschemaValidation {
            one_of: Some(vec![
                Schema::Object(all_of),
                Schema::Object(any_of),
                Schema::Object(not_branch),
            ]),
            ..Default::default()
        }));
        s
    }

    fn path_match_def_top(paths: &BTreeMap<String, LeafKind>) -> SchemaObject {
        let mut properties = Map::new();
        for (path, leaf) in paths {
            properties.insert(path.clone(), leaf_value_schema(leaf));
        }
        let mut s = description(
            "Match one or more fields of the statement. Each entry is \
             `<field>: <value>`; multiple entries are joined by AND. \
             The value is either a bare literal (shortcut for equality) \
             or an operator block (`eq`, `neq`, `in`, `contains`, \
             `exists`, `count`, etc.). Field names follow the dotted \
             path through the statement's typed facts.",
        );
        s.instance_type = Some(SingleOrVec::Single(Box::new(InstanceType::Object)));
        s.object = Some(Box::new(ObjectValidation {
            min_properties: Some(1),
            properties,
            additional_properties: Some(Box::new(Schema::Object(ref_obj("PredicateOpaqueValue")))),
            ..Default::default()
        }));
        s
    }

    // ── Per-element-type Predicate (`{T}Predicate`) ─────────────────

    /// Build the predicate definition for an element type. Combinator
    /// and path-match are inlined so the schema only carries one def
    /// per element type instead of three.
    fn element_predicate_def(type_name: &str, paths: &BTreeMap<String, LeafKind>) -> SchemaObject {
        let predicate_ref = || Schema::Object(ref_obj(&format!("{}Predicate", type_name)));

        // Inlined combinator arms.
        let all_of = obj_with_single_required("all_of", Schema::Object(array_of(predicate_ref())));
        let any_of = obj_with_single_required("any_of", Schema::Object(array_of(predicate_ref())));
        let not_branch = obj_with_single_required("not", predicate_ref());

        // Inlined path-match.
        let mut properties = Map::new();
        for (path, leaf) in paths {
            properties.insert(path.clone(), leaf_value_schema(leaf));
        }
        let path_match = SchemaObject {
            instance_type: Some(SingleOrVec::Single(Box::new(InstanceType::Object))),
            object: Some(Box::new(ObjectValidation {
                min_properties: Some(1),
                properties,
                additional_properties: Some(Box::new(Schema::Object(ref_obj(
                    "PredicateOpaqueValue",
                )))),
                ..Default::default()
            })),
            ..Default::default()
        };

        let mut s = description(&format!(
            "Match against a single `{0}` item. Same shape as the \
             top-level rule trigger, but the available fields are \
             those of `{0}` (not the whole statement).",
            type_name
        ));
        s.subschemas = Some(Box::new(SubschemaValidation {
            one_of: Some(vec![
                Schema::Object(all_of),
                Schema::Object(any_of),
                Schema::Object(not_branch),
                Schema::Object(path_match),
                Schema::Object(vacuous_predicate_branch()),
            ]),
            ..Default::default()
        }));
        s
    }

    /// Build the quantifier op-block for an element type. Referenced
    /// from every `Vec<{T}>` path's value schema; nested predicates
    /// root at `{T}Predicate`.
    fn element_quantifier_def(type_name: &str) -> SchemaObject {
        let predicate_ref = || Schema::Object(ref_obj(&format!("{}Predicate", type_name)));

        let exists_value = SchemaObject {
            subschemas: Some(Box::new(SubschemaValidation {
                any_of: Some(vec![
                    Schema::Object(typed_instance(InstanceType::Boolean)),
                    predicate_ref(),
                ]),
                ..Default::default()
            })),
            metadata: Some(Box::new(meta(
                "`exists: true` / `exists: false` checks whether the \
                 field is present, or `exists: { ... }` matches when at \
                 least one item in the list satisfies the inner match.",
            ))),
            ..Default::default()
        };

        let count_value = SchemaObject {
            subschemas: Some(Box::new(SubschemaValidation {
                any_of: Some(vec![
                    Schema::Object(nonneg_int_schema()),
                    Schema::Object(ref_obj("PredicateCountOpBlock")),
                ]),
                ..Default::default()
            })),
            ..Default::default()
        };

        let one_of = vec![
            Schema::Object(obj_with_single_required(
                "exists",
                Schema::Object(exists_value),
            )),
            Schema::Object(obj_with_single_required("all", predicate_ref())),
            Schema::Object(obj_with_single_required("none", predicate_ref())),
            Schema::Object(obj_with_single_required("each", predicate_ref())),
            Schema::Object(obj_with_single_required(
                "count",
                Schema::Object(count_value),
            )),
        ];

        let mut s = description(&format!(
            "Match against a list of `{0}` items. Pick exactly one: \
             `exists` (at least one item matches), `all` (every item \
             matches), `none` (no item matches), `each` (emit one \
             signal per matching item), or `count` (compare the number \
             of items).",
            type_name
        ));
        s.subschemas = Some(Box::new(SubschemaValidation {
            one_of: Some(one_of),
            ..Default::default()
        }));
        s
    }

    /// Generic top-level quantifier op-block. Nested predicates root
    /// at the top-level `Predicate`. Referenced by `PredicateVecValue`
    /// (unconstrained Vec<scalar> paths) and `PredicateOpaqueValue`.
    fn quantifier_op_block_generic() -> SchemaObject {
        let predicate_ref = || Schema::Object(ref_obj("Predicate"));

        let exists_value = SchemaObject {
            subschemas: Some(Box::new(SubschemaValidation {
                any_of: Some(vec![
                    Schema::Object(typed_instance(InstanceType::Boolean)),
                    predicate_ref(),
                ]),
                ..Default::default()
            })),
            ..Default::default()
        };
        let count_value = SchemaObject {
            subschemas: Some(Box::new(SubschemaValidation {
                any_of: Some(vec![
                    Schema::Object(nonneg_int_schema()),
                    Schema::Object(ref_obj("PredicateCountOpBlock")),
                ]),
                ..Default::default()
            })),
            ..Default::default()
        };
        let one_of = vec![
            Schema::Object(obj_with_single_required(
                "exists",
                Schema::Object(exists_value),
            )),
            Schema::Object(obj_with_single_required("all", predicate_ref())),
            Schema::Object(obj_with_single_required("none", predicate_ref())),
            Schema::Object(obj_with_single_required("each", predicate_ref())),
            Schema::Object(obj_with_single_required(
                "count",
                Schema::Object(count_value),
            )),
        ];

        let mut s = description(
            "Match against a list-valued field. Pick exactly one: \
             `exists` (at least one item matches), `all` (every item \
             matches), `none` (no item matches), `each` (emit one \
             signal per matching item), or `count` (compare the number \
             of items).",
        );
        s.subschemas = Some(Box::new(SubschemaValidation {
            one_of: Some(one_of),
            ..Default::default()
        }));
        s
    }

    // ── Path-value schema generation ────────────────────────────────

    /// Pick the value schema for a single enumerated path. For enum
    /// scalars and Vec<enum> we inline the constrained op-block
    /// inline at the path-property site (referencing the enum's
    /// schemars-generated definition by `$ref`) so there's no
    /// proliferation of `*Of{Enum}` wrapper definitions.
    fn leaf_value_schema(leaf: &LeafKind) -> Schema {
        match leaf {
            LeafKind::Scalar {
                enum_ref: Some(enum_name),
            } => Schema::Object(inline_enum_scalar_value(enum_name)),
            LeafKind::Scalar { enum_ref: None } => Schema::Object(ref_obj("PredicateScalarValue")),
            LeafKind::VecOfScalar {
                enum_ref: Some(enum_name),
            } => Schema::Object(inline_enum_vec_value(enum_name)),
            LeafKind::VecOfScalar { enum_ref: None } => {
                Schema::Object(ref_obj("PredicateVecValue"))
            }
            LeafKind::VecOfStruct {
                element_type: Some(t),
            } => Schema::Object(ref_obj(&format!("{}Quantifier", t))),
            LeafKind::VecOfStruct { element_type: None } => {
                Schema::Object(ref_obj("PredicateVecValue"))
            }
            LeafKind::Opaque => Schema::Object(ref_obj("PredicateOpaqueValue")),
        }
    }

    /// Inline value-schema for a scalar enum path: `oneOf [{$ref:Enum},
    /// <op-block with Enum-constrained literals>]`. No separate
    /// `*Of{Enum}` def is created.
    fn inline_enum_scalar_value(enum_name: &str) -> SchemaObject {
        let enum_ref = || Schema::Object(ref_obj(enum_name));
        let enum_list = || Schema::Object(array_of(enum_ref()));

        let op_branches: Vec<Schema> = vec![
            Schema::Object(obj_with_single_required("eq", enum_ref())),
            Schema::Object(obj_with_single_required("neq", enum_ref())),
            Schema::Object(obj_with_single_required("in", enum_list())),
            Schema::Object(obj_with_single_required("not_in", enum_list())),
            Schema::Object(obj_with_single_required(
                "exists",
                Schema::Object(typed_instance(InstanceType::Boolean)),
            )),
            Schema::Object(obj_with_single_required(
                "is_null",
                Schema::Object(typed_instance(InstanceType::Boolean)),
            )),
        ];
        let op_block = SchemaObject {
            subschemas: Some(Box::new(SubschemaValidation {
                one_of: Some(op_branches),
                ..Default::default()
            })),
            ..Default::default()
        };

        SchemaObject {
            subschemas: Some(Box::new(SubschemaValidation {
                any_of: Some(vec![enum_ref(), Schema::Object(op_block)]),
                ..Default::default()
            })),
            ..Default::default()
        }
    }

    /// Inline value-schema for a `Vec<Enum>` path: vec-scalar op-block
    /// (`contains` / `contains_any` / `contains_all`) with Enum-pinned
    /// literals, plus a generic quantifier fallback.
    fn inline_enum_vec_value(enum_name: &str) -> SchemaObject {
        let enum_ref = || Schema::Object(ref_obj(enum_name));
        let enum_list = || Schema::Object(array_of(enum_ref()));

        let op_branches: Vec<Schema> = vec![
            Schema::Object(obj_with_single_required("contains", enum_ref())),
            Schema::Object(obj_with_single_required("contains_any", enum_list())),
            Schema::Object(obj_with_single_required("contains_all", enum_list())),
        ];
        let op_block = SchemaObject {
            subschemas: Some(Box::new(SubschemaValidation {
                one_of: Some(op_branches),
                ..Default::default()
            })),
            ..Default::default()
        };

        SchemaObject {
            subschemas: Some(Box::new(SubschemaValidation {
                any_of: Some(vec![
                    Schema::Object(op_block),
                    Schema::Object(ref_obj("PredicateQuantifierOpBlock")),
                ]),
                ..Default::default()
            })),
            ..Default::default()
        }
    }

    // ── Value-side schemas ──────────────────────────────────────────

    fn scalar_value_def() -> SchemaObject {
        let mut s = description(
            "Match against a single-value field. Write a bare literal \
             (shortcut for equality) or an operator block such as \
             `{ eq: ... }`, `{ neq: ... }`, `{ in: [...] }`, \
             `{ matches: \"<pattern>\" }`, `{ range: { ... } }`, etc.",
        );
        s.subschemas = Some(Box::new(SubschemaValidation {
            any_of: Some(vec![
                Schema::Object(ref_obj("PredicateLiteral")),
                Schema::Object(ref_obj("PredicateScalarOpBlock")),
            ]),
            ..Default::default()
        }));
        s
    }

    fn vec_value_def() -> SchemaObject {
        let mut s = description(
            "Match against a list-valued field. Use list membership \
             (`{ contains: ... }`, `{ contains_any: [...] }`, \
             `{ contains_all: [...] }`) or a list match (`exists`, \
             `all`, `none`, `each`, `count`).",
        );
        s.subschemas = Some(Box::new(SubschemaValidation {
            any_of: Some(vec![
                Schema::Object(ref_obj("PredicateVecScalarOpBlock")),
                Schema::Object(ref_obj("PredicateQuantifierOpBlock")),
            ]),
            ..Default::default()
        }));
        s
    }

    fn opaque_value_def() -> SchemaObject {
        let mut s = description(
            "Generic field value. Accepts any operator block — used \
             inside nested matches where the field type isn't fully \
             pinned (for example, inside an expression tree).",
        );
        s.subschemas = Some(Box::new(SubschemaValidation {
            any_of: Some(vec![
                Schema::Object(ref_obj("PredicateLiteral")),
                Schema::Object(ref_obj("PredicateScalarOpBlock")),
                Schema::Object(ref_obj("PredicateVecScalarOpBlock")),
                Schema::Object(ref_obj("PredicateQuantifierOpBlock")),
            ]),
            ..Default::default()
        }));
        s
    }

    // ── Op-block schemas ────────────────────────────────────────────

    fn scalar_op_block_def() -> SchemaObject {
        let lit = || Schema::Object(ref_obj("PredicateLiteral"));
        let lit_list = || Schema::Object(array_of(lit()));

        let branches: Vec<(&str, Schema)> = vec![
            ("eq", lit()),
            ("neq", lit()),
            ("gt", lit()),
            ("lt", lit()),
            ("gte", lit()),
            ("lte", lit()),
            (
                "matches",
                Schema::Object(typed_instance(InstanceType::String)),
            ),
            ("in", lit_list()),
            ("not_in", lit_list()),
            (
                "exists",
                Schema::Object(typed_instance(InstanceType::Boolean)),
            ),
            (
                "is_null",
                Schema::Object(typed_instance(InstanceType::Boolean)),
            ),
            ("range", Schema::Object(ref_obj("PredicateRangeBlock"))),
        ];

        let one_of: Vec<Schema> = branches
            .into_iter()
            .map(|(k, v)| Schema::Object(obj_with_single_required(k, v)))
            .collect();

        let mut s = description(
            "Operator block for a single-value field. Pick exactly one: \
             `eq` (equals), `neq` (not equals), `gt` / `lt` / `gte` / \
             `lte` (numeric comparison), `matches` (glob pattern), \
             `in` / `not_in` (set membership), `exists` / `is_null` \
             (presence checks), `range` (inclusive range).",
        );
        s.subschemas = Some(Box::new(SubschemaValidation {
            one_of: Some(one_of),
            ..Default::default()
        }));
        s
    }

    fn vec_scalar_op_block_def() -> SchemaObject {
        let lit = || Schema::Object(ref_obj("PredicateLiteral"));
        let lit_list = || Schema::Object(array_of(lit()));

        let branches: Vec<(&str, Schema)> = vec![
            ("contains", lit()),
            ("contains_any", lit_list()),
            ("contains_all", lit_list()),
        ];

        let one_of: Vec<Schema> = branches
            .into_iter()
            .map(|(k, v)| Schema::Object(obj_with_single_required(k, v)))
            .collect();

        let mut s = description(
            "Membership operator block for a list field. `contains` \
             matches when the named value appears in the list; \
             `contains_any` matches when any of the listed values \
             appear; `contains_all` matches when all listed values \
             appear.",
        );
        s.subschemas = Some(Box::new(SubschemaValidation {
            one_of: Some(one_of),
            ..Default::default()
        }));
        s
    }

    fn count_op_block_def() -> SchemaObject {
        let nonneg_int = || Schema::Object(nonneg_int_schema());
        let one_of: Vec<Schema> = ["eq", "neq", "gt", "lt", "gte", "lte"]
            .into_iter()
            .map(|k| Schema::Object(obj_with_single_required(k, nonneg_int())))
            .collect();

        let mut s = description(
            "Compare a list's item count. Pick one: `eq`, `neq`, \
             `gt`, `lt`, `gte`, `lte`, with a non-negative integer.",
        );
        s.subschemas = Some(Box::new(SubschemaValidation {
            one_of: Some(one_of),
            ..Default::default()
        }));
        s
    }

    fn range_block_def() -> SchemaObject {
        let lit_ref = || Schema::Object(ref_obj("PredicateLiteral"));

        let mut props = Map::new();
        props.insert("low".to_string(), lit_ref());
        props.insert("high".to_string(), lit_ref());
        props.insert(
            "low_inclusive".to_string(),
            Schema::Object(bool_default(true)),
        );
        props.insert(
            "high_inclusive".to_string(),
            Schema::Object(bool_default(true)),
        );

        let mut required: schemars::Set<String> = Default::default();
        required.insert("low".into());
        required.insert("high".into());

        let mut s = description(
            "Inclusive range, used as the value of `range:`. Set \
             `low_inclusive` or `high_inclusive` to `false` to make \
             either side exclusive.",
        );
        s.instance_type = Some(SingleOrVec::Single(Box::new(InstanceType::Object)));
        s.object = Some(Box::new(ObjectValidation {
            required,
            properties: props,
            additional_properties: Some(Box::new(Schema::Bool(false))),
            ..Default::default()
        }));
        s
    }

    fn literal_def() -> SchemaObject {
        let mut s = description("A literal value: `null`, a boolean, a number, or a string.");
        s.subschemas = Some(Box::new(SubschemaValidation {
            any_of: Some(vec![
                Schema::Object(typed_instance(InstanceType::Null)),
                Schema::Object(typed_instance(InstanceType::Boolean)),
                Schema::Object(typed_instance(InstanceType::Number)),
                Schema::Object(typed_instance(InstanceType::String)),
            ]),
            ..Default::default()
        }));
        s
    }

    // ────────────────────────────────────────────────────────────────
    // Path enumerator: walk schemars-derived StatementFacts schema.
    // ────────────────────────────────────────────────────────────────

    #[derive(Debug, Clone)]
    enum LeafKind {
        /// Scalar-typed leaf (bool, int, string, enum). Bare literal
        /// or a `ScalarOpBlock`. When the underlying type is a string
        /// enum (e.g. `StatementKind`), `enum_ref` carries the type
        /// name so the value schema can constrain `eq` / `in` / etc.
        /// to the variant set.
        Scalar { enum_ref: Option<String> },
        /// `Vec<scalar>` — element type is a scalar primitive or enum.
        /// `enum_ref` is set when elements are string-enum-valued.
        VecOfScalar { enum_ref: Option<String> },
        /// `Vec<struct>` — element type is a complex object. The
        /// `element_type` carries the schemars-resolved name of the
        /// element type when known, so the quantifier op-block can
        /// nest a Predicate rooted at that element type.
        VecOfStruct { element_type: Option<String> },
        /// Path hit recursion limit or has unrecognized shape.
        /// Accepts any op-block.
        Opaque,
    }

    /// Output of one full walk of `StatementFacts` + all transitively
    /// discovered Vec<T> element types.
    #[derive(Debug, Default)]
    struct WalkOutput {
        /// Per-root path tables. Key is the root type name
        /// (`"StatementFacts"` for the top-level walk, then each
        /// discovered Vec<struct> element type).
        paths_by_root: BTreeMap<String, BTreeMap<String, LeafKind>>,
        /// Per-enum-type the set of allowed string values. Populated
        /// during walking when an enum-shaped schema is reached.
        enum_types: BTreeMap<String, Vec<String>>,
    }

    /// Walk `StatementFacts` and every Vec<struct> element type
    /// reachable from it. Returns a per-root path table plus the set
    /// of discovered enum types and their values.
    fn enumerate_paths(generator: &mut SchemaGenerator) -> WalkOutput {
        use crate::facts::StatementFacts;
        let root = generator.subschema_for::<StatementFacts>();
        let defs: Map<String, Schema> = generator.definitions().clone();

        let mut output = WalkOutput::default();
        let mut pending: VecDeque<String> = VecDeque::new();

        // Top-level walk: StatementFacts. Stored under the unsuffixed
        // root name so the schema's customer-facing entry point stays
        // `Predicate` / `PredicatePathMatch`.
        let mut paths: BTreeMap<String, LeafKind> = BTreeMap::new();
        let mut visiting: HashSet<String> = HashSet::new();
        walk(
            "",
            &root,
            &defs,
            &mut paths,
            &mut visiting,
            0,
            &mut output.enum_types,
            &mut pending,
        );
        output
            .paths_by_root
            .insert("StatementFacts".to_string(), paths);

        // Drain the queue, walking each discovered element type at most
        // once. New Vec<struct> fields encountered inside an element
        // type push onto `pending` for subsequent rounds.
        while let Some(type_name) = pending.pop_front() {
            if output.paths_by_root.contains_key(&type_name) {
                continue;
            }
            let schema = match defs.get(&type_name) {
                Some(s) => s.clone(),
                None => continue,
            };
            let mut paths: BTreeMap<String, LeafKind> = BTreeMap::new();
            let mut visiting: HashSet<String> = HashSet::new();
            visiting.insert(type_name.clone());
            walk(
                "",
                &schema,
                &defs,
                &mut paths,
                &mut visiting,
                0,
                &mut output.enum_types,
                &mut pending,
            );
            output.paths_by_root.insert(type_name, paths);
        }

        output
    }

    #[allow(clippy::too_many_arguments)]
    fn walk(
        prefix: &str,
        schema: &Schema,
        defs: &Map<String, Schema>,
        out: &mut BTreeMap<String, LeafKind>,
        visiting: &mut HashSet<String>,
        depth: usize,
        enum_types: &mut BTreeMap<String, Vec<String>>,
        pending: &mut VecDeque<String>,
    ) {
        if depth > MAX_WALK_DEPTH {
            insert_path(out, prefix, LeafKind::Opaque);
            return;
        }
        let obj = match schema {
            Schema::Bool(_) => return,
            Schema::Object(o) => o,
        };

        // 1. Enum detection — handle BEFORE descending. A named ref to
        //    an enum-shaped definition is recognized here so the type
        //    name carries through to the value schema.
        if let Some((type_name, values)) = extract_enum_ref(obj, defs) {
            if let Some(tn) = &type_name {
                enum_types.entry(tn.clone()).or_insert(values);
                insert_path(
                    out,
                    prefix,
                    LeafKind::Scalar {
                        enum_ref: Some(tn.clone()),
                    },
                );
            } else {
                // Anonymous enum — emit as plain Scalar.
                insert_path(out, prefix, LeafKind::Scalar { enum_ref: None });
            }
            return;
        }

        // 2. Resolve $ref with cycle detection.
        if let Some(reference) = &obj.reference {
            let name = strip_definitions_prefix(reference);
            if visiting.contains(name) {
                insert_path(out, prefix, LeafKind::Opaque);
                return;
            }
            let resolved = match defs.get(name) {
                Some(s) => s,
                None => return,
            };
            visiting.insert(name.to_string());
            walk(
                prefix, resolved, defs, out, visiting, depth, enum_types, pending,
            );
            visiting.remove(name);
            return;
        }

        // 3. Unwrap nullable (`Option<T>`).
        if let Some(inner) = unwrap_nullable(obj) {
            walk(
                prefix, &inner, defs, out, visiting, depth, enum_types, pending,
            );
            return;
        }

        // 4. Untagged / one_of / any_of — walk every branch and merge.
        if let Some(sub) = &obj.subschemas {
            let mut walked_any = false;
            for branch in iter_subschema_branches(sub) {
                walk(
                    prefix,
                    branch,
                    defs,
                    out,
                    visiting,
                    depth + 1,
                    enum_types,
                    pending,
                );
                walked_any = true;
            }
            if walked_any {
                return;
            }
        }

        // 5. Dispatch on instance type.
        let it = obj.instance_type.as_ref().and_then(single_instance_type);
        match it {
            Some(InstanceType::Object) => {
                if let Some(ov) = &obj.object {
                    for (name, sub) in &ov.properties {
                        let child_prefix = if prefix.is_empty() {
                            name.clone()
                        } else {
                            format!("{}.{}", prefix, name)
                        };
                        walk(
                            &child_prefix,
                            sub,
                            defs,
                            out,
                            visiting,
                            depth + 1,
                            enum_types,
                            pending,
                        );
                    }
                }
            }
            Some(InstanceType::Array) => {
                let kind = classify_array_element(obj, defs, visiting, enum_types, pending);
                insert_path(out, prefix, kind);
            }
            Some(InstanceType::Boolean)
            | Some(InstanceType::Integer)
            | Some(InstanceType::Number)
            | Some(InstanceType::String) => {
                insert_path(out, prefix, LeafKind::Scalar { enum_ref: None });
            }
            Some(InstanceType::Null) | None => {
                insert_path(out, prefix, LeafKind::Opaque);
            }
        }
    }

    fn insert_path(out: &mut BTreeMap<String, LeafKind>, prefix: &str, kind: LeafKind) {
        if prefix.is_empty() {
            return;
        }
        let merged = match out.get(prefix) {
            Some(existing) => merge_leaf(existing.clone(), kind),
            None => kind,
        };
        out.insert(prefix.to_string(), merged);
    }

    /// Merge two leaf classifications for the same path. Used when a
    /// path appears under multiple `oneOf` branches of a tagged enum
    /// — e.g. `policy.variant.unset_fields` is `Vec<PasswordPolicyField>`
    /// in one variant and `Vec<SessionPolicyField>` in another. When
    /// the two classifications conflict on their element type, we
    /// downgrade to the unconstrained form so customer rules that
    /// reference any variant's values still validate.
    fn merge_leaf(a: LeafKind, b: LeafKind) -> LeafKind {
        match (a, b) {
            (LeafKind::Opaque, x) | (x, LeafKind::Opaque) => x,
            (LeafKind::Scalar { enum_ref: r1 }, LeafKind::Scalar { enum_ref: r2 }) => {
                LeafKind::Scalar {
                    enum_ref: if r1 == r2 { r1 } else { None },
                }
            }
            (LeafKind::VecOfScalar { enum_ref: r1 }, LeafKind::VecOfScalar { enum_ref: r2 }) => {
                LeafKind::VecOfScalar {
                    enum_ref: if r1 == r2 { r1 } else { None },
                }
            }
            (
                LeafKind::VecOfStruct { element_type: t1 },
                LeafKind::VecOfStruct { element_type: t2 },
            ) => LeafKind::VecOfStruct {
                element_type: if t1 == t2 { t1 } else { None },
            },
            // Different families collide — fall back to Opaque so the
            // path still accepts every legal op-block shape.
            _ => LeafKind::Opaque,
        }
    }

    fn classify_array_element(
        obj: &SchemaObject,
        defs: &Map<String, Schema>,
        visiting: &mut HashSet<String>,
        enum_types: &mut BTreeMap<String, Vec<String>>,
        pending: &mut VecDeque<String>,
    ) -> LeafKind {
        let av = match &obj.array {
            Some(a) => a,
            None => return LeafKind::VecOfStruct { element_type: None },
        };
        let item_schema = match &av.items {
            Some(SingleOrVec::Single(s)) => s.as_ref(),
            Some(SingleOrVec::Vec(v)) if !v.is_empty() => &v[0],
            _ => return LeafKind::VecOfStruct { element_type: None },
        };

        // Try to attribute a name to the element type. If the element
        // is `$ref: #/definitions/Foo`, then `Foo` is the name.
        let element_name = match item_schema {
            Schema::Object(o) => o
                .reference
                .as_deref()
                .map(strip_definitions_prefix)
                .map(String::from),
            _ => None,
        };

        // Enum-element classification: if the element resolves to a
        // string-enum, capture it and emit VecOfScalar with the
        // enum_ref so vec-scalar ops (contains*) can be constrained.
        if let Schema::Object(item_obj) = item_schema {
            if let Some((type_name, values)) = extract_enum_ref(item_obj, defs) {
                if let Some(tn) = type_name {
                    enum_types.entry(tn.clone()).or_insert(values);
                    return LeafKind::VecOfScalar { enum_ref: Some(tn) };
                }
                return LeafKind::VecOfScalar { enum_ref: None };
            }
        }

        if element_is_scalar(item_schema, defs, visiting) {
            LeafKind::VecOfScalar { enum_ref: None }
        } else {
            // Schedule the element type for its own walk so its paths
            // become available inside quantifier sub-predicates.
            if let Some(name) = &element_name {
                pending.push_back(name.clone());
            }
            LeafKind::VecOfStruct {
                element_type: element_name,
            }
        }
    }

    fn element_is_scalar(
        schema: &Schema,
        defs: &Map<String, Schema>,
        visiting: &mut HashSet<String>,
    ) -> bool {
        let obj = match schema {
            Schema::Object(o) => o,
            Schema::Bool(_) => return false,
        };
        if let Some(reference) = &obj.reference {
            let name = strip_definitions_prefix(reference);
            if visiting.contains(name) {
                return false;
            }
            return defs
                .get(name)
                .map(|s| {
                    visiting.insert(name.to_string());
                    let r = element_is_scalar(s, defs, visiting);
                    visiting.remove(name);
                    r
                })
                .unwrap_or(false);
        }
        if let Some(it) = obj.instance_type.as_ref().and_then(single_instance_type) {
            return matches!(
                it,
                InstanceType::Boolean
                    | InstanceType::Integer
                    | InstanceType::Number
                    | InstanceType::String
            );
        }
        if let Some(sub) = &obj.subschemas {
            return iter_subschema_branches(sub).all(|b| element_is_scalar(b, defs, visiting));
        }
        false
    }

    // ── Enum detection ──────────────────────────────────────────────

    /// If `obj` is a `$ref` to a named type that the customer-facing
    /// rule DSL would treat as enum-like (i.e. the type accepts at
    /// least one string-literal variant), return its type name.
    /// Mixed enums with non-unit variants — e.g. `Privilege::Other(_)`
    /// — still qualify: the `$ref` to the type's own schema handles
    /// validation of literal-vs-tagged-object forms.
    fn extract_enum_ref(
        obj: &SchemaObject,
        defs: &Map<String, Schema>,
    ) -> Option<(Option<String>, Vec<String>)> {
        if let Some(reference) = &obj.reference {
            let name = strip_definitions_prefix(reference);
            if let Some(Schema::Object(target_obj)) = defs.get(name) {
                if has_string_enum_branch(target_obj) {
                    let values = extract_string_enum_inline(target_obj).unwrap_or_default();
                    return Some((Some(name.to_string()), values));
                }
            }
            return None;
        }
        extract_string_enum_inline(obj).map(|values| (None, values))
    }

    /// True if `obj` is or contains at least one string-typed
    /// enum-valued branch. Used to recognize mixed enums (some unit
    /// variants + a tagged data variant) as still enum-referenceable.
    fn has_string_enum_branch(obj: &SchemaObject) -> bool {
        if matches!(
            obj.instance_type.as_ref().and_then(single_instance_type),
            Some(InstanceType::String)
        ) && obj.enum_values.as_ref().is_some_and(|v| !v.is_empty())
        {
            return true;
        }
        if let Some(sub) = &obj.subschemas {
            for branch in iter_subschema_branches(sub) {
                if let Schema::Object(b) = branch {
                    if matches!(
                        b.instance_type.as_ref().and_then(single_instance_type),
                        Some(InstanceType::String)
                    ) && b.enum_values.as_ref().is_some_and(|v| !v.is_empty())
                    {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Detect a pure string-enum shape on an inline schema and return
    /// the variant values. Used for inline (anonymous) enums where we
    /// can't reference a named definition. Two patterns:
    /// 1. `{ type: "string", enum: [...] }` — direct.
    /// 2. `{ oneOf: [{type:"string",enum:[...]}, ...] }` — schemars
    ///    output for `rename_all` enums (branches may carry one or
    ///    many enum values depending on per-variant docs).
    fn extract_string_enum_inline(obj: &SchemaObject) -> Option<Vec<String>> {
        // Pattern 1.
        if matches!(
            obj.instance_type.as_ref().and_then(single_instance_type),
            Some(InstanceType::String)
        ) {
            if let Some(values) = &obj.enum_values {
                let strings: Option<Vec<String>> = values
                    .iter()
                    .map(|v| v.as_str().map(|s| s.to_string()))
                    .collect();
                if let Some(s) = strings {
                    if !s.is_empty() {
                        return Some(s);
                    }
                }
            }
        }
        // Pattern 2.
        if let Some(sub) = &obj.subschemas {
            // Either one_of (oneOf) or any_of (anyOf) — schemars uses
            // one_of for tagged enums with descriptions.
            let branches: Vec<&Schema> = sub
                .one_of
                .iter()
                .flatten()
                .chain(sub.any_of.iter().flatten())
                .collect();
            if branches.is_empty() {
                return None;
            }
            let mut collected = Vec::new();
            for branch in branches {
                let branch_obj = match branch {
                    Schema::Object(o) => o,
                    _ => return None,
                };
                // Each branch must be a string-typed enum schema. The
                // branch may have any number of `enum` values (schemars
                // emits a single branch with all variants when none of
                // them carry doc-comments, and one-branch-per-variant
                // when each carries its own description).
                if !matches!(
                    branch_obj
                        .instance_type
                        .as_ref()
                        .and_then(single_instance_type),
                    Some(InstanceType::String)
                ) {
                    return None;
                }
                let vs = branch_obj.enum_values.as_ref()?;
                for v in vs {
                    let s = v.as_str()?.to_string();
                    collected.push(s);
                }
            }
            if collected.is_empty() {
                return None;
            }
            return Some(collected);
        }
        None
    }

    fn unwrap_nullable(obj: &SchemaObject) -> Option<Schema> {
        // schemars 0.8 nullable patterns:
        // 1. instance_type: [Null, T] — single non-null entry plus Null.
        // 2. subschemas.any_of: [{type: null}, T-schema].
        if let Some(SingleOrVec::Vec(types)) = &obj.instance_type {
            let mut non_null: Vec<InstanceType> = types
                .iter()
                .copied()
                .filter(|t| *t != InstanceType::Null)
                .collect();
            if non_null.len() == 1 && types.len() > non_null.len() {
                let mut clone = obj.clone();
                clone.instance_type = Some(SingleOrVec::Single(Box::new(non_null.remove(0))));
                return Some(Schema::Object(clone));
            }
        }
        if let Some(sub) = &obj.subschemas {
            let branches: Vec<&Schema> = iter_subschema_branches(sub).collect();
            if branches.len() == 2 {
                let null_branches: Vec<&Schema> = branches
                    .iter()
                    .copied()
                    .filter(|b| is_null_schema(b))
                    .collect();
                if null_branches.len() == 1 {
                    for b in branches {
                        if !is_null_schema(b) {
                            return Some(b.clone());
                        }
                    }
                }
            }
        }
        None
    }

    fn is_null_schema(schema: &Schema) -> bool {
        if let Schema::Object(obj) = schema {
            matches!(
                obj.instance_type.as_ref().and_then(single_instance_type),
                Some(InstanceType::Null)
            )
        } else {
            false
        }
    }

    fn iter_subschema_branches(
        sub: &SubschemaValidation,
    ) -> Box<dyn Iterator<Item = &Schema> + '_> {
        Box::new(
            sub.one_of
                .iter()
                .flatten()
                .chain(sub.any_of.iter().flatten())
                .chain(sub.all_of.iter().flatten()),
        )
    }

    fn single_instance_type(t: &SingleOrVec<InstanceType>) -> Option<InstanceType> {
        match t {
            SingleOrVec::Single(t) => Some(**t),
            SingleOrVec::Vec(v) if v.len() == 1 => Some(v[0]),
            _ => None,
        }
    }

    fn strip_definitions_prefix(reference: &str) -> &str {
        reference
            .strip_prefix("#/definitions/")
            .unwrap_or(reference)
    }

    /// Walk the schema and drop any definition that is not transitively
    /// referenced from the root (or from another retained definition).
    /// `schemars` populates the generator with every type it has
    /// visited; we only need the ones the V1 wire types actually use.
    fn prune_unreferenced_definitions(root: &mut RootSchema) {
        let mut reachable: HashSet<String> = HashSet::new();

        // Seed from the root schema body and from any predicate-DSL
        // definition we authored manually (path enumeration in
        // `PredicatePathMatch` is the main backbone).
        collect_refs(&Schema::Object(root.schema.clone()), &mut reachable);
        for seed in [
            "Predicate",
            "PredicateCombinator",
            "PredicatePathMatch",
            "PredicateScalarValue",
            "PredicateScalarOpBlock",
            "PredicateVecValue",
            "PredicateQuantifierOpBlock",
            "PredicateVecScalarOpBlock",
            "PredicateCountOpBlock",
            "PredicateRangeBlock",
            "PredicateLiteral",
            "PredicateOpaqueValue",
        ] {
            reachable.insert(seed.to_string());
        }

        let mut frontier: Vec<String> = reachable.iter().cloned().collect();
        while let Some(name) = frontier.pop() {
            if let Some(schema) = root.definitions.get(&name).cloned() {
                let mut new_refs = HashSet::new();
                collect_refs(&schema, &mut new_refs);
                for r in new_refs {
                    if reachable.insert(r.clone()) {
                        frontier.push(r);
                    }
                }
            }
        }

        root.definitions
            .retain(|name, _| reachable.contains(name.as_str()));
    }

    fn collect_refs(schema: &Schema, out: &mut HashSet<String>) {
        let obj = match schema {
            Schema::Object(o) => o,
            Schema::Bool(_) => return,
        };
        if let Some(r) = &obj.reference {
            out.insert(strip_definitions_prefix(r).to_string());
        }
        if let Some(sub) = &obj.subschemas {
            for branch in iter_subschema_branches(sub) {
                collect_refs(branch, out);
            }
            if let Some(nb) = &sub.not {
                collect_refs(nb, out);
            }
        }
        if let Some(av) = &obj.array {
            if let Some(items) = &av.items {
                match items {
                    SingleOrVec::Single(s) => collect_refs(s, out),
                    SingleOrVec::Vec(v) => {
                        for it in v {
                            collect_refs(it, out);
                        }
                    }
                }
            }
        }
        if let Some(ov) = &obj.object {
            for sub in ov.properties.values() {
                collect_refs(sub, out);
            }
            for sub in ov.pattern_properties.values() {
                collect_refs(sub, out);
            }
            if let Some(ap) = &ov.additional_properties {
                collect_refs(ap, out);
            }
        }
    }

    // ────────────────────────────────────────────────────────────────
    // Primitive schema helpers.
    // ────────────────────────────────────────────────────────────────

    fn obj_with_single_required(key: &str, value_schema: Schema) -> SchemaObject {
        let mut props = Map::new();
        props.insert(key.to_string(), value_schema);

        let mut required: schemars::Set<String> = Default::default();
        required.insert(key.to_string());

        SchemaObject {
            instance_type: Some(SingleOrVec::Single(Box::new(InstanceType::Object))),
            object: Some(Box::new(ObjectValidation {
                required,
                properties: props,
                additional_properties: Some(Box::new(Schema::Bool(false))),
                ..Default::default()
            })),
            ..Default::default()
        }
    }

    fn array_of(item: Schema) -> SchemaObject {
        SchemaObject {
            instance_type: Some(SingleOrVec::Single(Box::new(InstanceType::Array))),
            array: Some(Box::new(ArrayValidation {
                items: Some(SingleOrVec::Single(Box::new(item))),
                ..Default::default()
            })),
            ..Default::default()
        }
    }

    fn ref_obj(name: &str) -> SchemaObject {
        SchemaObject {
            reference: Some(format!("#/definitions/{}", name)),
            ..Default::default()
        }
    }

    fn typed_instance(ty: InstanceType) -> SchemaObject {
        SchemaObject {
            instance_type: Some(SingleOrVec::Single(Box::new(ty))),
            ..Default::default()
        }
    }

    fn nonneg_int_schema() -> SchemaObject {
        let mut s = typed_instance(InstanceType::Integer);
        s.number = Some(Box::new(schemars::schema::NumberValidation {
            minimum: Some(0.0),
            ..Default::default()
        }));
        s
    }

    fn bool_default(default_value: bool) -> SchemaObject {
        SchemaObject {
            instance_type: Some(SingleOrVec::Single(Box::new(InstanceType::Boolean))),
            metadata: Some(Box::new(schemars::schema::Metadata {
                default: Some(Value::Bool(default_value)),
                ..Default::default()
            })),
            ..Default::default()
        }
    }

    fn description(text: &str) -> SchemaObject {
        SchemaObject {
            metadata: Some(Box::new(meta(text))),
            ..Default::default()
        }
    }

    fn meta(text: &str) -> schemars::schema::Metadata {
        schemars::schema::Metadata {
            description: Some(text.to_string()),
            ..Default::default()
        }
    }
}

#[cfg(feature = "schema")]
pub use schema_gen::{
    generate_v1_rules_schema, predicate_schema, predicate_schema_optional, schema_version,
};
