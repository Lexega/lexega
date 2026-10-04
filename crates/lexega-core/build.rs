// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

fn main() {
    precompile_builtin_rules();
}

/// Transcode the built-in rule corpus from YAML to JSON at build time.
/// The runtime deserializes JSON (far faster than YAML) on every process
/// start. The YAML file stays the single source of truth; the JSON is
/// derived from it, and a malformed corpus fails the build here.
fn precompile_builtin_rules() {
    const YAML_PATH: &str = "../../rules/builtin_rules.yaml";
    println!("cargo:rerun-if-changed={YAML_PATH}");

    let yaml = std::fs::read_to_string(YAML_PATH)
        .unwrap_or_else(|e| panic!("build: failed to read {YAML_PATH}: {e}"));
    // Transcode via a generic Value: YAML mappings (string keys) map
    // cleanly onto a JSON object, which deserializes into the same
    // `V1RulesFile` the YAML path uses.
    let value: serde_json::Value = serde_yaml_ng::from_str(&yaml)
        .unwrap_or_else(|e| panic!("build: {YAML_PATH} is not valid YAML: {e}"));
    let json = serde_json::to_vec(&value)
        .unwrap_or_else(|e| panic!("build: failed to serialize corpus to JSON: {e}"));

    let out_dir = std::env::var("OUT_DIR").expect("build: OUT_DIR not set");
    let out_path = std::path::Path::new(&out_dir).join("builtin_rules.json");
    std::fs::write(&out_path, json)
        .unwrap_or_else(|e| panic!("build: failed to write {}: {e}", out_path.display()));
}
