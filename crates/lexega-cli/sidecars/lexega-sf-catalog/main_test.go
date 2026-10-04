// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"runtime/debug"
	"strings"
	"testing"
)

func TestParseIdentFilter(t *testing.T) {
	name, quoted := parse_ident_filter(`LEXEGA_DEMO`)
	if quoted {
		t.Fatalf("expected unquoted")
	}
	if name != "LEXEGA_DEMO" {
		t.Fatalf("unexpected name: %q", name)
	}

	name, quoted = parse_ident_filter(`"MyDb"`)
	if !quoted {
		t.Fatalf("expected quoted")
	}
	if name != "MyDb" {
		t.Fatalf("unexpected name: %q", name)
	}
}

func TestIdentFilterMatches(t *testing.T) {
	// Unquoted filters are case-insensitive
	if !ident_filter_matches("LEXEGA_DEMO", "lexega_demo") {
		t.Fatalf("expected match")
	}
	if !ident_filter_matches("lexega_demo", "LEXEGA_DEMO") {
		t.Fatalf("expected match")
	}

	// Quoted filters are case-sensitive
	if ident_filter_matches("LEXEGA_DEMO", `"lexega_demo"`) {
		t.Fatalf("expected no match")
	}
	if !ident_filter_matches("lexega_demo", `"lexega_demo"`) {
		t.Fatalf("expected match")
	}
}

func TestParsePullArgs(t *testing.T) {
	args, err := parsePullArgs([]string{
		"--provider", "snowflake",
		"--account", "acct",
		"--user", "someone",
		"--include-tag", "PII",
		"--out", "-",
	})
	if err != nil {
		t.Fatalf("parsePullArgs failed: %v", err)
	}
	if args.Account != "acct" || args.User != "someone" || args.Out != "-" {
		t.Fatalf("unexpected args: %+v", args)
	}
	if len(args.IncludeTags) != 1 || args.IncludeTags[0] != "PII" {
		t.Fatalf("unexpected tags: %v", args.IncludeTags)
	}

	if _, err := parsePullArgs([]string{"--user", "someone", "--out", "-"}); err == nil {
		t.Fatalf("expected error when --account is missing")
	}
}

func TestParsePullArgsProvider(t *testing.T) {
	base := []string{"--account", "acct", "--user", "someone", "--out", "-"}

	for _, provider := range [][]string{nil, {"--provider", "snowflake"}, {"--provider=SF"}} {
		if _, err := parsePullArgs(append(provider, base...)); err != nil {
			t.Fatalf("provider %v: %v", provider, err)
		}
	}

	// A Databricks run is answered with the name of its own extractor,
	// whatever order its flags come in and whether or not it names the
	// provider.
	for _, argv := range [][]string{
		{"--provider", "databricks", "--workspace-url", "https://dbc-123.cloud.databricks.com", "--token-env", "DATABRICKS_TOKEN", "--out", "-"},
		{"--workspace-url", "https://dbc-123.cloud.databricks.com", "--include-grants", "--out", "-", "--provider", "dbx"},
		{"--workspace-url", "https://dbc-123.cloud.databricks.com", "--out", "-"},
	} {
		_, err := parsePullArgs(argv)
		if err == nil || !strings.Contains(err.Error(), "lexega-dbx-catalog") {
			t.Fatalf("%v: expected a pointer to the Databricks extractor, got %v", argv, err)
		}
	}

	// A value that happens to read "provider" is not the provider flag.
	if _, err := parsePullArgs(append([]string{"--role", "provider"}, base...)); err != nil {
		t.Fatalf("--role provider: %v", err)
	}

	_, err := parsePullArgs(append([]string{"--provider", "postgresql"}, base...))
	if err == nil || !strings.Contains(err.Error(), "invalid --provider") {
		t.Fatalf("expected an invalid-provider error, got %v", err)
	}
}

// Every module linked into the program has its license in the embedded
// notices. After a dependency change, regenerate them with
// `go run ../notices.go`.
func TestNoticesCoverEveryLinkedModule(t *testing.T) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		t.Skip("no build information in this binary")
	}
	for _, dep := range info.Deps {
		if !strings.Contains(thirdPartyLicenses, "  "+dep.Path+" "+dep.Version+"\n") {
			t.Errorf("%s %s is linked but missing from THIRD_PARTY_LICENSES.txt", dep.Path, dep.Version)
		}
	}
	if !strings.Contains(thirdPartyLicenses, "the Go standard library and runtime") {
		t.Errorf("Go's own license is missing from THIRD_PARTY_LICENSES.txt")
	}
}
