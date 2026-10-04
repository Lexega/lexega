// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"encoding/json"
	"net/url"
	"os"
	"runtime/debug"
	"strings"
	"testing"
)

func TestParsePullArgsValid(t *testing.T) {
	a, err := parsePullArgs([]string{"--out", "-", "--server", "localhost", "--user", "sa"})
	if err != nil {
		t.Fatalf("parsePullArgs failed: %v", err)
	}
	if a.Out != "-" || a.Server != "localhost" || a.User != "sa" {
		t.Fatalf("unexpected args: %+v", a)
	}
	if a.Port != 1433 {
		t.Fatalf("expected default port 1433, got %d", a.Port)
	}
	if a.Provider != "mssql" {
		t.Fatalf("expected provider mssql, got %q", a.Provider)
	}
}

func TestParsePullArgsProviderAliases(t *testing.T) {
	for _, alias := range []string{"mssql", "sqlserver", "sql_server", ""} {
		argv := []string{"--out", "-", "--server", "h"}
		if alias != "" {
			argv = append(argv, "--provider", alias)
		}
		a, err := parsePullArgs(argv)
		if err != nil {
			t.Fatalf("alias %q: unexpected error: %v", alias, err)
		}
		if a.Provider != "mssql" {
			t.Fatalf("alias %q: expected normalized mssql, got %q", alias, a.Provider)
		}
	}
}

func TestParsePullArgsErrors(t *testing.T) {
	cases := map[string][]string{
		"missing out":      {"--server", "h"},
		"missing server":   {"--out", "-"},
		"invalid provider": {"--out", "-", "--server", "h", "--provider", "oracle"},
		"invalid encrypt":  {"--out", "-", "--server", "h", "--encrypt", "maybe"},
	}
	for name, argv := range cases {
		if _, err := parsePullArgs(argv); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestParsePullArgsConnStringSkipsServerReq(t *testing.T) {
	a, err := parsePullArgs([]string{"--out", "-", "--connection-string-env", "MY_DSN"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a.ConnectionStringEnv != "MY_DSN" {
		t.Fatalf("unexpected conn string env: %q", a.ConnectionStringEnv)
	}
}

func TestBuildDSN(t *testing.T) {
	t.Setenv("MSSQL_PASSWORD", "s3cr3t")
	a := pullArgs{Server: "db.example.com", Port: 1433, User: "sa", Database: "Sales", Encrypt: "true", TrustServerCert: true, PasswordEnv: "MSSQL_PASSWORD"}
	dsn, err := buildDSN(a)
	if err != nil {
		t.Fatalf("buildDSN failed: %v", err)
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("DSN not a valid URL: %v", err)
	}
	if u.Scheme != "sqlserver" {
		t.Fatalf("expected sqlserver scheme, got %q", u.Scheme)
	}
	if u.Host != "db.example.com:1433" {
		t.Fatalf("unexpected host: %q", u.Host)
	}
	if user := u.User.Username(); user != "sa" {
		t.Fatalf("unexpected user: %q", user)
	}
	if pw, _ := u.User.Password(); pw != "s3cr3t" {
		t.Fatalf("password not carried from env")
	}
	q := u.Query()
	if q.Get("database") != "Sales" {
		t.Fatalf("unexpected database param: %q", q.Get("database"))
	}
	if q.Get("encrypt") != "true" {
		t.Fatalf("unexpected encrypt param: %q", q.Get("encrypt"))
	}
	if q.Get("TrustServerCertificate") != "true" {
		t.Fatalf("expected TrustServerCertificate=true")
	}
}

func TestBuildDSNConnStringPassthrough(t *testing.T) {
	t.Setenv("MY_DSN", "sqlserver://user:pw@host?database=Db")
	dsn, err := buildDSN(pullArgs{ConnectionStringEnv: "MY_DSN"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dsn != "sqlserver://user:pw@host?database=Db" {
		t.Fatalf("unexpected DSN: %q", dsn)
	}
}

func TestBuildDSNConnStringEmpty(t *testing.T) {
	_ = os.Unsetenv("MISSING_DSN")
	if _, err := buildDSN(pullArgs{ConnectionStringEnv: "MISSING_DSN"}); err == nil {
		t.Fatalf("expected error for empty connection-string env")
	}
}

func TestMapTableKind(t *testing.T) {
	cases := []struct {
		in       string
		external bool
		want     string
	}{
		{"U", false, "Table"},
		{"V", false, "View"},
		{"BASE TABLE", false, "Table"},
		{"base table", false, "Table"},
		{"VIEW", false, "View"},
		{"U", true, "ExternalTable"},
		{"SOMETHING", false, "Unknown"},
	}
	for _, c := range cases {
		if got := mapTableKind(c.in, c.external); got != c.want {
			t.Errorf("mapTableKind(%q,%v)=%q want %q", c.in, c.external, got, c.want)
		}
	}
}

func TestMapObjectType(t *testing.T) {
	cases := map[string]string{
		"USER_TABLE":           "TABLE",
		"VIEW":                 "VIEW",
		"SQL_STORED_PROCEDURE": "PROCEDURE",
		"SQL_SCALAR_FUNCTION":  "FUNCTION",
		"SYNONYM":              "SYNONYM",
		"SEQUENCE_OBJECT":      "SEQUENCE",
		"":                     "OBJECT",
		"WIDGET":               "WIDGET",
	}
	for in, want := range cases {
		if got := mapObjectType(in); got != want {
			t.Errorf("mapObjectType(%q)=%q want %q", in, got, want)
		}
	}
}

func TestCanonicalizePrivilege(t *testing.T) {
	if got := canonicalizePrivilege("  select  "); got != "SELECT" {
		t.Fatalf("got %q", got)
	}
	if got := canonicalizePrivilege("CONTROL"); got != "CONTROL" {
		t.Fatalf("got %q", got)
	}
}

func TestIsRolePrincipal(t *testing.T) {
	if !isRolePrincipal("DATABASE_ROLE") {
		t.Fatal("DATABASE_ROLE should be a role")
	}
	if !isRolePrincipal("application_role") {
		t.Fatal("APPLICATION_ROLE should be a role")
	}
	if isRolePrincipal("SQL_USER") {
		t.Fatal("SQL_USER should not be a role")
	}
}

func TestBracketQuote(t *testing.T) {
	if got := bracketQuote("My DB"); got != "[My DB]" {
		t.Fatalf("got %q", got)
	}
	// Closing bracket is escaped by doubling.
	if got := bracketQuote("we]rd"); got != "[we]]rd]" {
		t.Fatalf("got %q", got)
	}
}

func TestMatchesAnyCI(t *testing.T) {
	if !matchesAnyCI("Sales", []string{"sales"}) {
		t.Fatal("expected case-insensitive match")
	}
	if matchesAnyCI("Sales", []string{"hr"}) {
		t.Fatal("unexpected match")
	}
}

func TestParseUint64(t *testing.T) {
	if v, ok := parseUint64("42"); !ok || v != 42 {
		t.Fatalf("got %d,%v", v, ok)
	}
	if v, ok := parseUint64("1234.0"); !ok || v != 1234 {
		t.Fatalf("float-form parse got %d,%v", v, ok)
	}
	if _, ok := parseUint64(""); ok {
		t.Fatal("empty should not parse")
	}
	if _, ok := parseUint64("abc"); ok {
		t.Fatal("garbage should not parse")
	}
}

func TestMssqlIdentCaseInsensitive(t *testing.T) {
	id := mssqlIdent("Customers")
	if id.Name != "Customers" {
		t.Fatalf("name mangled: %q", id.Name)
	}
	if id.CaseSensitive {
		t.Fatal("mssql idents should be case-insensitive")
	}
}

// TestMarshalSnapshotRoundTrip verifies the emitted JSON matches the wire
// contract: schema_version=2, provider mssql, and structural round-trip.
func TestMarshalSnapshotRoundTrip(t *testing.T) {
	dt := "int"
	nn := false
	provider := "mssql"
	snap := CatalogSnapshot{
		SchemaVersion: schemaVersion,
		Provider:      &provider,
		Databases: []CatalogDatabase{{
			Name: mssqlIdent("Sales"),
			Schemas: []CatalogSchema{{
				Name: mssqlIdent("dbo"),
				Tables: []CatalogTable{{
					Name:    mssqlIdent("Orders"),
					Kind:    "Table",
					Columns: []CatalogColumn{{Name: mssqlIdent("id"), DataType: &dt, Nullable: &nn}},
					Constraints: []CatalogConstraint{{
						Kind:    "PrimaryKey",
						Columns: []CatalogIdent{mssqlIdent("id")},
					}},
				}},
			}},
		}},
	}

	data, err := marshalSnapshot(snap)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var back map[string]any
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("emitted JSON does not parse: %v", err)
	}
	if back["schema_version"].(float64) != 2 {
		t.Fatalf("schema_version != 2: %v", back["schema_version"])
	}
	if back["provider"].(string) != "mssql" {
		t.Fatalf("provider != mssql: %v", back["provider"])
	}

	// Structural round-trip into the typed shape.
	var typed CatalogSnapshot
	if err := json.Unmarshal(data, &typed); err != nil {
		t.Fatalf("typed round-trip failed: %v", err)
	}
	if len(typed.Databases) != 1 || len(typed.Databases[0].Schemas) != 1 {
		t.Fatalf("structure lost in round-trip: %+v", typed)
	}
	col := typed.Databases[0].Schemas[0].Tables[0].Columns[0]
	if col.DataType == nil || *col.DataType != "int" {
		t.Fatalf("column data_type lost")
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
