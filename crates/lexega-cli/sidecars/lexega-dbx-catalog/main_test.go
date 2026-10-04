// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
	t.Setenv(defaultTokenEnv, "test-token")

	args, err := parsePullArgs([]string{
		"--provider", "databricks",
		"--workspace-url", "https://dbc-123.cloud.databricks.com",
		"--include-db", "main",
		"--include-grants",
		"--out", "-",
	})
	if err != nil {
		t.Fatalf("parsePullArgs failed: %v", err)
	}
	if args.WorkspaceURL != "https://dbc-123.cloud.databricks.com" {
		t.Fatalf("unexpected workspace url: %q", args.WorkspaceURL)
	}
	if args.TokenEnv != defaultTokenEnv {
		t.Fatalf("unexpected token env: %q", args.TokenEnv)
	}
	if len(args.IncludeDB) != 1 || args.IncludeDB[0] != "main" || !args.IncludeGrants {
		t.Fatalf("unexpected scope: %+v", args)
	}
}

func TestParsePullArgsRequiresWorkspaceURL(t *testing.T) {
	t.Setenv(defaultTokenEnv, "test-token")

	_, err := parsePullArgs([]string{"--out", "-"})
	if err == nil {
		t.Fatalf("expected error when workspace-url missing")
	}
}

func TestParsePullArgsProvider(t *testing.T) {
	t.Setenv(defaultTokenEnv, "test-token")
	base := []string{"--workspace-url", "https://dbc-123.cloud.databricks.com", "--out", "-"}

	// The provider is optional, and every name the CLI resolves to this
	// extractor is accepted.
	for _, provider := range []string{"", "databricks", "DBX", "unity"} {
		argv := base
		if provider != "" {
			argv = append([]string{"--provider", provider}, base...)
		}
		if _, err := parsePullArgs(argv); err != nil {
			t.Fatalf("provider %q: %v", provider, err)
		}
	}

	_, err := parsePullArgs(append([]string{"--provider", "snowflake"}, base...))
	if err == nil || !strings.Contains(err.Error(), "invalid --provider") {
		t.Fatalf("expected an invalid-provider error, got %v", err)
	}
}

func TestParsePullArgsToken(t *testing.T) {
	base := []string{"--workspace-url", "https://dbc-123.cloud.databricks.com", "--out", "-"}

	t.Setenv(defaultTokenEnv, "")
	t.Setenv("MY_TOKEN", "")
	if _, err := parsePullArgs(base); err == nil {
		t.Fatalf("expected error when no token is available")
	}
	// Reading the token from stdin needs no environment variable.
	if _, err := parsePullArgs(append([]string{"--token-stdin"}, base...)); err != nil {
		t.Fatalf("--token-stdin: %v", err)
	}

	t.Setenv("MY_TOKEN", "named")
	if _, err := parsePullArgs(append([]string{"--token-env", "MY_TOKEN"}, base...)); err != nil {
		t.Fatalf("--token-env: %v", err)
	}
	if got := tokenFromEnv("MY_TOKEN"); got != "named" {
		t.Fatalf("unexpected token: %q", got)
	}

	// A named variable that is empty falls back to the default one.
	t.Setenv("MY_TOKEN", "")
	t.Setenv(defaultTokenEnv, "fallback")
	if got := tokenFromEnv("MY_TOKEN"); got != "fallback" {
		t.Fatalf("unexpected token: %q", got)
	}
}

func TestNormalizeWorkspaceURL(t *testing.T) {
	got, err := normalizeWorkspaceURL("dbc-123.cloud.databricks.com")
	if err != nil {
		t.Fatalf("normalizeWorkspaceURL failed: %v", err)
	}
	if got != "https://dbc-123.cloud.databricks.com" {
		t.Fatalf("unexpected normalized url: %q", got)
	}

	got2, err := normalizeWorkspaceURL("https://dbc-123.cloud.databricks.com/")
	if err != nil {
		t.Fatalf("normalizeWorkspaceURL failed: %v", err)
	}
	if got2 != "https://dbc-123.cloud.databricks.com" {
		t.Fatalf("unexpected normalized url: %q", got2)
	}
}

// tableJSON is a table as the Unity Catalog API returns it.
const tableJSON = `{
  "name": "employees",
  "full_name": "main.hr.employees",
  "table_type": "MANAGED",
  "columns": [
    {"name": "id", "type_text": "bigint", "type_name": "LONG", "nullable": false},
    {"name": "ssn", "type_text": "string", "nullable": true,
     "mask": {"function_name": "main.sec.mask_ssn", "using_column_names": ["id"]}},
    {"name": "dept_id", "type_text": "bigint", "nullable": true}
  ],
  "table_constraints": [
    {"primary_key_constraint": {"name": "pk_emp", "child_columns": ["id"], "rely": true}},
    {"foreign_key_constraint": {"name": "fk_dept", "child_columns": ["dept_id"],
      "parent_table": "main.hr.departments", "parent_columns": ["id"]}},
    {"named_table_constraint": {"name": "chk_ssn"}}
  ],
  "row_filter": {"function_name": "main.sec.only_my_dept", "input_column_names": ["dept_id"]},
  "properties": {"spark.sql.statistics.numRows": "1500"}
}`

func decodeTable(t *testing.T, doc string) dbxTableDef {
	t.Helper()
	var table dbxTableDef
	if err := json.Unmarshal([]byte(doc), &table); err != nil {
		t.Fatalf("decode table: %v", err)
	}
	return table
}

func TestExtractDatabricksConstraints(t *testing.T) {
	constraints := extractDatabricksConstraints(decodeTable(t, tableJSON).TableConstraints)
	if len(constraints) != 3 {
		t.Fatalf("expected 3 constraints, got %d", len(constraints))
	}

	pk := constraints[0]
	if pk.Kind != "PrimaryKey" || pk.Name == nil || *pk.Name != "pk_emp" {
		t.Fatalf("unexpected primary key: %+v", pk)
	}
	if len(pk.Columns) != 1 || pk.Columns[0].Name != "id" {
		t.Fatalf("unexpected primary key columns: %+v", pk.Columns)
	}
	if pk.Rely == nil || !*pk.Rely {
		t.Fatalf("expected rely on the primary key")
	}

	fk := constraints[1]
	if fk.Kind != "ForeignKey" || len(fk.Columns) != 1 || fk.Columns[0].Name != "dept_id" {
		t.Fatalf("unexpected foreign key: %+v", fk)
	}
	if fk.RefTable == nil || fk.RefTable.Database.Name != "main" || fk.RefTable.Schema.Name != "hr" || fk.RefTable.Name.Name != "departments" {
		t.Fatalf("unexpected referenced table: %+v", fk.RefTable)
	}
	if len(fk.RefColumns) != 1 || fk.RefColumns[0].Name != "id" {
		t.Fatalf("unexpected referenced columns: %+v", fk.RefColumns)
	}
	if fk.Rely != nil {
		t.Fatalf("rely is unset when the API does not report it")
	}

	named := constraints[2]
	if named.Kind != "Unknown" || named.Name == nil || *named.Name != "chk_ssn" {
		t.Fatalf("unexpected named constraint: %+v", named)
	}
}

func TestExtractDatabricksPolicies(t *testing.T) {
	policies, refs := extractDatabricksPolicies("main", "hr", "employees", decodeTable(t, tableJSON))
	if len(policies) != 2 || len(refs) != 2 {
		t.Fatalf("expected 2 policies and 2 references, got %d and %d", len(policies), len(refs))
	}

	filter, filterRef := policies[0], refs[0]
	if filter.Kind != "RowAccessPolicy" || filter.Name.Name.Name != "employees__row_filter" || *filter.Body != "main.sec.only_my_dept(...)" {
		t.Fatalf("unexpected row filter: %+v", filter)
	}
	if filterRef.RefColumn != nil || filterRef.RefTable.Name.Name != "employees" {
		t.Fatalf("unexpected row filter reference: %+v", filterRef)
	}

	mask, maskRef := policies[1], refs[1]
	if mask.Kind != "MaskingPolicy" || mask.Name.Name.Name != "employees__mask__ssn" || *mask.Body != "main.sec.mask_ssn(...)" {
		t.Fatalf("unexpected column mask: %+v", mask)
	}
	if maskRef.RefColumn == nil || maskRef.RefColumn.Name != "ssn" {
		t.Fatalf("unexpected column mask reference: %+v", maskRef)
	}
}

func TestTableWithoutPoliciesOrConstraints(t *testing.T) {
	table := decodeTable(t, `{"name": "plain", "columns": [{"name": "a", "type_text": "int"}]}`)
	if got := extractDatabricksConstraints(table.TableConstraints); got != nil {
		t.Fatalf("expected no constraints, got %+v", got)
	}
	policies, refs := extractDatabricksPolicies("main", "hr", "plain", table)
	if len(policies) != 0 || len(refs) != 0 {
		t.Fatalf("expected no policies, got %d and %d", len(policies), len(refs))
	}
}

// The list endpoint may leave out what the get endpoint returns, so a pull
// reads each table from both.
func TestPullCatalogReadsTheWholeTable(t *testing.T) {
	var requests []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/2.1/unity-catalog/schemas":
			w.Write([]byte(`{"schemas": [{"name": "hr"}]}`))
		case "/api/2.1/unity-catalog/tables":
			w.Write([]byte(`{"tables": [{"name": "employees", "full_name": "main.hr.employees", "table_type": "MANAGED",
				"columns": [{"name": "id", "type_text": "bigint"}]}]}`))
		case "/api/2.1/unity-catalog/tables/main.hr.employees":
			w.Write([]byte(tableJSON))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	tablesSeen := 0
	db, tableCount, policies, refs, securables, err := databricksPullCatalog(
		context.Background(), srv.Client(), srv.URL, "test-token", "main", 0, &tablesSeen)
	if err != nil {
		t.Fatalf("pull failed: %v", err)
	}
	if tableCount != 1 || len(db.Schemas) != 1 || len(db.Schemas[0].Tables) != 1 {
		t.Fatalf("unexpected catalog: %+v", db)
	}

	table := db.Schemas[0].Tables[0]
	if len(table.Columns) != 3 {
		t.Fatalf("expected the 3 columns of the complete table, got %d", len(table.Columns))
	}
	if len(table.Constraints) != 3 || table.Constraints[0].Kind != "PrimaryKey" {
		t.Fatalf("unexpected constraints: %+v", table.Constraints)
	}
	if table.RowCountEstimate == nil || *table.RowCountEstimate != 1500 {
		t.Fatalf("unexpected row count: %v", table.RowCountEstimate)
	}
	if len(policies) != 2 || len(refs) != 2 {
		t.Fatalf("expected the row filter and the column mask, got %d policies", len(policies))
	}
	if len(securables) != 3 {
		t.Fatalf("expected catalog, schema and table securables, got %d", len(securables))
	}

	for _, request := range requests {
		if !strings.HasPrefix(request, "GET ") {
			t.Fatalf("unexpected request: %s", request)
		}
	}
	if len(requests) != 3 {
		t.Fatalf("expected 3 requests, got %v", requests)
	}
}

func TestMapDatabricksObjectType(t *testing.T) {
	if got := mapDatabricksObjectType("VIEW"); got != "VIEW" {
		t.Fatalf("expected VIEW, got %q", got)
	}
	if got := mapDatabricksObjectType("MANAGED_TABLE"); got != "TABLE" {
		t.Fatalf("expected TABLE, got %q", got)
	}
}

func TestCanonicalizeDatabricksPrivilege(t *testing.T) {
	tests := []struct {
		privilege  string
		objectType string
		want       string
	}{
		// USE variants → USAGE
		{"USE CATALOG", "DATABASE", "USAGE"},
		{"USE SCHEMA", "SCHEMA", "USAGE"},
		{"USE CONNECTION", "CONNECTION", "USAGE"},
		{"USE", "CATALOG", "USAGE"},
		{"use catalog", "DATABASE", "USAGE"},  // case-insensitive
		{"  USE SCHEMA  ", "SCHEMA", "USAGE"}, // whitespace trimmed

		// Snowflake USAGE passes through (already canonical)
		{"USAGE", "SCHEMA", "USAGE"},
		{"usage", "SCHEMA", "USAGE"},

		// Databricks-specific privileges pass through uppercased
		{"SELECT", "TABLE", "SELECT"},
		{"MODIFY", "TABLE", "MODIFY"},
		{"MANAGE", "CATALOG", "MANAGE"},
		{"APPLY TAG", "TABLE", "APPLY TAG"},
		{"CREATE TABLE", "SCHEMA", "CREATE TABLE"},
		{"CREATE SCHEMA", "CATALOG", "CREATE SCHEMA"},
		{"READ FILES", "EXTERNAL LOCATION", "READ FILES"},
		{"WRITE FILES", "EXTERNAL LOCATION", "WRITE FILES"},
		{"READ VOLUME", "VOLUME", "READ VOLUME"},
		{"WRITE VOLUME", "VOLUME", "WRITE VOLUME"},
		{"BROWSE", "CATALOG", "BROWSE"},
		{"EXECUTE", "FUNCTION", "EXECUTE"},
		{"EXTERNAL USE LOCATION", "EXTERNAL LOCATION", "EXTERNAL USE LOCATION"},
		{"EXTERNAL USE SCHEMA", "SCHEMA", "EXTERNAL USE SCHEMA"},
		{"ALL PRIVILEGES", "CATALOG", "ALL PRIVILEGES"},

		// Empty/edge cases
		{"", "TABLE", ""},
		{"  ", "TABLE", ""},
	}
	for _, tt := range tests {
		got := canonicalizeDatabricksPrivilege(tt.privilege, tt.objectType)
		if got != tt.want {
			t.Errorf("canonicalizeDatabricksPrivilege(%q, %q) = %q, want %q",
				tt.privilege, tt.objectType, got, tt.want)
		}
	}
}

// pagedWorkspace answers the list endpoints one item per page.
func pagedWorkspace(t *testing.T, requests *[]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*requests = append(*requests, r.Method+" "+r.URL.RequestURI())
		q := r.URL.Query()
		page := q.Get("page_token")
		w.Header().Set("Content-Type", "application/json")
		respond := func(body string) { w.Write([]byte(body)) }
		switch {
		case r.URL.Path == "/api/2.1/unity-catalog/catalogs" && page == "":
			respond(`{"catalogs": [{"name": "main"}], "next_page_token": "c2"}`)
		case r.URL.Path == "/api/2.1/unity-catalog/catalogs" && page == "c2":
			respond(`{"catalogs": [{"name": "other"}]}`)

		case r.URL.Path == "/api/2.1/unity-catalog/schemas" && page == "":
			respond(`{"schemas": [{"name": "hr"}], "next_page_token": "s2"}`)
		case r.URL.Path == "/api/2.1/unity-catalog/schemas" && page == "s2":
			respond(`{"schemas": [{"name": "sales"}]}`)

		case r.URL.Path == "/api/2.1/unity-catalog/tables" && q.Get("schema_name") == "hr" && page == "":
			respond(`{"tables": [{"name": "employees", "table_type": "MANAGED"}], "next_page_token": "t2"}`)
		case r.URL.Path == "/api/2.1/unity-catalog/tables" && q.Get("schema_name") == "hr" && page == "t2":
			respond(`{"tables": [{"name": "departments", "table_type": "MANAGED"}]}`)
		// A page may be empty and still be followed by another.
		case r.URL.Path == "/api/2.1/unity-catalog/tables" && q.Get("schema_name") == "sales" && page == "":
			respond(`{"tables": [], "next_page_token": "more"}`)
		case r.URL.Path == "/api/2.1/unity-catalog/tables" && q.Get("schema_name") == "sales" && page == "more":
			respond(`{"tables": [{"name": "orders", "table_type": "MANAGED"}]}`)

		case r.URL.Path == "/api/2.1/unity-catalog/permissions/table/main.hr.employees" && page == "":
			respond(`{"privilege_assignments": [{"principal": "hr_team", "privileges": ["SELECT"]}], "next_page_token": "p2"}`)
		case r.URL.Path == "/api/2.1/unity-catalog/permissions/table/main.hr.employees" && page == "p2":
			respond(`{"privilege_assignments": [{"principal": "auditors", "privileges": ["SELECT"]}]}`)

		case strings.HasPrefix(r.URL.Path, "/api/2.0/preview/scim/v2/"):
			respond(`{"Resources": [], "totalResults": 0, "startIndex": 1, "itemsPerPage": 0}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestListCallsFollowNextPageToken(t *testing.T) {
	var requests []string
	srv := pagedWorkspace(t, &requests)
	ctx := context.Background()

	catalogs, err := databricksListCatalogs(ctx, srv.Client(), srv.URL, "test-token")
	if err != nil {
		t.Fatalf("list catalogs: %v", err)
	}
	if strings.Join(catalogs, ",") != "main,other" {
		t.Fatalf("unexpected catalogs: %v", catalogs)
	}

	tablesSeen := 0
	db, tableCount, _, _, _, err := databricksPullCatalog(ctx, srv.Client(), srv.URL, "test-token", "main", 0, &tablesSeen)
	if err != nil {
		t.Fatalf("pull catalog: %v", err)
	}
	var tables []string
	for _, schema := range db.Schemas {
		for _, table := range schema.Tables {
			tables = append(tables, schema.Name.Name+"."+table.Name.Name)
		}
	}
	if tableCount != 3 || strings.Join(tables, ",") != "hr.departments,hr.employees,sales.orders" {
		t.Fatalf("unexpected tables: %d %v", tableCount, tables)
	}

	grants, err := databricksPullGrantGraph(ctx, srv.Client(), srv.URL, "test-token", []dbxSecurableRef{
		{SecurableType: "table", ObjectType: "TABLE", FullName: "main.hr.employees"},
	})
	if err != nil {
		t.Fatalf("pull grants: %v", err)
	}
	if len(grants.ObjectPrivileges) != 2 || grants.ObjectPrivileges[0].Role != "hr_team" || grants.ObjectPrivileges[1].Role != "auditors" {
		t.Fatalf("unexpected privileges: %+v", grants.ObjectPrivileges)
	}

	// Catalogs, schemas and tables ask for the server's page length on every
	// page; later pages add only the token.
	want := []string{
		"GET /api/2.1/unity-catalog/catalogs?max_results=0",
		"GET /api/2.1/unity-catalog/catalogs?max_results=0&page_token=c2",
		"GET /api/2.1/unity-catalog/schemas?catalog_name=main&max_results=0",
		"GET /api/2.1/unity-catalog/schemas?catalog_name=main&max_results=0&page_token=s2",
		"GET /api/2.1/unity-catalog/tables?catalog_name=main&max_results=0&schema_name=hr",
		"GET /api/2.1/unity-catalog/tables?catalog_name=main&max_results=0&page_token=t2&schema_name=hr",
	}
	for i, request := range want {
		if i >= len(requests) || requests[i] != request {
			t.Fatalf("request %d: want %q, got %v", i, request, requests)
		}
	}
	for _, request := range []string{
		"GET /api/2.1/unity-catalog/tables?catalog_name=main&max_results=0&page_token=more&schema_name=sales",
		// A permissions request carries no page length.
		"GET /api/2.1/unity-catalog/permissions/table/main.hr.employees",
		"GET /api/2.1/unity-catalog/permissions/table/main.hr.employees?page_token=p2",
	} {
		found := false
		for _, got := range requests {
			found = found || got == request
		}
		if !found {
			t.Fatalf("missing request %q in %v", request, requests)
		}
	}
}

// A workspace that keeps answering with the same token ends the pull with an
// error instead of being asked for the same page forever.
func TestListStopsWhenThePageTokenRepeats(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Write([]byte(`{"catalogs": [{"name": "main"}], "next_page_token": "again"}`))
	}))
	defer srv.Close()

	_, err := databricksListCatalogs(context.Background(), srv.Client(), srv.URL, "test-token")
	if err == nil || !strings.Contains(err.Error(), "same page token") {
		t.Fatalf("expected a repeated-token error, got %v", err)
	}
	if calls != 2 {
		t.Fatalf("expected the list to stop after 2 requests, made %d", calls)
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
