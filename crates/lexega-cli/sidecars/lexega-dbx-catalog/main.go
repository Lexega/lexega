// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

// Command lexega-dbx-catalog is the Databricks catalog sidecar for Lexega.
//
// It reads Unity Catalog metadata from one workspace over its REST API:
// catalogs, schemas, tables, columns, constraints, row filters and column
// masks, and with --include-grants the permissions on each of those plus the
// workspace's users and groups from the SCIM API. It emits a schema_version=2
// CatalogSnapshot JSON consumed by the Rust engine (provider "databricks").
//
// Invocation contract (driven by `lexega catalog pull`):
//
//	lexega-dbx-catalog pull --out <file.json|-> --workspace-url <url> [flags]
//
// Snapshot JSON on stdout (with --out -) or written to the --out path; all
// progress goes to stderr so stdout stays clean for piping. The only network
// peer is the workspace named by --workspace-url, and every request is a GET.
package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// version is set at build time via -ldflags "-X main.version=..."
var version = "dev"

// thirdPartyLicenses is what the licenses subcommand prints.
//
//go:embed THIRD_PARTY_LICENSES.txt
var thirdPartyLicenses string

// defaultTokenEnv names the environment variable read for the access token
// unless --token-env names another.
const defaultTokenEnv = "DATABRICKS_TOKEN"

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func trimSpaceBytes(b []byte) []byte {
	start := 0
	for start < len(b) {
		switch b[start] {
		case ' ', '\t', '\n', '\r':
			start++
		default:
			goto endTrimLeft
		}
	}

endTrimLeft:
	end := len(b)
	for end > start {
		switch b[end-1] {
		case ' ', '\t', '\n', '\r':
			end--
		default:
			goto endTrimRight
		}
	}

endTrimRight:
	if start == 0 && end == len(b) {
		return b
	}
	return b[start:end]
}

// ---------------------------------------------------------------------------
// Wire structs — the shapes `lexega-sf-catalog` emits, so the Rust serde layer
// (CatalogSnapshot::load_from_path) accepts the output unchanged. Only the
// fields this extractor populates are kept; the Rust side defaults the rest.
// ---------------------------------------------------------------------------

type CatalogIdent struct {
	Name          string `json:"name"`
	CaseSensitive bool   `json:"case_sensitive,omitempty"`
}

type CatalogColumn struct {
	Name     CatalogIdent `json:"name"`
	DataType *string      `json:"data_type,omitempty"`
	Nullable *bool        `json:"nullable,omitempty"`
}

type CatalogTable struct {
	Name    CatalogIdent    `json:"name"`
	Kind    string          `json:"kind,omitempty"`
	Columns []CatalogColumn `json:"columns,omitempty"`

	RowCountEstimate *uint64 `json:"row_count_estimate,omitempty"`
	BytesEstimate    *uint64 `json:"bytes_estimate,omitempty"`

	Constraints []CatalogConstraint `json:"constraints,omitempty"`
}

type CatalogObjectName struct {
	Database CatalogIdent `json:"database"`
	Schema   CatalogIdent `json:"schema"`
	Name     CatalogIdent `json:"name"`
}

type CatalogConstraint struct {
	Kind string  `json:"kind,omitempty"`
	Name *string `json:"name,omitempty"`

	Columns []CatalogIdent `json:"columns,omitempty"`

	RefTable   *CatalogObjectName `json:"ref_table,omitempty"`
	RefColumns []CatalogIdent     `json:"ref_columns,omitempty"`

	Rely *bool `json:"rely,omitempty"`
}

type CatalogSchema struct {
	Name   CatalogIdent   `json:"name"`
	Tables []CatalogTable `json:"tables,omitempty"`
}

type CatalogDatabase struct {
	Name    CatalogIdent    `json:"name"`
	Schemas []CatalogSchema `json:"schemas,omitempty"`
}

// CatalogPolicy is a row filter or a column mask, named after the table
// (and column) it is bound to.
type CatalogPolicy struct {
	Name CatalogObjectName `json:"name"`
	Kind string            `json:"kind,omitempty"`
	Body *string           `json:"body,omitempty"`
}

// CatalogPolicyReference binds a policy to a table or one of its columns.
type CatalogPolicyReference struct {
	PolicyName CatalogObjectName `json:"policy_name"`
	PolicyKind string            `json:"policy_kind,omitempty"`
	RefTable   CatalogObjectName `json:"ref_table"`
	RefColumn  *CatalogIdent     `json:"ref_column,omitempty"`
	Enabled    *bool             `json:"enabled,omitempty"`
}

// CatalogRoleEdge is a group nested in another: members of the child group
// receive the parent group's grants.
type CatalogRoleEdge struct {
	ParentRole string `json:"parent"`
	ChildRole  string `json:"child"`
}

// CatalogObjectPrivilege is one privilege a principal holds on a securable.
type CatalogObjectPrivilege struct {
	Role       string `json:"role"`
	Privilege  string `json:"privilege"`
	ObjectType string `json:"object_type"`
	ObjectFQN  string `json:"object"`
}

// CatalogUserRole is a user's membership of a group.
type CatalogUserRole struct {
	User string `json:"user"`
	Role string `json:"role"`
}

// CatalogGrants is the grant graph for effective access analysis.
type CatalogGrants struct {
	RoleHierarchy    []CatalogRoleEdge        `json:"role_hierarchy,omitempty"`
	ObjectPrivileges []CatalogObjectPrivilege `json:"object_privileges,omitempty"`
	UserRoles        []CatalogUserRole        `json:"user_roles,omitempty"`
}

type CatalogSnapshot struct {
	SchemaVersion    uint32                   `json:"schema_version"`
	GeneratedAt      *string                  `json:"generated_at,omitempty"`
	Source           *string                  `json:"source,omitempty"`
	Provider         *string                  `json:"provider,omitempty"`
	Databases        []CatalogDatabase        `json:"databases,omitempty"`
	Policies         []CatalogPolicy          `json:"policies,omitempty"`
	PolicyReferences []CatalogPolicyReference `json:"policy_references,omitempty"`
	Grants           *CatalogGrants           `json:"grants,omitempty"`
}

type pullArgs struct {
	Out          string
	WorkspaceURL string

	TokenEnv   string
	TokenStdin bool

	IncludeDB []string
	ExcludeDB []string

	MaxTables     int
	IncludeGrants bool
}

func progressf(format string, args ...any) {
	// Keep progress on stderr so snapshot JSON on stdout (`--out -`) stays clean.
	// Intentionally lightweight (no progress bar) to remain CI/log friendly.
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "pull":
		args, err := parsePullArgs(os.Args[2:])
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			os.Exit(2)
		}
		if err := runPull(args); err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			os.Exit(1)
		}
	case "version", "--version", "-V":
		fmt.Printf("lexega-dbx-catalog %s\n", version)
	case "licenses", "--licenses":
		fmt.Print(thirdPartyLicenses)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	prog := filepath.Base(os.Args[0])
	fmt.Fprintf(os.Stderr, "Usage:\n")
	fmt.Fprintf(os.Stderr, "  %s pull --out <file.json|-> --workspace-url <https://...> [flags]\n", prog)
	fmt.Fprintf(os.Stderr, "  %s licenses\n", prog)
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "Connection flags:\n")
	fmt.Fprintf(os.Stderr, "  --workspace-url <https://...>  workspace to read\n")
	fmt.Fprintf(os.Stderr, "  --token-env <ENV>              environment variable holding the access token (default: %s)\n", defaultTokenEnv)
	fmt.Fprintf(os.Stderr, "  --token-stdin                  read the access token from stdin\n")
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "Scope flags:\n")
	fmt.Fprintf(os.Stderr, "  --include-db <CATALOG> (repeatable; default: all accessible)\n")
	fmt.Fprintf(os.Stderr, "  --exclude-db <CATALOG> (repeatable)\n")
	fmt.Fprintf(os.Stderr, "  --max-tables <n> (default: 0 = unlimited)\n")
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "Grant graph flags (for effective access analysis):\n")
	fmt.Fprintf(os.Stderr, "  --include-grants    Pull Unity Catalog permissions, users and groups\n")
}

func parsePullArgs(argv []string) (pullArgs, error) {
	fs := flag.NewFlagSet("pull", flag.ContinueOnError)
	fs.SetOutput(ioDiscard{})

	var a pullArgs
	// `lexega catalog pull` forwards the provider it was given.
	var provider string
	fs.StringVar(&a.Out, "out", "", "")
	fs.StringVar(&provider, "provider", "databricks", "")
	fs.StringVar(&a.WorkspaceURL, "workspace-url", "", "")
	fs.StringVar(&a.TokenEnv, "token-env", defaultTokenEnv, "")
	fs.BoolVar(&a.TokenStdin, "token-stdin", false, "")
	fs.IntVar(&a.MaxTables, "max-tables", 0, "")
	fs.BoolVar(&a.IncludeGrants, "include-grants", false, "")

	var includeDB multiString
	var excludeDB multiString
	fs.Var(&includeDB, "include-db", "")
	fs.Var(&excludeDB, "exclude-db", "")

	if err := fs.Parse(argv); err != nil {
		return pullArgs{}, err
	}
	a.IncludeDB = includeDB
	a.ExcludeDB = excludeDB

	if a.Out == "" {
		return pullArgs{}, errors.New("--out is required")
	}

	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "databricks", "dbx", "unity":
	default:
		return pullArgs{}, fmt.Errorf("invalid --provider: %q (this extractor reads Databricks)", provider)
	}

	if strings.TrimSpace(a.WorkspaceURL) == "" {
		return pullArgs{}, errors.New("--workspace-url is required")
	}
	if !a.TokenStdin && tokenFromEnv(a.TokenEnv) == "" {
		return pullArgs{}, missingTokenError(a.TokenEnv)
	}

	return a, nil
}

// tokenFromEnv reads the access token from the variable named by --token-env,
// falling back to the default variable.
func tokenFromEnv(name string) string {
	if tok := strings.TrimSpace(os.Getenv(name)); tok != "" {
		return tok
	}
	return strings.TrimSpace(os.Getenv(defaultTokenEnv))
}

func missingTokenError(name string) error {
	if name == defaultTokenEnv {
		return fmt.Errorf("missing Databricks token: set %s or use --token-stdin", defaultTokenEnv)
	}
	return fmt.Errorf("missing Databricks token: set %s or %s, or use --token-stdin", name, defaultTokenEnv)
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) { return len(p), nil }

type multiString []string

func (m *multiString) String() string { return strings.Join(*m, ",") }
func (m *multiString) Set(v string) error {
	*m = append(*m, v)
	return nil
}

func runPull(args pullArgs) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	workspaceURL, err := normalizeWorkspaceURL(args.WorkspaceURL)
	if err != nil {
		return err
	}

	tokenBytes, err := resolveDatabricksTokenBytes(args)
	if err != nil {
		return err
	}
	token := string(tokenBytes)
	zeroBytes(tokenBytes)

	progressf("Connecting to Databricks workspace: %s", workspaceURL)

	client := &http.Client{Timeout: 60 * time.Second}

	catalogNames, err := databricksListCatalogs(ctx, client, workspaceURL, token)
	if err != nil {
		return fmt.Errorf("list databricks catalogs: %w", err)
	}

	selectedCatalogs := make([]string, 0, len(catalogNames))
	for _, cat := range catalogNames {
		if len(args.IncludeDB) > 0 && !matches_any_ident_filter(cat, args.IncludeDB) {
			continue
		}
		if len(args.ExcludeDB) > 0 && matches_any_ident_filter(cat, args.ExcludeDB) {
			continue
		}
		selectedCatalogs = append(selectedCatalogs, cat)
	}
	sort.Strings(selectedCatalogs)

	if len(args.IncludeDB) > 0 && len(selectedCatalogs) == 0 {
		return fmt.Errorf("no catalogs matched --include-db filters: %v", args.IncludeDB)
	}

	progressf("Catalogs selected: %d", len(selectedCatalogs))

	snapshot := CatalogSnapshot{SchemaVersion: 2}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	snapshot.GeneratedAt = &now
	provider := "databricks"
	snapshot.Provider = &provider
	source := fmt.Sprintf("databricks workspace=%s", workspaceURL)
	snapshot.Source = &source

	tablesSeen := 0
	allSecurables := make([]dbxSecurableRef, 0)
	for _, catalogName := range selectedCatalogs {
		dbEntry, tableCount, policies, refs, securables, err := databricksPullCatalog(ctx, client, workspaceURL, token, catalogName, args.MaxTables, &tablesSeen)
		if err != nil {
			return fmt.Errorf("pull databricks catalog %s: %w", catalogName, err)
		}
		if len(policies) > 0 {
			snapshot.Policies = append(snapshot.Policies, policies...)
		}
		if len(refs) > 0 {
			snapshot.PolicyReferences = append(snapshot.PolicyReferences, refs...)
		}
		if len(securables) > 0 {
			allSecurables = append(allSecurables, securables...)
		}
		if tableCount == 0 {
			continue
		}
		snapshot.Databases = append(snapshot.Databases, dbEntry)
		progressf("  %s: tables=%d (total_tables=%d)", catalogName, tableCount, tablesSeen)
		if args.MaxTables > 0 && tablesSeen >= args.MaxTables {
			progressf("Reached max tables limit (%d); stopping.", args.MaxTables)
			break
		}
	}

	sort.Slice(snapshot.Databases, func(i, j int) bool {
		return strings.ToUpper(snapshot.Databases[i].Name.Name) < strings.ToUpper(snapshot.Databases[j].Name.Name)
	})

	if args.IncludeGrants {
		grants, err := databricksPullGrantGraph(ctx, client, workspaceURL, token, allSecurables)
		if err != nil {
			progressf("warning: failed to pull databricks grants: %v", err)
		} else {
			snapshot.Grants = grants
			objPrivs, roleEdges, userRoles := 0, 0, 0
			if grants != nil {
				objPrivs = len(grants.ObjectPrivileges)
				roleEdges = len(grants.RoleHierarchy)
				userRoles = len(grants.UserRoles)
			}
			progressf("Databricks grants: object_privileges=%d role_hierarchy=%d user_roles=%d", objPrivs, roleEdges, userRoles)
		}
	}

	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}

	if args.Out == "-" {
		progressf("Writing snapshot to stdout")
		if _, err := os.Stdout.Write(data); err != nil {
			return err
		}
		os.Stdout.Write([]byte("\n"))
		progressf("Wrote catalog snapshot to stdout")
		return nil
	}

	progressf("Writing snapshot: %s", args.Out)
	if err := os.WriteFile(args.Out, data, 0o644); err != nil {
		return err
	}
	progressf("Wrote catalog snapshot: %s", args.Out)
	return nil
}

func normalizeWorkspaceURL(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", errors.New("--workspace-url is required")
	}
	if !strings.Contains(trimmed, "://") {
		trimmed = "https://" + trimmed
	}

	u, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("invalid --workspace-url: %w", err)
	}
	if u.Scheme == "" {
		u.Scheme = "https"
	}
	if u.Host == "" {
		return "", errors.New("--workspace-url must include host, e.g. https://dbc-xxxx.cloud.databricks.com")
	}
	u.Path = ""
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	return strings.TrimRight(u.String(), "/"), nil
}

func resolveDatabricksTokenBytes(args pullArgs) ([]byte, error) {
	if args.TokenStdin {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, err
		}
		trimmed := trimSpaceBytes(b)
		if len(trimmed) == 0 {
			zeroBytes(b)
			return nil, errors.New("databricks token read from stdin is empty")
		}
		out := append([]byte(nil), trimmed...)
		zeroBytes(b)
		return out, nil
	}

	if tok := tokenFromEnv(args.TokenEnv); tok != "" {
		return []byte(tok), nil
	}
	return nil, missingTokenError(args.TokenEnv)
}

// serverPageLength, sent as max_results, asks a list endpoint to page its
// answer at the length the server is configured for.
const serverPageLength = "0"

// dbxPage is one page of a list response: its items, and the token that
// fetches the next page when there is one.
type dbxPage[T any] interface {
	items() []T
	nextPageToken() string
}

// dbxNamed is a catalog or a schema in a list response.
type dbxNamed struct {
	Name string `json:"name"`
}

type dbxCatalogListResponse struct {
	Catalogs      []dbxNamed `json:"catalogs"`
	NextPageToken string     `json:"next_page_token"`
}

func (r dbxCatalogListResponse) items() []dbxNamed     { return r.Catalogs }
func (r dbxCatalogListResponse) nextPageToken() string { return r.NextPageToken }

type dbxSchemaListResponse struct {
	Schemas       []dbxNamed `json:"schemas"`
	NextPageToken string     `json:"next_page_token"`
}

func (r dbxSchemaListResponse) items() []dbxNamed     { return r.Schemas }
func (r dbxSchemaListResponse) nextPageToken() string { return r.NextPageToken }

type dbxTableListResponse struct {
	Tables        []dbxTableDef `json:"tables"`
	NextPageToken string        `json:"next_page_token"`
}

func (r dbxTableListResponse) items() []dbxTableDef  { return r.Tables }
func (r dbxTableListResponse) nextPageToken() string { return r.NextPageToken }

// dbxTableDef is a table as both the list and the get endpoint return it.
type dbxTableDef struct {
	Name      string      `json:"name"`
	FullName  string      `json:"full_name"`
	TableType string      `json:"table_type"`
	Columns   []dbxColumn `json:"columns"`

	TableConstraints []dbxTableConstraint `json:"table_constraints"`
	RowFilter        *dbxFunctionRef      `json:"row_filter"`
	Properties       map[string]string    `json:"properties"`
}

type dbxColumn struct {
	Name     string          `json:"name"`
	TypeText string          `json:"type_text"`
	TypeName string          `json:"type_name"`
	Nullable *bool           `json:"nullable"`
	Mask     *dbxFunctionRef `json:"mask"`
}

// dbxFunctionRef names the function a row filter or a column mask applies.
type dbxFunctionRef struct {
	FunctionName string `json:"function_name"`
}

// dbxTableConstraint carries exactly one of its three members.
type dbxTableConstraint struct {
	PrimaryKey *dbxConstraint `json:"primary_key_constraint"`
	ForeignKey *dbxConstraint `json:"foreign_key_constraint"`
	Named      *dbxConstraint `json:"named_table_constraint"`
}

// dbxConstraint is the union of the fields the three constraint kinds carry:
// a named constraint has only a name, a primary key adds its columns, and a
// foreign key adds the table and columns it references.
type dbxConstraint struct {
	Name          string   `json:"name"`
	ChildColumns  []string `json:"child_columns"`
	ParentTable   string   `json:"parent_table"`
	ParentColumns []string `json:"parent_columns"`
	Rely          *bool    `json:"rely"`
}

type dbxPrivilegeAssignment struct {
	Principal  string   `json:"principal"`
	Privileges []string `json:"privileges"`
}

type dbxPermissionResponse struct {
	PrivilegeAssignments []dbxPrivilegeAssignment `json:"privilege_assignments"`
	NextPageToken        string                   `json:"next_page_token"`
}

func (r dbxPermissionResponse) items() []dbxPrivilegeAssignment { return r.PrivilegeAssignments }
func (r dbxPermissionResponse) nextPageToken() string           { return r.NextPageToken }

type dbxSecurableRef struct {
	SecurableType string
	ObjectType    string
	FullName      string
}

// SCIM response types for user/group extraction (effective access expansion)

type scimListResponse[T any] struct {
	Resources    []T `json:"Resources"`
	TotalResults int `json:"totalResults"`
	StartIndex   int `json:"startIndex"`
	ItemsPerPage int `json:"itemsPerPage"`
}

type scimGroupRef struct {
	Display string `json:"display"`
	Value   string `json:"value"`
}

type scimMember struct {
	Display string `json:"display"`
	Value   string `json:"value"`
	Ref     string `json:"$ref"`
}

type scimGroup struct {
	ID          string         `json:"id"`
	DisplayName string         `json:"displayName"`
	Members     []scimMember   `json:"members"`
	Groups      []scimGroupRef `json:"groups"` // parent groups this group belongs to
}

type scimUser struct {
	ID          string         `json:"id"`
	UserName    string         `json:"userName"`
	DisplayName string         `json:"displayName"`
	Active      bool           `json:"active"`
	Groups      []scimGroupRef `json:"groups"` // groups user belongs to
}

func databricksListCatalogs(ctx context.Context, client *http.Client, workspaceURL, token string) ([]string, error) {
	catalogs, err := databricksList[dbxNamed, dbxCatalogListResponse](ctx, client, workspaceURL, token, "/api/2.1/unity-catalog/catalogs", map[string]string{
		"max_results": serverPageLength,
	})
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(catalogs))
	for _, c := range catalogs {
		name := strings.TrimSpace(c.Name)
		if name != "" {
			out = append(out, name)
		}
	}
	return out, nil
}

func databricksPullCatalog(
	ctx context.Context,
	client *http.Client,
	workspaceURL, token, catalogName string,
	maxTables int,
	tablesSeen *int,
) (CatalogDatabase, int, []CatalogPolicy, []CatalogPolicyReference, []dbxSecurableRef, error) {
	schemas, err := databricksList[dbxNamed, dbxSchemaListResponse](ctx, client, workspaceURL, token, "/api/2.1/unity-catalog/schemas", map[string]string{
		"catalog_name": catalogName,
		"max_results":  serverPageLength,
	})
	if err != nil {
		return CatalogDatabase{}, 0, nil, nil, nil, err
	}

	schemaEntries := make([]CatalogSchema, 0, len(schemas))
	tableCount := 0
	policies := make([]CatalogPolicy, 0)
	policyRefs := make([]CatalogPolicyReference, 0)
	securables := make([]dbxSecurableRef, 0)

	securables = append(securables, dbxSecurableRef{
		SecurableType: "catalog",
		ObjectType:    "DATABASE",
		FullName:      catalogName,
	})

	for _, s := range schemas {
		schemaName := strings.TrimSpace(s.Name)
		if schemaName == "" {
			continue
		}

		tableDefs, err := databricksList[dbxTableDef, dbxTableListResponse](ctx, client, workspaceURL, token, "/api/2.1/unity-catalog/tables", map[string]string{
			"catalog_name": catalogName,
			"schema_name":  schemaName,
			"max_results":  serverPageLength,
		})
		if err != nil {
			return CatalogDatabase{}, 0, nil, nil, nil, err
		}

		securables = append(securables, dbxSecurableRef{
			SecurableType: "schema",
			ObjectType:    "SCHEMA",
			FullName:      fmt.Sprintf("%s.%s", catalogName, schemaName),
		})

		tables := make([]CatalogTable, 0, len(tableDefs))
		for _, t := range tableDefs {
			if maxTables > 0 && *tablesSeen >= maxTables {
				break
			}

			tableName := strings.TrimSpace(t.Name)
			if tableName == "" && t.FullName != "" {
				parts := strings.Split(t.FullName, ".")
				if len(parts) > 0 {
					tableName = strings.TrimSpace(parts[len(parts)-1])
				}
			}
			if tableName == "" {
				continue
			}

			fullName := strings.TrimSpace(t.FullName)
			if fullName == "" {
				fullName = fmt.Sprintf("%s.%s.%s", catalogName, schemaName, tableName)
			}

			// The get endpoint returns the complete table; take from it whatever
			// the list entry left out.
			detail, derr := databricksGetTableDetail(ctx, client, workspaceURL, token, fullName)
			if derr == nil {
				if len(detail.Columns) > 0 {
					t.Columns = detail.Columns
				}
				if len(detail.TableConstraints) > 0 {
					t.TableConstraints = detail.TableConstraints
				}
				if detail.RowFilter != nil {
					t.RowFilter = detail.RowFilter
				}
				if len(detail.Properties) > 0 {
					t.Properties = detail.Properties
				}
			}

			cols := make([]CatalogColumn, 0, len(t.Columns))
			for _, c := range t.Columns {
				colName := strings.TrimSpace(c.Name)
				if colName == "" {
					continue
				}
				var dataType *string
				tt := strings.TrimSpace(c.TypeText)
				if tt == "" {
					tt = strings.TrimSpace(c.TypeName)
				}
				if tt != "" {
					dataType = &tt
				}
				cols = append(cols, CatalogColumn{
					Name:     databricksIdent(colName),
					DataType: dataType,
					Nullable: c.Nullable,
				})
			}
			sort.Slice(cols, func(i, j int) bool {
				return strings.ToUpper(cols[i].Name.Name) < strings.ToUpper(cols[j].Name.Name)
			})

			// Extract row count and size from Delta table properties.
			var rowCountPtr *uint64
			var bytesPtr *uint64
			if s, ok := t.Properties["spark.sql.statistics.numRows"]; ok {
				if v, err := strconv.ParseUint(s, 10, 64); err == nil {
					rowCountPtr = &v
				}
			}
			if s, ok := t.Properties["spark.sql.statistics.totalSize"]; ok {
				if v, err := strconv.ParseUint(s, 10, 64); err == nil {
					bytesPtr = &v
				}
			}

			tables = append(tables, CatalogTable{
				Name:             databricksIdent(tableName),
				Kind:             mapDatabricksTableKind(t.TableType),
				Columns:          cols,
				Constraints:      extractDatabricksConstraints(t.TableConstraints),
				RowCountEstimate: rowCountPtr,
				BytesEstimate:    bytesPtr,
			})

			tablePolicies, tablePolicyRefs := extractDatabricksPolicies(catalogName, schemaName, tableName, t)
			if len(tablePolicies) > 0 {
				policies = append(policies, tablePolicies...)
			}
			if len(tablePolicyRefs) > 0 {
				policyRefs = append(policyRefs, tablePolicyRefs...)
			}

			securables = append(securables, dbxSecurableRef{
				SecurableType: "table",
				ObjectType:    mapDatabricksObjectType(t.TableType),
				FullName:      fullName,
			})

			*tablesSeen++
			tableCount++
		}

		if len(tables) > 0 {
			sort.Slice(tables, func(i, j int) bool {
				return strings.ToUpper(tables[i].Name.Name) < strings.ToUpper(tables[j].Name.Name)
			})
			schemaEntries = append(schemaEntries, CatalogSchema{
				Name:   databricksIdent(schemaName),
				Tables: tables,
			})
		}

		if maxTables > 0 && *tablesSeen >= maxTables {
			break
		}
	}

	sort.Slice(schemaEntries, func(i, j int) bool {
		return strings.ToUpper(schemaEntries[i].Name.Name) < strings.ToUpper(schemaEntries[j].Name.Name)
	})

	if tableCount == 0 {
		return CatalogDatabase{}, 0, policies, policyRefs, securables, nil
	}

	return CatalogDatabase{
		Name:    databricksIdent(catalogName),
		Schemas: schemaEntries,
	}, tableCount, policies, policyRefs, securables, nil
}

func mapDatabricksTableKind(tableType string) string {
	switch strings.ToUpper(strings.TrimSpace(tableType)) {
	case "MANAGED", "MANAGED_TABLE", "TABLE":
		return "Table"
	case "VIEW":
		return "View"
	case "MATERIALIZED_VIEW":
		return "MaterializedView"
	case "EXTERNAL", "EXTERNAL_TABLE":
		return "ExternalTable"
	default:
		return "Unknown"
	}
}

func mapDatabricksObjectType(tableType string) string {
	switch strings.ToUpper(strings.TrimSpace(tableType)) {
	case "VIEW":
		return "VIEW"
	default:
		return "TABLE"
	}
}

func databricksGetTableDetail(
	ctx context.Context,
	client *http.Client,
	workspaceURL, token, fullName string,
) (dbxTableDef, error) {
	return databricksGET[dbxTableDef](ctx, client, workspaceURL, token,
		"/api/2.1/unity-catalog/tables/"+url.PathEscape(fullName), nil)
}

func extractDatabricksConstraints(rows []dbxTableConstraint) []CatalogConstraint {
	if len(rows) == 0 {
		return nil
	}
	out := make([]CatalogConstraint, 0, len(rows))
	for _, row := range rows {
		switch {
		case row.PrimaryKey != nil:
			out = append(out, databricksConstraint("PrimaryKey", row.PrimaryKey))
		case row.ForeignKey != nil:
			out = append(out, databricksConstraint("ForeignKey", row.ForeignKey))
		case row.Named != nil:
			out = append(out, databricksConstraint("Unknown", row.Named))
		}
	}
	return out
}

func databricksConstraint(kind string, c *dbxConstraint) CatalogConstraint {
	out := CatalogConstraint{Kind: kind, Rely: c.Rely}
	if name := strings.TrimSpace(c.Name); name != "" {
		out.Name = &name
	}
	out.Columns = databricksIdents(c.ChildColumns)
	// A referenced table is named catalog.schema.table.
	if parts := strings.Split(strings.TrimSpace(c.ParentTable), "."); len(parts) == 3 {
		out.RefTable = &CatalogObjectName{
			Database: databricksIdent(parts[0]),
			Schema:   databricksIdent(parts[1]),
			Name:     databricksIdent(parts[2]),
		}
	}
	out.RefColumns = databricksIdents(c.ParentColumns)
	return out
}

func databricksIdents(names []string) []CatalogIdent {
	out := make([]CatalogIdent, 0, len(names))
	for _, name := range names {
		if name = strings.TrimSpace(name); name != "" {
			out = append(out, databricksIdent(name))
		}
	}
	return out
}

// extractDatabricksPolicies turns a table's row filter and its columns' masks
// into policies named after the table (and column) they are bound to.
func extractDatabricksPolicies(catalogName, schemaName, tableName string, t dbxTableDef) ([]CatalogPolicy, []CatalogPolicyReference) {
	policies := make([]CatalogPolicy, 0)
	refs := make([]CatalogPolicyReference, 0)
	table := CatalogObjectName{
		Database: databricksIdent(catalogName),
		Schema:   databricksIdent(schemaName),
		Name:     databricksIdent(tableName),
	}
	bind := func(kind, policy, fn string, column *CatalogIdent) {
		name := table
		name.Name = databricksIdent(policy)
		body := fmt.Sprintf("%s(...)", fn)
		policies = append(policies, CatalogPolicy{Name: name, Kind: kind, Body: &body})
		enabled := true
		refs = append(refs, CatalogPolicyReference{
			PolicyName: name,
			PolicyKind: kind,
			RefTable:   table,
			RefColumn:  column,
			Enabled:    &enabled,
		})
	}

	if t.RowFilter != nil {
		fn := strings.TrimSpace(t.RowFilter.FunctionName)
		if fn == "" {
			fn = "<row_filter>"
		}
		bind("RowAccessPolicy", tableName+"__row_filter", fn, nil)
	}

	for _, col := range t.Columns {
		colName := strings.TrimSpace(col.Name)
		if col.Mask == nil || colName == "" {
			continue
		}
		fn := strings.TrimSpace(col.Mask.FunctionName)
		if fn == "" {
			fn = "<column_mask>"
		}
		refCol := databricksIdent(colName)
		bind("MaskingPolicy", tableName+"__mask__"+colName, fn, &refCol)
	}

	return policies, refs
}

// databricksPullSCIMGroups fetches all workspace groups and their members/parent
// groups via the SCIM API. Returns group hierarchy edges (group nesting).
func databricksPullSCIMGroups(
	ctx context.Context,
	client *http.Client,
	workspaceURL, token string,
) ([]CatalogRoleEdge, error) {
	var allGroups []scimGroup
	startIndex := 1
	count := 100

	for {
		resp, err := databricksGET[scimListResponse[scimGroup]](
			ctx, client, workspaceURL, token,
			"/api/2.0/preview/scim/v2/Groups",
			map[string]string{
				"startIndex": fmt.Sprintf("%d", startIndex),
				"count":      fmt.Sprintf("%d", count),
			},
		)
		if err != nil {
			return nil, fmt.Errorf("SCIM Groups list failed: %w", err)
		}
		allGroups = append(allGroups, resp.Resources...)

		// Paginate: SCIM uses 1-indexed startIndex
		if startIndex+len(resp.Resources) > resp.TotalResults || len(resp.Resources) == 0 {
			break
		}
		startIndex += len(resp.Resources)
	}

	// Build role hierarchy edges from group nesting.
	// If group "data_engineers" is a member of group "all_users",
	// then all_users is the parent (child inherits parent's privileges in Snowflake terms,
	// but in Databricks the child group's members get the parent's grants).
	// We model: GRANT ROLE parent TO ROLE child — child inherits parent's privileges.
	// In Databricks: if group A has group B as a member, B's users get A's privileges.
	// So: parent=A, child=B.
	var edges []CatalogRoleEdge

	// Build a lookup from group ID → display name
	idToName := map[string]string{}
	for _, g := range allGroups {
		idToName[g.ID] = g.DisplayName
	}

	// Each group has a "groups" field listing parent groups it belongs to.
	// group.Groups[i].Display = parent group name, .Value = parent group ID.
	for _, g := range allGroups {
		for _, parentRef := range g.Groups {
			parentName := parentRef.Display
			if parentName == "" {
				parentName = idToName[parentRef.Value]
			}
			if parentName == "" || g.DisplayName == "" {
				continue
			}
			edges = append(edges, CatalogRoleEdge{
				ParentRole: parentName,
				ChildRole:  g.DisplayName,
			})
		}
	}

	progressf("  SCIM groups: %d groups, %d hierarchy edges", len(allGroups), len(edges))
	return edges, nil
}

// databricksPullSCIMUsers fetches all workspace users and their group memberships
// via the SCIM API. Returns user-to-group assignments.
func databricksPullSCIMUsers(
	ctx context.Context,
	client *http.Client,
	workspaceURL, token string,
) ([]CatalogUserRole, error) {
	var allUsers []scimUser
	startIndex := 1
	count := 100

	for {
		resp, err := databricksGET[scimListResponse[scimUser]](
			ctx, client, workspaceURL, token,
			"/api/2.0/preview/scim/v2/Users",
			map[string]string{
				"startIndex": fmt.Sprintf("%d", startIndex),
				"count":      fmt.Sprintf("%d", count),
			},
		)
		if err != nil {
			return nil, fmt.Errorf("SCIM Users list failed: %w", err)
		}
		allUsers = append(allUsers, resp.Resources...)

		if startIndex+len(resp.Resources) > resp.TotalResults || len(resp.Resources) == 0 {
			break
		}
		startIndex += len(resp.Resources)
	}

	var assignments []CatalogUserRole
	for _, u := range allUsers {
		if !u.Active {
			continue // skip deactivated users
		}
		userName := u.UserName
		if userName == "" {
			userName = u.DisplayName
		}
		if userName == "" {
			continue
		}
		for _, g := range u.Groups {
			groupName := g.Display
			if groupName == "" {
				continue
			}
			assignments = append(assignments, CatalogUserRole{
				User: userName,
				Role: groupName,
			})
		}
	}

	progressf("  SCIM users: %d active users, %d user-group assignments", len(allUsers), len(assignments))
	return assignments, nil
}

func databricksPullGrantGraph(
	ctx context.Context,
	client *http.Client,
	workspaceURL, token string,
	securables []dbxSecurableRef,
) (*CatalogGrants, error) {
	out := &CatalogGrants{
		RoleHierarchy:    []CatalogRoleEdge{},
		ObjectPrivileges: []CatalogObjectPrivilege{},
		UserRoles:        []CatalogUserRole{},
	}

	seen := map[string]struct{}{}
	for _, s := range securables {
		assignments, err := databricksList[dbxPrivilegeAssignment, dbxPermissionResponse](
			ctx,
			client,
			workspaceURL,
			token,
			"/api/2.1/unity-catalog/permissions/"+s.SecurableType+"/"+url.PathEscape(s.FullName),
			nil,
		)
		if err != nil {
			continue
		}
		for _, pa := range assignments {
			principal := strings.TrimSpace(pa.Principal)
			if principal == "" {
				continue
			}
			for _, priv := range pa.Privileges {
				p := canonicalizeDatabricksPrivilege(priv, s.ObjectType)
				if p == "" {
					continue
				}
				k := principal + "|" + p + "|" + s.ObjectType + "|" + s.FullName
				if _, ok := seen[k]; ok {
					continue
				}
				seen[k] = struct{}{}
				out.ObjectPrivileges = append(out.ObjectPrivileges, CatalogObjectPrivilege{
					Role:       principal,
					Privilege:  p,
					ObjectType: s.ObjectType,
					ObjectFQN:  s.FullName,
				})
			}
		}
	}

	progressf("  object privileges: %d grants", len(out.ObjectPrivileges))

	// Pull user-to-group assignments via SCIM Users API
	userRoles, err := databricksPullSCIMUsers(ctx, client, workspaceURL, token)
	if err != nil {
		progressf("  warning: SCIM user extraction failed: %v", err)
	} else {
		out.UserRoles = userRoles
	}

	// Pull group hierarchy via SCIM Groups API
	roleEdges, err := databricksPullSCIMGroups(ctx, client, workspaceURL, token)
	if err != nil {
		progressf("  warning: SCIM group hierarchy extraction failed: %v", err)
	} else {
		out.RoleHierarchy = roleEdges
	}

	return out, nil
}

// canonicalizeDatabricksPrivilege normalizes Databricks Unity Catalog
// privilege names to their Snowflake-equivalent form where a clear mapping
// exists. This ensures the grant graph and builtin rules work consistently
// across providers.
//
// Mapping:
//
//	USE CATALOG / USE SCHEMA / USE CONNECTION / USE → USAGE
//	Everything else passes through uppercased (preserved for Databricks-specific rules)
func canonicalizeDatabricksPrivilege(privilege, objectType string) string {
	p := strings.ToUpper(strings.TrimSpace(privilege))
	if p == "" {
		return ""
	}
	switch p {
	case "USE", "USE CATALOG", "USE SCHEMA", "USE CONNECTION":
		return "USAGE"
	default:
		return p
	}
}

// databricksList reads a list endpoint page by page, following
// next_page_token until a response carries none, and returns the items of
// every page.
func databricksList[T any, P dbxPage[T]](
	ctx context.Context,
	client *http.Client,
	workspaceURL, token, path string,
	query map[string]string,
) ([]T, error) {
	var all []T
	pageToken := ""
	for {
		pageQuery := query
		if pageToken != "" {
			pageQuery = make(map[string]string, len(query)+1)
			for k, v := range query {
				pageQuery[k] = v
			}
			pageQuery["page_token"] = pageToken
		}
		page, err := databricksGET[P](ctx, client, workspaceURL, token, path, pageQuery)
		if err != nil {
			return nil, err
		}
		all = append(all, page.items()...)

		next := page.nextPageToken()
		if next == "" {
			return all, nil
		}
		if next == pageToken {
			return nil, fmt.Errorf("databricks api %s returned the same page token twice", path)
		}
		pageToken = next
	}
}

func databricksGET[T any](
	ctx context.Context,
	client *http.Client,
	workspaceURL, token, path string,
	query map[string]string,
) (T, error) {
	var zero T
	base, err := url.Parse(workspaceURL)
	if err != nil {
		return zero, err
	}
	base.Path = path
	q := base.Query()
	for k, v := range query {
		q.Set(k, v)
	}
	base.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String(), nil)
	if err != nil {
		return zero, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return zero, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return zero, fmt.Errorf("databricks api %s returned %d: %s", path, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	dec := json.NewDecoder(resp.Body)
	var out T
	if err := dec.Decode(&out); err != nil {
		return zero, err
	}
	return out, nil
}

func parse_ident_filter(raw string) (name string, quoted bool) {
	s := strings.TrimSpace(raw)
	if len(s) >= 2 && strings.HasPrefix(s, "\"") && strings.HasSuffix(s, "\"") {
		inner := s[1 : len(s)-1]
		// Best-effort unescape for doubled double-quotes.
		inner = strings.ReplaceAll(inner, "\"\"", "\"")
		return inner, true
	}
	return s, false
}

func ident_filter_matches(candidate string, filter string) bool {
	name, quoted := parse_ident_filter(filter)
	if quoted {
		return candidate == name
	}
	return strings.EqualFold(candidate, name)
}

func matches_any_ident_filter(candidate string, filters []string) bool {
	for _, f := range filters {
		if ident_filter_matches(candidate, f) {
			return true
		}
	}
	return false
}

// databricksIdent creates a CatalogIdent for Databricks, which is universally
// case-insensitive. Unlike Snowflake (which uppercases unquoted identifiers),
// Databricks preserves the original case but resolves lookups case-insensitively.
// Therefore case_sensitive is always false regardless of casing in the name.
func databricksIdent(name string) CatalogIdent {
	return CatalogIdent{Name: name, CaseSensitive: false}
}
