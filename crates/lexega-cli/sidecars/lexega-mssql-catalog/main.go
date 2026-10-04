// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

// Command lexega-mssql-catalog is the SQL Server catalog sidecar for Lexega.
//
// It connects to a Microsoft SQL Server (or Azure SQL) instance, walks the
// accessible databases via the sys.* catalog views, and emits
// a schema_version=2 CatalogSnapshot JSON consumed by the Rust engine
// (provider "mssql" -> MsSqlCatalogProvider).
//
// Invocation contract (driven by `lexega catalog pull`):
//
//	lexega-mssql-catalog pull --out <file.json|-> [--provider mssql] [conn flags]
//
// Snapshot JSON on stdout (with --out -) or written to the --out path; all
// progress/diagnostics go to stderr so stdout stays clean for piping.
//
// The sidecar is a *recognition* front-end: it reports neutral primitives
// (names, types, nullability, constraint shapes, raw privilege strings). It
// makes no risk/governance verdict — that lives in the Rust/YAML rule layer.
package main

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "github.com/microsoft/go-mssqldb"
)

var version = "dev"

// thirdPartyLicenses is what the licenses subcommand prints.
//
//go:embed THIRD_PARTY_LICENSES.txt
var thirdPartyLicenses string

// ---------------------------------------------------------------------------
// Wire structs — the shapes `lexega-sf-catalog` emits, so the Rust serde layer
// (CatalogSnapshot::load_from_path) accepts the output unchanged. Only the
// fields the MSSQL provider populates are kept; omitted fields are
// `#[serde(default)]` on the Rust side. MSSQL has no masking/row-access
// policies (MsSqlCatalogProvider::supports_policies == false), so the policy
// fields are intentionally absent.
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

	Enforced *bool `json:"enforced,omitempty"`
	Rely     *bool `json:"rely,omitempty"`
}

type CatalogSchema struct {
	Name   CatalogIdent   `json:"name"`
	Tables []CatalogTable `json:"tables,omitempty"`
}

type CatalogDatabase struct {
	Name    CatalogIdent    `json:"name"`
	Schemas []CatalogSchema `json:"schemas,omitempty"`
}

// CatalogRoleEdge mirrors a role-membership edge. In SQL Server,
// `ALTER ROLE r ADD MEMBER m` makes m inherit r's privileges, so the
// privileges of r (parent/granted) flow to m (child/receiver).
type CatalogRoleEdge struct {
	ParentRole  string `json:"parent"`
	ChildRole   string `json:"child"`
	GrantOption bool   `json:"grant_option,omitempty"`
}

type CatalogObjectPrivilege struct {
	Role       string `json:"role"`
	Privilege  string `json:"privilege"`
	ObjectType string `json:"object_type"`
	ObjectFQN  string `json:"object"`
}

type CatalogUserRole struct {
	User string `json:"user"`
	Role string `json:"role"`
}

type CatalogGrants struct {
	RoleHierarchy    []CatalogRoleEdge        `json:"role_hierarchy,omitempty"`
	ObjectPrivileges []CatalogObjectPrivilege `json:"object_privileges,omitempty"`
	UserRoles        []CatalogUserRole        `json:"user_roles,omitempty"`
}

type CatalogSnapshot struct {
	SchemaVersion uint32            `json:"schema_version"`
	GeneratedAt   *string           `json:"generated_at,omitempty"`
	Source        *string           `json:"source,omitempty"`
	Provider      *string           `json:"provider,omitempty"`
	Databases     []CatalogDatabase `json:"databases,omitempty"`
	Grants        *CatalogGrants    `json:"grants,omitempty"`
}

const schemaVersion = 2

// tableKey identifies a table within a single database.
type tableKey struct{ schema, table string }

// marshalSnapshot renders the snapshot as the indented JSON the Rust engine
// loads via CatalogSnapshot::load_from_path.
func marshalSnapshot(snapshot CatalogSnapshot) ([]byte, error) {
	return json.MarshalIndent(snapshot, "", "  ")
}

// systemDatabases are skipped unless --include-system-db is passed.
var systemDatabases = map[string]bool{
	"master": true,
	"model":  true,
	"msdb":   true,
	"tempdb": true,
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

type pullArgs struct {
	Out string
	// Provider is forwarded by the Rust CLI; accepted for compatibility and
	// echoed into the snapshot. Always normalized to "mssql".
	Provider string

	Server   string
	Port     int
	User     string
	Database string

	PasswordEnv         string
	ConnectionStringEnv string

	Encrypt         string
	TrustServerCert bool
	IncludeSystemDB bool

	IncludeDB []string
	ExcludeDB []string
	MaxTables int

	IncludeGrants bool
	MaxGrants     int
}

func progressf(format string, args ...any) {
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
		fmt.Printf("lexega-mssql-catalog %s\n", version)
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
	fmt.Fprintf(os.Stderr, "  %s pull --out <file.json|-> [connection flags]\n", prog)
	fmt.Fprintf(os.Stderr, "  %s licenses\n\n", prog)
	fmt.Fprintf(os.Stderr, "Connection flags (password via env by default):\n")
	fmt.Fprintf(os.Stderr, "  --server <host>            SQL Server host (required unless --connection-string-env)\n")
	fmt.Fprintf(os.Stderr, "  --port <n>                 Port (default: 1433)\n")
	fmt.Fprintf(os.Stderr, "  --user <name>              SQL login\n")
	fmt.Fprintf(os.Stderr, "  --password-env <ENV>       Env var holding password (default: MSSQL_PASSWORD)\n")
	fmt.Fprintf(os.Stderr, "  --database <name>          Initial database to connect to (optional)\n")
	fmt.Fprintf(os.Stderr, "  --encrypt true|false|disable  TLS mode (default: true)\n")
	fmt.Fprintf(os.Stderr, "  --trust-server-cert        Skip server certificate validation\n")
	fmt.Fprintf(os.Stderr, "  --connection-string-env <ENV>  Env var with a full sqlserver:// DSN (overrides the above)\n\n")
	fmt.Fprintf(os.Stderr, "Scope flags:\n")
	fmt.Fprintf(os.Stderr, "  --include-db <DB>          Repeatable; default: all accessible non-system DBs\n")
	fmt.Fprintf(os.Stderr, "  --exclude-db <DB>          Repeatable\n")
	fmt.Fprintf(os.Stderr, "  --include-system-db        Include master/model/msdb/tempdb\n")
	fmt.Fprintf(os.Stderr, "  --max-tables <n>           Cap total tables (default: 0 = unlimited)\n\n")
	fmt.Fprintf(os.Stderr, "Grant graph flags:\n")
	fmt.Fprintf(os.Stderr, "  --include-grants           Pull object privileges + role membership\n")
	fmt.Fprintf(os.Stderr, "  --max-grants <n>           Cap object privileges (default: 500000)\n")
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) { return len(p), nil }

type multiString []string

func (m *multiString) String() string { return strings.Join(*m, ",") }
func (m *multiString) Set(v string) error {
	*m = append(*m, v)
	return nil
}

func parsePullArgs(argv []string) (pullArgs, error) {
	fs := flag.NewFlagSet("pull", flag.ContinueOnError)
	fs.SetOutput(ioDiscard{})

	var a pullArgs
	fs.StringVar(&a.Out, "out", "", "")
	fs.StringVar(&a.Provider, "provider", "mssql", "")
	fs.StringVar(&a.Server, "server", "", "")
	fs.IntVar(&a.Port, "port", 1433, "")
	fs.StringVar(&a.User, "user", "", "")
	fs.StringVar(&a.Database, "database", "", "")
	fs.StringVar(&a.PasswordEnv, "password-env", "MSSQL_PASSWORD", "")
	fs.StringVar(&a.ConnectionStringEnv, "connection-string-env", "", "")
	fs.StringVar(&a.Encrypt, "encrypt", "true", "")
	fs.BoolVar(&a.TrustServerCert, "trust-server-cert", false, "")
	fs.BoolVar(&a.IncludeSystemDB, "include-system-db", false, "")
	fs.IntVar(&a.MaxTables, "max-tables", 0, "")
	fs.BoolVar(&a.IncludeGrants, "include-grants", false, "")
	fs.IntVar(&a.MaxGrants, "max-grants", 500000, "")

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

	// Provider is informational; normalize the accepted aliases to "mssql".
	switch strings.ToLower(strings.TrimSpace(a.Provider)) {
	case "", "mssql", "sqlserver", "sql_server":
		a.Provider = "mssql"
	default:
		return pullArgs{}, fmt.Errorf("invalid --provider: %q (expected mssql)", a.Provider)
	}

	usingConnString := a.ConnectionStringEnv != ""
	if !usingConnString && strings.TrimSpace(a.Server) == "" {
		return pullArgs{}, errors.New("--server is required (or set --connection-string-env)")
	}

	switch strings.ToLower(strings.TrimSpace(a.Encrypt)) {
	case "true", "false", "disable":
	default:
		return pullArgs{}, fmt.Errorf("invalid --encrypt: %q (expected true, false, or disable)", a.Encrypt)
	}

	return a, nil
}

// buildDSN constructs a sqlserver:// connection URL from the parsed args.
// When --connection-string-env is set, that env var supplies the full DSN
// verbatim (enabling Azure AD / integrated auth without new flags).
func buildDSN(a pullArgs) (string, error) {
	if a.ConnectionStringEnv != "" {
		dsn := strings.TrimSpace(os.Getenv(a.ConnectionStringEnv))
		if dsn == "" {
			return "", fmt.Errorf("--connection-string-env %s is empty or unset", a.ConnectionStringEnv)
		}
		return dsn, nil
	}

	password := os.Getenv(a.PasswordEnv)

	u := &url.URL{Scheme: "sqlserver"}
	if a.User != "" {
		u.User = url.UserPassword(a.User, password)
	}
	host := a.Server
	if a.Port > 0 {
		host = fmt.Sprintf("%s:%d", a.Server, a.Port)
	}
	u.Host = host

	q := url.Values{}
	if a.Database != "" {
		q.Set("database", a.Database)
	}
	q.Set("encrypt", strings.ToLower(strings.TrimSpace(a.Encrypt)))
	if a.TrustServerCert {
		q.Set("TrustServerCertificate", "true")
	}
	q.Set("app name", "lexega-mssql-catalog")
	u.RawQuery = q.Encode()

	return u.String(), nil
}

func runPull(args pullArgs) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	dsn, err := buildDSN(args)
	if err != nil {
		return err
	}

	progressf("Connecting to SQL Server ...")
	db, err := sql.Open("sqlserver", dsn)
	if err != nil {
		return fmt.Errorf("open sqlserver: %w", err)
	}
	defer db.Close()

	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	progressf("Connected.")

	progressf("Discovering databases ...")
	allDBs, err := listDatabases(ctx, db)
	if err != nil {
		return fmt.Errorf("list databases: %w", err)
	}

	var dbNames []string
	for _, candidate := range allDBs {
		if !args.IncludeSystemDB && systemDatabases[strings.ToLower(candidate)] {
			continue
		}
		if len(args.IncludeDB) > 0 && !matchesAnyCI(candidate, args.IncludeDB) {
			continue
		}
		if len(args.ExcludeDB) > 0 && matchesAnyCI(candidate, args.ExcludeDB) {
			continue
		}
		dbNames = append(dbNames, candidate)
	}
	if len(args.IncludeDB) > 0 && len(dbNames) == 0 {
		return fmt.Errorf("no databases matched --include-db filters: %v", args.IncludeDB)
	}
	sort.Strings(dbNames)
	progressf("Databases selected: %d", len(dbNames))

	snapshot := CatalogSnapshot{SchemaVersion: schemaVersion}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	snapshot.GeneratedAt = &now
	provider := "mssql"
	snapshot.Provider = &provider
	source := fmt.Sprintf("mssql server=%s database=%s user=%s", args.Server, args.Database, args.User)
	snapshot.Source = &source

	tablesSeen := 0
	for _, dbName := range dbNames {
		if args.MaxTables > 0 && tablesSeen >= args.MaxTables {
			progressf("Reached max tables limit (%d); stopping.", args.MaxTables)
			break
		}
		progressf("Pulling %s ...", dbName)
		dbEntry, count, err := pullDatabase(ctx, db, dbName, args.MaxTables, &tablesSeen)
		if err != nil {
			return fmt.Errorf("pull database %s: %w", dbName, err)
		}
		if count == 0 {
			progressf("  %s: no tables (skipped)", dbName)
			continue
		}
		progressf("  %s: tables=%d (total_tables=%d)", dbName, count, tablesSeen)
		snapshot.Databases = append(snapshot.Databases, dbEntry)
	}

	if args.IncludeGrants {
		grants, err := pullGrantGraph(ctx, db, dbNames, args.MaxGrants)
		if err != nil {
			progressf("warning: failed to pull grant graph: %v", err)
		} else {
			snapshot.Grants = grants
			progressf("Grant graph: role_hierarchy=%d object_privileges=%d user_roles=%d",
				len(grants.RoleHierarchy), len(grants.ObjectPrivileges), len(grants.UserRoles))
		}
	}

	sort.Slice(snapshot.Databases, func(i, j int) bool {
		return strings.ToUpper(snapshot.Databases[i].Name.Name) < strings.ToUpper(snapshot.Databases[j].Name.Name)
	})

	return writeSnapshot(args.Out, snapshot)
}

func writeSnapshot(out string, snapshot CatalogSnapshot) error {
	data, err := marshalSnapshot(snapshot)
	if err != nil {
		return err
	}
	if out == "-" {
		progressf("Writing snapshot to stdout")
		if _, err := os.Stdout.Write(data); err != nil {
			return err
		}
		os.Stdout.Write([]byte("\n"))
		return nil
	}
	progressf("Writing snapshot: %s", out)
	if err := os.WriteFile(out, data, 0o644); err != nil {
		return err
	}
	progressf("Wrote catalog snapshot: %s", out)
	return nil
}

// ---------------------------------------------------------------------------
// Extraction
// ---------------------------------------------------------------------------

func listDatabases(ctx context.Context, db *sql.DB) ([]string, error) {
	const q = `SELECT name FROM sys.databases
WHERE state_desc = 'ONLINE' AND HAS_DBACCESS(name) = 1
ORDER BY name`
	rows, err := queryRows(ctx, db, q)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		if name := getField(r, "name"); name != "" {
			out = append(out, name)
		}
	}
	return out, nil
}

// pullDatabase extracts one database's schemas/tables/columns/constraints.
// Every catalog query is qualified with the database name (e.g.
// `[db].sys.objects`) so we never need to switch the connected database —
// matching SQL Server's three-part db.schema.object model.
func pullDatabase(ctx context.Context, db *sql.DB, dbName string, maxTables int, tablesSeen *int) (CatalogDatabase, int, error) {
	dbq := bracketQuote(dbName)

	// 1) Tables + views (sys.objects, object_id-keyed — avoids the
	// INFORMATION_SCHEMA view-resolution + string-join overhead).
	tblRows, err := queryRows(ctx, db, fmt.Sprintf(
		`SELECT s.name AS table_schema, o.name AS table_name, o.type AS object_type
FROM %s.sys.objects o
JOIN %s.sys.schemas s ON o.schema_id = s.schema_id
WHERE o.type IN ('U', 'V')
ORDER BY s.name, o.name`, dbq, dbq))
	if err != nil {
		return CatalogDatabase{}, 0, err
	}

	// table lookup keyed by (schema, table) -> *CatalogTable, plus ordered key list.
	tables := map[tableKey]*CatalogTable{}
	var order []tableKey
	truncated := false
	for _, r := range tblRows {
		if maxTables > 0 && *tablesSeen >= maxTables {
			truncated = true
			break
		}
		schema := getField(r, "table_schema")
		name := getField(r, "table_name")
		if schema == "" || name == "" {
			continue
		}
		k := tableKey{schema, name}
		if _, dup := tables[k]; dup {
			continue
		}
		t := &CatalogTable{
			Name: mssqlIdent(name),
			Kind: mapTableKind(getField(r, "object_type"), false),
		}
		tables[k] = t
		order = append(order, k)
		*tablesSeen++
	}
	if truncated {
		progressf("  %s: reached max-tables cap; remaining tables in this database skipped", dbName)
	}

	// 2) External tables (best-effort; feature may be unavailable).
	if extRows, err := queryRows(ctx, db, fmt.Sprintf(
		`SELECT s.name AS table_schema, et.name AS table_name
FROM %s.sys.external_tables et
JOIN %s.sys.schemas s ON et.schema_id = s.schema_id`, dbq, dbq)); err == nil {
		for _, r := range extRows {
			k := tableKey{getField(r, "table_schema"), getField(r, "table_name")}
			if t, ok := tables[k]; ok {
				t.Kind = "ExternalTable"
			}
		}
	}

	// 3) Columns (sys.columns + sys.types; user_type_id resolves user-defined
	// types to their base type name, ordered by column_id).
	colRows, err := queryRows(ctx, db, fmt.Sprintf(
		`SELECT s.name AS table_schema, o.name AS table_name, c.name AS column_name,
       ty.name AS data_type, CAST(c.is_nullable AS int) AS is_nullable
FROM %s.sys.columns c
JOIN %s.sys.objects o ON c.object_id = o.object_id
JOIN %s.sys.schemas s ON o.schema_id = s.schema_id
JOIN %s.sys.types ty ON c.user_type_id = ty.user_type_id
WHERE o.type IN ('U', 'V')
ORDER BY s.name, o.name, c.column_id`, dbq, dbq, dbq, dbq))
	if err != nil {
		return CatalogDatabase{}, 0, err
	}
	for _, r := range colRows {
		k := tableKey{getField(r, "table_schema"), getField(r, "table_name")}
		t, ok := tables[k]
		if !ok {
			continue
		}
		dataType := getField(r, "data_type")
		nullable := getField(r, "is_nullable") == "1"
		col := CatalogColumn{Name: mssqlIdent(getField(r, "column_name"))}
		if dataType != "" {
			dt := dataType
			col.DataType = &dt
		}
		n := nullable
		col.Nullable = &n
		t.Columns = append(t.Columns, col)
	}

	// 4) Primary key / unique constraints.
	if err := attachKeyConstraints(ctx, db, dbq, tables); err != nil {
		return CatalogDatabase{}, 0, err
	}

	// 5) Foreign keys (sys.* catalog views).
	if err := attachForeignKeys(ctx, db, dbq, dbName, tables); err != nil {
		return CatalogDatabase{}, 0, err
	}

	// 6) Row/byte estimates (best-effort; catalog metadata, no DMV so the
	// VIEW DATABASE STATE permission is not required). Row counts and byte
	// sizes are computed in SEPARATE queries on purpose: joining
	// sys.partitions to sys.allocation_units fans each partition out into up
	// to three rows, which would multiply SUM(rows).

	// Row counts: sys.partitions.rows for the heap (index_id 0) or clustered
	// index (index_id 1) — a table has exactly one of those, so no double
	// counting across index types; SUM covers multiple physical partitions.
	if rowRows, err := queryRows(ctx, db, fmt.Sprintf(
		`SELECT s.name AS table_schema, t.name AS table_name, SUM(p.rows) AS row_count
FROM %s.sys.tables t
JOIN %s.sys.schemas s ON t.schema_id = s.schema_id
JOIN %s.sys.partitions p ON t.object_id = p.object_id AND p.index_id IN (0, 1)
GROUP BY s.name, t.name`, dbq, dbq, dbq)); err == nil {
		for _, r := range rowRows {
			if t, ok := tables[tableKey{getField(r, "table_schema"), getField(r, "table_name")}]; ok {
				if rc, ok := parseUint64(getField(r, "row_count")); ok {
					t.RowCountEstimate = &rc
				}
			}
		}
	}

	// Byte sizes: total allocated pages across all partitions/indexes
	// (8 KB/page). au.type 1/3 (in-row / row-overflow) link via hobt_id;
	// type 2 (LOB) links via partition_id.
	if byteRows, err := queryRows(ctx, db, fmt.Sprintf(
		`SELECT s.name AS table_schema, t.name AS table_name, SUM(a.total_pages) AS total_pages
FROM %s.sys.tables t
JOIN %s.sys.schemas s ON t.schema_id = s.schema_id
JOIN %s.sys.partitions p ON t.object_id = p.object_id
JOIN %s.sys.allocation_units a ON
     (a.type IN (1, 3) AND a.container_id = p.hobt_id)
  OR (a.type = 2 AND a.container_id = p.partition_id)
GROUP BY s.name, t.name`, dbq, dbq, dbq, dbq)); err == nil {
		for _, r := range byteRows {
			if t, ok := tables[tableKey{getField(r, "table_schema"), getField(r, "table_name")}]; ok {
				if pages, ok := parseUint64(getField(r, "total_pages")); ok {
					b := pages * 8192
					t.BytesEstimate = &b
				}
			}
		}
	}

	// Assemble schemas (grouped from the table key order, then sorted).
	schemaTables := map[string][]CatalogTable{}
	var schemaOrder []string
	seenSchema := map[string]bool{}
	for _, k := range order {
		if !seenSchema[k.schema] {
			seenSchema[k.schema] = true
			schemaOrder = append(schemaOrder, k.schema)
		}
		schemaTables[k.schema] = append(schemaTables[k.schema], *tables[k])
	}
	sort.Strings(schemaOrder)

	dbEntry := CatalogDatabase{Name: mssqlIdent(dbName)}
	for _, schemaName := range schemaOrder {
		tl := schemaTables[schemaName]
		sort.Slice(tl, func(i, j int) bool {
			return strings.ToUpper(tl[i].Name.Name) < strings.ToUpper(tl[j].Name.Name)
		})
		dbEntry.Schemas = append(dbEntry.Schemas, CatalogSchema{
			Name:   mssqlIdent(schemaName),
			Tables: tl,
		})
	}
	return dbEntry, len(order), nil
}

func attachKeyConstraints(ctx context.Context, db *sql.DB, dbq string, tables map[tableKey]*CatalogTable) error {
	// sys.key_constraints carries PK/UQ; its unique_index_id points at the
	// backing index whose sys.index_columns give the key columns in order.
	rows, err := queryRows(ctx, db, fmt.Sprintf(
		`SELECT s.name AS table_schema, o.name AS table_name,
       kc.name AS constraint_name, kc.type AS constraint_type,
       col.name AS column_name
FROM %s.sys.key_constraints kc
JOIN %s.sys.objects o ON kc.parent_object_id = o.object_id
JOIN %s.sys.schemas s ON o.schema_id = s.schema_id
JOIN %s.sys.index_columns ic ON kc.parent_object_id = ic.object_id AND kc.unique_index_id = ic.index_id
JOIN %s.sys.columns col ON ic.object_id = col.object_id AND ic.column_id = col.column_id
WHERE kc.type IN ('PK', 'UQ') AND ic.is_included_column = 0
ORDER BY s.name, o.name, kc.name, ic.key_ordinal`,
		dbq, dbq, dbq, dbq, dbq))
	if err != nil {
		return err
	}
	type ckey struct{ schema, table, cname string }
	agg := map[ckey]*CatalogConstraint{}
	var ckeyOrder []ckey
	for _, r := range rows {
		schema := getField(r, "table_schema")
		table := getField(r, "table_name")
		cname := getField(r, "constraint_name")
		col := getField(r, "column_name")
		k := ckey{schema, table, cname}
		c, ok := agg[k]
		if !ok {
			kind := "Unique"
			if strings.EqualFold(strings.TrimSpace(getField(r, "constraint_type")), "PK") {
				kind = "PrimaryKey"
			}
			name := cname
			c = &CatalogConstraint{Kind: kind, Name: &name}
			agg[k] = c
			ckeyOrder = append(ckeyOrder, k)
		}
		c.Columns = append(c.Columns, mssqlIdent(col))
	}
	for _, k := range ckeyOrder {
		if t, ok := tables[tableKey{k.schema, k.table}]; ok {
			t.Constraints = append(t.Constraints, *agg[k])
		}
	}
	return nil
}

func attachForeignKeys(ctx context.Context, db *sql.DB, dbq, dbName string, tables map[tableKey]*CatalogTable) error {
	rows, err := queryRows(ctx, db, fmt.Sprintf(
		`SELECT fk.name AS fk_name,
       s1.name AS child_schema, t1.name AS child_table, c1.name AS child_column,
       s2.name AS parent_schema, t2.name AS parent_table, c2.name AS parent_column,
       CAST(fk.is_disabled AS int) AS is_disabled,
       CAST(fk.is_not_trusted AS int) AS is_not_trusted
FROM %s.sys.foreign_keys fk
JOIN %s.sys.foreign_key_columns fkc ON fk.object_id = fkc.constraint_object_id
JOIN %s.sys.tables t1 ON fkc.parent_object_id = t1.object_id
JOIN %s.sys.schemas s1 ON t1.schema_id = s1.schema_id
JOIN %s.sys.columns c1 ON fkc.parent_object_id = c1.object_id AND fkc.parent_column_id = c1.column_id
JOIN %s.sys.tables t2 ON fkc.referenced_object_id = t2.object_id
JOIN %s.sys.schemas s2 ON t2.schema_id = s2.schema_id
JOIN %s.sys.columns c2 ON fkc.referenced_object_id = c2.object_id AND fkc.referenced_column_id = c2.column_id
ORDER BY fk.name, fkc.constraint_column_id`,
		dbq, dbq, dbq, dbq, dbq, dbq, dbq, dbq))
	if err != nil {
		return err
	}

	type fkey struct{ schema, table, name string }
	agg := map[fkey]*CatalogConstraint{}
	var order []fkey
	for _, r := range rows {
		childSchema := getField(r, "child_schema")
		childTable := getField(r, "child_table")
		fkName := getField(r, "fk_name")
		k := fkey{childSchema, childTable, fkName}
		c, ok := agg[k]
		if !ok {
			name := fkName
			enforced := getField(r, "is_disabled") != "1"
			rely := getField(r, "is_not_trusted") != "1"
			c = &CatalogConstraint{
				Kind: "ForeignKey",
				Name: &name,
				RefTable: &CatalogObjectName{
					Database: mssqlIdent(dbName),
					Schema:   mssqlIdent(getField(r, "parent_schema")),
					Name:     mssqlIdent(getField(r, "parent_table")),
				},
				Enforced: &enforced,
				Rely:     &rely,
			}
			agg[k] = c
			order = append(order, k)
		}
		c.Columns = append(c.Columns, mssqlIdent(getField(r, "child_column")))
		c.RefColumns = append(c.RefColumns, mssqlIdent(getField(r, "parent_column")))
	}
	for _, k := range order {
		if t, ok := tables[tableKey{k.schema, k.table}]; ok {
			t.Constraints = append(t.Constraints, *agg[k])
		}
	}
	return nil
}

// pullGrantGraph collects object privileges and role membership across the
// selected databases. Object FQNs are db.schema.object.
func pullGrantGraph(ctx context.Context, db *sql.DB, dbNames []string, maxGrants int) (*CatalogGrants, error) {
	grants := &CatalogGrants{}
	seenRoleEdge := map[CatalogRoleEdge]bool{}
	seenUserRole := map[CatalogUserRole]bool{}

	for _, dbName := range dbNames {
		dbq := bracketQuote(dbName)

		// Object privileges (class = 1), grant/grant-with-grant states.
		privRows, err := queryRows(ctx, db, fmt.Sprintf(
			`SELECT pr.name AS grantee, dp.permission_name, dp.state_desc,
       s.name AS schema_name, o.name AS object_name, o.type_desc AS object_type
FROM %s.sys.database_permissions dp
JOIN %s.sys.database_principals pr ON dp.grantee_principal_id = pr.principal_id
JOIN %s.sys.objects o ON dp.major_id = o.object_id
JOIN %s.sys.schemas s ON o.schema_id = s.schema_id
WHERE dp.class = 1 AND dp.state IN ('G', 'W')`,
			dbq, dbq, dbq, dbq))
		if err != nil {
			progressf("  warning: object privileges for %s: %v", dbName, err)
		} else {
			for _, r := range privRows {
				if maxGrants > 0 && len(grants.ObjectPrivileges) >= maxGrants {
					progressf("  reached max-grants cap (%d); remaining privileges skipped", maxGrants)
					break
				}
				fqn := fmt.Sprintf("%s.%s.%s", dbName, getField(r, "schema_name"), getField(r, "object_name"))
				grants.ObjectPrivileges = append(grants.ObjectPrivileges, CatalogObjectPrivilege{
					Role:       getField(r, "grantee"),
					Privilege:  canonicalizePrivilege(getField(r, "permission_name")),
					ObjectType: mapObjectType(getField(r, "object_type")),
					ObjectFQN:  fqn,
				})
			}
		}

		// Role membership.
		memRows, err := queryRows(ctx, db, fmt.Sprintf(
			`SELECT rp.name AS role_name, mp.name AS member_name, mp.type_desc AS member_type
FROM %s.sys.database_role_members drm
JOIN %s.sys.database_principals rp ON drm.role_principal_id = rp.principal_id
JOIN %s.sys.database_principals mp ON drm.member_principal_id = mp.principal_id`,
			dbq, dbq, dbq))
		if err != nil {
			progressf("  warning: role membership for %s: %v", dbName, err)
			continue
		}
		for _, r := range memRows {
			role := getField(r, "role_name")
			member := getField(r, "member_name")
			if isRolePrincipal(getField(r, "member_type")) {
				edge := CatalogRoleEdge{ParentRole: role, ChildRole: member}
				if !seenRoleEdge[edge] {
					seenRoleEdge[edge] = true
					grants.RoleHierarchy = append(grants.RoleHierarchy, edge)
				}
			} else {
				ur := CatalogUserRole{User: member, Role: role}
				if !seenUserRole[ur] {
					seenUserRole[ur] = true
					grants.UserRoles = append(grants.UserRoles, ur)
				}
			}
		}
	}

	sort.Slice(grants.ObjectPrivileges, func(i, j int) bool {
		a, b := grants.ObjectPrivileges[i], grants.ObjectPrivileges[j]
		if a.ObjectFQN != b.ObjectFQN {
			return a.ObjectFQN < b.ObjectFQN
		}
		if a.Role != b.Role {
			return a.Role < b.Role
		}
		return a.Privilege < b.Privilege
	})
	sort.Slice(grants.RoleHierarchy, func(i, j int) bool {
		a, b := grants.RoleHierarchy[i], grants.RoleHierarchy[j]
		if a.ParentRole != b.ParentRole {
			return a.ParentRole < b.ParentRole
		}
		return a.ChildRole < b.ChildRole
	})
	sort.Slice(grants.UserRoles, func(i, j int) bool {
		a, b := grants.UserRoles[i], grants.UserRoles[j]
		if a.User != b.User {
			return a.User < b.User
		}
		return a.Role < b.Role
	})
	return grants, nil
}

// ---------------------------------------------------------------------------
// Helpers (pure — unit-tested in main_test.go)
// ---------------------------------------------------------------------------

// mssqlIdent builds a CatalogIdent for SQL Server. The overwhelmingly common
// server collation is case-insensitive (SQL_Latin1_General_CP1_CI_AS), and the
// Rust MsSqlCatalogProvider folds unquoted identifiers to uppercase. Marking
// names case-insensitive (case_sensitive=false) lets that folding resolve
// `Customers`, `customers`, and `CUSTOMERS` to the same catalog entry.
func mssqlIdent(name string) CatalogIdent {
	return CatalogIdent{Name: name, CaseSensitive: false}
}

// mapTableKind folds a sys.objects.type code ('U' user table, 'V' view) into
// the catalog kind vocabulary. The ANSI 'BASE TABLE'/'VIEW' spellings are also
// accepted so the mapper is robust to either metadata source.
func mapTableKind(objectType string, isExternal bool) string {
	if isExternal {
		return "ExternalTable"
	}
	switch strings.ToUpper(strings.TrimSpace(objectType)) {
	case "U", "BASE TABLE":
		return "Table"
	case "V", "VIEW":
		return "View"
	default:
		return "Unknown"
	}
}

// mapObjectType folds sys.objects.type_desc into the catalog's object-type
// vocabulary (TABLE / VIEW / PROCEDURE / FUNCTION / ...).
func mapObjectType(typeDesc string) string {
	switch strings.ToUpper(strings.TrimSpace(typeDesc)) {
	case "USER_TABLE", "INTERNAL_TABLE", "SYSTEM_TABLE":
		return "TABLE"
	case "VIEW":
		return "VIEW"
	case "SQL_STORED_PROCEDURE", "EXTENDED_STORED_PROCEDURE", "CLR_STORED_PROCEDURE":
		return "PROCEDURE"
	case "SQL_SCALAR_FUNCTION", "SQL_TABLE_VALUED_FUNCTION", "SQL_INLINE_TABLE_VALUED_FUNCTION",
		"CLR_SCALAR_FUNCTION", "CLR_TABLE_VALUED_FUNCTION", "AGGREGATE_FUNCTION":
		return "FUNCTION"
	case "SYNONYM":
		return "SYNONYM"
	case "SEQUENCE_OBJECT":
		return "SEQUENCE"
	default:
		s := strings.ToUpper(strings.TrimSpace(typeDesc))
		if s == "" {
			return "OBJECT"
		}
		return s
	}
}

// canonicalizePrivilege uppercases and trims a SQL Server permission name.
func canonicalizePrivilege(perm string) string {
	return strings.ToUpper(strings.TrimSpace(perm))
}

// isRolePrincipal reports whether a database principal type_desc denotes a role
// (vs a user) for role-hierarchy vs user-role classification.
func isRolePrincipal(typeDesc string) bool {
	switch strings.ToUpper(strings.TrimSpace(typeDesc)) {
	case "DATABASE_ROLE", "APPLICATION_ROLE":
		return true
	default:
		return false
	}
}

// bracketQuote wraps an identifier in [ ] brackets, escaping ] by doubling.
func bracketQuote(name string) string {
	return "[" + strings.ReplaceAll(name, "]", "]]") + "]"
}

// matchesAnyCI reports whether candidate equals any filter case-insensitively.
func matchesAnyCI(candidate string, filters []string) bool {
	for _, f := range filters {
		if strings.EqualFold(candidate, f) {
			return true
		}
	}
	return false
}

func parseUint64(s string) (uint64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		// Some drivers render large counts as floats ("1234.0").
		if f, ferr := strconv.ParseFloat(s, 64); ferr == nil && f >= 0 {
			return uint64(f), true
		}
		return 0, false
	}
	return v, true
}

func getField(row map[string]string, name string) string {
	return row[strings.ToLower(name)]
}

func queryRows(ctx context.Context, db *sql.DB, q string) ([]map[string]string, error) {
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	out := []map[string]string{}
	for rows.Next() {
		values := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range values {
			ptrs[i] = &values[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		r := make(map[string]string, len(cols))
		for i, c := range cols {
			key := strings.ToLower(c)
			switch t := values[i].(type) {
			case nil:
				r[key] = ""
			case []byte:
				r[key] = string(t)
			default:
				r[key] = fmt.Sprint(t)
			}
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
