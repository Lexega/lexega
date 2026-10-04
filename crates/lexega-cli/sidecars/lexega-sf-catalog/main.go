// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

// Command lexega-sf-catalog is the Snowflake catalog sidecar for Lexega.
//
// It connects to one Snowflake account, reads metadata — SHOW output,
// INFORMATION_SCHEMA and the SNOWFLAKE.ACCOUNT_USAGE views for tables,
// columns, constraints, policies, tags and grants — and emits a
// schema_version=2 CatalogSnapshot JSON consumed by the Rust engine.
//
// Invocation contract (driven by `lexega catalog pull`):
//
//	lexega-sf-catalog pull --out <file.json|-> --account <acct> --user <name> [flags]
//
// Snapshot JSON on stdout (with --out -) or written to the --out path; all
// progress goes to stderr so stdout stays clean for piping.
package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	_ "embed"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/snowflakedb/gosnowflake"
	"golang.org/x/term"
)

// version is set at build time via -ldflags "-X main.version=..."
var version = "dev"

// thirdPartyLicenses is what the licenses subcommand prints.
//
//go:embed THIRD_PARTY_LICENSES.txt
var thirdPartyLicenses string

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

type CatalogIdent struct {
	Name          string `json:"name"`
	CaseSensitive bool   `json:"case_sensitive,omitempty"`
}

// CatalogTag represents a tag assignment to a database object
type CatalogTag struct {
	TagDatabase string `json:"tag_database,omitempty"`
	TagSchema   string `json:"tag_schema,omitempty"`
	TagName     string `json:"tag_name"`
	TagValue    string `json:"tag_value,omitempty"`
}

type CatalogColumn struct {
	Name     CatalogIdent `json:"name"`
	DataType *string      `json:"data_type,omitempty"`
	Nullable *bool        `json:"nullable,omitempty"`
	Tags     []CatalogTag `json:"tags,omitempty"`
}

type CatalogTable struct {
	Name    CatalogIdent    `json:"name"`
	Kind    string          `json:"kind,omitempty"`
	Columns []CatalogColumn `json:"columns,omitempty"`

	RowCountEstimate     *uint64 `json:"row_count_estimate,omitempty"`
	RowCountEstimateAsOf *string `json:"row_count_estimate_as_of,omitempty"`

	BytesEstimate     *uint64 `json:"bytes_estimate,omitempty"`
	BytesEstimateAsOf *string `json:"bytes_estimate_as_of,omitempty"`

	Constraints []CatalogConstraint `json:"constraints,omitempty"`
	Comment     *string             `json:"comment,omitempty"`
	Tags        []CatalogTag        `json:"tags,omitempty"`
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

type ckey struct{ schema, name string }
type tkey struct{ schema, table string }

type colEntry struct {
	col       string
	ord       int
	posUnique int
}

type importedKeysAgg struct {
	fkCols  []colEntry
	pkTable *CatalogObjectName
	pkCols  []colEntry
}

type CatalogSchema struct {
	Name   CatalogIdent   `json:"name"`
	Tables []CatalogTable `json:"tables,omitempty"`
}

type CatalogDatabase struct {
	Name    CatalogIdent    `json:"name"`
	Schemas []CatalogSchema `json:"schemas,omitempty"`
}

// CatalogPolicy represents a governance policy (masking, row access, etc.)
type CatalogPolicy struct {
	Name       CatalogObjectName `json:"name"`
	Kind       string            `json:"kind,omitempty"`
	Body       *string           `json:"body,omitempty"`
	DDL        *string           `json:"ddl,omitempty"`
	Signature  *string           `json:"signature,omitempty"`
	ReturnType *string           `json:"return_type,omitempty"`
	Comment    *string           `json:"comment,omitempty"`
	CreatedAt  *string           `json:"created_at,omitempty"`
	Owner      *string           `json:"owner,omitempty"`
	// Note: body_table_dependencies populated by Rust parser, not Go sidecar
}

// CatalogPolicyReference represents a policy binding to a table/column
type CatalogPolicyReference struct {
	PolicyName CatalogObjectName `json:"policy_name"`
	PolicyKind string            `json:"policy_kind,omitempty"`
	RefTable   CatalogObjectName `json:"ref_table"`
	RefColumn  *CatalogIdent     `json:"ref_column,omitempty"`
	Enabled    *bool             `json:"enabled,omitempty"`
}

// === Grant Graph Structures ===
// These enable pre-execution analysis of effective access changes.

// CatalogRoleEdge represents a role hierarchy edge (GRANT ROLE parent TO ROLE child)
type CatalogRoleEdge struct {
	ParentRole  string `json:"parent"`                 // Role being granted
	ChildRole   string `json:"child"`                  // Role receiving the grant
	GrantOption bool   `json:"grant_option,omitempty"` // WITH GRANT OPTION
}

// CatalogObjectPrivilege represents a privilege grant on an object
type CatalogObjectPrivilege struct {
	Role       string `json:"role"`        // Role with the privilege
	Privilege  string `json:"privilege"`   // SELECT, INSERT, USAGE, OWNERSHIP, etc.
	ObjectType string `json:"object_type"` // TABLE, VIEW, SCHEMA, DATABASE, WAREHOUSE
	ObjectFQN  string `json:"object"`      // DB.SCHEMA.OBJECT fully qualified name
}

// CatalogUserRole represents a role assignment to a user
type CatalogUserRole struct {
	User string `json:"user"`
	Role string `json:"role"`
}

// CatalogGrants contains the grant graph for effective access analysis
type CatalogGrants struct {
	// Role hierarchy edges: role A granted to role B (B inherits A's privileges)
	RoleHierarchy []CatalogRoleEdge `json:"role_hierarchy,omitempty"`
	// Object privilege edges: role has privilege on object
	ObjectPrivileges []CatalogObjectPrivilege `json:"object_privileges,omitempty"`
	// User-to-role assignments
	UserRoles []CatalogUserRole `json:"user_roles,omitempty"`
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
	Out string

	Account   string
	User      string
	Role      string
	Warehouse string

	Auth string

	PasswordEnv    string
	PasswordStdin  bool
	PromptPassword bool
	TokenEnv       string
	TokenStdin     bool

	PrivateKeyPath string

	IncludeDB []string
	ExcludeDB []string

	MaxTables   int
	IncludeTags []string

	// Grant graph options
	IncludeGrants bool
	MaxGrants     int
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

	sub := os.Args[1]
	switch sub {
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
		fmt.Printf("lexega-sf-catalog %s\n", version)
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
	fmt.Fprintf(os.Stderr, "  %s pull --out <file.json> [connection flags]\n", prog)
	fmt.Fprintf(os.Stderr, "  %s licenses\n", prog)
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "Connection flags (secrets via env by default):\n")
	fmt.Fprintf(os.Stderr, "  --account <acct>\n")
	fmt.Fprintf(os.Stderr, "  --user <name>\n")
	fmt.Fprintf(os.Stderr, "  --role <role>\n")
	fmt.Fprintf(os.Stderr, "  --warehouse <wh>\n")
	fmt.Fprintf(os.Stderr, "  --auth snowflake|externalbrowser|jwt|oauth (default: snowflake)\n")
	fmt.Fprintf(os.Stderr, "  --password-env <ENV> (default: SNOWFLAKE_PASSWORD)\n")
	fmt.Fprintf(os.Stderr, "  --password-stdin (read password from stdin; snowflake auth only)\n")
	fmt.Fprintf(os.Stderr, "  --prompt-password (prompt on TTY; snowflake auth only)\n")
	fmt.Fprintf(os.Stderr, "  --token-env <ENV> (default: SNOWFLAKE_TOKEN)\n")
	fmt.Fprintf(os.Stderr, "  --token-stdin (read OAuth token from stdin; oauth auth only)\n")
	fmt.Fprintf(os.Stderr, "  --private-key-path <file> (jwt only; PKCS8 PEM)\n")
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "Scope flags:\n")
	fmt.Fprintf(os.Stderr, "  --include-db <DB> (repeatable; default: all accessible)\n")
	fmt.Fprintf(os.Stderr, "  --exclude-db <DB> (repeatable)\n")
	fmt.Fprintf(os.Stderr, "  --max-tables <n> (default: 0 = unlimited)\n")
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "Tag flags:\n")
	fmt.Fprintf(os.Stderr, "  --include-tag <TAG> (repeatable; pull tags with these names from ACCOUNT_USAGE)\n")
	fmt.Fprintf(os.Stderr, "                      Example: --include-tag PII --include-tag SENSITIVE\n")
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "Grant graph flags (for effective access analysis):\n")
	fmt.Fprintf(os.Stderr, "  --include-grants    Pull grant graph (role hierarchy + object privileges)\n")
	fmt.Fprintf(os.Stderr, "  --max-grants <n>    Limit object privileges (default: 500000)\n")
}

func parsePullArgs(argv []string) (pullArgs, error) {
	fs := flag.NewFlagSet("pull", flag.ContinueOnError)
	fs.SetOutput(ioDiscard{})

	var a pullArgs
	fs.StringVar(&a.Out, "out", "", "")
	// `lexega catalog pull` forwards the provider it was given.
	provider := fs.String("provider", "snowflake", "")
	// Defined only so that a Databricks invocation parses and is answered
	// with the name of its own extractor.
	workspaceURL := fs.String("workspace-url", "", "")
	fs.StringVar(&a.Account, "account", "", "")
	fs.StringVar(&a.User, "user", "", "")
	fs.StringVar(&a.Role, "role", "", "")
	fs.StringVar(&a.Warehouse, "warehouse", "", "")
	fs.StringVar(&a.Auth, "auth", "snowflake", "")
	fs.StringVar(&a.PasswordEnv, "password-env", "SNOWFLAKE_PASSWORD", "")
	fs.BoolVar(&a.PasswordStdin, "password-stdin", false, "")
	fs.BoolVar(&a.PromptPassword, "prompt-password", false, "")
	fs.StringVar(&a.TokenEnv, "token-env", "SNOWFLAKE_TOKEN", "")
	fs.BoolVar(&a.TokenStdin, "token-stdin", false, "")
	fs.StringVar(&a.PrivateKeyPath, "private-key-path", "", "")
	fs.IntVar(&a.MaxTables, "max-tables", 0, "")
	fs.BoolVar(&a.IncludeGrants, "include-grants", false, "")
	fs.IntVar(&a.MaxGrants, "max-grants", 500000, "")

	var includeDB multiString
	var excludeDB multiString
	var includeTags multiString
	fs.Var(&includeDB, "include-db", "")
	fs.Var(&excludeDB, "exclude-db", "")
	fs.Var(&includeTags, "include-tag", "")

	if err := fs.Parse(argv); err != nil {
		return pullArgs{}, err
	}
	a.IncludeDB = includeDB
	a.ExcludeDB = excludeDB
	a.IncludeTags = includeTags

	if a.Out == "" {
		return pullArgs{}, errors.New("--out is required")
	}

	switch strings.ToLower(strings.TrimSpace(*provider)) {
	case "snowflake", "sf":
		if *workspaceURL != "" {
			return pullArgs{}, errors.New("--workspace-url is a Databricks option; Databricks is read by lexega-dbx-catalog")
		}
	case "databricks", "dbx", "unity":
		return pullArgs{}, fmt.Errorf("invalid --provider: %q (this extractor reads Snowflake; Databricks is read by lexega-dbx-catalog)", *provider)
	default:
		return pullArgs{}, fmt.Errorf("invalid --provider: %q (this extractor reads Snowflake)", *provider)
	}

	if a.Account == "" {
		return pullArgs{}, errors.New("--account is required")
	}
	if a.User == "" {
		return pullArgs{}, errors.New("--user is required")
	}

	switch strings.ToLower(strings.TrimSpace(a.Auth)) {
	case "snowflake", "externalbrowser", "jwt", "oauth":
	default:
		return pullArgs{}, fmt.Errorf("invalid --auth: %q", a.Auth)
	}

	return a, nil
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

	progressf("NOTICE: catalog pull queries INFORMATION_SCHEMA; this may use warehouse compute. Use --warehouse to control which warehouse is used (or rely on your Snowflake user default).")
	progressf("Connecting to Snowflake (auth=%s) ...", strings.ToLower(strings.TrimSpace(args.Auth)))
	db, cfg, err := openSnowflake(ctx, args)
	if err != nil {
		return err
	}
	defer db.Close()
	progressf("Connected: account=%s user=%s role=%s warehouse=%s", cfg.Account, cfg.User, cfg.Role, cfg.Warehouse)

	// Always discover databases so we can apply case-insensitive filters correctly.
	// This also prevents accidental case-sensitive lookups caused by quoting identifiers
	// (we quote DB names in SQL, so we must use the canonical names returned by Snowflake).
	progressf("Discovering databases ...")
	allDBs, err := listDatabases(ctx, db)
	if err != nil {
		return err
	}

	// Apply include/exclude filters with Snowflake identifier semantics:
	// - unquoted filter values are case-insensitive
	// - quoted filter values (e.g. \"MyDb\") are case-sensitive
	// Note: To pass quotes through a shell, you must escape them, e.g.:
	//   --include-db '\"MyDb\"'
	var dbNames []string
	for _, candidate := range allDBs {
		if len(args.IncludeDB) > 0 {
			if !matches_any_ident_filter(candidate, args.IncludeDB) {
				continue
			}
		}
		if len(args.ExcludeDB) > 0 {
			if matches_any_ident_filter(candidate, args.ExcludeDB) {
				continue
			}
		}
		dbNames = append(dbNames, candidate)
	}
	if len(args.IncludeDB) > 0 && len(dbNames) == 0 {
		return fmt.Errorf("no databases matched --include-db filters: %v", args.IncludeDB)
	}
	sort.Strings(dbNames)
	progressf("Databases selected: %d", len(dbNames))
	if args.MaxTables > 0 {
		progressf("Max tables limit: %d", args.MaxTables)
	}

	snapshot := CatalogSnapshot{SchemaVersion: 2}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	snapshot.GeneratedAt = &now
	source := fmt.Sprintf("snowflake account=%s user=%s role=%s warehouse=%s auth=%v", cfg.Account, cfg.User, cfg.Role, cfg.Warehouse, cfg.Authenticator)
	snapshot.Source = &source

	tablesSeen := 0

	filteredToSpecificDBs := len(args.IncludeDB) > 0
	for _, dbName := range dbNames {
		progressf("Pulling %s ...", dbName)
		dbEntry, tableCount, err := pullDatabase(ctx, db, dbName, args.MaxTables, &tablesSeen, filteredToSpecificDBs)
		if err != nil {
			return fmt.Errorf("pull database %s: %w", dbName, err)
		}
		if tableCount == 0 {
			progressf("  %s: no tables (skipped)", dbName)
			continue
		}
		progressf("  %s: tables=%d (total_tables=%d)", dbName, tableCount, tablesSeen)
		snapshot.Databases = append(snapshot.Databases, dbEntry)
		if args.MaxTables > 0 && tablesSeen >= args.MaxTables {
			progressf("Reached max tables limit (%d); stopping.", args.MaxTables)
			break
		}
	}

	// Pull governance policies from ACCOUNT_USAGE (account-level, not per-database)
	policies, policyRefs, err := pullGovernancePolicies(ctx, db)
	if err != nil {
		// Non-fatal: continue without policies if ACCOUNT_USAGE access is denied
		progressf("warning: failed to pull governance policies: %v", err)
	} else {
		snapshot.Policies = policies
		snapshot.PolicyReferences = policyRefs
	}

	// Pull tags from ACCOUNT_USAGE if --include-tag was specified
	if len(args.IncludeTags) > 0 {
		tableTags, columnTags, err := pullTagReferences(ctx, db, args.IncludeTags)
		if err != nil {
			progressf("warning: failed to pull tag references: %v", err)
		} else {
			tagCount := applyTagsToSnapshot(&snapshot, tableTags, columnTags)
			progressf("Applied %d tag assignments to catalog", tagCount)
		}
	}

	// Pull grant graph if --include-grants was specified
	if args.IncludeGrants {
		grants, err := pullGrantGraph(ctx, db, args.MaxGrants)
		if err != nil {
			progressf("warning: failed to pull grant graph: %v", err)
		} else {
			snapshot.Grants = grants
			roleEdges := 0
			objPrivs := 0
			userRoles := 0
			if grants != nil {
				roleEdges = len(grants.RoleHierarchy)
				objPrivs = len(grants.ObjectPrivileges)
				userRoles = len(grants.UserRoles)
			}
			progressf("Grant graph: role_hierarchy=%d object_privileges=%d user_roles=%d", roleEdges, objPrivs, userRoles)
		}
	}

	// Ensure stable ordering.
	sort.Slice(snapshot.Databases, func(i, j int) bool {
		return strings.ToUpper(snapshot.Databases[i].Name.Name) < strings.ToUpper(snapshot.Databases[j].Name.Name)
	})

	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}

	// Support streaming to stdout with --out -
	if args.Out == "-" {
		progressf("Writing snapshot to stdout")
		if _, err := os.Stdout.Write(data); err != nil {
			return err
		}
		// Ensure trailing newline for clean piping
		os.Stdout.Write([]byte("\n"))
		progressf("Wrote catalog snapshot to stdout")
	} else {
		progressf("Writing snapshot: %s", args.Out)
		if err := os.WriteFile(args.Out, data, 0o644); err != nil {
			return err
		}
		progressf("Wrote catalog snapshot: %s", args.Out)
	}
	return nil
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

func openSnowflake(ctx context.Context, args pullArgs) (*sql.DB, gosnowflake.Config, error) {
	cfg := gosnowflake.Config{
		Account:   args.Account,
		User:      args.User,
		Role:      args.Role,
		Warehouse: args.Warehouse,
	}

	switch strings.ToLower(strings.TrimSpace(args.Auth)) {
	case "snowflake":
		cfg.Authenticator = gosnowflake.AuthTypeSnowflake
		pwBytes, err := resolvePasswordBytes(args)
		if err != nil {
			return nil, gosnowflake.Config{}, err
		}
		cfg.Password = string(pwBytes)
		zeroBytes(pwBytes)
	case "externalbrowser":
		cfg.Authenticator = gosnowflake.AuthTypeExternalBrowser
		// Password not required.
	case "oauth":
		cfg.Authenticator = gosnowflake.AuthTypeOAuth
		tokBytes, err := resolveTokenBytes(args)
		if err != nil {
			return nil, gosnowflake.Config{}, err
		}
		cfg.Token = string(tokBytes)
		zeroBytes(tokBytes)
	case "jwt":
		cfg.Authenticator = gosnowflake.AuthTypeJwt
		if strings.TrimSpace(args.PrivateKeyPath) == "" {
			return nil, gosnowflake.Config{}, errors.New("--private-key-path is required for jwt auth")
		}
		key, err := loadPKCS8RSAPrivateKeyFromPEM(args.PrivateKeyPath)
		if err != nil {
			return nil, gosnowflake.Config{}, err
		}
		cfg.PrivateKey = key
	default:
		return nil, gosnowflake.Config{}, fmt.Errorf("unsupported auth: %s", args.Auth)
	}

	if err := cfg.Validate(); err != nil {
		return nil, gosnowflake.Config{}, err
	}

	connector := gosnowflake.NewConnector(gosnowflake.SnowflakeDriver{}, cfg)
	db := sql.OpenDB(connector)

	pingCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		_ = db.Close()
		return nil, gosnowflake.Config{}, err
	}

	// Best-effort scrubbing: don't return secrets to the caller.
	// NOTE: gosnowflake requires strings internally, so secrets may still exist
	// in driver/connector memory; this only minimizes additional copies/lifetime
	// in this program.
	cfg.Password = ""
	cfg.Token = ""

	return db, cfg, nil
}

func resolvePasswordBytes(args pullArgs) ([]byte, error) {
	if args.PasswordStdin && args.PromptPassword {
		return nil, errors.New("choose only one of --password-stdin or --prompt-password")
	}
	if args.PasswordStdin {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, err
		}
		trimmed := trimSpaceBytes(b)
		if len(trimmed) == 0 {
			zeroBytes(b)
			return nil, errors.New("password read from stdin is empty")
		}
		pw := append([]byte(nil), trimmed...)
		zeroBytes(b)
		return pw, nil
	}
	if args.PromptPassword {
		return readSecretFromTTYBytes("Snowflake password: ")
	}
	// Default: environment
	// NOTE: env vars are already resident in process memory; we can only avoid
	// additional long-lived copies in this program.
	pwEnv := strings.TrimSpace(os.Getenv(args.PasswordEnv))
	if pwEnv == "" {
		return nil, fmt.Errorf("%s is empty; use --prompt-password, --password-stdin, or set the env var", args.PasswordEnv)
	}
	return []byte(pwEnv), nil
}

func resolveTokenBytes(args pullArgs) ([]byte, error) {
	if args.TokenStdin {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, err
		}
		trimmed := trimSpaceBytes(b)
		if len(trimmed) == 0 {
			zeroBytes(b)
			return nil, errors.New("token read from stdin is empty")
		}
		tok := append([]byte(nil), trimmed...)
		zeroBytes(b)
		return tok, nil
	}
	tokEnv := strings.TrimSpace(os.Getenv(args.TokenEnv))
	if tokEnv == "" {
		return nil, fmt.Errorf("%s is empty; use --token-stdin or set the env var", args.TokenEnv)
	}
	return []byte(tokEnv), nil
}

func readSecretFromTTYBytes(prompt string) ([]byte, error) {
	// Prefer /dev/tty so stdin can be used for piping if desired.
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err == nil {
		defer tty.Close()
		_, _ = fmt.Fprint(tty, prompt)
		b, err := term.ReadPassword(int(tty.Fd()))
		_, _ = fmt.Fprintln(tty)
		if err != nil {
			return nil, err
		}
		trimmed := trimSpaceBytes(b)
		if len(trimmed) == 0 {
			zeroBytes(b)
			return nil, errors.New("secret is empty")
		}
		out := append([]byte(nil), trimmed...)
		zeroBytes(b)
		return out, nil
	}

	// Fallback to stdin if we can't open /dev/tty.
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, errors.New("cannot prompt for secret: no TTY available")
	}
	fmt.Fprint(os.Stderr, prompt)
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	trimmed := trimSpaceBytes(b)
	if len(trimmed) == 0 {
		zeroBytes(b)
		return nil, errors.New("secret is empty")
	}
	out := append([]byte(nil), trimmed...)
	zeroBytes(b)
	return out, nil
}

func loadPKCS8RSAPrivateKeyFromPEM(path string) (*rsa.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	zeroBytes(b)
	if block == nil {
		return nil, errors.New("private key file is not valid PEM")
	}
	if x509.IsEncryptedPEMBlock(block) {
		return nil, errors.New("encrypted PKCS8 PEM is not supported; decrypt before use")
	}
	defer zeroBytes(block.Bytes)
	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := keyAny.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not RSA")
	}
	return key, nil
}

func listDatabases(ctx context.Context, db *sql.DB) ([]string, error) {
	rows, err := queryRows(ctx, db, "SHOW DATABASES")
	if err != nil {
		return nil, err
	}

	names := make([]string, 0, len(rows))
	for _, r := range rows {
		name := getFieldCI(r, "name")
		if name == "" {
			continue
		}
		names = append(names, name)
	}
	return names, nil
}

func pullDatabase(ctx context.Context, db *sql.DB, dbName string, maxTables int, tablesSeen *int, filteredToSpecificDBs bool) (CatalogDatabase, int, error) {
	// Defensive normalization: Snowflake system object names can show up with incidental whitespace
	// depending on driver/result formatting. Normalize once so special cases (like SNOWFLAKE) are
	// reliably detected.
	dbName = strings.TrimSpace(dbName)

	// Query tables
	tablesSQL := fmt.Sprintf(
		"SELECT TABLE_SCHEMA, TABLE_NAME, TABLE_TYPE, COMMENT FROM %s.INFORMATION_SCHEMA.TABLES",
		quoteIdent(dbName),
	)
	tableRows, err := queryRows(ctx, db, tablesSQL)
	if err != nil {
		return CatalogDatabase{}, 0, err
	}

	// Query constraints (best-effort). These INFORMATION_SCHEMA/ACCOUNT_USAGE queries can be expensive on large DBs.
	// We keep them database-scoped for determinism and to avoid SHOW 10k limits.
	//
	// NOTE: We intentionally do NOT query KEY_COLUMN_USAGE anywhere.
	var tcSQL string
	var rcSQL string
	if strings.EqualFold(dbName, "SNOWFLAKE") {
		if filteredToSpecificDBs {
			// If the user explicitly scoped the pull to specific DBs, prefer INFORMATION_SCHEMA to avoid
			// ACCOUNT_USAGE latency.
			progressf("  %s: info: using INFORMATION_SCHEMA constraint views (filtered pull)", dbName)
			tcSQL = "SELECT CONSTRAINT_SCHEMA, CONSTRAINT_NAME, TABLE_SCHEMA, TABLE_NAME, CONSTRAINT_TYPE, ENFORCED, RELY " +
				"FROM SNOWFLAKE.INFORMATION_SCHEMA.TABLE_CONSTRAINTS"
			rcSQL = "SELECT CONSTRAINT_SCHEMA, CONSTRAINT_NAME, UNIQUE_CONSTRAINT_CATALOG, UNIQUE_CONSTRAINT_SCHEMA, UNIQUE_CONSTRAINT_NAME, MATCH_OPTION, UPDATE_RULE, DELETE_RULE " +
				"FROM SNOWFLAKE.INFORMATION_SCHEMA.REFERENTIAL_CONSTRAINTS"
		} else {
			progressf("  %s: info: using ACCOUNT_USAGE constraint views", dbName)
			tcSQL = "SELECT CONSTRAINT_SCHEMA, CONSTRAINT_NAME, TABLE_SCHEMA, TABLE_NAME, CONSTRAINT_TYPE, ENFORCED, RELY " +
				"FROM SNOWFLAKE.ACCOUNT_USAGE.TABLE_CONSTRAINTS " +
				"WHERE TABLE_CATALOG = 'SNOWFLAKE' AND CONSTRAINT_CATALOG = 'SNOWFLAKE' AND DELETED IS NULL"
			rcSQL = "SELECT CONSTRAINT_SCHEMA, CONSTRAINT_NAME, UNIQUE_CONSTRAINT_CATALOG, UNIQUE_CONSTRAINT_SCHEMA, UNIQUE_CONSTRAINT_NAME, MATCH_OPTION, UPDATE_RULE, DELETE_RULE " +
				"FROM SNOWFLAKE.ACCOUNT_USAGE.REFERENTIAL_CONSTRAINTS " +
				"WHERE CONSTRAINT_CATALOG = 'SNOWFLAKE' AND DELETED IS NULL"
		}
	} else {
		tcSQL = fmt.Sprintf(
			"SELECT CONSTRAINT_SCHEMA, CONSTRAINT_NAME, TABLE_SCHEMA, TABLE_NAME, CONSTRAINT_TYPE, ENFORCED, RELY FROM %s.INFORMATION_SCHEMA.TABLE_CONSTRAINTS",
			quoteIdent(dbName),
		)
		rcSQL = fmt.Sprintf(
			"SELECT CONSTRAINT_SCHEMA, CONSTRAINT_NAME, UNIQUE_CONSTRAINT_CATALOG, UNIQUE_CONSTRAINT_SCHEMA, UNIQUE_CONSTRAINT_NAME, MATCH_OPTION, UPDATE_RULE, DELETE_RULE FROM %s.INFORMATION_SCHEMA.REFERENTIAL_CONSTRAINTS",
			quoteIdent(dbName),
		)
	}
	tcRows, err := queryRows(ctx, db, tcSQL)
	if err != nil {
		// Do not fail entire snapshot on constraint query issues.
		progressf("  %s: warning: failed to query TABLE_CONSTRAINTS: %v", dbName, err)
		tcRows = nil
	}

	// We omit constraint column membership to avoid KEY_COLUMN_USAGE.
	// Constraint presence and (where available) referential relationships are still captured.
	var kcuRows []map[string]string
	kcuRows = nil

	rcRows, err := queryRows(ctx, db, rcSQL)
	if err != nil {
		progressf("  %s: warning: failed to query REFERENTIAL_CONSTRAINTS: %v", dbName, err)
		rcRows = nil
	}

	columnsSQL := fmt.Sprintf(
		"SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, DATA_TYPE, IS_NULLABLE FROM %s.INFORMATION_SCHEMA.COLUMNS",
		quoteIdent(dbName),
	)
	colRows, err := queryRows(ctx, db, columnsSQL)
	if err != nil {
		return CatalogDatabase{}, 0, err
	}

	// Stats from SHOW TABLES (doesn't require a warehouse). Execute per schema to avoid SHOW pagination issues.
	schemaSet := make(map[string]struct{})
	for _, r := range tableRows {
		sch := getFieldCI(r, "table_schema")
		if sch == "" {
			continue
		}
		schemaSet[sch] = struct{}{}
	}
	var schemaList []string
	for s := range schemaSet {
		schemaList = append(schemaList, s)
	}
	sort.Strings(schemaList)

	// Best-effort FK column membership via SHOW IMPORTED KEYS.
	// This fills the KEY_COLUMN_USAGE gap without making the snapshot fail if the command
	// is unsupported or privileges are missing.
	importedByFK := collectImportedKeysBestEffort(ctx, db, dbName, schemaList, tableRows)

	nowRFC := time.Now().UTC().Format(time.RFC3339Nano)
	statsBySTRows := make(map[string]map[string]uint64)  // schema -> table -> rows
	statsBySTBytes := make(map[string]map[string]uint64) // schema -> table -> bytes
	for _, sch := range schemaList {
		showSQL := fmt.Sprintf("SHOW TABLES IN SCHEMA %s.%s", quoteIdent(dbName), quoteIdent(sch))
		showRows, err := queryRows(ctx, db, showSQL)
		if err != nil {
			progressf("  %s.%s: warning: SHOW TABLES failed: %v", dbName, sch, err)
			continue
		}
		for _, r := range showRows {
			tbl := getFieldCI(r, "name")
			if tbl == "" {
				continue
			}
			if _, ok := statsBySTRows[sch]; !ok {
				statsBySTRows[sch] = make(map[string]uint64)
			}
			if _, ok := statsBySTBytes[sch]; !ok {
				statsBySTBytes[sch] = make(map[string]uint64)
			}
			rowsStr := strings.TrimSpace(getFieldCI(r, "rows"))
			if rowsStr != "" && strings.ToUpper(rowsStr) != "NULL" {
				if v, ok := parseUint64(rowsStr); ok {
					statsBySTRows[sch][tbl] = v
				}
			}
			bytesStr := strings.TrimSpace(getFieldCI(r, "bytes"))
			if bytesStr != "" && strings.ToUpper(bytesStr) != "NULL" {
				if v, ok := parseUint64(bytesStr); ok {
					statsBySTBytes[sch][tbl] = v
				}
			}
		}
	}

	// Build constraint maps.

	constraintToTable := make(map[ckey]tkey)
	constraintType := make(map[ckey]string)
	constraintEnforced := make(map[ckey]*bool)
	constraintRely := make(map[ckey]*bool)
	uniqueConstraintToTable := make(map[ckey]tkey)

	for _, r := range tcRows {
		cs := getFieldCI(r, "constraint_schema")
		cn := getFieldCI(r, "constraint_name")
		ts := getFieldCI(r, "table_schema")
		tn := getFieldCI(r, "table_name")
		ct := strings.ToUpper(strings.TrimSpace(getFieldCI(r, "constraint_type")))
		if cs == "" || cn == "" || ts == "" || tn == "" {
			continue
		}
		k := ckey{schema: cs, name: cn}
		constraintToTable[k] = tkey{schema: ts, table: tn}
		constraintType[k] = ct

		enfStr := strings.ToUpper(strings.TrimSpace(getFieldCI(r, "enforced")))
		if enfStr == "YES" {
			b := true
			constraintEnforced[k] = &b
		} else if enfStr == "NO" {
			b := false
			constraintEnforced[k] = &b
		}
		relyStr := strings.ToUpper(strings.TrimSpace(getFieldCI(r, "rely")))
		if relyStr == "YES" {
			b := true
			constraintRely[k] = &b
		} else if relyStr == "NO" {
			b := false
			constraintRely[k] = &b
		}

		if ct == "PRIMARY KEY" || ct == "UNIQUE" || ct == "UNIQUE KEY" {
			uniqueConstraintToTable[k] = tkey{schema: ts, table: tn}
		}
	}

	// key column usage: collect columns by constraint
	colsByConstraint := make(map[ckey][]colEntry)
	for _, r := range kcuRows {
		cs := getFieldCI(r, "constraint_schema")
		cn := getFieldCI(r, "constraint_name")
		col := getFieldCI(r, "column_name")
		if cs == "" || cn == "" || col == "" {
			continue
		}
		ord := parseIntDefault(getFieldCI(r, "ordinal_position"), 0)
		posUnique := parseIntDefault(getFieldCI(r, "position_in_unique_constraint"), 0)
		k := ckey{schema: cs, name: cn}
		colsByConstraint[k] = append(colsByConstraint[k], colEntry{col: col, ord: ord, posUnique: posUnique})
	}

	// referential constraints: map fk constraint -> referenced unique constraint.
	refByFK := make(map[ckey]ckey)
	for _, r := range rcRows {
		cs := getFieldCI(r, "constraint_schema")
		cn := getFieldCI(r, "constraint_name")
		ucs := getFieldCI(r, "unique_constraint_schema")
		ucn := getFieldCI(r, "unique_constraint_name")
		if cs == "" || cn == "" || ucs == "" || ucn == "" {
			continue
		}
		refByFK[ckey{schema: cs, name: cn}] = ckey{schema: ucs, name: ucn}
	}

	// constraintsByTable: schema -> table -> []constraint
	constraintsByST := make(map[string]map[string][]CatalogConstraint)
	for k, ct := range constraintType {
		loc, ok := constraintToTable[k]
		if !ok {
			continue
		}
		if _, ok := constraintsByST[loc.schema]; !ok {
			constraintsByST[loc.schema] = make(map[string][]CatalogConstraint)
		}
		// Columns for this constraint.
		entries := colsByConstraint[k]
		sort.SliceStable(entries, func(i, j int) bool {
			ai, aj := entries[i], entries[j]
			if ai.ord != 0 && aj.ord != 0 && ai.ord != aj.ord {
				return ai.ord < aj.ord
			}
			return strings.ToUpper(ai.col) < strings.ToUpper(aj.col)
		})
		cols := make([]CatalogIdent, 0, len(entries))
		for _, e := range entries {
			cols = append(cols, identFromName(e.col))
		}

		kind := "Unknown"
		if ct == "PRIMARY KEY" {
			kind = "PrimaryKey"
		} else if ct == "UNIQUE" || ct == "UNIQUE KEY" {
			kind = "Unique"
		} else if ct == "FOREIGN KEY" {
			kind = "ForeignKey"
		}

		nameCopy := k.name
		con := CatalogConstraint{
			Kind:     kind,
			Name:     &nameCopy,
			Columns:  cols,
			Enforced: constraintEnforced[k],
			Rely:     constraintRely[k],
		}

		// FK referenced side best-effort.
		if kind == "ForeignKey" {
			// Prefer SHOW IMPORTED KEYS for column membership if available.
			// (We intentionally do not query KEY_COLUMN_USAGE.)
			if importedByFK != nil {
				if agg, ok := importedByFK[k]; ok {
					if len(con.Columns) == 0 && len(agg.fkCols) > 0 {
						cols2 := make([]CatalogIdent, 0, len(agg.fkCols))
						for _, e := range agg.fkCols {
							cols2 = append(cols2, identFromName(e.col))
						}
						con.Columns = cols2
					}
					if con.RefTable == nil && agg.pkTable != nil {
						con.RefTable = agg.pkTable
					}
					if len(con.RefColumns) == 0 && len(agg.pkCols) > 0 {
						refCols2 := make([]CatalogIdent, 0, len(agg.pkCols))
						for _, e := range agg.pkCols {
							refCols2 = append(refCols2, identFromName(e.col))
						}
						con.RefColumns = refCols2
					}
				}
			}
			if ref, ok := refByFK[k]; ok {
				if refLoc, ok := uniqueConstraintToTable[ref]; ok {
					// Ref columns are columns of the referenced unique constraint.
					// NOTE: When KEY_COLUMN_USAGE is omitted, refEntries will often be empty.
					// Do not overwrite imported-key results with empty slices.
					refEntries := colsByConstraint[ref]
					sort.SliceStable(refEntries, func(i, j int) bool {
						ai, aj := refEntries[i], refEntries[j]
						if ai.ord != 0 && aj.ord != 0 && ai.ord != aj.ord {
							return ai.ord < aj.ord
						}
						return strings.ToUpper(ai.col) < strings.ToUpper(aj.col)
					})
					refCols := make([]CatalogIdent, 0, len(refEntries))
					for _, e := range refEntries {
						refCols = append(refCols, identFromName(e.col))
					}
					if con.RefTable == nil {
						con.RefTable = &CatalogObjectName{
							Database: identFromName(dbName),
							Schema:   identFromName(refLoc.schema),
							Name:     identFromName(refLoc.table),
						}
					}
					if len(con.RefColumns) == 0 && len(refCols) > 0 {
						con.RefColumns = refCols
					}
				}
			}
		}

		constraintsByST[loc.schema][loc.table] = append(constraintsByST[loc.schema][loc.table], con)
	}

	// columnsBySchemaTable: schema -> table -> []col
	colsByST := make(map[string]map[string][]CatalogColumn)
	for _, r := range colRows {
		sch := getFieldCI(r, "table_schema")
		tbl := getFieldCI(r, "table_name")
		col := getFieldCI(r, "column_name")
		if sch == "" || tbl == "" || col == "" {
			continue
		}
		if _, ok := colsByST[sch]; !ok {
			colsByST[sch] = make(map[string][]CatalogColumn)
		}
		dt := getFieldCI(r, "data_type")
		var dtPtr *string
		if dt != "" {
			dtCopy := dt
			dtPtr = &dtCopy
		}
		nullableStr := strings.ToUpper(getFieldCI(r, "is_nullable"))
		var nullablePtr *bool
		if nullableStr == "YES" {
			b := true
			nullablePtr = &b
		} else if nullableStr == "NO" {
			b := false
			nullablePtr = &b
		}

		colsByST[sch][tbl] = append(colsByST[sch][tbl], CatalogColumn{
			Name:     identFromName(col),
			DataType: dtPtr,
			Nullable: nullablePtr,
		})
	}

	// schemas: schema -> tables
	schemas := make(map[string]map[string]CatalogTable)
	tableCount := 0

	for _, r := range tableRows {
		sch := getFieldCI(r, "table_schema")
		tbl := getFieldCI(r, "table_name")
		if sch == "" || tbl == "" {
			continue
		}

		if maxTables > 0 && *tablesSeen >= maxTables {
			break
		}

		kind := mapTableKind(getFieldCI(r, "table_type"))
		comment := getFieldCI(r, "comment")
		var commentPtr *string
		if strings.TrimSpace(comment) != "" {
			c := comment
			commentPtr = &c
		}

		cols := colsByST[sch][tbl]
		sort.Slice(cols, func(i, j int) bool {
			return strings.ToUpper(cols[i].Name.Name) < strings.ToUpper(cols[j].Name.Name)
		})

		// Stats (SHOW TABLES).
		var rowCountPtr *uint64
		if m, ok := statsBySTRows[sch]; ok {
			if v, ok2 := m[tbl]; ok2 {
				vv := v
				rowCountPtr = &vv
			}
		}
		var bytesPtr *uint64
		if m, ok := statsBySTBytes[sch]; ok {
			if v, ok2 := m[tbl]; ok2 {
				vv := v
				bytesPtr = &vv
			}
		}

		// Constraints.
		constraints := constraintsByST[sch][tbl]
		// Stable ordering.
		sort.SliceStable(constraints, func(i, j int) bool {
			a, b := constraints[i], constraints[j]
			ak := strings.ToUpper(a.Kind)
			bk := strings.ToUpper(b.Kind)
			if ak != bk {
				return ak < bk
			}
			an, bn := "", ""
			if a.Name != nil {
				an = *a.Name
			}
			if b.Name != nil {
				bn = *b.Name
			}
			if strings.ToUpper(an) != strings.ToUpper(bn) {
				return strings.ToUpper(an) < strings.ToUpper(bn)
			}
			// Fall back to columns.
			ac := make([]string, 0, len(a.Columns))
			for _, c := range a.Columns {
				ac = append(ac, strings.ToUpper(c.Name))
			}
			bc := make([]string, 0, len(b.Columns))
			for _, c := range b.Columns {
				bc = append(bc, strings.ToUpper(c.Name))
			}
			return strings.Join(ac, ",") < strings.Join(bc, ",")
		})

		if _, ok := schemas[sch]; !ok {
			schemas[sch] = make(map[string]CatalogTable)
		}
		schemas[sch][tbl] = CatalogTable{
			Name:             identFromName(tbl),
			Kind:             kind,
			Columns:          cols,
			RowCountEstimate: rowCountPtr,
			RowCountEstimateAsOf: func() *string {
				if rowCountPtr == nil {
					return nil
				}
				v := nowRFC
				return &v
			}(),
			BytesEstimate: bytesPtr,
			BytesEstimateAsOf: func() *string {
				if bytesPtr == nil {
					return nil
				}
				v := nowRFC
				return &v
			}(),
			Constraints: constraints,
			Comment:     commentPtr,
		}
		tableCount++
		(*tablesSeen)++
	}

	if tableCount == 0 {
		return CatalogDatabase{}, 0, nil
	}

	schemaNames := make([]string, 0, len(schemas))
	for s := range schemas {
		schemaNames = append(schemaNames, s)
	}
	sort.Strings(schemaNames)

	schemaEntries := make([]CatalogSchema, 0, len(schemaNames))
	for _, sch := range schemaNames {
		tableMap := schemas[sch]
		tableNames := make([]string, 0, len(tableMap))
		for t := range tableMap {
			tableNames = append(tableNames, t)
		}
		sort.Strings(tableNames)

		tables := make([]CatalogTable, 0, len(tableNames))
		for _, t := range tableNames {
			tables = append(tables, tableMap[t])
		}
		schemaEntries = append(schemaEntries, CatalogSchema{
			Name:   identFromName(sch),
			Tables: tables,
		})
	}

	return CatalogDatabase{
		Name:    identFromName(dbName),
		Schemas: schemaEntries,
	}, tableCount, nil
}

func identFromName(name string) CatalogIdent {
	// Best-effort heuristic: information_schema does not tell us whether the identifier
	// was quoted at creation time. If a name contains lowercase letters, it must have
	// been quoted and therefore should be treated as case-sensitive.
	caseSensitive := false
	for _, r := range name {
		if r >= 'a' && r <= 'z' {
			caseSensitive = true
			break
		}
	}
	return CatalogIdent{Name: name, CaseSensitive: caseSensitive}
}

func mapTableKind(tableType string) string {
	switch strings.ToUpper(strings.TrimSpace(tableType)) {
	case "BASE TABLE":
		return "Table"
	case "VIEW":
		return "View"
	case "MATERIALIZED VIEW":
		return "MaterializedView"
	case "EXTERNAL TABLE":
		return "ExternalTable"
	default:
		return "Unknown"
	}
}

func quoteIdent(name string) string {
	// Double quotes escaped by doubling.
	escaped := strings.ReplaceAll(name, "\"", "\"\"")
	return "\"" + escaped + "\""
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
			v := values[i]
			if v == nil {
				r[key] = ""
				continue
			}
			switch t := v.(type) {
			case []byte:
				r[key] = string(t)
			default:
				r[key] = fmt.Sprint(v)
			}
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func parseUint64(s string) (uint64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	var v uint64
	// SHOW outputs are numeric-ish; parse via fmt first to be tolerant.
	_, err := fmt.Sscan(s, &v)
	if err != nil {
		return 0, false
	}
	return v, true
}

func parseIntDefault(s string, def int) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return def
	}
	var v int
	_, err := fmt.Sscan(s, &v)
	if err != nil {
		return def
	}
	return v
}

func getFieldCI(row map[string]string, name string) string {
	v, ok := row[strings.ToLower(name)]
	if ok {
		return v
	}
	return ""
}

func collectImportedKeysBestEffort(
	ctx context.Context,
	db *sql.DB,
	dbName string,
	schemaList []string,
	tableRows []map[string]string,
) map[ckey]*importedKeysAgg {
	// NOTE: SHOW IMPORTED KEYS is not officially documented, so we treat this as best-effort.
	// We only rely on the output schema that we observed empirically.
	//
	// Output columns (observed):
	//   created_on, pk_database_name, pk_schema_name, pk_table_name, pk_column_name,
	//   fk_database_name, fk_schema_name, fk_table_name, fk_column_name, key_sequence,
	//   update_rule, delete_rule, fk_name, pk_name, deferrability, rely, comment

	tablesBySchema := make(map[string]map[string]struct{})
	for _, r := range tableRows {
		sch := getFieldCI(r, "table_schema")
		tbl := getFieldCI(r, "table_name")
		if sch == "" || tbl == "" {
			continue
		}
		if _, ok := tablesBySchema[sch]; !ok {
			tablesBySchema[sch] = make(map[string]struct{})
		}
		tablesBySchema[sch][tbl] = struct{}{}
	}

	// 1) Try DB-scoped query first.
	// If it errors or appears truncated (10k cap), fall back to schema/table scoping.
	dbSQL := fmt.Sprintf("SHOW IMPORTED KEYS IN DATABASE %s", quoteIdent(dbName))
	rows, err := queryRows(ctx, db, dbSQL)
	if err == nil {
		if len(rows) > 0 && len(rows) < 10000 {
			return aggregateImportedKeys(rows)
		}
		if len(rows) >= 10000 {
			progressf("  %s: info: SHOW IMPORTED KEYS in database returned %d rows (possible 10k truncation); falling back to per-schema", dbName, len(rows))
		}
	} else {
		// If unsupported/privilege error, per-schema likely fails too, but we still try.
		progressf("  %s: info: SHOW IMPORTED KEYS in database failed (will fall back): %v", dbName, err)
	}

	// 2) Per-schema.
	agg := make(map[ckey]*importedKeysAgg)
	anySuccess := false
	for _, sch := range schemaList {
		schSQL := fmt.Sprintf("SHOW IMPORTED KEYS IN SCHEMA %s.%s", quoteIdent(dbName), quoteIdent(sch))
		schRows, schErr := queryRows(ctx, db, schSQL)
		if schErr == nil {
			anySuccess = true
			if len(schRows) > 0 && len(schRows) < 10000 {
				mergeImportedAgg(agg, aggregateImportedKeys(schRows))
				continue
			}
			if len(schRows) >= 10000 {
				progressf("  %s.%s: info: SHOW IMPORTED KEYS in schema returned %d rows (possible 10k truncation); falling back to per-table", dbName, sch, len(schRows))
			} else {
				// 0 rows: nothing to do.
				continue
			}
		} else {
			// Don't spam warnings: most schemas will behave similarly.
			progressf("  %s.%s: info: SHOW IMPORTED KEYS in schema failed (will attempt per-table): %v", dbName, sch, schErr)
		}

		// 3) Per-table fallback for this schema.
		tblSet := tablesBySchema[sch]
		if len(tblSet) == 0 {
			continue
		}
		tableNames := make([]string, 0, len(tblSet))
		for t := range tblSet {
			tableNames = append(tableNames, t)
		}
		sort.Strings(tableNames)
		for _, tbl := range tableNames {
			tblSQL := fmt.Sprintf("SHOW IMPORTED KEYS IN TABLE %s.%s.%s", quoteIdent(dbName), quoteIdent(sch), quoteIdent(tbl))
			tblRows, tblErr := queryRows(ctx, db, tblSQL)
			if tblErr != nil {
				continue
			}
			if len(tblRows) == 0 {
				continue
			}
			anySuccess = true
			mergeImportedAgg(agg, aggregateImportedKeys(tblRows))
		}
	}

	if !anySuccess || len(agg) == 0 {
		return nil
	}
	return agg
}

func aggregateImportedKeys(rows []map[string]string) map[ckey]*importedKeysAgg {
	out := make(map[ckey]*importedKeysAgg)
	for _, r := range rows {
		fkSchema := strings.TrimSpace(getFieldCI(r, "fk_schema_name"))
		fkName := strings.TrimSpace(getFieldCI(r, "fk_name"))
		fkTable := strings.TrimSpace(getFieldCI(r, "fk_table_name"))
		fkCol := strings.TrimSpace(getFieldCI(r, "fk_column_name"))
		pkDB := strings.TrimSpace(getFieldCI(r, "pk_database_name"))
		pkSchema := strings.TrimSpace(getFieldCI(r, "pk_schema_name"))
		pkTable := strings.TrimSpace(getFieldCI(r, "pk_table_name"))
		pkCol := strings.TrimSpace(getFieldCI(r, "pk_column_name"))
		seq := parseIntDefault(getFieldCI(r, "key_sequence"), 0)

		if fkSchema == "" || fkName == "" || fkTable == "" {
			continue
		}
		if fkCol == "" || pkDB == "" || pkSchema == "" || pkTable == "" || pkCol == "" {
			continue
		}

		k := ckey{schema: fkSchema, name: fkName}
		entry, ok := out[k]
		if !ok {
			entry = &importedKeysAgg{}
			entry.pkTable = &CatalogObjectName{
				Database: identFromName(pkDB),
				Schema:   identFromName(pkSchema),
				Name:     identFromName(pkTable),
			}
			out[k] = entry
		}

		entry.fkCols = append(entry.fkCols, colEntry{col: fkCol, ord: seq})
		entry.pkCols = append(entry.pkCols, colEntry{col: pkCol, ord: seq})
	}

	for _, v := range out {
		sort.SliceStable(v.fkCols, func(i, j int) bool {
			ai, aj := v.fkCols[i], v.fkCols[j]
			if ai.ord != 0 && aj.ord != 0 && ai.ord != aj.ord {
				return ai.ord < aj.ord
			}
			return strings.ToUpper(ai.col) < strings.ToUpper(aj.col)
		})
		sort.SliceStable(v.pkCols, func(i, j int) bool {
			ai, aj := v.pkCols[i], v.pkCols[j]
			if ai.ord != 0 && aj.ord != 0 && ai.ord != aj.ord {
				return ai.ord < aj.ord
			}
			return strings.ToUpper(ai.col) < strings.ToUpper(aj.col)
		})
	}

	return out
}

func mergeImportedAgg(dst map[ckey]*importedKeysAgg, src map[ckey]*importedKeysAgg) {
	for k, v := range src {
		if existing, ok := dst[k]; ok {
			// Merge columns; de-dupe by (col, ord).
			existing.fkCols = mergeColEntries(existing.fkCols, v.fkCols)
			existing.pkCols = mergeColEntries(existing.pkCols, v.pkCols)
			if existing.pkTable == nil && v.pkTable != nil {
				existing.pkTable = v.pkTable
			}
			continue
		}
		dst[k] = v
	}
}

func mergeColEntries(a []colEntry, b []colEntry) []colEntry {
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]colEntry, 0, len(a)+len(b))
	add := func(e colEntry) {
		key := fmt.Sprintf("%d:%s", e.ord, strings.ToUpper(e.col))
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, e)
	}
	for _, e := range a {
		add(e)
	}
	for _, e := range b {
		add(e)
	}
	sort.SliceStable(out, func(i, j int) bool {
		ai, aj := out[i], out[j]
		if ai.ord != 0 && aj.ord != 0 && ai.ord != aj.ord {
			return ai.ord < aj.ord
		}
		return strings.ToUpper(ai.col) < strings.ToUpper(aj.col)
	})
	return out
}

// ============================================================================
// Governance Policy Extraction from ACCOUNT_USAGE
// ============================================================================

// pullGovernancePolicies queries SNOWFLAKE.ACCOUNT_USAGE for masking policies,
// row access policies, and policy references. These are account-level governance
// objects that can reference lookup tables in their bodies.
func pullGovernancePolicies(ctx context.Context, db *sql.DB) ([]CatalogPolicy, []CatalogPolicyReference, error) {
	var policies []CatalogPolicy
	var refs []CatalogPolicyReference

	// Pull masking policies
	progressf("Pulling governance policies from ACCOUNT_USAGE...")
	maskingPolicies, err := pullMaskingPolicies(ctx, db)
	if err != nil {
		progressf("  warning: failed to query masking policies: %v", err)
	} else {
		policies = append(policies, maskingPolicies...)
		progressf("  masking policies: %d", len(maskingPolicies))
	}

	// Pull row access policies
	rapPolicies, err := pullRowAccessPolicies(ctx, db)
	if err != nil {
		progressf("  warning: failed to query row access policies: %v", err)
	} else {
		policies = append(policies, rapPolicies...)
		progressf("  row access policies: %d", len(rapPolicies))
	}

	// Pull policy references (bindings to tables/columns)
	policyRefs, err := pullPolicyReferences(ctx, db)
	if err != nil {
		progressf("  warning: failed to query policy references: %v", err)
	} else {
		refs = policyRefs
		progressf("  policy references: %d", len(refs))
	}

	return policies, refs, nil
}

func pullMaskingPolicies(ctx context.Context, db *sql.DB) ([]CatalogPolicy, error) {
	// SNOWFLAKE.ACCOUNT_USAGE.MASKING_POLICIES contains policy definitions
	// Note: POLICY_BODY contains the actual masking expression
	sql := `
		SELECT 
			POLICY_CATALOG,
			POLICY_SCHEMA,
			POLICY_NAME,
			POLICY_BODY,
			POLICY_SIGNATURE,
			POLICY_RETURN_TYPE,
			POLICY_COMMENT,
			CREATED,
			POLICY_OWNER
		FROM SNOWFLAKE.ACCOUNT_USAGE.MASKING_POLICIES
		WHERE DELETED IS NULL
	`
	rows, err := queryRows(ctx, db, sql)
	if err != nil {
		return nil, err
	}

	var policies []CatalogPolicy
	for _, r := range rows {
		catalog := getFieldCI(r, "policy_catalog")
		schema := getFieldCI(r, "policy_schema")
		name := getFieldCI(r, "policy_name")
		if name == "" {
			continue
		}

		p := CatalogPolicy{
			Name: CatalogObjectName{
				Database: CatalogIdent{Name: catalog},
				Schema:   CatalogIdent{Name: schema},
				Name:     CatalogIdent{Name: name},
			},
			Kind: "MaskingPolicy",
		}

		if body := getFieldCI(r, "policy_body"); body != "" {
			p.Body = &body
		}
		if sig := getFieldCI(r, "policy_signature"); sig != "" {
			p.Signature = &sig
		}
		if ret := getFieldCI(r, "policy_return_type"); ret != "" {
			p.ReturnType = &ret
		}
		if cmt := getFieldCI(r, "policy_comment"); cmt != "" {
			p.Comment = &cmt
		}
		if created := getFieldCI(r, "created"); created != "" {
			p.CreatedAt = &created
		}
		if owner := getFieldCI(r, "policy_owner"); owner != "" {
			p.Owner = &owner
		}

		policies = append(policies, p)
	}

	return policies, nil
}

func pullRowAccessPolicies(ctx context.Context, db *sql.DB) ([]CatalogPolicy, error) {
	// SNOWFLAKE.ACCOUNT_USAGE.ROW_ACCESS_POLICIES contains policy definitions
	sql := `
		SELECT 
			POLICY_CATALOG,
			POLICY_SCHEMA,
			POLICY_NAME,
			POLICY_BODY,
			POLICY_SIGNATURE,
			POLICY_RETURN_TYPE,
			POLICY_COMMENT,
			CREATED,
			POLICY_OWNER
		FROM SNOWFLAKE.ACCOUNT_USAGE.ROW_ACCESS_POLICIES
		WHERE DELETED IS NULL
	`
	rows, err := queryRows(ctx, db, sql)
	if err != nil {
		return nil, err
	}

	var policies []CatalogPolicy
	for _, r := range rows {
		catalog := getFieldCI(r, "policy_catalog")
		schema := getFieldCI(r, "policy_schema")
		name := getFieldCI(r, "policy_name")
		if name == "" {
			continue
		}

		p := CatalogPolicy{
			Name: CatalogObjectName{
				Database: CatalogIdent{Name: catalog},
				Schema:   CatalogIdent{Name: schema},
				Name:     CatalogIdent{Name: name},
			},
			Kind: "RowAccessPolicy",
		}

		if body := getFieldCI(r, "policy_body"); body != "" {
			p.Body = &body
		}
		if sig := getFieldCI(r, "policy_signature"); sig != "" {
			p.Signature = &sig
		}
		if ret := getFieldCI(r, "policy_return_type"); ret != "" {
			p.ReturnType = &ret
		}
		if cmt := getFieldCI(r, "policy_comment"); cmt != "" {
			p.Comment = &cmt
		}
		if created := getFieldCI(r, "created"); created != "" {
			p.CreatedAt = &created
		}
		if owner := getFieldCI(r, "policy_owner"); owner != "" {
			p.Owner = &owner
		}

		policies = append(policies, p)
	}

	return policies, nil
}

func pullPolicyReferences(ctx context.Context, db *sql.DB) ([]CatalogPolicyReference, error) {
	// SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES shows which tables/columns have policies applied
	sql := `
		SELECT 
			POLICY_DB,
			POLICY_SCHEMA,
			POLICY_NAME,
			POLICY_KIND,
			REF_DATABASE_NAME,
			REF_SCHEMA_NAME,
			REF_ENTITY_NAME,
			REF_COLUMN_NAME,
			POLICY_STATUS
		FROM SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES
	`
	rows, err := queryRows(ctx, db, sql)
	if err != nil {
		return nil, err
	}

	var refs []CatalogPolicyReference
	for _, r := range rows {
		policyDB := getFieldCI(r, "policy_db")
		policySchema := getFieldCI(r, "policy_schema")
		policyName := getFieldCI(r, "policy_name")
		policyKind := getFieldCI(r, "policy_kind")
		refDB := getFieldCI(r, "ref_database_name")
		refSchema := getFieldCI(r, "ref_schema_name")
		refTable := getFieldCI(r, "ref_entity_name")
		refColumn := getFieldCI(r, "ref_column_name")
		status := getFieldCI(r, "policy_status")

		if policyName == "" || refTable == "" {
			continue
		}

		ref := CatalogPolicyReference{
			PolicyName: CatalogObjectName{
				Database: CatalogIdent{Name: policyDB},
				Schema:   CatalogIdent{Name: policySchema},
				Name:     CatalogIdent{Name: policyName},
			},
			PolicyKind: policyKind,
			RefTable: CatalogObjectName{
				Database: CatalogIdent{Name: refDB},
				Schema:   CatalogIdent{Name: refSchema},
				Name:     CatalogIdent{Name: refTable},
			},
		}

		if refColumn != "" {
			col := CatalogIdent{Name: refColumn}
			ref.RefColumn = &col
		}

		if status != "" {
			enabled := strings.EqualFold(status, "ACTIVE")
			ref.Enabled = &enabled
		}

		refs = append(refs, ref)
	}

	return refs, nil
}

// tagKey is used to index tags by object
type tagKey struct {
	database string
	schema   string
	table    string
	column   string // empty for table-level tags
}

// pullTagReferences queries SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES for tags on tables and columns.
// Only tags with names in tagNames are fetched (for performance and relevance).
// Returns two maps: table-level tags and column-level tags, keyed by qualified name.
func pullTagReferences(ctx context.Context, db *sql.DB, tagNames []string) (map[tagKey][]CatalogTag, map[tagKey][]CatalogTag, error) {
	if len(tagNames) == 0 {
		return nil, nil, nil
	}

	progressf("Pulling tag references from ACCOUNT_USAGE...")

	// Build IN clause for tag names (case-insensitive matching in Snowflake)
	var quotedNames []string
	for _, name := range tagNames {
		// Escape single quotes in tag names
		escaped := strings.ReplaceAll(name, "'", "''")
		quotedNames = append(quotedNames, fmt.Sprintf("'%s'", escaped))
	}
	inClause := strings.Join(quotedNames, ", ")

	query := fmt.Sprintf(`
		SELECT 
			TAG_DATABASE,
			TAG_SCHEMA,
			TAG_NAME,
			TAG_VALUE,
			OBJECT_DATABASE,
			OBJECT_SCHEMA,
			OBJECT_NAME,
			COLUMN_NAME,
			DOMAIN
		FROM SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES
		WHERE OBJECT_DELETED IS NULL
		  AND DOMAIN IN ('TABLE', 'COLUMN')
		  AND UPPER(TAG_NAME) IN (%s)
	`, strings.ToUpper(inClause))

	rows, err := queryRows(ctx, db, query)
	if err != nil {
		return nil, nil, err
	}

	tableTags := make(map[tagKey][]CatalogTag)
	columnTags := make(map[tagKey][]CatalogTag)

	for _, r := range rows {
		tagDB := getFieldCI(r, "tag_database")
		tagSchema := getFieldCI(r, "tag_schema")
		tagName := getFieldCI(r, "tag_name")
		tagValue := getFieldCI(r, "tag_value")
		objDB := getFieldCI(r, "object_database")
		objSchema := getFieldCI(r, "object_schema")
		objName := getFieldCI(r, "object_name")
		colName := getFieldCI(r, "column_name")
		domain := getFieldCI(r, "domain")

		if objName == "" {
			continue
		}

		tag := CatalogTag{
			TagDatabase: tagDB,
			TagSchema:   tagSchema,
			TagName:     tagName,
			TagValue:    tagValue,
		}

		if strings.EqualFold(domain, "TABLE") {
			key := tagKey{database: objDB, schema: objSchema, table: objName}
			tableTags[key] = append(tableTags[key], tag)
		} else if strings.EqualFold(domain, "COLUMN") && colName != "" {
			key := tagKey{database: objDB, schema: objSchema, table: objName, column: colName}
			columnTags[key] = append(columnTags[key], tag)
		}
	}

	progressf("  table tags: %d assignments, column tags: %d assignments", len(tableTags), len(columnTags))
	return tableTags, columnTags, nil
}

// applyTagsToSnapshot attaches tags to tables and columns in the snapshot.
// Returns the total number of tag assignments applied.
func applyTagsToSnapshot(snapshot *CatalogSnapshot, tableTags, columnTags map[tagKey][]CatalogTag) int {
	count := 0

	for i := range snapshot.Databases {
		db := &snapshot.Databases[i]
		dbName := db.Name.Name

		for j := range db.Schemas {
			schema := &db.Schemas[j]
			schemaName := schema.Name.Name

			for k := range schema.Tables {
				table := &schema.Tables[k]
				tableName := table.Name.Name

				// Apply table-level tags
				tkey := tagKey{database: dbName, schema: schemaName, table: tableName}
				if tags, ok := tableTags[tkey]; ok {
					table.Tags = tags
					count += len(tags)
				}

				// Apply column-level tags
				for l := range table.Columns {
					col := &table.Columns[l]
					colName := col.Name.Name

					ckey := tagKey{database: dbName, schema: schemaName, table: tableName, column: colName}
					if tags, ok := columnTags[ckey]; ok {
						col.Tags = tags
						count += len(tags)
					}
				}
			}
		}
	}

	return count
}

// pullGrantGraph pulls the grant graph from ACCOUNT_USAGE for effective access analysis.
// This includes role hierarchy, object privileges, and user-role assignments.
func pullGrantGraph(ctx context.Context, db *sql.DB, maxPrivileges int) (*CatalogGrants, error) {
	progressf("Pulling grant graph from ACCOUNT_USAGE...")

	grants := &CatalogGrants{}

	// 1. Role hierarchy: GRANT ROLE parent TO ROLE child
	roleHierarchySQL := `
		SELECT 
			NAME as parent_role,
			GRANTEE_NAME as child_role,
			GRANT_OPTION
		FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES
		WHERE GRANTED_ON = 'ROLE'
		  AND DELETED_ON IS NULL
		  AND GRANTED_TO = 'ROLE'
		ORDER BY parent_role, child_role
	`
	roleRows, err := queryRows(ctx, db, roleHierarchySQL)
	if err != nil {
		// Try alternative without ACCOUNT_USAGE (SHOW command)
		progressf("  warning: GRANTS_TO_ROLES query failed (may lack ACCOUNT_USAGE access): %v", err)
	} else {
		for _, r := range roleRows {
			parent := getFieldCI(r, "parent_role")
			child := getFieldCI(r, "child_role")
			grantOptStr := strings.ToUpper(strings.TrimSpace(getFieldCI(r, "grant_option")))
			grantOpt := grantOptStr == "TRUE" || grantOptStr == "YES"

			if parent == "" || child == "" {
				continue
			}

			grants.RoleHierarchy = append(grants.RoleHierarchy, CatalogRoleEdge{
				ParentRole:  parent,
				ChildRole:   child,
				GrantOption: grantOpt,
			})
		}
		progressf("  role hierarchy: %d edges", len(grants.RoleHierarchy))
	}

	// 2. Object privileges: role has privilege on object
	// Filter to security-relevant privileges and object types
	objPrivSQL := fmt.Sprintf(`
		SELECT DISTINCT
			GRANTEE_NAME as role,
			PRIVILEGE,
			GRANTED_ON as object_type,
			COALESCE(TABLE_CATALOG, '') as obj_database,
			COALESCE(TABLE_SCHEMA, '') as obj_schema,
			NAME as obj_name
		FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES
		WHERE GRANTED_ON IN ('TABLE', 'VIEW', 'MATERIALIZED VIEW', 'SCHEMA', 'DATABASE', 'WAREHOUSE', 'STAGE', 'STREAM', 'TASK', 'FUNCTION', 'PROCEDURE')
		  AND DELETED_ON IS NULL
		  AND PRIVILEGE IN ('SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'USAGE', 'OPERATE', 'MONITOR', 'OWNERSHIP', 'REFERENCES', 'READ', 'WRITE')
		  AND GRANTED_TO IN ('ROLE', 'DATABASE_ROLE')
		ORDER BY role, object_type, obj_database, obj_schema, obj_name
		LIMIT %d
	`, maxPrivileges)

	privRows, err := queryRows(ctx, db, objPrivSQL)
	if err != nil {
		progressf("  warning: object privileges query failed: %v", err)
	} else {
		for _, r := range privRows {
			role := getFieldCI(r, "role")
			priv := getFieldCI(r, "privilege")
			objType := getFieldCI(r, "object_type")
			objDB := getFieldCI(r, "obj_database")
			objSchema := getFieldCI(r, "obj_schema")
			objName := getFieldCI(r, "obj_name")

			if role == "" || priv == "" || objName == "" {
				continue
			}

			// Build FQN
			var fqn string
			if objDB != "" && objSchema != "" {
				fqn = fmt.Sprintf("%s.%s.%s", objDB, objSchema, objName)
			} else if objDB != "" {
				fqn = fmt.Sprintf("%s.%s", objDB, objName)
			} else {
				fqn = objName
			}

			grants.ObjectPrivileges = append(grants.ObjectPrivileges, CatalogObjectPrivilege{
				Role:       role,
				Privilege:  priv,
				ObjectType: objType,
				ObjectFQN:  fqn,
			})
		}
		progressf("  object privileges: %d grants", len(grants.ObjectPrivileges))
		if len(grants.ObjectPrivileges) >= maxPrivileges {
			progressf("  (reached max-grants limit of %d)", maxPrivileges)
		}
	}

	// 3. User-role assignments
	userRoleSQL := `
		SELECT 
			GRANTEE_NAME as user_name,
			ROLE as role_name
		FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS
		WHERE DELETED_ON IS NULL
		ORDER BY user_name, role_name
	`
	userRows, err := queryRows(ctx, db, userRoleSQL)
	if err != nil {
		progressf("  warning: user roles query failed: %v", err)
	} else {
		for _, r := range userRows {
			user := getFieldCI(r, "user_name")
			role := getFieldCI(r, "role_name")

			if user == "" || role == "" {
				continue
			}

			grants.UserRoles = append(grants.UserRoles, CatalogUserRole{
				User: user,
				Role: role,
			})
		}
		progressf("  user roles: %d assignments", len(grants.UserRoles))
	}

	// Return nil if we got nothing (all queries failed)
	if len(grants.RoleHierarchy) == 0 && len(grants.ObjectPrivileges) == 0 && len(grants.UserRoles) == 0 {
		return nil, fmt.Errorf("no grant data retrieved (may lack ACCOUNT_USAGE.GRANTS_* access)")
	}

	return grants, nil
}
