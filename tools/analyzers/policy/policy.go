// Package policy is the one place that says where each safe primitive lives and which trees are
// product code. The static safe-primitives checks (FF-SP1 to FF-SP3 of
// knowledge/development/architecture/safe-primitives.md §8) and the go/analysis passes in
// tools/analyzers all ask it, so a path moves in one file.
//
// Paths are repository-relative and slash-separated. A pattern is either a directory prefix
// ("internal/platform/proc" also covers its subpackages) or, when it starts with "**/", a path suffix
// that may sit anywhere ("**/export/csv"). The suffix form is for the output encoders (P7), whose root
// is still provisional in safe-primitives §12 (T-0004 fixes roots).
package policy

import (
	"path"
	"strings"
)

// Homes of the primitives (blueprint §1.1 and §7.4).
const (
	Connector   = "internal/connector"                   // the only importer of directory protocol libraries
	Scope       = "internal/connector/ad/scope"          // escape controls and the Global Catalog port
	Psx         = "internal/connector/psx"               // typed PowerShell sidecar client
	LDAPFilter  = "internal/directory/ldapfilter"        // P1
	DN          = "internal/directory/dn"                // P2
	OData       = "internal/directory/odata"             // P8
	GraphSchema = "internal/directory/odata/graphschema" // P8 property declarations
	Graph       = "internal/connector/graph"             // the Microsoft Graph connector
	ADConn      = "internal/connector/ad"                // AD connector: LDAPS dial to domain controllers (TB2, not TB9)
	FleetDial   = "internal/platform/fleet/dial"         // component to server dial, pinned to the installation CA (TB6, not TB9)
	Attr        = "internal/directory/attr"              // P3
	Secret      = "internal/platform/secret"             // Secret and secretjson
	Store       = "internal/platform/store"              // data-access package: pgx, set_config, reportsql
	Proc        = "internal/platform/proc"               // native process invocation
	Egress      = "internal/platform/egress"             // the one outbound HTTP client (TM-TB9-T1)
	Pslit       = "internal/platform/pslit"              // PowerShell display literal
	APIHost     = "internal/platform/apihost"            // the single caller of secretjson.Decode
	Modules     = "internal/modules"                     // server feature modules
	AgentMods   = "internal/agentmodules"                // agent feature modules

	// Output encoders (P7). Provisional roots: matched anywhere in the tree.
	Cellsafe  = "**/export/cellsafe"
	ExportCSV = "**/export/csv"
	ExportXLS = "**/export/xlsx"
	ExportPDF = "**/export/pdf"
	Htmlx     = "**/htmlx"
	Httpx     = "**/httpx"
	Msgtpl    = "**/msgtpl"
	Mail      = "**/notify/mail"
	TLSConfig = "**/tlsconfig"
)

// UnitHomes maps each FF-SP4 corpus unit to the home package patterns of its implementation. The
// corpus gate (tools/fitness/corpus) fails when Go code exists in a home but no implementation entry
// in testdata/safe-primitives/implementations.json declares the unit, so an implementation cannot
// exist without running the corpus. P6 (sd.read, sd.write) has no home here yet: its packages are
// named by the build tickets T-0118 and T-0135.
var UnitHomes = map[string][]string{
	"ldapfilter":      {LDAPFilter},
	"dn":              {DN},
	"odata":           {OData},
	"attr.guid":       {Attr},
	"attr.sid":        {Attr},
	"attr.filetime":   {Attr},
	"attr.gentime":    {Attr},
	"attr.flags":      {Attr},
	"attr.unicodepwd": {Secret, Attr + "/unicodepwd"}, // Secret and secretjson are part of the unit (safe-primitives §8: "incl. Secret, SecureConn"); the codec package joins them when built
	"psx":             {Psx},
	"pslit":           {Pslit},
	"proc":            {Proc},
	"sql":             {Store},
	"cellsafe":        {Cellsafe},
	"csv":             {ExportCSV},
	"xlsx":            {ExportXLS},
	"html":            {Htmlx},
	"mail":            {Mail},
	"pdf":             {ExportPDF},
}

// TokenURLSite names one function or method of the Graph connector that is exempt from one
// graph-url-assembly check (FF-SP2, safe-primitives-odata §6). Pkg is the exact package directory,
// Recv the receiver type name ("" for a plain function, which then never matches a method of the
// same name) and Func the function or method name.
type TokenURLSite struct{ Pkg, Recv, Func string }

// GraphTokenURL is the explicit list of token-endpoint sites that may use the URL and form
// encoders because the OAuth token endpoint is not OData. A new one is a reviewed change here.
var GraphTokenURL = []TokenURLSite{
	{Pkg: Graph, Recv: "Client", Func: "bearer"}, // client.go: the client-credentials POST, form body and tokenURL
}

// GraphURLParse is the explicit list of sites that may call url.Parse and friends in the Graph
// connector: the config parses in the constructor and the host-pinned @odata.nextLink parse.
var GraphURLParse = []TokenURLSite{
	{Pkg: Graph, Func: "New"},  // client.go: Authority and GraphBase from configuration
	{Pkg: Graph, Func: "list"}, // request.go: nextLink, checked against the pinned base in get
}

// GraphHTTPSite is the explicit list of sites that may create an outgoing HTTP request in the Graph
// connector: get (host-pinned, bearer-carrying reads) and bearer (the token endpoint). A request made
// anywhere else would skip the host pin.
var GraphHTTPSite = []TokenURLSite{
	{Pkg: Graph, Recv: "Client", Func: "get"},
	{Pkg: Graph, Recv: "Client", Func: "bearer"},
}

func siteListed(sites []TokenURLSite, rel, recv, fn string) bool {
	for _, s := range sites {
		if s.Pkg == path.Clean(rel) && s.Recv == recv && s.Func == fn {
			return true
		}
	}
	return false
}

// IsGraphTokenURL reports whether the function (recv "" ) or method is a listed token-endpoint site.
func IsGraphTokenURL(rel, recv, fn string) bool { return siteListed(GraphTokenURL, rel, recv, fn) }

// IsGraphHTTPSite reports whether the function or method may create an HTTP request in the Graph connector.
func IsGraphHTTPSite(rel, recv, fn string) bool { return siteListed(GraphHTTPSite, rel, recv, fn) }

// IsGraphURLParse reports whether the function or method may parse a URL in the Graph connector.
func IsGraphURLParse(rel, recv, fn string) bool { return siteListed(GraphURLParse, rel, recv, fn) }

// SidecarHost is where the .NET PowerShell SDK may be referenced.
const SidecarHost = "sidecars/pshost"

// Match reports whether the repository-relative directory rel is covered by pattern.
func Match(rel, pattern string) bool {
	rel = path.Clean(strings.TrimSuffix(rel, "/"))
	if suffix, ok := strings.CutPrefix(pattern, "**/"); ok {
		return rel == suffix || strings.HasSuffix(rel, "/"+suffix) ||
			strings.HasPrefix(rel, suffix+"/") || strings.Contains(rel, "/"+suffix+"/")
	}
	return rel == pattern || strings.HasPrefix(rel, pattern+"/")
}

// MatchAny reports whether rel is covered by any pattern.
func MatchAny(rel string, patterns []string) bool {
	for _, p := range patterns {
		if Match(rel, p) {
			return true
		}
	}
	return false
}

// IsToolTier reports tier L: lab and tools. It may build hostile input by hand (safe-primitives §2.1)
// and is never imported by product code.
func IsToolTier(rel string) bool {
	return Match(rel, "tools") || Match(rel, "lab")
}

// IsTest reports a Go test file by name.
func IsTest(file string) bool { return strings.HasSuffix(file, "_test.go") }

// TestSupport lists the packages that exist only to be imported by tests: they start the Docker
// PostgreSQL of the integration suites and run DDL by hand, which product code may not do. They are
// judged like test files, and product code may not import them (FF-SP1 test-support-import). Each is
// named, never matched by a "…test" suffix, so a new one is a reviewed change to this list.
var TestSupport = []string{
	"internal/platform/store/storetest",
	"internal/platform/jobs/jobstest", // fleet-wide claim lapse: a product import could double-run jobs
}

// SQLForwarder names one access wrapper whose Exec/Query/QueryRow pass their own SQL parameter to the
// same-named method of the type they hide (FF-SP2 sqlconst). Pkg is the exact package directory, Recv
// the receiver type name.
type SQLForwarder struct{ Pkg, Recv string }

// SQLForwarders is the explicit list of such wrappers. Each is named, so a new one is a reviewed change
// to this list; the callers of the interface the wrapper implements are still judged.
var SQLForwarders = []SQLForwarder{
	{Pkg: Store, Recv: "tx"}, // store.Tx over pgx.Tx
}

// IsSQLForwarder reports whether the receiver type recv declared in package directory rel is listed.
func IsSQLForwarder(rel, recv string) bool {
	for _, f := range SQLForwarders {
		if f.Pkg == path.Clean(rel) && f.Recv == recv {
			return true
		}
	}
	return false
}

// IsTestSupport reports whether the repository-relative directory rel is a test-support package.
func IsTestSupport(rel string) bool { return MatchAny(rel, TestSupport) }

// SQLCHeader is the first line of every sqlc-generated file.
const SQLCHeader = "// Code generated by sqlc. DO NOT EDIT."

// IsSQLCPackageDir reports a generated data-access package: the directory is named sqlcdb
// (blueprint §2). Every file in it must also carry SQLCHeader for the pgx exemption to apply.
func IsSQLCPackageDir(rel string) bool { return path.Base(rel) == "sqlcdb" }

// GeneratedByAPI is the header of the files tools/gen/api emits (ADR-0004).
const GeneratedByAPI = "// Code generated by tools/gen/api; DO NOT EDIT."

// DirOf returns the slash-separated directory of a repository-relative file.
func DirOf(rel string) string {
	d := path.Dir(rel)
	if d == "." {
		return "."
	}
	return d
}

// ModuleRel strips the module path from an import path, giving the repository-relative directory.
// An import path outside the module comes back unchanged with ok false. An empty module means the
// path is already relative (analysistest layouts).
func ModuleRel(importPath, module string) (string, bool) {
	if module == "" {
		return importPath, true
	}
	if importPath == module {
		return ".", true
	}
	if rest, ok := strings.CutPrefix(importPath, module+"/"); ok {
		return rest, true
	}
	return importPath, false
}
