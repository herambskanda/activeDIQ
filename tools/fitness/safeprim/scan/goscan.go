package scan

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"strconv"
	"strings"

	"github.com/skenzeriq/activediq/tools/analyzers/policy"
)

// goFile is one parsed Go file with what every check needs to know about it.
type goFile struct {
	rel       string // repository-relative, slash-separated
	dir       string
	fset      *token.FileSet
	file      *ast.File
	isTest    bool
	isTool    bool // tier L: lab/ and tools/
	sqlcGen   bool
	imports   map[string]string          // local name -> import path
	importSet []string                   // every import path
	consts    map[string]bool            // names declared const anywhere in the file
	strLits   map[string][]*ast.BasicLit // identifier -> string literals it is bound to (const, var, :=, =)
	module    string
	out       *[]Finding
}

func (g *goFile) add(ff, rule string, pos token.Pos, msg string) {
	*g.out = append(*g.out, Finding{FF: ff, Rule: rule, File: g.rel, Line: g.fset.Position(pos).Line, Msg: msg})
}

// scanGo runs FF-SP1, FF-SP2 (syntactic half) and FF-SP3 on one Go file. It deliberately ignores
// build constraints: a file that no target compiles today is still checked.
func scanGo(rel string, src []byte, module string, checks map[string]bool, out *[]Finding) error {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, rel, src, parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		return err
	}
	g := &goFile{rel: rel, dir: policy.DirOf(rel), fset: fset, file: f, isTest: policy.IsTest(rel) || policy.IsTestSupport(policy.DirOf(rel)), isTool: policy.IsToolTier(rel),
		imports: map[string]string{}, consts: map[string]bool{}, strLits: map[string][]*ast.BasicLit{}, module: module, out: out,
		sqlcGen: bytes.HasPrefix(bytes.TrimSpace(src), []byte(policy.SQLCHeader))}
	for _, is := range f.Imports {
		p, err := strconv.Unquote(is.Path.Value)
		if err != nil {
			continue
		}
		g.importSet = append(g.importSet, p)
		name := importName(p)
		if is.Name != nil {
			name = is.Name.Name
		}
		g.imports[name] = p
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.GenDecl:
			for _, sp := range v.Specs {
				vs, ok := sp.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, id := range vs.Names {
					if v.Tok == token.CONST {
						g.consts[id.Name] = true
					}
					if i < len(vs.Values) {
						g.bindLit(id.Name, vs.Values[i])
					}
				}
			}
		case *ast.AssignStmt:
			if (v.Tok == token.DEFINE || v.Tok == token.ASSIGN) && len(v.Lhs) == len(v.Rhs) {
				for i, l := range v.Lhs {
					if id, ok := l.(*ast.Ident); ok {
						g.bindLit(id.Name, v.Rhs[i])
					}
				}
			}
		}
		return true
	})
	if checks["FF-SP1"] {
		g.checkImports()
	}
	if checks["FF-SP2"] {
		g.checkImportBans()
		g.checkDotImports()
		g.checkLinkname()
		g.checkUnsafe()
		g.checkCgo()
		g.checkSymbols()
		g.checkTLS()
		g.checkJSONEscape()
		g.checkPredeclaredShadow()
		g.checkLiterals()
		g.checkFeaturePackages()
	}
	if checks["FF-SP3"] {
		g.checkShapes()
	}
	return nil
}

// importName is the identifier a package is referred to by when the import has no alias.
func importName(p string) string {
	parts := strings.Split(p, "/")
	last := parts[len(parts)-1]
	if len(parts) > 1 && regexp.MustCompile(`^v[0-9]+$`).MatchString(last) {
		last = parts[len(parts)-2]
	}
	if i := strings.LastIndex(last, ".v"); i > 0 {
		last = last[:i]
	}
	return strings.ReplaceAll(last, "-", "_")
}

func hasPrefixAny(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// ---- FF-SP1: import boundaries ----------------------------------------------------------------

func (g *goFile) importAllowed(r importRule) bool {
	if policy.MatchAny(g.dir, r.Home) {
		return true
	}
	if r.GeneratedHome && g.sqlcGen && policy.IsSQLCPackageDir(g.dir) {
		return true
	}
	if r.LabExempt && g.isLabBuild() {
		return true
	}
	return r.TestsExempt && g.isTest
}

// isLabBuild reports a policy.LabBuilds file that still carries a `//go:build lab` constraint.
func (g *goFile) isLabBuild() bool {
	if !contains(policy.LabBuilds, g.rel) {
		return false
	}
	for _, cg := range g.file.Comments {
		if cg.Pos() >= g.file.Package {
			break
		}
		for _, c := range cg.List {
			if strings.TrimSpace(c.Text) == "//go:build lab" {
				return true
			}
		}
	}
	return false
}

func (g *goFile) checkImports() {
	if g.isTool {
		return // tier L is exempt: it may use any library, and product code never imports it
	}
	for _, is := range g.file.Imports {
		p, err := strconv.Unquote(is.Path.Value)
		if err != nil {
			continue
		}
		for _, r := range importRules {
			if !(contains(r.Exact, p) || (hasPrefixAny(p, r.Prefixes) && !contains(r.Except, p))) {
				continue
			}
			if g.importAllowed(r) {
				continue
			}
			g.add("FF-SP1", r.Rule, is.Pos(), "imports "+p+": "+r.Msg)
		}
		if rel, ok := policy.ModuleRel(p, g.module); ok && g.module != "" && (policy.IsToolTier(rel)) {
			g.add("FF-SP1", "tier-l-import", is.Pos(), "product code imports "+p+": lab/ and tools/ are never imported by product packages (§2.1)")
		}
		if rel, ok := policy.ModuleRel(p, g.module); ok && g.module != "" && policy.IsTestSupport(rel) && !g.isTest {
			g.add("FF-SP1", "test-support-import", is.Pos(), "product code imports "+p+": test-support packages are imported only by tests")
		}
	}
}

// ---- FF-SP2: banned APIs ----------------------------------------------------------------------

func (g *goFile) checkImportBans() {
	for _, is := range g.file.Imports {
		p, err := strconv.Unquote(is.Path.Value)
		if err != nil {
			continue
		}
		for _, b := range importBans {
			if !contains(b.Paths, p) || (b.TestsExempt && g.isTest) || (b.ToolsExempt && g.isTool) {
				continue
			}
			g.add("FF-SP2", b.Rule, is.Pos(), "imports "+p+": "+b.Msg)
		}
	}
}

func (g *goFile) importsAny(prefixes []string) bool {
	if len(prefixes) == 0 {
		return true
	}
	for _, p := range g.importSet {
		if hasPrefixAny(p, prefixes) {
			return true
		}
	}
	return false
}

func (g *goFile) symbolApplies(r symbolRule) bool {
	if g.isTool || (r.TestsExempt && g.isTest) {
		return false
	}
	if len(r.OnlyIn) > 0 && !policy.MatchAny(g.dir, r.OnlyIn) {
		return false
	}
	return !policy.MatchAny(g.dir, r.Home)
}

func (g *goFile) checkSymbols() {
	seen := map[string]bool{}
	report := func(r symbolRule, pos token.Pos, what string) {
		line := g.fset.Position(pos).Line
		k := r.Rule + ":" + strconv.Itoa(line) + ":" + what
		if seen[k] {
			return
		}
		seen[k] = true
		g.add("FF-SP2", r.Rule, pos, what+": "+r.Msg)
	}
	ast.Inspect(g.file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		var pkgPath string
		if id, ok := sel.X.(*ast.Ident); ok {
			pkgPath = g.imports[id.Name]
		}
		for _, r := range symbolRules {
			if !g.symbolApplies(r) {
				continue
			}
			if pkgPath != "" && (r.Pkg != "" || r.PkgPrefix != "") {
				if (r.Pkg != "" && pkgPath == r.Pkg) || (r.PkgPrefix != "" && strings.HasPrefix(pkgPath, r.PkgPrefix)) {
					if len(r.Names) == 0 || contains(r.Names, sel.Sel.Name) {
						report(r, sel.Pos(), importName(pkgPath)+"."+sel.Sel.Name)
					}
				}
			}
			if len(r.MethodNames) > 0 && contains(r.MethodNames, sel.Sel.Name) && g.importsAny(r.RequireImport) {
				report(r, sel.Pos(), "."+sel.Sel.Name)
			}
		}
		return true
	})
}

// checkJSONEscape bans jsontext.EscapeForHTML / EscapeForJS in any form but a direct call with the
// literal true: API responses keep their HTML and JS escaping (§12.5 rule 7). A non-constant
// argument is banned because it can be false at run time; a method value (f := jsontext.EscapeForJS)
// is banned because the argument can no longer be seen.
func (g *goFile) checkJSONEscape() {
	if g.isTool || g.isTest {
		return
	}
	isEscape := func(e ast.Expr) (*ast.SelectorExpr, bool) {
		sel, ok := e.(*ast.SelectorExpr)
		if !ok || (sel.Sel.Name != "EscapeForHTML" && sel.Sel.Name != "EscapeForJS") {
			return nil, false
		}
		id, ok := sel.X.(*ast.Ident)
		return sel, ok && g.imports[id.Name] == "encoding/json/jsontext"
	}
	allowed := map[*ast.SelectorExpr]bool{}
	ast.Inspect(g.file, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := isEscape(call.Fun); ok && len(call.Args) == 1 {
				if id, ok := call.Args[0].(*ast.Ident); ok && id.Name == "true" {
					allowed[sel] = true
				}
			}
		}
		return true
	})
	ast.Inspect(g.file, func(n ast.Node) bool {
		e, ok := n.(ast.Expr)
		if !ok {
			return true
		}
		if sel, ok := isEscape(e); ok && !allowed[sel] {
			g.add("FF-SP2", "json-escape-off", sel.Pos(), "jsontext."+sel.Sel.Name+" must be called directly with the literal true in product code: JSON responses keep their HTML and JS escaping ("+refP7+".5 rule 7)")
		}
		return true
	})
}

// checkPredeclaredShadow bans declaring true or false in product code. The scan reads the literal
// true as the predeclared identifier (no type information, and a package-level const in a sibling
// file defeats any per-file check), so `true := false` or `const true = false` would turn
// EscapeForHTML(true) into EscapeForHTML(false) unseen.
func (g *goFile) checkPredeclaredShadow() {
	if g.isTool || g.isTest {
		return
	}
	bad := func(id *ast.Ident) {
		if id != nil && (id.Name == "true" || id.Name == "false") {
			g.add("FF-SP2", "predeclared-shadow", id.Pos(), "declares "+id.Name+" in product code: shadowing a predeclared boolean defeats the literal-true checks ("+refP7+".5)")
		}
	}
	fields := func(fl *ast.FieldList) {
		if fl == nil {
			return
		}
		for _, f := range fl.List {
			for _, id := range f.Names {
				bad(id)
			}
		}
	}
	for _, is := range g.file.Imports {
		bad(is.Name)
	}
	ast.Inspect(g.file, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.AssignStmt:
			if v.Tok == token.DEFINE {
				for _, l := range v.Lhs {
					if id, ok := l.(*ast.Ident); ok {
						bad(id)
					}
				}
			}
		case *ast.RangeStmt:
			if v.Tok == token.DEFINE {
				for _, e := range []ast.Expr{v.Key, v.Value} {
					if id, ok := e.(*ast.Ident); ok {
						bad(id)
					}
				}
			}
		case *ast.ValueSpec:
			for _, id := range v.Names {
				bad(id)
			}
		case *ast.TypeSpec:
			bad(v.Name)
			fields(v.TypeParams)
		case *ast.FuncDecl:
			bad(v.Name)
			fields(v.Recv)
		case *ast.FuncType:
			fields(v.TypeParams)
			fields(v.Params)
			fields(v.Results)
		}
		return true
	})
}

// checkDotImports bans `import . "pkg"` in product code: it hides every pkg.Sym selector from the
// symbol bans. Tests and tier L are exempt.
func (g *goFile) checkDotImports() {
	if g.isTool || g.isTest {
		return
	}
	for _, is := range g.file.Imports {
		if is.Name != nil && is.Name.Name == "." {
			g.add("FF-SP2", "dot-import", is.Pos(), "dot import of "+is.Path.Value+" in product code: it hides pkg.Symbol uses from the safe-primitive bans; import the package by name ("+refP7+".5)")
		}
	}
}

// checkLinkname bans //go:linkname in product code: a directive binds any symbol by string name,
// so it evades every pkg.Sym ban on third-party packages (go-ldap, pgx) with no selector and no
// import of the package (T-0186). Tests and tier L are exempt: neither ships in the product.
func (g *goFile) checkLinkname() {
	if g.isTool || g.isTest {
		return
	}
	for _, cg := range g.file.Comments {
		for _, c := range cg.List {
			if strings.HasPrefix(c.Text, "//go:linkname") {
				g.add("FF-SP2", "linkname", c.Pos(), "//go:linkname binds symbols by name and evades the symbol bans; it is banned in product code (T-0186)")
			}
		}
	}
}

// checkCgo bans import "C" in product code: cgo steps outside Go's memory safety and compiles
// foreign code the scan cannot see (T-0215). Tests and tier L are exempt: neither ships.
func (g *goFile) checkCgo() {
	if g.isTool || g.isTest {
		return
	}
	for _, is := range g.file.Imports {
		if path, err := strconv.Unquote(is.Path.Value); err == nil && path == "C" {
			g.add("FF-SP2", "asm-cgo", is.Pos(), `import "C" (cgo) is banned in product code: it escapes memory safety and builds unscanned foreign code (T-0215)`)
		}
	}
}

// unsafeHomes may import "unsafe", and only in files carrying the generated-code header.
var unsafeHomes = []string{"internal/proto"}

// unsafeWindowsHomes may import "unsafe" in their *_windows.go files: the Windows host and its
// installer call Win32 (wevtapi, token, job object, security descriptors) through x/sys/windows
// LazyProc.Call, which takes uintptr(unsafe.Pointer(...)). The agent-host fitness rulings put that
// reach in the host, never in a module (knowledge/development/decisions/agent-host-fitness-rulings.md,
// Ruling 1; fitness-agent-host R3 keeps unsafe out of addc and the other modules). T-0800.
//
// internal/platform/ownerfile and internal/platform/fleet/dial (T-0883) write and re-check owner-only
// state files with a PROTECTED DACL. Their *_windows.go files need unsafe for two things x/sys/windows
// offers no helper for: unsafe.Sizeof(SecurityAttributes) for the Length field, and reading the SID
// that trails an ACCESS_ALLOWED_ACE ((*windows.SID)(unsafe.Pointer(&ace.SidStart))). Same ruling as the
// agent host: Win32 security-descriptor reach, Windows files only. Every other directory, and every
// non-windows file in these two, stays banned.
var unsafeWindowsHomes = []string{"internal/platform/agent", "cmd/agentsetup", "internal/platform/ownerfile", "internal/platform/fleet/dial"}

// checkUnsafe bans importing "unsafe" in product code outside generated protobuf packages: linkname
// needs it, and so does every memory-safety escape. Tests and tier L are exempt.
func (g *goFile) checkUnsafe() {
	if g.isTool || g.isTest {
		return
	}
	generated := false
	for _, cg := range g.file.Comments {
		if cg.Pos() >= g.file.Package {
			break
		}
		for _, c := range cg.List {
			if strings.HasPrefix(c.Text, "// Code generated ") && strings.HasSuffix(c.Text, " DO NOT EDIT.") {
				generated = true
			}
		}
	}
	if generated && policy.MatchAny(g.dir, unsafeHomes) {
		return
	}
	if strings.HasSuffix(g.rel, "_windows.go") && policy.MatchAny(g.dir, unsafeWindowsHomes) {
		return
	}
	for _, is := range g.file.Imports {
		if path, err := strconv.Unquote(is.Path.Value); err == nil && path == "unsafe" {
			g.add("FF-SP2", "unsafe-import", is.Pos(), "importing unsafe is banned in product code outside generated protobuf packages (T-0186)")
		}
	}
}

// checkTLS bans verification bypasses everywhere: tests and tier L included (§2.1, §5.6).
func (g *goFile) checkTLS() {
	inTLSHome := policy.Match(g.dir, policy.TLSConfig)
	isFalse := func(e ast.Expr) bool {
		id, ok := e.(*ast.Ident)
		return ok && id.Name == "false"
	}
	ast.Inspect(g.file, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.KeyValueExpr:
			if k, ok := v.Key.(*ast.Ident); ok {
				g.tlsField(k.Name, v.Value, v.Pos(), inTLSHome, isFalse)
			}
		case *ast.AssignStmt:
			for i, l := range v.Lhs {
				if sel, ok := l.(*ast.SelectorExpr); ok && i < len(v.Rhs) {
					g.tlsField(sel.Sel.Name, v.Rhs[i], v.Pos(), inTLSHome, isFalse)
				}
			}
		}
		return true
	})
}

func (g *goFile) tlsField(name string, val ast.Expr, pos token.Pos, inTLSHome bool, isFalse func(ast.Expr) bool) {
	switch name {
	case "InsecureSkipVerify":
		if !isFalse(val) {
			g.add("FF-SP2", "tls-skip-verify", pos, "InsecureSkipVerify other than literal false disables certificate verification ("+refTLS+")")
		}
	case "VerifyPeerCertificate", "VerifyConnection":
		if !inTLSHome {
			g.add("FF-SP2", "tls-verify-callback", pos, name+" is set outside the TLS-config package: a callback can accept any certificate ("+refTLS+")")
		}
	}
}

func (g *goFile) literalApplies(r literalRule) bool {
	if !r.Everywhere {
		if g.isTool || (r.TestsExempt && g.isTest) {
			return false
		}
	}
	return !policy.MatchAny(g.dir, r.Home)
}

func (g *goFile) checkLiterals() {
	inImport := map[*ast.BasicLit]bool{}
	for _, is := range g.file.Imports {
		inImport[is.Path] = true
	}
	seen := map[string]bool{}
	ast.Inspect(g.file, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || inImport[lit] {
			return true
		}
		var val string
		isInt := lit.Kind == token.INT
		switch lit.Kind {
		case token.STRING:
			v, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			val = v
		case token.INT:
			val = lit.Value
		default:
			return true
		}
		for _, r := range literalRules {
			if !g.literalApplies(r) {
				continue
			}
			hit := false
			switch {
			case isInt:
				hit = contains(r.Ints, val)
			default:
				for _, e := range r.Equal {
					if strings.EqualFold(strings.TrimSpace(val), e) {
						hit = true
					}
				}
				if !hit && r.Re != nil && r.Re.MatchString(val) {
					hit = true
				}
			}
			if !hit {
				continue
			}
			k := r.Rule + ":" + strconv.Itoa(g.fset.Position(lit.Pos()).Line)
			if seen[k] {
				continue
			}
			seen[k] = true
			g.add("FF-SP2", r.Rule, lit.Pos(), "literal "+shorten(lit.Value)+": "+r.Msg)
		}
		return true
	})
}

// checkFeaturePackages bans UAC and groupType bit names in feature packages: flag decoding is attr's job (§5).
func (g *goFile) checkFeaturePackages() {
	if g.isTest || g.isTool || !policy.MatchAny(g.dir, featurePackages) {
		return
	}
	seen := map[string]bool{}
	ast.Inspect(g.file, func(n ast.Node) bool {
		id, ok := n.(*ast.Ident)
		if !ok || !reFlagConst.MatchString(id.Name) {
			return true
		}
		k := id.Name + ":" + strconv.Itoa(g.fset.Position(id.Pos()).Line)
		if !seen[k] {
			seen[k] = true
			g.add("FF-SP2", "flag-bit-constant", id.Pos(), id.Name+": UAC and groupType bit constants are banned in feature packages; use the attr flag codecs ("+refP3+")")
		}
		return true
	})
}

func shorten(s string) string {
	s = strings.ReplaceAll(s, "\n", `\n`)
	if len(s) > 48 {
		return s[:45] + `…"`
	}
	return s
}

// ---- FF-SP3: literal-shape scanner ------------------------------------------------------------

type shape struct {
	Rule   string
	Re     *regexp.Regexp
	Home   []string
	Always bool // flag the literal on its own, not only when combined with data
	Msg    string
}

var (
	reFilterShape = regexp.MustCompile(`\(\s*[&|!]\s*\(|\(\s*(?i:objectClass|objectCategory|sAMAccountName|userPrincipalName|cn|mail|memberOf|distinguishedName|member|objectSid|objectGUID|displayName|givenName|sn|userAccountControl|uid|name)\s*[=~<>:]|:1\.2\.840\.113556\.1\.4\.\d+:=`)
	reDNShape     = regexp.MustCompile(`(?i)(?:^|[,\s])(?:CN|OU|DC)=`)
	rePSShape     = regexp.MustCompile(`(?i)\b(?:Get|Set|New|Remove|Add|Disable|Enable|Unlock|Reset|Move|Rename|Invoke|Start|Stop|Import|Export|Search|Clear|Grant|Revoke|Test)-(?:AD|Mailbox|Recipient|DistributionGroup|Gpo|GP[A-Z]|Acl|Item|Content|Process|Service|Command|Expression|Object|Variable|Module|ExecutionPolicy|LocalUser|LocalGroup|Computer|Date|Aduser|Adgroup)\w*|\s-(?:Identity|LDAPFilter|SearchBase|ArgumentList|ScriptBlock|EncodedCommand)\b`)
	rePSReplace   = regexp.MustCompile(`(?i)-i?c?replace\s+["']`)
	reSQLShape    = regexp.MustCompile(`(?is)\b(?:select\b.+\bfrom|insert\s+into|update\s+[\w."]+\s+set|delete\s+from|alter\s+(?:table|role|user)|drop\s+(?:table|role|user)|create\s+(?:table|role|user|function)|truncate\s+table)\b|\bwhere\s+[\w."()]+\s*(?:=|<|>|like|ilike|in|is)\b|\border\s+by\s+[\w."]|\bset_config\s*\(`)
	reHTMLShape   = regexp.MustCompile(`(?i)<\s*(?:td|th|tr|table|a\s|script|div|span|img|ul|li|style|iframe|svg|body|html|p>|b>)`)
	// OData (safe-primitives-odata §6). An option name with $ or %24 (any case) at the start of a
	// literal or of a query segment, or the bare name followed by "=".
	reODataOption = regexp.MustCompile(`(?i)(?:^|[?&\s])(?:\$|%24)(?:filter|search|orderby|select|expand|apply|compute|skiptoken|top|count|skip|deltatoken|format)\b|(?:^|[?&])(?:filter|search|orderby|select|expand|apply|compute|skiptoken|top|count|skip|deltatoken|format)=`)
	reODataFilter = regexp.MustCompile(`(?i)\b(?:eq|ne|gt|ge|lt|le|has)\s+'|\bin\s*\(\s*'|\b(?:startswith|endswith|contains|any|all)\s*\(|'\s*\)?\s+(?:and|or)(?:\s*$|\s+\(?\s*[A-Za-z_][\w./]*\s+(?:eq|ne|gt|ge|lt|le|has|in)\b)`)
	// An opening set(, set(' or set(prop=' piece, or a printf verb inside the key parentheses. The
	// closing piece of a key is not matched on its own: "')" ends startswith(…) pieces too (FX-6), and
	// every key built from text has an opening piece that is.
	reODataKey  = regexp.MustCompile(`[A-Za-z_]\w*\(\s*(?:[A-Za-z_]\w*\s*=\s*)?'?\s*$|[A-Za-z_]\w*\(\s*(?:[A-Za-z_]\w*\s*=\s*)?'?%[-+# 0-9.]*[a-zA-Z]`)
	reMailShape = regexp.MustCompile(`(?i)(?:^|\r\n|\n)\s*(?:subject|bcc|cc|to|from|reply-to|content-type|mime-version|content-transfer-encoding):|\r\n`)
)

var reODataBareName = regexp.MustCompile(`(?i)^\s*(?:filter|search|orderby|select|expand|apply|compute|skiptoken|top|count|skip|deltatoken|format)\s*$`)

var shapes = []shape{
	{Rule: "ldap-filter-shape", Re: reFilterShape, Home: []string{policy.LDAPFilter},
		Msg: "an LDAP filter built from text; build an ldapfilter AST (" + refP1 + ")"},
	{Rule: "dn-shape", Re: reDNShape, Home: []string{policy.DN},
		Msg: "a distinguished name built from text; use dn builders and ObjectRef (" + refP2 + ")"},
	{Rule: "powershell-shape", Re: rePSShape, Home: []string{policy.Pslit, policy.Psx, policy.Proc},
		Msg: "PowerShell text built from data; use psx typed operations, or pslit for display (" + refP4 + ")"},
	{Rule: "powershell-quote-escaper", Re: rePSReplace, Home: []string{policy.Pslit}, Always: true,
		Msg: "a PowerShell -replace quote escaper is the PatchIQ escapePSPath shape; use pslit (" + refPS + ")"},
	{Rule: "sql-shape", Re: reSQLShape, Home: []string{policy.Store},
		Msg: "SQL text built from data; use sqlc queries and bind parameters (" + refP5 + ")"},
	{Rule: "html-shape", Re: reHTMLShape, Home: []string{policy.Htmlx},
		Msg: "HTML built from text; use html/template through htmlx (" + refP7 + ".5)"},
	{Rule: "odata-option-literal", Re: reODataOption, Home: []string{policy.OData}, Always: true,
		Msg: "a system query option name outside the odata primitive; build the request with odata.Query (safe-primitives-odata §6)"},
	{Rule: "odata-filter-shape", Re: reODataFilter, Home: []string{policy.OData},
		Msg: "an OData filter built from text; build an odata filter AST (safe-primitives-odata §6)"},
	{Rule: "odata-key-shape", Re: reODataKey, Home: []string{policy.OData},
		Msg: "an OData key segment built from text; use odata.Key, KeyStr or AltKey (safe-primitives-odata §6)"},
	{Rule: "mail-header-shape", Re: reMailShape, Home: []string{policy.Mail},
		Msg: "mail headers or CRLF built from text; use notify/mail (" + refP7 + ".6)"},
}

// combine says how a literal is joined with data.
type combine string

const (
	byConcat  combine = "concatenation"
	byFormat  combine = "formatting"
	byBuilder combine = "a string builder"
)

// formatFuncs are the fmt functions that format or join their arguments, with the index of the
// format string (-1 when there is none: every literal argument is then a piece being joined).
var formatFuncs = map[string]int{
	"Sprintf": 0, "Fprintf": 1, "Appendf": 1, "Errorf": 0, "Printf": 0,
	"Sprint": -1, "Sprintln": -1, "Fprint": -1, "Fprintln": -1, "Print": -1, "Println": -1, "Append": -1, "Appendln": -1,
}

// joinFuncs are the strings and bytes functions that assemble text out of pieces.
var joinFuncs = map[string]bool{"Join": true, "Replace": true, "ReplaceAll": true, "NewReplacer": true, "Repeat": true}

// rePrintfVerb matches a printf verb once literal percent signs are removed.
var rePrintfVerb = regexp.MustCompile(`%[#+\- 0-9.*\[\]]*[vTtbcdoOqxXUeEfFgGsp]`)

func hasPrintfVerb(v string) bool {
	return rePrintfVerb.MatchString(strings.ReplaceAll(v, "%%", ""))
}

// bindLit remembers that name is bound to a string literal (possibly joined from several by +),
// so a literal reached through a const or variable is judged where that name is combined with data.
func (g *goFile) bindLit(name string, e ast.Expr) {
	switch v := e.(type) {
	case *ast.BasicLit:
		if v.Kind == token.STRING {
			g.strLits[name] = append(g.strLits[name], v)
		}
	case *ast.ParenExpr:
		g.bindLit(name, v.X)
	case *ast.BinaryExpr:
		if v.Op == token.ADD {
			g.bindLit(name, v.X)
			g.bindLit(name, v.Y)
		}
	}
}

// markCombined records every string literal that e is, or names, as combined by how.
func (g *goFile) markCombined(e ast.Expr, how combine, combined map[*ast.BasicLit]combine) {
	switch v := e.(type) {
	case *ast.BasicLit:
		if v.Kind == token.STRING {
			combined[v] = how
		}
	case *ast.ParenExpr:
		g.markCombined(v.X, how, combined)
	case *ast.Ident:
		for _, l := range g.strLits[v.Name] {
			combined[l] = how
		}
	case *ast.CallExpr: // []byte("…") and string(…) conversions
		if len(v.Args) == 1 {
			if _, isConv := v.Fun.(*ast.ArrayType); isConv {
				g.markCombined(v.Args[0], how, combined)
			} else if id, ok := v.Fun.(*ast.Ident); ok && id.Name == "string" {
				g.markCombined(v.Args[0], how, combined)
			}
		}
	case *ast.CompositeLit: // []string{"(&(cn=", x, "))"}
		if !g.anyDynamic(v.Elts) {
			return
		}
		for _, el := range v.Elts {
			g.markCombined(el, how, combined)
		}
	case *ast.BinaryExpr:
		if v.Op == token.ADD {
			g.markCombined(v.X, how, combined)
			g.markCombined(v.Y, how, combined)
		}
	}
}

// anyDynamicArg is anyDynamic for call arguments, where a slice literal is judged by its elements.
func (g *goFile) anyDynamicArg(args []ast.Expr) bool {
	for _, a := range args {
		if cl, ok := a.(*ast.CompositeLit); ok {
			if g.anyDynamic(cl.Elts) {
				return true
			}
			continue
		}
		if !g.isStaticOperand(a) {
			return true
		}
	}
	return false
}

func (g *goFile) anyDynamic(es []ast.Expr) bool {
	for _, e := range es {
		if !g.isStaticOperand(e) {
			return true
		}
	}
	return false
}

func (g *goFile) isStaticOperand(e ast.Expr) bool {
	switch v := e.(type) {
	case *ast.BasicLit:
		return true
	case *ast.ParenExpr:
		return g.isStaticOperand(v.X)
	case *ast.Ident:
		return g.consts[v.Name] || v.Name == "true" || v.Name == "false"
	case *ast.BinaryExpr:
		return g.isStaticOperand(v.X) && g.isStaticOperand(v.Y)
	}
	return false
}

func flattenAdd(e ast.Expr, out *[]ast.Expr, nested map[*ast.BinaryExpr]bool) {
	switch v := e.(type) {
	case *ast.ParenExpr:
		flattenAdd(v.X, out, nested)
	case *ast.BinaryExpr:
		if v.Op == token.ADD {
			nested[v] = true
			flattenAdd(v.X, out, nested)
			flattenAdd(v.Y, out, nested)
			return
		}
		*out = append(*out, e)
	default:
		*out = append(*out, e)
	}
}

func (g *goFile) shapeApplies(s shape) bool {
	return !g.isTool && !g.isTest && !policy.MatchAny(g.dir, s.Home) && !(g.sqlcGen)
}

func (g *goFile) checkShapes() {
	if g.isTool || g.isTest {
		return
	}
	combined := map[*ast.BasicLit]combine{}
	nested := map[*ast.BinaryExpr]bool{}
	ast.Inspect(g.file, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.BinaryExpr:
			if v.Op != token.ADD || nested[v] {
				return true
			}
			var ops []ast.Expr
			flattenAdd(v, &ops, nested)
			nested[v] = true
			dynamic := false
			for _, o := range ops {
				if !g.isStaticOperand(o) {
					dynamic = true
				}
			}
			if dynamic {
				for _, o := range ops {
					g.markCombined(o, byConcat, combined)
				}
			}
		case *ast.AssignStmt:
			// s += x, and s += "(cn=": appending is building, whatever the left side holds.
			if v.Tok == token.ADD_ASSIGN && len(v.Rhs) == 1 {
				g.markCombined(v.Rhs[0], byConcat, combined)
				if id, ok := v.Lhs[0].(*ast.Ident); ok {
					for _, l := range g.strLits[id.Name] {
						combined[l] = byConcat
					}
				}
			}
		case *ast.CallExpr:
			g.callShapes(v, combined)
		}
		return true
	})
	seen := map[string]bool{}
	ast.Inspect(g.file, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		val, err := strconv.Unquote(lit.Value)
		if err != nil {
			return true
		}
		how, isCombined := combined[lit]
		for _, s := range shapes {
			verb := hasPrintfVerb(val)
			if !g.shapeApplies(s) || !s.Re.MatchString(val) || !(isCombined || s.Always || verb) {
				continue
			}
			k := s.Rule + ":" + strconv.Itoa(g.fset.Position(lit.Pos()).Line)
			if seen[k] {
				continue
			}
			seen[k] = true
			msg := "literal " + shorten(lit.Value) + " combined by " + string(how) + ": " + s.Msg
			if !isCombined && verb && !s.Always {
				msg = "literal " + shorten(lit.Value) + " is a format template for text of this shape: " + s.Msg
			} else if s.Always && !isCombined {
				msg = "literal " + shorten(lit.Value) + ": " + s.Msg
			}
			g.add("FF-SP3", s.Rule, lit.Pos(), msg)
		}
		return true
	})
}

var quoteChars = map[string]bool{"'": true, "‘": true, "’": true, "‚": true, "‛": true}

var formulaLeadLits = map[string]bool{"=": true, "+": true, "-": true, "@": true, "\t": true, "\r": true, "=+-@": true, "+-=@": true, "=+-@\t\r": true, "\t\r=+-@": true, "=-+@": true}

func (g *goFile) strLit(e ast.Expr) (string, bool) {
	l, ok := e.(*ast.BasicLit)
	if !ok || l.Kind != token.STRING {
		return "", false
	}
	v, err := strconv.Unquote(l.Value)
	return v, err == nil
}

// callShapes records literals that a call combines with data and checks the call-level shapes.
func (g *goFile) callShapes(call *ast.CallExpr, combined map[*ast.BasicLit]combine) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return
	}
	pkg := ""
	if id, ok := sel.X.(*ast.Ident); ok {
		pkg = g.imports[id.Name]
	}
	name := sel.Sel.Name
	if pkg == "fmt" {
		if idx, ok := formatFuncs[name]; ok {
			dynamic := false
			for i, a := range call.Args {
				if i != idx && !g.isStaticOperand(a) {
					dynamic = true
				}
			}
			switch {
			case idx >= 0 && idx < len(call.Args) && len(call.Args) > idx+1:
				g.markCombined(call.Args[idx], byFormat, combined)
			case idx < 0 && dynamic:
				for _, a := range call.Args {
					g.markCombined(a, byFormat, combined)
				}
			}
		}
	}
	if (pkg == "strings" || pkg == "bytes") && joinFuncs[name] && g.anyDynamicArg(call.Args) {
		for _, a := range call.Args {
			g.markCombined(a, byFormat, combined)
		}
	}
	if pkg == "" && name == "Replace" && len(call.Args) == 1 { // strings.NewReplacer(…).Replace(template)
		g.markCombined(call.Args[0], byFormat, combined)
	}
	if (name == "WriteString" || name == "Write") && len(call.Args) == 1 {
		g.markCombined(call.Args[0], byBuilder, combined)
	}
	// url.Values.Set/Add with a bare option name as the key: q.Add("filter", x).
	if (name == "Set" || name == "Add") && len(call.Args) == 2 && !g.isTool && !g.isTest && !policy.Match(g.dir, policy.OData) {
		if v, ok := g.strLit(call.Args[0]); ok && reODataBareName.MatchString(v) {
			g.add("FF-SP3", "odata-option-literal", call.Pos(), "query key "+shorten(strconv.Quote(v))+" is a system query option name outside the odata primitive; build the request with odata.Query (safe-primitives-odata §6)")
		}
	}
	// Quote doubling: two adjacent string arguments, the second a doubling of the first.
	for i := 0; i+1 < len(call.Args); i++ {
		a, ok1 := g.strLit(call.Args[i])
		b, ok2 := g.strLit(call.Args[i+1])
		if ok1 && ok2 && b == a+a && (quoteChars[a] || a == `"`) {
			home := []string{policy.Pslit, policy.Store, policy.ExportCSV, policy.OData}
			if !policy.MatchAny(g.dir, home) {
				g.add("FF-SP3", "quote-doubling", call.Pos(), "quote doubling ("+shorten(strconv.Quote(a))+" to "+shorten(strconv.Quote(b))+") is the PatchIQ escapePSPath shape; use pslit, store, export/csv or odata ("+refPS+")")
			}
		}
	}
	// Formula-lead checks outside cellsafe (§12.2).
	if pkg == "strings" && (name == "HasPrefix" || name == "TrimLeft" || name == "TrimPrefix" || name == "ContainsAny" || name == "IndexAny") &&
		(inTree(g.dir, "export") || inTree(g.dir, "reports")) && !policy.Match(g.dir, policy.Cellsafe) {
		for _, a := range call.Args {
			if v, ok := g.strLit(a); ok && formulaLeadLits[v] {
				g.add("FF-SP3", "formula-lead-check", call.Pos(), "a hand-written formula-lead check; only cellsafe decides ("+refP7+".2)")
			}
		}
	}
	// strings.Join(…, ",") written to a writer: a hand-made CSV row (§12.3).
	if name == "Write" || name == "WriteString" || name == "Fprintln" || name == "Fprint" || name == "Fprintf" {
		if !policy.MatchAny(g.dir, []string{policy.ExportCSV, policy.Httpx}) {
			for _, a := range call.Args {
				if joinWithComma(g, a) {
					g.add("FF-SP3", "csv-row-join", call.Pos(), "a CSV row joined with a comma or semicolon and written out; use export/csv ("+refP7+".3)")
				}
			}
		}
	}
}

func inTree(dir, seg string) bool {
	return dir == seg || strings.HasPrefix(dir, seg+"/") || strings.HasSuffix(dir, "/"+seg) || strings.Contains(dir, "/"+seg+"/")
}

func joinWithComma(g *goFile, e ast.Expr) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if s, ok := c.Fun.(*ast.SelectorExpr); ok && s.Sel.Name == "Join" && len(c.Args) == 2 {
			if id, ok := s.X.(*ast.Ident); ok && g.imports[id.Name] == "strings" {
				if v, ok := g.strLit(c.Args[1]); ok && (v == "," || v == ";") {
					found = true
				}
			}
		}
		return true
	})
	return found
}
