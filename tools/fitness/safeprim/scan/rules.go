package scan

import (
	"regexp"

	"github.com/skenzeriq/activediq/tools/analyzers/policy"
)

// Section references used in messages. All are in knowledge/development/architecture/safe-primitives.md.
const (
	refP1  = "§3.5"
	refP2  = "§4.6"
	refP3  = "§5"
	refTLS = "§5.6"
	refP4  = "§6"
	refPS  = "§6.2"
	refPr  = "§6.3"
	refP5  = "§7"
	refP7  = "§12"
)

// importRule is FF-SP1: an import path that may only appear in its home.
type importRule struct {
	Rule     string
	Exact    []string // import paths
	Prefixes []string // import path prefixes
	Except   []string // import paths excluded from Prefixes
	Home     []string // policy patterns that may import it; empty means nowhere
	// GeneratedHome lets a sqlc-generated sqlcdb package (every file carrying the sqlc header) import it too.
	GeneratedHome bool
	TestsExempt   bool
	Msg           string
}

var importRules = []importRule{
	{Rule: "ldap-library", Prefixes: []string{"github.com/go-ldap/"}, Home: []string{policy.Connector},
		Msg: "the LDAP library is imported only by internal/connector (" + refP1 + ")"},
	{Rule: "sql-driver", Exact: []string{"database/sql", "github.com/lib/pq", "github.com/jmoiron/sqlx", "github.com/jackc/pgx/v5/pgxpool", "github.com/jackc/pgx/v5/stdlib"},
		Prefixes: []string{"gorm.io/", "github.com/jackc/pgx/v4", "entgo.io/", "github.com/uptrace/bun", "github.com/go-pg/pg"},
		Home:     []string{policy.Store},
		Msg:      "the SQL driver, pool and ORMs are imported only by internal/platform/store (" + refP5 + ")"},
	{Rule: "pgx-types", Exact: []string{"github.com/jackc/pgx/v5", "github.com/jackc/pgx/v5/pgconn", "github.com/jackc/pgx/v5/pgtype"},
		Home: []string{policy.Store}, GeneratedHome: true,
		Msg: "pgx is imported only by internal/platform/store and by sqlc-generated sqlcdb packages (" + refP5 + ")"},
	{Rule: "process-api", Exact: []string{"os/exec"}, Home: []string{policy.Proc}, TestsExempt: true,
		Msg: "os/exec is imported only by internal/platform/proc (" + refPr + ")"},
	// P7: output encoders (§12).
	{Rule: "csv-writer", Exact: []string{"encoding/csv"}, Home: []string{policy.ExportCSV}, TestsExempt: true,
		Msg: "encoding/csv is imported only by export/csv (" + refP7 + ".3)"},
	{Rule: "xlsx-library", Prefixes: []string{"github.com/xuri/excelize", "github.com/qax-os/excelize", "github.com/360EntSecGroup-Skylar/excelize", "github.com/tealeg/xlsx", "github.com/thedatashed/xlsxreader", "github.com/shakinm/xlsReader"},
		Home: []string{policy.ExportXLS}, TestsExempt: true,
		Msg: "an XLSX library is imported only by export/xlsx (" + refP7 + ".4)"},
	{Rule: "pdf-library", Prefixes: []string{"github.com/signintech/gopdf", "github.com/johnfercher/maroto", "github.com/phpdave11/gofpdf", "github.com/go-pdf/fpdf", "github.com/jung-kurt/gofpdf", "github.com/pdfcpu/pdfcpu", "github.com/unidoc/", "github.com/jung-kurt/gofpdi", "github.com/phpdave11/gofpdi"},
		Home: []string{policy.ExportPDF}, TestsExempt: true,
		Msg: "a PDF library is imported only by export/pdf (" + refP7 + ".7)"},
	{Rule: "mail-writer", Exact: []string{"net/smtp", "mime/multipart", "mime/quotedprintable"}, Home: []string{policy.Mail}, TestsExempt: true,
		Msg: "net/smtp, mime/multipart and mime/quotedprintable are imported only by notify/mail (" + refP7 + ".6)"},
	{Rule: "html-to-pdf-engine", Prefixes: []string{"github.com/chromedp/", "github.com/go-rod/", "github.com/playwright-community/playwright-go", "github.com/SebastiaanKlippert/go-wkhtmltopdf", "github.com/mafredri/cdp", "github.com/wkhtmltopdf/"},
		Msg: "a headless browser or HTML-to-PDF engine is banned in product code (" + refP7 + ".7)"},
}

// symbolRule is FF-SP2 by package-qualified name: pkg.Name selected from an import path, or a bare
// method name on any receiver in a file that imports one of RequireImport.
type symbolRule struct {
	Rule          string
	Pkg           string   // import path (exact) the selector's package resolves to
	PkgPrefix     string   // or an import path prefix
	Names         []string // selected identifiers; nil means any
	MethodNames   []string // method or field names on any receiver
	RequireImport []string // import path prefixes the file must import (for MethodNames)
	Home          []string // policy patterns allowed to use it
	OnlyIn        []string // when set, the rule applies only in these trees
	TestsExempt   bool
	Msg           string
}

var symbolRules = []symbolRule{
	{Rule: "ldap-filter-library", PkgPrefix: "github.com/go-ldap/ldap", Names: []string{"CompileFilter", "DecompileFilter", "EscapeFilter"},
		Home: []string{policy.LDAPFilter}, TestsExempt: true,
		Msg: "the LDAP library's filter compiler and escaper are banned outside ldapfilter (" + refP1 + ")"},
	{Rule: "ldap-dn-library", PkgPrefix: "github.com/go-ldap/ldap", Names: []string{"ParseDN", "EscapeDN"},
		Home: []string{policy.DN}, TestsExempt: true,
		Msg: "the LDAP library's DN parser and escaper are banned outside dn (" + refP2 + ")"},
	{Rule: "ldap-raw-attribute-access", MethodNames: []string{"GetAttributeValue", "GetAttributeValues", "GetRawAttributeValue", "GetRawAttributeValues"},
		RequireImport: []string{"github.com/go-ldap/ldap"}, Home: []string{policy.Connector, policy.Attr}, TestsExempt: true,
		Msg: "raw entry attribute accessors are banned outside the connector and attr (" + refP3 + ")"},
	{Rule: "process-start", Pkg: "os/exec", Names: []string{"Command", "CommandContext"}, Home: []string{policy.Proc}, TestsExempt: true,
		Msg: "exec.Command is banned outside internal/platform/proc (" + refPr + ")"},
	{Rule: "process-start", Pkg: "os", Names: []string{"StartProcess"}, Home: []string{policy.Proc}, TestsExempt: true,
		Msg: "os.StartProcess is banned outside internal/platform/proc (" + refPr + ")"},
	{Rule: "process-start", Pkg: "syscall", Names: []string{"StartProcess", "ForkExec", "Exec", "CreateProcess"}, Home: []string{policy.Proc}, TestsExempt: true,
		Msg: "syscall process creation is banned outside internal/platform/proc (" + refPr + ")"},
	{Rule: "process-start", PkgPrefix: "golang.org/x/sys/windows", Names: []string{"CreateProcess", "CreateProcessAsUser", "CreateProcessWithLogon"}, Home: []string{policy.Proc}, TestsExempt: true,
		Msg: "Win32 process creation is banned outside internal/platform/proc (" + refPr + ")"},
	{Rule: "pgx-simple-protocol", Pkg: "github.com/jackc/pgx/v5", Names: []string{"QueryExecModeSimpleProtocol"}, Home: []string{policy.Store},
		Msg: "pgx simple protocol interpolates client-side (CVE-2024-27289); only the store's pool-construction assertion may name it (" + refP5 + " rule 6)"},
	{Rule: "pgx-connection", Pkg: "github.com/jackc/pgx/v5", Names: []string{"Connect", "ConnectConfig", "ParseConfig", "ConnConfig"}, Home: []string{policy.Store},
		Msg: "pgx connections and their configuration are created only in internal/platform/store (" + refP5 + ")"},
	{Rule: "template-typed-string", Pkg: "html/template", Names: []string{"HTML", "HTMLAttr", "JS", "JSStr", "CSS", "URL", "Srcset"}, Home: []string{policy.Htmlx}, TestsExempt: true,
		Msg: "typed template strings declare trust and are constructed only in htmlx (" + refP7 + ".5 rule 2)"},
	{Rule: "mail-header-writers", Pkg: "mime", Names: []string{"QEncoding", "BEncoding"}, Home: []string{policy.Mail}, TestsExempt: true,
		Msg: "hand-built mail headers are banned outside notify/mail (" + refP7 + ".6)"},
	{Rule: "mail-header-writers", Pkg: "net/textproto", Names: []string{"NewWriter", "Writer"}, Home: []string{policy.Mail}, TestsExempt: true,
		Msg: "net/textproto.Writer is banned outside notify/mail (" + refP7 + ".6)"},
	{Rule: "xlsx-active-content", MethodNames: []string{"SetCellFormula", "SetCellHyperLink", "AddVBAProject", "SetDefinedName", "AddComment", "AddPicture", "SetCellValue", "SetSheetFormula"},
		RequireImport: []string{"github.com/xuri/excelize", "github.com/qax-os/excelize", "github.com/360EntSecGroup-Skylar/excelize"}, TestsExempt: true,
		Msg: "XLSX formula, hyperlink, VBA, defined-name, comment, picture setters and type-inferring SetCellValue are banned (" + refP7 + ".4)"},
	{Rule: "pdf-active-content", MethodNames: []string{"AddExternalLink", "AddInternalLink", "LinkString", "AddLink", "SetLink", "ImportPage", "ImportPageFromStream", "UseImportedTemplate", "SetJavascript", "AddAttachment", "SetAttachments", "SetFormField"},
		RequireImport: []string{"github.com/signintech/gopdf", "github.com/johnfercher/maroto", "github.com/phpdave11/gofpdf", "github.com/go-pdf/fpdf", "github.com/jung-kurt/gofpdf", "github.com/phpdave11/gofpdi", "github.com/pdfcpu/pdfcpu"}, TestsExempt: true,
		Msg: "PDF link, annotation, JavaScript, attachment, form and page-import APIs are banned (" + refP7 + ".7); best effort until the library is chosen (T-0102)"},
	{Rule: "binary-little-endian", Pkg: "encoding/binary", Names: []string{"LittleEndian"}, OnlyIn: featurePackages, TestsExempt: true,
		Msg: "binary.LittleEndian on attribute bytes is banned in feature packages (" + refP3 + ")"},
}

// importBan is FF-SP2 by import path alone, with exemptions.
type importBan struct {
	Rule        string
	Paths       []string
	Msg         string
	TestsExempt bool // tests may import it
	ToolsExempt bool // tier L may import it
}

var importBans = []importBan{
	{Rule: "profiling-import", Paths: []string{"net/http/pprof", "runtime/pprof"}, TestsExempt: true, ToolsExempt: true,
		Msg: "pprof is banned in product code: heap and goroutine profiles carry secrets (" + refTLS + " R7)"},
	{Rule: "text-template", Paths: []string{"text/template"}, TestsExempt: true, ToolsExempt: true,
		Msg: "text/template is banned in product code: use html/template, or msgtpl for message text (" + refP7 + ".5 rule 1)"},
}

// literalRule is FF-SP2 on string or integer literals.
type literalRule struct {
	Rule        string
	Re          *regexp.Regexp // against the interpreted string value
	Equal       []string       // case-insensitive whole-value matches
	Ints        []string       // integer literal texts
	Home        []string
	Everywhere  bool // tier L and tests too
	TestsExempt bool
	Msg         string
}

var (
	reSetConfigFalse = regexp.MustCompile(`(?is)set_config\s*\([^;]*,\s*false\s*\)`)
	reSetApp         = regexp.MustCompile(`(?i)(?:^|;|\s)set\s+(?:local\s+|session\s+)?app\.`)
	reSimpleProto    = regexp.MustCompile(`(?i)simple_protocol`)
	reEscapeOIDs     = regexp.MustCompile(`1\.2\.840\.113556\.1\.4\.(?:1504|1340|417|2064|2065|841|2090|473|805|521|2255|619|2256)\b|2\.16\.840\.1\.113730\.3\.4\.9\b`)
	reGCPort         = regexp.MustCompile(`(?::|\b)326[89]\b`)
	reCmdlet         = regexp.MustCompile(`(?i)\binvoke-expression\b|\binvoke-command\b|\[scriptblock\]::create|\.invokescript|expandstring`)
	reGoTraceback    = regexp.MustCompile(`GOTRACEBACK\s*[=:]\s*["']?crash`)
)

var literalRules = []literalRule{
	{Rule: "set-config-session-scope", Re: reSetConfigFalse, TestsExempt: true,
		Msg: "set_config(…, false) sets a session setting that leaks across pooled connections; use is_local = true (" + refP5 + " rule 2)"},
	{Rule: "set-app-literal", Re: reSetApp, TestsExempt: true,
		Msg: "SET app.… sets a session or transaction setting from text; use the store's tenancy API (" + refP5 + " rule 2)"},
	{Rule: "simple-protocol-literal", Re: reSimpleProto, TestsExempt: true, Home: []string{policy.Store},
		Msg: "simple_protocol mode interpolates client-side (CVE-2024-27289) (" + refP5 + " rule 6)"},
	{Rule: "powershell-literal", Equal: []string{"powershell", "powershell.exe", "pwsh", "pwsh.exe", "cmd.exe", "/bin/sh", "/bin/bash", "-command", "-encodedcommand", "-commandwithargs", ".bat", ".cmd"},
		Home: []string{policy.Psx, policy.Proc}, TestsExempt: true,
		Msg: "interpreter and shell names, -Command and -EncodedCommand are banned outside psx and proc (" + refP4 + ")"},
	{Rule: "powershell-invoke-literal", Re: reCmdlet, Home: []string{policy.Psx, policy.Proc}, TestsExempt: true,
		Msg: "Invoke-Expression, ScriptBlock.Create and ExpandString build code from text (" + refP4 + ")"},
	{Rule: "unicodepwd-literal", Equal: []string{"unicodePwd"}, Home: []string{policy.Attr, policy.Connector}, TestsExempt: true,
		Msg: "the literal \"unicodePwd\" is banned outside attr and the connector (" + refP3 + ")"},
	{Rule: "gc-port", Re: reGCPort, Ints: []string{"3268", "3269"}, Home: []string{policy.Connector}, TestsExempt: true,
		Msg: "the Global Catalog ports are named only in the connector's forest-wide operations (" + refP1 + ", §3.6)"},
	{Rule: "escape-control-oid", Re: reEscapeOIDs, Home: []string{policy.Scope}, TestsExempt: true,
		Msg: "escape-control OIDs may appear only in scope's named-operation table (" + refP1 + ", LF-30)"},
	{Rule: "content-disposition-literal", Equal: []string{"content-disposition"}, Home: []string{policy.Httpx}, TestsExempt: true,
		Msg: "Content-Disposition is set only by httpx.Attachment (" + refP7 + ".5 rule 5)"},
	{Rule: "csv-media-type", Equal: []string{"text/csv", ".csv"}, Home: []string{policy.ExportCSV, policy.Httpx}, TestsExempt: true,
		Msg: "the text/csv media type and the .csv extension are named only in export/csv and httpx (" + refP7 + ".3)"},
	{Rule: "gotraceback-crash", Re: reGoTraceback, Everywhere: true,
		Msg: "a crash-mode GOTRACEBACK writes core dumps that carry secrets (" + refTLS + " R7)"},
}

// featurePackages are the roots in which UAC and groupType bit names and little-endian reads are banned.
var featurePackages = []string{policy.Modules, policy.AgentMods}

var reFlagConst = regexp.MustCompile(`^(?:ADS_)?(?:UF_|GROUP_TYPE_)[A-Z0-9_]+$`)

// moduleDenylist is FF-SP1 on go.mod: modules banned from product dependencies altogether.
var moduleDenylist = []string{
	"github.com/chromedp/chromedp", "github.com/go-rod/rod", "github.com/playwright-community/playwright-go",
	"github.com/SebastiaanKlippert/go-wkhtmltopdf", "github.com/mafredri/cdp",
}

// webPackageDenylist is FF-SP3 on web/package.json (§12.3, §12.5 W1).
var webPackageDenylist = map[string]string{
	"papaparse": "a CSV library: exports are server-side (§12.3)", "json-2-csv": "a CSV library: exports are server-side (§12.3)",
	"csv-stringify": "a CSV library: exports are server-side (§12.3)", "fast-csv": "a CSV library: exports are server-side (§12.3)",
	"xlsx": "an XLSX library: exports are server-side (§12.3)", "exceljs": "an XLSX library: exports are server-side (§12.3)",
	"xlsx-populate": "an XLSX library: exports are server-side (§12.3)", "sheetjs": "an XLSX library: exports are server-side (§12.3)",
	"jspdf": "a PDF library: exports are server-side (§12.7)", "pdfmake": "a PDF library: exports are server-side (§12.7)",
	"html2pdf.js": "an HTML-to-PDF engine (§12.7)", "html-react-parser": "an HTML string renderer (§12.5 W1)",
	"rehype-raw": "raw HTML in Markdown (§12.5 W1)",
}
