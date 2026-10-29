package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// T-0762: the WiX SDK builds the MSI through MSBuild, so anything MSBuild runs after the rules above have
// judged the sources (a Target/Exec running msitran or MsiDb, a custom task, an imported .targets, a .mst
// transform) can rewrite the built MSI. None of that is approvable via installer-allow.txt.

// msiOpaqueExts are MSI transforms, patches and patch creation files: opaque databases that add or change
// CustomAction, ServiceInstall and sequence rows in the built MSI.
var msiOpaqueExts = setOf(".mst", ".msp", ".pcp")

var msbuildExts = setOf(".props", ".targets", ".proj", ".wixproj")

// MSBuild is judged by allowlist, not denylist: only the elements, property names, item types and
// attributes below are reviewed; anything else (a hook nobody listed, a new element, an unknown property)
// fails, because every unknown thing in a build file is a way to run code on the built MSI.
var msbuildAllowedProps = setOf("outputname", "outputtype", "platform", "platforms", "configuration", "configurations",
	"defineconstants", "installerplatform", "suppressvalidation", "suppressices", "cultures", "treatwarningsaserrors",
	"warningsaserrors", "nowarn", "outputpath", "deterministic",
	"productversion", "version", "assemblyname", "rootnamespace", "nologo", "debugtype", "signoutput")

var msbuildAllowedItems = setOf("compile", "bindpath", "content", "none")

// msbuildReviewedPackages are the only PackageReference/WixExtension Include/Version pairs allowed (NuGet
// auto-imports a package's build/*.props|targets, and a WiX extension runs inside wix build). Empty until a
// security-architect review adds one as "id/version".
var msbuildReviewedPackages = map[string]bool{}

// msbuildOpaqueNames are files MSBuild reads automatically that are not judged as XML: a response file feeds
// command-line switches (-p:WixTargetsPath=...), so none may reach a WiX project.
func isRspFile(p string) bool { return strings.EqualFold(filepath.Ext(p), ".rsp") }

func isNuGetConfig(p string) bool { return strings.EqualFold(filepath.Base(p), "nuget.config") }

func isGlobalJSON(p string) bool { return strings.EqualFold(filepath.Base(p), "global.json") }

func isMSBuildFile(p string) bool {
	l := strings.ToLower(p)
	return msbuildExts[strings.ToLower(filepath.Ext(p))] || strings.HasSuffix(l, ".wixproj.user") || strings.HasSuffix(l, ".proj.user")
}

func isDirectoryBuild(p string) bool {
	return strings.HasPrefix(strings.ToLower(filepath.Base(p)), "directory.build.") ||
		strings.HasPrefix(strings.ToLower(filepath.Base(p)), "directory.solution.")
}

// msbuildProblems walks root for opaque MSI artifacts and MSBuild files that reach a WiX source, and
// returns violations. wixDirs are the repo-relative directories holding WiX sources.
func msbuildProblems(root string) []string {
	var out []string
	var wixDirs []string
	var projDirs, projNames []string
	var cands []string
	_ = filepath.WalkDir(root, func(p string, e fs.DirEntry, err error) error {
		if err != nil || e == nil {
			return nil
		}
		if e.IsDir() {
			if e.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		ext := strings.ToLower(filepath.Ext(p))
		if msiOpaqueExts[ext] {
			out = append(out, fmt.Sprintf("%s is an MSI transform, patch or patch-creation file (%s): it is an opaque database that adds or changes CustomAction, ServiceInstall and sequence rows in the built MSI after every rule has run; installer-allow.txt cannot approve one (T-0762)", rel, ext))
			return nil
		}
		if strings.HasSuffix(strings.ToLower(rel), ".wixproj") {
			projDirs = append(projDirs, filepath.ToSlash(filepath.Dir(rel)))
			projNames = append(projNames, strings.ToLower(filepath.Base(rel)))
		}
		if isRepoWix(p) {
			wixDirs = append(wixDirs, filepath.ToSlash(filepath.Dir(rel)))
		}
		if isMSBuildFile(p) || isDirectoryBuild(p) || isRspFile(p) || isNuGetConfig(p) || isGlobalJSON(p) {
			cands = append(cands, rel)
		}
		return nil
	})
	for _, rel := range cands {
		dir := filepath.ToSlash(filepath.Dir(rel))
		if !msbuildReachesWix(rel, dir, wixDirs) && !msbuildWildcardImported(rel, dir, projDirs, projNames) {
			continue
		}
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			out = append(out, fmt.Sprintf("%s is an MSBuild file that cannot be read (%v): it could run a post-build step on the MSI (T-0762)", rel, err))
			continue
		}
		switch {
		case isRspFile(rel):
			out = append(out, fmt.Sprintf("%s is an MSBuild response file that reaches a WiX project: MSBuild reads it automatically and its switches (-p:WixTargetsPath=..., -p:CustomAfterMicrosoftCommonTargets=...) run unreviewed targets on the MSI; installer-allow.txt cannot approve one (T-0762)", rel))
		case isNuGetConfig(rel):
			out = append(out, judgeNuGetConfig(rel, b)...)
		case isGlobalJSON(rel):
			out = append(out, judgeGlobalJSON(rel, b)...)
		default:
			out = append(out, judgeMSBuild(rel, b)...)
		}
	}
	return out
}

// msbuildReachesWix: a .wixproj always counts; any other MSBuild file counts when it sits under packaging/,
// or in a directory at or above a WiX source (Directory.Build.* applies to everything below it).
func msbuildReachesWix(rel, dir string, wixDirs []string) bool {
	if strings.HasSuffix(strings.ToLower(rel), ".wixproj") || strings.HasSuffix(strings.ToLower(rel), ".wixproj.user") || strings.HasPrefix(rel, "packaging/") {
		return true
	}
	for _, w := range wixDirs {
		if dir == "." || w == dir || strings.HasPrefix(w, dir+"/") {
			return true
		}
	}
	return false
}

// msbuildWildcardImported: MSBuild wildcard-imports $(MSBuildProjectExtensionsPath)$(MSBuildProjectFile).*.props|targets
// (default obj/, redirectable), so any file named <wixproj>.*.props|targets is judged wherever it sits, and so is
// any .props/.targets in or below a directory holding a .wixproj (that is where obj/ lives).
func msbuildWildcardImported(rel, dir string, projDirs, projNames []string) bool {
	l := strings.ToLower(rel)
	if !strings.HasSuffix(l, ".props") && !strings.HasSuffix(l, ".targets") {
		return false
	}
	base := strings.ToLower(filepath.Base(rel))
	for i, n := range projNames {
		if strings.HasPrefix(base, n+".") {
			return true
		}
		if d := projDirs[i]; d == "." || dir == d || strings.HasPrefix(dir, d+"/") {
			return true
		}
	}
	return false
}

// msbuildPropFunc matches a property function or registry lookup after XML decoding: MSBuild tolerates
// whitespace and (removed-before-expansion) XML comments between "$(" and "[" or "registry:".
var msbuildPropFunc = regexp.MustCompile(`(?i)\$\(\s*(\[|registry:)`)

func judgeMSBuild(rel string, b []byte) []string {
	var out []string
	add := func(s string) {
		out = append(out, fmt.Sprintf("%s: %s: MSBuild can rewrite the built MSI after every A1 rule has run; installer-allow.txt cannot approve one (T-0762)", rel, s))
	}
	text, ok := decodeText(b)
	if !ok {
		add("cannot be read as text")
		return out
	}
	if strings.Contains(text, "&#") {
		add("uses a numeric character reference (&#...), which can hide a $([...]) property function from a text check")
	}
	if strings.Contains(text, "$([") || strings.Contains(strings.ToLower(text), "$(registry:") {
		add("uses an MSBuild property function $([...]) or Registry: lookup")
	}
	d := xml.NewDecoder(strings.NewReader(text))
	d.Strict = false
	d.CharsetReader = func(_ string, r io.Reader) (io.Reader, error) { return r, nil }
	depth := 0
	var stackKind []string
	var chars strings.Builder
	flushChars := func() {
		if msbuildPropFunc.MatchString(chars.String()) {
			add("uses an MSBuild property function $([...]) or Registry: lookup (found in decoded element text, comments ignored)")
		}
		chars.Reset()
	}
	onlyAttrs := func(t xml.StartElement, names ...string) {
		for _, a := range t.Attr {
			n := strings.ToLower(a.Name.Local)
			if a.Name.Space == "xmlns" || n == "xmlns" || n == "condition" {
				continue
			}
			found := false
			for _, w := range names {
				found = found || n == w
			}
			if !found {
				add(fmt.Sprintf("%s has a %s attribute, which is not on the reviewed list", t.Name.Local, a.Name.Local))
			}
		}
	}
	for {
		tok, err := d.RawToken()
		if err != nil {
			if err != io.EOF {
				add("is not well-formed XML, so it cannot be judged")
			}
			break
		}
		switch t := tok.(type) {
		case xml.CharData:
			chars.Write([]byte(t))
		case xml.Directive:
			add("has a DOCTYPE or ENTITY declaration")
		case xml.StartElement:
			flushChars()
			for _, a := range t.Attr {
				if msbuildPropFunc.MatchString(a.Value) {
					add(fmt.Sprintf("%s attribute %s uses an MSBuild property function $([...]) or Registry: lookup", t.Name.Local, a.Name.Local))
				}
			}
			depth++
			n := strings.ToLower(t.Name.Local)
			switch {
			case depth == 1 && n == "project":
				onlyAttrs(t, "sdk", "toolsversion")
				for _, a := range t.Attr {
					if strings.EqualFold(a.Name.Local, "sdk") && !sdkListAllowed(a.Value) {
						add(fmt.Sprintf("uses SDK %q: only the pinned WiX SDK is reviewed", a.Value))
					}
				}
			case depth == 1:
				add(fmt.Sprintf("root element is %s, not Project", t.Name.Local))
			case depth == 2 && n == "import":
				onlyAttrs(t, "project", "sdk")
				p := attrOf(t, "project")
				if attrOf(t, "sdk") == "" || (!strings.EqualFold(p, "Sdk.props") && !strings.EqualFold(p, "Sdk.targets")) {
					add(fmt.Sprintf("has an Import of %q: only Sdk.props or Sdk.targets from the pinned SDK is reviewed", p))
				} else if !sdkListAllowed(attrOf(t, "sdk")) {
					add(fmt.Sprintf("has an Import from SDK %q: only the pinned WiX SDK is reviewed", attrOf(t, "sdk")))
				}
			case depth == 2 && n == "sdk":
				onlyAttrs(t, "name", "version")
				if !sdkListAllowed(attrOf(t, "name")) {
					add(fmt.Sprintf("uses SDK %q: only the pinned WiX SDK is reviewed", attrOf(t, "name")))
				}
			case depth == 2 && (n == "propertygroup" || n == "itemgroup"):
				onlyAttrs(t)
			case depth == 3 && n != "" && len(stackKind) > 0 && stackKind[len(stackKind)-1] == "propertygroup":
				onlyAttrs(t)
				if !msbuildAllowedProps[n] {
					add(fmt.Sprintf("sets property %s, which is not on the reviewed list", t.Name.Local))
				}
			case depth == 3 && len(stackKind) > 0 && stackKind[len(stackKind)-1] == "itemgroup":
				switch {
				case n == "packagereference" || n == "wixextension":
					onlyAttrs(t, "include", "version")
					if !msbuildReviewedPackages[attrOf(t, "include")+"/"+attrOf(t, "version")] {
						add(fmt.Sprintf("%s %q version %q is not a reviewed, pinned package or extension (NuGet imports its build/*.targets; extensions run inside wix build)", t.Name.Local, attrOf(t, "include"), attrOf(t, "version")))
					}
				case msbuildAllowedItems[n]:
					onlyAttrs(t, "include", "update", "remove")
				default:
					add(fmt.Sprintf("has an item of type %s (ProjectReference, Reference, Using and the like), which is not on the reviewed list", t.Name.Local))
				}
			default:
				add(fmt.Sprintf("has a %s element (Target, Exec, UsingTask and every other element not on the reviewed list fail)", t.Name.Local))
			}
			stackKind = append(stackKind, n)
		case xml.EndElement:
			flushChars()
			depth--
			if len(stackKind) > 0 {
				stackKind = stackKind[:len(stackKind)-1]
			}
		}
	}
	return out
}

func attrOf(t xml.StartElement, name string) string {
	for _, a := range t.Attr {
		if strings.EqualFold(a.Name.Local, name) {
			return a.Value
		}
	}
	return ""
}

// sdkListAllowed reports whether every entry of a (possibly semicolon-separated) SDK list is a reviewed,
// version-pinned SDK. A single foreign entry brings its targets in, so all entries must pass.
func sdkListAllowed(list string) bool {
	n := 0
	for _, e := range strings.Split(list, ";") {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		n++
		if !strings.HasPrefix(e, "WixToolset.Sdk/") && !strings.HasPrefix(e, "Microsoft.Build.NoTargets/") {
			return false
		}
	}
	return n > 0
}

const nugetOrgURL = "https://api.nuget.org/v3/index.json"

// judgeNuGetConfig accepts only a nuget.config that leaves nuget.org as the single source (and optional
// package source mapping): any other feed or setting could serve a rogue WixToolset.Sdk or package.
func judgeNuGetConfig(rel string, b []byte) []string {
	var out []string
	add := func(s string) {
		out = append(out, fmt.Sprintf("%s: %s: NuGet decides which WiX SDK and packages the build runs; only a nuget.org-only config is reviewed; installer-allow.txt cannot approve another (T-0762)", rel, s))
	}
	text, ok := decodeText(b)
	if !ok {
		add("cannot be read as text")
		return out
	}
	d := xml.NewDecoder(strings.NewReader(text))
	d.Strict = false
	d.CharsetReader = func(_ string, r io.Reader) (io.Reader, error) { return r, nil }
	var stack []string
	for {
		tok, err := d.RawToken()
		if err != nil {
			if err != io.EOF {
				add("is not well-formed XML, so it cannot be judged")
			}
			return out
		}
		switch t := tok.(type) {
		case xml.Directive:
			add("has a DOCTYPE or ENTITY declaration")
		case xml.StartElement:
			n := strings.ToLower(t.Name.Local)
			parent := ""
			if len(stack) > 0 {
				parent = stack[len(stack)-1]
			}
			switch {
			case len(stack) == 0 && n == "configuration", n == "clear" && parent == "packagesources",
				n == "packagesources" && parent == "configuration", n == "packagesourcemapping" && parent == "configuration",
				n == "packagesource" && parent == "packagesourcemapping", n == "package" && parent == "packagesource":
			case n == "add" && parent == "packagesources":
				if !strings.EqualFold(attrOf(t, "key"), "nuget.org") || attrOf(t, "value") != nugetOrgURL {
					add(fmt.Sprintf("adds package source %q=%q; only nuget.org (%s) is reviewed", attrOf(t, "key"), attrOf(t, "value"), nugetOrgURL))
				}
			default:
				add(fmt.Sprintf("has a %s element (under %q) that is not on the reviewed list", t.Name.Local, parent))
			}
			if n == "packagesource" && parent == "packagesourcemapping" && !strings.EqualFold(attrOf(t, "key"), "nuget.org") {
				add(fmt.Sprintf("maps packages to source %q; only nuget.org is reviewed", attrOf(t, "key")))
			}
			stack = append(stack, n)
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		}
	}
}

// judgeGlobalJSON accepts only a global.json that pins the dotnet SDK version: msbuild-sdks (or any other key)
// swaps the SDK the build resolves without touching the .wixproj.
func judgeGlobalJSON(rel string, b []byte) []string {
	bad := func(s string) []string {
		return []string{fmt.Sprintf("%s: %s: global.json can swap the MSBuild SDK the build resolves; only a plain sdk version pin is reviewed; installer-allow.txt cannot approve another (T-0762)", rel, s)}
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return bad("is not valid JSON, so it cannot be judged")
	}
	var out []string
	for k, v := range m {
		if k != "sdk" {
			out = append(out, bad(fmt.Sprintf("has a %q key (msbuild-sdks, tools and the like)", k))...)
			continue
		}
		var sdk map[string]json.RawMessage
		if json.Unmarshal(v, &sdk) != nil {
			out = append(out, bad("has an sdk entry that is not an object")...)
			continue
		}
		for sk := range sdk {
			if sk != "version" && sk != "rollForward" && sk != "allowPrerelease" {
				out = append(out, bad(fmt.Sprintf("has an sdk.%s key", sk))...)
			}
		}
	}
	return out
}
