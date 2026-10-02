package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The fixtures below build a throw-away repository, run the real checks over it and look at what
// they report. Strings that name a banned build flag are assembled from parts so the checker does
// not trip over its own tests when it scans this repository (F2 scans every non-prose file).
const (
	bmFlag    = "-build" + "mode="
	cSharedBM = bmFlag + "c-shared"
	pluginBM  = bmFlag + "plugin"
)

const registerText = `# Register

| Project | Licence | Use | Mode | Ships | Status |
| --- | --- | --- | --- | --- | --- |
| Good (` + "`example.com/good`" + `) | MIT | test | Embedded | Yes | **Clear** |
| Bad (` + "`example.com/bad`" + `) | AGPL-3.0 | test | Embedded | No | **Rejected** (direct use) |
| Web (` + "`react`" + `, ` + "`@scope/pkg`" + `) | MIT | test | Embedded | Yes | **Clear** |
| Crates (` + "`windows`" + `) | MIT | test | Embedded | Yes | **Candidate** |
| Nuget (` + "`Some.Package`" + `) | MIT | test | Embedded | Yes | **Clear** |
| Copied (` + "`third_party/copied`" + `) | MIT | test | Embedded | Yes | **Clear** |
| Mentioned only | MIT | uses ` + "`example.com/only-in-use-column`" + ` | Embedded | Yes | **Clear** |
`

func adrText(status string) string {
	return "---\ntitle: \"ADR\"\nstatus: " + status + "          # ladder\n---\n\n# ADR\n"
}

type fixture struct {
	t    *testing.T
	root string
	m    Manifest
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{t: t, root: t.TempDir()}
	b, err := os.ReadFile("manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := strictDecode(b, &f.m); err != nil {
		t.Fatal(err)
	}
	f.m.BuildMatrix = []string{"linux/amd64", "windows/arm64"}
	f.m.Exceptions = Exceptions{}
	f.m.Binaries = []Binary{{Name: "server", Tier: "S", Package: "./cmd/server"}}
	f.write("go.mod", "module fx.test\n\ngo 1.27.0\n")
	f.write("cmd/server/main.go", "package main\n\nfunc main() {}\n")
	f.write("knowledge/development/decisions/0001-technology-stack.md", adrText("ratified"))
	f.write("knowledge/development/decisions/0003-accepted.md", adrText("accepted"))
	f.write("knowledge/development/decisions/0009-draft.md", adrText("proposed"))
	f.write(f.m.LicenceReg, registerText)
	return f
}

func (f *fixture) write(rel, content string) {
	f.t.Helper()
	p := filepath.Join(f.root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) run(checks string, skipBuild bool) []Violation {
	f.t.Helper()
	b, _ := json.Marshal(f.m)
	f.write("manifest.json", string(b))
	vs, err := Run(f.root, "manifest.json", strings.Split(checks, ","), skipBuild)
	if err != nil {
		f.t.Fatal(err)
	}
	return vs
}

// want requires a violation of check on a file whose name contains file and whose message contains msg.
func want(t *testing.T, vs []Violation, check, file, msg string) {
	t.Helper()
	for _, v := range vs {
		if v.Check == check && strings.Contains(v.File, file) && strings.Contains(v.Msg, msg) {
			return
		}
	}
	t.Errorf("want %s on %q mentioning %q; got:\n%s", check, file, msg, dump(vs))
}

func none(t *testing.T, vs []Violation) {
	t.Helper()
	if len(vs) != 0 {
		t.Errorf("want no violations; got:\n%s", dump(vs))
	}
}

func dump(vs []Violation) string {
	var sb strings.Builder
	for _, v := range vs {
		sb.WriteString("  " + v.String() + "\n")
	}
	return sb.String()
}

func TestMessageNamesFileCheckAndADRRule(t *testing.T) {
	f := newFixture(t)
	f.write("src/x.rs", "fn main() {}\n")
	vs := f.run("F1", true)
	if len(vs) != 1 || vs[0].String() != "src/x.rs: F1 (ADR-0001 rule 1): Rust outside [native]" {
		t.Fatalf("got:\n%s", dump(vs))
	}
	for check, rule := range map[string]string{"F2": "rule 2", "F3": "rule 3", "F4": "rule 6", "F5": "rule 5"} {
		if got := (Violation{check, "f", "m"}).String(); !strings.Contains(got, "ADR-0001 "+rule) {
			t.Errorf("%s message %q lacks %q", check, got, rule)
		}
	}
}

func TestCleanFixtureIsGreen(t *testing.T) {
	f := newFixture(t)
	none(t, f.run("F1,F2,F3,F4,F5", false))
}

// ---- F1 ------------------------------------------------------------------------------------

func TestF1Zones(t *testing.T) {
	cases := []struct{ name, file, content, msg string }{
		{"rust outside native", "svc/lib.rs", "", "Rust outside [native]"},
		{"python outside lab and tools", "svc/gen.py", "", "python outside [lab tools]"},
		{"powershell outside lab and tools", "svc/run.ps1", "", "powershell outside"},
		{"shell outside lab and tools", "svc/run.sh", "", "shell outside"},
		{"extensionless python script", "svc/run", "#!/usr/bin/env python3\n", "python outside"},
		{"extensionless shell script", "svc/hook", "#!/bin/sh\n", "shell outside"},
		{"typescript outside web", "svc/a.ts", "", "typescript outside [web]"},
		{"tsx outside web", "svc/a.tsx", "", "typescript outside [web]"},
		{"js outside web", "svc/a.js", "", "javascript outside [web]"},
		{"mjs outside web", "tools/a.mjs", "", "javascript outside [web]"},
		{"cjs outside web", "lab/a.cjs", "", "javascript outside [web]"},
		{"node shebang script outside web", "tools/serve", "#!/usr/bin/env node\n", "javascript outside"},
		{"c outside native", "svc/a.c", "", "C/C++ outside [native]"},
		{"cpp outside native", "svc/a.cpp", "", "C/C++ outside [native]"},
		{"header outside native", "svc/a.h", "", "C/C++ outside [native]"},
		{"cpp inside native without a fallback", "native/pf/a.cpp", "", "C++ fallback"},
		{"csharp outside sidecars", "svc/a.cs", "", "outside [sidecars]"},
		{"csproj outside sidecars", "svc/a.csproj", "", "outside [sidecars]"},
		{"csharp inside sidecars but undeclared", "sidecars/exo/a.cs", "", "declared in manifest exceptions.sidecars"},
		{"java", "native/a.java", "", "java source is not an allowed language"},
		{"kotlin", "svc/a.kt", "", "kotlin source"},
		{"ruby", "svc/a.rb", "", "ruby source"},
		{"php", "svc/a.php", "", "php source"},
		{"lua", "svc/a.lua", "", "lua source"},
		{"bat", "svc/a.bat", "", "batch source"},
		{"cmd", "svc/a.cmd", "", "batch source"},
		{"vbs", "svc/a.vbs", "", "vbscript source"},
		{"swift (macOS logon component has no ADR yet)", "native/mac/a.swift", "", "swift source"},
		{"PAM module in C", "native/pam/pam.c", "", "C/C++"},
		{"go in web", "web/a.go", "package web\n", "not allowed under"},
		{"stray go.mod", "svc/go.mod", "module x\n", "go.mod outside the root zone"},
		{"stray package.json", "svc/package.json", "{}", "package.json outside"},
		{"stray Cargo.toml", "svc/Cargo.toml", "", "Cargo.toml outside the native zone"},
		{"undeclared crate", "native/pf/Cargo.toml", "", "not a declared tier-N Windows component"},
		{"rust file in an undeclared native dir", "native/pf/src/lib.rs", "", "not inside a declared tier-N"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.write(tc.file, tc.content)
			want(t, f.run("F1", true), "F1", tc.file, tc.msg)
		})
	}
}

func TestF1AllowedPlacements(t *testing.T) {
	f := newFixture(t)
	for _, p := range []string{"lab/a.py", "tools/a.sh", "tools/a.ps1", "lab/bin/run", "web/a.ts", "web/a.tsx", "web/eslint.config.js", "web/package.json", "internal/x/a.go", "lab/gen/a.go", "native/pf/src/lib.rs", "native/pf/Cargo.toml", "sidecars/exo/a.cs", "scripts/build.sh"} {
		f.write(p, "")
	}
	f.write("lab/bin/run", "#!/bin/bash\n")
	f.m.Exceptions.NativeComponents = []Exception{{Path: "native/pf", ADR: "0001-technology-stack.md", Tier: "N", Platform: "windows"}}
	f.m.Exceptions.Sidecars = []Exception{{Path: "sidecars/exo", ADR: "0001-technology-stack.md"}}
	f.m.Exceptions.BuildScripts = []Exception{{Path: "scripts/build.sh", ADR: "0001-technology-stack.md"}}
	none(t, f.run("F1", true))
}

func TestF1DeclaredExceptionsAreHonoured(t *testing.T) {
	f := newFixture(t)
	f.write("native/pf/a.cpp", "")
	f.write("tools/playwright/a.mjs", "")
	f.write("tools/playwright/package.json", "{}")
	f.write("svc/go.mod", "module x\n")
	f.m.Exceptions.CppFallbacks = []Exception{{Path: "native/pf", ADR: "0001-technology-stack.md"}}
	f.m.Exceptions.DevNodeTools = []Exception{{Path: "tools/playwright", ADR: "0001-technology-stack.md"}}
	f.m.Exceptions.ExtraGoModules = []Exception{{Path: "svc", ADR: "0001-technology-stack.md"}}
	none(t, f.run("F1", true))
}

func TestF1NativeComponentMustBeTierNWindows(t *testing.T) {
	for _, tc := range []struct{ name, tier, platform string }{{"linux PAM", "N", "linux"}, {"wrong tier", "S", "windows"}, {"unset", "", ""}} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.write("native/pam/Cargo.toml", "")
			f.m.Exceptions.NativeComponents = []Exception{{Path: "native/pam", ADR: "0001-technology-stack.md", Tier: tc.tier, Platform: tc.platform}}
			want(t, f.run("F1", true), "F1", "manifest.json", "tier \"N\" on platform \"windows\"")
		})
	}
}

func TestF1UnknownLanguageHasNoZone(t *testing.T) {
	f := newFixture(t)
	delete(f.m.LanguageZones, "python")
	f.write("lab/a.py", "")
	want(t, f.run("F1", true), "F1", "lab/a.py", "no zone")
}

// ---- F2 ------------------------------------------------------------------------------------

func TestF2SourceScan(t *testing.T) {
	cgoSrc := "package p\n\n// #include <stdio.h>\nimport \"C\"\n"
	cases := []struct{ name, file, content, msg string }{
		{"import C", "internal/a/a.go", cgoSrc, `import "C"`},
		{"import C under go:build ignore", "internal/a/a.go", "//go:build ignore\n\n" + cgoSrc, `import "C"`},
		{"import C in a _test file", "internal/a/a_test.go", cgoSrc, `import "C"`},
		{"import C in a grouped import", "internal/a/a.go", "package p\n\nimport (\n\t\"fmt\"\n\t\"C\"\n)\n\nvar _ = fmt.Sprint\n", `import "C"`},
		{"cgo export", "internal/a/a.go", "package p\n\n//export Foo\nfunc Foo() {}\n", "//export"},
		{"plugin package", "internal/a/a.go", "package p\n\nimport _ \"plugin\"\n", "plugin package"},
		{"build mode in a Makefile", "Makefile", "dll:\n\tgo build " + cSharedBM + " ./x\n", "build flag"},
		{"build mode plugin in a script", "tools/build.sh", "go build " + pluginBM + " ./x\n", "build flag"},
		{"build mode with a space", "tools/build.ps1", "go build " + strings.Replace(cSharedBM, "=", " ", 1) + " .\n", "build flag"},
		{"build mode in a go:generate line", "internal/a/a.go", "package p\n\n//go:generate go build " + bmFlag + "shared ./x\n", "build flag"},
		{"GOOS filename suffix", "internal/a/a_windows.go", "package p\n", "_windows"},
		{"GOARCH filename suffix", "internal/a/a_arm64.go", "package p\n", "_arm64"},
		{"GOOS_GOARCH filename suffix", "internal/a/a_linux_amd64.go", "package p\n", "_linux_amd64"},
		{"GOOS suffix on a test file", "internal/a/a_windows_test.go", "package p\n", "_windows"},
		{"go:build naming a GOOS", "internal/a/a.go", "//go:build windows\n\npackage p\n", `"windows"`},
		{"go:build negating a GOOS", "internal/a/a.go", "//go:build !darwin\n\npackage p\n", `"darwin"`},
		{"go:build naming a GOARCH", "internal/a/a.go", "//go:build amd64 && !purego\n\npackage p\n", `"amd64"`},
		{"go:build unix counts as a GOOS", "internal/a/a.go", "//go:build unix\n\npackage p\n", `"unix"`},
		{"go:build ignore", "internal/a/a.go", "//go:build ignore\n\npackage main\n", `"ignore"`},
		{"go:build cgo", "internal/a/a.go", "//go:build cgo\n\npackage p\n", `"cgo"`},
		{"go:build custom tag", "internal/a/a.go", "//go:build enterprise\n\npackage p\n", `"enterprise"`},
		{"legacy plus-build", "internal/a/a.go", "// +build ignore\n\npackage p\n", `"ignore"`},
		{"test tag in a non-test file", "internal/a/a.go", "//go:build lab\n\npackage p\n", "only allowed in _test.go"},
		{"windowslab tag in a non-test file", "internal/a/a.go", "//go:build windowslab\n\npackage p\n", "only allowed in _test.go"},
		{"unparseable Go", "internal/a/a.go", "package\n", "cannot be parsed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.write(tc.file, tc.content)
			want(t, f.run("F2", true), "F2", tc.file, tc.msg)
		})
	}
}

func TestF2NoFalsePositives(t *testing.T) {
	f := newFixture(t)
	f.write("internal/a/a.go", "package p\n\n// Mentions import \"C\" and //export and plugin in a comment only.\nconst a = `import \"C\"\n//export X`\nconst b = \"-buildmode=exe and \\\"C\\\"\"\n")
	f.write("internal/a/a_test.go", "//go:build lab\n\npackage p\n")
	f.write("internal/a/b_test.go", "//go:build windowslab && lab\n\npackage p\n")
	f.write("internal/a/race.go", "//go:build race || go1.25 || purego\n\npackage p\n")
	f.write("internal/a/note.go", "package p\n\n// the word windows or linux in a comment is fine\nvar windows = 1\n")
	f.write("internal/a/windows.go", "package p\n") // a file simply named windows.go has no suffix
	f.write("internal/a/s_unixish.go", "package p\n")
	f.write("docs.md", "go build "+cSharedBM+"\n")
	f.write("Makefile", "pie:\n\tgo build "+bmFlag+"pie ./x\n")
	none(t, f.run("F2", true))
}

func TestF2PlatformAdapterMayNameAnOS(t *testing.T) {
	f := newFixture(t)
	f.write("internal/winsvc/svc_windows.go", "package winsvc\n")
	f.write("internal/winsvc/svc_other.go", "//go:build !windows\n\npackage winsvc\n")
	f.write("internal/winsvc/svc_linux_arm64.go", "//go:build linux && arm64\n\npackage winsvc\n")
	f.write("internal/winsvc/lab_windows_test.go", "//go:build windowslab && windows\n\npackage winsvc\n")
	f.m.Exceptions.PlatformAdapters = []Exception{{Path: "internal/winsvc", ADR: "0001-technology-stack.md"}}
	none(t, f.run("F2", true))
	// an adapter is still not allowed an arbitrary tag, or cgo
	f.write("internal/winsvc/bad.go", "//go:build ignore\n\npackage winsvc\n")
	f.write("internal/winsvc/c.go", "package winsvc\n\nimport \"C\"\n")
	vs := f.run("F2", true)
	want(t, vs, "F2", "internal/winsvc/bad.go", `"ignore"`)
	want(t, vs, "F2", "internal/winsvc/c.go", `import "C"`)
}

func TestF2ToolchainDirectivesAgree(t *testing.T) {
	f := newFixture(t)
	f.write("svc/go.mod", "module svc.test\n\ngo 1.27.0\n\ntoolchain go1.27.3\n")
	f.m.Exceptions.ExtraGoModules = []Exception{{Path: "svc", ADR: "0001-technology-stack.md"}}
	want(t, f.run("F2", true), "F2", "svc/go.mod", "differs from go1.27.0")
	f.write("svc/go.mod", "module svc.test\n\ngo 1.27.0\n")
	none(t, f.run("F2", true))
	f.write("go.mod", "module fx.test\n\ngo 1.27.0\n\ntoolchain go1.27.3\n")
	f.write("svc/go.mod", "module svc.test\n\ngo 1.27.0\n\ntoolchain go1.27.3\n")
	none(t, f.run("F2", true))
}

func TestF2RustToolchainFileRequiredWhenNativeExists(t *testing.T) {
	f := newFixture(t)
	f.write("native/pf/README.txt", "x")
	want(t, f.run("F2", true), "F2", "native", "rust-toolchain.toml is missing")
	f.write("rust-toolchain.toml", "[toolchain]\nchannel = \"1.90.0\"\n")
	none(t, f.run("F2", true))
}

func TestF2CrossBuildFailsWhenACgoOnlyPackageCannotBuild(t *testing.T) {
	f := newFixture(t)
	f.write("internal/c/c.go", "package c\n\n// int one(void) { return 1; }\nimport \"C\"\n\nfunc One() int { return int(C.one()) }\n")
	f.write("cmd/server/main.go", "package main\n\nimport _ \"fx.test/internal/c\"\n\nfunc main() {}\n")
	vs := f.run("F2", false)
	want(t, vs, "F2", "go.mod", "CGO_ENABLED=0 go build ./... fails for linux/amd64")
	want(t, vs, "F2", "go.mod", "fails for windows/arm64")
	want(t, vs, "F2", "internal/c/c.go", `import "C"`)
}

func TestF2CrossBuildPassesOnPureGo(t *testing.T) {
	f := newFixture(t)
	f.m.BuildMatrix = []string{"linux/amd64", "linux/arm64", "windows/amd64", "windows/arm64", "darwin/arm64"}
	f.write("internal/a/a_windows.go", "package a\n\nconst OS = \"w\"\n")
	f.m.Exceptions.PlatformAdapters = []Exception{{Path: "internal/a", ADR: "0001-technology-stack.md"}}
	f.write("internal/a/a_other.go", "//go:build !windows\n\npackage a\n\nconst OS = \"o\"\n")
	none(t, f.run("F2", false))
}

func TestShippedManifestListsTheADRMatrix(t *testing.T) {
	var m Manifest
	b, _ := os.ReadFile("manifest.json")
	if err := strictDecode(b, &m); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(m.BuildMatrix, " "); got != "linux/amd64 linux/arm64 windows/amd64 windows/arm64 darwin/arm64" {
		t.Errorf("build matrix is %q; ADR-0001 rule 2 fixes it", got)
	}
	if got := strings.Join(m.TestTags, " "); got != "lab windowslab" {
		t.Errorf("test tags are %q; ADR-0001 rule 2 starts with lab and windowslab", got)
	}
}

// ---- F3 ------------------------------------------------------------------------------------

func withRedis(f *fixture) {
	f.write("go.mod", "module fx.test\n\ngo 1.27.0\n\nrequire github.com/redis/go-redis/v9 v9.0.0\n\nreplace github.com/redis/go-redis/v9 => ./third/redis\n")
	f.write("third/redis/go.mod", "module github.com/redis/go-redis/v9\n\ngo 1.27.0\n")
	f.write("third/redis/redis.go", "package redis\n\nconst X = 1\n")
	f.write("cmd/server/main.go", "package main\n\nimport _ \"github.com/redis/go-redis/v9\"\n\nfunc main() {}\n")
	f.write("knowledge/business/licensing/open-source-license-register.md", registerText+"| Redis (`github.com/redis/go-redis/v9`) | BSD | test | Embedded | Yes | **Clear** |\n")
}

func TestF3DenylistedDependencyNamesBinaryAndPackage(t *testing.T) {
	f := newFixture(t)
	withRedis(f)
	vs := f.run("F3", true)
	want(t, vs, "F3", "cmd/server", `binary "server"`)
	want(t, vs, "F3", "cmd/server", "github.com/redis/go-redis/v9")
	want(t, vs, "F3", "cmd/server", "second stateful service")
}

func TestF3IsPerBinary(t *testing.T) {
	f := newFixture(t)
	withRedis(f)
	f.write("cmd/server/main.go", "package main\n\nfunc main() {}\n")
	f.write("cmd/agent/main.go", "package main\n\nimport _ \"github.com/redis/go-redis/v9\"\n\nfunc main() {}\n")
	f.m.Binaries = append(f.m.Binaries, Binary{Name: "agent", Tier: "A", Package: "./cmd/agent"})
	vs := f.run("F3", true)
	want(t, vs, "F3", "cmd/agent", `binary "agent"`)
	for _, v := range vs {
		if strings.Contains(v.File, "cmd/server") {
			t.Errorf("server does not link the denylisted package, got %s", v)
		}
	}
}

func TestF3PrefixMatchesSubpackagesNotSiblings(t *testing.T) {
	f := newFixture(t)
	f.m.Denylist = []DenyEntry{{Prefix: "fx.test/internal/banned", Reason: "test"}}
	f.write("internal/banned/b.go", "package banned\n")
	f.write("internal/banned/deep/d.go", "package deep\n")
	f.write("internal/bannedish/b.go", "package bannedish\n")
	f.write("cmd/server/main.go", "package main\n\nimport (\n\t_ \"fx.test/internal/banned/deep\"\n\t_ \"fx.test/internal/bannedish\"\n)\n\nfunc main() {}\n")
	vs := f.run("F3", true)
	want(t, vs, "F3", "cmd/server", "fx.test/internal/banned/deep")
	if len(vs) != 1 {
		t.Errorf("only the sub-package should match; got:\n%s", dump(vs))
	}
}

func TestF3UndeclaredBinaryIsRejected(t *testing.T) {
	f := newFixture(t)
	f.write("cmd/newthing/main.go", "package main\n\nfunc main() {}\n")
	want(t, f.run("F3", true), "F3", "cmd/newthing/main.go", "not declared in manifest binaries")
}

func TestF3DenylistIsExtensibleFromAnotherJobsManifest(t *testing.T) {
	f := newFixture(t)
	f.write("internal/uemlike/u.go", "package uemlike\n")
	f.write("cmd/server/main.go", "package main\n\nimport _ \"fx.test/internal/uemlike\"\n\nfunc main() {}\n")
	none(t, f.run("F3", true))
	f.write("tools/fitness/profiles/denylist.json", `{"denylist":[{"prefix":"fx.test/internal/uemlike","reason":"UEM/PatchIQ module (U1)"}]}`)
	f.m.Extends = []string{"tools/fitness/profiles/denylist.json"}
	want(t, f.run("F3", true), "F3", "cmd/server", "UEM/PatchIQ module (U1)")
}

func TestF3ReportsAGoListFailure(t *testing.T) {
	f := newFixture(t)
	f.write("cmd/server/main.go", "package main\n\nimport _ \"example.invalid/missing\"\n\nfunc main() {}\n")
	want(t, f.run("F3", true), "F3", "go.mod", "go list -deps failed")
}

// ---- F4 ------------------------------------------------------------------------------------

func goModRequiring(deps ...string) string {
	s := "module fx.test\n\ngo 1.27.0\n\nrequire (\n"
	for _, d := range deps {
		s += "\t" + d + " v1.0.0\n"
	}
	s += ")\n"
	for _, d := range deps {
		s += "\nreplace " + d + " => ./third/" + strings.ReplaceAll(d, "/", "_") + "\n"
	}
	return s
}

func localModule(f *fixture, path, licence string) {
	dir := "third/" + strings.ReplaceAll(path, "/", "_")
	f.write(dir+"/go.mod", "module "+path+"\n\ngo 1.27.0\n")
	f.write(dir+"/x.go", "package x\n")
	if licence != "" {
		f.write(dir+"/LICENSE", licence)
	}
}

func TestF4DirectGoDependency(t *testing.T) {
	cases := []struct {
		name, dep, msg string
	}{
		{"no register row", "example.com/unknown", "no licence-register row"},
		{"row marked Rejected", "example.com/bad", "marked Rejected"},
		{"path only in a Use cell", "example.com/only-in-use-column", "no licence-register row"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.write("go.mod", goModRequiring(tc.dep))
			localModule(f, tc.dep, "MIT License\n")
			f.write("cmd/server/main.go", "package main\n\nfunc main() {}\n")
			want(t, f.run("F4", true), "F4", "go.mod", tc.msg)
		})
	}
	t.Run("registered, and indirect needs no row", func(t *testing.T) {
		f := newFixture(t)
		f.write("go.mod", goModRequiring("example.com/good")+"\nrequire example.com/indirect v1.0.0 // indirect\nreplace example.com/indirect => ./third/ind\n")
		localModule(f, "example.com/good", "MIT License\n")
		f.write("third/ind/go.mod", "module example.com/indirect\n\ngo 1.27.0\n")
		none(t, f.run("F4", true))
	})
}

func TestF4TransitiveCopyleftInAShippedBinary(t *testing.T) {
	gpl := "                    GNU GENERAL PUBLIC LICENSE\n                       Version 3, 29 June 2007\n"
	agpl := "                    GNU AFFERO GENERAL PUBLIC LICENSE\n                       Version 3, 19 November 2007\n"
	lgpl := "                   GNU LESSER GENERAL PUBLIC LICENSE\n  This version of the GNU Lesser General Public License incorporates the terms of the GNU General Public License.\n"
	for _, tc := range []struct{ name, text, fam string }{
		{"GPL", gpl, "GPL"}, {"AGPL", agpl, "AGPL"},
		{"SSPL", "Server Side Public License\nVERSION 1, OCTOBER 16, 2018\n", "SSPL"},
		{"Elastic", "Elastic License 2.0\n\nURL: https://www.elastic.co/licensing/elastic-license\n", "Elastic"},
		{"BUSL", "Business Source License 1.1\n", "BUSL"},
		{"SPDX line", "Copyright 2026 Someone\nSPDX-License-Identifier: GPL-3.0-only\n", "GPL-3.0-only"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.write("go.mod", goModRequiring("example.com/good", "example.com/deep"))
			localModule(f, "example.com/good", "MIT License\n")
			// good imports deep, which carries the copyleft licence: the closure, not just direct deps.
			f.write("third/example.com_good/x.go", "package x\n\nimport _ \"example.com/deep\"\n")
			localModule(f, "example.com/deep", tc.text)
			f.write("cmd/server/main.go", "package main\n\nimport _ \"example.com/good\"\n\nfunc main() {}\n")
			vs := f.run("F4,F3", true)
			want(t, vs, "F4", "go.mod", "example.com/deep")
			want(t, vs, "F4", "go.mod", tc.fam)
		})
	}
	t.Run("LGPL, MPL and permissive licences pass", func(t *testing.T) {
		f := newFixture(t)
		f.write("go.mod", goModRequiring("example.com/good", "example.com/lgpl"))
		localModule(f, "example.com/good", "MIT License\n")
		f.write("third/example.com_good/x.go", "package x\n\nimport _ \"example.com/lgpl\"\n")
		localModule(f, "example.com/lgpl", lgpl)
		f.write("cmd/server/main.go", "package main\n\nimport _ \"example.com/good\"\n\nfunc main() {}\n")
		f.write("knowledge/business/licensing/open-source-license-register.md", registerText+"| L (`example.com/lgpl`) | LGPL | t | Embedded | Yes | **Check** |\n")
		none(t, f.run("F4", true))
	})
	t.Run("a copyleft module no binary links is not shipped", func(t *testing.T) {
		f := newFixture(t)
		f.write("go.mod", goModRequiring("example.com/good", "example.com/deep"))
		localModule(f, "example.com/good", "MIT License\n")
		localModule(f, "example.com/deep", gpl)
		f.write("cmd/server/main.go", "package main\n\nimport _ \"example.com/good\"\n\nfunc main() {}\n")
		f.write("knowledge/business/licensing/open-source-license-register.md", registerText+"| D (`example.com/deep`) | GPL | t | Embedded | No | **Clear** |\n")
		none(t, f.run("F4", true))
	})
	t.Run("a declared licence exception is honoured", func(t *testing.T) {
		f := newFixture(t)
		f.write("go.mod", goModRequiring("example.com/good"))
		localModule(f, "example.com/good", gpl)
		f.write("cmd/server/main.go", "package main\n\nimport _ \"example.com/good\"\n\nfunc main() {}\n")
		want(t, f.run("F4", true), "F4", "go.mod", "example.com/good")
		f.m.LicenceExcepts = []LicenceExcept{{Module: "example.com/good", ADR: "0003-accepted.md", Reason: "test"}}
		none(t, f.run("F4,F5", true))
	})
}

func TestF4WebDependencies(t *testing.T) {
	f := newFixture(t)
	f.write("web/package.json", `{"dependencies":{"react":"1.0.0","left-pad":"1.0.0"},"devDependencies":{"@scope/pkg":"1.0.0","dev-only-unregistered":"1.0.0"}}`)
	vs := f.run("F4", true)
	want(t, vs, "F4", "web/package.json", "left-pad")
	want(t, vs, "F4", "web/package.json", "dev-only-unregistered")
	for _, v := range vs {
		if strings.Contains(v.Msg, "react") || strings.Contains(v.Msg, "@scope/pkg") {
			t.Errorf("registered package reported: %s", v)
		}
	}
}

func TestF4WebTransitiveLicences(t *testing.T) {
	f := newFixture(t)
	f.write("web/package.json", `{"dependencies":{"react":"1.0.0"}}`)
	f.write("web/package-lock.json", `{"packages":{
	  "": {"name":"web"},
	  "node_modules/react": {"license":"MIT"},
	  "node_modules/react/node_modules/gpl-lib": {"license":"GPL-3.0-or-later"},
	  "node_modules/dev-gpl": {"license":"GPL-3.0-only","dev":true},
	  "node_modules/dual": {"license":"(MIT OR GPL-2.0)"},
	  "node_modules/agpl": {"license":"AGPL-3.0"},
	  "node_modules/lgpl": {"license":"LGPL-3.0-only"}}}`)
	vs := f.run("F4", true)
	want(t, vs, "F4", "web/package-lock.json", "gpl-lib under GPL-3.0-or-later")
	want(t, vs, "F4", "web/package-lock.json", "agpl under AGPL-3.0")
	for _, v := range vs {
		for _, ok := range []string{"dev-gpl", "dual", "lgpl"} {
			if strings.Contains(v.Msg, "includes "+ok+" ") {
				t.Errorf("%s should pass: %s", ok, v)
			}
		}
	}
}

func TestF4RustDependencies(t *testing.T) {
	f := newFixture(t)
	f.write("native/pf/Cargo.toml", `[package]
name = "pf"
version = "0.1.0"

[dependencies]
windows = { version = "0.62", features = ["Win32_Foundation"] }
mystery = "1"
own = { path = "../own" }
inherited.workspace = true
renamed = { package = "other-name", version = "2" }

[dependencies.tabled]
version = "1"

[dev-dependencies]
dev-mystery = "1"

[target.'cfg(windows)'.dependencies]
winonly = "1"
`)
	vs := f.run("F4", true)
	for _, d := range []string{"mystery", "other-name", "tabled", "dev-mystery", "winonly"} {
		want(t, vs, "F4", "native/pf/Cargo.toml", "dependency "+d+" ")
	}
	for _, v := range vs {
		for _, ok := range []string{"dependency windows ", "dependency own ", "dependency inherited ", "dependency renamed ", "dependency path "} {
			if strings.Contains(v.Msg, ok) {
				t.Errorf("should not be reported: %s", v)
			}
		}
	}
}

func TestF4RustTransitiveLicences(t *testing.T) {
	src := "registry+https://github.com/rust-lang/crates.io-index"
	md := `{"packages":[
	  {"name":"ours","version":"0.1.0","license":"LicenseRef-Proprietary","source":null},
	  {"name":"fine","version":"1.0.0","license":"MIT OR Apache-2.0","source":"` + src + `"},
	  {"name":"dual","version":"1.0.0","license":"GPL-2.0-only OR MIT","source":"` + src + `"},
	  {"name":"copyleft","version":"2.3.4","license":"GPL-3.0-only","source":"` + src + `"},
	  {"name":"nolicence","version":"1.0.0","license":null,"source":"` + src + `"}]}`
	vs := cargoLicenceViolations("native/pf/Cargo.toml", []byte(md), func(string) bool { return false })
	if len(vs) != 1 || !strings.Contains(vs[0].Msg, "copyleft 2.3.4 under GPL-3.0-only") {
		t.Fatalf("got:\n%s", dump(vs))
	}
	if vs := cargoLicenceViolations("x", []byte(md), func(n string) bool { return n == "copyleft" }); len(vs) != 0 {
		t.Errorf("an exempt crate should pass:\n%s", dump(vs))
	}
}

func TestF4RustTransitiveWithRealCargo(t *testing.T) {
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("cargo is not installed")
	}
	f := newFixture(t)
	f.write("rust-toolchain.toml", "[toolchain]\nchannel = \"stable\"\n")
	f.write("native/pf/Cargo.toml", "[package]\nname = \"pf\"\nversion = \"0.1.0\"\nedition = \"2021\"\n")
	f.write("native/pf/src/lib.rs", "")
	f.m.Exceptions.NativeComponents = []Exception{{Path: "native/pf", ADR: "0001-technology-stack.md", Tier: "N", Platform: "windows"}}
	none(t, f.run("F4", true))
	f.write("native/pf/Cargo.toml", "[package]\nname = \"pf\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nbroken = { path = \"../missing\" }\n")
	want(t, f.run("F4", true), "F4", "native/pf/Cargo.toml", "cargo metadata failed")
}

func TestF4NugetAndSidecars(t *testing.T) {
	f := newFixture(t)
	f.write("sidecars/exo/exo.csproj", `<Project><ItemGroup><PackageReference Include="Some.Package" Version="1" /><PackageReference Include="Unregistered.Pkg" Version="1" /></ItemGroup></Project>`)
	f.m.Exceptions.Sidecars = []Exception{{Path: "sidecars/exo", ADR: "0001-technology-stack.md"}}
	vs := f.run("F4", true)
	want(t, vs, "F4", "exo.csproj", "Unregistered.Pkg")
	want(t, vs, "F4", "manifest.json", "transitive NuGet licence scan is not built")
}

func TestF4ThirdPartyNeedsRowAndLicenceFile(t *testing.T) {
	f := newFixture(t)
	f.write("third_party/copied/a.go", "package copied\n")
	f.write("third_party/other/b.go", "package other\n")
	f.write("third_party/other/LICENSE", "MIT\n")
	f.m.Exceptions.ThirdParty = []Exception{
		{Path: "third_party/copied", ADR: "0001-technology-stack.md"},
		{Path: "third_party/other", ADR: "0001-technology-stack.md"},
	}
	vs := f.run("F4", true)
	want(t, vs, "F4", "third_party/copied", "no LICENSE file")
	want(t, vs, "F4", "third_party/other", "no licence-register row")
	f.write("third_party/copied/LICENSE", "MIT\n")
	vs = f.run("F4", true)
	if len(vs) != 1 {
		t.Errorf("only third_party/other should still fail:\n%s", dump(vs))
	}
}

func TestSPDXAndLicenceText(t *testing.T) {
	for expr, blocked := range map[string]bool{
		"MIT": false, "Apache-2.0": false, "LGPL-3.0-only": false, "MPL-2.0": false, "BlueOak-1.0.0": false,
		"GPL-3.0-only": true, "GPL-2.0+": true, "AGPL-3.0-or-later": true, "SSPL-1.0": true, "Elastic-2.0": true, "BUSL-1.1": true,
		"(MIT OR GPL-2.0)": false, "(GPL-2.0 OR AGPL-3.0)": true, "MIT AND GPL-3.0-only": true, "GPL-2.0 WITH Classpath-exception-2.0": true,
		"": false, "UNLICENSED": false, "SEE LICENSE IN LICENSE": false,
	} {
		if got := spdxBlocked(expr); got != blocked {
			t.Errorf("spdxBlocked(%q) = %v, want %v", expr, got, blocked)
		}
	}
	if got := classifyLicenceText("MIT License\n\nCopyright (c) 2026\n\nPermission is hereby granted... GNU General Public License is a different thing"); got != "" {
		t.Errorf("an MIT text that only mentions the GPL deep inside must not be flagged, got %q", got)
	}
}

func TestRegisterParsing(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "r.md")
	if err := os.WriteFile(p, []byte(registerText), 0o644); err != nil {
		t.Fatal(err)
	}
	reg, err := loadRegister(p)
	if err != nil {
		t.Fatal(err)
	}
	for pkg, want := range map[string]string{
		"example.com/good": "", "example.com/bad": "has a licence-register row marked Rejected",
		"react": "", "@scope/pkg": "", "example.com/nope": "has no licence-register row whose Project cell carries its exact path in backticks",
		"example.com/good/sub": "has no licence-register row whose Project cell carries its exact path in backticks",
	} {
		if got := reg.problem(pkg); got != want {
			t.Errorf("problem(%q) = %q, want %q", pkg, got, want)
		}
	}
}

// ---- F5 ------------------------------------------------------------------------------------

func TestF5Exceptions(t *testing.T) {
	cases := []struct{ name, adr, msg string }{
		{"no ADR named", "", "names no ADR"},
		{"ADR file missing", "0042-nothing.md", "does not exist"},
		{"ADR still proposed", "0009-draft.md", `status is "proposed"`},
		{"path traversal", "../../../README.md", "not an ADR file name"},
		{"not a markdown file", "0001-technology-stack", "not an ADR file name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.write("internal/winsvc/a.go", "package winsvc\n")
			f.m.Exceptions.PlatformAdapters = []Exception{{Path: "internal/winsvc", ADR: tc.adr}}
			want(t, f.run("F5", true), "F5", "manifest.json", tc.msg)
		})
	}
	for _, status := range []string{"ratified", "accepted"} {
		t.Run(status+" ADR is enough", func(t *testing.T) {
			f := newFixture(t)
			f.write("internal/winsvc/a.go", "package winsvc\n")
			f.write("knowledge/development/decisions/0005-x.md", adrText(status))
			f.m.Exceptions.PlatformAdapters = []Exception{{Path: "internal/winsvc", ADR: "0005-x.md"}}
			none(t, f.run("F5", true))
		})
	}
	for _, status := range []string{"superseded", "withdrawn", "template", "draft"} {
		t.Run(status+" ADR is refused", func(t *testing.T) {
			f := newFixture(t)
			f.write("internal/winsvc/a.go", "package winsvc\n")
			f.write("knowledge/development/decisions/0005-x.md", adrText(status))
			f.m.Exceptions.PlatformAdapters = []Exception{{Path: "internal/winsvc", ADR: "0005-x.md"}}
			want(t, f.run("F5", true), "F5", "manifest.json", `status is "`+status+`"`)
		})
	}
}

func TestF5EveryExceptionKindIsChecked(t *testing.T) {
	f := newFixture(t)
	for _, p := range []string{"a", "b", "c", "d", "e", "g", "h", "i"} {
		f.write(p+"/x.txt", "x")
	}
	bad := func(p string) Exception { return Exception{Path: p, ADR: "0009-draft.md"} }
	x := &f.m.Exceptions
	x.PlatformAdapters = []Exception{bad("a")}
	x.Sidecars = []Exception{bad("b")}
	x.CppFallbacks = []Exception{bad("c")}
	x.ExtraGoModules = []Exception{bad("d")}
	x.ThirdParty = []Exception{bad("e")}
	x.BuildScripts = []Exception{bad("g/x.txt")}
	x.DevNodeTools = []Exception{bad("h")}
	x.NativeComponents = []Exception{bad("i")}
	f.m.LicenceExcepts = []LicenceExcept{{Module: "m", ADR: "0009-draft.md"}}
	vs := f.run("F5", true)
	for _, kind := range []string{"platformAdapters", "sidecars", "cppFallbacks", "extraGoModules", "thirdParty", "buildScripts", "devNodeTools", "nativeComponents", "licenceExceptions"} {
		want(t, vs, "F5", "manifest.json", kind)
	}
}

func TestF5StaleEntryAndUndeclaredThirdParty(t *testing.T) {
	f := newFixture(t)
	f.m.Exceptions.Sidecars = []Exception{{Path: "sidecars/gone", ADR: "0001-technology-stack.md"}}
	f.write("third_party/sneaky/a.go", "package sneaky\n")
	vs := f.run("F5", true)
	want(t, vs, "F5", "manifest.json", "path does not exist")
	want(t, vs, "F5", "third_party/sneaky", "not declared")
}

func TestManifestRejectsUnknownFields(t *testing.T) {
	f := newFixture(t)
	f.write("manifest.json", `{"decisionsDir":"d","licenceRegister":"r","surprise":1}`)
	if _, err := LoadManifest(f.root, "manifest.json"); err == nil || !strings.Contains(err.Error(), "surprise") {
		t.Errorf("an unknown manifest key must be an error, got %v", err)
	}
}

func TestTheRealTreeIsGreenWhenGitIsAvailable(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Skip("not inside the repository")
	}
	vs, err := Run(root, defaultManifest, []string{"F1", "F2", "F3", "F4", "F5"}, true)
	if err != nil {
		t.Fatal(err)
	}
	none(t, vs)
}
