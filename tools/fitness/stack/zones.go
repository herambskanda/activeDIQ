package main

import (
	"bufio"
	"fmt"
	"os"
	"path"
	"strings"
)

var extLang = map[string]string{
	".go": "go", ".rs": "rust",
	".c": "c", ".cc": "c", ".cpp": "c", ".cxx": "c", ".h": "c", ".hh": "c", ".hpp": "c", ".hxx": "c",
	".cs": "csharp", ".csproj": "csharp", ".vbproj": "csharp", ".fsproj": "csharp", ".sln": "csharp",
	".py": "python", ".ps1": "powershell", ".psm1": "powershell", ".psd1": "powershell",
	".sh": "shell", ".bash": "shell", ".zsh": "shell",
	".ts": "typescript", ".tsx": "typescript", ".mts": "typescript", ".cts": "typescript",
	".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
	".java": "java", ".kt": "kotlin", ".kts": "kotlin", ".rb": "ruby", ".php": "php", ".lua": "lua",
	".bat": "batch", ".cmd": "batch", ".vbs": "vbscript", ".swift": "swift", ".pl": "perl",
	".m": "objective-c", ".mm": "objective-c",
}

// shebangLang names the language of an extensionless script from its interpreter, so a script
// without an extension cannot slip past the zones.
func shebangLang(line string) string {
	fields := strings.Fields(strings.TrimPrefix(line, "#!"))
	if len(fields) == 0 {
		return ""
	}
	interp := path.Base(fields[0])
	if interp == "env" {
		for _, f := range fields[1:] {
			if !strings.HasPrefix(f, "-") && !strings.Contains(f, "=") {
				interp = path.Base(f)
				break
			}
		}
	}
	switch {
	case interp == "sh" || interp == "bash" || interp == "zsh" || interp == "dash" || interp == "ksh":
		return "shell"
	case strings.HasPrefix(interp, "python"):
		return "python"
	case interp == "pwsh" || interp == "powershell":
		return "powershell"
	case interp == "node" || interp == "deno" || interp == "bun":
		return "javascript"
	case strings.HasPrefix(interp, "ruby"):
		return "ruby"
	case strings.HasPrefix(interp, "php"):
		return "php"
	case strings.HasPrefix(interp, "perl"):
		return "perl"
	case strings.HasPrefix(interp, "lua"):
		return "lua"
	}
	return ""
}

func (c *Ctx) languageOf(f string) string {
	ext := strings.ToLower(path.Ext(f))
	if l, ok := extLang[ext]; ok {
		return l
	}
	if ext != "" {
		return ""
	}
	fh, err := os.Open(c.abs(f))
	if err != nil {
		return ""
	}
	defer fh.Close()
	line, _ := bufio.NewReaderSize(fh, 256).ReadString('\n')
	if strings.HasPrefix(line, "#!") {
		return shebangLang(strings.TrimSpace(line))
	}
	return ""
}

// checkZones is F1 (ADR-0001 rule 1): every source file's language must be allowed in its zone. It
// is an allowlist per zone, not an extension denylist, so a language the table knows is rejected
// wherever it is not named, and a file whose language is banned is rejected everywhere.
func (c *Ctx) checkZones() []Violation {
	var vs []Violation
	m := c.M
	add := func(f, msg string) { vs = append(vs, Violation{"F1", f, msg}) }
	banned := map[string]bool{}
	for _, b := range m.Banned {
		banned[b] = true
	}
	nativeRoots := m.LanguageZones["rust"].Allow

	for _, e := range m.Exceptions.NativeComponents {
		if e.Tier != "N" || e.Platform != "windows" {
			add(c.ManifestPath, fmt.Sprintf("native component %q must be declared tier \"N\" on platform \"windows\" (found tier %q, platform %q); non-Windows logon components need their own ADR before the manifest accepts them", e.Path, e.Tier, e.Platform))
		}
		if !underAny(e.Path, nativeRoots) {
			add(c.ManifestPath, fmt.Sprintf("native component %q is outside the native zone %v", e.Path, nativeRoots))
		}
	}

	for _, f := range c.Files {
		base := path.Base(f)
		switch {
		case base == "go.mod":
			if f != "go.mod" && !underAny(path.Dir(f), exceptionPaths(m.Exceptions.ExtraGoModules)) {
				add(f, "go.mod outside the root zone and not declared in manifest exceptions.extraGoModules")
			}
			continue
		case base == "package.json":
			if !underAny(f, m.LanguageZones["typescript"].Allow) && !underAny(f, exceptionPaths(m.Exceptions.DevNodeTools)) {
				add(f, fmt.Sprintf("package.json outside the web zone %v and not declared in manifest exceptions.devNodeTools", m.LanguageZones["typescript"].Allow))
			}
			continue
		case base == "Cargo.toml":
			if !underAny(f, nativeRoots) {
				add(f, fmt.Sprintf("Cargo.toml outside the native zone %v", nativeRoots))
			} else if !underAny(f, exceptionPaths(m.Exceptions.NativeComponents)) {
				add(f, "crate is not a declared tier-N Windows component (manifest exceptions.nativeComponents cites the ADR that allows it)")
			}
			continue
		}
		lang := c.languageOf(f)
		if lang == "" {
			continue
		}
		if banned[lang] {
			add(f, fmt.Sprintf("%s source is not an allowed language anywhere in the product; non-Windows logon components (PAM, macOS) need their own ADR first", lang))
			continue
		}
		zone, ok := m.LanguageZones[lang]
		if !ok {
			add(f, fmt.Sprintf("%s has no zone in the manifest languageZones, so it is not allowed anywhere", lang))
			continue
		}
		if msg := c.zoneViolation(f, lang, zone); msg != "" {
			add(f, msg)
		}
	}
	return vs
}

func (c *Ctx) zoneViolation(f, lang string, zone Zone) string {
	x := c.M.Exceptions
	if underAny(f, zone.Deny) {
		return fmt.Sprintf("%s source is not allowed under %v", lang, zone.Deny)
	}
	inZone := zone.Anywhere || underAny(f, zone.Allow)
	switch lang {
	case "python", "powershell", "shell":
		if !inZone && !underAny(f, exceptionPaths(x.BuildScripts)) {
			return fmt.Sprintf("%s outside %v; a build script elsewhere must be named in manifest exceptions.buildScripts", lang, zone.Allow)
		}
	case "javascript", "typescript":
		if !inZone && !underAny(f, exceptionPaths(x.DevNodeTools)) {
			return fmt.Sprintf("%s outside %v; a build-time-only Node tool must be declared in manifest exceptions.devNodeTools", lang, zone.Allow)
		}
	case "c":
		if !inZone {
			return fmt.Sprintf("C/C++ outside %v", zone.Allow)
		}
		if !underAny(f, exceptionPaths(x.CppFallbacks)) {
			return "C/C++ is allowed only for a component recorded as a C++ fallback (rule 4): declare it in manifest exceptions.cppFallbacks citing the ADR amendment"
		}
	case "csharp":
		if !inZone {
			return fmt.Sprintf("C# or project file outside %v", zone.Allow)
		}
		if !underAny(f, exceptionPaths(x.Sidecars)) {
			return "C# is allowed only in a sidecar declared in manifest exceptions.sidecars"
		}
	case "rust":
		if !inZone {
			return fmt.Sprintf("Rust outside %v", zone.Allow)
		}
		if !underAny(f, exceptionPaths(x.NativeComponents)) {
			return "Rust file is not inside a declared tier-N Windows component (manifest exceptions.nativeComponents)"
		}
	default:
		if !inZone {
			return fmt.Sprintf("%s outside %v", lang, zone.Allow)
		}
	}
	return ""
}
