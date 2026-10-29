package main

import (
	"encoding/xml"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// T-0762: the WiX SDK builds the MSI through MSBuild, so anything MSBuild runs after the rules above have
// judged the sources (a Target/Exec running msitran or MsiDb, a custom task, an imported .targets, a .mst
// transform) can rewrite the built MSI. None of that is approvable via installer-allow.txt.

// msiOpaqueExts are MSI transforms, patches and patch creation files: opaque databases that add or change
// CustomAction, ServiceInstall and sequence rows in the built MSI.
var msiOpaqueExts = setOf(".mst", ".msp", ".pcp")

var msbuildExts = setOf(".props", ".targets", ".proj", ".wixproj", ".rsp")

// msbuildForbiddenElems run or import code: a Target (and so every task in it), Exec, UsingTask (custom or
// inline task assemblies), Import of anything but an SDK, and the item/property hooks that run targets.
var msbuildForbiddenElems = setOf("target", "exec", "usingtask", "importgroup", "task", "inlinetask", "taskfactory",
	"customtask", "projectextensions", "onerror", "calltarget", "msbuild", "cl", "invoketask")

// msbuildForbiddenProps are properties that inject targets or run commands without a Target element.
var msbuildForbiddenProps = setOf("prebuildevent", "postbuildevent", "prebuildeventdependson", "postbuildeventdependson",
	"builddependson", "compiledependson", "linkdependson", "targetstriggeredbycompilation", "customafterdirectorybuildtargets",
	"customafterdirectorybuildprops", "custombeforedirectorybuildtargets", "custombeforedirectorybuildprops",
	"wixtargetspath", "wixtoolpath", "wixsdkpath", "msbuildprojectextensionspath", "customafterwixtargets", "custombeforewixtargets")

func isMSBuildFile(p string) bool {
	return msbuildExts[strings.ToLower(filepath.Ext(p))]
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
		if isRepoWix(p) {
			wixDirs = append(wixDirs, filepath.ToSlash(filepath.Dir(rel)))
		}
		if isMSBuildFile(p) || isDirectoryBuild(p) {
			cands = append(cands, rel)
		}
		return nil
	})
	for _, rel := range cands {
		dir := filepath.ToSlash(filepath.Dir(rel))
		if !msbuildReachesWix(rel, dir, wixDirs) {
			continue
		}
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			out = append(out, fmt.Sprintf("%s is an MSBuild file that cannot be read (%v): it could run a post-build step on the MSI (T-0762)", rel, err))
			continue
		}
		out = append(out, judgeMSBuild(rel, b)...)
	}
	return out
}

// msbuildReachesWix: a .wixproj always counts; any other MSBuild file counts when it sits under packaging/,
// or in a directory at or above a WiX source (Directory.Build.* applies to everything below it).
func msbuildReachesWix(rel, dir string, wixDirs []string) bool {
	if strings.HasSuffix(strings.ToLower(rel), ".wixproj") || strings.HasPrefix(rel, "packaging/") {
		return true
	}
	for _, w := range wixDirs {
		if dir == "." || w == dir || strings.HasPrefix(w, dir+"/") {
			return true
		}
	}
	return false
}

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
	if strings.Contains(text, "$([") {
		add("uses an MSBuild property function $([...])")
	}
	d := xml.NewDecoder(strings.NewReader(text))
	d.Strict = false
	d.CharsetReader = func(_ string, r io.Reader) (io.Reader, error) { return r, nil }
	depth := 0
	for {
		tok, err := d.RawToken()
		if err != nil {
			if err != io.EOF {
				add("is not well-formed XML, so it cannot be judged")
			}
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			n := strings.ToLower(t.Name.Local)
			switch {
			case n == "import":
				if attrOf(t, "sdk") == "" || !strings.HasPrefix(attrOf(t, "project"), "Sdk.") {
					add("has an Import of a non-SDK file")
				}
			case n == "project" || n == "sdk":
				for _, a := range t.Attr {
					if strings.EqualFold(a.Name.Local, "sdk") || n == "sdk" && strings.EqualFold(a.Name.Local, "name") {
						if !strings.HasPrefix(a.Value, "WixToolset.Sdk/") && !strings.HasPrefix(a.Value, "Microsoft.Build.NoTargets/") {
							add(fmt.Sprintf("uses SDK %q: only the pinned WiX SDK is reviewed", a.Value))
						}
					}
				}
			case msbuildForbiddenElems[n]:
				add(fmt.Sprintf("has a %s element", t.Name.Local))
			case msbuildForbiddenProps[n] || strings.HasPrefix(n, "custombefore") || strings.HasPrefix(n, "customafter"):
				add(fmt.Sprintf("sets %s, a hook that runs targets or commands", t.Name.Local))
			}
			for _, a := range t.Attr {
				switch strings.ToLower(a.Name.Local) {
				case "aftertargets", "beforetargets", "dependsontargets", "initialtargets", "defaulttargets", "inputs", "outputs":
					add(fmt.Sprintf("%s has a %s attribute", t.Name.Local, a.Name.Local))
				}
			}
		case xml.EndElement:
			depth--
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
