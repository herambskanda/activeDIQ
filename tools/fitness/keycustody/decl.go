package main

import (
	"regexp"
)

var (
	declTenantKeys = regexp.MustCompile(`(?s)tablekind\.Declare\(tablekind\.Table\{[^\n]*Name:\s*"public\.tenant_keys".*?\)\n`)
	sealedWrapped  = regexp.MustCompile(`Sealed:\s*\[\]string\{[^}]*"wrapped_dek"`)
	declKEK        = regexp.MustCompile(`(?s)tablekind\.Declare\(tablekind\.Table\{[^\n]*Name:\s*"public\.installation_kek".*?\)\n`)
	kekPlatform    = regexp.MustCompile(`Kind:\s*tablekind\.Platform`)
)

// checkDeclarations is the static half of FF-KEY-1: tenant_keys is declared with Sealed: wrapped_dek,
// and installation_kek, once it exists, is declared a platform (global) table.
func checkDeclarations(files []goFile) []Violation {
	var vs []Violation
	var tk, kek string
	for _, g := range files {
		if g.Test || !g.in(keysDir) {
			continue
		}
		if m := declTenantKeys.FindString(g.Source); m != "" {
			tk = m
		}
		if m := declKEK.FindString(g.Source); m != "" {
			kek = m
		}
	}
	if tk == "" {
		vs = append(vs, Violation{"FF-KEY-1", "declaration", keysDir, "tenant_keys has no tablekind.Declare in the keys package"})
	} else if !sealedWrapped.MatchString(tk) {
		vs = append(vs, Violation{"FF-KEY-1", "sealed-declaration", keysDir, "the tenant_keys declaration lacks Sealed: wrapped_dek"})
	}
	if kek != "" && !kekPlatform.MatchString(kek) {
		vs = append(vs, Violation{"FF-KEY-1", "global-declaration", keysDir, "installation_kek is declared but not as a platform (registered-global) table"})
	}
	return vs
}
