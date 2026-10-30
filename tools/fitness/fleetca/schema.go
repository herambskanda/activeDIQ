package main

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var sealedCheck = regexp.MustCompile(`(?is)\bCHECK\s*\([^;]*\bsealed_key\b`)

// checkSchema is FCS-5 on the migrations: fleet_server_ca is installation scope (no tenant_id, ever added
// later either) and its sealed_key is guarded by a CHECK as fleet_ca's is. It returns whether the table
// exists, so the Go checks can demand the signer.
func checkSchema(root string) (vs []Violation, pending []string, present bool, err error) {
	names, err := filepath.Glob(filepath.Join(root, "migrations", "*.sql"))
	if err != nil {
		return nil, nil, false, err
	}
	sort.Strings(names)
	var stmts []string
	var where []string
	for _, n := range names {
		b, err := os.ReadFile(n)
		if err != nil {
			return nil, nil, false, err
		}
		for _, s := range strings.Split(stripSQLComments(string(b)), ";") {
			if strings.Contains(s, "fleet_server_ca") {
				stmts = append(stmts, s)
				where = append(where, filepath.Base(n))
			}
		}
	}
	if len(stmts) == 0 {
		return nil, []string{"FCS-5 fleet_server_ca schema (migration not landed: server CA migration ticket)"}, false, nil
	}
	var hasCheck bool
	for i, s := range stmts {
		if regexp.MustCompile(`(?i)\btenant_id\b`).MatchString(s) {
			vs = append(vs, Violation{"FCS-5", "tenant-id", where[i], "fleet_server_ca is installation scope: no tenant_id column"})
		}
		if sealedCheck.MatchString(s) {
			hasCheck = true
		}
	}
	if !hasCheck {
		vs = append(vs, Violation{"FCS-5", "sealed-key-check", where[0], "fleet_server_ca has no CHECK on sealed_key (the key is erased on retire and never in clear), as fleet_ca has"})
	}
	return vs, nil, true, nil
}

func stripSQLComments(s string) string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if i := strings.Index(l, "--"); i >= 0 {
			l = l[:i]
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}
