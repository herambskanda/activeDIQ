// Package migrations holds the product's one forward-only SQL sequence, NNNN_<owner>_<what>.sql
// (blueprint §1, ADR-0003 rule 6), embedded in the binary. It is a leaf: it imports only the standard
// library, and only compose/server imports it, to hand the files to the update step.
package migrations

import (
	"embed"
	"strings"
)

// FS holds every migration file at its root.
//
//go:embed *.sql
var FS embed.FS

// afterPrefix marks a line of a migration file as a statement the runner executes on its own after the
// file's transaction has committed: what cannot run inside a transaction (VACUUM). The file is run as one
// multi-statement execution, which PostgreSQL wraps in a transaction.
const afterPrefix = "-- after: "

// After returns the statements of a migration file's "-- after:" lines, in order. A line is one complete
// statement, repository content and never input.
func After(sql string) []string {
	var out []string
	for _, l := range strings.Split(sql, "\n") {
		if rest, ok := strings.CutPrefix(l, afterPrefix); ok && strings.TrimSpace(rest) != "" {
			out = append(out, strings.TrimSpace(rest))
		}
	}
	return out
}
