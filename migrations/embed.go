// Package migrations holds the product's one forward-only SQL sequence, NNNN_<owner>_<what>.sql
// (blueprint §1, ADR-0003 rule 6), embedded in the binary. It is a leaf: it imports only the standard
// library, and only compose/server imports it, to hand the files to the update step.
package migrations

import "embed"

// FS holds every migration file at its root.
//
//go:embed *.sql
var FS embed.FS
