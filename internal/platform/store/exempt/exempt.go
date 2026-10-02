// Package exempt embeds the tenancy exemption registry of ADR-0002 (rule 4): the one list of global
// tables, SECURITY DEFINER functions, platform-scope call sites and platform jobs that may sit outside
// the tenant rules, each with a reason (and, for a global table, the one package whose SQL may name it).
//
// registry.json is the single source. fitness-tenancy (tools/fitness/tenancy) reads this same file by
// path, so there is no second list to drift; the product embeds it so the binary carries the registry it
// was built and checked against. A new global table, platform path or job is an entry here, reviewed
// with the change that needs it.
package exempt

import _ "embed"

// JSON is the registry document, exactly as checked into the repository.
//
//go:embed registry.json
var JSON []byte
