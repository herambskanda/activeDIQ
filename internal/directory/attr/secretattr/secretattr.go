// Package secretattr holds the static half of SecretAttrs (safe-primitives §3.7, X4): the directory
// attributes whose values are secrets whether or not an estate's schema flags them. The other half is
// schema-driven (searchFlags 0x80, 0x200 or 0x1000) and is computed at connect by the connector.
//
// The static list is the one source for everything that must recognise a secret attribute by name,
// the fitness-domain-keys check (no column named for one outside the sealed allow-list) among them.
package secretattr

import "github.com/skenzeriq/activediq/internal/platform/secret"

// Static returns a copy of the static list. The list itself lives in internal/platform/secret, where
// the operation runner (which may not import this package) reads it: there is one copy.
func Static() []string { return secret.StaticAttrs() }
