// Package tenant defines tenant.ID, the identity every tenant-scoped operation carries (ADR-0002
// "Where tenancy lives", rule 5). It also owns the tenants table: only SQL in this package and its
// subpackages may name public.tenants (the exemption registry's owning package).
//
// A tenant ID is minted, never parsed from input. The constructors below are the only ways to make one,
// and the fitness-tenancy check T5 allows a call to them only from the authentication package, the job
// wrapper, registry-listed platform paths and tests. The type has no Unmarshal, Scan or Set method, so
// no decoder (encoding/json, database/sql, flag) can fill one in from a request. There is no
// default-tenant constant: a single-tenant install's tenant is a random UUID created at install time.
package tenant

import (
	"crypto/rand"
	"errors"
	"fmt"
)

// ID identifies one tenant. The zero value is "no tenant" and is never valid: store.WithTenant
// refuses it.
type ID struct{ b [16]byte }

// ErrInvalidID is returned by Parse for anything that is not a canonical, non-nil UUID.
var ErrInvalidID = errors.New("tenant: invalid tenant id")

// New returns a fresh random (version 4) tenant ID. It is for tenant provisioning only.
func New() ID {
	var id ID
	if _, err := rand.Read(id.b[:]); err != nil {
		panic(fmt.Sprintf("tenant: no entropy: %v", err)) // crypto/rand does not fail on supported platforms
	}
	id.b[6] = id.b[6]&0x0f | 0x40 // version 4
	id.b[8] = id.b[8]&0x3f | 0x80 // RFC 4122 variant
	return id
}

// Parse reads the canonical textual form of a UUID: 36 characters, hyphens after the 8th, 13th, 18th
// and 23rd, hex digits only (either case). Braces, URNs, missing hyphens, whitespace and the nil UUID
// are rejected, so hostile text never reaches SQL (safe-primitives SQL-03). The error never echoes the
// input.
func Parse(s string) (ID, error) {
	var id ID
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return ID{}, ErrInvalidID
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		v, ok := hexVal(s[i])
		if !ok {
			return ID{}, ErrInvalidID
		}
		if n%2 == 0 {
			id.b[n/2] = v << 4
		} else {
			id.b[n/2] |= v
		}
		n++
	}
	if id.IsZero() {
		return ID{}, ErrInvalidID
	}
	return id, nil
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// IsZero reports whether the ID is the zero value, "no tenant".
func (id ID) IsZero() bool { return id == ID{} }

// String is the canonical lower-case form, safe to bind as a SQL parameter, a log field or a path
// segment.
func (id ID) String() string {
	const hexd = "0123456789abcdef"
	var out [36]byte
	j := 0
	for i, v := range id.b {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			out[j] = '-'
			j++
		}
		out[j], out[j+1] = hexd[v>>4], hexd[v&0x0f]
		j += 2
	}
	return string(out[:])
}

// MarshalText encodes the ID for output (logs, JSON responses). There is deliberately no inverse.
func (id ID) MarshalText() ([]byte, error) { return []byte(id.String()), nil }
