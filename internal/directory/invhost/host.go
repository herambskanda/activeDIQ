// Package invhost is the InventoryHost typed value (safe-primitives §6.3, PROC-14, PROC-17).
//
// A host name that reaches a connection or a process argument makes our service account authenticate to
// that host. Names that come from directory data (homeDirectory, profilePath, dNSHostName, gPCFileSysPath)
// are attacker-writable, so an InventoryHost can be obtained only two ways, and never by converting a string:
//
//   - a DC found through DNS SRV records and confirmed by its nTDSDSA object (DCSource);
//   - a server an admin registered, an audited action (Service.Register).
//
// Service.Resolve takes a candidate string, but only as a key: it is matched against the registry and the
// discovered DCs, and the returned value carries the inventory's own name, not the candidate. Anything that
// is not in inventory (including a UNC path, an IP literal or a dNSHostName nobody registered) yields
// ErrNotInventoryHost before any dial, and the refusal is audited. The package imports no transport.
package invhost

import (
	"errors"
	"strings"
)

// Origin says which constructor made a host.
type Origin string

// The two origins.
const (
	OriginDiscoveredDC Origin = "discovered_dc"
	OriginRegistered   Origin = "registered"
)

// Errors.
var (
	// ErrNotInventoryHost is PROC-14: the host is not in inventory. No connection was attempted.
	ErrNotInventoryHost = errors.New("invhost: NotInventoryHost")
	// ErrInvalidHostname is returned by Register for a name that is not a plain DNS name.
	ErrInvalidHostname = errors.New("invhost: InvalidHostname")
	// ErrNotConfigured is returned by a Service built without a required collaborator.
	ErrNotConfigured = errors.New("invhost: not configured")
	// ErrNoTenant is returned when the tenant is missing.
	ErrNoTenant = errors.New("invhost: no tenant")
)

// InventoryHost is a host that is in inventory. Its fields are unexported and the zero value is invalid
// (IsZero): the only way to get a non-zero value is a Service constructor, so a consumer that requires an
// InventoryHost cannot be handed a string.
type InventoryHost struct {
	fqdn   string
	origin Origin
}

// FQDN is the normalised DNS name (lower case, no trailing dot), the form the connection hostname
// verification and Kerberos SPNs use.
func (h InventoryHost) FQDN() string { return h.fqdn }

// Origin reports which constructor made the host.
func (h InventoryHost) Origin() Origin { return h.origin }

// IsZero reports an unconstructed value. Consumers must refuse it.
func (h InventoryHost) IsZero() bool { return h.fqdn == "" }

// String is the FQDN, for logs.
func (h InventoryHost) String() string { return h.fqdn }

// Normalize validates name as a plain multi-label DNS host name and returns its stored form: ASCII letters,
// digits and hyphens in labels of 1-63 characters, at least two labels, 253 characters in all, not
// starting or ending a label with a hyphen, not an IP literal, with at most one trailing dot removed. No
// UNC prefix, path, port, userinfo, whitespace or control character is accepted.
func Normalize(name string) (string, error) {
	n := strings.TrimSuffix(name, ".")
	if len(n) < 3 || len(n) > 253 {
		return "", ErrInvalidHostname
	}
	labels := strings.Split(n, ".")
	if len(labels) < 2 {
		return "", ErrInvalidHostname
	}
	var b strings.Builder
	for _, l := range labels {
		if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return "", ErrInvalidHostname
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			switch {
			case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
			case c >= 'A' && c <= 'Z':
				c += 'a' - 'A'
			default:
				return "", ErrInvalidHostname
			}
			b.WriteByte(c)
		}
		b.WriteByte('.')
	}
	out := strings.TrimSuffix(b.String(), ".")
	// An IP literal (or anything numeric in the last label) is not a host name we register.
	last := labels[len(labels)-1]
	allDigits := true
	for i := 0; i < len(last); i++ {
		if last[i] < '0' || last[i] > '9' {
			allDigits = false
			break
		}
	}
	if allDigits {
		return "", ErrInvalidHostname
	}
	return out, nil
}
