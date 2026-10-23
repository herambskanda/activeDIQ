package fleet

import (
	"crypto/x509"
	"errors"
	"net/url"
	"strings"

	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// The certificate SAN is the component's whole identity (ADR-0002 Request row, TM-TB6-T3): two URI
// names and nothing else. The component name carries the kind because the server picks the bound
// contract from the kind in the SAN (TM-D24 rule A1).
const (
	tenantURIPrefix    = "urn:activediq:tenant:"
	componentURIPrefix = "urn:activediq:component:"
)

// Identity is who a leaf certificate says its holder is.
type Identity struct {
	Tenant      tenant.ID
	Kind        string // "connector" or "agent"
	ComponentID string // canonical lower-case UUID
	Serial      string // lower-case hex serial of the certificate, as stored in components.cert_serial
}

// ErrIdentity is returned for a certificate whose SAN is not exactly one tenant and one component.
var ErrIdentity = errors.New("fleet: certificate does not carry a component identity")

// URIs returns the two SAN names for an identity. Issuance puts exactly these in the leaf.
func URIs(tid tenant.ID, kind, componentID string) []*url.URL {
	return []*url.URL{
		{Scheme: "urn", Opaque: strings.TrimPrefix(tenantURIPrefix, "urn:") + tid.String()},
		{Scheme: "urn", Opaque: strings.TrimPrefix(componentURIPrefix, "urn:") + kind + ":" + componentID},
	}
}

// IdentityOf reads the identity from a verified leaf certificate. The SAN must be exactly one tenant
// URI and one component URI: no DNS name, IP address, e-mail address or further URI, so a certificate
// with anything extra is refused rather than half-read.
func IdentityOf(c *x509.Certificate) (Identity, error) {
	if c == nil || len(c.DNSNames) != 0 || len(c.IPAddresses) != 0 || len(c.EmailAddresses) != 0 || len(c.URIs) != 2 {
		return Identity{}, ErrIdentity
	}
	var out Identity
	var haveT, haveC bool
	for _, u := range c.URIs {
		s := u.String()
		switch {
		case strings.HasPrefix(s, tenantURIPrefix) && !haveT:
			id, err := tenant.Parse(strings.TrimPrefix(s, tenantURIPrefix))
			if err != nil || id.String() != strings.TrimPrefix(s, tenantURIPrefix) {
				return Identity{}, ErrIdentity
			}
			out.Tenant, haveT = id, true
		case strings.HasPrefix(s, componentURIPrefix) && !haveC:
			kind, cid, ok := strings.Cut(strings.TrimPrefix(s, componentURIPrefix), ":")
			if !ok || (kind != "connector" && kind != "agent") || !isCanonicalUUID(cid) {
				return Identity{}, ErrIdentity
			}
			out.Kind, out.ComponentID, haveC = kind, cid, true
		default:
			return Identity{}, ErrIdentity
		}
	}
	if !haveT || !haveC {
		return Identity{}, ErrIdentity
	}
	out.Serial = c.SerialNumber.Text(16)
	return out, nil
}

func isCanonicalUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case i == 8 || i == 13 || i == 18 || i == 23:
			if c != '-' {
				return false
			}
		case (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'):
		default:
			return false
		}
	}
	return true
}
