// Package idp holds the ports of the TM-D17 attestation (the identity provider's token exchange and the
// one Graph read) and the values that cross them. It is a leaf of the connections module: the module
// and its Entra adapters (connections/entra) both import it, so neither imports the other's types.
package idp

import (
	"context"
	"errors"
)

// AttestScope is the one delegated permission the flow requests. No offline_access, no openid, no
// other scope: the token is for one read and is discarded (TM-D17 rule 2). The Graph docs name Global
// Administrator as the only supported role for this call.
// https://learn.microsoft.com/en-us/graph/api/onpremisesdirectorysynchronization-get?view=graph-rest-1.0
const AttestScope = "OnPremDirectorySynchronization.Read.All"

// ErrTenantMismatch means the token's tenant is not the connection's tenant.
var ErrTenantMismatch = errors.New("connections: token tenant is not the connection's tenant")

// Bearer is a delegated access token held only for the duration of the callback. It cannot be
// printed, logged or marshalled, and Zero overwrites the bytes. It is never stored.
type Bearer struct{ b []byte }

// NewBearer wraps token bytes (the IdP adapter's job); the slice is owned by the Bearer afterwards.
func NewBearer(b []byte) Bearer { return Bearer{b: b} }

// Use calls fn with the token bytes. fn must not retain them.
func (t Bearer) Use(fn func([]byte) error) error { return fn(t.b) }

// Zero overwrites the token.
func (t Bearer) Zero() {
	for i := range t.b {
		t.b[i] = 0
	}
}

// String implements fmt.Stringer; it never reveals the token.
func (Bearer) String() string { return "[redacted token]" }

// GoString implements fmt.GoStringer.
func (Bearer) GoString() string { return "[redacted token]" }

// MarshalJSON refuses to serialise the token.
func (Bearer) MarshalJSON() ([]byte, error) { return []byte(`"[redacted]"`), nil }

// MarshalText refuses to serialise the token.
func (Bearer) MarshalText() ([]byte, error) { return []byte("[redacted]"), nil }

// Grant is what the IdP adapter returns after the code exchange, from tokens it has validated
// (signature, issuer, audience, expiry). Only the claims the flow needs and the bearer for the one read.
type Grant struct {
	TenantID string   // tid claim
	ObjectID string   // oid claim: the signed-in Global Administrator
	Scopes   []string // scopes the IdP granted
	Token    Bearer
}

// ExchangeRequest is the authorization-code redemption.
type ExchangeRequest struct {
	TenantID     string // the connection's tenant; the token endpoint is tenant-specific
	Code         string
	CodeVerifier string
	RedirectURI  string
	Scopes       []string
}

// IdP redeems an authorization code. The adapter must not request or keep a refresh token or ID token
// beyond validating the claims it returns.
type IdP interface {
	Exchange(ctx context.Context, req ExchangeRequest) (Grant, error)
}

// SyncFeatures are the two values DM-20.I4(f) needs.
type SyncFeatures struct {
	BlockCloudObjectTakeoverThroughHardMatch bool
	BlockSoftMatch                           bool
}

// Graph makes the one delegated read, GET /directory/onPremisesSynchronization.
type Graph interface {
	ReadSyncFeatures(ctx context.Context, token Bearer) (SyncFeatures, error)
}
