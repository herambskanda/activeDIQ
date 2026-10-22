package connection

import (
	"context"

	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// ConnectorClient is the port through which the registry's callers reach a directory to answer the
// questions a connection's lifecycle depends on. It is declared here, in the registry, so that the
// verification run can depend on it without importing the transport client (`client` imports
// `connection`, never the reverse; blueprint §5.2). `directory/client` implements it.
//
// It is deliberately one method: the V5 identity read that feeds SetDirectoryIdentity. The rest of
// verification (V1–V9, rights, override) is another ticket and extends the port when it lands.
type ConnectorClient interface {
	// ReadIdentity reads the directory identity of the connection's directory: the objectGUID of
	// the forest root domain NC (AD) or the tenant ID (Entra). It never returns secret material.
	ReadIdentity(ctx context.Context, c Connection) (DirectoryIdentity, error)
}

// HybridLinks is the read port over DM-21 that other packages depend on: the write gate decides
// no_hybrid_link from HasHybridLink, and correlations authorize only across a confirmed link
// (DM-20.I4(d)). Both reads fail closed: an error is returned, never a false that a caller could
// mistake for "no link". Tenant is explicit, as on Registry.
type HybridLinks interface {
	// Confirmed reports whether a confirmed link joins this AD domain and this Entra tenant. A
	// proposed link is not enough (DM-21.I2): discovery cannot bootstrap trust.
	Confirmed(ctx context.Context, tid tenant.ID, adConn ID, nc NCGUID, entraConn ID) (bool, error)
	// HasHybridLink reports whether the AD connection has any link that is not removed (proposed or
	// confirmed), in any domain and to any tenant.
	HasHybridLink(ctx context.Context, tid tenant.ID, adConn ID) (bool, error)
}
