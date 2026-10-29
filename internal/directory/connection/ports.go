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
// It is one method: the connector's own rights check (contract v1.1 VerifyConnection, TM §6.5 for AD,
// §6.6 for Entra). The run also answers the V5 identity question, so there is no separate identity
// read: the identity is a field of the result.
type ConnectorClient interface {
	// VerifyConnection runs the check list for the connection and returns the completed result. It
	// returns an error, and no result, when the run did not complete: a stream that ends without its
	// completion message is not a result (contract §2 rule 11). It never returns secret material.
	VerifyConnection(ctx context.Context, req VerifyRequest) (VerifyResult, error)
}

// VerifyRequest names the run. VerificationID is drawn by the server and becomes the DM-24 row ID.
type VerifyRequest struct {
	Connection     Connection
	Kind           VerificationKind
	VerificationID VerificationID
	// PinnedC13 are the C13 group GUIDs (canonical text) pinned for the connection (TM-D26 rule 10).
	// The server reads them from its own store and sends them so a renamed pinned group stays tier0.
	PinnedC13 []string
}

// VerifyResult is a completed run as the connector reported it, in domain types. Findings are the
// whole set: the activation gate compares them with an override's acknowledged set.
type VerifyResult struct {
	// DirectoryIdentity is what V5 read (AD: the forest root domain NC objectGUID; Entra: the tenant
	// ID). Empty if the run did not get that far.
	DirectoryIdentity DirectoryIdentity
	CheckListVersion  int
	Outcomes          map[Check]Outcome
	Verdict           Verdict
	Findings          []Finding
	// C13Groups are the C13 groups (canonical GUID text) the run's tier0_set reported. The service
	// pins them at onboarding (TM-D26 rule 10).
	C13Groups []string
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
