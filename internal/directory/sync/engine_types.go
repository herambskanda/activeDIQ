package sync

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"

	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// Ports of the Engine. Each is satisfied structurally by the production type named with it, so the engine
// is testable with a fake connector and a real database.
type (
	// Tenants runs fn in one transaction of the tenant (*store.DB).
	Tenants interface {
		WithTenant(ctx context.Context, id tenant.ID, fn func(ctx context.Context, tx store.Tx) error) error
	}
	// Connections reads a connection (*connection.Registry).
	Connections interface {
		Get(ctx context.Context, tid tenant.ID, id connection.ID) (connection.Connection, error)
	}
	// ConnectorSource resolves a connection to its connector (client.TunnelSource).
	ConnectorSource interface {
		Connector(ctx context.Context, connectionID string) (connectorv1.ConnectorClient, error)
	}
	// Ingest is the inventory ingester's write side (inventory.Ingester).
	Ingest interface {
		Ingest(ctx context.Context, tx store.Tx, c inventory.Cycle) (inventory.Ingested, error)
	}
	// Cursors is the lease-fenced cursor store (Store).
	Cursors interface {
		Claim(ctx context.Context, tx store.Tx, k Key, l jobs.Lease) (Cursor, error)
		CompleteScan(ctx context.Context, tx store.Tx, k Key, l jobs.Lease, at time.Time) (Cursor, error)
	}
	// Domains lists the domain naming contexts the admin manages on a connection (DM-14.I1, FR-24). The
	// engine reads exactly these and nothing else; it re-checks that each is a domain NC.
	Domains interface {
		ManagedDomains(ctx context.Context, tid tenant.ID, id connection.ID) ([]Domain, error)
	}
)

// LeaseFunc returns the platform lease that guards the cursor of the partition with this lease name
// (LeaseName), acquired or renewed by the caller (jobs.AcquireLease). One lease per partition keeps the
// "one reader per partition" rule (DM-19.I2); the engine never acquires a lease itself.
type LeaseFunc func(ctx context.Context, name string) (jobs.Lease, error)

// NCKind is the kind of a naming context (DM-14).
type NCKind string

// The kinds. Only a domain NC is ever read.
const (
	NCDomain        NCKind = "domain"
	NCConfiguration NCKind = "configuration"
	NCSchema        NCKind = "schema"
	NCApplication   NCKind = "application"
)

// Domain is one naming context a connection manages.
type Domain struct {
	// NC is the naming context head's objectGUID, canonical lower-case text.
	NC   inventory.GUID
	Kind NCKind
}

// Typed errors. None carries a directory value, a DN or a connector message.
var (
	// ErrNotConfigured: a port of the Engine is missing.
	ErrNotConfigured = errors.New("sync: engine is not configured")
	// ErrRefused: the connection may not be read. The detail is *Refusal.
	ErrRefused = errors.New("sync: the connection may not be read")
	// ErrNoManagedDomains: the connection manages no domain NC, so there is nothing to read.
	ErrNoManagedDomains = errors.New("sync: the connection manages no domain naming context")
	// ErrNotDomainNC: a naming context that is not a domain NC (configuration, schema, application, or one
	// the connector does not report as a domain) was offered. Nothing was read.
	ErrNotDomainNC = errors.New("sync: only domain naming contexts are read")
	// ErrPaused: the partition's cursor is paused; it resumes through ResumeConnection and a resync.
	ErrPaused = errors.New("sync: the partition is paused")
	// ErrSource: a port (the connection registry or the managed-domain list) failed.
	ErrSource = errors.New("sync: a source of the cycle failed")
	// ErrIncomplete: the connector's search ended without its completion marker, so what it delivered is
	// not the whole naming context.
	ErrIncomplete = errors.New("sync: the search ended without a completion marker")
	// ErrProtocol: the connector's stream broke the ScopedSearch contract.
	ErrProtocol = errors.New("sync: the search stream violates the contract")
	// ErrConnector: the connector refused or failed the call. The detail is *ConnectorError.
	ErrConnector = errors.New("sync: the connector failed the call")
)

// Refusal says why FullCycle refused a connection without reading anything.
type Refusal struct{ Reason RefusalReason }

// RefusalReason is a fixed vocabulary.
type RefusalReason string

// The reasons.
const (
	RefusedNotAD      RefusalReason = "not_ad_forest"
	RefusedNotActive  RefusalReason = "not_active"
	RefusedRetired    RefusalReason = "retired"
	RefusedNoIdentity RefusalReason = "directory_identity_unknown"
)

func (r *Refusal) Error() string { return "sync: the connection may not be read: " + string(r.Reason) }

// Is makes errors.Is(err, ErrRefused) true.
func (r *Refusal) Is(target error) bool { return target == ErrRefused }

// ConnectorError is a failed connector call: only the gRPC status code, never its message (which may carry
// a directory value).
type ConnectorError struct{ Code codes.Code }

func (e *ConnectorError) Error() string {
	return "sync: the connector failed the call: " + e.Code.String()
}

// Is makes errors.Is(err, ErrConnector) true.
func (e *ConnectorError) Is(target error) bool { return target == ErrConnector }

// DomainError is a failure of one domain's read. The domain before it, and the rows this domain had
// already committed, are kept; the domain's pass and cursor did not move.
type DomainError struct {
	NC    inventory.GUID
	Phase string // "prescan", "read" or "store"
	Err   error
}

func (e *DomainError) Error() string {
	return fmt.Sprintf("sync: domain %s: %s: %v", e.NC, e.Phase, e.Err)
}

// Unwrap returns the cause.
func (e *DomainError) Unwrap() error { return e.Err }

// RefusalKey identifies a kind of refused entry: an attribute name of this package's own and a code from
// the fixed vocabulary (see Error), never directory text.
type RefusalKey struct {
	Attr string
	Code Code
}

// DomainReport is what the engine did for one managed domain.
type DomainReport struct {
	NC inventory.GUID
	// Skipped says the domain was not read: its cursor is already incremental.
	Skipped bool
	// Completed says the whole domain was read and its pass and cursor recorded.
	Completed bool
	// Entries is how many entries the connector delivered; Mapped how many became observations;
	// Refused how many were refused as malformed and skipped (RefusedBy has the breakdown).
	Entries, Mapped, Refused int
	RefusedBy                map[RefusalKey]int
	// Batches is how many ingest transactions committed.
	Batches                  int
	Inserted, Updated, Stale int
	Members, PrimaryGroups   int
	// AncestryUnresolved counts observations whose parent chain could not be completed from the domain's own
	// objects (a parent the search did not deliver, a cycle, a chain past the store's bound): the store keeps
	// them with ancestry_complete false, which is out of every delegated scope.
	AncestryUnresolved int
	// GroupsPartial counts groups whose member list was not complete (a ranged value: the search never
	// follows ranges) and MembersUnresolved the member values that named no object GUID. Their edges are
	// added but no edge is removed on their account.
	GroupsPartial, MembersUnresolved int
	// PrimaryGroupUnresolved counts principals whose primaryGroupID named no group of the domain.
	PrimaryGroupUnresolved int
}

// Report is the outcome of FullCycle: one entry per managed domain, in the order they were offered.
type Report struct {
	Connection inventory.ConnectionID
	Domains    []DomainReport
}

// Engine runs the sync cycles of one AD connection's managed domains into the inventory.
type Engine struct {
	Tenants  Tenants
	Conns    Connections
	Domains  Domains
	Source   ConnectorSource
	Ingester Ingest
	Cursors  Cursors
	// Clock is the time source; nil is time.Now.
	Clock func() time.Time
	// Log receives one summary line per domain: counts and fixed codes, never a directory value. Nil
	// discards.
	Log *slog.Logger
}

func (e *Engine) ready() error {
	if e == nil || e.Tenants == nil || e.Conns == nil || e.Domains == nil || e.Source == nil || e.Ingester == nil || e.Cursors == nil {
		return ErrNotConfigured
	}
	return nil
}

func (e *Engine) now() time.Time {
	if e.Clock != nil {
		return e.Clock()
	}
	return time.Now()
}

func (e *Engine) log() *slog.Logger {
	if e.Log != nil {
		return e.Log
	}
	return slog.New(slog.DiscardHandler)
}

// RefusingClassifier is the PairClassifier of an ingester that must form no pair: Classify refuses, so a
// cycle that would need one fails instead of storing a guess (inventory.ErrNotConfigured). An AD-only
// tenant has no pair, so it is never called; the production classifier belongs to the Entra sync.
func RefusingClassifier() inventory.PairClassifier { return refusingClassifier{} }

type refusingClassifier struct{}

func (refusingClassifier) Classify(context.Context, store.Tx, inventory.Ref, inventory.Ref) (inventory.PairFacts, error) {
	return inventory.PairFacts{}, fmt.Errorf("%w: the AD sync has no pair classifier", inventory.ErrNotConfigured)
}

// NewIngester returns the inventory ingester the AD sync uses: it forms no pair (RefusingClassifier).
func NewIngester() inventory.Ingester {
	return inventory.Ingester{Classifier: RefusingClassifier()}
}
