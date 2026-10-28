// Package agentingest stores the records an addc agent appends. The one rule it exists to keep is S1
// (agent-host contract §2, TM-D24): the tenant, the component and the kind of a record are stamped from
// the verified client certificate, and nothing in the payload can name or override them. The Batch type
// has no field for any of the three, so there is nothing to ignore by convention; the request cannot
// carry them.
//
// The agent's own gapless agent_seq makes redelivery idempotent: a record already stored is counted as
// a duplicate and left untouched (the table is append-only). Gaps and drops the agent reports are
// stored as records of their own type, so a hole in the trail is itself visible.
package agentingest

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/audit/chain"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/fleet"
	"github.com/skenzeriq/activediq/internal/platform/fleet/fleetsql"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tablekind"
)

var _ = tablekind.Declare(tablekind.Table{Name: "public.agent_event", Entity: "DM-89", Kind: tablekind.Tenant, AppendOnly: true})

// Bounds (contract §3 and the table's checks).
const (
	MaxBatchRecords = 1000
	MaxFieldsBytes  = 64 << 10
	maxFieldKeys    = 64
)

// Record types.
const (
	TypeEvent   = "event"
	TypeGap     = "gap"
	TypeDropped = "dropped"
)

// AlertDCGUIDMismatch is raised when the DC GUID an agent reports is not the one the server's
// replication metadata attributes to the host (contract §2 note on S1).
const AlertDCGUIDMismatch fleetsql.AlertKind = "agentfleet.event.dc_guid_mismatch"

// Audit kind of an accepted batch. Details carry counts and the highest sequence only.
const KindBatchAccepted audit.Kind = "agentfleet.events.accepted"

var (
	// ErrNoIdentity: the call had no client-certificate identity. The gateway guarantees one for every
	// authenticated method; a missing one is a wiring bug and fails closed.
	ErrNoIdentity = errors.New("agentingest: no authenticated identity")
	// ErrWrongKind: the certificate belongs to another module's component.
	ErrWrongKind = errors.New("agentingest: certificate is not an addc component")
	// ErrInvalid: the batch is outside its bounds. Nothing is stored.
	ErrInvalid       = errors.New("agentingest: invalid batch")
	ErrNotConfigured = errors.New("agentingest: not configured")
)

// Record is one appended item. It deliberately carries no tenant, component or kind.
type Record struct {
	AgentSeq      uint64
	Type          string
	Channel       string // "security" or "directory_service"; empty for gap and dropped
	EventRecordID *uint64
	ObservedAt    time.Time
	// ReportedDCGUID is what the agent says about its host. It is data to cross-check, never identity.
	ReportedDCGUID string
	Fields         map[string]string
}

// Batch is one AppendEvents call's payload.
type Batch struct{ Records []Record }

// Result counts what a batch did.
type Result struct {
	Accepted   int
	Duplicates int
	// HighestSeq is the highest agent_seq now stored for the component, which the agent may prune up to.
	HighestSeq uint64
}

// DCClaims confirms a reported DC GUID against the server's own knowledge of the host. It is optional:
// without it no cross-check runs (the data source lands with the DC observation table).
type DCClaims interface {
	Matches(ctx context.Context, tx store.Tx, id fleet.Identity, reportedDCGUID string) (bool, error)
}

// Alerter raises operator alerts.
type Alerter interface {
	Raise(ctx context.Context, a fleetsql.Alert)
}

// Ingester stores batches.
type Ingester struct {
	DB     *store.DB
	Audit  audit.Sink
	Alerts Alerter  // optional
	Claims DCClaims // optional
	Clock  func() time.Time
}

// AppendAuthenticated is the entry point for a handler: the identity is read from the context the
// gateway built, never from the request.
func (g *Ingester) AppendAuthenticated(ctx context.Context, b Batch) (Result, error) {
	id, ok := fleet.IdentityFrom(ctx)
	if !ok {
		return Result{}, ErrNoIdentity
	}
	return g.Append(ctx, id, b)
}

// Append stores b for the component id names.
func (g *Ingester) Append(ctx context.Context, id fleet.Identity, b Batch) (Result, error) {
	if g == nil || g.DB == nil || g.Audit == nil {
		return Result{}, ErrNotConfigured
	}
	if id.Kind != fleet.KindADDC || id.Tenant.IsZero() {
		return Result{}, ErrWrongKind
	}
	if err := validate(b); err != nil {
		return Result{}, err
	}
	var res Result
	var mismatch bool
	err := g.DB.WithTenant(ctx, id.Tenant, func(ctx context.Context, tx store.Tx) error {
		res, mismatch = Result{}, false
		for _, r := range b.Records {
			fields, _ := json.Marshal(r.Fields) // validated: a string map
			var dc any
			if r.ReportedDCGUID != "" {
				dc = r.ReportedDCGUID
				if g.Claims != nil {
					ok, err := g.Claims.Matches(ctx, tx, id, r.ReportedDCGUID)
					if err != nil {
						return fmt.Errorf("agentingest: dc cross-check: %w", err)
					}
					mismatch = mismatch || !ok
				}
			}
			var channel any
			if r.Channel != "" {
				channel = r.Channel
			}
			var rid any
			if r.EventRecordID != nil {
				rid = int64(*r.EventRecordID)
			}
			tag, err := tx.Exec(ctx, `INSERT INTO public.agent_event
				(tenant_id, component_id, agent_seq, record_type, channel, event_record_id, observed_at, reported_dc_guid, fields)
				VALUES ($1, $2::uuid, $3, $4, $5, $6, $7, $8::uuid, $9::jsonb)
				ON CONFLICT (tenant_id, component_id, agent_seq) DO NOTHING`,
				id.Tenant.String(), id.ComponentID, int64(r.AgentSeq), r.Type, channel, rid, r.ObservedAt.UTC(), dc, string(fields))
			if err != nil {
				return fmt.Errorf("agentingest: store record: %w", err)
			}
			if tag.RowsAffected() == 1 {
				res.Accepted++
			} else {
				res.Duplicates++
			}
		}
		var hi int64
		if err := tx.QueryRow(ctx, `SELECT COALESCE(max(agent_seq), 0) FROM public.agent_event WHERE component_id = $1::uuid`, id.ComponentID).Scan(&hi); err != nil {
			return fmt.Errorf("agentingest: read high-water mark: %w", err)
		}
		res.HighestSeq = uint64(hi)
		if res.Accepted == 0 {
			return nil
		}
		now := time.Now().UTC()
		if g.Clock != nil {
			now = g.Clock().UTC()
		}
		return g.Audit.Append(ctx, tx, audit.Event{
			ID:   fmt.Sprintf("%s.%s.%d", KindBatchAccepted, id.ComponentID, res.HighestSeq),
			Kind: KindBatchAccepted, At: now,
			Actor:     authority.Chain{Requester: authority.Principal{ID: authority.PrincipalID("component:" + id.ComponentID), Kind: authority.System}},
			Target:    authority.TargetRef{GUID: id.ComponentID, Class: "component"},
			Component: "agentfleet", Outcome: audit.Success,
			Details: []chain.Detail{{Key: "accepted", Value: fmt.Sprint(res.Accepted)}, {Key: "duplicates", Value: fmt.Sprint(res.Duplicates)}, {Key: "highest_seq", Value: fmt.Sprint(res.HighestSeq)}},
		})
	})
	if err != nil {
		return Result{}, err
	}
	if mismatch && g.Alerts != nil {
		g.Alerts.Raise(ctx, fleetsql.Alert{Kind: AlertDCGUIDMismatch, Tenant: id.Tenant, Component: id.ComponentID})
	}
	return res, nil
}

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func validate(b Batch) error {
	if len(b.Records) == 0 || len(b.Records) > MaxBatchRecords {
		return fmt.Errorf("%w: record count", ErrInvalid)
	}
	var prev uint64
	for i, r := range b.Records {
		if r.AgentSeq == 0 || (i > 0 && r.AgentSeq <= prev) {
			return fmt.Errorf("%w: agent_seq must be positive and strictly increasing", ErrInvalid)
		}
		prev = r.AgentSeq
		switch r.Type {
		case TypeEvent:
			if r.Channel != "security" && r.Channel != "directory_service" {
				return fmt.Errorf("%w: channel", ErrInvalid)
			}
		case TypeGap, TypeDropped:
			if r.Channel != "" && r.Channel != "security" && r.Channel != "directory_service" {
				return fmt.Errorf("%w: channel", ErrInvalid)
			}
		default:
			return fmt.Errorf("%w: record type", ErrInvalid)
		}
		if r.ObservedAt.IsZero() {
			return fmt.Errorf("%w: observed_at", ErrInvalid)
		}
		if r.EventRecordID != nil && *r.EventRecordID > 1<<62 {
			return fmt.Errorf("%w: event_record_id", ErrInvalid)
		}
		if r.ReportedDCGUID != "" {
			if !uuidRE.MatchString(r.ReportedDCGUID) {
				return fmt.Errorf("%w: reported_dc_guid", ErrInvalid)
			}
		}
		if len(r.Fields) > maxFieldKeys {
			return fmt.Errorf("%w: fields", ErrInvalid)
		}
		size := 0
		for k, v := range r.Fields {
			size += len(k) + len(v) + 6
		}
		if size > MaxFieldsBytes/2 { // escaping can double the JSON; the column check is the hard limit
			return fmt.Errorf("%w: fields too large", ErrInvalid)
		}
	}
	return nil
}
