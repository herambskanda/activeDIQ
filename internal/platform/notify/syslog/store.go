package syslog

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/audit/chain"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tablekind"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

var _ = tablekind.Declare(tablekind.Table{Name: "public.notify_syslog_destinations", Entity: "DM-82", Kind: tablekind.Tenant})

// Errors of the store. None carries SQL or a stored value.
var (
	ErrNotFound     = errors.New("syslog: no such destination")
	ErrInvalidInput = errors.New("syslog: invalid input")
)

var requestIDRe = regexp.MustCompile(`^[\x21-\x7e]{1,128}$`)

var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Spec is the writable part of a destination. A zero Transport means TLS; Port 0 takes the default.
type Spec struct {
	Host           string
	Port           int
	Transport      Transport
	PlaintextOptIn bool
}

// Store persists destinations per tenant. Every write normalizes the destination and is stored in one transaction with its audit
// event; a plaintext write also carries its OptInEvent (TM-TB15-T7). If an audit
// append fails, the destination is not stored. Safe for concurrent use.
type Store struct {
	db    *store.DB
	audit audit.Sink
}

// NewStore returns the destination store over db, appending opt-in events to sink.
func NewStore(db *store.DB, sink audit.Sink) (*Store, error) {
	if db == nil || sink == nil {
		return nil, errors.New("syslog: store needs a database and an audit sink")
	}
	return &Store{db: db, audit: sink}, nil
}

const cols = `id::text, host, port, transport, plaintext_opt_in`

func scan(row interface{ Scan(dest ...any) error }) (Destination, error) {
	var d Destination
	var tr string
	if err := row.Scan(&d.ID, &d.Host, &d.Port, &tr, &d.PlaintextOptIn); err != nil {
		return Destination{}, err
	}
	d.Transport = Transport(tr)
	return d, nil
}

// Create stores a new destination and returns its View. requestID names the audit events of the
// request. Create draws a fresh destination id per call, so a caller that retries after an ambiguous
// commit may create two destinations, each with its own events; Update is safe to retry.
func (s *Store) Create(ctx context.Context, t tenant.ID, sp Spec, by authority.Chain, requestID string) (View, error) {
	return s.write(ctx, t, "", sp, by, requestID)
}

// Update replaces the writable fields of destination id and returns its View. Every write appends a
// siem.destination.updated event with the previous and new target; a plaintext result also appends an
// opt-in event, because the plaintext target or its settings were just (re)approved.
func (s *Store) Update(ctx context.Context, t tenant.ID, id string, sp Spec, by authority.Chain, requestID string) (View, error) {
	if !uuidRe.MatchString(id) {
		return View{}, ErrInvalidInput
	}
	return s.write(ctx, t, id, sp, by, requestID)
}

func (s *Store) write(ctx context.Context, t tenant.ID, id string, sp Spec, by authority.Chain, requestID string) (View, error) {
	if t.IsZero() || by.Validate() != nil || !requestIDRe.MatchString(requestID) {
		return View{}, ErrInvalidInput
	}
	creating := id == ""
	var out Destination
	err := s.db.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		var at time.Time
		if err := tx.QueryRow(ctx, `SELECT now()`).Scan(&at); err != nil {
			return err
		}
		if creating {
			if err := tx.QueryRow(ctx, `SELECT gen_random_uuid()::text`).Scan(&id); err != nil {
				return err
			}
		}
		var prev Destination
		if !creating {
			// Lock the row so the recorded previous target is the one this write replaces.
			var err error
			if prev, err = scan(tx.QueryRow(ctx, `SELECT `+cols+` FROM public.notify_syslog_destinations
				WHERE tenant_id = $1 AND id = $2::uuid FOR UPDATE`, t.String(), id)); err != nil {
				return err
			}
		}
		d, err := Destination{ID: id, Host: sp.Host, Port: sp.Port, Transport: sp.Transport, PlaintextOptIn: sp.PlaintextOptIn}.Normalize()
		if err != nil {
			return err
		}
		var row interface{ Scan(dest ...any) error }
		if creating {
			row = tx.QueryRow(ctx, `INSERT INTO public.notify_syslog_destinations
				(tenant_id, id, host, port, transport, plaintext_opt_in, created_at, updated_at)
				VALUES ($1, $2::uuid, $3, $4, $5, $6, $7, $7) RETURNING `+cols,
				t.String(), d.ID, d.Host, d.Port, string(d.Transport), d.PlaintextOptIn, at)
		} else {
			row = tx.QueryRow(ctx, `UPDATE public.notify_syslog_destinations
				SET host = $3, port = $4, transport = $5, plaintext_opt_in = $6, updated_at = $7
				WHERE tenant_id = $1 AND id = $2::uuid RETURNING `+cols,
				t.String(), d.ID, d.Host, d.Port, string(d.Transport), d.PlaintextOptIn, at)
		}
		// Re-read what was stored: the View is built from the row, not from the request.
		if out, err = scan(row); err != nil {
			return err
		}
		if err := s.audit.Append(ctx, tx, changeEvent(requestID, by, creating, prev, out, at.UTC())); err != nil {
			return fmt.Errorf("syslog: audit destination change: %w", err)
		}
		if ev := OptInEvent("siem.destination."+out.ID+".plaintext_opt_in."+requestID, by, out, at.UTC()); ev != nil {
			ev.Target = authority.TargetRef{GUID: out.ID, Class: "siem_destination"}
			if err := s.audit.Append(ctx, tx, *ev); err != nil {
				return fmt.Errorf("syslog: audit plaintext opt-in: %w", err)
			}
		}
		return nil
	})
	if store.IsNoRows(err) {
		return View{}, ErrNotFound
	}
	if err != nil {
		if errors.Is(err, ErrBadDestination) || errors.Is(err, ErrPlaintextNotOptedIn) {
			return View{}, err
		}
		return View{}, fmt.Errorf("syslog: store destination: %w", err)
	}
	return out.View(), nil
}

// Audit kinds of a destination's lifecycle. Any change of target redirects the SIEM stream, so every
// write is recorded, TLS or not.
const (
	KindDestinationCreated audit.Kind = "siem.destination.created"
	KindDestinationUpdated audit.Kind = "siem.destination.updated"
)

// changeEvent records the stored destination and, for an update, the target it replaced. Details are
// in strictly increasing key order.
func changeEvent(requestID string, by authority.Chain, creating bool, prev, cur Destination, at time.Time) audit.Event {
	kind, verb := KindDestinationUpdated, "updated"
	details := []chain.Detail{
		{Key: "destination", Value: cur.ID},
		{Key: "host", Value: cur.Host},
		{Key: "port", Value: strconv.Itoa(cur.Port)},
	}
	if creating {
		kind, verb = KindDestinationCreated, "created"
	} else {
		details = append(details,
			chain.Detail{Key: "previous_host", Value: prev.Host},
			chain.Detail{Key: "previous_port", Value: strconv.Itoa(prev.Port)},
			chain.Detail{Key: "previous_transport", Value: string(prev.Transport)})
	}
	details = append(details, chain.Detail{Key: "transport", Value: string(cur.Transport)})
	return audit.Event{
		ID: "siem.destination." + cur.ID + "." + verb + "." + requestID, Kind: kind, At: at, Actor: by,
		Target:    authority.TargetRef{GUID: cur.ID, Class: "siem_destination"},
		Component: "notify.syslog", Outcome: audit.Success, Reason: verb, Details: details,
	}
}

// List returns the Views of the tenant's destinations, oldest first.
func (s *Store) List(ctx context.Context, t tenant.ID) ([]View, error) {
	if t.IsZero() {
		return nil, ErrInvalidInput
	}
	out := []View{}
	err := s.db.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+cols+` FROM public.notify_syslog_destinations WHERE tenant_id = $1 ORDER BY created_at, id`, t.String())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			d, err := scan(rows)
			if err != nil {
				return err
			}
			out = append(out, d.View())
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("syslog: list destinations: %w", err)
	}
	return out, nil
}

// Get returns the View of one destination.
func (s *Store) Get(ctx context.Context, t tenant.ID, id string) (View, error) {
	if t.IsZero() || !uuidRe.MatchString(id) {
		return View{}, ErrInvalidInput
	}
	var d Destination
	err := s.db.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		var err error
		d, err = scan(tx.QueryRow(ctx, `SELECT `+cols+` FROM public.notify_syslog_destinations WHERE tenant_id = $1 AND id = $2::uuid`, t.String(), id))
		return err
	})
	if store.IsNoRows(err) {
		return View{}, ErrNotFound
	}
	if err != nil {
		return View{}, fmt.Errorf("syslog: read destination: %w", err)
	}
	return d.View(), nil
}
