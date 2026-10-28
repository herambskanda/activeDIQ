package syslog

import (
	"context"
	"crypto/sha256"
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
	// ErrIdempotencyConflict is returned by Create when the request ID already created a destination
	// with a different spec.
	ErrIdempotencyConflict = errors.New("syslog: request id already used for a different destination")
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
// request and is the idempotency key: the destination id is derived from the tenant and requestID, so a
// retry with the same spec returns the stored destination and appends nothing, and a retry with a
// different spec is refused with ErrIdempotencyConflict. Update is safe to retry.
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
			id = createID(t, requestID)
			if prior, found, err := s.existing(ctx, tx, t, id); err != nil {
				return err
			} else if found {
				n, err := Destination{ID: id, Host: sp.Host, Port: sp.Port, Transport: sp.Transport, PlaintextOptIn: sp.PlaintextOptIn}.Normalize()
				if err != nil {
					return err
				}
				if n != prior {
					return ErrIdempotencyConflict
				}
				out = prior
				return nil
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
		if !creating {
			// A key that already recorded an update must never change the row again: the audit chain
			// treats a repeated event as a retry and would skip it, leaving a change with no event.
			var seen bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM public.audit_event WHERE tenant_id = $1::uuid AND event_id = $2)`,
				t.String(), "siem.destination."+id+".updated."+requestID).Scan(&seen); err != nil {
				return err
			}
			if seen {
				if d != prev {
					return ErrIdempotencyConflict
				}
				out = prev
				return nil
			}
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
		if errors.Is(err, ErrBadDestination) || errors.Is(err, ErrPlaintextNotOptedIn) || errors.Is(err, ErrIdempotencyConflict) {
			return View{}, err
		}
		if errors.Is(err, audit.ErrEventIDReused) {
			return View{}, ErrIdempotencyConflict
		}
		return View{}, fmt.Errorf("syslog: store destination: %w", err)
	}
	return out.View(), nil
}

// createID is the destination id a create with requestID gets: a version-8 style UUID taken from a
// SHA-256 of the tenant and the request ID, so the same request names the same destination.
func createID(t tenant.ID, requestID string) string {
	h := sha256.Sum256([]byte("siem.destination.create\x00" + t.String() + "\x00" + requestID))
	b := h[:16]
	b[6] = b[6]&0x0f | 0x80
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func (s *Store) existing(ctx context.Context, tx store.Tx, t tenant.ID, id string) (Destination, bool, error) {
	d, err := scan(tx.QueryRow(ctx, `SELECT `+cols+` FROM public.notify_syslog_destinations WHERE tenant_id = $1 AND id = $2::uuid`, t.String(), id))
	if store.IsNoRows(err) {
		return Destination{}, false, nil
	}
	return d, err == nil, err
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
