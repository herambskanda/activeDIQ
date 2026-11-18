// Package read serves the admin read of the audit trail (listAuditEvents, T-2300): a typed search of the
// tenant's chained events by DC, DM-11 credential, target GUID and time, answering Requester and Via so an
// auditor can join a line of a DC's own log to the technician behind it. It holds no domain logic: the
// search is audit.Search, and the read is itself recorded in the chain.
package read

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/audit/api"
	"github.com/skenzeriq/activediq/internal/platform/authn/tenantref"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/rbac"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Permission is what listAuditEvents needs. It is not a step-up permission: it is a read and the chain
// holds no personal value (ADR-0005 rule 11). apihost authorises it before a handler runs and records a
// refusal (authz.permission.denied), so a caller without it never reaches this package.
const Permission = "audit.read"

// KindQueried is the event a search records about itself.
const KindQueried audit.Kind = "audit.queried"

// DB is the tenant transaction runner. *store.DB satisfies it.
type DB interface {
	WithTenant(ctx context.Context, id tenant.ID, fn func(ctx context.Context, tx store.Tx) error) error
}

// Handlers implements api.Handlers.
type Handlers struct {
	DB   DB
	Sink audit.Sink
	Now  func() time.Time // nil: time.Now
	Log  *slog.Logger     // nil: slog.Default()
}

var _ api.Handlers = Handlers{}

// Bind returns the tag's routes for apihost.Build.
func (h Handlers) Bind() apihost.TagHandlers { return api.Bind(h) }

func (h Handlers) log() *slog.Logger {
	if h.Log != nil {
		return h.Log
	}
	return slog.Default()
}

func (h Handlers) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

// ListAuditEvents implements api.Handlers.
func (h Handlers) ListAuditEvents(ctx context.Context, in api.ListAuditEventsInput) (api.ListAuditEventsOutput, error) {
	p, ok := apihost.PrincipalFrom(ctx)
	if !ok || p.ID == "" {
		return nil, apitypes.Forbidden("")
	}
	tid, err := tenantref.TenantFromText(p.Tenant)
	if err != nil {
		return nil, apitypes.Forbidden("")
	}
	q := audit.SearchQuery{}
	if in.Dc != nil {
		q.DC = *in.Dc
	}
	if in.CredentialID != nil {
		q.CredentialID = *in.CredentialID
	}
	if in.Target != nil {
		q.Target = in.Target.String()
	}
	if in.From != nil {
		q.From = in.From.Time()
	}
	if in.To != nil {
		q.To = in.To.Time()
	}
	if in.Limit != nil {
		q.Limit = int(*in.Limit)
	}
	if !q.From.IsZero() && !q.To.IsZero() && !q.From.Before(q.To) {
		return nil, apitypes.Validation("from must be before to")
	}
	bind := filterBinding(q)
	if in.Cursor != nil {
		seq, err := openCursor(string(*in.Cursor), bind)
		if err != nil {
			return nil, apitypes.Validation("cursor is not valid for this query")
		}
		q.AfterSeq = seq
	}
	kind := authority.Human
	if p.Kind == apihost.KindToken {
		kind = authority.APIToken
	}
	actor := authority.Chain{Requester: authority.Principal{ID: authority.PrincipalID(p.ID), Kind: kind}}

	var page audit.SearchPage
	err = h.DB.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) error {
		var err error
		if page, err = audit.Search(ctx, tx, tid, q); err != nil {
			return err
		}
		ev, err := h.queriedEvent(tid, actor, q, len(page.Events))
		if err != nil {
			return err
		}
		return h.Sink.Append(ctx, tx, ev) // the read is recorded with the transaction that made it
	})
	switch {
	case errors.Is(err, audit.ErrBadSearch):
		return nil, apitypes.Validation("")
	case err != nil:
		h.log().Error("audit search failed", "error_class", "internal")
		return nil, apitypes.Internal("")
	}
	out := api.AuditEventList{Items: make([]api.AuditEvent, 0, len(page.Events))}
	for _, e := range page.Events {
		out.Items = append(out.Items, wire(e))
	}
	if page.Next != 0 {
		c := sealCursor(page.Next, bind)
		out.NextCursor = &c
	}
	return api.ListAuditEvents200{Body: out}, nil
}

func wire(e audit.Envelope) api.AuditEvent {
	pr := func(id, kind string) api.AuditPrincipal { return api.AuditPrincipal{ID: id, Kind: kind} }
	w := api.AuditEvent{Seq: apitypes.Int64String(e.Seq), EventID: e.EventID, Kind: e.Kind, At: apitypes.NewTimestamp(e.At),
		Requester: pr(e.Requester.ID, e.Requester.Kind), Via: []api.AuditPrincipal{}, Component: e.Component, Outcome: e.Outcome}
	for _, v := range e.Via {
		w.Via = append(w.Via, pr(v.ID, v.Kind))
	}
	set := func(dst **string, v string) {
		if v != "" {
			s := v
			*dst = &s
		}
	}
	set(&w.Connection, e.Connection)
	set(&w.Target, e.TargetGUID)
	set(&w.TargetClass, e.TargetClass)
	set(&w.Operation, e.Operation)
	set(&w.Reason, e.Reason)
	set(&w.PlanHash, e.PlanHash)
	set(&w.Dc, audit.DetailValue(e, "dc"))
	set(&w.CredentialID, audit.DetailValue(e, "credential_id"))
	if e.HasStep {
		i, s := int64(e.Item), int64(e.Step)
		w.Item, w.Step = &i, &s
	}
	return w
}

// queriedEvent is the audit.queried event: the filters used and how many events were answered. Filter
// values are public (a host name, a credential ID, an objectGUID); keys are in increasing order. The
// keys are filter_*, never dc or credential_id: those name where a step was written, and a search must not
// answer another search as if it were a step.
func (h Handlers) queriedEvent(tid tenant.ID, actor authority.Chain, q audit.SearchQuery, n int) (audit.Event, error) {
	var idb [16]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return audit.Event{}, err
	}
	var d []audit.Detail
	add := func(k, v string) {
		if v != "" {
			d = append(d, audit.Detail{Key: k, Value: v})
		}
	}
	add("count", strconv.Itoa(n))
	add("filter_credential_id", q.CredentialID)
	add("filter_dc", q.DC)
	if !q.From.IsZero() {
		add("filter_from", q.From.UTC().Format(time.RFC3339Nano))
	}
	add("filter_target", q.Target)
	if !q.To.IsZero() {
		add("filter_to", q.To.UTC().Format(time.RFC3339Nano))
	}
	return audit.Event{ID: hex.EncodeToString(idb[:]), Kind: KindQueried, At: h.now(), Actor: actor,
		Target:    authority.TargetRef{Class: rbac.TargetClassTenant, GUID: tid.String()},
		Component: "audit", Outcome: audit.Success, Details: d}, nil
}

// A cursor is the chain position plus a short digest of the filters it was made for, so it cannot be
// replayed against other filters. It grants nothing a caller could not already read (same tenant, same
// permission), so it is bound, not signed.
func filterBinding(q audit.SearchQuery) string {
	s := strings.Join([]string{strings.ToLower(q.DC), q.CredentialID, q.Target, q.From.UTC().Format(time.RFC3339Nano), q.To.UTC().Format(time.RFC3339Nano)}, "\x00")
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:6])
}

func sealCursor(seq uint64, bind string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatUint(seq, 10) + "." + bind))
}

var errCursor = errors.New("audit read: cursor invalid")

func openCursor(c, bind string) (uint64, error) {
	raw, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return 0, errCursor
	}
	num, b, ok := strings.Cut(string(raw), ".")
	if !ok || b != bind {
		return 0, errCursor
	}
	seq, err := strconv.ParseUint(num, 10, 64)
	if err != nil || seq == 0 {
		return 0, fmt.Errorf("%w", errCursor)
	}
	return seq, nil
}
