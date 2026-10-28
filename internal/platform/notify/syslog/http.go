package syslog

import (
	"context"
	"errors"
	"log/slog"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
	"github.com/skenzeriq/activediq/internal/platform/authn/tenantref"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/notify/api"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// ReadPermission is what list and get need; it is not a step-up permission (TM §7.4, AG-8).
const ReadPermission = "siem.destination.read"

// ManagePermission is what create and update need; policy.yaml makes it a step-up permission.
// apihost authorises it server-side (chain step 12) before a handler runs; the handler adds nothing
// and changes nothing for a caller who failed it.
const ManagePermission = "siem.destination.manage"

// Handlers implements the generated Handlers of the platform.notify tag over Store. It holds no domain
// logic: it maps the request onto the Store and the Store's refusals onto problems. There is no delete
// operation (the runtime role cannot delete a destination).
type Handlers struct {
	Store *Store
	Log   *slog.Logger // nil: slog.Default()
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

// caller derives the tenant and the authority chain from the authenticated principal, never from the
// request.
func caller(ctx context.Context) (tenant.ID, authority.Chain, error) {
	p, ok := apihost.PrincipalFrom(ctx)
	if !ok || p.ID == "" {
		return tenant.ID{}, authority.Chain{}, apitypes.Forbidden("")
	}
	t, err := tenantref.TenantFromText(p.Tenant)
	if err != nil {
		return t, authority.Chain{}, apitypes.Forbidden("")
	}
	kind := authority.Human
	if p.Kind == apihost.KindToken {
		kind = authority.APIToken
	}
	return t, authority.Chain{Requester: authority.Principal{ID: authority.PrincipalID(p.ID), Kind: kind}}, nil
}

// problem maps a Store error to a problem. The text of the error is never sent.
func (h Handlers) problem(err error) error {
	switch {
	case errors.Is(err, ErrNotFound):
		return apitypes.NotFound("")
	case errors.Is(err, ErrIdempotencyConflict):
		return apitypes.IdempotencyKeyReuse("")
	case errors.Is(err, ErrInvalidInput), errors.Is(err, ErrBadDestination), errors.Is(err, ErrPlaintextNotOptedIn):
		return apitypes.Validation("")
	}
	h.log().Error("siem destination request failed", "error_class", "internal")
	return apitypes.Internal("")
}

func spec(w api.SiemDestinationWrite) Spec {
	sp := Spec{Host: w.Host}
	if w.Port != nil {
		sp.Port = int(*w.Port)
	}
	if w.Transport != nil {
		sp.Transport = Transport(*w.Transport)
	}
	if w.PlaintextOptIn != nil {
		sp.PlaintextOptIn = *w.PlaintextOptIn
	}
	return sp
}

func wire(v View) (api.SiemDestination, error) {
	id, err := apitypes.ParseUUID(v.ID)
	if err != nil {
		return api.SiemDestination{}, err
	}
	out := api.SiemDestination{ID: id, Host: v.Host, Port: int64(v.Port), Transport: api.SiemTransport(v.Transport),
		TLSVerified: v.TLSVerified, PlaintextOptIn: v.PlaintextOptIn}
	if v.Warning != "" {
		w := v.Warning
		out.Warning = &w
	}
	return out, nil
}

// ListSiemDestinations implements api.Handlers.
func (h Handlers) ListSiemDestinations(ctx context.Context, _ api.ListSiemDestinationsInput) (api.ListSiemDestinationsOutput, error) {
	t, _, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	vs, err := h.Store.List(ctx, t)
	if err != nil {
		return nil, h.problem(err)
	}
	items := make([]api.SiemDestination, 0, len(vs))
	for _, v := range vs {
		d, err := wire(v)
		if err != nil {
			return nil, h.problem(err)
		}
		items = append(items, d)
	}
	return api.ListSiemDestinations200{Body: api.SiemDestinationList{Items: items}}, nil
}

// GetSiemDestination implements api.Handlers.
func (h Handlers) GetSiemDestination(ctx context.Context, in api.GetSiemDestinationInput) (api.GetSiemDestinationOutput, error) {
	t, _, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	v, err := h.Store.Get(ctx, t, in.DestinationID.String())
	if err != nil {
		return nil, h.problem(err)
	}
	d, err := wire(v)
	if err != nil {
		return nil, h.problem(err)
	}
	return api.GetSiemDestination200{Body: d}, nil
}

// CreateSiemDestination implements api.Handlers. The Idempotency-Key is the Store's request ID.
func (h Handlers) CreateSiemDestination(ctx context.Context, in api.CreateSiemDestinationInput) (api.CreateSiemDestinationOutput, error) {
	t, c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	v, err := h.Store.Create(ctx, t, spec(in.Body), c, in.IdempotencyKey)
	if err != nil {
		return nil, h.problem(err)
	}
	d, err := wire(v)
	if err != nil {
		return nil, h.problem(err)
	}
	return api.CreateSiemDestination201{Body: d}, nil
}

// UpdateSiemDestination implements api.Handlers.
func (h Handlers) UpdateSiemDestination(ctx context.Context, in api.UpdateSiemDestinationInput) (api.UpdateSiemDestinationOutput, error) {
	t, c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	v, err := h.Store.Update(ctx, t, in.DestinationID.String(), spec(in.Body), c, in.IdempotencyKey)
	if err != nil {
		return nil, h.problem(err)
	}
	d, err := wire(v)
	if err != nil {
		return nil, h.problem(err)
	}
	return api.UpdateSiemDestination200{Body: d}, nil
}
