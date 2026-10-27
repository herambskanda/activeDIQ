package connections

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/modules/connections/api"
	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Where the callback sends the browser. Fixed strings: nothing from the request or the IdP is put in a
// redirect.
const (
	AttestRecordedLocation = "/connections?takeover-attestation=recorded"
	AttestFailedLocation   = "/connections?takeover-attestation=failed"
)

// CallbackGate limits the unauthenticated callback before it reaches Attester.Callback, which writes an
// audit row for every bad state (security review of T-0280, finding a). Allow is asked once per request,
// first with the source and then, once the state names a tenant, with the tenant.
type CallbackGate interface {
	AllowSource(src string) bool
	AllowTenant(t tenant.ID) bool
}

// WindowGate is a fixed-window CallbackGate held in memory. A full table does not admit a new key: it
// shares the overflow bucket, so a flood of distinct sources is throttled together, never admitted.
type WindowGate struct {
	PerSource int           // requests per window per source; zero: 20
	PerTenant int           // requests per window per tenant; zero: 60
	Window    time.Duration // zero: one minute
	MaxKeys   int           // zero: 4096
	Now       func() time.Time

	mu      sync.Mutex
	start   time.Time
	sources map[string]int
	tenants map[tenant.ID]int
}

var _ CallbackGate = (*WindowGate)(nil)

func (g *WindowGate) roll() {
	now := time.Now
	if g.Now != nil {
		now = g.Now
	}
	w := g.Window
	if w <= 0 {
		w = time.Minute
	}
	if g.sources == nil || now().Sub(g.start) >= w {
		g.start = now()
		g.sources, g.tenants = map[string]int{}, map[tenant.ID]int{}
	}
}

func (g *WindowGate) max() int {
	if g.MaxKeys > 0 {
		return g.MaxKeys
	}
	return 4096
}

// AllowSource implements CallbackGate. IPv6 sources count per /64 and IPv4 per address, like the
// platform limiter (threat model §7.8); an unparseable source shares one bucket.
func (g *WindowGate) AllowSource(src string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.roll()
	key := sourceKey(src)
	if _, seen := g.sources[key]; !seen && len(g.sources) >= g.max() {
		key = "overflow"
	}
	g.sources[key]++
	n := g.PerSource
	if n <= 0 {
		n = 20
	}
	return g.sources[key] <= n
}

// AllowTenant implements CallbackGate.
func (g *WindowGate) AllowTenant(t tenant.ID) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.roll()
	if _, seen := g.tenants[t]; !seen && len(g.tenants) >= g.max() {
		t = tenant.ID{}
	}
	g.tenants[t]++
	n := g.PerTenant
	if n <= 0 {
		n = 60
	}
	return g.tenants[t] <= n
}

func sourceKey(src string) string {
	a, err := netip.ParseAddr(src)
	if err != nil {
		return "unparseable"
	}
	a = a.WithZone("").Unmap()
	if a.Is6() {
		p, _ := a.Prefix(64)
		return p.String()
	}
	return a.String()
}

// AttestHandlers implements the generated Handlers of the connections tag for the attestation.
type AttestHandlers struct {
	Attester *Attester
	Gate     CallbackGate
	Log      *slog.Logger // nil: slog.Default()
}

var _ api.Handlers = (*AttestHandlers)(nil)

func (h *AttestHandlers) log() *slog.Logger {
	if h.Log != nil {
		return h.Log
	}
	return slog.Default()
}

// sessionRequest derives who asks from the authenticated principal. Only a console session is a human
// with a step-up; a token is refused here and never reaches the Attester.
func sessionRequest(ctx context.Context) (tenant.ID, authority.Chain, string, error) {
	p, ok := apihost.PrincipalFrom(ctx)
	if !ok || p.Kind != apihost.KindSession || p.SessionID == "" {
		return tenant.ID{}, authority.Chain{}, "", apitypes.Forbidden("")
	}
	t, err := tenant.Parse(p.Tenant)
	if err != nil || t.IsZero() {
		return tenant.ID{}, authority.Chain{}, "", apitypes.Forbidden("")
	}
	return t, authority.Chain{Requester: authority.Principal{ID: authority.PrincipalID(p.ID), Kind: authority.Human}}, p.SessionID, nil
}

// problem maps an Attester error to a problem. The text of the error is never sent.
func (h *AttestHandlers) problem(err error) error {
	switch {
	case errors.Is(err, ErrNotPermitted):
		return apitypes.Forbidden("")
	case errors.Is(err, ErrStepUpRequired):
		return apitypes.StepUpRequired("")
	case errors.Is(err, ErrNotAttestable), errors.Is(err, connection.ErrNotFound):
		return apitypes.NotFound("")
	case errors.Is(err, connection.ErrAttestationMaxAge):
		return apitypes.Validation("")
	}
	h.log().Error("takeover attestation failed", "error_class", "internal")
	return apitypes.Internal("")
}

// StartTakeoverAttestation implements api.Handlers.
func (h *AttestHandlers) StartTakeoverAttestation(ctx context.Context, in api.StartTakeoverAttestationInput) (api.StartTakeoverAttestationOutput, error) {
	t, c, sid, err := sessionRequest(ctx)
	if err != nil {
		return nil, err
	}
	u, err := h.Attester.Start(ctx, StartRequest{Tenant: t, ConnectionID: connection.ID(in.ConnectionID.String()), Chain: c, SessionID: sid})
	if err != nil {
		return nil, h.problem(err)
	}
	return api.StartTakeoverAttestation200{Body: api.TakeoverAttestationStart{AuthorizeURL: u}}, nil
}

// SetTakeoverAttestationMaxAge implements api.Handlers.
func (h *AttestHandlers) SetTakeoverAttestationMaxAge(ctx context.Context, in api.SetTakeoverAttestationMaxAgeInput) (api.SetTakeoverAttestationMaxAgeOutput, error) {
	t, c, sid, err := sessionRequest(ctx)
	if err != nil {
		return nil, err
	}
	err = h.Attester.SetMaxAge(ctx, MaxAgeRequest{Tenant: t, ConnectionID: connection.ID(in.ConnectionID.String()), Chain: c,
		SessionID: sid, MaxAge: time.Duration(in.Body.MaxAgeSeconds) * time.Second})
	if err != nil {
		return nil, h.problem(err)
	}
	return api.SetTakeoverAttestationMaxAge204{}, nil
}

// CompleteTakeoverAttestation implements api.Handlers. The request is unauthenticated: it is limited by
// source first, then by the tenant its state names, and only then reaches the Attester. Every outcome
// but a recorded attestation is the same redirect; the cause is in the audit.
func (h *AttestHandlers) CompleteTakeoverAttestation(ctx context.Context, in api.CompleteTakeoverAttestationInput) (api.CompleteTakeoverAttestationOutput, error) {
	failed := api.CompleteTakeoverAttestation303{Location: AttestFailedLocation}
	if h.Gate == nil || !h.Gate.AllowSource(in.PeerIP) {
		return nil, apitypes.RateLimited("")
	}
	t, ok := StateTenant(in.State)
	if !ok {
		return failed, nil
	}
	if !h.Gate.AllowTenant(t) {
		return nil, apitypes.RateLimited("")
	}
	code := ""
	if in.Code != nil && in.Error == nil {
		code = *in.Code
	}
	if _, err := h.Attester.Callback(ctx, CallbackRequest{Tenant: t, State: in.State, Code: code}); err != nil {
		return failed, nil
	}
	return api.CompleteTakeoverAttestation303{Location: AttestRecordedLocation}, nil
}

// Bind returns the tag's routes for apihost.Build.
func (h *AttestHandlers) Bind() apihost.TagHandlers { return api.Bind(h) }
