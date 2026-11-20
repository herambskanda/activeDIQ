package helpdesk

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"time"

	"github.com/skenzeriq/activediq/internal/modules/helpdesk/api"
	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
	"github.com/skenzeriq/activediq/internal/platform/authn/tenantref"
	"github.com/skenzeriq/activediq/internal/platform/limiter"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// VerifyPermission is what both routes need. It is not objects.user.reset_password: that permission is a step-up
// permission (TM-D16), and a verified caller is what stands in for the technician's step-up, so routing it here would
// demand the MFA the verification replaces.
const VerifyPermission = "helpdesk.caller.verify"

// Service is what the handlers need of the engine. *Verifier satisfies it.
type Service interface {
	IssueOnce(ctx context.Context, key string, in IssueInput) (Challenge, error)
	VerifyOnce(ctx context.Context, key string, in VerifyInput) (Verified, error)
}

var _ Service = (*Verifier)(nil)

// Limits of the handler, on top of apihost's per-IP floor and per-principal class and the engine's own caps
// (4.3, 4.6, 4.7). Per-IP is generous because a help desk shares one NAT address; per-session is the tight one.
// They live in the shared principal store, so every node sees one budget.
var (
	sessionIssueLimit  = limiter.Limit{Rate: 10, Burst: 5}
	sessionVerifyLimit = limiter.Limit{Rate: 20, Burst: 10}
	ipIssueLimit       = limiter.Limit{Rate: 60, Burst: 30}
	ipVerifyLimit      = limiter.Limit{Rate: 120, Burst: 40}
)

// RefusalFloor is the least time a refusal takes. Every refusal waits out the rest of it, so a wrong code, a used-up
// cap, an unknown challenge and an ineligible target cost the same to a client that times them (acceptance 2, AC-OTP-12).
const RefusalFloor = 300 * time.Millisecond

// Handlers implements api.Handlers. It holds no domain logic: it maps the request onto the engine and the engine's
// refusals onto problems. Both operations are POST only; a console session carries the CSRF check at apihost chain
// step 9, and a token is refused here because the verifier is the human at the console (DM-38.I4).
type Handlers struct {
	Service  Service
	Throttle limiter.PrincipalStore // shared store of the per-session and per-IP buckets; nil refuses every request
	Floor    time.Duration          // 0 takes RefusalFloor
	Now      func() time.Time       // nil: time.Now
	Sleep    func(ctx context.Context, d time.Duration)
	Log      *slog.Logger
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

func (h Handlers) floor() time.Duration {
	if h.Floor > 0 {
		return h.Floor
	}
	return RefusalFloor
}

func (h Handlers) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

func (h Handlers) sleep(ctx context.Context, d time.Duration) {
	if d <= 0 {
		return
	}
	if h.Sleep != nil {
		h.Sleep(ctx, d)
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

// caller is the technician: the console session's tenant and account. A token, a missing principal or a bad
// tenant is a bare 403.
func caller(ctx context.Context) (tenant.ID, apihost.Principal, error) {
	var none tenant.ID // the zero tenant accompanies every refusal
	p, ok := apihost.PrincipalFrom(ctx)
	if !ok || p.ID == "" || p.Kind != apihost.KindSession || p.SessionID == "" {
		return none, p, apitypes.Forbidden("")
	}
	t, err := tenantref.TenantFromText(p.Tenant)
	if err != nil {
		return none, p, apitypes.Forbidden("")
	}
	return t, p, nil
}

// throttle takes one token from the per-IP bucket and one from the per-session bucket. Either bucket empty is 429.
// No store, or a store fault, refuses: a limit that cannot be counted is not skipped.
func (h Handlers) throttle(ctx context.Context, op string, p apihost.Principal, session, ip limiter.Limit) error {
	if h.Throttle == nil {
		return apitypes.NotReady("")
	}
	for _, b := range []struct {
		key string
		lim limiter.Limit
	}{
		{"helpdesk.cv/ip/" + op + "/" + ipPrefix(apihost.SourceIPFrom(ctx)), ip},
		{"helpdesk.cv/session/" + op + "/" + p.Tenant + "/" + p.SessionID, session},
	} {
		d, err := h.Throttle.Take(ctx, b.key, b.lim)
		if err != nil {
			h.log().Error("caller verification: rate limit store failed", "error_class", "internal")
			return apitypes.Internal("")
		}
		if !d.Allowed {
			return apitypes.RateLimited("")
		}
	}
	return nil
}

// ipPrefix keys a source address by the same prefix the limiter uses (§7.8), never by the raw string.
func ipPrefix(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return "unparseable"
	}
	pre, ok := limiter.SourcePrefix(a, limiter.DefaultIPv4Bits, limiter.DefaultIPv6Bits)
	if !ok {
		return "unparseable"
	}
	return pre.String()
}

// refuse answers a refusal no sooner than the floor after the request began.
func (h Handlers) refuse(ctx context.Context, began time.Time, p *apitypes.Problem) error {
	h.sleep(ctx, h.floor()-h.now().Sub(began))
	return p
}

func (h Handlers) fault(err error) error {
	h.log().Error("caller verification failed", "error_class", "internal")
	_ = err // the text of an engine error is never sent or logged: it may name a target
	return apitypes.Internal("")
}

// IssueCallerVerification implements api.Handlers.
func (h Handlers) IssueCallerVerification(ctx context.Context, in api.IssueCallerVerificationInput) (api.IssueCallerVerificationOutput, error) {
	began := h.now()
	t, p, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	if h.Service == nil {
		return nil, apitypes.NotReady("")
	}
	if err := h.throttle(ctx, "issue", p, sessionIssueLimit, ipIssueLimit); err != nil {
		return nil, err
	}
	resend := in.Body.Resend != nil && *in.Body.Resend
	ch, err := h.Service.IssueOnce(ctx, in.IdempotencyKey, IssueInput{
		Tenant: t, Technician: p.ID,
		Target: Target{ConnectionID: in.Body.ConnectionID.String(), ObjectGUID: in.Body.ObjectGUID.String()},
		Factor: Factor(in.Body.Factor), Resend: resend,
	})
	switch {
	case err == nil:
		id, perr := apitypes.ParseUUID(ch.ID)
		if perr != nil {
			return nil, h.fault(perr)
		}
		return api.IssueCallerVerification200{Body: api.CallerVerificationChallenge{
			ChallengeID: id, Factor: api.CallerVerificationFactor(ch.Factor), DestinationMasked: ch.Masked,
			ExpiresAt: apitypes.NewTimestamp(ch.ExpiresAt), Reused: ch.Reused}}, nil
	case errors.Is(err, ErrNotAuthorised), errors.Is(err, ErrNoDestination):
		// One answer for every ineligible target (4.18), the same cost whichever check refused.
		return nil, h.refuse(ctx, began, apitypes.CallerVerificationUnavailable(""))
	case errors.Is(err, ErrQuota):
		return nil, limitProblem("quota")
	case errors.Is(err, ErrPaused):
		return nil, limitProblem("paused")
	case errors.Is(err, ErrDelivery):
		return nil, apitypes.CallerVerificationDeliveryFailed("")
	default:
		return nil, h.keyOrFault(err)
	}
}

func limitProblem(code string) *apitypes.Problem {
	var e apitypes.Errors
	e.AddBody("", code, "")
	return apitypes.CallerVerificationLimit("").WithErrors(&e)
}

// keyOrFault maps the idempotency and shape errors both operations share.
func (h Handlers) keyOrFault(err error) error {
	switch {
	case errors.Is(err, ErrKeyReuse):
		return apitypes.IdempotencyKeyReuse("")
	case errors.Is(err, ErrKeyInFlight):
		return apitypes.Conflict("a request with this Idempotency-Key is still being processed")
	case errors.Is(err, ErrKeyInvalid), errors.Is(err, ErrInvalid):
		return apitypes.Validation("")
	}
	return h.fault(err)
}

// VerifyCallerVerification implements api.Handlers.
func (h Handlers) VerifyCallerVerification(ctx context.Context, in api.VerifyCallerVerificationInput) (api.VerifyCallerVerificationOutput, error) {
	began := h.now()
	t, p, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	if h.Service == nil {
		return nil, apitypes.NotReady("")
	}
	if err := h.throttle(ctx, "verify", p, sessionVerifyLimit, ipVerifyLimit); err != nil {
		return nil, err
	}
	code, ok := readCode(in)
	if !ok {
		var e apitypes.Errors
		e.AddBody("/code", "code_invalid", "The code is six digits.")
		return nil, apitypes.Validation("").WithErrors(&e)
	}
	v, err := h.Service.VerifyOnce(ctx, in.IdempotencyKey, VerifyInput{Tenant: t, Technician: p.ID, ChallengeID: in.ChallengeID.String(), Code: code})
	switch {
	case err == nil:
		id, perr := apitypes.ParseUUID(v.ChallengeID)
		if perr != nil {
			return nil, h.fault(perr)
		}
		return api.VerifyCallerVerification200{Body: api.CallerVerified{ChallengeID: id, AuthorisedUntil: apitypes.NewTimestamp(v.Until)}}, nil
	case errors.Is(err, ErrRefused):
		// The cap, a wrong code, an expired, superseded, foreign or unknown challenge: one answer (acceptance 2).
		return nil, h.refuse(ctx, began, apitypes.CallerVerificationRefused(""))
	default:
		return nil, h.keyOrFault(err)
	}
}

// readCode returns the code when it is exactly six ASCII digits. The text is the engine's input; it is held
// in a Secret until here and copied only for the comparison.
func readCode(in api.VerifyCallerVerificationInput) (string, bool) {
	var code string
	ok := false
	in.Body.Code.Expose(func(b []byte) {
		if len(b) != CodeLength {
			return
		}
		for _, c := range b {
			if c < '0' || c > '9' {
				return
			}
		}
		code, ok = string(b), true
	})
	return code, ok
}
