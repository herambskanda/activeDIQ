package fleetsql

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tablekind"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

var _ = tablekind.Declare(tablekind.Table{Name: "public.components", Entity: "DM-12", Kind: tablekind.Tenant})
var _ = tablekind.Declare(tablekind.Table{Name: "public.enrollment_tokens", Entity: "DM-12", Kind: tablekind.Tenant})

// PermissionIssue is the permission that may issue an enrollment token (DM-12.I2). It is a tenant
// permission and needs a fresh multi-factor check.
const PermissionIssue = "fleet.enrollment.issue"

// Token lifetime: short by default, never more than the database allows.
const (
	DefaultTTL = time.Hour
	MaxTTL     = 24 * time.Hour
)

// Kind is what an enrolled component is.
type Kind string

// The two kinds of component (DM-12).
const (
	KindConnector Kind = "connector"
	KindAgent     Kind = "agent"
)

// Errors. None carries a token, a hash or SQL.
var (
	ErrForbidden       = errors.New("fleetsql: the principal may not issue enrollment tokens")
	ErrStepUpRequired  = errors.New("fleetsql: issuing an enrollment token needs a fresh multi-factor check")
	ErrInvalid         = errors.New("fleetsql: invalid component request")
	ErrTokenInvalid    = errors.New("fleetsql: enrollment token is not valid") // unknown, used, expired, revoked or malformed: one answer, so nothing is revealed
	ErrRateLimited     = errors.New("fleetsql: too many failed enrollment attempts")
	ErrNotConfigured   = errors.New("fleetsql: enrollment service is missing a dependency")
	errLimiterUnusable = errors.New("fleetsql: failure limiter unavailable")
)

// RateLimitedError carries the wait. It matches ErrRateLimited.
type RateLimitedError struct{ RetryAfter time.Duration }

func (e *RateLimitedError) Error() string   { return ErrRateLimited.Error() }
func (e *RateLimitedError) Is(t error) bool { return t == ErrRateLimited }

// Enrollment issues and redeems enrollment tokens.
type Enrollment struct {
	DB      *store.DB
	Authz   apihost.Authorizer
	StepUp  apihost.StepUpChecker
	Limiter FailureLimiter
}

// NewComponent asks for a pending component and the token that will enrol it.
type NewComponent struct {
	Kind Kind
	Name string
	TTL  time.Duration // 0 means DefaultTTL
}

func (n NewComponent) validate() (time.Duration, error) {
	if n.Kind != KindConnector && n.Kind != KindAgent {
		return 0, fmt.Errorf("%w: kind", ErrInvalid)
	}
	name := strings.TrimSpace(n.Name)
	if name == "" || utf8.RuneCountInString(name) > 200 || strings.ContainsFunc(name, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return 0, fmt.Errorf("%w: name", ErrInvalid)
	}
	ttl := n.TTL
	if ttl == 0 {
		ttl = DefaultTTL
	}
	if ttl < time.Minute || ttl > MaxTTL {
		return 0, fmt.Errorf("%w: ttl must be between 1 minute and %s", ErrInvalid, MaxTTL)
	}
	return ttl, nil
}

// Issued is the result of Issue. Token is the only copy of the plaintext.
type Issued struct {
	ComponentID string
	TokenID     string
	ExpiresAt   time.Time
	Token       Token
}

func (e *Enrollment) ready() error {
	if e == nil || e.DB == nil || e.Authz == nil || e.StepUp == nil || e.Limiter == nil {
		return ErrNotConfigured
	}
	return nil
}

// Issue creates a pending component and one enrollment token for it. Only the token's SHA-256 is
// stored; the plaintext is returned here and nowhere else. The principal must hold PermissionIssue
// and have completed step-up, both checked server-side before any write. The caller records the
// audited Operation around this call (who: p.ID, what: the returned ComponentID and TokenID).
func (e *Enrollment) Issue(ctx context.Context, tid tenant.ID, p apihost.Principal, n NewComponent) (Issued, error) {
	if err := e.ready(); err != nil {
		return Issued{}, err
	}
	ttl, err := n.validate()
	if err != nil {
		return Issued{}, err
	}
	if p.ID == "" || utf8.RuneCountInString(p.ID) > 200 {
		return Issued{}, ErrForbidden
	}
	ok, err := e.Authz.Allow(ctx, p, PermissionIssue, "tenant")
	if err != nil {
		return Issued{}, fmt.Errorf("fleetsql: authorize: %w", err)
	}
	if !ok {
		return Issued{}, ErrForbidden
	}
	fresh, err := e.StepUp.Fresh(ctx, p)
	if err != nil {
		return Issued{}, fmt.Errorf("fleetsql: step-up check: %w", err)
	}
	if !fresh {
		return Issued{}, ErrStepUpRequired
	}
	tok, h, err := newToken(tid)
	if err != nil {
		return Issued{}, err
	}
	out := Issued{Token: tok}
	err = e.DB.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) error {
		if err := tx.QueryRow(ctx, `INSERT INTO public.components (tenant_id, kind, name)
			VALUES (NULLIF(current_setting('app.tenant_id', true), '')::uuid, $1, $2) RETURNING id::text`,
			string(n.Kind), strings.TrimSpace(n.Name)).Scan(&out.ComponentID); err != nil {
			return fmt.Errorf("fleetsql: create component: %w", err)
		}
		if err := tx.QueryRow(ctx, `INSERT INTO public.enrollment_tokens (tenant_id, component_id, token_hash, issued_by, expires_at)
			VALUES (NULLIF(current_setting('app.tenant_id', true), '')::uuid, $1::uuid, $2, $3, now() + make_interval(secs => $4::float8))
			RETURNING id::text, expires_at`,
			out.ComponentID, h[:], p.ID, ttl.Seconds()).Scan(&out.TokenID, &out.ExpiresAt); err != nil {
			return fmt.Errorf("fleetsql: store token: %w", err)
		}
		return nil
	})
	if err != nil {
		return Issued{}, err
	}
	return out, nil
}

// Redeemed names the component a token enrolled. The tenant is the token's, resolved here, so the
// Enroll handler never takes one from a message.
type Redeemed struct {
	TenantID    tenant.ID
	ComponentID string
	Kind        Kind
	Name        string
}

// Redeem consumes a token: exactly one caller of the same token succeeds, however many race. A token
// that is unknown, malformed, expired, already used or whose component is no longer pending returns
// ErrTokenInvalid, the same answer for each. source is the peer address the gateway saw; once it has
// spent its redeem budget every attempt is refused with ErrRateLimited before the token is
// looked at, so the refusal says nothing about whether the token exists.
func (e *Enrollment) Redeem(ctx context.Context, source string, tok Token) (Redeemed, error) {
	if err := e.ready(); err != nil {
		return Redeemed{}, err
	}
	if _, ok := sourceKey(source); !ok {
		// A programming error in the caller (it must pass the transport peer), not a client fault:
		// fail closed without touching any shared bucket.
		return Redeemed{}, fmt.Errorf("%w: redeem source is not an IP address", ErrNotConfigured)
	}
	wait, admitted, err := e.Limiter.Admit(ctx, source)
	if err != nil {
		return Redeemed{}, fmt.Errorf("%w: %w", errLimiterUnusable, err) // fail closed
	}
	if !admitted {
		return Redeemed{}, &RateLimitedError{RetryAfter: wait}
	}
	tid, ok := tenantOf(tok)
	if !ok {
		return Redeemed{}, ErrTokenInvalid
	}
	h := hash(tok)
	out := Redeemed{TenantID: tid}
	err = e.DB.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) error {
		var kind string
		err := tx.QueryRow(ctx, `WITH used AS (
				UPDATE public.enrollment_tokens t SET used_at = now()
				WHERE t.token_hash = $1 AND t.used_at IS NULL AND t.expires_at > now()
				  AND EXISTS (SELECT 1 FROM public.components c WHERE c.tenant_id = t.tenant_id AND c.id = t.component_id AND c.state = 'pending')
				RETURNING t.tenant_id, t.component_id)
			SELECT c.id::text, c.kind, c.name FROM used u JOIN public.components c ON c.tenant_id = u.tenant_id AND c.id = u.component_id`,
			h[:]).Scan(&out.ComponentID, &kind, &out.Name)
		if store.IsNoRows(err) {
			return ErrTokenInvalid
		}
		if err != nil {
			return fmt.Errorf("fleetsql: redeem: %w", err)
		}
		out.Kind = Kind(kind)
		return nil
	})
	if err != nil {
		return Redeemed{}, err
	}
	e.Limiter.Succeeded(ctx, source)
	return out, nil
}
