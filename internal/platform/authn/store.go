package authn

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tablekind"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

var _ = tablekind.Declare(tablekind.Table{Name: "public.authn_sessions", Entity: "DM-31", Kind: tablekind.Tenant})

// Errors. None carries a token, a hash, SQL or a stored value. A caller answers all of ErrSessionNotFound,
// ErrExpired and ErrRevoked with the same 401; they differ only for the audit trail.
var (
	ErrSessionNotFound = errors.New("authn: no such session")
	ErrExpired         = errors.New("authn: session expired")
	ErrRevoked         = errors.New("authn: session revoked")
	// ErrInvalid is returned for input that is not acceptable (a malformed ID, an unknown reason, no
	// authentication method). No SQL has run.
	ErrInvalid = errors.New("authn: invalid input")
)

// Reason is why a session was revoked. The set is closed and matches the table's CHECK.
type Reason string

// Reasons a caller may revoke with. Expiry and the concurrent limit are the store's own.
const (
	ReasonAccountDisabled Reason = "account_disabled" // DM-31.I2
	ReasonRoleChanged     Reason = "role_changed"
	ReasonPasswordReset   Reason = "password_reset"
	ReasonMFAReset        Reason = "mfa_reset"
	ReasonLogout          Reason = "logout"
	ReasonOnDemand        Reason = "on_demand"
)

func (r Reason) valid() bool {
	switch r {
	case ReasonAccountDisabled, ReasonRoleChanged, ReasonPasswordReset, ReasonMFAReset, ReasonLogout, ReasonOnDemand:
		return true
	}
	return false
}

// SessionState is a session's lifecycle state: active, then expired or revoked.
type SessionState string

// States.
const (
	SessionActive  SessionState = "active"
	SessionExpired SessionState = "expired"
	SessionRevoked SessionState = "revoked"
)

// PolicySource gives a tenant's session policy. It is read on every Create and Lookup, so a change
// takes effect on the next request.
type PolicySource interface {
	SessionPolicy(ctx context.Context, t tenant.ID) (Policy, error)
}

// StaticPolicy is a PolicySource that gives every tenant one Policy.
type StaticPolicy Policy

// SessionPolicy implements PolicySource.
func (s StaticPolicy) SessionPolicy(context.Context, tenant.ID) (Policy, error) {
	return Policy(s), nil
}

// Config configures a Store.
type Config struct {
	DB       *store.DB
	Policies PolicySource // nil means DefaultPolicy for every tenant
	Bounds   Bounds       // zero means DefaultBounds
	// TouchEvery is how often a busy session writes its sliding idle expiry; 0 means 30 seconds. It
	// keeps one write per session per interval off the request path.
	TouchEvery time.Duration
	// Clock overrides the time source. Nil uses the database clock, which every node shares, so node
	// clock skew never lengthens or shortens a session. Tests set it.
	Clock func() time.Time
}

// Store is the session store. It is safe for concurrent use and holds no session state: every node
// sharing a database sees the same sessions.
type Store struct {
	db       *store.DB
	policies PolicySource
	bounds   Bounds
	touch    time.Duration
	clock    func() time.Time
}

// New returns a Store.
func New(cfg Config) (*Store, error) {
	if cfg.DB == nil {
		return nil, errors.New("authn: Store needs a database")
	}
	s := &Store{db: cfg.DB, policies: cfg.Policies, bounds: cfg.Bounds, touch: cfg.TouchEvery, clock: cfg.Clock}
	if s.policies == nil {
		s.policies = StaticPolicy(DefaultPolicy)
	}
	if s.bounds == (Bounds{}) {
		s.bounds = DefaultBounds
	}
	if s.touch <= 0 {
		s.touch = 30 * time.Second
	}
	return s, nil
}

// Session is a session as the rest of the product sees it. It never holds the token or its hash.
type Session struct {
	ID                string // a handle for listing and revoking; not the token
	Tenant            tenant.ID
	Account           string
	Methods           []string
	MFAAt             *time.Time
	AuthorityFactorAt *time.Time
	ClientIP          netip.Addr
	CreatedAt         time.Time
	LastSeenAt        time.Time
	IdleExpiry        time.Time
	AbsoluteExpiry    time.Time
	State             SessionState
}

// CreateInput is what sign-in knows.
type CreateInput struct {
	Tenant tenant.ID
	// Account is the console account's ID, a canonical UUID.
	Account string
	// Methods are how the account authenticated, at least one (for example "password", "totp").
	Methods           []string
	MFAAt             *time.Time
	AuthorityFactorAt *time.Time
	ClientIP          netip.Addr // zero when unknown
}

// CreateResult is returned by Create.
type CreateResult struct {
	// Token is the plain session ID. This is the only time it exists outside the client.
	Token   Token
	Session Session
	// Evicted is how many of the account's other sessions the concurrent limit revoked.
	Evicted int
}

const (
	sqlClock  = `SELECT clock_timestamp()`
	sqlAcctLk = `SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))`

	// expireDue ends an account's sessions whose deadline has passed. $2 is NULL for every account.
	expireDue = `UPDATE public.authn_sessions
SET state = 'expired', ended_at = $3,
    end_reason = CASE WHEN absolute_expiry <= $3 THEN 'absolute_timeout' ELSE 'idle_timeout' END
WHERE tenant_id = $1 AND ($2::uuid IS NULL OR account_id = $2::uuid) AND state = 'active'
  AND (idle_expiry <= $3 OR absolute_expiry <= $3)`

	// evict revokes the $4 sessions of one account that the policy ($3) ranks first.
	evict = `UPDATE public.authn_sessions
SET state = 'revoked', ended_at = $5, end_reason = 'concurrent_limit'
WHERE tenant_id = $1 AND id IN (
  SELECT id FROM public.authn_sessions
  WHERE tenant_id = $1 AND account_id = $2::uuid AND state = 'active'
  ORDER BY CASE WHEN $3::text = 'least_recently_used' THEN last_seen_at ELSE created_at END, created_at, id
  LIMIT $4)`

	countActive = `SELECT count(*) FROM public.authn_sessions WHERE tenant_id = $1 AND account_id = $2::uuid AND state = 'active'`

	insert = `INSERT INTO public.authn_sessions
  (tenant_id, id_hash, account_id, methods, mfa_at, authority_factor_at, client_ip, created_at, last_seen_at, idle_expiry, absolute_expiry)
VALUES ($1, $2, $3::uuid, $4, $5, $6, $7, $8, $8, $9, $10)
RETURNING id`

	columns = `id, account_id::text, methods, mfa_at, authority_factor_at, client_ip, created_at, last_seen_at, idle_expiry, absolute_expiry, state`
)

// now reads the clock: the database's unless a test set one.
func (s *Store) now(ctx context.Context, tx store.Tx) (time.Time, error) {
	if s.clock != nil {
		return s.clock().UTC(), nil
	}
	var t time.Time
	if err := tx.QueryRow(ctx, sqlClock).Scan(&t); err != nil {
		return time.Time{}, err
	}
	return t.UTC(), nil
}

func (s *Store) policy(ctx context.Context, t tenant.ID) (Policy, error) {
	p, err := s.policies.SessionPolicy(ctx, t)
	if err != nil {
		return Policy{}, fmt.Errorf("authn: read session policy: %w", err)
	}
	if err := p.Validate(s.bounds); err != nil {
		return Policy{}, err
	}
	return p, nil
}

func validAccount(a string) bool {
	_, err := tenant.Parse(a) // the canonical-UUID parser; the zero UUID is refused too
	return err == nil
}

// Create opens a session for an authenticated account. In one transaction, serialised per account, it
// ends the account's sessions that are past their deadline, revokes as many of the rest as the policy's
// eviction ranks first so that the new session is within the concurrent limit, and stores the new one
// with only the hash of its token.
func (s *Store) Create(ctx context.Context, in CreateInput) (CreateResult, error) {
	if in.Tenant.IsZero() || !validAccount(in.Account) || len(in.Methods) == 0 || len(in.Methods) > 8 {
		return CreateResult{}, ErrInvalid
	}
	for _, m := range in.Methods {
		if m == "" || len(m) > 32 {
			return CreateResult{}, ErrInvalid
		}
	}
	pol, err := s.policy(ctx, in.Tenant)
	if err != nil {
		return CreateResult{}, err
	}
	tok, err := newToken(in.Tenant)
	if err != nil {
		return CreateResult{}, err
	}
	var ip *netip.Addr
	if in.ClientIP.IsValid() {
		a := in.ClientIP.Unmap()
		ip = &a
	}
	res := CreateResult{Token: tok}
	err = s.db.WithTenant(ctx, in.Tenant, func(ctx context.Context, tx store.Tx) error {
		now, err := s.now(ctx, tx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, sqlAcctLk, in.Tenant.String()+"/"+in.Account); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, expireDue, in.Tenant.String(), in.Account, now); err != nil {
			return err
		}
		var active int
		if err := tx.QueryRow(ctx, countActive, in.Tenant.String(), in.Account).Scan(&active); err != nil {
			return err
		}
		if over := active - (pol.MaxConcurrent - 1); over > 0 {
			tag, err := tx.Exec(ctx, evict, in.Tenant.String(), in.Account, string(pol.Eviction), over, now)
			if err != nil {
				return err
			}
			res.Evicted = int(tag.RowsAffected())
		}
		idle := now.Add(pol.Idle)
		abs := now.Add(pol.Absolute)
		if idle.After(abs) {
			idle = abs
		}
		var id string
		if err := tx.QueryRow(ctx, insert, in.Tenant.String(), tok.hash(), in.Account, in.Methods, in.MFAAt, in.AuthorityFactorAt, ip, now, idle, abs).Scan(&id); err != nil {
			return err
		}
		res.Session = Session{ID: id, Tenant: in.Tenant, Account: in.Account, Methods: append([]string(nil), in.Methods...),
			MFAAt: in.MFAAt, AuthorityFactorAt: in.AuthorityFactorAt, ClientIP: in.ClientIP.Unmap(),
			CreatedAt: now, LastSeenAt: now, IdleExpiry: idle, AbsoluteExpiry: abs, State: SessionActive}
		return nil
	})
	if err != nil {
		return CreateResult{}, fmt.Errorf("authn: create session: %w", err)
	}
	return res, nil
}

func scanSession(t tenant.ID, row interface{ Scan(dest ...any) error }) (Session, error) {
	var s Session
	var ip *netip.Addr
	var st string
	if err := row.Scan(&s.ID, &s.Account, &s.Methods, &s.MFAAt, &s.AuthorityFactorAt, &ip, &s.CreatedAt, &s.LastSeenAt, &s.IdleExpiry, &s.AbsoluteExpiry, &st); err != nil {
		return Session{}, err
	}
	if ip != nil {
		s.ClientIP = *ip
	}
	s.Tenant, s.State = t, SessionState(st)
	return s, nil
}

// Lookup resolves a token presented by a client. It refuses a token whose session does not exist, was
// revoked, or is past its idle or absolute deadline; the last case also marks the session expired. A
// live session's idle expiry slides forward, never past its absolute expiry. The deadlines are the
// stricter of the stored ones and the tenant's current policy, so tightening the policy ends sessions
// that the tighter rule would already have ended.
func (s *Store) Lookup(ctx context.Context, tok Token) (Session, error) {
	t, err := tok.Tenant()
	if err != nil {
		return Session{}, ErrSessionNotFound
	}
	pol, err := s.policy(ctx, t)
	if err != nil {
		return Session{}, err
	}
	var (
		sess    Session
		outcome error
	)
	err = s.db.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		now, err := s.now(ctx, tx)
		if err != nil {
			return err
		}
		sess, err = scanSession(t, tx.QueryRow(ctx, `SELECT `+columns+` FROM public.authn_sessions WHERE tenant_id = $1 AND id_hash = $2 FOR UPDATE`, t.String(), tok.hash()))
		if store.IsNoRows(err) {
			outcome = ErrSessionNotFound
			return nil
		}
		if err != nil {
			return err
		}
		switch sess.State {
		case SessionRevoked:
			outcome = ErrRevoked
			return nil
		case SessionExpired:
			outcome = ErrExpired
			return nil
		}
		idleDeadline := minTime(sess.IdleExpiry, sess.LastSeenAt.Add(pol.Idle))
		absDeadline := minTime(sess.AbsoluteExpiry, sess.CreatedAt.Add(pol.Absolute))
		if !now.Before(idleDeadline) || !now.Before(absDeadline) {
			reason := "idle_timeout"
			if !now.Before(absDeadline) {
				reason = "absolute_timeout"
			}
			if _, err := tx.Exec(ctx, `UPDATE public.authn_sessions SET state = 'expired', ended_at = $3, end_reason = $4 WHERE tenant_id = $1 AND id = $2::uuid AND state = 'active'`,
				t.String(), sess.ID, now, reason); err != nil {
				return err
			}
			outcome = ErrExpired
			return nil // commit the marking
		}
		if now.Sub(sess.LastSeenAt) >= s.touch {
			next := minTime(now.Add(pol.Idle), absDeadline)
			if _, err := tx.Exec(ctx, `UPDATE public.authn_sessions SET last_seen_at = $3, idle_expiry = $4 WHERE tenant_id = $1 AND id = $2::uuid AND state = 'active'`,
				t.String(), sess.ID, now, next); err != nil {
				return err
			}
			sess.LastSeenAt, sess.IdleExpiry = now, next
		}
		return nil
	})
	if err != nil {
		return Session{}, fmt.Errorf("authn: look up session: %w", err)
	}
	if outcome != nil {
		return Session{}, outcome
	}
	return sess, nil
}

func minTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

// Revoke ends one session by its handle, on demand or for a stated reason. It reports whether it ended
// one: revoking an already-ended or unknown session is not an error and returns false.
func (s *Store) Revoke(ctx context.Context, t tenant.ID, sessionID string, why Reason) (bool, error) {
	if t.IsZero() || !validAccount(sessionID) || !why.valid() {
		return false, ErrInvalid
	}
	return s.revoke(ctx, t, `UPDATE public.authn_sessions SET state = 'revoked', ended_at = $4, end_reason = $3
WHERE tenant_id = $1 AND id = $2::uuid AND state = 'active'`, sessionID, why)
}

// RevokeAccount ends every active session of an account: on account disable (DM-31.I2), role change,
// password or MFA reset, and on demand. It returns how many it ended. Because the store is shared, the
// next Lookup on any node refuses them.
func (s *Store) RevokeAccount(ctx context.Context, t tenant.ID, account string, why Reason) (int, error) {
	if t.IsZero() || !validAccount(account) || !why.valid() {
		return 0, ErrInvalid
	}
	return s.revokeN(ctx, t, `UPDATE public.authn_sessions SET state = 'revoked', ended_at = $4, end_reason = $3
WHERE tenant_id = $1 AND account_id = $2::uuid AND state = 'active'`, account, why)
}

// Logout ends the session a token names.
func (s *Store) Logout(ctx context.Context, tok Token) error {
	t, err := tok.Tenant()
	if err != nil {
		return ErrSessionNotFound
	}
	n, err := s.revokeN(ctx, t, `UPDATE public.authn_sessions SET state = 'revoked', ended_at = $4, end_reason = $3
WHERE tenant_id = $1 AND id_hash = $2 AND state = 'active'`, tok.hash(), ReasonLogout)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrSessionNotFound
	}
	return nil
}

func (s *Store) revoke(ctx context.Context, t tenant.ID, sql string, key any, why Reason) (bool, error) {
	n, err := s.revokeN(ctx, t, sql, key, why)
	return n > 0, err
}

func (s *Store) revokeN(ctx context.Context, t tenant.ID, sql string, key any, why Reason) (int, error) {
	var n int
	err := s.db.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		now, err := s.now(ctx, tx)
		if err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, sql, t.String(), key, string(why), now)
		n = int(tag.RowsAffected())
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("authn: revoke: %w", err)
	}
	return n, nil
}

// ListActive returns an account's live sessions, oldest first, for the "your sessions" view and for
// revoking on demand. Sessions past their deadline are not live.
func (s *Store) ListActive(ctx context.Context, t tenant.ID, account string) ([]Session, error) {
	if t.IsZero() || !validAccount(account) {
		return nil, ErrInvalid
	}
	var out []Session
	err := s.db.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		now, err := s.now(ctx, tx)
		if err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT `+columns+` FROM public.authn_sessions
WHERE tenant_id = $1 AND account_id = $2::uuid AND state = 'active' AND idle_expiry > $3 AND absolute_expiry > $3
ORDER BY created_at, id`, t.String(), account, now)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			sess, err := scanSession(t, rows)
			if err != nil {
				return err
			}
			out = append(out, sess)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("authn: list sessions: %w", err)
	}
	return out, nil
}

// ExpireDue marks every session of the tenant that is past its deadline as expired. A maintenance job
// calls it; Lookup and Create do not depend on it.
func (s *Store) ExpireDue(ctx context.Context, t tenant.ID) (int, error) {
	if t.IsZero() {
		return 0, ErrInvalid
	}
	var n int
	err := s.db.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		now, err := s.now(ctx, tx)
		if err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, expireDue, t.String(), nil, now)
		n = int(tag.RowsAffected())
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("authn: expire sessions: %w", err)
	}
	return n, nil
}
