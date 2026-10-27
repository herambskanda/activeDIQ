package authn

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
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
	// ErrTenantMismatch is returned when a transaction passed to RevokeAccountTx (or an On* method) belongs
	// to a different tenant than the one named; nothing is revoked and the caller's change must roll back.
	ErrTenantMismatch = errors.New("authn: transaction is not of the named tenant")

	// ErrAccountInactive is returned when a session is requested for an account that is not active:
	// invited, disabled, deleted or unknown. It is deliberately one error for all four, so a caller
	// cannot probe which accounts exist. No session row is written.
	ErrAccountInactive = errors.New("authn: account is not active")

	// ErrCredentialsChanged is returned when the account's password, MFA or roles changed after the
	// sign-in captured its Epoch: whatever the sign-in verified no longer exists. No session row is
	// written. Callers answer it as any failed sign-in (the same 401) and may start the sign-in again.
	ErrCredentialsChanged = errors.New("authn: credentials changed during sign-in")

	// ErrPolicyRead means the tenant's session policy could not be read, which is what a token naming
	// an unknown tenant produces. HTTP callers answer it as they answer an unknown session.
	ErrPolicyRead = errors.New("authn: read session policy")
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

// bumpsEpoch: the reasons that change what a sign-in verifies. Account disable is covered by the state
// check; logout and on-demand revocation change nothing a sign-in depends on.
func (r Reason) bumpsEpoch() bool {
	return r == ReasonPasswordReset || r == ReasonMFAReset || r == ReasonRoleChanged
}

const sqlBumpEpoch = `UPDATE public.authn_accounts SET session_epoch = session_epoch + 1
WHERE tenant_id = $1 AND id = $2::uuid AND state <> 'deleted'`

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
	DB *store.DB
	// Audit receives every session lifecycle event inside the transaction that causes it (create, evict,
	// expire, revoke). Required: a session store that cannot record who ended whose session is refused.
	Audit    audit.Sink
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
	audit    audit.Sink
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
	if cfg.Audit == nil {
		return nil, errors.New("authn: Store needs an audit sink")
	}
	s := &Store{db: cfg.DB, audit: cfg.Audit, policies: cfg.Policies, bounds: cfg.Bounds, touch: cfg.TouchEvery, clock: cfg.Clock}
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

// Epoch is the account's session epoch as read BEFORE a sign-in verified anything (password, MFA secret,
// roles). It is bumped by every password reset, MFA reset and role change, and createTx refuses a session
// minted from an older one (ErrCredentialsChanged). It is obtained only from Store.Epoch / EpochTx; the
// zero value is invalid, so a caller that forgot to capture one fails closed.
type Epoch struct {
	n  int64
	ok bool
}

const sqlEpoch = `SELECT session_epoch FROM public.authn_accounts WHERE tenant_id = $1 AND id = $2::uuid`

// Epoch reads the account's current session epoch. Read it before verifying a credential, then pass it
// in CreateInput (or BeginInput). An unknown account is ErrAccountInactive.
func (s *Store) Epoch(ctx context.Context, t tenant.ID, account string) (Epoch, error) {
	if t.IsZero() || !validAccount(account) {
		return Epoch{}, ErrInvalid
	}
	var e Epoch
	err := s.db.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) (err error) {
		e, err = s.EpochTx(ctx, tx, t, account)
		return err
	})
	return e, err
}

// EpochTx is Epoch inside the caller's tenant transaction, for a sign-in step that reads the epoch and
// verifies in one transaction. It takes no lock: the check that matters is createTx's.
func (s *Store) EpochTx(ctx context.Context, tx store.Tx, t tenant.ID, account string) (Epoch, error) {
	if tx == nil || t.IsZero() || !validAccount(account) {
		return Epoch{}, ErrInvalid
	}
	var n int64
	if err := tx.QueryRow(ctx, sqlEpoch, t.String(), account).Scan(&n); err != nil {
		if store.IsNoRows(err) {
			return Epoch{}, ErrAccountInactive
		}
		return Epoch{}, err
	}
	return Epoch{n: n, ok: true}, nil
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
	// Epoch is the account's epoch captured before the credential/MFA/roles were verified. Required.
	Epoch Epoch

	// inherit is set only by Rotate: the new session continues the old one's absolute window.
	inherit *Session
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
	sqlClock = `SELECT clock_timestamp()`
	// sqlTxTenant is the tenant the transaction is scoped to ('' when none).
	sqlTxTenant = `SELECT coalesce(current_setting('app.tenant_id', true), '')`
	sqlAcctLk   = `SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))`

	// expireDue ends an account's sessions whose deadline has passed. $2 is NULL for every account.
	expireDue = `UPDATE public.authn_sessions
SET state = 'expired', ended_at = $3,
    end_reason = CASE WHEN absolute_expiry <= $3 THEN 'absolute_timeout' ELSE 'idle_timeout' END
WHERE tenant_id = $1 AND ($2::uuid IS NULL OR account_id = $2::uuid) AND state = 'active'
  AND (idle_expiry <= $3 OR absolute_expiry <= $3)
RETURNING id, account_id::text, end_reason`

	// evict revokes the $4 sessions of one account that the policy ($3) ranks first.
	evict = `UPDATE public.authn_sessions
SET state = 'revoked', ended_at = $5, end_reason = 'concurrent_limit'
WHERE tenant_id = $1 AND id IN (
  SELECT id FROM public.authn_sessions
  WHERE tenant_id = $1 AND account_id = $2::uuid AND state = 'active'
  ORDER BY CASE WHEN $3::text = 'least_recently_used' THEN last_seen_at ELSE created_at END, created_at, id
  LIMIT $4)
RETURNING id, account_id::text, end_reason`

	countActive = `SELECT count(*) FROM public.authn_sessions WHERE tenant_id = $1 AND account_id = $2::uuid AND state = 'active'`

	insert = `INSERT INTO public.authn_sessions
  (tenant_id, id_hash, account_id, methods, mfa_at, authority_factor_at, client_ip, created_at, last_seen_at, idle_expiry, absolute_expiry)
VALUES ($1, $2, $3::uuid, $4, $5, $6, $7, $11, $8, $9, $10)
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
		return Policy{}, fmt.Errorf("%w: %w", ErrPolicyRead, err)
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

func validateCreate(in CreateInput) error {
	if in.Tenant.IsZero() || !validAccount(in.Account) || len(in.Methods) == 0 || len(in.Methods) > 8 {
		return ErrInvalid
	}
	if in.inherit == nil && !in.Epoch.ok {
		return ErrInvalid // a sign-in that did not capture the epoch cannot be checked: fail closed
	}
	for _, m := range in.Methods {
		if m == "" || len(m) > 32 {
			return ErrInvalid
		}
	}
	return nil
}

// Create opens a session for an authenticated account. In one transaction, serialised per account, it
// ends the account's sessions that are past their deadline, revokes as many of the rest as the policy's
// eviction ranks first so that the new session is within the concurrent limit, and stores the new one
// with only the hash of its token.
func (s *Store) Create(ctx context.Context, in CreateInput) (CreateResult, error) {
	if err := validateCreate(in); err != nil {
		return CreateResult{}, err
	}
	pol, err := s.policy(ctx, in.Tenant)
	if err != nil {
		return CreateResult{}, err
	}
	var res CreateResult
	err = s.db.WithTenant(ctx, in.Tenant, func(ctx context.Context, tx store.Tx) error {
		var err error
		res, err = s.createTx(ctx, tx, in, pol)
		return err
	})
	if err != nil {
		return CreateResult{}, fmt.Errorf("authn: create session: %w", err)
	}
	return res, nil
}

// CreateTx is Create inside the caller's tenant transaction, so a sign-in step that must commit with
// the session (consuming a pending sign-in, AN-10) does so atomically: a rollback leaves no session.
// tx must belong to in.Tenant.
func (s *Store) CreateTx(ctx context.Context, tx store.Tx, in CreateInput) (CreateResult, error) {
	if err := validateCreate(in); err != nil {
		return CreateResult{}, err
	}
	pol, err := s.policy(ctx, in.Tenant)
	if err != nil {
		return CreateResult{}, err
	}
	res, err := s.createTx(ctx, tx, in, pol)
	if err != nil {
		return CreateResult{}, fmt.Errorf("authn: create session: %w", err)
	}
	return res, nil
}

func (s *Store) createTx(ctx context.Context, tx store.Tx, in CreateInput, pol Policy) (CreateResult, error) {
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
	now, err := s.now(ctx, tx)
	if err != nil {
		return CreateResult{}, err
	}
	// DM-31.I2 and T-0429: the account row is read FOR SHARE in this transaction, so it cannot move to
	// disabled or deleted (SetState takes FOR UPDATE) and its session_epoch cannot be bumped (a password
	// reset, MFA reset or role change updates the row, in RevokeAccountTx) between this check and the
	// INSERT. A change that committed first is seen here: the state or the epoch no longer matches what
	// the sign-in verified and no session is minted. One that arrives later waits for this commit and
	// then revokes the new session in its own transaction.
	// Lock order is account row, then the per-account advisory lock below. RevokeAccountTx never takes the
	// advisory lock (it holds the row, then updates session rows), so the two paths cannot deadlock; the
	// row lock comes first here so the advisory lock is never held while waiting on a row.
	var (
		state string
		epoch int64
	)
	if err := tx.QueryRow(ctx, `SELECT state, session_epoch FROM public.authn_accounts WHERE tenant_id = $1 AND id = $2::uuid FOR SHARE`, in.Tenant.String(), in.Account).Scan(&state, &epoch); err != nil {
		if store.IsNoRows(err) {
			return CreateResult{}, ErrAccountInactive
		}
		return CreateResult{}, err
	}
	if AccountState(state) != AccountActive {
		return CreateResult{}, ErrAccountInactive
	}
	// A rotated session carries no epoch: Rotate revokes the old session and mints the new one in this
	// same transaction under this lock, so a reset either revoked the old session first (Rotate fails) or
	// revokes the new one afterwards.
	if in.inherit == nil && epoch != in.Epoch.n {
		return CreateResult{}, ErrCredentialsChanged
	}
	if _, err := tx.Exec(ctx, sqlAcctLk, in.Tenant.String()+"/"+in.Account); err != nil {
		return CreateResult{}, err
	}
	if _, err := s.endRows(ctx, tx, now, expireDue, []any{in.Tenant.String(), in.Account, now}, KindSessionExpired, nil); err != nil {
		return CreateResult{}, err
	}
	var active int
	if err := tx.QueryRow(ctx, countActive, in.Tenant.String(), in.Account).Scan(&active); err != nil {
		return CreateResult{}, err
	}
	if over := active - (pol.MaxConcurrent - 1); over > 0 {
		n, err := s.endRows(ctx, tx, now, evict, []any{in.Tenant.String(), in.Account, string(pol.Eviction), over, now}, KindSessionEvicted, nil)
		if err != nil {
			return CreateResult{}, err
		}
		res.Evicted = n
	}
	idle := now.Add(pol.Idle)
	abs := now.Add(pol.Absolute)
	created := now
	if in.inherit != nil {
		// A rotated session keeps the original sign-in's window; only a full sign-in starts a new one.
		created = in.inherit.CreatedAt
		if a := created.Add(pol.Absolute); a.Before(abs) {
			abs = a
		}
		if in.inherit.AbsoluteExpiry.Before(abs) {
			abs = in.inherit.AbsoluteExpiry
		}
		if !abs.After(now) {
			return CreateResult{}, ErrExpired
		}
	}
	if idle.After(abs) {
		idle = abs
	}
	var id string
	if err := tx.QueryRow(ctx, insert, in.Tenant.String(), tok.hash(), in.Account, in.Methods, in.MFAAt, in.AuthorityFactorAt, ip, now, idle, abs, created).Scan(&id); err != nil {
		return CreateResult{}, err
	}
	res.Session = Session{ID: id, Tenant: in.Tenant, Account: in.Account, Methods: append([]string(nil), in.Methods...),
		MFAAt: in.MFAAt, AuthorityFactorAt: in.AuthorityFactorAt, ClientIP: in.ClientIP.Unmap(),
		CreatedAt: created, LastSeenAt: now, IdleExpiry: idle, AbsoluteExpiry: abs, State: SessionActive}
	if err := s.emit(ctx, tx, now, KindSessionCreated, id, in.Account, accountChain(in.Account), "", in.Methods); err != nil {
		return CreateResult{}, err
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
			if err := s.emit(ctx, tx, now, KindSessionExpired, sess.ID, sess.Account, systemChain, reason, nil); err != nil {
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

// Revoke ends one session by its handle, on demand or for a stated reason; by is who asked (the real
// human, or the system principal). It reports whether it ended one: revoking an already-ended or unknown
// session is not an error and returns false.
func (s *Store) Revoke(ctx context.Context, t tenant.ID, sessionID string, why Reason, by authority.Chain) (bool, error) {
	if t.IsZero() || !validAccount(sessionID) || !why.valid() || by.Validate() != nil {
		return false, ErrInvalid
	}
	n, err := s.revokeN(ctx, t, sqlRevokeSession, sessionID, why, func(string) authority.Chain { return by })
	return n > 0, err
}

// RevokeAccount ends every active session of an account: on account disable (DM-31.I2), role change,
// password or MFA reset, and on demand. It returns how many it ended. Because the store is shared, the
// next Lookup on any node refuses them. It commits on its own; a caller changing the account in a
// transaction of its own uses RevokeAccountTx (or an On* method) so both commit or neither does.
func (s *Store) RevokeAccount(ctx context.Context, t tenant.ID, account string, why Reason, by authority.Chain) (int, error) {
	if t.IsZero() || !validAccount(account) || !why.valid() || by.Validate() != nil {
		return 0, ErrInvalid
	}
	if why.bumpsEpoch() {
		var n int
		err := s.db.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) (err error) {
			n, err = s.RevokeAccountTx(ctx, tx, t, account, why, by)
			return err
		})
		return n, err
	}
	return s.revokeN(ctx, t, sqlRevokeAccount, account, why, func(string) authority.Chain { return by })
}

// RevokeAccountTx is RevokeAccount inside the caller's tenant transaction, the one that disables the
// account, changes its roles or resets its password or MFA: the revocation and its audit records commit
// with the change, or not at all. tx must be a transaction of tenant t: if it is not (row-level security
// would hide t's rows and the update would silently match nothing) the call fails with ErrTenantMismatch so
// the caller's change rolls back instead of committing with every session still live.
func (s *Store) RevokeAccountTx(ctx context.Context, tx store.Tx, t tenant.ID, account string, why Reason, by authority.Chain) (int, error) {
	if tx == nil || t.IsZero() || !validAccount(account) || !why.valid() || by.Validate() != nil {
		return 0, ErrInvalid
	}
	var cur string
	if err := tx.QueryRow(ctx, sqlTxTenant).Scan(&cur); err != nil {
		return 0, fmt.Errorf("authn: revoke: read transaction tenant: %w", err)
	}
	if cur != t.String() {
		return 0, ErrTenantMismatch
	}
	now, err := s.now(ctx, tx)
	if err != nil {
		return 0, err
	}
	if why.bumpsEpoch() {
		// T-0429: take the account row exclusively and invalidate every sign-in that captured the old
		// epoch. It waits for in-flight createTx (FOR SHARE) to commit, whose new session the revoke
		// below then ends. A deleted account is final and its row cannot be updated; it mints nothing.
		if _, err := tx.Exec(ctx, sqlBumpEpoch, t.String(), account); err != nil {
			return 0, fmt.Errorf("authn: revoke: bump session epoch: %w", err)
		}
	}
	n, err := s.endRows(ctx, tx, now, sqlRevokeAccount, []any{t.String(), account, string(why), now}, KindSessionRevoked, func(string) authority.Chain { return by })
	if err != nil {
		return 0, fmt.Errorf("authn: revoke: %w", err)
	}
	return n, nil
}

// Rotate replaces the session a token names with a new one for the same account, methods and factor
// times, and revokes the old one for why. It is the revocation mechanism for the presenting browser when
// privilege changes (step-up, role change of the signed-in account; RevokeAccount ends the account's
// other sessions), so a value captured before the change is dead and the CSRF value, which is derived
// from the token, changes with it. The new session keeps the old one's CreatedAt and absolute deadline
// (capped by the current policy): rotation never extends a session's lifetime, only a full sign-in does. The old session is revoked and the new one stored in one
// transaction under the account row's lock (T-0429); if that fails the old one is revoked on its own, so
// the caller is signed out, never left on a stale token. A concurrent Rotate of the same token finds it
// already ended and gets ErrRevoked.
func (s *Store) Rotate(ctx context.Context, old Token, why Reason) (CreateResult, error) {
	sess, err := s.Lookup(ctx, old)
	if err != nil {
		return CreateResult{}, err
	}
	pol, err := s.policy(ctx, sess.Tenant)
	if err != nil {
		return CreateResult{}, err
	}
	var res CreateResult
	err = s.db.WithTenant(ctx, sess.Tenant, func(ctx context.Context, tx store.Tx) error {
		// T-0429: the account row is locked FOR SHARE before the old session is revoked, and createTx
		// (same transaction) mints the new one under that lock. A reset that committed earlier already
		// revoked the old session, so this revoke finds nothing and Rotate fails; one that arrives later
		// revokes the new session.
		var one int
		if err := tx.QueryRow(ctx, `SELECT 1 FROM public.authn_accounts WHERE tenant_id = $1 AND id = $2::uuid FOR SHARE`, sess.Tenant.String(), sess.Account).Scan(&one); err != nil {
			if store.IsNoRows(err) {
				return ErrAccountInactive
			}
			return err
		}
		now, err := s.now(ctx, tx)
		if err != nil {
			return err
		}
		n, err := s.endRows(ctx, tx, now, sqlRevokeSession, []any{sess.Tenant.String(), sess.ID, string(why), now}, KindSessionRevoked, func(string) authority.Chain { return accountChain(sess.Account) })
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrRevoked
		}
		res, err = s.createTx(ctx, tx, CreateInput{Tenant: sess.Tenant, Account: sess.Account, Methods: sess.Methods,
			MFAAt: sess.MFAAt, AuthorityFactorAt: sess.AuthorityFactorAt, ClientIP: sess.ClientIP, inherit: &sess}, pol)
		return err
	})
	if err != nil {
		if !errors.Is(err, ErrRevoked) {
			// The rotation rolled back, so the old token is still live. Rotation exists to kill a captured
			// value: if it fails for any other reason the caller is signed out, never left on a stale token.
			if _, rerr := s.Revoke(ctx, sess.Tenant, sess.ID, why, accountChain(sess.Account)); rerr != nil {
				return CreateResult{}, errors.Join(err, rerr)
			}
		}
		return CreateResult{}, fmt.Errorf("authn: rotate session: %w", err)
	}
	return res, nil
}

// Logout ends the session a token names.
func (s *Store) Logout(ctx context.Context, tok Token) error {
	t, err := tok.Tenant()
	if err != nil {
		return ErrSessionNotFound
	}
	n, err := s.revokeN(ctx, t, sqlRevokeToken, tok.hash(), ReasonLogout, accountChain)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrSessionNotFound
	}
	return nil
}

const (
	sqlRevokeSession = `UPDATE public.authn_sessions SET state = 'revoked', ended_at = $4, end_reason = $3
WHERE tenant_id = $1 AND id = $2::uuid AND state = 'active' RETURNING id, account_id::text, end_reason`
	sqlRevokeAccount = `UPDATE public.authn_sessions SET state = 'revoked', ended_at = $4, end_reason = $3
WHERE tenant_id = $1 AND account_id = $2::uuid AND state = 'active' RETURNING id, account_id::text, end_reason`
	sqlRevokeToken = `UPDATE public.authn_sessions SET state = 'revoked', ended_at = $4, end_reason = $3
WHERE tenant_id = $1 AND id_hash = $2 AND state = 'active' RETURNING id, account_id::text, end_reason`
)

func (s *Store) revokeN(ctx context.Context, t tenant.ID, sql string, key any, why Reason, by func(account string) authority.Chain) (int, error) {
	var n int
	err := s.db.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		now, err := s.now(ctx, tx)
		if err != nil {
			return err
		}
		n, err = s.endRows(ctx, tx, now, sql, []any{t.String(), key, string(why), now}, KindSessionRevoked, by)
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
		n, err = s.endRows(ctx, tx, now, expireDue, []any{t.String(), nil, now}, KindSessionExpired, nil)
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("authn: expire sessions: %w", err)
	}
	return n, nil
}
