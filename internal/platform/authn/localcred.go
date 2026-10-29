package authn

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/keys"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// AN-8, the break-glass password step (threat model §7.6 rules 2 and 3). It turns a right username and
// password of an active local account into a pending sign-in and nothing else; a session exists only after
// AN-10. Every other outcome is ErrSignInRefused, one answer for an unknown, wrong, non-local, disabled,
// throttled or empty-credential attempt.

var (
	// ErrSignInRefused is the one refusal of the password step.
	ErrSignInRefused = errors.New("authn: sign-in refused")
	// ErrWeakPassword: the password is shorter than MinPasswordLength runes.
	ErrWeakPassword = errors.New("authn: password is too short")
	// ErrUsernameTaken: another local account of the tenant holds this (normalised) username.
	ErrUsernameTaken = errors.New("authn: username is taken")
)

// Password and throttle settings.
const (
	MinPasswordLength = 12
	maxPasswordBytes  = 1024
	maxUsernameRunes  = 128

	// Argon2id parameters (RFC 9106 second recommendation: 64 MiB, t=3). Verification reads them from the
	// stored hash, so they can be raised later.
	argonMemoryKiB = 64 * 1024
	argonTime      = 3
	argonThreads   = 2
	argonSaltLen   = 16
	argonKeyLen    = 32

	// ThrottleBurst failures are free; the next ones are delayed 1 s, doubling, up to ThrottleCeiling.
	ThrottleBurst   = 5
	ThrottleWindow  = 15 * time.Minute
	ThrottleCeiling = 15 * time.Minute
	// DefaultThrottleKeys caps the key table; a new key past it falls into one shared overflow bucket.
	DefaultThrottleKeys = 100000
	// DefaultLatencyFloor is the least time every answer of the password step takes.
	DefaultLatencyFloor = 300 * time.Millisecond

	pepperTable  = "authn_signin_pepper"
	pepperColumn = "sealed_secret"
	pepperBytes  = 32
)

// Audit kinds of the password step. Failure events carry the throttle key hash, never the submitted name
// unless it matches an account (rule 2g); no event carries a password.
const (
	KindSignInPasswordFailed    audit.Kind = "authn.signin.password_failed"
	KindSignInPasswordSucceeded audit.Kind = "authn.signin.password_succeeded"
)

// NormaliseUsername is the one function the account lookup and the throttle key share: trim, Unicode NFC,
// case-fold. ok is false for an empty or over-long result.
func NormaliseUsername(s string) (string, bool) {
	n := cases.Fold().String(norm.NFC.String(strings.TrimSpace(s)))
	if n == "" || utf8.RuneCountInString(n) > maxUsernameRunes || !utf8.ValidString(n) {
		return "", false
	}
	return n, true
}

// hashPassword returns the argon2id hash of pw in PHC string form with a fresh salt.
func hashPassword(pw []byte) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("authn: password salt: %w", err)
	}
	return encodeHash(salt, argon2.IDKey(pw, salt, argonTime, argonMemoryKiB, argonThreads, argonKeyLen)), nil
}

func encodeHash(salt, sum []byte) string {
	b := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemoryKiB, argonTime, argonThreads, b.EncodeToString(salt), b.EncodeToString(sum))
}

// verifyHash reports whether pw matches the PHC hash. A malformed hash never matches.
func verifyHash(encoded string, pw []byte) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var v int
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[2], "v=%d", &v); err != nil || v != argon2.Version {
		return false
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil || m > 1<<20 || t == 0 || t > 16 || p == 0 {
		return false
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[4])
	want, err2 := base64.RawStdEncoding.DecodeString(parts[5])
	if err1 != nil || err2 != nil || len(want) == 0 {
		return false
	}
	got := argon2.IDKey(pw, salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

var (
	dummyOnce sync.Once
	dummyHash string
)

// dummy is the fixed hash an attempt without a checkable account is verified against, so every answer
// costs one verification (rule 2).
func dummy() string {
	dummyOnce.Do(func() { dummyHash, _ = hashPassword([]byte("activediq-an8-dummy")) })
	return dummyHash
}

// LocalCredentials stores local-account passwords and runs the AN-8 password step.
type LocalCredentials struct {
	DB       *store.DB
	Sessions *Store // the epoch, and the session end on a password change
	Pending  *PendingStore
	Keys     KeySource
	Audit    audit.Sink // bound to DB (audit.NewChainer)
	// Tenant is the install's tenant, or false while it is not ready. The sign-in request names none.
	Tenant func() (tenant.ID, bool)
	// MaxKeys caps the throttle key table (DefaultThrottleKeys when 0). LatencyFloor is the least time
	// of every answer (DefaultLatencyFloor when 0; a negative value turns it off, for tests).
	MaxKeys      int
	LatencyFloor time.Duration
	Clock        func() time.Time // nil: the real clock

	hashes int // verifications run (tests)
	mu     sync.Mutex
}

func (l *LocalCredentials) now() time.Time {
	if l.Clock != nil {
		return l.Clock().UTC()
	}
	return time.Now().UTC()
}

func (l *LocalCredentials) ready() error {
	if l.DB == nil || l.Sessions == nil || l.Pending == nil || l.Keys == nil || l.Audit == nil || l.Tenant == nil {
		return errors.New("authn: LocalCredentials is not fully configured")
	}
	return nil
}

// Verifications is the number of password-hash verifications run so far, dummy ones included.
func (l *LocalCredentials) Verifications() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.hashes
}

func (l *LocalCredentials) count() {
	l.mu.Lock()
	l.hashes++
	l.mu.Unlock()
}

// SetPassword gives the local account its username and password inside the caller's transaction. The
// account must be a local one. Replacing an existing password ends the account's sessions (reason
// password_reset) in the same transaction; by is who changed it.
func (l *LocalCredentials) SetPassword(ctx context.Context, tx store.Tx, t tenant.ID, account, username string, password secret.Secret, by authority.Chain) error {
	if err := l.ready(); err != nil {
		return err
	}
	name, ok := NormaliseUsername(username)
	if t.IsZero() || !validAccount(account) || !ok || by.Validate() != nil {
		return ErrInvalid
	}
	var hash string
	var short bool
	password.Expose(func(b []byte) {
		if utf8.RuneCount(b) < MinPasswordLength || len(b) > maxPasswordBytes || !utf8.Valid(b) {
			short = true
			return
		}
		hash, _ = hashPassword(b)
	})
	if short {
		return ErrWeakPassword
	}
	var kind string
	if err := tx.QueryRow(ctx, `SELECT kind FROM public.authn_accounts WHERE tenant_id = $1::uuid AND id = $2::uuid`, t.String(), account).Scan(&kind); err != nil {
		if store.IsNoRows(err) {
			return ErrAccountNotFound
		}
		return err
	}
	if kind != string(KindLocal) {
		return ErrInvalid
	}
	var other int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM public.authn_local_credentials WHERE tenant_id = $1::uuid AND username_norm = $2 AND account_id <> $3::uuid`,
		t.String(), name, account).Scan(&other); err != nil {
		return err
	}
	if other > 0 {
		return ErrUsernameTaken
	}
	tag, err := tx.Exec(ctx, `UPDATE public.authn_local_credentials SET username_norm = $3, password_hash = $4, updated_at = now() WHERE tenant_id = $1::uuid AND account_id = $2::uuid`,
		t.String(), account, name, hash)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 1 {
		_, err = l.Sessions.OnPasswordReset(ctx, tx, t, account, by)
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO public.authn_local_credentials (tenant_id, account_id, username_norm, password_hash) VALUES ($1::uuid, $2::uuid, $3, $4)`,
		t.String(), account, name, hash)
	return err
}

// BeginPassword is AN-8. It returns the handle for the pending cookie when username and password are those
// of an active local account that is not in its throttle delay; every other outcome is ErrSignInRefused
// after the same work and the same minimum time. An infrastructure fault is any other error.
func (l *LocalCredentials) BeginPassword(ctx context.Context, username string, password secret.Secret, from netip.Addr) (PendingHandle, error) {
	if err := l.ready(); err != nil {
		return PendingHandle{}, err
	}
	start := time.Now()
	h, err := l.begin(ctx, username, password, from)
	floor := l.LatencyFloor
	if floor == 0 {
		floor = DefaultLatencyFloor
	}
	if rest := floor - time.Since(start); floor > 0 && rest > 0 {
		select {
		case <-time.After(rest):
		case <-ctx.Done():
		}
	}
	return h, err
}

func (l *LocalCredentials) begin(ctx context.Context, username string, password secret.Secret, from netip.Addr) (PendingHandle, error) {
	t, ok := l.Tenant()
	if !ok {
		return PendingHandle{}, errors.New("authn: the install's tenant is not ready")
	}
	name, nameOK := NormaliseUsername(username)
	if !nameOK { // still one key and one verification: an unusable name is just a name that never matches
		name = strings.TrimSpace(username)
		if len(name) > 4*maxUsernameRunes {
			name = name[:4*maxUsernameRunes]
		}
	}
	var (
		granted bool
		account string
		epoch   Epoch
	)
	err := l.DB.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		now := l.now()
		pepper, err := l.pepper(ctx, tx, t)
		if err != nil {
			return err
		}
		defer clear(pepper)
		key := throttleKey(pepper, t, name)
		key, err = l.cappedKey(ctx, tx, t, key, now)
		if err != nil {
			return err
		}
		failures, notBefore, err := l.lockThrottle(ctx, tx, t, key, now)
		if err != nil {
			return err
		}
		throttled := now.Before(notBefore)
		var hash string
		var acct string
		var active bool
		if !throttled && nameOK {
			err := tx.QueryRow(ctx, `SELECT c.account_id::text, c.password_hash, a.state = 'active' AND a.kind = 'local'
FROM public.authn_local_credentials c JOIN public.authn_accounts a ON a.tenant_id = c.tenant_id AND a.id = c.account_id
WHERE c.tenant_id = $1::uuid AND c.username_norm = $2`, t.String(), name).Scan(&acct, &hash, &active)
			if err != nil && !store.IsNoRows(err) {
				return err
			}
			if !active {
				hash = ""
			}
		}
		if hash != "" { // the epoch is read BEFORE the credential is verified (T-0429)
			epoch, err = l.Sessions.EpochTx(ctx, tx, t, acct)
			switch {
			case errors.Is(err, ErrAccountInactive):
				hash = ""
			case err != nil:
				return err
			}
		}
		verified := false
		check := dummy()
		if hash != "" {
			check = hash
		}
		pw := secretBytes(password)
		l.count()
		match := verifyHash(check, pw)
		clear(pw)
		verified = match && hash != "" && !password.IsEmpty()
		if verified {
			granted, account = true, acct
			if err := l.resetThrottle(ctx, tx, t, key); err != nil {
				return err
			}
			return l.record(ctx, tx, t, KindSignInPasswordSucceeded, key, acct, from, now)
		}
		matched := ""
		if hash != "" {
			matched = acct // the name matched an account: only then may the log name it (rule 2g)
		}
		if err := l.recordFailure(ctx, tx, t, key, failures, now); err != nil {
			return err
		}
		return l.record(ctx, tx, t, KindSignInPasswordFailed, key, matched, from, now)
	})
	if err != nil {
		return PendingHandle{}, err
	}
	if !granted {
		return PendingHandle{}, ErrSignInRefused
	}
	return l.Pending.Begin(ctx, BeginInput{Tenant: t, Account: account, FirstFactor: FirstPassword, ClientIP: from, Epoch: epoch})
}

func secretBytes(s secret.Secret) []byte {
	var out []byte
	s.Expose(func(b []byte) { out = append([]byte(nil), b...) })
	return out
}

func throttleKey(pepper []byte, t tenant.ID, name string) []byte {
	m := hmac.New(sha256.New, pepper)
	m.Write([]byte(t.String()))
	m.Write([]byte{0})
	m.Write([]byte(name))
	return m.Sum(nil)
}

// overflowKey is the one shared bucket for every new key once the table is full (rule 2e).
var overflowKey = sha256.Sum256([]byte("activediq/an8/overflow"))

// cappedKey returns key, or the shared overflow key when key is new and the table of live keys is full.
func (l *LocalCredentials) cappedKey(ctx context.Context, tx store.Tx, t tenant.ID, key []byte, now time.Time) ([]byte, error) {
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM public.authn_signin_throttle WHERE tenant_id = $1::uuid AND key_hash = $2 AND window_start > $3)`,
		t.String(), key, now.Add(-ThrottleWindow)).Scan(&exists); err != nil {
		return nil, err
	}
	if exists {
		return key, nil
	}
	limit := l.MaxKeys
	if limit <= 0 {
		limit = DefaultThrottleKeys
	}
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM public.authn_signin_throttle WHERE tenant_id = $1::uuid AND window_start > $2`, t.String(), now.Add(-ThrottleWindow)).Scan(&n); err != nil {
		return nil, err
	}
	if n >= limit {
		return overflowKey[:], nil
	}
	return key, nil
}

// lockThrottle creates the key's row if it is absent or dead, locks it and returns its live counters.
func (l *LocalCredentials) lockThrottle(ctx context.Context, tx store.Tx, t tenant.ID, key []byte, now time.Time) (int, time.Time, error) {
	if _, err := tx.Exec(ctx, `INSERT INTO public.authn_signin_throttle (tenant_id, key_hash, failures, window_start, not_before)
VALUES ($1::uuid, $2, 0, $3, $3)
ON CONFLICT (tenant_id, key_hash) DO UPDATE SET failures = 0, window_start = EXCLUDED.window_start, not_before = EXCLUDED.not_before
  WHERE public.authn_signin_throttle.window_start <= $4`, t.String(), key, now, now.Add(-ThrottleWindow)); err != nil {
		return 0, time.Time{}, err
	}
	var failures int
	var nb time.Time
	if err := tx.QueryRow(ctx, `SELECT failures, not_before FROM public.authn_signin_throttle WHERE tenant_id = $1::uuid AND key_hash = $2 FOR UPDATE`, t.String(), key).Scan(&failures, &nb); err != nil {
		return 0, time.Time{}, err
	}
	return failures, nb, nil
}

func (l *LocalCredentials) resetThrottle(ctx context.Context, tx store.Tx, t tenant.ID, key []byte) error {
	_, err := tx.Exec(ctx, `UPDATE public.authn_signin_throttle SET failures = 0, not_before = window_start WHERE tenant_id = $1::uuid AND key_hash = $2`, t.String(), key)
	return err
}

// recordFailure counts one failure (a non-evaluated attempt too, rule 2f) and sets the not-before time:
// none for the first ThrottleBurst, then 1 s doubling to the ceiling.
func (l *LocalCredentials) recordFailure(ctx context.Context, tx store.Tx, t tenant.ID, key []byte, failures int, now time.Time) error {
	failures++
	nb := now
	if failures >= ThrottleBurst {
		shift := failures - ThrottleBurst
		d := ThrottleCeiling
		if shift < 20 {
			d = min(time.Second<<shift, ThrottleCeiling)
		}
		nb = now.Add(d)
	}
	_, err := tx.Exec(ctx, `UPDATE public.authn_signin_throttle SET failures = $3, not_before = GREATEST(not_before, $4) WHERE tenant_id = $1::uuid AND key_hash = $2`, t.String(), key, failures, nb)
	return err
}

func (l *LocalCredentials) record(ctx context.Context, tx store.Tx, t tenant.ID, kind audit.Kind, key []byte, account string, from netip.Addr, now time.Time) error {
	var id string
	if err := tx.QueryRow(ctx, `SELECT gen_random_uuid()::text`).Scan(&id); err != nil {
		return err
	}
	details := []audit.Detail{}
	if account != "" {
		details = append(details, audit.Detail{Key: "account", Value: account})
	}
	if from.IsValid() {
		details = append(details, audit.Detail{Key: "client_ip", Value: from.Unmap().String()})
	}
	details = append(details, audit.Detail{Key: "key", Value: fmt.Sprintf("%x", key)})
	outcome := audit.Failure
	reason := "refused"
	actor := authority.Principal{ID: "authn-password", Kind: authority.System}
	if kind == KindSignInPasswordSucceeded {
		outcome, reason = audit.Success, "break-glass"
		actor = authority.Principal{ID: authority.PrincipalID(account), Kind: authority.Human}
	}
	ev := audit.Event{
		ID: "authn.signin." + id, Kind: kind, At: now, Actor: authority.Chain{Requester: actor},
		Target:    authority.TargetRef{GUID: t.String(), Class: "signin"},
		Component: "authn", Outcome: outcome, Reason: reason, Details: details,
	}
	if err := l.Audit.Append(ctx, tx, ev); err != nil {
		return fmt.Errorf("authn: audit password step: %w", err)
	}
	return nil
}

// pepper returns the tenant's throttle HMAC key, creating it on first use (sealed under the tenant data key).
func (l *LocalCredentials) pepper(ctx context.Context, tx store.Tx, t tenant.ID) ([]byte, error) {
	for range 2 {
		var blob []byte
		var ver int32
		err := tx.QueryRow(ctx, `SELECT sealed_secret, key_version FROM public.authn_signin_pepper WHERE tenant_id = $1::uuid`, t.String()).Scan(&blob, &ver)
		switch {
		case err == nil:
			dek, err := l.Keys.DEK(ctx, tx, t, uint32(ver))
			if err != nil {
				return nil, fmt.Errorf("authn: tenant key: %w", err)
			}
			defer dek.Destroy()
			p, err := keys.Open(dek, pepperContext(t, uint32(ver)), blob)
			if err != nil {
				return nil, fmt.Errorf("authn: open throttle key: %w", err)
			}
			return p, nil
		case !store.IsNoRows(err):
			return nil, err
		}
		raw := make([]byte, pepperBytes)
		if _, err := rand.Read(raw); err != nil {
			return nil, fmt.Errorf("authn: throttle key: %w", err)
		}
		dek, err := l.Keys.DEK(ctx, tx, t, 0)
		if err != nil {
			clear(raw)
			return nil, fmt.Errorf("authn: tenant key: %w", err)
		}
		sealed, err := keys.Seal(dek, pepperContext(t, dek.Version), raw)
		ver2 := dek.Version
		dek.Destroy()
		clear(raw)
		if err != nil {
			return nil, fmt.Errorf("authn: seal throttle key: %w", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO public.authn_signin_pepper (tenant_id, sealed_secret, key_version) VALUES ($1::uuid, $2, $3) ON CONFLICT DO NOTHING`, t.String(), sealed, int32(ver2)); err != nil {
			return nil, err
		}
	}
	return nil, errors.New("authn: throttle key unavailable")
}

func pepperContext(t tenant.ID, version uint32) keys.Context {
	return keys.Context{Tenant: t, Table: pepperTable, Row: t.String(), Column: pepperColumn, Version: version}
}
