// cursor.go is DM-19 SyncCursor: the change-feed position of one partition, and the lease-fenced store that
// is the only writer of public.sync_cursors (migration 0070). The package comment is in doc.go (T-1189).

package sync

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tablekind"
)

var _ = tablekind.Declare(tablekind.Table{Name: "public.sync_cursors", Entity: "DM-19", Kind: tablekind.Tenant})

// State is the lifecycle state of a cursor (DM-19): initial_sync → incremental ⇄ resync_required, and
// paused while the connection is suspended.
type State string

// The cursor states.
const (
	StateInitialSync    State = "initial_sync"
	StateIncremental    State = "incremental"
	StateResyncRequired State = "resync_required"
	StatePaused         State = "paused"
)

const (
	maxCookieBytes          = 64 * 1024
	clockSkewAllowance      = 5 * time.Minute
	leaseNamePrefix         = "sync.cursor."
	redacted                = "[redacted cookie]"
	maxGraphPartitionLength = 40
)

// transitions is the DM-19 lifecycle: the moves from one state to another. A state staying as it is is not
// a move. Migration 0070's trigger enforces the same matrix; the tests compare the two over every pair.
var transitions = map[State][]State{
	StateInitialSync:    {StateIncremental, StatePaused},
	StateIncremental:    {StateResyncRequired, StatePaused},
	StateResyncRequired: {StateIncremental, StatePaused},
	StatePaused:         {StateResyncRequired}, // resumption always resyncs: the cookie is not trusted across a pause
}

// Valid reports whether s is one of the four lifecycle states.
func (s State) Valid() bool { _, ok := transitions[s]; return ok }

// CanTransition reports whether the lifecycle allows a move from one state to another.
func CanTransition(from, to State) bool {
	for _, t := range transitions[from] {
		if t == to {
			return true
		}
	}
	return false
}

// movesTo returns the states from which to is reachable by one move.
func movesTo(to State) []string {
	var out []string
	for from := range transitions {
		if CanTransition(from, to) {
			out = append(out, string(from))
		}
	}
	sort.Strings(out)
	return out
}

// Typed errors. None carries a cookie, a directory value or a database message.
var (
	// ErrInvalid is a malformed key, lease, cookie or time.
	ErrInvalid = errors.New("sync: invalid cursor argument")
	// ErrNoTenant: the transaction carries no tenant.
	ErrNoTenant = errors.New("sync: no tenant")
	// ErrNotFound: the tenant has no cursor for the key (RLS hides another tenant's rows the same way).
	ErrNotFound = errors.New("sync: no such cursor")
	// ErrUnknownConnection: the tenant has no such connection.
	ErrUnknownConnection = errors.New("sync: unknown connection")
	// ErrFenced: a newer lease holder has written the cursor, so the caller's lease is stale (DM-19.I2,
	// DM-06.I2). The caller must stop and write nothing more. Test with errors.Is; the detail is *FencedError.
	ErrFenced = errors.New("sync: the lease was taken over (fenced)")
	// ErrIllegalTransition: the move is not in the DM-19 lifecycle, or the operation does not apply in the
	// cursor's state. The row is unchanged. The detail is *TransitionError.
	ErrIllegalTransition = errors.New("sync: illegal cursor transition")
	// ErrWrongLease: the lease does not guard this cursor (LeaseName).
	ErrWrongLease = errors.New("sync: the lease does not guard this cursor")
)

// FencedError says which tokens collided. Tokens are counters, not secrets.
type FencedError struct{ Held, Stored int64 }

func (e *FencedError) Error() string {
	return fmt.Sprintf("%s: token %d is below the stored token %d", ErrFenced, e.Held, e.Stored)
}

// Is makes errors.Is(err, ErrFenced) true.
func (e *FencedError) Is(target error) bool { return target == ErrFenced }

// TransitionError names the refused move.
type TransitionError struct{ From, To State }

func (e *TransitionError) Error() string {
	return fmt.Sprintf("%s: %s to %s", ErrIllegalTransition, e.From, e.To)
}

// Is makes errors.Is(err, ErrIllegalTransition) true.
func (e *TransitionError) Is(target error) bool { return target == ErrIllegalTransition }

var (
	guidTextRE   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	graphPartRe  = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	nilGUID      = "00000000-0000-0000-0000-000000000000"
	errBadCookie = fmt.Errorf("%w: cookie must be 1..%d bytes", ErrInvalid, maxCookieBytes)
)

// Partition names the feed of one cursor: an AD naming context by its lower-case objectGUID, or one Graph
// resource of an Entra tenant by a lower-case token such as "users".
type Partition string

// NCPartition is the partition of an AD naming context. The GUID is the canonical lower-case text form.
func NCPartition(guid string) (Partition, error) {
	g := strings.ToLower(guid)
	if !guidTextRE.MatchString(g) || g == nilGUID {
		return "", fmt.Errorf("%w: a naming context partition is its objectGUID", ErrInvalid)
	}
	return Partition(g), nil
}

// GraphPartition is the partition of one Graph resource ("users", "groups").
func GraphPartition(resource string) (Partition, error) {
	if len(resource) > maxGraphPartitionLength || !graphPartRe.MatchString(resource) {
		return "", fmt.Errorf("%w: a Graph partition is a lower-case token of at most %d characters", ErrInvalid, maxGraphPartitionLength)
	}
	return Partition(resource), nil
}

func (p Partition) valid() bool {
	s := string(p)
	if guidTextRE.MatchString(s) {
		return s != nilGUID
	}
	return len(s) <= maxGraphPartitionLength && graphPartRe.MatchString(s)
}

// Key identifies a cursor within the transaction's tenant.
type Key struct {
	Connection inventory.ConnectionID
	Partition  Partition
}

func (k Key) validate() error {
	c := string(k.Connection)
	if !guidTextRE.MatchString(c) || c == nilGUID || !k.Partition.valid() {
		return fmt.Errorf("%w: key", ErrInvalid)
	}
	return nil
}

// LeaseName is the platform lease that guards the key's cursor (DM-19.I2: one reader per partition). It is
// derived, so every caller agrees on it, and it is a valid jobs lease name.
func LeaseName(k Key) (string, error) {
	if err := k.validate(); err != nil {
		return "", err
	}
	return leaseNamePrefix + strings.ReplaceAll(string(k.Connection), "-", "") + "." + strings.ReplaceAll(string(k.Partition), "-", ""), nil
}

func (k Key) checkLease(l jobs.Lease) error {
	name, err := LeaseName(k)
	if err != nil {
		return err
	}
	if l.Name != name {
		return ErrWrongLease
	}
	if l.Token < 1 {
		return fmt.Errorf("%w: lease token", ErrInvalid)
	}
	return nil
}

// Cookie is the opaque change-feed position: a DirSync cookie or a Graph delta token. It is never parsed
// here, never compared and never printed: every formatting verb, slog and encoding/json show a fixed
// placeholder. Only the lease holder that resumes the feed reads the bytes, through Bytes.
//
// The bytes live in a closure, not a field: fmt and slog fall back to reflection when a Cookie sits in an
// unexported field of another struct (they cannot call its methods there), and reflection prints a []byte
// field. A func value prints as an address, never as its captured bytes.
type Cookie struct{ get func() []byte }

func newCookie(b []byte) Cookie {
	held := append([]byte(nil), b...)
	return Cookie{get: func() []byte { return held }}
}

// NewCookie wraps the bytes the directory returned. They are copied.
func NewCookie(b []byte) (Cookie, error) {
	if len(b) == 0 || len(b) > maxCookieBytes {
		return Cookie{}, errBadCookie
	}
	return newCookie(b), nil
}

// IsZero reports whether there is no cookie (a feed that must start from a full sync).
func (c Cookie) IsZero() bool { return c.get == nil || len(c.get()) == 0 }

// Bytes returns a copy of the cookie for the request that resumes the feed.
func (c Cookie) Bytes() []byte {
	if c.get == nil {
		return nil
	}
	return append([]byte(nil), c.get()...)
}

// String, GoString, Format, LogValue and the encoders never reveal the bytes.
func (Cookie) String() string   { return redacted }
func (Cookie) GoString() string { return redacted }

// Format covers every fmt verb, including %x and %q.
func (Cookie) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(redacted)) }

// LogValue keeps the cookie out of structured logs.
func (Cookie) LogValue() slog.Value { return slog.StringValue(redacted) }

// MarshalJSON refuses: a cookie is stored in the database and nowhere else.
func (Cookie) MarshalJSON() ([]byte, error) {
	return nil, errors.New("sync: a cookie is never encoded")
}

// MarshalText refuses, for the same reason.
func (Cookie) MarshalText() ([]byte, error) {
	return nil, errors.New("sync: a cookie is never encoded")
}

// Cursor is the diagnostic view of a stored cursor. It has no cookie field: whether one is held is all it
// says. Every list and read method returns this type.
type Cursor struct {
	Key            Key
	State          State
	HasCookie      bool
	IssuingDSA     string // the DC that issued the AD cookie (DM-19.I4); empty for Graph or no cookie
	LastFullSync   time.Time
	LastChange     time.Time
	FencingToken   int64
	StateChangedAt time.Time
}

// String is a one-line description for diagnostics. It carries no cookie, by construction.
func (c Cursor) String() string {
	return fmt.Sprintf("cursor{connection=%s partition=%s state=%s cookie=%t token=%d}",
		c.Key.Connection, c.Key.Partition, c.State, c.HasCookie, c.FencingToken)
}

// LogValue is the structured-log form of String.
func (c Cursor) LogValue() slog.Value { return slog.StringValue(c.String()) }

// Store is the only writer of sync_cursors. It holds no state: every method runs in the caller's
// transaction (DM-19.I1), which the caller opened for the tenant, so the cursor commits or rolls back with
// the inventory rows it covers. Nothing here begins, commits or rolls back.
type Store struct{}

const cursorColumns = `connection_id::text, partition, state, cookie IS NOT NULL, COALESCE(issuing_dsa_guid::text, ''),
  last_full_sync_at, last_change_at, lease_fencing_token, state_changed_at`

const keyMatch = `tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND connection_id = $1::uuid AND partition = $2`

type rowScanner interface{ Scan(dest ...any) error }

// scanCursor reads the cursorColumns, then any extra destinations.
func scanCursor(r rowScanner, extra ...any) (Cursor, error) {
	var (
		c        Cursor
		conn, p  string
		st       string
		full, ch *time.Time
	)
	dest := append([]any{&conn, &p, &st, &c.HasCookie, &c.IssuingDSA, &full, &ch, &c.FencingToken, &c.StateChangedAt}, extra...)
	if err := r.Scan(dest...); err != nil {
		return Cursor{}, err
	}
	c.Key = Key{Connection: inventory.ConnectionID(conn), Partition: Partition(p)}
	c.State = State(st)
	if full != nil {
		c.LastFullSync = full.UTC()
	}
	if ch != nil {
		c.LastChange = ch.UTC()
	}
	return c, nil
}

func requireTenant(ctx context.Context, tx store.Tx) error {
	var ok bool
	if err := tx.QueryRow(ctx, `SELECT NULLIF(current_setting('app.tenant_id', true), '') IS NOT NULL`).Scan(&ok); err != nil {
		return fmt.Errorf("sync: tenant context: %w", err)
	}
	if !ok {
		return ErrNoTenant
	}
	return nil
}

// notFuture refuses a time later than the database clock plus the skew allowance: an as-of is when the
// read started, so it cannot be ahead of now.
func notFuture(ctx context.Context, tx store.Tx, t time.Time) error {
	if t.IsZero() {
		return fmt.Errorf("%w: time", ErrInvalid)
	}
	var future bool
	if err := tx.QueryRow(ctx, `SELECT $1::timestamptz > now() + $2::interval`, t.UTC(), fmt.Sprintf("%d seconds", int(clockSkewAllowance.Seconds()))).Scan(&future); err != nil {
		return writeErr("time check", err)
	}
	if future {
		return fmt.Errorf("%w: time is in the future", ErrInvalid)
	}
	return nil
}

func writeErr(what string, err error) error {
	switch store.SQLState(err) {
	case "23503":
		return ErrUnknownConnection
	case "23514", "22P02", "23502":
		return fmt.Errorf("%w: %s", ErrInvalid, what)
	}
	return fmt.Errorf("sync: %s: %w", what, err)
}

// diagnose explains why a guarded UPDATE or upsert touched no row. Order matters: a stale lease is reported
// before a state mismatch, because the stale holder must stop whatever the state.
func diagnose(ctx context.Context, tx store.Tx, k Key, held int64, to State) error {
	var (
		stored int64
		from   string
	)
	err := tx.QueryRow(ctx, `SELECT lease_fencing_token, state FROM public.sync_cursors WHERE `+keyMatch,
		string(k.Connection), string(k.Partition)).Scan(&stored, &from)
	switch {
	case store.IsNoRows(err):
		return ErrNotFound
	case err != nil:
		return writeErr("diagnose", err)
	case stored > held:
		return &FencedError{Held: held, Stored: stored}
	}
	return &TransitionError{From: State(from), To: to}
}

// Claim records that the lease holder owns the cursor, at the lease's fencing token, creating the cursor in
// initial_sync if the partition has none. Call it right after jobs.AcquireLease succeeds, in a transaction
// of its own or the first cycle's: from then on a holder of an older token is fenced (ErrFenced) even
// before the new holder has advanced anything. Claiming with the stored token again is a no-op that
// succeeds, so a holder may claim every cycle.
func (Store) Claim(ctx context.Context, tx store.Tx, k Key, l jobs.Lease) (Cursor, error) {
	if err := k.checkLease(l); err != nil {
		return Cursor{}, err
	}
	if err := requireTenant(ctx, tx); err != nil {
		return Cursor{}, err
	}
	c, err := scanCursor(tx.QueryRow(ctx, `INSERT INTO public.sync_cursors AS c (tenant_id, connection_id, partition, lease_fencing_token)
		VALUES (NULLIF(current_setting('app.tenant_id', true), '')::uuid, $1::uuid, $2, $3)
		ON CONFLICT (tenant_id, connection_id, partition) DO UPDATE
		SET lease_fencing_token = EXCLUDED.lease_fencing_token,
		    updated_at = CASE WHEN c.lease_fencing_token = EXCLUDED.lease_fencing_token THEN c.updated_at ELSE now() END
		WHERE c.lease_fencing_token <= EXCLUDED.lease_fencing_token
		RETURNING `+cursorColumns, string(k.Connection), string(k.Partition), l.Token))
	switch {
	case err == nil:
		return c, nil
	case store.IsNoRows(err):
		return Cursor{}, diagnose(ctx, tx, k, l.Token, StateInitialSync)
	}
	return Cursor{}, writeErr("claim cursor", err)
}

// Position is the feed position the lease holder resumes from. Cookie.IsZero is true when the cursor holds
// none (initial_sync or resync_required): the feed starts from a full sync. A stale lease is ErrFenced, so a
// deposed holder never resumes from a position it no longer owns.
func (Store) Position(ctx context.Context, tx store.Tx, k Key, l jobs.Lease) (Cursor, Cookie, error) {
	if err := k.checkLease(l); err != nil {
		return Cursor{}, Cookie{}, err
	}
	if err := requireTenant(ctx, tx); err != nil {
		return Cursor{}, Cookie{}, err
	}
	var raw []byte
	row := tx.QueryRow(ctx, `SELECT `+cursorColumns+`, cookie FROM public.sync_cursors WHERE `+keyMatch, string(k.Connection), string(k.Partition))
	c, err := scanCursor(row, &raw)
	switch {
	case store.IsNoRows(err):
		return Cursor{}, Cookie{}, ErrNotFound
	case err != nil:
		return Cursor{}, Cookie{}, writeErr("read position", err)
	case c.FencingToken > l.Token:
		return Cursor{}, Cookie{}, &FencedError{Held: l.Token, Stored: c.FencingToken}
	}
	if len(raw) == 0 {
		return c, Cookie{}, nil
	}
	return c, newCookie(raw), nil
}

// Move is one incremental step of the feed: the new position, and when the directory last changed.
type Move struct {
	// Cookie is the new position returned by the feed. Required.
	Cookie Cookie
	// IssuingDSA is the objectGUID of the DC that issued an AD cookie; empty for Graph (DM-19.I4).
	IssuingDSA string
	// LastChange is the newest change this step saw. The zero time means the step saw none: the cookie
	// advances and last_change_at stays. It never moves back.
	LastChange time.Time
}

// Advance stores the feed's next position of an incremental cursor. It is the compare-and-set of DM-19.I2:
// a lease whose token is below the stored one is refused with ErrFenced and the row is unchanged. A cursor
// that is not incremental is ErrIllegalTransition. Call it in the transaction that stores the inventory rows
// the step covers (DM-19.I1).
func (Store) Advance(ctx context.Context, tx store.Tx, k Key, l jobs.Lease, m Move) (Cursor, error) {
	if err := k.checkLease(l); err != nil {
		return Cursor{}, err
	}
	dsa, err := optGUID(m.IssuingDSA)
	if err != nil {
		return Cursor{}, err
	}
	if m.Cookie.IsZero() {
		return Cursor{}, errBadCookie
	}
	var change *time.Time
	if !m.LastChange.IsZero() {
		if err := notFuture(ctx, tx, m.LastChange); err != nil {
			return Cursor{}, err
		}
		t := m.LastChange.UTC()
		change = &t
	}
	if err := requireTenant(ctx, tx); err != nil {
		return Cursor{}, err
	}
	return written(ctx, tx, k, l.Token, StateIncremental, tx.QueryRow(ctx, `UPDATE public.sync_cursors SET cookie = $5, issuing_dsa_guid = $6::uuid,
		last_change_at = GREATEST(last_change_at, $7::timestamptz), lease_fencing_token = $3, updated_at = now()
		WHERE `+keyMatch+` AND lease_fencing_token <= $3 AND state = ANY($4)
		RETURNING `+cursorColumns, string(k.Connection), string(k.Partition), l.Token, []string{string(StateIncremental)}, m.Cookie.Bytes(), dsa, change))
}

// FullSync is the outcome of a completed full sync (the first one, or a resync).
type FullSync struct {
	// At is when the full read started (Cycle.Observed), never its completion.
	At time.Time
	// Cookie is the position to resume from. Required: incremental means there is one.
	Cookie Cookie
	// IssuingDSA is the DC that issued an AD cookie; empty for Graph.
	IssuingDSA string
}

// CompleteFull moves an initial_sync or resync_required cursor to incremental with the position the full
// sync ended at. Any other state is ErrIllegalTransition. Call it in the transaction that stores the last
// batch of the full sync's inventory rows.
func (Store) CompleteFull(ctx context.Context, tx store.Tx, k Key, l jobs.Lease, f FullSync) (Cursor, error) {
	if err := k.checkLease(l); err != nil {
		return Cursor{}, err
	}
	dsa, err := optGUID(f.IssuingDSA)
	if err != nil {
		return Cursor{}, err
	}
	if f.Cookie.IsZero() {
		return Cursor{}, errBadCookie
	}
	if err := notFuture(ctx, tx, f.At); err != nil {
		return Cursor{}, err
	}
	if err := requireTenant(ctx, tx); err != nil {
		return Cursor{}, err
	}
	return written(ctx, tx, k, l.Token, StateIncremental, tx.QueryRow(ctx, `UPDATE public.sync_cursors SET state = 'incremental', cookie = $5, issuing_dsa_guid = $6::uuid,
		last_full_sync_at = GREATEST(last_full_sync_at, $7::timestamptz), state_changed_at = now(), lease_fencing_token = $3, updated_at = now()
		WHERE `+keyMatch+` AND lease_fencing_token <= $3 AND state = ANY($4)
		RETURNING `+cursorColumns, string(k.Connection), string(k.Partition), l.Token, movesTo(StateIncremental), f.Cookie.Bytes(), dsa, f.At.UTC()))
}

// CompleteScan records that a full read of the partition by a scoped search (no change feed) finished: an
// initial_sync or resync_required cursor moves to incremental with last_full_sync_at at the read's start, and
// an incremental one keeps its state and cookie and only moves last_full_sync_at forward. It writes no
// cookie, because an AD initial state is a ScopedSearch and not a DirSync read (connector contract §6.1): the
// change-feed ticket primes the cookie, so an incremental cursor with no cookie (Position's Cookie.IsZero)
// means "no feed position yet", never "feed caught up". A paused cursor is ErrIllegalTransition. Call it in
// the transaction that stores the last batch of the read's inventory rows (DM-19.I1).
func (Store) CompleteScan(ctx context.Context, tx store.Tx, k Key, l jobs.Lease, at time.Time) (Cursor, error) {
	if err := k.checkLease(l); err != nil {
		return Cursor{}, err
	}
	if err := notFuture(ctx, tx, at); err != nil {
		return Cursor{}, err
	}
	if err := requireTenant(ctx, tx); err != nil {
		return Cursor{}, err
	}
	return written(ctx, tx, k, l.Token, StateIncremental, tx.QueryRow(ctx, `UPDATE public.sync_cursors SET state = 'incremental',
		last_full_sync_at = GREATEST(last_full_sync_at, $5::timestamptz),
		state_changed_at = CASE WHEN state = 'incremental' THEN state_changed_at ELSE now() END,
		lease_fencing_token = $3, updated_at = now()
		WHERE `+keyMatch+` AND lease_fencing_token <= $3 AND state = ANY($4)
		RETURNING `+cursorColumns, string(k.Connection), string(k.Partition), l.Token,
		[]string{string(StateInitialSync), string(StateResyncRequired), string(StateIncremental)}, at.UTC()))
}

// RequireResync records that the cookie is unusable (DM-19.I3: invalid or expired; I4: issued by another
// DC; a Graph delta token that expired) and drops it, so the next cycle starts from a full sync. It is
// idempotent on a cursor that already requires a resync. An initial_sync or paused cursor is
// ErrIllegalTransition: the first has no cookie to distrust, the second resumes through ResumeConnection.
func (Store) RequireResync(ctx context.Context, tx store.Tx, k Key, l jobs.Lease) (Cursor, error) {
	if err := k.checkLease(l); err != nil {
		return Cursor{}, err
	}
	if err := requireTenant(ctx, tx); err != nil {
		return Cursor{}, err
	}
	return written(ctx, tx, k, l.Token, StateResyncRequired, tx.QueryRow(ctx, `UPDATE public.sync_cursors SET state = 'resync_required', cookie = NULL, issuing_dsa_guid = NULL,
		state_changed_at = CASE WHEN state = 'resync_required' THEN state_changed_at ELSE now() END,
		lease_fencing_token = $3, updated_at = now()
		WHERE `+keyMatch+` AND lease_fencing_token <= $3 AND state = ANY($4)
		RETURNING `+cursorColumns, string(k.Connection), string(k.Partition), l.Token,
		// Not from paused, which is a legal move but not the reader's to make: only ResumeConnection resumes.
		[]string{string(StateIncremental), string(StateResyncRequired)}))
}

// written reads the row a guarded UPDATE returned ($1 connection, $2 partition, $3 token, $4 allowed
// states, then the operation's own arguments). No row means the guard refused: diagnose says why.
func written(ctx context.Context, tx store.Tx, k Key, token int64, to State, row rowScanner) (Cursor, error) {
	c, err := scanCursor(row)
	switch {
	case err == nil:
		return c, nil
	case store.IsNoRows(err):
		return Cursor{}, diagnose(ctx, tx, k, token, to)
	}
	return Cursor{}, writeErr("write cursor", err)
}

// PauseConnection pauses every cursor of a connection that is being suspended (DM-19 lifecycle). It is not
// lease-fenced: the suspension is an administrative act, not the reader's, and it does not touch the fencing
// token. A reader that still holds its lease finds the cursor paused and is refused (ErrIllegalTransition)
// on its next write. It returns how many cursors it paused.
func (Store) PauseConnection(ctx context.Context, tx store.Tx, c inventory.ConnectionID) (int64, error) {
	if err := checkConnection(ctx, tx, c); err != nil {
		return 0, err
	}
	tag, err := tx.Exec(ctx, `UPDATE public.sync_cursors SET state = 'paused', state_changed_at = now(), updated_at = now()
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND connection_id = $1::uuid AND state = ANY($2)`,
		string(c), movesTo(StatePaused))
	if err != nil {
		return 0, writeErr("pause cursors", err)
	}
	return tag.RowsAffected(), nil
}

// ResumeConnection resumes the paused cursors of a connection that is active again. Resumption sets
// resync_required and drops the cookie: nothing is assumed about what changed while the connection was
// suspended, so the next cycle runs a full resync, which also reconciles deletions it missed (DM-19.I3).
func (Store) ResumeConnection(ctx context.Context, tx store.Tx, c inventory.ConnectionID) (int64, error) {
	if err := checkConnection(ctx, tx, c); err != nil {
		return 0, err
	}
	tag, err := tx.Exec(ctx, `UPDATE public.sync_cursors SET state = 'resync_required', cookie = NULL, issuing_dsa_guid = NULL,
		state_changed_at = now(), updated_at = now()
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND connection_id = $1::uuid AND state = 'paused'`,
		string(c))
	if err != nil {
		return 0, writeErr("resume cursors", err)
	}
	return tag.RowsAffected(), nil
}

func checkConnection(ctx context.Context, tx store.Tx, c inventory.ConnectionID) error {
	if s := string(c); !guidTextRE.MatchString(s) || s == nilGUID {
		return fmt.Errorf("%w: connection", ErrInvalid)
	}
	return requireTenant(ctx, tx)
}

// Get returns the diagnostic view of one cursor. It never carries the cookie.
func (Store) Get(ctx context.Context, tx store.Tx, k Key) (Cursor, error) {
	if err := k.validate(); err != nil {
		return Cursor{}, err
	}
	if err := requireTenant(ctx, tx); err != nil {
		return Cursor{}, err
	}
	c, err := scanCursor(tx.QueryRow(ctx, `SELECT `+cursorColumns+` FROM public.sync_cursors WHERE `+keyMatch,
		string(k.Connection), string(k.Partition)))
	switch {
	case store.IsNoRows(err):
		return Cursor{}, ErrNotFound
	case err != nil:
		return Cursor{}, writeErr("read cursor", err)
	}
	return c, nil
}

// List returns the cursors of one connection ordered by partition. It never carries a cookie.
func (Store) List(ctx context.Context, tx store.Tx, c inventory.ConnectionID) ([]Cursor, error) {
	if s := string(c); !guidTextRE.MatchString(s) || s == nilGUID {
		return nil, fmt.Errorf("%w: connection", ErrInvalid)
	}
	if err := requireTenant(ctx, tx); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT `+cursorColumns+` FROM public.sync_cursors
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND connection_id = $1::uuid ORDER BY partition`, string(c))
	if err != nil {
		return nil, writeErr("list cursors", err)
	}
	defer rows.Close()
	var out []Cursor
	for rows.Next() {
		cur, err := scanCursor(rows)
		if err != nil {
			return nil, writeErr("list cursors", err)
		}
		out = append(out, cur)
	}
	if err := rows.Err(); err != nil {
		return nil, writeErr("list cursors", err)
	}
	return out, nil
}

func optGUID(s string) (*string, error) {
	if s == "" {
		return nil, nil
	}
	g := strings.ToLower(s)
	if !guidTextRE.MatchString(g) || g == nilGUID {
		return nil, fmt.Errorf("%w: issuing DSA GUID", ErrInvalid)
	}
	return &g, nil
}
