package jobs

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tablekind"
)

// leasesTable declares public.platform_leases (DM-06, platform shape) for fitness-domain-keys.
var leasesTable = tablekind.Declare(tablekind.Table{
	Name:   "public.platform_leases",
	Entity: "DM-06",
	Kind:   tablekind.Platform,
})

// Lease names of the singleton work this package runs.
const (
	LeaseRescue = "jobs.rescue"
	LeaseClean  = "jobs.clean"
)

const (
	maxLeaseTTL = time.Hour
	// maintenanceTTL bounds a crashed rescuer or cleaner: another node takes over after this long.
	maintenanceTTL = 2 * time.Minute
)

var holderPattern = regexp.MustCompile(`^[A-Za-z0-9._:@-]{1,200}$`)

// ErrLeaseLost is returned when a lease is renewed or released by a holder that no longer holds it: it
// expired (and may have been taken over) or was released. The caller must stop the work it guards.
var ErrLeaseLost = errors.New("jobs: the lease is no longer held")

// Lease is a held platform lease. Token is its fencing token: it rises on every takeover, and a write
// made under a lease should carry it (DM-06 I2).
type Lease struct {
	Name    string
	Holder  string
	Token   int64
	Expires time.Time
}

// acquireLease takes the lease when it is free or expired, in one statement: the conflicting row is
// locked by the upsert, so of two concurrent callers the second re-evaluates the WHERE against the
// first's committed row and takes nothing.
const acquireLease = `INSERT INTO public.platform_leases AS l (name, holder, fencing_token, expires_at)
VALUES ($1, $2, 1, now() + $3 * interval '1 millisecond')
ON CONFLICT (name) DO UPDATE SET holder = EXCLUDED.holder, fencing_token = l.fencing_token + 1,
  expires_at = EXCLUDED.expires_at, acquired_at = now(), updated_at = now()
WHERE l.expires_at <= now()
RETURNING l.fencing_token, l.expires_at`

// AcquireLease takes the named platform lease for holder for ttl, if nobody holds it. The boolean is false
// when another holder's lease is still live (that is not an error).
func AcquireLease(ctx context.Context, db *store.DB, name, holder string, ttl time.Duration) (Lease, bool, error) {
	if err := checkLease(name, holder, ttl); err != nil {
		return Lease{}, false, err
	}
	l := Lease{Name: name, Holder: holder}
	err := db.WithPlatform(ctx, "jobs: acquire a platform lease", func(ctx context.Context, tx store.Tx) error {
		return tx.QueryRow(ctx, acquireLease, name, holder, ttl.Milliseconds()).Scan(&l.Token, &l.Expires)
	})
	switch {
	case err == nil:
		return l, true, nil
	case store.IsNoRows(err):
		return Lease{}, false, nil
	}
	return Lease{}, false, fmt.Errorf("jobs: acquire lease: %w", err)
}

// renewLease is fenced on holder, token and liveness: an expired lease cannot be renewed, even if nobody
// has taken it over yet.
const renewLease = `UPDATE public.platform_leases SET expires_at = now() + $4 * interval '1 millisecond', updated_at = now()
WHERE name = $1 AND holder = $2 AND fencing_token = $3 AND expires_at > now()
RETURNING expires_at`

// RenewLease extends a held lease by ttl from now. It returns ErrLeaseLost if the lease expired or was
// taken over (the holder is fenced).
func RenewLease(ctx context.Context, db *store.DB, l Lease, ttl time.Duration) (Lease, error) {
	if err := checkLease(l.Name, l.Holder, ttl); err != nil {
		return Lease{}, err
	}
	err := db.WithPlatform(ctx, "jobs: renew a platform lease", func(ctx context.Context, tx store.Tx) error {
		return tx.QueryRow(ctx, renewLease, l.Name, l.Holder, l.Token, ttl.Milliseconds()).Scan(&l.Expires)
	})
	switch {
	case err == nil:
		return l, nil
	case store.IsNoRows(err):
		return Lease{}, ErrLeaseLost
	}
	return Lease{}, fmt.Errorf("jobs: renew lease: %w", err)
}

// releaseLease expires the lease now; the row stays so the fencing token keeps rising.
const releaseLease = `UPDATE public.platform_leases SET expires_at = now(), updated_at = now()
WHERE name = $1 AND holder = $2 AND fencing_token = $3 AND expires_at > now()`

// ReleaseLease gives the lease up so another caller can take it at once. It returns ErrLeaseLost if the
// lease was no longer held; nothing changed then.
func ReleaseLease(ctx context.Context, db *store.DB, l Lease) error {
	if err := checkLease(l.Name, l.Holder, time.Second); err != nil {
		return err
	}
	var n int64
	err := db.WithPlatform(ctx, "jobs: release a platform lease", func(ctx context.Context, tx store.Tx) error {
		tag, err := tx.Exec(ctx, releaseLease, l.Name, l.Holder, l.Token)
		n = tag.RowsAffected()
		return err
	})
	if err != nil {
		return fmt.Errorf("jobs: release lease: %w", err)
	}
	if n != 1 {
		return ErrLeaseLost
	}
	return nil
}

func checkLease(name, holder string, ttl time.Duration) error {
	switch {
	case !kindPattern.MatchString(name):
		return invalid("lease name %q is not lower-case letters, digits, '_' and '.' starting with a letter (at most 100)", name)
	case !holderPattern.MatchString(holder):
		return invalid("lease holder must be 1..200 characters of letters, digits and ._:@-")
	case ttl <= 0 || ttl > maxLeaseTTL:
		return invalid("lease ttl must be positive and at most %s", maxLeaseTTL)
	}
	return nil
}

// withLease runs fn only if it can take the named lease, and releases it after. ran is false when
// another holder has it. The work guarded here is idempotent and SKIP LOCKED, so a holder whose lease
// lapses mid-call is harmless; the lease keeps the work to one runner, it is not what makes it correct.
func withLease(ctx context.Context, db *store.DB, name, holder string, fn func(ctx context.Context) error) (ran bool, err error) {
	l, ok, err := AcquireLease(ctx, db, name, holder, maintenanceTTL)
	if err != nil || !ok {
		return false, err
	}
	err = fn(ctx)
	// Release even if ctx was cancelled; a lease nobody frees would only block others until it expires.
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if rerr := ReleaseLease(rctx, db, l); rerr != nil && !errors.Is(rerr, ErrLeaseLost) && err == nil {
		err = rerr
	}
	return true, err
}

// RunRescue is the worker's Rescue entry point: it rescues only while holding the LeaseRescue platform
// lease, so one rescuer runs cluster-wide. ran is false when another worker holds the lease.
func RunRescue(ctx context.Context, db *store.DB, holder string, limit int) (res Rescued, ran bool, err error) {
	ran, err = withLease(ctx, db, LeaseRescue, holder, func(ctx context.Context) error {
		var e error
		res, e = Rescue(ctx, db, limit)
		return e
	})
	return res, ran, err
}

// RunClean is the worker's Clean entry point: it cleans only while holding the LeaseClean platform lease.
func RunClean(ctx context.Context, db *store.DB, holder string, retention time.Duration, limit int) (n int64, ran bool, err error) {
	ran, err = withLease(ctx, db, LeaseClean, holder, func(ctx context.Context) error {
		var e error
		n, e = Clean(ctx, db, retention, limit)
		return e
	})
	return n, ran, err
}
