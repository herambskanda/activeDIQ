// Package jobstest is test support for code that runs the job worker against a real database. It owns
// the SQL such tests need against public.jobs and public.platform_leases that the jobs package does not
// export (ADR-0002 T5: those tables are registered-global, so only this package's owner,
// internal/platform/jobs, and its own test support may reference them in SQL). Never import it from
// product code.
package jobstest

import (
	"context"
	"testing"
)

// Exec runs one statement as the database owner; storetest's Database.ExecOwner has this shape.
type Exec func(ctx context.Context, sql string, args ...any) error

// LapseClaims makes every running claim in the database lapse now, as if the worker holding it had died
// and its lease had run out, so that jobs.Rescue requeues it.
func LapseClaims(t testing.TB, exec Exec) {
	t.Helper()
	if err := exec(context.Background(),
		`UPDATE public.jobs SET claimed_until = now() - interval '1 second' WHERE state = 'running'`); err != nil {
		t.Fatalf("jobstest: lapse claims: %v", err)
	}
}

// Query runs one statement as the database owner and returns the first column of each row as text;
// the audit rig's adminStrings has this shape.
type Query func(sql string, args ...any) ([]string, error)

// MakeDue makes every queued job of the kind runnable now.
func MakeDue(t testing.TB, exec Exec, kind string) {
	t.Helper()
	if err := exec(context.Background(),
		`UPDATE public.jobs SET run_at = now() WHERE kind = $1 AND state = 'available'`, kind); err != nil {
		t.Fatalf("jobstest: make %s due: %v", kind, err)
	}
}

// MakeDueUnderKey makes every queued job of the kind runnable now and moves it to its own unique key, as
// a real run in a later schedule bucket has (a test cannot wait out the bucket).
func MakeDueUnderKey(t testing.TB, exec Exec, kind, uniqueKey string) {
	t.Helper()
	if err := exec(context.Background(),
		`UPDATE public.jobs SET run_at = now() - interval '1 second', unique_key = $2 WHERE kind = $1`, kind, uniqueKey); err != nil {
		t.Fatalf("jobstest: make %s due: %v", kind, err)
	}
}

// QueuedErrorCodes returns the error_code ("" when none) of each queued job of the kind that has made
// exactly the given number of attempts.
func QueuedErrorCodes(q Query, kind string, attempt int) ([]string, error) {
	return q(`SELECT coalesce(error_code, '') FROM public.jobs WHERE kind = $1 AND attempt = $2 AND state = 'available'`, kind, attempt)
}

// FirstRetryErrorCode returns the error_code of the oldest job of the kind that has made at least two
// attempts, as a one-element slice, or an empty one when there is none.
func FirstRetryErrorCode(q Query, kind string) ([]string, error) {
	return q(`SELECT coalesce(error_code, '') FROM public.jobs WHERE kind = $1 AND attempt >= 2 ORDER BY id LIMIT 1`, kind)
}

// CountQueued returns how many jobs of the kind are waiting to run.
func CountQueued(q Query, kind string) (string, error) {
	v, err := q(`SELECT count(*)::text FROM public.jobs WHERE kind = $1 AND state = 'available'`, kind)
	if err != nil || len(v) != 1 {
		return "", err
	}
	return v[0], nil
}

// CountForTenant returns how many jobs of the kind exist for the tenant, in any state.
func CountForTenant(q Query, kind, tenantID string) (string, error) {
	v, err := q(`SELECT count(*)::text FROM public.jobs WHERE kind = $1 AND tenant_id = $2::uuid`, kind, tenantID)
	if err != nil || len(v) != 1 {
		return "", err
	}
	return v[0], nil
}

// ErrorCodesByKind returns the error_code ("" when none) of every job of the kind, in any state.
func ErrorCodesByKind(q Query, kind string) ([]string, error) {
	return q(`SELECT coalesce(error_code, '') FROM public.jobs WHERE kind = $1`, kind)
}

// ErrorCodesByState returns the error_code ("" when none) of every job of the kind in the given state.
func ErrorCodesByState(q Query, kind, state string) ([]string, error) {
	return q(`SELECT coalesce(error_code, '') FROM public.jobs WHERE kind = $1 AND state = $2`, kind, state)
}

// JobArgText returns the text value at key in the args of every job of the kind.
func JobArgText(q Query, kind, key string) ([]string, error) {
	return q(`SELECT args->>$2 FROM public.jobs WHERE kind = $1`, kind, key)
}

// ActiveLeaseNames returns the names of the active (not yet expired) leases whose name matches the
// SQL LIKE pattern.
func ActiveLeaseNames(q Query, pattern string) ([]string, error) {
	return q(`SELECT name FROM public.platform_leases WHERE name LIKE $1 AND expires_at > now()`, pattern)
}

// ActiveLeaseHolders returns the distinct holders of the active leases whose name matches the SQL
// LIKE pattern.
func ActiveLeaseHolders(q Query, pattern string) ([]string, error) {
	return q(`SELECT holder FROM public.platform_leases WHERE name LIKE $1 AND expires_at > now() GROUP BY holder`, pattern)
}

// ExpireLeases makes every lease whose name matches the SQL LIKE pattern expire now, as if its
// holder had stopped renewing it. Returns the error rather than failing the test, since a caller
// running inside a callback on another goroutine (as a lease-theft test commonly does) must not
// call t.Fatal.
func ExpireLeases(exec Exec, pattern string) error {
	return exec(context.Background(),
		`UPDATE public.platform_leases SET expires_at = now() - interval '1 second' WHERE name LIKE $1`, pattern)
}
