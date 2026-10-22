// Package jobstest is test support for code that runs the job worker against a real database. It owns the
// one piece of SQL such tests need that the jobs package does not export: making claims lapse, which is
// what the passing of a kind's lease would do. Never import it from product code.
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
