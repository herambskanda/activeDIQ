package audit_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/audit/chain"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/personal"
	"github.com/skenzeriq/activediq/internal/platform/store"
)

const (
	pConn    = "11111111-1111-4111-8111-111111111111"
	pGUID    = "22222222-2222-4222-8222-222222222222"
	pSubject = "dir:" + pConn + ":" + pGUID
)

func personalEvent(id string) audit.Event {
	return audit.Event{ID: id, Kind: "operation.step.applied", At: time.Now(), Actor: human, Component: "test", Outcome: audit.Success,
		Target: authority.TargetRef{Connection: pConn, GUID: pGUID, Class: "user"},
		Changes: []audit.Change{
			{Subject: pSubject, Attribute: "mail", Before: []string{"old@example.test"}, After: []string{"new@example.test", "alt@example.test"}},
			{Subject: pSubject, Attribute: "unicodePwd", Secret: true, After: []string{"must-not-be-kept"}},
		},
		Snapshots: []audit.Snapshot{{Subject: pSubject, Field: "displayName", Value: "Ada Lovelace"}}}
}

func (r *rig) appendEvent(e audit.Event) {
	r.t.Helper()
	if err := r.db.WithTenant(context.Background(), r.id, func(ctx context.Context, tx store.Tx) error { return r.ch.Append(ctx, tx, e) }); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rig) lastEnvelope(b chain.Bundle) chain.Envelope {
	r.t.Helper()
	env, err := chain.ParseEnvelope(b.Events[len(b.Events)-1].Envelope)
	if err != nil {
		r.t.Fatal(err)
	}
	return env
}

func (r *rig) render(env chain.Envelope) audit.Rendered {
	r.t.Helper()
	var out audit.Rendered
	err := r.db.WithTenant(context.Background(), r.id, func(ctx context.Context, tx store.Tx) (err error) {
		out, err = audit.Render(ctx, tx, r.id, env)
		return err
	})
	if err != nil {
		r.t.Fatal(err)
	}
	return out
}

// Acceptance 1, 2 and 3 of T-0306.
func TestValuesAndSnapshotsAreRefsAndErasureKeepsTheChain(t *testing.T) {
	each(t, func(t *testing.T, r *rig) {
		r.appendEvent(personalEvent("p1"))
		b := r.export(r.id)
		raw := b.Events[len(b.Events)-1].Envelope
		for _, clear := range []string{"old@example.test", "new@example.test", "alt@example.test", "Ada Lovelace", "must-not-be-kept"} {
			if strings.Contains(string(raw), clear) {
				t.Fatalf("envelope holds %q inline", clear)
			}
		}
		env := r.lastEnvelope(b)
		if len(env.Changes) != 2 || len(env.Changes[0].Before) != 1 || len(env.Changes[0].After) != 2 || len(env.Snapshots) != 1 ||
			len(env.Changes[1].After) != 0 {
			t.Fatalf("refs = %+v snapshots = %d", env.Changes, len(env.Snapshots))
		}
		if res := chain.Verify(b, r.pin(r.id)); res.Status != chain.OK {
			t.Fatalf("verify = %+v", res)
		}

		got := r.render(env)
		if got.Changes[0].Before[0] != "old@example.test" || got.Changes[0].After[1] != "alt@example.test" ||
			got.Snapshots[0].Value != "Ada Lovelace" || len(got.Changes[1].After) != 0 {
			t.Fatalf("rendered = %+v", got)
		}

		// Erase the subject (as the erasure Action does): values and salt go.
		if err := r.admin(`DELETE FROM public.personal_value WHERE subject_ref = $1`, pSubject); err != nil {
			t.Fatal(err)
		}
		if err := r.admin(`DELETE FROM public.personal_subject WHERE subject_ref = $1`, pSubject); err != nil {
			t.Fatal(err)
		}
		got = r.render(env)
		if got.Changes[0].Before[0] != personal.Redacted || got.Changes[0].After[0] != personal.Redacted || got.Snapshots[0].Value != personal.Redacted {
			t.Fatalf("after erasure rendered = %+v", got)
		}
		b2 := r.export(r.id)
		if res := chain.Verify(b2, r.pin(r.id)); res.Status != chain.OK {
			t.Fatalf("verify after erasure = %+v", res)
		}
	})
}

// A retried append (ambiguous commit) is one event and keeps one set of values.
func TestRetriedPersonalEventKeepsOneSetOfValues(t *testing.T) {
	each(t, func(t *testing.T, r *rig) {
		r.appendEvent(personalEvent("p1"))
		r.appendEvent(personalEvent("p1"))
		var n int
		err := r.db.WithTenant(context.Background(), r.id, func(ctx context.Context, tx store.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM public.personal_value WHERE subject_ref = $1`, pSubject).Scan(&n)
		})
		if err != nil || n != 5-1 { // before 1 + after 2 + snapshot 1; the secret change keeps nothing
			t.Fatalf("values = %d, %v; want 4", n, err)
		}
	})
}

// A rolled-back append leaves no personal value behind.
func TestRolledBackPersonalEventLeavesNoValues(t *testing.T) {
	each(t, func(t *testing.T, r *rig) {
		_ = r.db.WithTenant(context.Background(), r.id, func(ctx context.Context, tx store.Tx) error {
			if err := r.ch.Append(ctx, tx, personalEvent("p2")); err != nil {
				return err
			}
			return context.Canceled
		})
		var n int
		_ = r.db.WithTenant(context.Background(), r.id, func(ctx context.Context, tx store.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM public.personal_value`).Scan(&n)
		})
		if n != 0 {
			t.Fatalf("values = %d after rollback", n)
		}
	})
}
