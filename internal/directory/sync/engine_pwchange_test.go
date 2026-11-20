package sync_test

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/store"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

type pwRow struct {
	state string
	asOf  bool
}

// pwRows is password_change_state and whether password_change_at is set, per object GUID text.
func (e *env) pwRows(t *testing.T) map[string]pwRow {
	t.Helper()
	out := map[string]pwRow{}
	err := e.tx(e.a, func(ctx context.Context, tx store.Tx) error {
		rows, err := tx.Query(ctx, `SELECT object_guid::text, COALESCE(password_change_state, 'not_confirmed'), password_change_at IS NOT NULL
			FROM public.directory_objects WHERE connection_id = $1::uuid`, string(e.conn))
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var g string
			var r pwRow
			if err := rows.Scan(&g, &r.state, &r.asOf); err != nil {
				return err
			}
			out[g] = r
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func userGUIDs(f *forest) []string {
	var us []string
	for n, nd := range f.nodes {
		if nd.class[len(nd.class)-1] == "user" {
			us = append(us, gtext(n))
		}
	}
	sort.Strings(us)
	return us
}

func smallForest() *forest {
	f := newForest()
	f.build(ncA, 1, 40, 5)
	return f
}

// TestPasswordChangeStoredPerUser: every state the connector classified is stored for the user it names,
// with the as-of time, and only users are asked.
func TestPasswordChangeStoredPerUser(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		f := smallForest()
		us := userGUIDs(f)
		fake := newFake(f.doms...)
		fake.pwStates = map[string]connectorv1.PasswordChangeState{
			us[0]: connectorv1.PasswordChangeState_PASSWORD_CHANGE_STATE_BLOCKED,
			us[1]: connectorv1.PasswordChangeState_PASSWORD_CHANGE_STATE_BLOCKED_ONE_ACE,
		}
		r := e.rig(t, fake, ncA)
		rep, err := r.run(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		rows := e.pwRows(t)
		want := map[string]string{us[0]: "blocked", us[1]: "blocked_one_ace", us[2]: "no_deny_ace"}
		for g, s := range want {
			if rows[g].state != s || !rows[g].asOf {
				t.Errorf("%s = %+v, want %s with an as-of", g, rows[g], s)
			}
		}
		if len(fake.reads) != len(us) {
			t.Fatalf("%d per-object reads for %d users", len(fake.reads), len(us))
		}
		for _, rq := range fake.reads {
			if !rq.GetIncludePasswordChange() || rq.GetDc().GetPinnedDsaGuid() == nil {
				t.Fatalf("read without the verdict flag or the DC pin: %v", rq)
			}
			for _, a := range rq.GetAttributes() {
				if strings.EqualFold(a, "nTSecurityDescriptor") {
					t.Fatal("the engine asked for the raw descriptor")
				}
			}
		}
		pw := rep.Domains[0].PasswordChange
		if pw["blocked"] != 1 || pw["blocked_one_ace"] != 1 || pw["no_deny_ace"] != len(us)-2 {
			t.Fatalf("report = %v", pw)
		}
		for g, row := range rows { // groups, OUs: never stamped
			if !contains(us, g) && row.asOf {
				t.Errorf("non-user %s has a descriptor time", g)
			}
		}
	})
}

// resync moves the cursor of a domain to resync_required so the next run reads it again.
func (e *env) resync(t *testing.T, r *rig, nc uint64) {
	t.Helper()
	k := e.key(t, gtext(nc))
	l, err := r.leases(context.Background(), mustLeaseName(t, k))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.tx(e.a, func(ctx context.Context, tx store.Tx) error {
		_, err := e.store.RequireResync(ctx, tx, k, l)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// TestPasswordChangeFailsClosed is acceptance 1 and 2: every failure shape reads not_confirmed WITH a
// descriptor time (never the previous value, never the foreign state), the pass completes, and the log
// has the code but no value.
func TestPasswordChangeFailsClosed(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		f := smallForest()
		us := userGUIDs(f)
		fake := newFake(f.doms...)
		faults := []pwFault{pwErr, pwMismatch, pwNoVerdict, pwCoded, pwNoGUID}
		fake.pwFaults = map[string]pwFault{}
		fake.pwStates = map[string]connectorv1.PasswordChangeState{}
		for i, ft := range faults {
			fake.pwFaults[us[i]] = ft
			// a mismatch or an unbound verdict carries a definite state that must not be stored
			fake.pwStates[us[i]] = connectorv1.PasswordChangeState_PASSWORD_CHANGE_STATE_BLOCKED
		}
		r := e.rig(t, fake, ncA)

		// A previous cycle left a definite state: a failed re-read must not keep it.
		first, err := r.run(context.Background())
		if err != nil || !first.Domains[0].Completed {
			t.Fatalf("pass: %v %+v", err, first.Domains[0])
		}
		rows := e.pwRows(t)
		for i := range faults {
			if rows[us[i]].state != "not_confirmed" || !rows[us[i]].asOf {
				t.Errorf("%s fault: %+v, want not_confirmed with an as-of", faults[i], rows[us[i]])
			}
		}
		if rows[us[len(faults)]].state != "no_deny_ace" {
			t.Errorf("a bad descriptor leaked into the next user: %+v", rows[us[len(faults)]])
		}
		pw := first.Domains[0].PasswordChange
		if pw["not_confirmed.call.Unavailable"] != 1 || pw["not_confirmed.guid_mismatch"] != 2 || pw["not_confirmed.no_verdict"] != 1 ||
			pw["not_confirmed.code.ERROR_CODE_INSUFFICIENT_RIGHTS"] != 1 {
			t.Fatalf("report = %v", pw)
		}
		out := r.logs.String()
		if strings.Contains(out, "SENTINEL") {
			t.Fatalf("the connector's message reached the log:\n%s", out)
		}
		if !strings.Contains(out, "password_change.not_confirmed.code.ERROR_CODE_INSUFFICIENT_RIGHTS") {
			t.Fatalf("the log carries no error code:\n%s", out)
		}

		// The user stored as no_deny_ace is re-read and the read fails: not the old value.
		e.resync(t, r, ncA)
		fake.pwFaults = map[string]pwFault{us[len(faults)]: pwErr}
		fake.pwStates = map[string]connectorv1.PasswordChangeState{us[len(faults)]: connectorv1.PasswordChangeState_PASSWORD_CHANGE_STATE_BLOCKED}
		if _, err := r.run(context.Background()); err != nil {
			t.Fatal(err)
		}
		if got := e.pwRows(t)[us[len(faults)]].state; got != "not_confirmed" {
			t.Fatalf("a failed read kept %s", got)
		}
	})
}
