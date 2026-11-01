package fleetsql_test

import (
	"context"
	"errors"
	"math/big"
	"sync"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/fleet/fleetsql"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

func adminIn(t tenant.ID) apihost.Principal {
	p := admin
	p.Tenant = t.String()
	return p
}

type caAuthz struct{ allow bool }

func (a caAuthz) Allow(_ context.Context, _ apihost.Principal, perm, scope string) (bool, error) {
	return a.allow && perm == fleetsql.PermissionCAWithdraw && scope == "tenant", nil
}

// commitProbe records the calls the committing process makes after the commit, and what the database
// showed at the moment of each call (the withdrawal must already be committed).
type commitProbe struct {
	mu        sync.Mutex
	e         *enrollEnv
	tid       tenant.ID
	order     []string
	activeAt  []int
	closedFor []tenant.ID
}

func (p *commitProbe) seen() int {
	n := -1
	_ = p.e.db.WithTenant(context.Background(), p.tid, func(ctx context.Context, tx store.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM public.fleet_ca WHERE state = 'active'`).Scan(&n)
	})
	return n
}

func (p *commitProbe) Invalidate() {
	n := p.seen()
	p.mu.Lock()
	p.order, p.activeAt = append(p.order, "invalidate"), append(p.activeAt, n)
	p.mu.Unlock()
}

func (p *commitProbe) CloseTenant(tid tenant.ID) int {
	p.mu.Lock()
	p.order, p.closedFor = append(p.order, "close"), append(p.closedFor, tid)
	p.mu.Unlock()
	return 3
}

type caRow struct {
	id, state string
	sealed    bool
}

func (e *enrollEnv) caRows(t *testing.T, tid tenant.ID) []caRow {
	t.Helper()
	var out []caRow
	err := e.db.WithTenant(context.Background(), tid, func(ctx context.Context, tx store.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id::text, state, sealed_key IS NOT NULL FROM public.fleet_ca ORDER BY created_at, id`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r caRow
			if err := rows.Scan(&r.id, &r.state, &r.sealed); err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func (e *enrollEnv) initCA(t *testing.T, tid tenant.ID) {
	t.Helper()
	if err := e.db.WithTenant(context.Background(), tid, func(ctx context.Context, tx store.Tx) error {
		return e.enr.InitTenant(ctx, tx, tid)
	}); err != nil {
		t.Fatal(err)
	}
}

func (e *enrollEnv) caAdmin(allow bool, p *commitProbe, fresh ...bool) *fleetsql.CAAdmin {
	f := len(fresh) == 0 || fresh[0]
	return &fleetsql.CAAdmin{DB: e.db, Authz: caAuthz{allow}, Keys: e.ks, Audit: e.sink, StepUp: fakeStepUp{f}, Pool: p, Streams: p}
}

func TestWithdrawActiveCA(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		ctx := context.Background()
		e := setupEnroll(t, s)
		e.initCA(t, e.a)
		e.initCA(t, e.b)
		old := e.caRows(t, e.a)
		if len(old) != 1 || old[0].state != "active" {
			t.Fatalf("setup: %+v", old)
		}
		bBefore := e.caRows(t, e.b)
		probe := &commitProbe{e: e, tid: e.a}
		ca := e.caAdmin(true, probe)
		before := len(e.sink.evs)

		res, err := ca.Withdraw(ctx, e.a, adminIn(e.a), old[0].id, "key exposure suspected on host CA-1")
		if err != nil || res.ClosedStreams != 3 || !res.Replaced {
			t.Fatalf("withdraw: %+v %v", res, err)
		}

		// AC1: withdrawn old row (key destroyed) and a new active row, one transaction.
		rows := e.caRows(t, e.a)
		if len(rows) != 2 || rows[0].id != old[0].id || rows[0].state != "withdrawn" || rows[0].sealed ||
			rows[1].state != "active" || !rows[1].sealed {
			t.Fatalf("rows: %+v", rows)
		}
		// AC2: both calls, after the commit (the database already showed the replacement), in the tenant.
		if len(probe.order) != 2 || probe.order[0] != "invalidate" || probe.order[1] != "close" ||
			probe.activeAt[0] != 1 || len(probe.closedFor) != 1 || probe.closedFor[0] != e.a {
			t.Fatalf("calls: %+v", probe)
		}
		// The withdrawn CA is gone from the tenant's trust list; the other tenant is untouched.
		cas, err := e.enr.TenantCAs(ctx, e.a)
		if err != nil || len(cas) != 1 || cas[0].SerialNumber.Cmp(mustSerial(t, e, old[0].id)) == 0 {
			t.Fatalf("TenantCAs: %d %v", len(cas), err)
		}
		if got := e.caRows(t, e.b); len(got) != 1 || got[0] != bBefore[0] {
			t.Fatalf("other tenant changed: %+v", got)
		}

		// AC3: audit records actor, tenant, CA serial and reason.
		if len(e.sink.evs) != before+1 {
			t.Fatalf("audit events: %d", len(e.sink.evs)-before)
		}
		ev := e.sink.evs[before]
		det := map[string]string{}
		for _, d := range ev.Details {
			det[d.Key] = d.Value
		}
		if ev.Kind != "fleet.ca.withdrawn" || ev.Actor.Requester.ID != "human-1" || ev.Target.GUID != old[0].id ||
			det["tenant"] != e.a.String() || det["ca_serial"] == "" || det["reason"] != "key exposure suspected on host CA-1" ||
			det["previous_state"] != "active" || det["replacement_spki"] == "" {
			t.Fatalf("audit event: %+v", ev)
		}

		// A withdrawn CA is terminal: a second withdrawal is refused and calls nothing.
		probe.order = nil
		if _, err := ca.Withdraw(ctx, e.a, adminIn(e.a), old[0].id, "again"); !errors.Is(err, fleetsql.ErrWithdrawRefused) || len(probe.order) != 0 {
			t.Fatalf("second withdraw: %v %v", err, probe.order)
		}
		// Another tenant's CA id is not visible from this tenant.
		if _, err := ca.Withdraw(ctx, e.a, adminIn(e.a), bBefore[0].id, "cross tenant"); !errors.Is(err, fleetsql.ErrWithdrawRefused) {
			t.Fatalf("cross-tenant withdraw: %v", err)
		}
		if got := e.caRows(t, e.b); got[0].state != "active" {
			t.Fatalf("tenant B CA changed: %+v", got)
		}
	})
}

func mustSerial(t *testing.T, e *enrollEnv, id string) (n *big.Int) {
	t.Helper()
	// The serial is read back from the audit trail's recorded value of the old CA.
	for _, ev := range e.sink.evs {
		if ev.Target.GUID == id {
			for _, d := range ev.Details {
				if d.Key == "ca_serial" {
					n, ok := new(big.Int).SetString(d.Value, 16)
					if !ok {
						t.Fatal("bad serial")
					}
					return n
				}
			}
		}
	}
	t.Fatal("no audit event for CA")
	return nil
}

func TestWithdrawRetiredCA(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		ctx := context.Background()
		e := setupEnroll(t, s)
		e.initCA(t, e.a)
		first := e.caRows(t, e.a)[0]
		// Stage a rollover result: the first CA retired (key erased), a second one active.
		if _, err := e.raw(e.a, `UPDATE public.fleet_ca SET state = 'retired', sealed_key = NULL WHERE id = $1::uuid`, first.id); err != nil {
			t.Fatal(err)
		}
		if err := e.db.WithTenant(ctx, e.a, func(ctx context.Context, tx store.Tx) error {
			return fleetsql.InsertCAForTest(ctx, tx, e.ks, e.a)
		}); err != nil {
			t.Fatal(err)
		}
		probe := &commitProbe{e: e, tid: e.a}
		res, err := e.caAdmin(true, probe).Withdraw(ctx, e.a, adminIn(e.a), first.id, "retired CA host compromised")
		if err != nil || res.Replaced {
			t.Fatalf("withdraw retired: %+v %v", res, err)
		}
		rows := e.caRows(t, e.a)
		if len(rows) != 2 || rows[0].state != "withdrawn" || rows[1].state != "active" {
			t.Fatalf("rows: %+v", rows)
		}
		if len(probe.order) != 2 {
			t.Fatalf("calls: %v", probe.order)
		}
	})
}

// AC4 and the failure paths: nothing is written and nothing is called.
func TestWithdrawRefusals(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		ctx := context.Background()
		e := setupEnroll(t, s)
		e.initCA(t, e.a)
		e.initCA(t, e.b)
		bRows := e.caRows(t, e.b)
		id := e.caRows(t, e.a)[0].id
		probe := &commitProbe{e: e, tid: e.a}
		before := len(e.sink.evs)
		untouched := func(t *testing.T, what string) {
			t.Helper()
			rows := e.caRows(t, e.a)
			if len(rows) != 1 || rows[0].state != "active" || !rows[0].sealed || len(probe.order) != 0 || len(e.sink.evs) != before {
				t.Fatalf("%s changed state: rows=%+v calls=%v audit=%d", what, rows, probe.order, len(e.sink.evs)-before)
			}
		}

		if _, err := e.caAdmin(false, probe).Withdraw(ctx, e.a, adminIn(e.a), id, "why"); !errors.Is(err, fleetsql.ErrWithdrawForbidden) {
			t.Fatalf("without the right: %v", err)
		}
		untouched(t, "forbidden")

		ca := e.caAdmin(true, probe)
		for _, r := range []string{"", "bad\nreason", "x\x00", "a\u202eb", "a\u200bb"} {
			if _, err := ca.Withdraw(ctx, e.a, adminIn(e.a), id, r); !errors.Is(err, fleetsql.ErrWithdrawReason) {
				t.Fatalf("reason %q: %v", r, err)
			}
		}
		if _, err := ca.Withdraw(ctx, e.a, apihost.Principal{}, id, "why"); !errors.Is(err, fleetsql.ErrWithdrawForbidden) {
			t.Fatalf("no principal: %v", err)
		}
		if _, err := ca.Withdraw(ctx, e.a, adminIn(e.a), "not-a-uuid", "why"); !errors.Is(err, fleetsql.ErrWithdrawRefused) {
			t.Fatalf("bad id: %v", err)
		}
		untouched(t, "invalid input")

		// Confused deputy: a tenant-A principal naming tenant B, and a platform principal, are refused.
		if _, err := ca.Withdraw(ctx, e.b, adminIn(e.a), id, "x"); !errors.Is(err, fleetsql.ErrWithdrawForbidden) {
			t.Fatalf("cross-tenant principal: %v", err)
		}
		if _, err := ca.Withdraw(ctx, e.a, admin, id, "x"); !errors.Is(err, fleetsql.ErrWithdrawForbidden) {
			t.Fatalf("platform principal: %v", err)
		}
		untouched(t, "cross-tenant")
		if got := e.caRows(t, e.b); len(got) != 1 || got[0] != bRows[0] {
			t.Fatalf("tenant B changed: %+v", got)
		}

		// No fresh step-up: refused, nothing changed.
		if _, err := e.caAdmin(true, probe, false).Withdraw(ctx, e.a, adminIn(e.a), id, "why"); !errors.Is(err, fleetsql.ErrStepUpRequired) {
			t.Fatalf("stale step-up: %v", err)
		}
		untouched(t, "stale step-up")
		noSU := e.caAdmin(true, probe)
		noSU.StepUp = nil
		if _, err := noSU.Withdraw(ctx, e.a, adminIn(e.a), id, "why"); !errors.Is(err, fleetsql.ErrNotConfigured) {
			t.Fatalf("nil step-up: %v", err)
		}
		untouched(t, "nil step-up")

		// A replacement that cannot be sealed rolls the whole withdrawal back.
		e.ks.setFail(true)
		if _, err := ca.Withdraw(ctx, e.a, adminIn(e.a), id, "why"); err == nil {
			t.Fatal("withdraw succeeded without a data key")
		}
		e.ks.setFail(false)
		untouched(t, "failed replacement")

		// A missing port is a configuration error, never a partial commit.
		bad := e.caAdmin(true, probe)
		bad.Streams = nil
		if _, err := bad.Withdraw(ctx, e.a, adminIn(e.a), id, "why"); !errors.Is(err, fleetsql.ErrNotConfigured) {
			t.Fatalf("missing port: %v", err)
		}
		untouched(t, "misconfigured")
	})
}
