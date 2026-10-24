package operation

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/audit/chain"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/keys"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

func TestMain(m *testing.M) { os.Exit(storetest.Main(m)) }

// ---- fakes: a directory, a pinner, settings, provenance, alerts, keys, a gate ----

type dirFake struct {
	mu      sync.Mutex
	val     map[string]string
	pwdSet  map[string]time.Time
	applies map[string]int
	mode    map[string]string // guid -> behaviour of Apply
	secret  string
}

func newDir() *dirFake {
	return &dirFake{val: map[string]string{}, pwdSet: map[string]time.Time{}, applies: map[string]int{}, mode: map[string]string{}}
}

func (d *dirFake) get(g string) string { d.mu.Lock(); defer d.mu.Unlock(); return d.val[g] }
func (d *dirFake) set(g, v string)     { d.mu.Lock(); d.val[g] = v; d.mu.Unlock() }

type itemIn struct {
	GUID  string
	Want  string
	Phase int
	Cred  bool
}
type dirIn struct{ Items []itemIn }
type dirPayload struct{ GUID, Before, Want string }
type dirOut struct{ GUID string }

func (d *dirFake) action(t *testing.T, id ActionID, stepUp, secretIn bool, class Reversibility) Action {
	a, err := Define(Typed[dirIn, dirPayload, dirOut]{
		Descriptor: Descriptor{ID: id, Version: 1, Permission: "ad.user.set", Input: "#/components/schemas/Dir", Target: TargetAD,
			Reversibility: class, AuditKind: "directory.user.changed", StepUp: stepUp, SecretInput: secretIn},
		Plan: func(_ context.Context, _ PlanContext, in dirIn) ([]TypedStep[dirPayload], error) {
			var out []TypedStep[dirPayload]
			for _, it := range in.Items {
				before := d.get(it.GUID)
				if before == it.Want {
					out = append(out, TypedStep[dirPayload]{Plan: StepPlan{Target: authority.TargetRef{Connection: "c1", GUID: it.GUID, Class: "user"},
						Kind: "ldap.modify", Reversibility: class, NC: "dc=example"}, Payload: dirPayload{GUID: it.GUID}})
					continue
				}
				out = append(out, TypedStep[dirPayload]{
					Plan: StepPlan{Target: authority.TargetRef{Connection: "c1", GUID: it.GUID, Class: "user"}, Kind: "ldap.modify",
						Reversibility: class, Phase: it.Phase, NC: "dc=example", Credential: it.Cred,
						Diff: []Change{{Attribute: "title", Before: []string{before}, After: []string{it.Want}}}},
					Payload: dirPayload{GUID: it.GUID, Before: before, Want: it.Want}})
			}
			return out, nil
		},
		Apply: func(ctx context.Context, s step.Step, p TypedStep[dirPayload]) (dirOut, error) {
			if err := s.Valid(); err != nil {
				return dirOut{}, err
			}
			// What client.Write does: live facts, the re-check, then the write.
			if _, err := s.Recheck(ctx, authority.Facts{Exists: true}); err != nil {
				return dirOut{}, err
			}
			d.mu.Lock()
			defer d.mu.Unlock()
			g := p.Payload.GUID
			d.applies[g]++
			if secretIn {
				s.Secret().Expose(func(b []byte) { d.secret = string(b) })
			}
			switch d.mode[g] {
			case "transient_before":
				return dirOut{}, fmt.Errorf("busy: %w", ErrTransient)
			case "transient_after":
				d.val[g] = p.Payload.Want
				return dirOut{}, fmt.Errorf("lost reply: %w", ErrTransient)
			case "stale":
				return dirOut{}, fmt.Errorf("moved: %w", ErrStaleState)
			case "unknown":
				return dirOut{}, ErrOutcomeUnknown
			case "defer":
				d.val[g] = p.Payload.Want
				return dirOut{GUID: g}, nil
			}
			d.val[g] = p.Payload.Want
			d.pwdSet[g] = time.Now()
			return dirOut{GUID: g}, nil
		},
		Verify: func(_ context.Context, _ step.Step, p TypedStep[dirPayload], _ dirOut) (Verdict, error) {
			if d.mode[p.Payload.GUID] == "defer" && d.mode["verified"] != "yes" {
				return Verdict{}, ErrDeferVerify
			}
			if d.get(p.Payload.GUID) != p.Payload.Want {
				return Verdict{Reason: "mismatch"}, nil
			}
			return Verdict{OK: true}, nil
		},
		Inverse: func(TypedStep[dirPayload], dirOut) (dirIn, error) { return dirIn{}, ErrIrreversible },
		Observe: func(_ context.Context, _ authority.Pins, p TypedStep[dirPayload], claimedAt time.Time) (Observation, error) {
			d.mu.Lock()
			defer d.mu.Unlock()
			g := p.Payload.GUID
			if p.Plan.Credential {
				if d.pwdSet[g].After(claimedAt) {
					return ObservedAfter, nil
				}
				return ObservedBefore, nil
			}
			switch d.val[g] {
			case p.Payload.Want:
				return ObservedAfter, nil
			case p.Payload.Before:
				return ObservedBefore, nil
			}
			return ObservedOther, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

type pinFake struct{}

func (pinFake) Pin(context.Context, string, authority.NamingContextID, string) (string, error) {
	return "dc1.example.test", nil
}

type settingsFake struct{ irreversible bool }

func (s settingsFake) ApprovalForIrreversible(context.Context) (bool, error) {
	return s.irreversible, nil
}

type provFake struct {
	tied map[[2]authority.PrincipalID]bool
	err  error
}

func (p provFake) Tied(_ context.Context, actor, subject authority.PrincipalID, _ time.Time) (bool, error) {
	return p.tied[[2]authority.PrincipalID{actor, subject}], p.err
}

type alertsFake struct {
	mu  sync.Mutex
	got []Alert
}

func (a *alertsFake) Alert(_ context.Context, x Alert) {
	a.mu.Lock()
	a.got = append(a.got, x)
	a.mu.Unlock()
}
func (a *alertsFake) reasons() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []string
	for _, x := range a.got {
		out = append(out, x.Reason)
	}
	return out
}

type keySrc struct{}

func (keySrc) DEK(context.Context, store.Tx, tenant.ID, uint32) (keys.DEK, error) {
	return keys.DEKFromBytes(1, bytes.Repeat([]byte{7}, keys.DEKSize))
}

type holdGate struct {
	route Route
	err   error
}

func (holdGate) ID() GateID { return "test-gate" }
func (g holdGate) Route(context.Context, PlanSummary) (Route, error) {
	return g.route, g.err
}

type prig struct {
	t      *testing.T
	d      *storetest.Database
	db     *store.DB
	r      *Runner
	dir    *dirFake
	alerts *alertsFake
	prov   *provFake
	tn     tenant.ID
}

type rigOpt struct {
	gate     Gate
	irrev    bool
	attempts int
	slots    int
	stepUp   bool
	secretIn bool
	class    Reversibility
}

func newPRig(t *testing.T, s *storetest.Server, o rigOpt) *prig {
	t.Helper()
	d := s.NewDatabase(t)
	d.Migrate(t)
	ctx := context.Background()
	db, err := store.Open(ctx, store.Config{DSN: d.AppDSN()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	ch := audit.NewChainer(db)
	cp := audit.NewCheckpointer(ch, keySrc{}, nopAnchor{})
	tn := tenanttest.Seed(t, d.ExecOwner, "A")
	if err := db.WithTenant(ctx, tn, func(ctx context.Context, tx store.Tx) error { return cp.InitTenant(ctx, tx, tn) }); err != nil {
		t.Fatal(err)
	}
	p := &prig{t: t, d: d, db: db, dir: newDir(), alerts: &alertsFake{}, prov: &provFake{tied: map[[2]authority.PrincipalID]bool{}}, tn: tn}
	if o.class == "" {
		o.class = Reversible
	}
	reg, err := NewRegistry(p.dir.action(t, "ad.user.set", o.stepUp, o.secretIn, o.class))
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{DB: db, Audit: ch, Authz: &authzFake{}, Registry: reg, Facts: factsFake{}, Gate: o.gate, Jobs: jobs.NewRegistry(),
		Keys: keySrc{}, Pinner: pinFake{}, Settings: settingsFake{irreversible: o.irrev}, Provenance: p.prov, Alerts: p.alerts,
		Attempts: o.attempts, Slots: o.slots, Backoff: time.Millisecond, Lease: time.Minute}
	if p.r, err = NewRunner(cfg); err != nil {
		t.Fatal(err)
	}
	p.r.sleep = func(time.Duration) {}
	return p
}

type nopAnchor struct{}

func (nopAnchor) Anchor(context.Context, chain.Checkpoint) error { return nil }

// owner and exec run as the superuser: the owner role is subject to FORCE ROW LEVEL SECURITY and sees no
// tenant rows. They are fixture helpers; the statements are test text.
func (p *prig) owner(sql string, args ...any) []string {
	p.t.Helper()
	ctx := context.Background()
	c, err := p.d.Admin(ctx)
	if err != nil {
		p.t.Fatal(err)
	}
	defer c.Close(ctx)
	rows, err := c.Query(ctx, sql, args...)
	if err != nil {
		p.t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			p.t.Fatal(err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		p.t.Fatal(err)
	}
	return out
}

func (p *prig) exec(sql string, args ...any) {
	p.t.Helper()
	ctx := context.Background()
	c, err := p.d.Admin(ctx)
	if err != nil {
		p.t.Fatal(err)
	}
	defer c.Close(ctx)
	if _, err := c.Exec(ctx, sql, args...); err != nil {
		p.t.Fatal(err)
	}
}

var alice = authority.Chain{Requester: authority.Principal{ID: "alice", Kind: authority.Human}}

func (p *prig) req(items ...itemIn) Request {
	in := fmt.Sprintf(`{"Items":[%s]}`, joinItems(items))
	return Request{Tenant: p.tn, Actor: alice, Action: "ad.user.set", Input: Input(in), Origin: OriginConsole}
}

func joinItems(items []itemIn) string {
	var parts []string
	for _, it := range items {
		parts = append(parts, fmt.Sprintf(`{"GUID":%q,"Want":%q,"Phase":%d,"Cred":%t}`, it.GUID, it.Want, it.Phase, it.Cred))
	}
	return strings.Join(parts, ",")
}

func (p *prig) opState(id step.OperationID) string {
	return p.owner(`SELECT state FROM public.operations WHERE id = $1::uuid`, string(id))[0]
}

// stepRow returns state|reason|attempt|recovered of item n's only step.
func (p *prig) stepRow(id step.OperationID, item int) string {
	return p.owner(`SELECT state || '|' || COALESCE(reason, '') || '|' || attempt || '|' || recovered FROM public.operation_steps
WHERE operation_id = $1::uuid AND item_no = $2`, string(id), item)[0]
}

func (p *prig) runChunks(id step.OperationID) {
	p.t.Helper()
	for phase := 0; phase < 3; phase++ {
		if err := p.r.RunChunk(context.Background(), p.tn, p.r.txFor(p.tn), chunkArgs{Operation: string(id), Phase: phase, Chunk: 0}); err != nil {
			p.t.Fatal(err)
		}
	}
}

func (p *prig) events(kind string) int {
	n := p.owner(`SELECT count(*) FROM public.audit_event WHERE kind = $1`, kind)
	var c int
	fmt.Sscan(n[0], &c)
	return c
}

// ---- tests ----

func TestSubmitAndApplyEndToEnd(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		p := newPRig(t, s, rigOpt{})
		p.dir.set("g1", "old")
		sub, err := p.r.SubmitDirectory(context.Background(), p.req(itemIn{GUID: "g1", Want: "new"}, itemIn{GUID: "g2", Want: "x"}, itemIn{GUID: "g3", Want: ""}))
		if err != nil {
			t.Fatal(err)
		}
		if sub.State != OpQueued || sub.Planned != 2 || sub.Skipped != 1 {
			t.Fatalf("sub = %+v", sub)
		}
		if n := p.owner(`SELECT count(*) FROM public.jobs WHERE kind = 'operation.apply'`)[0]; n != "1" {
			t.Fatalf("apply jobs = %s", n)
		}
		p.runChunks(sub.Operation)
		if st := p.opState(sub.Operation); st != "succeeded" {
			t.Fatalf("operation = %s", st)
		}
		if p.dir.get("g1") != "new" || p.dir.get("g2") != "x" {
			t.Fatal("directory not written")
		}
		if got := p.stepRow(sub.Operation, 0); got != "verified||1|false" {
			t.Fatalf("step = %s", got)
		}
		if p.events("directory.user.changed") != 2 || p.events("operation.started") != 1 || p.events("operation.completed") != 1 {
			t.Fatalf("events: step=%d started=%d completed=%d", p.events("directory.user.changed"), p.events("operation.started"), p.events("operation.completed"))
		}
		dup, err := p.r.SubmitDirectory(context.Background(), func() Request { r := p.req(itemIn{GUID: "g1", Want: "new"}); r.IdempotencyKey = "k"; return r }())
		if err != nil || dup.Duplicate {
			t.Fatal(err, dup)
		}
		again, err := p.r.SubmitDirectory(context.Background(), func() Request { r := p.req(itemIn{GUID: "g9", Want: "z"}); r.IdempotencyKey = "k"; return r }())
		if err != nil || !again.Duplicate || again.Operation != dup.Operation {
			t.Fatalf("idempotent resubmit = %+v %v", again, err)
		}
	})
}

func TestPhasesRunInOrder(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		p := newPRig(t, s, rigOpt{})
		sub, err := p.r.SubmitDirectory(context.Background(), p.req(itemIn{GUID: "a", Want: "1", Phase: 1}, itemIn{GUID: "b", Want: "1", Phase: 0}))
		if err != nil {
			t.Fatal(err)
		}
		if n := p.owner(`SELECT count(*) FROM public.jobs WHERE kind = 'operation.apply'`)[0]; n != "1" {
			t.Fatalf("only the first phase is queued, got %s jobs", n)
		}
		if err := p.r.RunChunk(context.Background(), p.tn, p.r.txFor(p.tn), chunkArgs{Operation: string(sub.Operation), Phase: 0}); err != nil {
			t.Fatal(err)
		}
		if p.dir.get("a") != "" || p.dir.get("b") != "1" {
			t.Fatal("phase 1 ran before phase 0 finished")
		}
		if n := p.owner(`SELECT count(*) FROM public.jobs WHERE kind = 'operation.apply'`)[0]; n != "2" {
			t.Fatalf("the settled phase enqueues the next in the recording transaction, got %s jobs", n)
		}
	})
}

// claimOnly claims the next step as a worker that then dies.
func (p *prig) claimOnly(id step.OperationID) *claimed {
	p.t.Helper()
	var c *claimed
	err := p.r.txFor(p.tn)(context.Background(), func(ctx context.Context, tx store.Tx) (err error) {
		c, err = p.r.claimNext(ctx, tx, p.tn, string(id), 0, 0)
		return err
	})
	if err != nil || c == nil {
		p.t.Fatalf("claim: %v %v", c, err)
	}
	return c
}

func (p *prig) lapse(id step.OperationID) {
	p.exec(`UPDATE public.operation_steps SET claimed_until = now() - interval '1 second' WHERE operation_id = $1::uuid AND state = 'applying'`, string(id))
}

func TestReconcileLapsedClaim(t *testing.T) {
	cases := []struct {
		name      string
		dirValue  string // what the directory holds after the "crash"
		cancel    bool
		cred      bool
		pwdAfter  bool
		want      string
		wantApply int
	}{
		{"after-state is applied, recovered", "new", false, false, false, "verified||2|true", 0},
		{"before-state is applied again", "old", false, false, false, "verified||2|false", 1},
		{"before-state while cancelling is not_run", "old", true, false, false, "not_run|cancelled|2|false", 0},
		{"anything else is stale_state", "other", false, false, false, "failed|stale_state|2|false", 0},
		{"password never re-applied: outcome unknown", "old", false, true, false, "failed|outcome_unknown|2|false", 0},
		{"password set after the claim is applied", "new", false, true, true, "verified||2|true", 0},
	}
	for _, tc := range cases {
		storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
			t.Run(tc.name, func(t *testing.T) {
				p := newPRig(t, s, rigOpt{})
				p.dir.set("g1", "old")
				sub, err := p.r.SubmitDirectory(context.Background(), p.req(itemIn{GUID: "g1", Want: "new", Cred: tc.cred}))
				if err != nil {
					t.Fatal(err)
				}
				c := p.claimOnly(sub.Operation)
				p.dir.set("g1", tc.dirValue)
				if tc.pwdAfter {
					p.dir.pwdSet["g1"] = c.claimedAt.Add(time.Second)
				}
				if tc.cancel {
					if _, err := p.r.Cancel(context.Background(), p.tn, alice, string(sub.Operation)); err != nil {
						t.Fatal(err)
					}
					if p.opState(sub.Operation) != "cancelling" {
						t.Fatalf("operation = %s", p.opState(sub.Operation))
					}
				}
				p.lapse(sub.Operation)
				if n, err := p.r.Reconcile(context.Background(), p.tn, p.r.txFor(p.tn), 10); err != nil || n != 1 {
					t.Fatalf("reconcile = %d %v", n, err)
				}
				if got := p.stepRow(sub.Operation, 0); got != tc.want {
					t.Fatalf("step = %s, want %s", got, tc.want)
				}
				if p.dir.applies["g1"] != tc.wantApply {
					t.Fatalf("applies = %d, want %d", p.dir.applies["g1"], tc.wantApply)
				}
			})
		})
	}
}

func TestSupersededAttemptChangesNothing(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		p := newPRig(t, s, rigOpt{})
		p.dir.set("g1", "old")
		sub, _ := p.r.SubmitDirectory(context.Background(), p.req(itemIn{GUID: "g1", Want: "new"}))
		old := p.claimOnly(sub.Operation)
		p.lapse(sub.Operation)
		p.dir.set("g1", "old")
		if _, err := p.r.Reconcile(context.Background(), p.tn, p.r.txFor(p.tn), 10); err != nil {
			t.Fatal(err)
		}
		before := p.stepRow(sub.Operation, 0)
		// The revived original writer reports a failure for its superseded attempt 1.
		if err := p.r.record(context.Background(), p.tn, p.r.txFor(p.tn), old, recordSpec{failed: "late"}); err != nil {
			t.Fatal(err)
		}
		if got := p.stepRow(sub.Operation, 0); got != before || !strings.HasPrefix(got, "verified") {
			t.Fatalf("a superseded attempt changed the step: %s -> %s", before, got)
		}
	})
}

func TestRetriesExhausted(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		p := newPRig(t, s, rigOpt{attempts: 3})
		p.dir.set("a", "old")
		p.dir.set("b", "old")
		p.dir.mode["a"], p.dir.mode["b"] = "transient_after", "transient_before"
		sub, err := p.r.SubmitDirectory(context.Background(), p.req(itemIn{GUID: "a", Want: "new"}, itemIn{GUID: "b", Want: "new"}))
		if err != nil {
			t.Fatal(err)
		}
		p.runChunks(sub.Operation)
		if got := p.stepRow(sub.Operation, 0); !strings.HasPrefix(got, "verified|") || !strings.Contains(got, "|true") {
			t.Fatalf("after-state in place must not be failed: %s", got)
		}
		if got := p.stepRow(sub.Operation, 1); !strings.HasPrefix(got, "failed|retries_exhausted|3") {
			t.Fatalf("before-state: %s", got)
		}
		if st := p.opState(sub.Operation); st != "partially_succeeded" {
			t.Fatalf("operation = %s", st)
		}
	})
}

func TestStaleStateAndOutcomeUnknown(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		p := newPRig(t, s, rigOpt{})
		p.dir.mode["a"], p.dir.mode["b"] = "stale", "unknown"
		sub, _ := p.r.SubmitDirectory(context.Background(), p.req(itemIn{GUID: "a", Want: "n"}, itemIn{GUID: "b", Want: "n"}))
		p.runChunks(sub.Operation)
		if p.stepRow(sub.Operation, 0) != "failed|stale_state|1|false" || p.stepRow(sub.Operation, 1) != "failed|outcome_unknown|1|false" {
			t.Fatalf("steps = %s / %s", p.stepRow(sub.Operation, 0), p.stepRow(sub.Operation, 1))
		}
		if p.opState(sub.Operation) != "failed" {
			t.Fatal(p.opState(sub.Operation))
		}
	})
}

func TestLostJobRedrivenBySweeper(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		p := newPRig(t, s, rigOpt{})
		p.r.cfg.StallWindow = time.Minute
		sub, _ := p.r.SubmitDirectory(context.Background(), p.req(itemIn{GUID: "a", Want: "n"}))
		p.exec(`DELETE FROM public.jobs`) // the job is lost
		p.exec(`UPDATE public.operations SET updated_at = now() - interval '1 hour'`)
		p.exec(`UPDATE public.operation_steps SET updated_at = now() - interval '1 hour'`)
		if err := p.r.Sweep(context.Background(), p.tn, p.r.txFor(p.tn)); err != nil {
			t.Fatal(err)
		}
		if n := p.owner(`SELECT count(*) FROM public.jobs WHERE kind = 'operation.apply'`)[0]; n != "1" {
			t.Fatalf("sweeper did not re-drive: %s jobs", n)
		}
		_ = sub
	})
}

func TestSweepSettlesFinishedOperationAndDropsExpiredSecrets(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		p := newPRig(t, s, rigOpt{secretIn: true})
		r := p.req(itemIn{GUID: "a", Want: "n"})
		r.Secrets = map[int]secret.Secret{0: secret.FromBytes([]byte("Sup3rSecret!"))}
		sub, err := p.r.SubmitDirectory(context.Background(), r)
		if err != nil {
			t.Fatal(err)
		}
		if n := p.owner(`SELECT count(*) FROM public.operation_secrets`)[0]; n != "1" {
			t.Fatalf("secrets = %s", n)
		}
		if blob := p.owner(`SELECT encode(sealed_secret, 'escape') FROM public.operation_secrets`)[0]; strings.Contains(blob, "Sup3rSecret") {
			t.Fatal("secret stored in the clear")
		}
		if in := p.owner(`SELECT COALESCE(encode(input, 'escape'), 'NULL') FROM public.operations`)[0]; in != "NULL" {
			t.Fatalf("a secret-input operation keeps its input: %s", in)
		}
		p.exec(`UPDATE public.operation_secrets SET expires_at = now() - interval '1 second'`)
		p.runChunks(sub.Operation)
		if got := p.stepRow(sub.Operation, 0); got != "failed|secret_expired|1|false" {
			t.Fatalf("expired secret: %s", got)
		}
		if p.dir.applies["a"] != 0 {
			t.Fatal("wrote with an expired secret")
		}
	})
}

func TestSecretUsedThenDeleted(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		p := newPRig(t, s, rigOpt{secretIn: true})
		r := p.req(itemIn{GUID: "a", Want: "n"}, itemIn{GUID: "b", Want: "n"})
		r.Secrets = map[int]secret.Secret{0: secret.FromBytes([]byte("pw-a")), 1: secret.FromBytes([]byte("pw-b"))}
		sub, err := p.r.SubmitDirectory(context.Background(), r)
		if err != nil {
			t.Fatal(err)
		}
		p.runChunks(sub.Operation)
		if p.opState(sub.Operation) != "succeeded" || p.dir.secret == "" {
			t.Fatalf("state %s secret %q", p.opState(sub.Operation), p.dir.secret)
		}
		if n := p.owner(`SELECT count(*) FROM public.operation_secrets`)[0]; n != "0" {
			t.Fatalf("secrets left after success: %s", n)
		}
		if err := p.d.ExecOwner(context.Background(), `SELECT 1`); err != nil {
			t.Fatal(err)
		}
	})
}

func TestSlotLimit(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		p := newPRig(t, s, rigOpt{slots: 1})
		sub, _ := p.r.SubmitDirectory(context.Background(), p.req(itemIn{GUID: "a", Want: "n"}, itemIn{GUID: "b", Want: "n"}))
		p.claimOnly(sub.Operation)
		err := p.r.txFor(p.tn)(context.Background(), func(ctx context.Context, tx store.Tx) error {
			_, err := p.r.claimNext(ctx, tx, p.tn, string(sub.Operation), 0, 0)
			return err
		})
		if !errors.Is(err, errBusy) {
			t.Fatalf("second claim on a full DC = %v", err)
		}
	})
}

func TestGateErrorLeavesOperationPlannedAndAlerts(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		p := newPRig(t, s, rigOpt{gate: holdGate{err: errors.New("gate down")}})
		sub, err := p.r.SubmitDirectory(context.Background(), p.req(itemIn{GUID: "a", Want: "n"}))
		if !errors.Is(err, ErrGate) {
			t.Fatalf("err = %v", err)
		}
		if p.opState(sub.Operation) != "planned" || len(p.alerts.reasons()) != 1 {
			t.Fatalf("state %s alerts %v", p.opState(sub.Operation), p.alerts.reasons())
		}
		if n := p.owner(`SELECT count(*) FROM public.jobs`)[0]; n != "0" {
			t.Fatal("an unapproved operation has jobs")
		}
	})
}

var bob = authority.Principal{ID: "bob", Kind: authority.Human}

func TestKernelHolds(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		t.Run("automation over max_objects is held", func(t *testing.T) {
			p := newPRig(t, s, rigOpt{})
			r := p.req(itemIn{GUID: "a", Want: "n"}, itemIn{GUID: "b", Want: "n"})
			r.Origin, r.MaxObjects = OriginAutomation, 1
			r.Actor = authority.Chain{Requester: authority.Principal{ID: "pol", Kind: authority.Automation}}
			sub, err := p.r.SubmitDirectory(context.Background(), r)
			if err != nil || sub.State != OpAwaitingApproval || sub.Hold != HoldBlastRadius {
				t.Fatalf("%+v %v", sub, err)
			}
		})
		t.Run("irreversible with the tenant setting is held", func(t *testing.T) {
			p := newPRig(t, s, rigOpt{irrev: true, class: Irreversible})
			sub, err := p.r.SubmitDirectory(context.Background(), p.req(itemIn{GUID: "a", Want: "n"}))
			if err != nil || sub.Hold != HoldIrreversible {
				t.Fatalf("%+v %v", sub, err)
			}
		})
		t.Run("a StepUp action started by a token is held; a human without step-up is refused", func(t *testing.T) {
			p := newPRig(t, s, rigOpt{stepUp: true})
			r := p.req(itemIn{GUID: "a", Want: "n"})
			r.Actor = authority.Chain{Requester: authority.Principal{ID: "tok", Kind: authority.APIToken}}
			sub, err := p.r.SubmitDirectory(context.Background(), r)
			if err != nil || sub.Hold != HoldStepUp {
				t.Fatalf("%+v %v", sub, err)
			}
			if _, err := p.r.SubmitDirectory(context.Background(), p.req(itemIn{GUID: "a", Want: "n"})); !errors.Is(err, ErrDenied) {
				t.Fatalf("human without step-up: %v", err)
			}
		})
		t.Run("undo of an operation that needed approval is held", func(t *testing.T) {
			p := newPRig(t, s, rigOpt{})
			r := p.req(itemIn{GUID: "a", Want: "n"})
			r.Origin, r.UndoNeededApproval = OriginUndo, true
			sub, err := p.r.SubmitDirectory(context.Background(), r)
			if err != nil || sub.Hold != HoldUndoNeededAppr {
				t.Fatalf("%+v %v", sub, err)
			}
		})
	})
}

func TestApprovals(t *testing.T) {
	human := Approval{Principal: bob, Interactive: true}
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		held := func(t *testing.T, o rigOpt) (*prig, Submission) {
			o.gate = holdGate{route: Route{Kind: RouteHold, Ref: "REQ-1"}}
			p := newPRig(t, s, o)
			r := p.req(itemIn{GUID: "a", Want: "n"})
			r.FreshStepUp = true
			sub, err := p.r.SubmitDirectory(context.Background(), r)
			if err != nil || sub.State != OpAwaitingApproval {
				t.Fatalf("%+v %v", sub, err)
			}
			return p, sub
		}
		ctx := context.Background()
		t.Run("a directory-admitted human approves; the operation is queued", func(t *testing.T) {
			p, sub := held(t, rigOpt{})
			got, err := p.r.Approve(ctx, p.tn, string(sub.Operation), sub.PlanHash, human)
			if err != nil || got.State != OpQueued {
				t.Fatalf("%+v %v", got, err)
			}
			if p.events("operation.approved") != 1 {
				t.Fatal("approval not recorded")
			}
		})
		t.Run("refusals", func(t *testing.T) {
			p, sub := held(t, rigOpt{stepUp: true})
			id := string(sub.Operation)
			for name, c := range map[string]struct {
				hash string
				ap   Approval
				want error
			}{
				"stale plan hash":   {"deadbeef", human, ErrStalePlanHash},
				"the initiator":     {sub.PlanHash, Approval{Principal: alice.Requester, Interactive: true, FreshStepUp: true}, ErrSelfApproval},
				"a token":           {sub.PlanHash, Approval{Principal: authority.Principal{ID: "t", Kind: authority.APIToken}, Interactive: true}, ErrNotHuman},
				"a non-interactive": {sub.PlanHash, Approval{Principal: bob}, ErrNotHuman},
				"no fresh step-up":  {sub.PlanHash, human, ErrStepUpRequired},
			} {
				if _, err := p.r.Approve(ctx, p.tn, id, c.hash, c.ap); !errors.Is(err, c.want) {
					t.Errorf("%s: %v, want %v", name, err, c.want)
				}
			}
			if p.opState(sub.Operation) != "awaiting_approval" {
				t.Fatal("a refusal moved the operation")
			}
		})
		for _, dir := range []string{"approver-created-requester", "requester-created-approver"} {
			t.Run("sock puppet "+dir, func(t *testing.T) {
				p, sub := held(t, rigOpt{})
				if dir == "approver-created-requester" {
					p.prov.tied[[2]authority.PrincipalID{"bob", "alice"}] = true
				} else {
					p.prov.tied[[2]authority.PrincipalID{"alice", "bob"}] = true
				}
				if _, err := p.r.Approve(ctx, p.tn, string(sub.Operation), sub.PlanHash, human); !errors.Is(err, ErrSockPuppet) {
					t.Fatalf("err = %v", err)
				}
				if got := p.alerts.reasons(); len(got) == 0 || got[len(got)-1] != "sock_puppet_approval" {
					t.Fatalf("alerts = %v", got)
				}
			})
		}
		t.Run("a provenance error fails closed", func(t *testing.T) {
			p, sub := held(t, rigOpt{})
			p.prov.err = errors.New("db down")
			if _, err := p.r.Approve(ctx, p.tn, string(sub.Operation), sub.PlanHash, human); !errors.Is(err, ErrSockPuppet) {
				t.Fatalf("err = %v", err)
			}
		})
		t.Run("an approver outside the scope is refused", func(t *testing.T) {
			p, sub := held(t, rigOpt{})
			p.r.cfg.Authz.(*authzFake).deny = map[authority.PrincipalID]bool{"bob": true}
			if _, err := p.r.Approve(ctx, p.tn, string(sub.Operation), sub.PlanHash, human); !errors.Is(err, ErrNotApprover) {
				t.Fatalf("err = %v", err)
			}
		})
		t.Run("a re-plan with the same hash keeps the approval", func(t *testing.T) {
			p, sub := held(t, rigOpt{})
			if _, err := p.r.Approve(ctx, p.tn, string(sub.Operation), sub.PlanHash, human); err != nil {
				t.Fatal(err)
			}
			p.exec(`UPDATE public.operations SET state = 'approved'`) // as if re-planned before the jobs ran
			again, err := p.r.Replan(ctx, p.tn, string(sub.Operation))
			if err != nil || again.PlanHash != sub.PlanHash || again.State != OpQueued {
				t.Fatalf("%+v %v", again, err)
			}
		})
		t.Run("a re-plan with a changed hash clears the approval", func(t *testing.T) {
			p, sub := held(t, rigOpt{})
			if _, err := p.r.Approve(ctx, p.tn, string(sub.Operation), sub.PlanHash, human); err != nil {
				t.Fatal(err)
			}
			p.exec(`UPDATE public.operations SET state = 'approved'`)
			p.dir.set("a", "drifted") // the before-state in the plan changes
			again, err := p.r.Replan(ctx, p.tn, string(sub.Operation))
			if err != nil || again.PlanHash == sub.PlanHash || again.State != OpAwaitingApproval {
				t.Fatalf("%+v %v", again, err)
			}
		})
	})
}

func TestCancelRunning(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		p := newPRig(t, s, rigOpt{})
		sub, _ := p.r.SubmitDirectory(context.Background(), p.req(itemIn{GUID: "a", Want: "n"}, itemIn{GUID: "b", Want: "n"}))
		p.claimOnly(sub.Operation) // item a is in flight
		if st, err := p.r.Cancel(context.Background(), p.tn, alice, string(sub.Operation)); err != nil || st != OpCancelling {
			t.Fatalf("%s %v", st, err)
		}
		if _, err := p.r.Cancel(context.Background(), p.tn, authority.Chain{Requester: bob}, string(sub.Operation)); !errors.Is(err, ErrDenied) {
			t.Fatalf("a stranger cancelled: %v", err)
		}
		p.runChunks(sub.Operation)
		if p.dir.get("b") != "" {
			t.Fatal("a cancelled operation kept claiming")
		}
	})
}

func TestDeferredVerifyIsDrivenLater(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		p := newPRig(t, s, rigOpt{})
		p.dir.mode["a"] = "defer"
		sub, _ := p.r.SubmitDirectory(context.Background(), p.req(itemIn{GUID: "a", Want: "n"}))
		p.runChunks(sub.Operation)
		if got := p.stepRow(sub.Operation, 0); !strings.HasPrefix(got, "applied|") || p.opState(sub.Operation) != "running" {
			t.Fatalf("step %s op %s", got, p.opState(sub.Operation))
		}
		p.dir.mode["verified"] = "yes"
		if err := p.r.Verify(context.Background(), p.tn, p.r.txFor(p.tn), string(sub.Operation)); err != nil {
			t.Fatal(err)
		}
		if p.stepRow(sub.Operation, 0) != "verified||1|false" || p.opState(sub.Operation) != "succeeded" {
			t.Fatalf("step %s op %s", p.stepRow(sub.Operation, 0), p.opState(sub.Operation))
		}
	})
}
