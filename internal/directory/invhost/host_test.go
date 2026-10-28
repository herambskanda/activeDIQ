package invhost_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/invhost"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

type fakeStore struct {
	rows map[string]string
	err  error
}

func (f *fakeStore) Find(_ context.Context, _ store.Tx, _ tenant.ID, fqdn string) (bool, error) {
	_, ok := f.rows[fqdn]
	return ok, f.err
}

func (f *fakeStore) Insert(_ context.Context, _ store.Tx, _ tenant.ID, fqdn, by string) (string, bool, error) {
	if f.err != nil {
		return "", false, f.err
	}
	if _, ok := f.rows[fqdn]; ok {
		return "", false, nil
	}
	f.rows[fqdn] = by
	return "row-1", true, nil
}

type fakeDCs struct {
	dcs   map[string]invhost.DC
	calls int
}

func (f *fakeDCs) ConfirmedDC(_ context.Context, _ tenant.ID, fqdn string) (invhost.DC, bool, error) {
	f.calls++
	dc, ok := f.dcs[fqdn]
	return dc, ok, nil
}

type fakeSink struct {
	events []audit.Event
	err    error
}

func (f *fakeSink) Append(_ context.Context, _ store.Tx, ev audit.Event) error {
	if f.err != nil {
		return f.err
	}
	f.events = append(f.events, ev)
	return nil
}

type rig struct {
	svc  *invhost.Service
	st   *fakeStore
	dcs  *fakeDCs
	sink *fakeSink
	tid  tenant.ID
	who  authority.Chain
}

func newRig() *rig {
	r := &rig{st: &fakeStore{rows: map[string]string{}}, dcs: &fakeDCs{dcs: map[string]invhost.DC{}}, sink: &fakeSink{}, tid: tenant.New(),
		who: authority.Chain{Requester: authority.Principal{ID: "acct-1", Kind: authority.Human}}}
	n := 0
	r.svc = &invhost.Service{
		Run: func(ctx context.Context, _ tenant.ID, fn func(context.Context, store.Tx) error) error {
			return fn(ctx, &storetest.FakeTx{})
		},
		Store: r.st, DCs: r.dcs, Audit: r.sink,
		Now:   func() time.Time { return time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC) },
		NewID: func() string { n++; return "ev-" + string(rune('0'+n)) },
	}
	return r
}

func TestNormalize(t *testing.T) {
	good := map[string]string{"Files.Corp.Example": "files.corp.example", "fs1.corp.example.": "fs1.corp.example", "a-b.c1.io": "a-b.c1.io"}
	for in, want := range good {
		if got, err := invhost.Normalize(in); err != nil || got != want {
			t.Errorf("Normalize(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := []string{"", "fs1", `\\files.attacker.example\h`, "files.attacker.example\\h", "10.0.0.1", "fs1.corp.example:445", "a b.example",
		"-a.example", "a-.example", "a..example", "fs1.corp.example..", "fs\x00.example", "fs1\n.example", "ünï.example", "fs1.corp.example/x",
		"user@fs1.corp.example", "dc01 & calc.example", "0x7f.0x1", "1.2.3.0x4", "1.2.3.4e", "a.b.1x", strings.Repeat("a", 64) + ".example", strings.Repeat("a.", 130) + "io"}
	for _, in := range bad {
		if _, err := invhost.Normalize(in); !errors.Is(err, invhost.ErrInvalidHostname) {
			t.Errorf("Normalize(%q) err = %v; want ErrInvalidHostname", in, err)
		}
	}
}

func TestZeroValue(t *testing.T) {
	var h invhost.InventoryHost
	if !h.IsZero() || h.FQDN() != "" {
		t.Fatal("zero value must be invalid")
	}
}

// Acceptance 1: not in inventory, or a homeDirectory UNC host -> NotInventory, audited, no DC dial for a UNC.
func TestResolveRefusesAndAudits(t *testing.T) {
	for _, cand := range []string{"attacker.example", "files.attacker.example", `\\files.attacker.example\h`, "10.1.2.3", "", "dnshostname-of-a-computer.corp.example"} {
		r := newRig()
		h, err := r.svc.Resolve(context.Background(), r.tid, r.who, cand)
		if !errors.Is(err, invhost.ErrNotInventoryHost) || !h.IsZero() {
			t.Fatalf("Resolve(%q) = %v, %v", cand, h, err)
		}
		if len(r.sink.events) != 1 {
			t.Fatalf("Resolve(%q): %d audit events", cand, len(r.sink.events))
		}
		ev := r.sink.events[0]
		if ev.Kind != invhost.KindRefused || ev.Outcome != audit.Denied || ev.Reason != invhost.ReasonNotInventory || ev.Validate() != nil {
			t.Fatalf("bad refusal event %+v (%v)", ev, ev.Validate())
		}
		for _, d := range ev.Details {
			if strings.Contains(d.Value, "attacker") {
				t.Fatalf("candidate text leaked into audit: %+v", d)
			}
		}
		if strings.HasPrefix(cand, `\\`) && r.dcs.calls != 0 {
			t.Fatal("UNC candidate reached discovery")
		}
	}
}

func TestRegisterThenResolve(t *testing.T) {
	r := newRig()
	h, err := r.svc.Register(context.Background(), r.tid, r.who, "FS1.Corp.Example.")
	if err != nil || h.FQDN() != "fs1.corp.example" || h.Origin() != invhost.OriginRegistered {
		t.Fatalf("Register = %v, %v", h, err)
	}
	if len(r.sink.events) != 1 || r.sink.events[0].Kind != invhost.KindRegistered || r.sink.events[0].Outcome != audit.Success || r.sink.events[0].Validate() != nil {
		t.Fatalf("registration not audited: %+v", r.sink.events)
	}
	// Idempotent: no second event.
	if _, err := r.svc.Register(context.Background(), r.tid, r.who, "fs1.corp.example"); err != nil || len(r.sink.events) != 1 {
		t.Fatalf("re-register: %v, %d events", err, len(r.sink.events))
	}
	got, err := r.svc.Resolve(context.Background(), r.tid, r.who, "fs1.CORP.example")
	if err != nil || got.FQDN() != "fs1.corp.example" {
		t.Fatalf("Resolve = %v, %v", got, err)
	}
	if len(r.sink.events) != 1 {
		t.Fatal("successful resolve must not add events")
	}
}

func TestRegisterRefusesInvalidName(t *testing.T) {
	r := newRig()
	_, err := r.svc.Register(context.Background(), r.tid, r.who, `\\evil.example\share`)
	if !errors.Is(err, invhost.ErrInvalidHostname) || len(r.st.rows) != 0 {
		t.Fatalf("err = %v rows = %v", err, r.st.rows)
	}
	if len(r.sink.events) != 1 || r.sink.events[0].Outcome != audit.Denied {
		t.Fatalf("refusal not audited: %+v", r.sink.events)
	}
}

func TestRegisterAuditFailureRollsBackViaError(t *testing.T) {
	r := newRig()
	r.sink.err = errors.New("audit down")
	if _, err := r.svc.Register(context.Background(), r.tid, r.who, "fs1.corp.example"); err == nil {
		t.Fatal("registration must fail when its audit event cannot be appended")
	}
}

func TestDiscoveredDC(t *testing.T) {
	r := newRig()
	r.dcs.dcs["dc01.corp.example"] = invhost.DC{FQDN: "dc01.corp.example", SRV: true, NTDSDSA: true}
	r.dcs.dcs["dc02.corp.example"] = invhost.DC{FQDN: "dc02.corp.example", SRV: true}                // not confirmed by nTDSDSA
	r.dcs.dcs["dc03.corp.example"] = invhost.DC{FQDN: "dc99.corp.example", SRV: true, NTDSDSA: true} // key/name mismatch
	h, err := r.svc.Resolve(context.Background(), r.tid, r.who, "DC01.corp.example")
	if err != nil || h.Origin() != invhost.OriginDiscoveredDC || h.FQDN() != "dc01.corp.example" {
		t.Fatalf("Resolve DC = %v, %v", h, err)
	}
	for _, c := range []string{"dc02.corp.example", "dc03.corp.example"} {
		if _, err := r.svc.Resolve(context.Background(), r.tid, r.who, c); !errors.Is(err, invhost.ErrNotInventoryHost) {
			t.Fatalf("Resolve(%s) = %v", c, err)
		}
	}
}

func TestStoreErrorIsNotARefusal(t *testing.T) {
	r := newRig()
	r.st.err = errors.New("db down")
	_, err := r.svc.Resolve(context.Background(), r.tid, r.who, "fs1.corp.example")
	if err == nil || errors.Is(err, invhost.ErrNotInventoryHost) || len(r.sink.events) != 0 {
		t.Fatalf("err = %v events = %d", err, len(r.sink.events))
	}
}

func TestNotConfiguredAndNoTenant(t *testing.T) {
	var s *invhost.Service
	if _, err := s.Resolve(context.Background(), tenant.New(), authority.Chain{}, "a.b"); !errors.Is(err, invhost.ErrNotConfigured) {
		t.Fatal(err)
	}
	r := newRig()
	if _, err := r.svc.Resolve(context.Background(), tenant.ID{}, r.who, "a.b"); !errors.Is(err, invhost.ErrNoTenant) {
		t.Fatal(err)
	}
	if _, err := r.svc.Resolve(context.Background(), r.tid, authority.Chain{}, "a.b"); err == nil {
		t.Fatal("empty actor must be refused")
	}
}

func FuzzNormalizeNeverAllowsSeparators(f *testing.F) {
	for _, s := range []string{`\\a.b\c`, "a.b:1", "a.b/c", "a b.c"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out, err := invhost.Normalize(s)
		if err != nil {
			return
		}
		if strings.ContainsAny(out, "\\/: @\x00\r\n\t\"'") || out != strings.ToLower(out) || strings.HasSuffix(out, ".") {
			t.Fatalf("Normalize(%q) = %q", s, out)
		}
		if again, err := invhost.Normalize(out); err != nil || again != out {
			t.Fatalf("not idempotent: %q -> %q -> %q, %v", s, out, again, err)
		}
	})
}

func TestRegisterRefusesNonHuman(t *testing.T) {
	via := []authority.Principal{{ID: "svc", Kind: authority.System}}
	cases := map[string]authority.Chain{
		"automation": {Requester: authority.Principal{ID: "a", Kind: authority.Automation}},
		"system":     {Requester: authority.Principal{ID: "s", Kind: authority.System}},
		"api_token":  {Requester: authority.Principal{ID: "t", Kind: authority.APIToken}},
		"human_via":  {Requester: authority.Principal{ID: "h", Kind: authority.Human}, Via: via},
	}
	for name, who := range cases {
		r := newRig()
		_, err := r.svc.Register(context.Background(), r.tid, who, "files.attacker.example")
		if !errors.Is(err, invhost.ErrNotHuman) || len(r.st.rows) != 0 {
			t.Errorf("%s: err = %v rows = %v", name, err, r.st.rows)
		}
		if len(r.sink.events) != 1 || r.sink.events[0].Outcome != audit.Denied || r.sink.events[0].Reason != invhost.ReasonNotHuman {
			t.Errorf("%s: refusal not audited: %+v", name, r.sink.events)
		}
	}
}
