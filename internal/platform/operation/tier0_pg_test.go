package operation

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

// lateFacts is Tier-0 only after the step wrote: the plan-time and apply-time reads see nothing.
type lateFacts struct {
	d   *dirFake
	err bool // reads fail after the write
}

func (f lateFacts) Facts(_ context.Context, _ authority.Pins, q authority.FactsQuery) (authority.Facts, error) {
	f.d.mu.Lock()
	wrote := f.d.applies[q.Target.GUID] > 0
	f.d.mu.Unlock()
	if wrote && f.err {
		return authority.Facts{}, errors.New("pin down")
	}
	return authority.Facts{Exists: true, Tier0: wrote}, nil
}

func (p *prig) tier0Run(mode string) runOut {
	p.dir.mode["a"] = mode
	sub, _ := p.r.SubmitDirectory(context.Background(), p.req(itemIn{GUID: "a", Want: "n"}, itemIn{GUID: "b", Want: "n"}))
	p.runChunks(sub.Operation)
	return runOut{p.stepRow(sub.Operation, 0), p.opState(sub.Operation), p.dir.get("b"), sub.Operation}
}

type runOut struct {
	row, op, b string
	id         any
}

// T-0523 acceptance 1 and 3: the connector's step-9 report outranks the read-back and a Verify error,
// with or without a basis, and the alert carries objects, bases, source, DC, step and chain.
func TestConnectorReportProducesTier0AfterWrite(t *testing.T) {
	for _, tc := range []struct{ mode, want string }{
		{"report", "x-guid:C2"}, {"report_verr", "x-guid:C2"}, {"report_unclassified", "x-guid:"},
	} {
		storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
			p := newPRig(t, s, rigOpt{})
			r := p.tier0Run(tc.mode)
			if r.row != "verify_failed|tier0_after_write|1|false" {
				t.Fatalf("%s: step = %s", tc.mode, r.row)
			}
			if r.b != "" || r.op != "cancelled" {
				t.Fatalf("%s: later item ran (%q) or operation = %s", tc.mode, r.b, r.op)
			}
			if len(p.alerts.got) != 1 {
				t.Fatalf("alerts = %+v", p.alerts.got)
			}
			a := p.alerts.got[0]
			if a.Severity != "critical" || a.Source != Tier0SourceConnector || a.DC != "dc1.example.test" ||
				a.Step.Item != 0 || a.Initiator.Requester.ID == "" || len(a.Objects) != 1 ||
				a.Objects[0].Object+":"+strings.Join(a.Objects[0].Bases, ",") != tc.want {
				t.Fatalf("%s: alert = %+v", tc.mode, a)
			}
		})
	}
}

// The server's own re-read finds a touched object tier0 with a clean connector report.
func TestServerRereadProducesTier0AfterWrite(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		p := newPRig(t, s, rigOpt{})
		p.r.cfg.Facts = lateFacts{d: p.dir}
		r := p.tier0Run("")
		if r.row != "verify_failed|tier0_after_write|1|false" || r.op != "cancelled" || r.b != "" {
			t.Fatalf("step %s op %s b %q", r.row, r.op, r.b)
		}
		if a := p.alerts.got; len(a) != 1 || a[0].Source != Tier0SourceServer || a[0].Objects[0].Object != "a" || len(a[0].Objects[0].Bases) != 0 {
			t.Fatalf("alerts = %+v", a)
		}
	})
}

// A fact still unknown on every DC after the write counts as tier0; a Verify error does not hide it.
func TestServerRereadUnknownCountsAsTier0(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		p := newPRig(t, s, rigOpt{attempts: 2})
		p.r.cfg.Facts = lateFacts{d: p.dir, err: true}
		r := p.tier0Run("verr")
		if r.row != "verify_failed|tier0_after_write|1|false" {
			t.Fatalf("step = %s", r.row)
		}
		if a := p.alerts.got; len(a) != 1 || a[0].Source != Tier0SourceServer {
			t.Fatalf("alerts = %+v", a)
		}
	})
}

// A clean report and clean re-read leaves the other reasons alone.
func TestNoTier0KeepsOtherReasons(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		p := newPRig(t, s, rigOpt{})
		p.dir.mode["a"] = "verr"
		sub, _ := p.r.SubmitDirectory(context.Background(), p.req(itemIn{GUID: "a", Want: "n"}))
		p.runChunks(sub.Operation)
		if got := p.stepRow(sub.Operation, 0); got != "verify_failed|verify_error|1|false" || !slices.Equal(p.alerts.reasons(), nil) {
			t.Fatalf("step = %s alerts %v", got, p.alerts.reasons())
		}
	})
}

// hostFacts is Tier-0 after the write for the listed objects, per DC: a host in down fails every read,
// a host in tier0 reports the object tier0 once the step wrote.
type hostFacts struct {
	d     *dirFake
	t0    map[string]bool // guid -> tier0 after the write, on any DC that answers
	down  map[string]bool // host -> reads fail after the write
	hosts []string        // every host a post-write read was made on
}

func (f *hostFacts) Facts(_ context.Context, pins authority.Pins, q authority.FactsQuery) (authority.Facts, error) {
	f.d.mu.Lock()
	wrote := false
	for _, n := range f.d.applies {
		wrote = wrote || n > 0
	}
	f.d.mu.Unlock()
	if !wrote {
		return authority.Facts{Exists: true}, nil
	}
	h := pins[q.Target.NC]
	f.hosts = append(f.hosts, h)
	if f.down[h] {
		return authority.Facts{}, errors.New("dc down")
	}
	return authority.Facts{Exists: true, Tier0: f.t0[q.Target.GUID]}, nil
}

// afterWritePinner hands out the first DC until the step wrote, then another one.
type afterWritePinner struct {
	d    *dirFake
	fail bool // the pinner errors once the step wrote
}

func (p afterWritePinner) Pin(context.Context, string, authority.NamingContextID, string) (DCPin, error) {
	p.d.mu.Lock()
	defer p.d.mu.Unlock()
	for _, n := range p.d.applies {
		if n > 0 {
			if p.fail {
				return DCPin{}, errors.New("no other DC")
			}
			return DCPin{Host: "dc2.example.test", DSAGUID: "66666666-2222-3333-4444-555555555555"}, nil
		}
	}
	return DCPin{Host: "dc1.example.test", DSAGUID: "11111111-2222-3333-4444-555555555555"}, nil
}

// ADR-0005 rule 7: the re-read covers every touched object, not only the target (the O8 shape: X is
// the member added, the target group is clean).
func TestServerRereadCoversTouchedObject(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		p := newPRig(t, s, rigOpt{})
		p.dir.touch["a"] = "x-guid"
		p.r.cfg.Facts = &hostFacts{d: p.dir, t0: map[string]bool{"x-guid": true}}
		r := p.tier0Run("")
		if r.row != "verify_failed|tier0_after_write|1|false" || r.op != "cancelled" || r.b != "" {
			t.Fatalf("step %s op %s b %q", r.row, r.op, r.b)
		}
		a := p.alerts.got
		if len(a) != 1 || a[0].Source != Tier0SourceServer || len(a[0].Objects) != 1 || a[0].Objects[0].Object != "x-guid" {
			t.Fatalf("alerts = %+v", a)
		}
	})
}

// Fallback DC: a pin outage alone is not a finding; a tier0 answer from the fallback is, naming that DC.
func TestServerRereadFallbackDC(t *testing.T) {
	for _, tc := range []struct {
		name   string
		tier0  bool
		pinner func(*dirFake) Pinner
		finds  bool
		dc     string
	}{
		{"fallback clean", false, func(d *dirFake) Pinner { return afterWritePinner{d: d} }, false, ""},
		{"fallback tier0", true, func(d *dirFake) Pinner { return afterWritePinner{d: d} }, true, "dc2.example.test"},
		{"no other DC", false, func(d *dirFake) Pinner { return afterWritePinner{d: d, fail: true} }, true, "dc1.example.test"},
		{"fallback fails too", false, func(*dirFake) Pinner { return pinFake{} }, true, "dc1.example.test"},
	} {
		storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
			p := newPRig(t, s, rigOpt{attempts: 2})
			hf := &hostFacts{d: p.dir, t0: map[string]bool{"a": tc.tier0}, down: map[string]bool{"dc1.example.test": true}}
			if tc.name == "fallback fails too" {
				hf.down["dc2.example.test"] = true
			}
			p.r.cfg.Facts = hf
			p.r.cfg.Pinner = tc.pinner(p.dir)
			r := p.tier0Run("")
			a := p.alerts.got
			if !tc.finds {
				if r.row != "verified||1|false" || len(a) != 0 {
					t.Fatalf("%s: step %s alerts %+v", tc.name, r.row, a)
				}
				return
			}
			if r.row != "verify_failed|tier0_after_write|1|false" || len(a) != 1 || a[0].DC != tc.dc || a[0].Source != Tier0SourceServer {
				t.Fatalf("%s: step %s alerts %+v", tc.name, r.row, a)
			}
		})
	}
}
