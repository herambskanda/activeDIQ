package agent

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

type rec struct {
	level slog.Level
	id    uint32
	msg   string
}

type fakeReporter struct {
	mu  sync.Mutex
	got []rec
}

func (f *fakeReporter) Report(l slog.Level, id uint32, msg string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.got = append(f.got, rec{l, id, msg})
}

func (f *fakeReporter) all() []rec {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]rec(nil), f.got...)
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newLog(t *testing.T) (*slog.Logger, *fakeReporter, *clock, *bytes.Buffer) {
	t.Helper()
	rep := &fakeReporter{}
	clk := &clock{t: time.Unix(1_000_000, 0)}
	var stderr bytes.Buffer
	h := NewServiceLog(slog.NewJSONHandler(&stderr, &slog.HandlerOptions{Level: slog.LevelInfo}), rep)
	h.Now = clk.now
	return slog.New(h), rep, clk, &stderr
}

// T-1277 AC1: a dial failure writes one event naming its class, rate limited per class.
func TestTunnelFailureClassIsReportedOncePerInterval(t *testing.T) {
	log, rep, clk, _ := newLog(t)
	for i := 0; i < 50; i++ { // a retry loop hammering the same failure
		log.Warn("tunnel ended", "err_kind", "unreachable")
		clk.t = clk.t.Add(time.Second)
	}
	got := rep.all()
	if len(got) != 1 || got[0].id != EventTunnelUnreachable || got[0].msg != "tunnel ended: unreachable" || got[0].level != slog.LevelWarn {
		t.Fatalf("got %+v, want one event 110", got)
	}
	// Another class is not suppressed by the first.
	log.Warn("tunnel ended", "err_kind", "tls_trust")
	if got = rep.all(); len(got) != 2 || got[1].id != EventTunnelTLSTrust {
		t.Fatalf("got %+v", got)
	}
	// After the interval the class reports again and says what it swallowed.
	clk.t = clk.t.Add(DefaultEventInterval)
	log.Warn("tunnel ended", "err_kind", "unreachable")
	got = rep.all()
	if len(got) != 3 || !strings.Contains(got[2].msg, "(49 more since the last report)") {
		t.Fatalf("got %+v", got)
	}
}

func TestEveryTunnelClassHasADocumentedID(t *testing.T) {
	want := map[string]uint32{"unreachable": 110, "resolve": 111, "tls_trust": 112, "tls_handshake": 113,
		"rejected": 114, "protocol": 115, "transport": 116}
	for k, id := range want {
		if tunnelClasses[k] != id {
			t.Errorf("class %s = %d, want %d", k, tunnelClasses[k], id)
		}
	}
	if len(tunnelClasses) != len(want) {
		t.Errorf("undocumented class in tunnelClasses: %v", tunnelClasses)
	}
}

// Nothing but the constant message and the class token reaches the event log: not attributes, not
// error text, not an unrecognised class token.
func TestEventsCarryNoAttributeData(t *testing.T) {
	log, rep, _, stderr := newLog(t)
	const secret = "SECRET-TOKEN-0123 -----BEGIN PRIVATE KEY-----"
	log.Warn("tunnel ended", "err_kind", "unreachable", "err", secret, "token", secret)
	log.With("token", secret).Error("policy not persisted; not activated", "err", secret)
	log.Warn("tunnel ended", "err_kind", secret) // a hostile or buggy token
	log.WithGroup("g").Warn("outbox read failed", "err", secret)
	for _, r := range rep.all() {
		if strings.Contains(r.msg, "SECRET") || strings.Contains(r.msg, "PRIVATE") {
			t.Fatalf("event %d leaked: %q", r.id, r.msg)
		}
	}
	if len(rep.all()) != 4 {
		t.Fatalf("got %+v", rep.all())
	}
	if rep.all()[2].id != EventTunnelTransport {
		t.Fatalf("unknown token not mapped to transport: %+v", rep.all()[2])
	}
	if !strings.Contains(stderr.String(), "SECRET") {
		t.Log("note: stderr (foreground) carries attributes by design; only the event log is restricted")
	}
}

func TestOnlyFailuresAreReported(t *testing.T) {
	log, rep, _, stderr := newLog(t)
	log.Info("applied", "what", "policy", "seq", 3)
	log.Warn("tunnel ended", "err_kind", "closed") // a clean end is not a failure
	log.Debug("noise")
	if n := len(rep.all()); n != 0 {
		t.Fatalf("reported %+v", rep.all())
	}
	if !strings.Contains(stderr.String(), `"msg":"applied"`) {
		t.Fatal("stderr lost the info record")
	}
	log.Error("installed policy could not be activated", "err", "x")
	if got := rep.all(); len(got) != 1 || got[0].id != EventAgentError || got[0].level != slog.LevelError {
		t.Fatalf("got %+v", got)
	}
}

// The set of tracked generic messages and the message length are bounded.
func TestGenericClassesAndMessagesAreBounded(t *testing.T) {
	log, rep, _, _ := newLog(t)
	for i := 0; i < 500; i++ {
		log.Warn("m" + strings.Repeat("x", i))
	}
	if n := len(rep.all()); n != maxOtherKeys+1 {
		t.Fatalf("%d events for 500 distinct messages, want %d", n, maxOtherKeys+1)
	}
	log, rep, _, _ = newLog(t)
	log.Error(strings.Repeat("é", 1000))
	m := rep.all()[0].msg
	if len(m) > maxEventMessage+3 || !strings.HasSuffix(m, "...") || strings.ContainsRune(m, '�') {
		t.Fatalf("message not cut cleanly: %d bytes", len(m))
	}
}

func TestNilReporterIsPassThrough(t *testing.T) {
	var stderr bytes.Buffer
	log := slog.New(NewServiceLog(slog.NewJSONHandler(&stderr, nil), nil))
	log.Warn("tunnel ended", "err_kind", "unreachable")
	if !strings.Contains(stderr.String(), "tunnel ended") {
		t.Fatal("record lost")
	}
}

// A backwards clock step must not wedge a class silent for hours.
func TestClockStepBackReportsAgain(t *testing.T) {
	log, rep, clk, _ := newLog(t)
	log.Warn("tunnel ended", "err_kind", "resolve")
	clk.t = clk.t.Add(-time.Hour)
	log.Warn("tunnel ended", "err_kind", "resolve")
	if len(rep.all()) != 2 {
		t.Fatalf("got %+v", rep.all())
	}
}

func TestConcurrentUse(t *testing.T) {
	log, _, _, _ := newLog(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				log.Warn("tunnel ended", "err_kind", "unreachable")
				_ = log.Handler().Enabled(context.Background(), slog.LevelWarn)
			}
		}()
	}
	wg.Wait()
}
