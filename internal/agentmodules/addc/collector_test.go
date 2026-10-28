package addc

import (
	"context"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/agent"
	"github.com/skenzeriq/activediq/internal/platform/agentpolicy"
	addcv1 "github.com/skenzeriq/activediq/internal/proto/activediq/addc/v1"
	agentv1 "github.com/skenzeriq/activediq/internal/proto/skenzeriq/agent/v1"
)

type memSink struct {
	mu sync.Mutex
	ev []*agentv1.AgentEvent
}

func (m *memSink) Append(e *agentv1.AgentEvent) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ev = append(m.ev, e)
	return uint64(len(m.ev)), nil
}
func (m *memSink) Flush() error { return nil }
func (m *memSink) kinds() []agentv1.EventKind {
	m.mu.Lock()
	defer m.mu.Unlock()
	var k []agentv1.EventKind
	for _, e := range m.ev {
		k = append(k, e.Kind)
	}
	return k
}

type scripted struct {
	ids []uint64
	err error
}

func (s *scripted) Subscribe(ctx context.Context, _ agentpolicy.Channel, after uint64, _ []uint32, emit func(RawEvent)) error {
	for _, id := range s.ids {
		if id > after {
			emit(RawEvent{RecordID: id, EventID: 4624})
		}
	}
	if s.err != nil {
		return s.err
	}
	<-ctx.Done()
	return ctx.Err()
}

func deps(t *testing.T, sink *memSink, now func() time.Time) agent.ModuleDeps {
	b, err := agent.NewBlobs(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return agent.ModuleDeps{Events: sink, Blobs: b, Log: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})), Now: now}
}

func rulesEv(rate uint32) agentpolicy.EventRules {
	return agentpolicy.EventRules{CollectionEnabled: true, Channels: []agentpolicy.Channel{agentpolicy.ChannelSecurity},
		EventIDs: []uint32{4624}, MaxEventsPerSecond: rate, BatchMaxBytes: 1024, OutboxMaxBytes: 4096}
}

func run1(t *testing.T, src Source, d agent.ModuleDeps, ev agentpolicy.EventRules) *Collector {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	c := NewCollector(src, d, "dc")
	c.setRoot(ctx)
	c.Apply(ev)
	return c
}

func waitFor(t *testing.T, f func() bool) {
	t.Helper()
	for i := 0; i < 400; i++ {
		if f() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not reached")
}

func TestCollectorRecordIDJumpEmitsGap(t *testing.T) {
	sink := &memSink{}
	c := run1(t, &scripted{ids: []uint64{1, 2, 7}}, deps(t, sink, time.Now), rulesEv(1000))
	waitFor(t, func() bool { return len(sink.kinds()) == 4 })
	k := sink.kinds()
	if k[2] != agentv1.EventKind_EVENT_KIND_GAP {
		t.Fatalf("kinds %v", k)
	}
	if g := sink.ev[2]; g.Fields[1].Value != "3" || g.Fields[2].Value != "6" {
		t.Fatalf("gap range %v", g.Fields)
	}
	c.Stop()
	if s := c.Snapshot()[0]; s.GapsSeen != 1 || s.EventsCollected != 3 {
		t.Fatalf("state %+v", s)
	}
}

func TestCollectorThrottleDropsAreVisibleAsGap(t *testing.T) {
	sink := &memSink{}
	fixed := time.Unix(1000, 0)
	c := run1(t, &scripted{ids: []uint64{1, 2, 3, 4, 5}}, deps(t, sink, func() time.Time { return fixed }), rulesEv(2))
	waitFor(t, func() bool { return c.Snapshot()[0].EventsThrottled == 3 })
	c.Stop() // closes the open throttled run
	var gap *agentv1.AgentEvent
	for _, e := range sink.ev {
		if e.Kind == agentv1.EventKind_EVENT_KIND_GAP {
			gap = e
		}
	}
	if gap == nil || gap.Fields[0].Value != "throttled" || gap.Fields[1].Value != "3" || gap.Fields[2].Value != "5" {
		t.Fatalf("gap %v", gap)
	}
}

func TestCollectorResumesFromBookmark(t *testing.T) {
	sink := &memSink{}
	d := deps(t, sink, func() time.Time { return time.Now() })
	c := run1(t, &scripted{ids: []uint64{1, 2, 3}}, d, rulesEv(1000))
	waitFor(t, func() bool { return c.Snapshot()[0].EventsCollected == 3 })
	c.Stop()
	if loadBookmark(d.Blobs, agentpolicy.ChannelSecurity) == 0 {
		// persist is rate-limited to once a second; the first event always persists.
		t.Fatal("no bookmark saved")
	}
}

func TestCollectorUnreadableIsReportedNotFatal(t *testing.T) {
	sink := &memSink{}
	m := New(&scripted{err: ErrUnreadable}, "dc")
	if err := m.Start(context.Background(), deps(t, sink, time.Now)); err != nil {
		t.Fatal(err)
	}
	defer m.Stop(context.Background())
	if err := m.Activate(agentpolicy.AddcPolicy{Events: rulesEv(10), Password: agentpolicy.PasswordRules{MinLength: 8, MaxLength: 64}}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return m.Collection() == agentv1.CollectionState_COLLECTION_STATE_CHANNEL_UNREADABLE })
	r, _ := m.GetCollectionState(context.Background(), &addcv1.GetCollectionStateRequest{})
	if r.Channels[0].Status != addcv1.ChannelStatus_CHANNEL_STATUS_UNREADABLE {
		t.Fatalf("%+v", r.Channels)
	}
}

func TestDisabledPolicyStopsAndReports(t *testing.T) {
	m := New(&scripted{}, "dc")
	_ = m.Start(context.Background(), deps(t, &memSink{}, time.Now))
	defer m.Stop(context.Background())
	if m.Collection() != agentv1.CollectionState_COLLECTION_STATE_NO_POLICY {
		t.Fatal("expected no policy")
	}
	ev := rulesEv(10)
	ev.CollectionEnabled = false
	_ = m.Activate(agentpolicy.AddcPolicy{Events: ev})
	if m.Collection() != agentv1.CollectionState_COLLECTION_STATE_STOPPED_BY_POLICY {
		t.Fatal("expected stopped_by_policy")
	}
}

func TestCatalogueRefusesUnknownID(t *testing.T) {
	ev := rulesEv(10)
	ev.EventIDs = []uint32{4624, 9999}
	if err := New(nil, "").Validate(agentpolicy.AddcPolicy{Events: ev}); err == nil {
		t.Fatal("unknown id accepted")
	}
}

func TestParseEventXML(t *testing.T) {
	x := `<Event><System><EventID>4625</EventID><TimeCreated SystemTime="2026-10-01T12:00:00.5Z"/><EventRecordID>77</EventRecordID></System>
<EventData><Data Name="TargetUserName">jsmith</Data><Data Name="Empty"></Data></EventData></Event>`
	e, err := ParseEventXML([]byte(x))
	if err != nil || e.EventID != 4625 || e.RecordID != 77 || len(e.Fields) != 1 || e.Fields[0].Value != "jsmith" {
		t.Fatalf("%+v %v", e, err)
	}
	for _, bad := range []string{"", "<Event>", "<Event><System></System></Event>", "<!DOCTYPE x [<!ENTITY a 'b'>]><Event/>"} {
		if _, err := ParseEventXML([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if got := truncate("ééé", 3); got != "é" {
		t.Fatalf("truncate split a rune: %q", got)
	}
}
