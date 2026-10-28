package addc

import (
	"context"
	"encoding/binary"
	"log/slog"
	"os"
	"slices"
	"strings"
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

// scripted is a log of (record id, event id) pairs. Like the real subscription it honours the event
// id filter, so ids outside the filter leave holes in the record ids it delivers.
type scripted struct {
	recs   [][2]uint64 // {record id, event id}
	ids    []uint64    // shorthand: record ids with event id 4624
	err    error
	oldest uint64
	bad    map[uint64]bool // record ids delivered as unparsable
	mu     sync.Mutex
	asked  []uint32
}

func (s *scripted) OldestRecord(agentpolicy.Channel) (uint64, error) { return s.oldest, nil }

func (s *scripted) Subscribe(ctx context.Context, _ agentpolicy.Channel, after uint64, filter []uint32, emit func(RawEvent)) error {
	s.mu.Lock()
	s.asked = filter
	s.mu.Unlock()
	recs := s.recs
	for _, id := range s.ids {
		recs = append(recs, [2]uint64{id, 4624})
	}
	for _, r := range recs {
		if r[0] <= after {
			continue
		}
		if s.bad[r[0]] {
			emit(RawEvent{Unparsable: true, RecordID: r[0]})
			continue
		}
		if len(filter) > 0 && !slices.Contains(filter, uint32(r[1])) {
			continue
		}
		emit(RawEvent{RecordID: r[0], EventID: uint32(r[1])})
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

func gapReasons(s *memSink) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, e := range s.ev {
		if e.Kind == agentv1.EventKind_EVENT_KIND_GAP {
			out = append(out, e.Fields[0].Value+":"+e.Fields[1].Value+"-"+e.Fields[2].Value)
		}
	}
	return out
}

// An interleaved log with ids outside the filter must produce no GAP records.
func TestFilteredInterleavedLogHasNoGaps(t *testing.T) {
	sink := &memSink{}
	src := &scripted{recs: [][2]uint64{{1, 4624}, {2, 4672}, {3, 5156}, {4, 4624}, {5, 4672}, {6, 4624}}}
	c := run1(t, src, deps(t, sink, time.Now), rulesEv(1000))
	waitFor(t, func() bool { return c.Snapshot()[0].EventsCollected == 3 })
	c.Stop()
	if g := gapReasons(sink); len(g) != 0 {
		t.Fatalf("unexpected gaps %v", g)
	}
	if !slices.Contains(src.asked, 1102) {
		t.Fatalf("1102 not always subscribed: %v", src.asked)
	}
}

func TestClearedLogIsReportedAsItself(t *testing.T) {
	sink := &memSink{}
	src := &scripted{recs: [][2]uint64{{1, 4624}, {2, 1102}}}
	c := run1(t, src, deps(t, sink, time.Now), rulesEv(1000))
	waitFor(t, func() bool { return c.Snapshot()[0].EventsCollected == 2 })
	c.Stop()
	if g := gapReasons(sink); len(g) != 0 {
		t.Fatalf("gaps %v", g)
	}
	if sink.ev[1].Fields[0].Value != "1102" {
		t.Fatalf("%v", sink.ev[1].Fields)
	}
}

func TestOldestPastBookmarkGivesOneGap(t *testing.T) {
	sink := &memSink{}
	d := deps(t, sink, time.Now)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], 10)
	if err := d.Blobs.Save(blobName(agentpolicy.ChannelSecurity), b[:]); err != nil {
		t.Fatal(err)
	}
	src := &scripted{ids: []uint64{50, 51}, oldest: 40}
	c := run1(t, src, d, rulesEv(1000))
	waitFor(t, func() bool { return c.Snapshot()[0].EventsCollected == 2 })
	c.Stop()
	g := gapReasons(sink)
	if len(g) != 1 || g[0] != "log_wrapped:11-39" {
		t.Fatalf("gaps %v", g)
	}
}

func TestUnparsableEventIsReportedNotDropped(t *testing.T) {
	sink := &memSink{}
	src := &scripted{ids: []uint64{1, 2, 3}, bad: map[uint64]bool{2: true}}
	c := run1(t, src, deps(t, sink, time.Now), rulesEv(1000))
	waitFor(t, func() bool { return len(sink.kinds()) == 3 })
	c.Stop()
	if g := gapReasons(sink); len(g) != 1 || g[0] != "unparsable:2-2" {
		t.Fatalf("gaps %v", g)
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

func TestParseEventXMLSanitisesIllegalCharacters(t *testing.T) {
	for _, v := range []string{"a\x01b", "a&#x1;b", "a&#1;b", "a&#xFFFE;b", "a&#99999999999;b"} {
		x := "<Event><System><EventID>5136</EventID><EventRecordID>9</EventRecordID></System><EventData><Data Name=\"V\">" + v + "</Data></EventData></Event>"
		e, err := ParseEventXML([]byte(x))
		if err != nil || e.RecordID != 9 || len(e.Fields) != 1 || e.Fields[0].Value != "a\uFFFDb" {
			t.Fatalf("%q: %+v %v", v, e, err)
		}
	}
	// legal references survive
	e, err := ParseEventXML([]byte("<Event><System><EventID>1</EventID><EventRecordID>2</EventRecordID></System><EventData><Data Name=\"V\">a&#x41;&amp;b</Data></EventData></Event>"))
	if err != nil || e.Fields[0].Value != "aA&b" {
		t.Fatalf("%+v %v", e, err)
	}
}

func TestDecodeEventKeepsRecordIDOfUnparsable(t *testing.T) {
	big := "<Event><System><EventID>5136</EventID><EventRecordID>1234</EventRecordID></System><EventData><Data Name=\"V\">" + strings.Repeat("x", maxXMLBytes) + "</Data></EventData></Event>"
	for _, x := range []string{big, "<Event><System><EventRecordID>77</EventRecordID><EventID>1</EventID></System><Oops></Event>"} {
		e := DecodeEvent([]byte(x))
		if !e.Unparsable || e.RecordID == 0 {
			t.Fatalf("%+v", e)
		}
	}
}
