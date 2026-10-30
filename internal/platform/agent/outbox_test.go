package agent

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	agentv1 "github.com/skenzeriq/activediq/internal/proto/skenzeriq/agent/v1"
)

func ev(n int) *agentv1.AgentEvent {
	return &agentv1.AgentEvent{
		Kind: agentv1.EventKind_EVENT_KIND_EVENT, Channel: "security", EventRecordId: uint64(n),
		ObservedAtUnixNanos: 1,
		Fields:              []*agentv1.EventField{{Name: "n", Value: strconv.Itoa(n)}},
	}
}

func open(t *testing.T, dir string, max, seg int64) *Outbox {
	t.Helper()
	o, err := OpenOutbox(dir, max, seg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { o.Close() })
	return o
}

func TestAppendNextAckGapless(t *testing.T) {
	o := open(t, t.TempDir(), 1<<20, 256<<10)
	for i := 1; i <= 50; i++ {
		seq, err := o.Append(ev(i))
		if err != nil || seq != uint64(i) {
			t.Fatalf("append %d = %d, %v", i, seq, err)
		}
	}
	got, err := o.Next(1000, 1<<20)
	if err != nil || len(got) != 50 {
		t.Fatalf("next = %d, %v", len(got), err)
	}
	for i, e := range got {
		if e.AgentSeq != uint64(i+1) {
			t.Fatalf("gap at %d: %d", i, e.AgentSeq)
		}
	}
	o.Ack(20)
	got, _ = o.Next(1000, 1<<20)
	if len(got) != 30 || got[0].AgentSeq != 21 {
		t.Fatalf("after ack: %d first %d", len(got), got[0].AgentSeq)
	}
	if st := o.Stats(); st.Records != 30 || st.LastSeq != 50 || st.AckedThrough != 20 {
		t.Fatalf("stats %+v", st)
	}
	o.Ack(9999) // beyond anything assigned
	if st := o.Stats(); st.AckedThrough != 50 || st.Records != 0 {
		t.Fatalf("ack clamp: %+v", st)
	}
}

func TestNextBounds(t *testing.T) {
	o := open(t, t.TempDir(), 1<<20, 256<<10)
	for i := 1; i <= 10; i++ {
		o.Append(ev(i))
	}
	if got, _ := o.Next(3, 1<<20); len(got) != 3 {
		t.Fatalf("record bound: %d", len(got))
	}
	if got, _ := o.Next(100, 1); len(got) != 1 {
		t.Fatalf("a single oversize-for-budget record must still be returned: %d", len(got))
	}
}

func TestRestartKeepsRecordsAndSequence(t *testing.T) {
	dir := t.TempDir()
	o, _ := OpenOutbox(dir, 1<<20, 256<<10)
	for i := 1; i <= 5; i++ {
		o.Append(ev(i))
	}
	o.Ack(5)
	o.Close()
	o2 := open(t, dir, 1<<20, 256<<10)
	seq, _ := o2.Append(ev(6))
	if seq != 6 {
		t.Fatalf("sequence reused after restart: %d", seq)
	}
	// The ack floor is memory only, so the active segment is redelivered: at-least-once, and the
	// server counts the repeats as duplicates (agentingest). Nothing may be missing.
	got, _ := o2.Next(10, 1<<20)
	if len(got) == 0 || got[len(got)-1].AgentSeq != 6 {
		t.Fatalf("newest record missing after restart: %v", got)
	}
}

func TestBoundDropsOldestAndSaysSo(t *testing.T) {
	// Fault: the disk budget is far smaller than the load. The subscription is never blocked.
	o := open(t, t.TempDir(), 4*4096, 4096)
	big := ev(1)
	big.Fields[0].Value = string(make([]byte, 1500))
	var last uint64
	for i := 0; i < 200; i++ {
		seq, err := o.Append(big)
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		last = seq
	}
	st := o.Stats()
	if st.Dropped == 0 {
		t.Fatal("nothing dropped under a tiny bound")
	}
	if st.Bytes > 4*4096+4096 {
		t.Fatalf("bound exceeded: %d bytes", st.Bytes)
	}
	got, _ := o.Next(10000, 1<<30)
	var sawDropped bool
	for _, e := range got {
		if e.Kind == agentv1.EventKind_EVENT_KIND_DROPPED {
			sawDropped = true
		}
	}
	if !sawDropped {
		t.Fatal("no dropped record in the queue: a hole in the trail would be silent")
	}
	if got[len(got)-1].AgentSeq != last {
		t.Fatal("newest record lost")
	}
}

func TestCorruptTailIsTruncatedNotFatal(t *testing.T) {
	dir := t.TempDir()
	o, _ := OpenOutbox(dir, 1<<20, 256<<10)
	for i := 1; i <= 5; i++ {
		o.Append(ev(i))
	}
	o.Close()
	segs, _ := filepath.Glob(filepath.Join(dir, "ob-*.seg"))
	f, _ := os.OpenFile(segs[0], os.O_APPEND|os.O_WRONLY, 0)
	f.Write([]byte{0, 0, 0, 40, 1, 2, 3, 4, 'g', 'a', 'r', 'b'}) // a torn record
	f.Close()
	o2 := open(t, dir, 1<<20, 256<<10)
	got, _ := o2.Next(100, 1<<20)
	if len(got) != 5 {
		t.Fatalf("good prefix lost: %d", len(got))
	}
	if seq, err := o2.Append(ev(6)); err != nil || seq != 6 {
		t.Fatalf("append after repair: %d %v", seq, err)
	}
}

func TestCorruptMiddleKeepsWorking(t *testing.T) {
	dir := t.TempDir()
	o, _ := OpenOutbox(dir, 1<<20, 256<<10)
	for i := 1; i <= 5; i++ {
		o.Append(ev(i))
	}
	o.Close()
	segs, _ := filepath.Glob(filepath.Join(dir, "ob-*.seg"))
	b, _ := os.ReadFile(segs[0])
	b[len(b)/2] ^= 0xff
	os.WriteFile(segs[0], b, 0o600)
	o2 := open(t, dir, 1<<20, 256<<10)
	if _, err := o2.Append(ev(99)); err != nil {
		t.Fatalf("a damaged file must not stop the agent: %v", err)
	}
	got, _ := o2.Next(100, 1<<20)
	prev := uint64(0)
	for _, e := range got {
		if e.AgentSeq <= prev {
			t.Fatalf("sequence not increasing: %d after %d", e.AgentSeq, prev)
		}
		prev = e.AgentSeq
	}
}

func TestWriteFailureIsCountedAndReportedLater(t *testing.T) {
	// Fault: the disk fills (simulated by closing the descriptor under the outbox). The caller gets an
	// error, not a panic, and the loss is reported as a dropped record once writing works again.
	dir := t.TempDir()
	o := open(t, dir, 1<<20, 256<<10)
	o.Append(ev(1))
	o.mu.Lock()
	good := o.active
	broken, _ := os.Open(os.DevNull) // read-only descriptor: Write fails
	o.active = broken
	o.mu.Unlock()
	if _, err := o.Append(ev(2)); err == nil {
		t.Fatal("expected a write error")
	}
	o.mu.Lock()
	o.active = good
	o.mu.Unlock()
	if _, err := o.Append(ev(3)); err != nil {
		t.Fatal(err)
	}
	got, _ := o.Next(100, 1<<20)
	var dropped int
	for _, e := range got {
		if e.Kind == agentv1.EventKind_EVENT_KIND_DROPPED {
			dropped++
		}
	}
	if dropped != 1 || o.Stats().WriteErrors != 1 {
		t.Fatalf("dropped records %d, stats %+v", dropped, o.Stats())
	}
}

func TestRejectsTooSmallBound(t *testing.T) {
	if _, err := OpenOutbox(t.TempDir(), 1000, 4096); err == nil {
		t.Fatal("bound below four segments accepted")
	}
}
