package addc

import (
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/skenzeriq/activediq/internal/agenthost/hostapi"
	"github.com/skenzeriq/activediq/internal/platform/agentpolicy"
	addcv1 "github.com/skenzeriq/activediq/internal/proto/activediq/addc/v1"
)

// chanState is the live state of one channel's collection.
type chanState struct {
	status    atomic.Int32 // addcv1.ChannelStatus
	lastID    atomic.Uint64
	gaps      atomic.Uint64
	collected atomic.Uint64
	throttled atomic.Uint64
}

// bucket is a token bucket sized in events per second, with a one-second burst.
type bucket struct {
	rate   float64
	tokens float64
	last   time.Time
}

func (b *bucket) allow(now time.Time) bool {
	if b.last.IsZero() {
		b.last, b.tokens = now, b.rate
	}
	b.tokens = min(b.rate, b.tokens+now.Sub(b.last).Seconds()*b.rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// run is one channel's collector for one policy generation.
type run struct {
	ch    agentpolicy.Channel
	name  string
	st    *chanState
	sink  hostapi.EventSink
	blobs hostapi.Blobs
	log   *slog.Logger
	now   func() time.Time
	bk    bucket
	dc    string

	lastSeen    uint64 // last record id seen (emitted or throttled)
	thrFirst    uint64 // first record id of an open throttled run
	thrLast     uint64
	lastPersist time.Time
}

func blobName(c agentpolicy.Channel) string { return "bookmark-" + channelName(c) }
func loadBookmark(b hostapi.Blobs, c agentpolicy.Channel) uint64 {
	d, err := b.Load(blobName(c))
	if err != nil || len(d) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(d)
}

func (r *run) append(e *hostapi.Event) bool {
	e.ObservedAtUnixNanos = r.now().UnixNano()
	e.ReportedDcGuid = r.dc
	if _, err := r.sink.Append(e); err != nil {
		r.log.Warn("outbox append failed", "channel", r.name, "err", err)
		return false
	}
	return true
}

func (r *run) gapRecord(reason string, first, last uint64) *hostapi.Event {
	return &hostapi.Event{Kind: hostapi.EventKindGap, Channel: r.name, Fields: []*hostapi.EventField{
		{Name: "reason", Value: reason},
		{Name: "first_record_id", Value: strconv.FormatUint(first, 10)},
		{Name: "last_record_id", Value: strconv.FormatUint(last, 10)},
	}}
}

// closeThrottle writes the GAP record for a throttled run: an event dropped on purpose is still a
// visible hole (TM-R7).
func (r *run) closeThrottle() {
	if r.thrFirst != 0 {
		r.append(r.gapRecord("throttled", r.thrFirst, r.thrLast))
		r.thrFirst, r.thrLast = 0, 0
	}
}

// handle processes one event. It never blocks beyond a local disk append.
func (r *run) handle(ev RawEvent) {
	if ev.RecordID != 0 && ev.RecordID <= r.lastSeen {
		return // already seen (resubscribe overlap)
	}
	if ev.Unparsable {
		// Never drop silently (TM-R7): say which record was lost. Not throttled: a flood of unparsable
		// events must stay visible, and the outbox bound already protects the disk.
		r.st.gaps.Add(1)
		r.closeThrottle()
		r.append(r.gapRecord("unparsable", ev.RecordID, ev.RecordID))
		if ev.RecordID > r.lastSeen {
			r.lastSeen = ev.RecordID
		}
		return
	}
	// A record-id jump is NOT a gap signal: the subscription filters by event id, so ids outside the
	// catalogue legitimately leave holes. Wraps and clears are detected from the channel's oldest
	// record at (re)subscribe (checkWrap) and from event 1102.
	r.lastSeen = ev.RecordID
	if !r.bk.allow(r.now()) {
		r.st.throttled.Add(1)
		if r.thrFirst == 0 {
			r.thrFirst = ev.RecordID
		}
		r.thrLast = ev.RecordID
		return
	}
	r.closeThrottle()
	fields := make([]*hostapi.EventField, 0, len(ev.Fields)+1)
	fields = append(fields, &hostapi.EventField{Name: "event_id", Value: strconv.FormatUint(uint64(ev.EventID), 10)})
	for _, f := range ev.Fields {
		fields = append(fields, &hostapi.EventField{Name: f.Name, Value: f.Value})
	}
	if !r.append(&hostapi.Event{Kind: hostapi.EventKindEvent, Channel: r.name, EventRecordId: ev.RecordID, Fields: fields}) {
		return
	}
	r.st.collected.Add(1)
	r.st.lastID.Store(ev.RecordID)
	r.persist()
}

// checkWrap compares the bookmark with the channel's oldest record: if the oldest is past the
// bookmark, records between them were overwritten or cleared while we were not reading.
func (r *run) checkWrap(src Source) {
	if r.lastSeen == 0 {
		return
	}
	oldest, err := src.OldestRecord(r.ch)
	if err != nil || oldest == 0 || oldest <= r.lastSeen+1 {
		return
	}
	r.st.gaps.Add(1)
	r.closeThrottle()
	r.append(r.gapRecord("log_wrapped", r.lastSeen+1, oldest-1))
	r.lastSeen = oldest - 1
}

// persist saves the bookmark only after the events before it are durable, so a crash re-reads
// (at-least-once) and never skips.
func (r *run) persist() {
	if r.now().Sub(r.lastPersist) < time.Second {
		return
	}
	r.lastPersist = r.now()
	if err := r.sink.Flush(); err != nil {
		return
	}
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], r.st.lastID.Load())
	if err := r.blobs.Save(blobName(r.ch), b[:]); err != nil {
		r.log.Warn("bookmark not saved", "channel", r.name, "err", err)
	}
}

// Collector owns the per-channel subscriptions of one module instance.
type Collector struct {
	src   Source
	deps  hostapi.ModuleDeps
	dc    string
	mu    sync.Mutex
	state map[agentpolicy.Channel]*chanState
	stop  context.CancelFunc
	done  chan struct{}
	root  context.Context
}

// NewCollector returns a collector that is idle until Apply is called.
func NewCollector(src Source, deps hostapi.ModuleDeps, dcGUID string) *Collector {
	return &Collector{src: src, deps: deps, dc: dcGUID, state: map[agentpolicy.Channel]*chanState{
		agentpolicy.ChannelSecurity: {}, agentpolicy.ChannelDirectoryService: {}}}
}

func (c *Collector) setRoot(ctx context.Context) { c.mu.Lock(); c.root = ctx; c.mu.Unlock() }

// Apply replaces the running subscriptions with those the policy asks for. A disabled policy stops
// collection; the host reports that as stopped_by_policy.
func (c *Collector) Apply(ev agentpolicy.EventRules) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stop != nil {
		c.stop()
		<-c.done
		c.stop = nil
	}
	for _, s := range c.state {
		s.status.Store(int32(addcv1.ChannelStatus_CHANNEL_STATUS_NOT_COLLECTED))
	}
	if !ev.CollectionEnabled || c.root == nil || c.root.Err() != nil {
		return
	}
	ctx, cancel := context.WithCancel(c.root)
	c.stop, c.done = cancel, make(chan struct{})
	var wg sync.WaitGroup
	for _, ch := range ev.Channels {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.collect(ctx, ch, ev)
		}()
	}
	go func(done chan struct{}) { wg.Wait(); close(done) }(c.done)
}

// Stop ends every subscription and waits for them.
func (c *Collector) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stop != nil {
		c.stop()
		<-c.done
		c.stop = nil
	}
}

func (c *Collector) collect(ctx context.Context, ch agentpolicy.Channel, ev agentpolicy.EventRules) {
	st := c.state[ch]
	r := &run{ch: ch, name: channelName(ch), st: st, sink: c.deps.Events, blobs: c.deps.Blobs, log: c.deps.Log, now: c.deps.Now, dc: c.dc,
		bk: bucket{rate: float64(ev.MaxEventsPerSecond)}}
	r.lastSeen = loadBookmark(c.deps.Blobs, ch)
	st.lastID.Store(r.lastSeen)
	backoff := time.Second
	for ctx.Err() == nil {
		st.status.Store(int32(addcv1.ChannelStatus_CHANNEL_STATUS_COLLECTING))
		r.checkWrap(c.src)
		err := c.src.Subscribe(ctx, ch, r.lastSeen, withAlways(ch, ev.EventIDs), r.handle)
		r.closeThrottle()
		_ = c.deps.Events.Flush()
		if ctx.Err() != nil {
			return
		}
		switch {
		case errors.Is(err, ErrUnreadable):
			st.status.Store(int32(addcv1.ChannelStatus_CHANNEL_STATUS_UNREADABLE))
		default:
			st.status.Store(int32(addcv1.ChannelStatus_CHANNEL_STATUS_FAILED))
		}
		c.deps.Log.Warn("channel subscription ended", "channel", r.name, "unreadable", errors.Is(err, ErrUnreadable))
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, time.Minute)
	}
}

func withAlways(ch agentpolicy.Channel, ids []uint32) []uint32 {
	out := append([]uint32(nil), ids...)
	for _, a := range alwaysIDs(ch) {
		if !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	return out
}

// Snapshot returns the per-channel state in a stable order.
func (c *Collector) Snapshot() []*addcv1.ChannelState {
	out := make([]*addcv1.ChannelState, 0, 2)
	for _, p := range []struct {
		pc agentpolicy.Channel
		ac addcv1.Channel
	}{{agentpolicy.ChannelSecurity, addcv1.Channel_CHANNEL_SECURITY}, {agentpolicy.ChannelDirectoryService, addcv1.Channel_CHANNEL_DIRECTORY_SERVICE}} {
		s := c.state[p.pc]
		status := addcv1.ChannelStatus(s.status.Load())
		if status == addcv1.ChannelStatus_CHANNEL_STATUS_UNSPECIFIED {
			status = addcv1.ChannelStatus_CHANNEL_STATUS_NOT_COLLECTED
		}
		out = append(out, &addcv1.ChannelState{Channel: p.ac, Status: status, LastEventRecordId: s.lastID.Load(),
			GapsSeen: s.gaps.Load(), EventsCollected: s.collected.Load(), EventsThrottled: s.throttled.Load()})
	}
	return out
}
