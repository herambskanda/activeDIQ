package agent

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/skenzeriq/activediq/internal/proto/skenzeriq/agent/v1"
)

// The outbox is a durable, bounded, at-least-once queue on disk (agent-host-addc-contract.md §5).
//
// Layout: a directory of segment files "ob-<first agent_seq, 20 digits>.seg". A segment holds
// consecutive sequence numbers; a record is  u32 length | u32 CRC-32C of the payload | payload  with
// the payload a marshalled AgentEvent. The newest segment is the active one and is never deleted, so
// the highest sequence ever assigned survives a restart even when every record has been acknowledged
// (a restarted agent that reused a sequence would look like a divergent redelivery to the server).
//
// Bounds. When the queue would exceed MaxBytes the oldest sealed segments are dropped and one
// "dropped" record names the range lost. Append never blocks and never waits for the network. A write
// failure (disk full) is counted and surfaced as a dropped record on the next successful append; the
// caller keeps running.

// Outbox errors.
var (
	// ErrOutboxWrite: the record could not be written (disk full, directory gone). It was counted and
	// will be reported as a dropped record once writing works again.
	ErrOutboxWrite  = errors.New("agent: outbox write failed")
	ErrOutboxClosed = errors.New("agent: outbox is closed")
)

const (
	segPrefix = "ob-"
	segSuffix = ".seg"
	recHeader = 8
	// MaxEventBytes bounds one marshalled record. The collector bounds fields below this; a larger
	// record is refused rather than written.
	MaxEventBytes = 96 << 10
	// DefaultSegmentBytes is the drop granularity.
	DefaultSegmentBytes = 1 << 20
	minSegments         = 4
)

var crcTable = crc32.MakeTable(crc32.Castagnoli)

// OutboxStats is a snapshot for GetStatus.
type OutboxStats struct {
	Records, Bytes, Dropped, WriteErrors uint64
	LastSeq, AckedThrough                uint64
}

type segment struct {
	first, last uint64 // last < first when empty
	size        int64
}

func (s segment) empty() bool { return s.last < s.first }

// Outbox is safe for concurrent use.
type Outbox struct {
	mu       sync.Mutex
	dir      string
	segBytes int64
	maxBytes int64
	segs     []segment // oldest first; the last is active
	active   *os.File
	next     uint64 // next sequence to assign
	acked    uint64
	dropped  uint64 // records dropped over the life of the process
	pending  uint64 // records lost to write failures, to report
	werrs    uint64
	closed   bool
}

// OpenOutbox opens or creates the outbox in dir. A torn or corrupt tail is truncated at the last good
// record: an unclean shutdown, a full disk or a damaged file costs records, never a failed start.
func OpenOutbox(dir string, maxBytes, segBytes int64) (*Outbox, error) {
	if segBytes <= 0 {
		segBytes = DefaultSegmentBytes
	}
	if maxBytes < minSegments*segBytes {
		return nil, fmt.Errorf("agent: outbox maximum %d is below %d segments of %d", maxBytes, minSegments, segBytes)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	o := &Outbox{dir: dir, segBytes: segBytes, maxBytes: maxBytes, next: 1}
	names, err := listSegments(dir)
	if err != nil {
		return nil, err
	}
	for i, n := range names {
		first := n.first
		path := filepath.Join(dir, n.name)
		last, size, err := scanSegment(path, first, i == len(names)-1)
		if err != nil {
			return nil, err
		}
		seg := segment{first: first, last: last, size: size}
		if i > 0 && seg.first != o.next {
			// A hole between segments (a lost file): keep the sequence monotonic, the server sees a gap.
			o.next = seg.first
		}
		o.segs = append(o.segs, seg)
		if !seg.empty() {
			o.next = seg.last + 1
		} else {
			o.next = seg.first
		}
	}
	if len(o.segs) == 0 {
		if err := o.rotateLocked(); err != nil {
			return nil, err
		}
	} else if err := o.openActiveLocked(); err != nil {
		return nil, err
	}
	return o, nil
}

type segName struct {
	name  string
	first uint64
}

func listSegments(dir string) ([]segName, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []segName
	for _, e := range ents {
		n := e.Name()
		if !strings.HasPrefix(n, segPrefix) || !strings.HasSuffix(n, segSuffix) || e.IsDir() || !e.Type().IsRegular() {
			continue
		}
		v, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(n, segPrefix), segSuffix), 10, 64)
		if err != nil || segFile(v) != n {
			continue
		}
		out = append(out, segName{n, v})
	}
	slices.SortFunc(out, func(a, b segName) int {
		switch {
		case a.first < b.first:
			return -1
		case a.first > b.first:
			return 1
		}
		return 0
	})
	return out, nil
}

func segFile(first uint64) string { return fmt.Sprintf("%s%020d%s", segPrefix, first, segSuffix) }

// scanSegment walks a segment, returns the last good sequence (first-1 when none) and the size of the
// good prefix, and truncates anything after it.
func scanSegment(path string, first uint64, isLast bool) (last uint64, good int64, err error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	last = first - 1
	r := bufio.NewReaderSize(f, 64<<10)
	for {
		payload, n, rerr := readRecord(r)
		if rerr != nil {
			break
		}
		var ev agentv1.AgentEvent
		if proto.Unmarshal(payload, &ev) != nil || ev.GetAgentSeq() != last+1 {
			break
		}
		last++
		good += int64(n)
	}
	st, serr := f.Stat()
	if serr != nil {
		return 0, 0, serr
	}
	if st.Size() != good {
		if err := f.Truncate(good); err != nil {
			return 0, 0, err
		}
	}
	_ = isLast
	return last, good, nil
}

// readRecord reads one framed record. It returns the payload and the bytes consumed.
func readRecord(r *bufio.Reader) ([]byte, int, error) {
	var h [recHeader]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, 0, err
	}
	n := binary.BigEndian.Uint32(h[:4])
	if n == 0 || n > MaxEventBytes {
		return nil, 0, errCorrupt
	}
	p := make([]byte, n)
	if _, err := io.ReadFull(r, p); err != nil {
		return nil, 0, err
	}
	if crc32.Checksum(p, crcTable) != binary.BigEndian.Uint32(h[4:]) {
		return nil, 0, errCorrupt
	}
	return p, recHeader + int(n), nil
}

var errCorrupt = errors.New("agent: corrupt outbox record")

func (o *Outbox) openActiveLocked() error {
	last := o.segs[len(o.segs)-1]
	f, err := os.OpenFile(filepath.Join(o.dir, segFile(last.first)), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return err
	}
	o.active = f
	return nil
}

func (o *Outbox) rotateLocked() error {
	if o.active != nil {
		_ = o.active.Sync()
		_ = o.active.Close()
		o.active = nil
	}
	f, err := os.OpenFile(filepath.Join(o.dir, segFile(o.next)), os.O_WRONLY|os.O_APPEND|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	o.segs = append(o.segs, segment{first: o.next, last: o.next - 1})
	o.active = f
	return nil
}

// SetMaxBytes narrows or widens the queue bound (the policy narrows it below the local ceiling; the
// caller clamps). Excess is dropped on the next Append.
func (o *Outbox) SetMaxBytes(n int64) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if n >= minSegments*o.segBytes {
		o.maxBytes = n
	}
}

func (o *Outbox) totalLocked() int64 {
	var t int64
	for _, s := range o.segs {
		t += s.size
	}
	return t
}

// Append assigns the next sequence, writes the record and returns the sequence. ev.AgentSeq is
// overwritten. The record is durable after the next Flush.
func (o *Outbox) Append(ev *agentv1.AgentEvent) (uint64, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return 0, ErrOutboxClosed
	}
	// Report earlier losses first, so the trail shows them in order.
	if o.pending > 0 {
		n := o.pending
		if _, err := o.writeLocked(droppedEvent(0, 0, n, "write_failed")); err == nil {
			o.pending = 0
		}
	}
	seq, err := o.writeLocked(ev)
	if err != nil {
		o.pending++
		o.werrs++
		return 0, fmt.Errorf("%w", ErrOutboxWrite)
	}
	return seq, nil
}

func droppedEvent(from, to, count uint64, reason string) *agentv1.AgentEvent {
	return &agentv1.AgentEvent{
		Kind: agentv1.EventKind_EVENT_KIND_DROPPED,
		Fields: []*agentv1.EventField{
			{Name: "reason", Value: reason},
			{Name: "first_agent_seq", Value: strconv.FormatUint(from, 10)},
			{Name: "last_agent_seq", Value: strconv.FormatUint(to, 10)},
			{Name: "count", Value: strconv.FormatUint(count, 10)},
		},
	}
}

func (o *Outbox) writeLocked(ev *agentv1.AgentEvent) (uint64, error) {
	cp := proto.Clone(ev).(*agentv1.AgentEvent)
	cp.AgentSeq = o.next
	p, err := proto.MarshalOptions{Deterministic: true}.Marshal(cp)
	if err != nil || len(p) == 0 || len(p) > MaxEventBytes {
		return 0, errors.New("agent: event is not storable")
	}
	need := int64(recHeader + len(p))
	act := &o.segs[len(o.segs)-1]
	if act.size > 0 && act.size+need > o.segBytes {
		if err := o.rotateLocked(); err != nil {
			return 0, err
		}
		act = &o.segs[len(o.segs)-1]
	}
	o.enforceBoundLocked(need)
	act = &o.segs[len(o.segs)-1]
	buf := make([]byte, recHeader+len(p))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(p)))
	binary.BigEndian.PutUint32(buf[4:8], crc32.Checksum(p, crcTable))
	copy(buf[recHeader:], p)
	if n, err := o.active.Write(buf); err != nil {
		if n > 0 { // a torn record would poison the segment: cut it back
			_ = o.active.Truncate(act.size)
		}
		return 0, err
	}
	act.size += need
	act.last = o.next
	o.next++
	return cp.AgentSeq, nil
}

// enforceBoundLocked drops the oldest sealed segments until need more bytes fit, then records it.
func (o *Outbox) enforceBoundLocked(need int64) {
	var from, to, count uint64
	for o.totalLocked()+need > o.maxBytes && len(o.segs) > 1 {
		s := o.segs[0]
		if err := os.Remove(filepath.Join(o.dir, segFile(s.first))); err != nil && !errors.Is(err, os.ErrNotExist) {
			break // cannot free space; the append may still succeed or fail on its own
		}
		o.segs = o.segs[1:]
		if s.empty() {
			continue
		}
		lo := max(s.first, o.acked+1)
		if s.last >= lo {
			if count == 0 {
				from = lo
			}
			to = s.last
			count += s.last - lo + 1
		}
	}
	if count > 0 {
		o.dropped += count
		// The dropped record is written outside the bound check on purpose (it is one small record).
		_, _ = o.writeRawLocked(droppedEvent(from, to, count, "outbox_full"))
	}
}

// writeRawLocked writes without the bound or rotation logic; used only for the dropped record.
func (o *Outbox) writeRawLocked(ev *agentv1.AgentEvent) (uint64, error) {
	cp := proto.Clone(ev).(*agentv1.AgentEvent)
	cp.AgentSeq = o.next
	p, err := proto.Marshal(cp)
	if err != nil {
		return 0, err
	}
	buf := make([]byte, recHeader+len(p))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(p)))
	binary.BigEndian.PutUint32(buf[4:8], crc32.Checksum(p, crcTable))
	copy(buf[recHeader:], p)
	act := &o.segs[len(o.segs)-1]
	if _, err := o.active.Write(buf); err != nil {
		_ = o.active.Truncate(act.size)
		return 0, err
	}
	act.size += int64(len(buf))
	act.last = o.next
	o.next++
	return cp.AgentSeq, nil
}

// Flush makes everything appended so far durable. A collector persists its bookmark only after Flush,
// so a crash re-reads events rather than losing them.
func (o *Outbox) Flush() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed || o.active == nil {
		return nil
	}
	return o.active.Sync()
}

// Next returns up to maxRecords unacknowledged records in sequence order, stopping before maxBytes of
// marshalled payload (at least one record is returned if any exists). It does not consume them.
func (o *Outbox) Next(maxRecords int, maxBytes int) ([]*agentv1.AgentEvent, error) {
	o.mu.Lock()
	segs := slices.Clone(o.segs)
	acked := o.acked
	o.mu.Unlock()

	var out []*agentv1.AgentEvent
	total := 0
	for _, s := range segs {
		if s.empty() || s.last <= acked {
			continue
		}
		f, err := os.Open(filepath.Join(o.dir, segFile(s.first)))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) { // dropped meanwhile
				continue
			}
			return out, err
		}
		r := bufio.NewReaderSize(f, 64<<10)
		var readBytes int64
		for readBytes < s.size {
			p, n, err := readRecord(r)
			if err != nil {
				break
			}
			readBytes += int64(n)
			var ev agentv1.AgentEvent
			if proto.Unmarshal(p, &ev) != nil {
				break
			}
			if ev.GetAgentSeq() <= acked {
				continue
			}
			if len(out) > 0 && (len(out) >= maxRecords || total+len(p) > maxBytes) {
				f.Close()
				return out, nil
			}
			out = append(out, &ev)
			total += len(p)
		}
		f.Close()
	}
	return out, nil
}

// Ack lets the outbox drop records through seq. Sequences it never assigned are ignored beyond the
// highest assigned one.
func (o *Outbox) Ack(through uint64) {
	o.mu.Lock()
	defer o.mu.Unlock()
	through = min(through, o.next-1)
	if through <= o.acked {
		return
	}
	o.acked = through
	for len(o.segs) > 1 && !o.segs[0].empty() && o.segs[0].last <= o.acked {
		_ = os.Remove(filepath.Join(o.dir, segFile(o.segs[0].first)))
		o.segs = o.segs[1:]
	}
}

// Stats returns a snapshot.
func (o *Outbox) Stats() OutboxStats {
	o.mu.Lock()
	defer o.mu.Unlock()
	st := OutboxStats{Dropped: o.dropped, WriteErrors: o.werrs, LastSeq: o.next - 1, AckedThrough: o.acked}
	for _, s := range o.segs {
		if s.empty() || s.last <= o.acked {
			continue
		}
		st.Records += s.last - max(s.first-1, o.acked)
		st.Bytes += uint64(s.size)
	}
	return st
}

// Close flushes and closes. Further appends fail.
func (o *Outbox) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return nil
	}
	o.closed = true
	if o.active != nil {
		err := o.active.Sync()
		if cerr := o.active.Close(); err == nil {
			err = cerr
		}
		o.active = nil
		return err
	}
	return nil
}

// noteDropped counts records the host gave up on (a record the server refused as invalid).
func (o *Outbox) noteDropped(n uint64) {
	o.mu.Lock()
	o.dropped += n
	o.mu.Unlock()
}
