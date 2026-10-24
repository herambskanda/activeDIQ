package rights

// The shrink ratchet's local evidence (contract §8.3a, TM-D23 rule 8). A completed run compares its
// designated and correlated tier0 inputs with the set the previous epoch reported, as sets, and
// writes one tier0_set_shrink record on the connector host for every dropped entry. The reported set
// is persisted (atomically, flushed) so a smaller run right after a restart still leaves its record.
//
// Every write here is required. A failure ends the run with LOCAL_RECORD_FAILED and starts no epoch
// (the caller closes the write gate); the in-memory reported set is never shrunk by a failed run.
// Records and the baseline hold identifiers only (CC-WRITE-13).

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/ownerfile"
	v1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// Source of a reported entry.
const (
	SourceRunInput       = "run_input"
	SourceRequestContext = "request_context"
)

// ReportedEntry is one designated or correlated tier0 object the connector has reported.
type ReportedEntry struct {
	GUID   string        `json:"guid"`  // canonical dashed
	Basis  v1.Tier0Basis `json:"basis"` // CUSTOMER_DESIGNATED, C16 or E5
	Source string        `json:"source"`
	// Revision is the tier0_revision of the first request context that marked it (request_context only).
	Revision string `json:"revision,omitempty"`
}

type entryKey struct {
	guid  string
	basis v1.Tier0Basis
}

func (e ReportedEntry) key() entryKey { return entryKey{e.GUID, e.Basis} }

// Baseline is the persisted reported set of the current epoch.
type Baseline struct {
	VerificationID string          `json:"verification_id"`
	Entries        []ReportedEntry `json:"entries"`
}

// BaselineStore persists the Baseline. Save must be atomic and durable; Load returns
// fs.ErrNotExist when none was ever saved.
type BaselineStore interface {
	Load() (*Baseline, error)
	Save(*Baseline) error
}

// FileBaselineStore keeps the baseline in one file readable and writable by the connector's service
// identity only. Save writes a temporary file, flushes it, renames it over the target and flushes the
// directory.
type FileBaselineStore struct{ Path string }

func (s FileBaselineStore) Load() (*Baseline, error) {
	raw, err := os.ReadFile(s.Path)
	if err != nil {
		return nil, err
	}
	var b Baseline
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return nil, fmt.Errorf("baseline unreadable: %w", err)
	}
	return &b, nil
}

func (s FileBaselineStore) Save(b *Baseline) error {
	raw, err := json.Marshal(b)
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.Path)
	tmp, err := os.CreateTemp(dir, ".baseline-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	cleanup := func(e error) error { _ = tmp.Close(); _ = os.Remove(name); return e }
	if _, err := ownerfile.Restrict(name); err != nil {
		return cleanup(err)
	}
	if _, err := tmp.Write(raw); err != nil {
		return cleanup(err)
	}
	if err := tmp.Sync(); err != nil {
		return cleanup(err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Rename(name, s.Path); err != nil {
		_ = os.Remove(name)
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// ShrinkRecord is the tier0_set_shrink record.
type ShrinkRecord struct {
	Event                string          `json:"event"` // "tier0_set_shrink"
	Time                 time.Time       `json:"time"`
	PreviousVerification string          `json:"previous_verification_id"`
	NewVerification      string          `json:"verification_id"`
	Dropped              []ReportedEntry `json:"dropped"`
	CountsByBasis        map[string]int  `json:"counts_by_basis"`
}

// RecordSink writes the connector's local records. Each method must return only after the record is
// durable, or an error. A sink for the Windows event log (Application log, the connector's own
// source) implements the same interface (windows-engineer) and is combined with MultiSink.
type RecordSink interface {
	WriteShrink(ctx context.Context, r ShrinkRecord) error
	// WriteBaselineMissing records tier0_baseline_missing: the comparison was skipped (or, after
	// no restart, done from memory) because the persisted baseline is missing or unreadable.
	WriteBaselineMissing(ctx context.Context, verificationID string, cause error) error
}

// FileRecordSink appends JSON lines to a local log file (mode 0600) and flushes each one.
type FileRecordSink struct{ Path string }

func (s FileRecordSink) append(v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(s.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(raw, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func (s FileRecordSink) WriteShrink(_ context.Context, r ShrinkRecord) error { return s.append(r) }

func (s FileRecordSink) WriteBaselineMissing(_ context.Context, id string, cause error) error {
	// The cause is classified, never echoed: it can carry a path.
	reason := "unreadable"
	if errors.Is(cause, fs.ErrNotExist) {
		reason = "not_found"
	}
	return s.append(map[string]any{"event": "tier0_baseline_missing", "time": time.Now().UTC(), "verification_id": id, "reason": reason})
}

// MultiSink writes to every sink; it fails if any fails, after trying all.
type MultiSink []RecordSink

func (m MultiSink) WriteShrink(ctx context.Context, r ShrinkRecord) error {
	var errs []error
	for _, s := range m {
		errs = append(errs, s.WriteShrink(ctx, r))
	}
	return errors.Join(errs...)
}

func (m MultiSink) WriteBaselineMissing(ctx context.Context, id string, cause error) error {
	var errs []error
	for _, s := range m {
		errs = append(errs, s.WriteBaselineMissing(ctx, id, cause))
	}
	return errors.Join(errs...)
}

// ErrLocalRecordFailed ends a VerifyConnection stream in place of `completed`
// (ERROR_CODE_LOCAL_RECORD_FAILED). The caller closes the write gate with
// WRITE_GATE_STATE_LOCAL_RECORD_FAILED and starts no epoch.
var ErrLocalRecordFailed = errors.New("rights: a local tier0 record could not be made durable")

// EpochState is the reported set of the current verification epoch, in memory and persisted.
type EpochState struct {
	store BaselineStore
	sink  RecordSink
	now   func() time.Time

	mu       sync.Mutex
	known    bool // an epoch completed (or an entry was appended) since this process started
	verifyID string
	reported map[entryKey]ReportedEntry
}

// NewEpochState returns the state for one connection and credential. now may be nil.
func NewEpochState(store BaselineStore, sink RecordSink, now func() time.Time) *EpochState {
	if now == nil {
		now = time.Now
	}
	return &EpochState{store: store, sink: sink, now: now, reported: map[entryKey]ReportedEntry{}}
}

// Append adds a ratchet entry (an accepted request context marked an object, contract §8.3a) and
// makes it durable before returning. An error means the caller must refuse the call and close the gate.
func (s *EpochState) Append(e ReportedEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.reported[e.key()]; ok {
		return nil
	}
	if !s.known {
		// After a restart the persisted baseline is the epoch's reported set: append to it, never over it.
		if b, err := s.store.Load(); err == nil {
			s.adopt(b)
		}
	}
	s.reported[e.key()] = e
	if err := s.store.Save(s.snapshot()); err != nil {
		delete(s.reported, e.key())
		return ErrLocalRecordFailed
	}
	s.known = true
	return nil
}

func (s *EpochState) adopt(b *Baseline) {
	s.verifyID = b.VerificationID
	s.reported = map[entryKey]ReportedEntry{}
	for _, e := range b.Entries {
		s.reported[e.key()] = e
	}
	s.known = true
}

func (s *EpochState) snapshot() *Baseline {
	b := &Baseline{VerificationID: s.verifyID}
	for _, e := range s.reported {
		b.Entries = append(b.Entries, e)
	}
	sort.Slice(b.Entries, func(i, j int) bool {
		if b.Entries[i].GUID != b.Entries[j].GUID {
			return b.Entries[i].GUID < b.Entries[j].GUID
		}
		return b.Entries[i].Basis < b.Entries[j].Basis
	})
	return b
}

// Complete is called when a run reached its end, before `completed` is sent. It compares the run's
// inputs with the reported set, writes the shrink record, persists the new baseline and starts the
// new epoch. It returns the number of dropped entries. Any failed write returns ErrLocalRecordFailed
// and leaves the reported set as it was.
func (s *EpochState) Complete(ctx context.Context, verificationID string, inputs []ReportedEntry) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	prev := s.reported
	prevID := s.verifyID
	compare := s.known
	missing := false
	var missingCause error
	b, lerr := s.store.Load()
	switch {
	case lerr == nil && !s.known:
		prev = map[entryKey]ReportedEntry{}
		for _, e := range b.Entries {
			prev[e.key()] = e
		}
		prevID, compare = b.VerificationID, true
	case lerr != nil:
		missing, missingCause = true, lerr
	}
	if missing {
		if err := s.sink.WriteBaselineMissing(ctx, verificationID, missingCause); err != nil {
			return 0, ErrLocalRecordFailed
		}
	}

	next := map[entryKey]ReportedEntry{}
	for _, e := range inputs {
		e.Source = SourceRunInput
		e.Revision = ""
		next[e.key()] = e
	}
	var dropped []ReportedEntry
	if compare {
		for k, e := range prev {
			if _, ok := next[k]; !ok {
				dropped = append(dropped, e)
			}
		}
	}
	if len(dropped) > 0 {
		sort.Slice(dropped, func(i, j int) bool {
			if dropped[i].GUID != dropped[j].GUID {
				return dropped[i].GUID < dropped[j].GUID
			}
			return dropped[i].Basis < dropped[j].Basis
		})
		counts := map[string]int{}
		for _, e := range dropped {
			counts[e.Basis.String()]++
		}
		rec := ShrinkRecord{Event: "tier0_set_shrink", Time: s.now().UTC(), PreviousVerification: prevID,
			NewVerification: verificationID, Dropped: dropped, CountsByBasis: counts}
		if err := s.sink.WriteShrink(ctx, rec); err != nil {
			return 0, ErrLocalRecordFailed
		}
	}
	nb := &Baseline{VerificationID: verificationID}
	for _, e := range next {
		nb.Entries = append(nb.Entries, e)
	}
	sort.Slice(nb.Entries, func(i, j int) bool {
		if nb.Entries[i].GUID != nb.Entries[j].GUID {
			return nb.Entries[i].GUID < nb.Entries[j].GUID
		}
		return nb.Entries[i].Basis < nb.Entries[j].Basis
	})
	if err := s.store.Save(nb); err != nil {
		return 0, ErrLocalRecordFailed
	}
	s.reported, s.verifyID, s.known = next, verificationID, true
	return len(dropped), nil
}
