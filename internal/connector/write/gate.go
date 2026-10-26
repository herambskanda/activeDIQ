package write

import (
	"bytes"
	"encoding/json/v2"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/skenzeriq/activediq/internal/connector/tier0"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// Basis is a row of threat-model §6.4.
type Basis = connectorv1.Tier0Basis

const designatedBasis = tier0.Designated

// Mark is one object the connector knows to be tier0, with the basis and where the knowledge came
// from. Inputs of a VerifyConnection run (designated_tier0, correlated_tier0) and accepted request
// marks are Marks.
type Mark struct {
	Object guid.GUID
	Basis  Basis
	// Source is "run" for a verification input and "request" for a mark the ratchet took from an
	// accepted Tier0Context (with its tier0_revision in Revision).
	Source   string
	Revision uint64
}

// Run is the part of a completed VerifyConnection the write gate and the ratchet stand on
// (contract §8.2). It is held in memory only; a restart leaves the gate NOT_VERIFIED.
type Run struct {
	VerificationID []byte
	CompletedAt    time.Time
	Verdict        connectorv1.VerificationVerdict
	Checks         map[connectorv1.VerificationCheck]connectorv1.CheckOutcome
	// Blocking are the fingerprints of the run's blocking V7 or EV3 findings.
	Blocking [][]byte
	// Set is the connector's computed tier0 set (C1-C15 or E1-E4), keyed by canonical GUID text.
	Set map[string][]Basis
	// Inputs are the run's designated_tier0 and correlated_tier0 entries.
	Inputs []Mark
}

// Baseline is the durable, connector-host-local record of the reported set (contract §8.3a). Append
// must have written and flushed the marks to stable storage before it returns nil.
type Baseline interface {
	Append(connectionID string, marks []Mark) error
}

// GateBook holds the write gate state and the ratchet per connection. The zero value is not
// usable; build it with NewGateBook.
type GateBook struct {
	mu    sync.Mutex
	now   func() time.Time
	base  Baseline
	conns map[string]*epoch
}

type epoch struct {
	run     Run
	ratchet map[string]map[Basis]Mark
	lrf     bool // a local record failed: the gate is closed until the next completed run
}

// NewGateBook returns an empty book (every gate NOT_VERIFIED). base records ratchet appends; a nil
// base is refused, since a ratchet that cannot be made durable must close the gate.
func NewGateBook(base Baseline, now func() time.Time) (*GateBook, error) {
	if base == nil {
		return nil, errors.New("write: gate book needs a durable baseline")
	}
	if now == nil {
		now = time.Now
	}
	return &GateBook{now: now, base: base, conns: map[string]*epoch{}}, nil
}

// Complete starts a new epoch for the connection: the verification stream ended with `completed`
// and its local records are durable. It replaces the run, resets the ratchet to the run's inputs and
// reopens a gate closed by LOCAL_RECORD_FAILED.
func (g *GateBook) Complete(connectionID string, r Run) {
	g.mu.Lock()
	defer g.mu.Unlock()
	e := &epoch{run: r, ratchet: map[string]map[Basis]Mark{}}
	for _, m := range r.Inputs {
		e.put(m)
	}
	g.conns[connectionID] = e
}

// CloseLocalRecordFailed closes the connection's gate because a shrink record or baseline could not
// be made durable (contract §8.3a). The next Complete reopens it.
func (g *GateBook) CloseLocalRecordFailed(connectionID string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if e, ok := g.conns[connectionID]; ok {
		e.lrf = true
	}
}

func (e *epoch) put(m Mark) {
	k := m.Object.String()
	if e.ratchet[k] == nil {
		e.ratchet[k] = map[Basis]Mark{}
	}
	if _, ok := e.ratchet[k][m.Basis]; !ok {
		e.ratchet[k][m.Basis] = m
	}
}

// Decision is the answer of the write gate (§8.2).
type Decision struct {
	Open  bool
	State connectorv1.WriteGateState
	// Unacknowledged counts blocking findings the request's override does not cover.
	Unacknowledged uint32
	VerificationID []byte
	// ByOverride: the gate is open only through the override's second branch (TM-D23 rule 9). Then
	// Acknowledged is the number of the run's blocking fingerprints the override covered and Listed
	// the number of fingerprints the override lists.
	ByOverride   bool
	Acknowledged int
	Listed       int
}

// Check evaluates the gate for a connection of the given kind. The conditions are checked in the
// order of the table in §8.2.
func (g *GateBook) Check(connectionID string, ad bool, ov *connectorv1.WriteGateOverride) Decision {
	g.mu.Lock()
	defer g.mu.Unlock()
	st := connectorv1.WriteGateState_WRITE_GATE_STATE_NOT_VERIFIED
	e, ok := g.conns[connectionID]
	if !ok {
		return Decision{State: st}
	}
	d := Decision{VerificationID: e.run.VerificationID}
	if g.now().Sub(e.run.CompletedAt) > MaxVerificationAge {
		d.State = connectorv1.WriteGateState_WRITE_GATE_STATE_STALE
		return d
	}
	if e.lrf {
		d.State = connectorv1.WriteGateState_WRITE_GATE_STATE_LOCAL_RECORD_FAILED
		return d
	}
	over, suff := connectorv1.VerificationCheck_VERIFICATION_CHECK_V7_OVER_PRIVILEGE, connectorv1.VerificationCheck_VERIFICATION_CHECK_V8_READ_SUFFICIENCY
	if !ad {
		over, suff = connectorv1.VerificationCheck_VERIFICATION_CHECK_EV3_OVER_PRIVILEGE, connectorv1.VerificationCheck_VERIFICATION_CHECK_EV4_SUFFICIENCY
	}
	if e.run.Checks[suff] == connectorv1.CheckOutcome_CHECK_OUTCOME_FAIL { // never overridable (FR-12)
		d.State = connectorv1.WriteGateState_WRITE_GATE_STATE_INSUFFICIENT
		return d
	}
	switch e.run.Checks[over] {
	case connectorv1.CheckOutcome_CHECK_OUTCOME_PASS, connectorv1.CheckOutcome_CHECK_OUTCOME_WARN:
		if e.run.Verdict == connectorv1.VerificationVerdict_VERIFICATION_VERDICT_FAILED {
			d.State = connectorv1.WriteGateState_WRITE_GATE_STATE_COULD_NOT_VERIFY
			return d
		}
		d.Open = true
		return d
	case connectorv1.CheckOutcome_CHECK_OUTCOME_FAIL:
		if e.run.Verdict == connectorv1.VerificationVerdict_VERIFICATION_VERDICT_FAILED {
			d.State = connectorv1.WriteGateState_WRITE_GATE_STATE_COULD_NOT_VERIFY
			return d
		}
		d.State = connectorv1.WriteGateState_WRITE_GATE_STATE_OVERPRIVILEGED
		listed := ov.GetAcknowledgedFingerprints()
		var unack uint32
		for _, f := range e.run.Blocking {
			if !containsBytes(listed, f) {
				unack++
			}
		}
		if len(e.run.Blocking) == 0 { // a FAIL that names nothing cannot be acknowledged
			d.Unacknowledged = 1
			return d
		}
		d.Unacknowledged = unack
		if unack == 0 {
			d.Open, d.ByOverride, d.Acknowledged, d.Listed = true, true, len(e.run.Blocking), len(listed)
			d.State = connectorv1.WriteGateState_WRITE_GATE_STATE_UNSPECIFIED
		}
		return d
	}
	d.State = connectorv1.WriteGateState_WRITE_GATE_STATE_COULD_NOT_VERIFY
	return d
}

func containsBytes(list [][]byte, b []byte) bool {
	for _, x := range list {
		if bytes.Equal(x, b) {
			return true
		}
	}
	return false
}

// Lookup returns the bases the connector's own set (the run's set plus the epoch's ratchet) holds
// for an object (CONNECTOR_SET, §8.3a).
func (g *GateBook) Lookup(connectionID string, id guid.GUID) []Basis {
	g.mu.Lock()
	defer g.mu.Unlock()
	e, ok := g.conns[connectionID]
	if !ok {
		return nil
	}
	k := id.String()
	seen := map[Basis]bool{}
	var out []Basis
	for _, b := range e.run.Set[k] {
		if !seen[b] {
			seen[b], out = true, append(out, b)
		}
	}
	for b := range e.ratchet[k] {
		if !seen[b] {
			seen[b], out = true, append(out, b)
		}
	}
	return out
}

// Designated returns every object the connector itself holds as a customer-designated group for the
// connection: the run's inputs and set, and the epoch's ratchet marks, with basis CUSTOMER_DESIGNATED.
// Step 7 and step 9 check membership of these as well as the request's own designations, so a server
// that omits a designation cannot unprotect a group the connector was already told about.
func (g *GateBook) Designated(connectionID string) []guid.GUID {
	g.mu.Lock()
	defer g.mu.Unlock()
	e, ok := g.conns[connectionID]
	if !ok {
		return nil
	}
	seen := map[guid.GUID]bool{}
	var out []guid.GUID
	add := func(id guid.GUID) {
		if !seen[id] {
			seen[id], out = true, append(out, id)
		}
	}
	for _, m := range e.run.Inputs {
		if m.Basis == designatedBasis {
			add(m.Object)
		}
	}
	for k, bases := range e.run.Set {
		for _, b := range bases {
			if b == designatedBasis {
				if id, err := guid.Parse(k); err == nil {
					add(id)
				}
			}
		}
	}
	for _, byBasis := range e.ratchet {
		if m, ok := byBasis[designatedBasis]; ok {
			add(m.Object)
		}
	}
	return out
}

// Ratchet adds marks to the epoch's set. Every mark whose basis is CUSTOMER_DESIGNATED, C16 or E5
// that is new to the epoch is appended to the durable baseline before Ratchet returns. When the
// append fails the gate closes with LOCAL_RECORD_FAILED and the error is returned; the in-memory
// marks are kept either way, because adding protection is always the fail-closed direction.
func (g *GateBook) Ratchet(connectionID string, marks []Mark) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	e, ok := g.conns[connectionID]
	if !ok {
		return nil
	}
	var fresh []Mark
	for _, m := range marks {
		if _, dup := e.ratchet[m.Object.String()][m.Basis]; dup {
			continue
		}
		e.put(m)
		fresh = append(fresh, m)
	}
	if len(fresh) == 0 {
		return nil
	}
	if err := g.base.Append(connectionID, fresh); err != nil {
		e.lrf = true
		return err
	}
	return nil
}

// FileBaseline appends marks as JSON lines to one file, readable and writable by the connector's
// service identity only (mode 0600), and syncs it before returning. It holds identifiers only.
type FileBaseline struct {
	mu   sync.Mutex
	Path string
}

type baselineLine struct {
	Connection string    `json:"connection"`
	Object     string    `json:"object"`
	Basis      string    `json:"basis"`
	Source     string    `json:"source"`
	Revision   uint64    `json:"tier0_revision,omitempty"`
	At         time.Time `json:"at"`
}

// Append implements Baseline.
func (f *FileBaseline) Append(connectionID string, marks []Mark) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	fh, err := os.OpenFile(f.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	for _, m := range marks {
		line, err := json.Marshal(baselineLine{Connection: connectionID, Object: m.Object.String(), Basis: m.Basis.String(),
			Source: m.Source, Revision: m.Revision, At: time.Now().UTC()}, json.Deterministic(true))
		if err == nil {
			_, err = fh.Write(append(line, '\n'))
		}
		if err != nil {
			_ = fh.Close()
			return err
		}
	}
	if err := fh.Sync(); err != nil {
		_ = fh.Close()
		return err
	}
	return fh.Close()
}
