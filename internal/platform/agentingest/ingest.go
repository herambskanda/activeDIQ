// Package agentingest stores the records an addc agent appends. The one rule it exists to keep is S1
// (agent-host contract §2, TM-D24): the tenant, the component and the kind of a record are stamped from
// the verified client certificate, and nothing in the payload can name or override them. The Batch type
// has no field for any of the three, so there is nothing to ignore by convention; the request cannot
// carry them.
//
// The agent's own gapless agent_seq makes redelivery idempotent: a record already stored is counted as
// a duplicate and left untouched (the table is append-only). Gaps and drops the agent reports are
// stored as records of their own type, so a hole in the trail is itself visible.
package agentingest

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"math"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/audit/chain"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/fleet"
	"github.com/skenzeriq/activediq/internal/platform/fleet/fleetsql"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tablekind"
)

var _ = tablekind.Declare(tablekind.Table{Name: "public.agent_event", Entity: "DM-89", Kind: tablekind.Tenant, AppendOnly: true})

// Bounds (contract §3 and the table's checks).
const (
	MaxBatchRecords = 1000
	MaxFieldsBytes  = 64 << 10
	// maxEncodedFields leaves room for jsonb::text re-rendering (extra separator spaces) under the column CHECK.
	maxEncodedFields = MaxFieldsBytes - 4096
	maxKeyRunes      = 32
	// The agent's FILETIME clock spans 1601..30828; the server accepts 1601..9999, which timestamptz stores.
	minObservedYear = 1601
	maxObservedYear = 9999
	maxFieldKeys    = 64
)

// Record types.
const (
	TypeEvent   = "event"
	TypeGap     = "gap"
	TypeDropped = "dropped"
)

// AlertDCGUIDMismatch is raised when the DC GUID an agent reports is not the one the server's
// replication metadata attributes to the host (contract §2 note on S1).
const AlertDCGUIDMismatch fleetsql.AlertKind = "agentfleet.event.dc_guid_mismatch"

// AlertSeqDivergence is raised when an agent redelivers an agent_seq that is already stored with
// different content: the agent's state went backwards (snapshot or backup restore under the same
// certificate) and its new events reuse old sequence numbers. The stored row is never replaced.
const AlertSeqDivergence fleetsql.AlertKind = "agentfleet.event.seq_divergence"

// SanitizedKey names the field that lists the keys whose content was repaired (NUL bytes and invalid
// UTF-8 replaced by U+FFFD) so the record could be stored. An agent-supplied value under this key is
// overwritten.
const SanitizedKey = "_sanitized"

// TruncatedKey names the field that lists the keys whose value was cut to fit the stored size bound.
// Like SanitizedKey, one the agent sent is replaced.
const TruncatedKey = "_truncated"

// Audit kind of an accepted batch. Details carry counts and the highest sequence only.
const KindBatchAccepted audit.Kind = "agentfleet.events.accepted"

// KindSeqDivergence is audited when redelivered sequences differ from what is stored.
const KindSeqDivergence audit.Kind = "agentfleet.events.seq_divergence"

var (
	// ErrNoIdentity: the call had no client-certificate identity. The gateway guarantees one for every
	// authenticated method; a missing one is a wiring bug and fails closed.
	ErrNoIdentity = errors.New("agentingest: no authenticated identity")
	// ErrWrongKind: the certificate belongs to another module's component.
	ErrWrongKind = errors.New("agentingest: certificate is not an addc component")
	// ErrInvalid: the batch is outside its bounds. Nothing is stored.
	ErrInvalid = errors.New("agentingest: invalid batch")
	// ErrSeqDivergence: an agent_seq was redelivered with different content. The other records of the
	// batch are stored; the diverging ones are not, and an operator alert is raised. Match with
	// errors.As on *DivergenceError for the sequences.
	ErrSeqDivergence = errors.New("agentingest: agent_seq redelivered with different content")
	ErrNotConfigured = errors.New("agentingest: not configured")
)

// DivergenceError names the agent_seq values that diverged from what is stored.
type DivergenceError struct{ Seqs []uint64 }

func (e *DivergenceError) Error() string {
	return fmt.Sprintf("%v: agent_seq %v", ErrSeqDivergence, e.Seqs)
}
func (e *DivergenceError) Unwrap() error { return ErrSeqDivergence }

// Record is one appended item. It deliberately carries no tenant, component or kind.
type Record struct {
	AgentSeq      uint64
	Type          string
	Channel       string // "security" or "directory_service"; empty for gap and dropped
	EventRecordID *uint64
	ObservedAt    time.Time
	// ReportedDCGUID is what the agent says about its host. It is data to cross-check, never identity.
	ReportedDCGUID string
	Fields         map[string]string
}

// Batch is one AppendEvents call's payload.
type Batch struct{ Records []Record }

// Result counts what a batch did.
type Result struct {
	Accepted   int
	Duplicates int
	// Diverged lists redelivered sequences whose content differs from the stored row (ErrSeqDivergence).
	Diverged []uint64
	// HighestSeq is the highest agent_seq now stored for the component, which the agent may prune up to.
	HighestSeq uint64
}

// DCClaims confirms a reported DC GUID against the server's own knowledge of the host. It is optional:
// without it no cross-check runs (the data source lands with the DC observation table).
type DCClaims interface {
	Matches(ctx context.Context, tx store.Tx, id fleet.Identity, reportedDCGUID string) (bool, error)
}

// Alerter raises operator alerts.
type Alerter interface {
	Raise(ctx context.Context, a fleetsql.Alert)
}

// Ingester stores batches.
type Ingester struct {
	DB     *store.DB
	Audit  audit.Sink
	Alerts Alerter  // optional
	Claims DCClaims // optional
	Clock  func() time.Time
}

// AppendAuthenticated is the entry point for a handler: the identity is read from the context the
// gateway built, never from the request.
func (g *Ingester) AppendAuthenticated(ctx context.Context, b Batch) (Result, error) {
	id, ok := fleet.IdentityFrom(ctx)
	if !ok {
		return Result{}, ErrNoIdentity
	}
	return g.Append(ctx, id, b)
}

// Append stores b for the component id names.
func (g *Ingester) Append(ctx context.Context, id fleet.Identity, b Batch) (Result, error) {
	if g == nil || g.DB == nil || g.Audit == nil {
		return Result{}, ErrNotConfigured
	}
	if id.Kind != fleet.KindADDC || id.Tenant.IsZero() {
		return Result{}, ErrWrongKind
	}
	prepared, err := prepare(b)
	if err != nil {
		return Result{}, err
	}
	var res Result
	var mismatch bool
	var first, last uint64
	err = g.DB.WithTenant(ctx, id.Tenant, func(ctx context.Context, tx store.Tx) error {
		res, mismatch, first, last = Result{}, false, 0, 0
		for _, p := range prepared {
			r, fields := p.rec, p.fields
			var dc any
			if r.ReportedDCGUID != "" {
				dc = r.ReportedDCGUID
				if g.Claims != nil {
					ok, err := g.Claims.Matches(ctx, tx, id, r.ReportedDCGUID)
					if err != nil {
						return fmt.Errorf("agentingest: dc cross-check: %w", err)
					}
					mismatch = mismatch || !ok
				}
			}
			var channel any
			if r.Channel != "" {
				channel = r.Channel
			}
			var rid any
			if r.EventRecordID != nil {
				rid = int64(*r.EventRecordID)
			}
			tag, err := tx.Exec(ctx, `INSERT INTO public.agent_event
				(tenant_id, component_id, agent_seq, record_type, channel, event_record_id, observed_at, reported_dc_guid, fields, content_sha256)
				VALUES ($1, $2::uuid, $3, $4, $5, $6, $7, $8::uuid, $9::jsonb, $10)
				ON CONFLICT (tenant_id, component_id, agent_seq) DO NOTHING`,
				id.Tenant.String(), id.ComponentID, int64(r.AgentSeq), r.Type, channel, rid, r.ObservedAt.UTC(), dc, string(fields), p.hash[:])
			if err != nil {
				return fmt.Errorf("agentingest: store record: %w", err)
			}
			if tag.RowsAffected() == 1 {
				res.Accepted++
				if first == 0 {
					first = r.AgentSeq
				}
				last = r.AgentSeq
				continue
			}
			// Already stored: a duplicate only if it is the same record.
			var stored []byte
			if err := tx.QueryRow(ctx, `SELECT content_sha256 FROM public.agent_event WHERE component_id = $1::uuid AND agent_seq = $2`,
				id.ComponentID, int64(r.AgentSeq)).Scan(&stored); err != nil {
				return fmt.Errorf("agentingest: read stored record: %w", err)
			}
			if string(stored) == string(p.hash[:]) {
				res.Duplicates++
			} else {
				res.Diverged = append(res.Diverged, r.AgentSeq)
			}
		}
		var hi int64
		if err := tx.QueryRow(ctx, `SELECT COALESCE(max(agent_seq), 0) FROM public.agent_event WHERE component_id = $1::uuid`, id.ComponentID).Scan(&hi); err != nil {
			return fmt.Errorf("agentingest: read high-water mark: %w", err)
		}
		res.HighestSeq = uint64(hi)
		if res.Accepted == 0 && len(res.Diverged) == 0 {
			return nil
		}
		now := time.Now().UTC()
		if g.Clock != nil {
			now = g.Clock().UTC()
		}
		actor := authority.Chain{Requester: authority.Principal{ID: authority.PrincipalID("component:" + id.ComponentID), Kind: authority.System}}
		target := authority.TargetRef{GUID: id.ComponentID, Class: "component"}
		if res.Accepted > 0 {
			// The accepted range identifies the batch: a batch that fills sequences below the current
			// maximum must not reuse the ID of an earlier one (the chainer refuses a reused ID).
			if err := g.Audit.Append(ctx, tx, audit.Event{
				ID:   fmt.Sprintf("%s.%s.%d-%d", KindBatchAccepted, id.ComponentID, first, last),
				Kind: KindBatchAccepted, At: now, Actor: actor, Target: target,
				Component: "agentfleet", Outcome: audit.Success,
				Details: []chain.Detail{ // key order is required by the chain
					{Key: "accepted", Value: fmt.Sprint(res.Accepted)}, {Key: "diverged", Value: fmt.Sprint(len(res.Diverged))},
					{Key: "duplicates", Value: fmt.Sprint(res.Duplicates)}, {Key: "first_seq", Value: fmt.Sprint(first)},
					{Key: "highest_seq", Value: fmt.Sprint(res.HighestSeq)}, {Key: "last_seq", Value: fmt.Sprint(last)}},
			}); err != nil {
				return err
			}
		}
		if len(res.Diverged) == 0 {
			return nil
		}
		// A DC state rollback is a tamper signal. The agent redelivers the same head until an operator
		// acts, so every attempt is its own event: the timestamp keeps the ID unique.
		return g.Audit.Append(ctx, tx, audit.Event{
			ID:   fmt.Sprintf("%s.%s.%d-%d.%d", KindSeqDivergence, id.ComponentID, res.Diverged[0], res.Diverged[len(res.Diverged)-1], now.UnixNano()),
			Kind: KindSeqDivergence, At: now, Actor: actor, Target: target,
			Component: "agentfleet", Outcome: audit.Failure,
			Details: []chain.Detail{
				{Key: "diverged", Value: fmt.Sprint(len(res.Diverged))}, {Key: "first_seq", Value: fmt.Sprint(res.Diverged[0])},
				{Key: "highest_seq", Value: fmt.Sprint(res.HighestSeq)}, {Key: "last_seq", Value: fmt.Sprint(res.Diverged[len(res.Diverged)-1])}},
		})
	})
	if err != nil {
		return Result{}, err
	}
	if mismatch && g.Alerts != nil {
		g.Alerts.Raise(ctx, fleetsql.Alert{Kind: AlertDCGUIDMismatch, Tenant: id.Tenant, Component: id.ComponentID})
	}
	if len(res.Diverged) > 0 {
		if g.Alerts != nil {
			g.Alerts.Raise(ctx, fleetsql.Alert{Kind: AlertSeqDivergence, Tenant: id.Tenant, Component: id.ComponentID})
		}
		return res, &DivergenceError{Seqs: res.Diverged}
	}
	return res, nil
}

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type prepared struct {
	rec    Record
	fields []byte
	hash   [sha256.Size]byte
}

// prepare validates the batch and makes every record storable: text the database cannot hold (NUL, invalid
// UTF-8 including lone surrogates) is repaired deterministically instead of failing the batch, because a
// record the server refuses is redelivered forever and would stop event collection from that DC. Repaired
// keys are listed under SanitizedKey. Nothing is stored here.
func prepare(b Batch) ([]prepared, error) {
	if len(b.Records) == 0 || len(b.Records) > MaxBatchRecords {
		return nil, fmt.Errorf("%w: record count", ErrInvalid)
	}
	out := make([]prepared, 0, len(b.Records))
	var prev uint64
	for i, r := range b.Records {
		if r.AgentSeq == 0 || r.AgentSeq > math.MaxInt64 || (i > 0 && r.AgentSeq <= prev) {
			return nil, fmt.Errorf("%w: agent_seq %d must be in 1..2^63-1 and strictly increasing", ErrInvalid, r.AgentSeq)
		}
		prev = r.AgentSeq
		switch r.Type {
		case TypeEvent:
			if r.Channel != "security" && r.Channel != "directory_service" {
				return nil, fmt.Errorf("%w: agent_seq %d: channel", ErrInvalid, r.AgentSeq)
			}
		case TypeGap, TypeDropped:
			if r.Channel != "" && r.Channel != "security" && r.Channel != "directory_service" {
				return nil, fmt.Errorf("%w: agent_seq %d: channel", ErrInvalid, r.AgentSeq)
			}
		default:
			return nil, fmt.Errorf("%w: agent_seq %d: record type", ErrInvalid, r.AgentSeq)
		}
		if y := r.ObservedAt.UTC().Year(); r.ObservedAt.IsZero() || y < minObservedYear || y > maxObservedYear {
			return nil, fmt.Errorf("%w: agent_seq %d: observed_at outside %d..%d", ErrInvalid, r.AgentSeq, minObservedYear, maxObservedYear)
		}
		if r.EventRecordID != nil && *r.EventRecordID > 1<<62 {
			return nil, fmt.Errorf("%w: agent_seq %d: event_record_id", ErrInvalid, r.AgentSeq)
		}
		if r.ReportedDCGUID != "" && !uuidRE.MatchString(r.ReportedDCGUID) {
			return nil, fmt.Errorf("%w: agent_seq %d: reported_dc_guid", ErrInvalid, r.AgentSeq)
		}
		if len(r.Fields) > maxFieldKeys {
			return nil, fmt.Errorf("%w: agent_seq %d: fields", ErrInvalid, r.AgentSeq)
		}
		fields, enc, err := fitFields(sanitizeFields(r.Fields))
		if err != nil {
			return nil, fmt.Errorf("%w: agent_seq %d: fields: %v", ErrInvalid, r.AgentSeq, err)
		}
		r.Fields = fields
		out = append(out, prepared{rec: r, fields: enc, hash: contentHash(r, fields)})
	}
	return out, nil
}

// sanitizeFields returns fields with NUL and invalid UTF-8 replaced by U+FFFD in keys and values. Keys
// that collide after repair get a "#n" suffix so no value is lost. The repaired keys are listed (sorted,
// comma-separated) under SanitizedKey; a SanitizedKey the agent sent is replaced.
func sanitizeFields(in map[string]string) map[string]string {
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	out := make(map[string]string, len(in)+1)
	var repaired []string
	for _, k := range keys {
		if k == SanitizedKey || k == TruncatedKey {
			continue
		}
		nk, kc := repair(k)
		if r := []rune(nk); len(r) > maxKeyRunes {
			nk, kc = string(r[:maxKeyRunes]), true
		}
		nv, vc := repair(in[k])
		if _, taken := out[nk]; taken || nk == SanitizedKey || nk == TruncatedKey {
			for n := 2; ; n++ {
				c := fmt.Sprintf("%s#%d", nk, n)
				if _, t := out[c]; !t && c != SanitizedKey && c != TruncatedKey {
					nk = c
					break
				}
			}
			kc = true
		}
		out[nk] = nv
		if kc || vc {
			repaired = append(repaired, nk)
		}
	}
	if len(repaired) > 0 {
		out[SanitizedKey] = strings.Join(repaired, ",")
	}
	return out
}

// fitFields encodes fields and, if the encoding exceeds the stored bound (control characters escape to six
// bytes each), halves the largest values until it fits, listing the cut keys under TruncatedKey. The record
// is always stored; it is never refused for size. Keys are bounded, so the loop terminates.
func fitFields(fields map[string]string) (map[string]string, []byte, error) {
	var cut []string
	for {
		enc, err := json.Marshal(fields)
		if err != nil {
			return nil, nil, err
		}
		if len(enc) <= maxEncodedFields {
			return fields, enc, nil
		}
		big, bigLen := "", 0
		for _, k := range slices.Sorted(maps.Keys(fields)) {
			if k == SanitizedKey || k == TruncatedKey {
				continue
			}
			if n := len(fields[k]); n > bigLen {
				big, bigLen = k, n
			}
		}
		if bigLen == 0 {
			return nil, nil, errors.New("keys alone exceed the size bound")
		}
		// Halve by encoded weight: control characters cost six bytes, so cut on runes, not bytes.
		r := []rune(fields[big])
		fields[big] = string(r[:len(r)/2])
		if !slices.Contains(cut, big) {
			cut = append(cut, big)
			slices.Sort(cut)
			fields[TruncatedKey] = strings.Join(cut, ",")
		}
	}
}

func repair(s string) (string, bool) {
	if !strings.ContainsRune(s, 0) && utf8Valid(s) {
		return s, false
	}
	s = strings.ToValidUTF8(s, "\uFFFD")
	return strings.ReplaceAll(s, "\x00", "\uFFFD"), true
}

func utf8Valid(s string) bool { return strings.ToValidUTF8(s, "") == s }

// contentHash is a canonical digest of everything the agent supplied for a record (not the identity the
// server stamps), so a redelivery can be told from a different record that reuses the sequence.
func contentHash(r Record, fields map[string]string) [sha256.Size]byte {
	h := sha256.New()
	w := func(s string) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(s)))
		h.Write(n[:])
		h.Write([]byte(s))
	}
	w(r.Type)
	w(r.Channel)
	if r.EventRecordID != nil {
		w(fmt.Sprint(*r.EventRecordID))
	} else {
		w("-")
	}
	w(r.ObservedAt.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano)) // timestamptz keeps microseconds
	w(r.ReportedDCGUID)
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		w(k)
		w(fields[k])
	}
	var sum [sha256.Size]byte
	h.Sum(sum[:0])
	return sum
}
