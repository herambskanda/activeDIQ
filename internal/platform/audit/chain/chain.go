// Package chain is the pure part of the audit trail's tamper evidence (ADR-0005 rule 11): the event
// envelope and its canonical form, the hash links, the signed checkpoint statement, the export bundle
// and the verifier. It imports only the standard library and canon, because cmd/auditverify links it:
// the server that writes the chain and the binary an auditor runs offline share one definition.
package chain

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit/canon"
)

// HashSize is the length of every chain hash.
const HashSize = sha256.Size

// Hash is a SHA-256 value.
type Hash [HashSize]byte

// Domain strings (ADR-0005 rule 11).
const (
	linkDomain       = "adq-audit-chain/1"
	genesisDomain    = "adq-audit-genesis/1"
	checkpointDomain = "adq-audit-checkpoint/1"
)

// Event kinds the chain itself defines. The verifier needs them to learn the checkpoint keys' windows.
const (
	KindKeyCreated   = "audit.checkpoint_key.created"
	KindKeyRetired   = "audit.checkpoint_key.retired"
	KindTenantInited = "audit.tenant.initialised"
)

// Genesis returns hash_0 for a tenant: SHA-256("adq-audit-genesis/1" ‖ 0x00 ‖ tenant_id). The same value
// is recomputed in SQL by the audit_head genesis trigger.
func Genesis(tenant [16]byte) Hash {
	h := sha256.New()
	h.Write([]byte(genesisDomain))
	h.Write([]byte{0})
	h.Write(tenant[:])
	return Hash(h.Sum(nil))
}

// BodyHash is SHA-256 of the canonical envelope (which carries neither prev_hash nor hash).
func BodyHash(envelope []byte) Hash { return sha256.Sum256(envelope) }

// Link returns hash_n = SHA-256("adq-audit-chain/1" ‖ 0x00 ‖ tenant_id ‖ uint64be(seq) ‖ hash_{n-1} ‖ body_hash).
// Tenant and seq are inside every link, so an event cannot be moved to another tenant or position.
func Link(tenant [16]byte, seq uint64, prev, body Hash) Hash {
	h := sha256.New()
	h.Write([]byte(linkDomain))
	h.Write([]byte{0})
	h.Write(tenant[:])
	var s [8]byte
	binary.BigEndian.PutUint64(s[:], seq)
	h.Write(s[:])
	h.Write(prev[:])
	h.Write(body[:])
	return Hash(h.Sum(nil))
}

// Principal is one subject of the actor chain.
type Principal struct {
	ID   string
	Kind string
}

// Change is one changed attribute. Values are personal data and live outside the chain (ADR-0005 rule
// 12); the chain records which attribute changed, whether it is a secret, and how many values moved.
type Change struct {
	Attribute   string
	Secret      bool
	BeforeCount uint64
	AfterCount  uint64
	// Before and After hold one Ref per value, in value order, when the values were kept by reference
	// (T-0306). They hold commitments only; the hash covers them, so erasing a subject changes nothing.
	Before []Ref
	After  []Ref
}

// Ref is the chained form of a personal.Ref: the subject, the value ID, the field and the commitment.
// Its encoding is byte-identical to personal.Ref.Canonical.
type Ref struct {
	Subject    string
	ValueID    [16]byte
	Field      string
	Commitment [32]byte
}

// Bytes returns the adq-canon/1 encoding of the ref.
func (r Ref) Bytes() ([]byte, error) {
	var e canon.Encoder
	e.String(1, r.Subject)
	e.UUID(2, r.ValueID)
	e.String(3, r.Field)
	e.Bytes(4, r.Commitment[:])
	return e.Result()
}

// Detail is one typed public detail of an event, kept in key order.
type Detail struct{ Key, Value string }

// Envelope is the chained form of an event (AG-3). It never holds a clear personal value.
type Envelope struct {
	Tenant      [16]byte
	Seq         uint64
	At          time.Time
	EventID     string
	Kind        string
	KindVersion uint64
	Requester   Principal
	Via         []Principal
	Component   string
	Connection  string
	TargetGUID  string
	TargetClass string
	Parent      string
	Operation   string
	Item        uint64
	Step        uint64
	HasStep     bool // Item and Step are meaningful (zero is a valid index)
	Outcome     string
	Reason      string
	PlanHash    string
	Changes     []Change
	Details     []Detail
	Snapshots   []Ref // display snapshots (a name or similar as it read at the time), by reference
}

// Field tags of the envelope. They are part of the format and never reused.
const (
	tTenant = iota + 1
	tSeq
	tAt
	tEventID
	tKind
	tKindVersion
	tRequester
	tVia
	tComponent
	tConnection
	tTargetGUID
	tTargetClass
	tParent
	tOperation
	tItem
	tStep
	tOutcome
	tReason
	tPlanHash
	tChanges
	tDetails
	tSnapshots
)

func principalBytes(p Principal) ([]byte, error) {
	var e canon.Encoder
	e.String(1, p.ID)
	e.String(2, p.Kind)
	return e.Result()
}

// Marshal returns the adq-canon/1 form of the envelope.
func (v Envelope) Marshal() ([]byte, error) {
	var e canon.Encoder
	e.UUID(tTenant, v.Tenant)
	e.Uint(tSeq, v.Seq)
	e.Time(tAt, v.At)
	if v.EventID != "" {
		e.String(tEventID, v.EventID)
	}
	e.String(tKind, v.Kind)
	e.Uint(tKindVersion, max(v.KindVersion, 1))
	req, err := principalBytes(v.Requester)
	if err != nil {
		return nil, err
	}
	e.Message(tRequester, req)
	if len(v.Via) > 0 {
		var items [][]byte
		for _, p := range v.Via {
			b, err := principalBytes(p)
			if err != nil {
				return nil, err
			}
			items = append(items, b)
		}
		e.List(tVia, items)
	}
	optString(&e, tComponent, v.Component)
	optString(&e, tConnection, v.Connection)
	optString(&e, tTargetGUID, v.TargetGUID)
	optString(&e, tTargetClass, v.TargetClass)
	optString(&e, tParent, v.Parent)
	optString(&e, tOperation, v.Operation)
	if v.HasStep {
		e.Uint(tItem, v.Item)
		e.Uint(tStep, v.Step)
	}
	e.String(tOutcome, v.Outcome)
	optString(&e, tReason, v.Reason)
	optString(&e, tPlanHash, v.PlanHash)
	if len(v.Changes) > 0 {
		var items [][]byte
		for _, c := range v.Changes {
			var ce canon.Encoder
			ce.String(1, c.Attribute)
			if c.Secret {
				ce.Uint(2, 1)
			}
			ce.Uint(3, c.BeforeCount)
			ce.Uint(4, c.AfterCount)
			if err := putRefs(&ce, 5, c.Before); err != nil {
				return nil, err
			}
			if err := putRefs(&ce, 6, c.After); err != nil {
				return nil, err
			}
			b, err := ce.Result()
			if err != nil {
				return nil, err
			}
			items = append(items, b)
		}
		e.List(tChanges, items)
	}
	if len(v.Details) > 0 {
		var items [][]byte
		for i, d := range v.Details {
			if i > 0 && v.Details[i-1].Key >= d.Key {
				return nil, errors.New("chain: details must be in strictly increasing key order")
			}
			var de canon.Encoder
			de.String(1, d.Key)
			de.String(2, d.Value)
			b, err := de.Result()
			if err != nil {
				return nil, err
			}
			items = append(items, b)
		}
		e.List(tDetails, items)
	}
	if err := putRefs(&e, tSnapshots, v.Snapshots); err != nil {
		return nil, err
	}
	return e.Result()
}

func putRefs(e *canon.Encoder, tag uint64, refs []Ref) error {
	if len(refs) == 0 {
		return nil
	}
	items := make([][]byte, 0, len(refs))
	for _, r := range refs {
		b, err := r.Bytes()
		if err != nil {
			return err
		}
		items = append(items, b)
	}
	e.List(tag, items)
	return nil
}

func parseRefs(b []byte) ([]Ref, error) {
	items, err := canon.AsList(b)
	if err != nil {
		return nil, err
	}
	var out []Ref
	for _, it := range items {
		fs, err := canon.Decode(it)
		if err != nil {
			return nil, err
		}
		var r Ref
		for _, f := range fs {
			switch f.Tag {
			case 1:
				r.Subject, err = canon.AsString(f.Value)
			case 2:
				r.ValueID, err = canon.AsUUID(f.Value)
			case 3:
				r.Field, err = canon.AsString(f.Value)
			case 4:
				if len(f.Value) != len(r.Commitment) {
					err = fmt.Errorf("%w: commitment length", canon.ErrNonCanonical)
				} else {
					copy(r.Commitment[:], f.Value)
				}
			default:
				err = fmt.Errorf("%w: unknown ref tag %d", canon.ErrNonCanonical, f.Tag)
			}
			if err != nil {
				return nil, err
			}
		}
		out = append(out, r)
	}
	return out, nil
}

func optString(e *canon.Encoder, tag uint64, s string) {
	if s != "" {
		e.String(tag, s)
	}
}

func parsePrincipal(b []byte) (Principal, error) {
	fs, err := canon.Decode(b)
	if err != nil {
		return Principal{}, err
	}
	var p Principal
	if v, ok := canon.Get(fs, 1); ok {
		if p.ID, err = canon.AsString(v); err != nil {
			return p, err
		}
	}
	if v, ok := canon.Get(fs, 2); ok {
		if p.Kind, err = canon.AsString(v); err != nil {
			return p, err
		}
	}
	return p, nil
}

// ParseEnvelope decodes the canonical form, refusing non-canonical input and any unknown tag. It also
// re-marshals the result and requires the same bytes, so one envelope has exactly one encoding.
func ParseEnvelope(b []byte) (Envelope, error) {
	fs, err := canon.Decode(b)
	if err != nil {
		return Envelope{}, err
	}
	var v Envelope
	var hasItem, hasStep bool
	for _, f := range fs {
		switch f.Tag {
		case tTenant:
			v.Tenant, err = canon.AsUUID(f.Value)
		case tSeq:
			v.Seq, err = canon.AsUint(f.Value)
		case tAt:
			v.At, err = canon.AsTime(f.Value)
		case tEventID:
			v.EventID, err = canon.AsString(f.Value)
		case tKind:
			v.Kind, err = canon.AsString(f.Value)
		case tKindVersion:
			v.KindVersion, err = canon.AsUint(f.Value)
		case tRequester:
			v.Requester, err = parsePrincipal(f.Value)
		case tVia:
			var items [][]byte
			if items, err = canon.AsList(f.Value); err == nil {
				for _, it := range items {
					var p Principal
					if p, err = parsePrincipal(it); err != nil {
						break
					}
					v.Via = append(v.Via, p)
				}
			}
		case tComponent:
			v.Component, err = canon.AsString(f.Value)
		case tConnection:
			v.Connection, err = canon.AsString(f.Value)
		case tTargetGUID:
			v.TargetGUID, err = canon.AsString(f.Value)
		case tTargetClass:
			v.TargetClass, err = canon.AsString(f.Value)
		case tParent:
			v.Parent, err = canon.AsString(f.Value)
		case tOperation:
			v.Operation, err = canon.AsString(f.Value)
		case tItem:
			v.Item, err = canon.AsUint(f.Value)
			hasItem = true
		case tStep:
			v.Step, err = canon.AsUint(f.Value)
			hasStep = true
		case tOutcome:
			v.Outcome, err = canon.AsString(f.Value)
		case tReason:
			v.Reason, err = canon.AsString(f.Value)
		case tPlanHash:
			v.PlanHash, err = canon.AsString(f.Value)
		case tChanges:
			v.Changes, err = parseChanges(f.Value)
		case tDetails:
			v.Details, err = parseDetails(f.Value)
		case tSnapshots:
			v.Snapshots, err = parseRefs(f.Value)
		default:
			err = fmt.Errorf("%w: unknown tag %d", canon.ErrNonCanonical, f.Tag)
		}
		if err != nil {
			return Envelope{}, err
		}
	}
	if hasItem != hasStep {
		return Envelope{}, fmt.Errorf("%w: item without step", canon.ErrNonCanonical)
	}
	v.HasStep = hasItem
	again, err := v.Marshal()
	if err != nil || string(again) != string(b) {
		return Envelope{}, fmt.Errorf("%w: envelope does not re-encode to itself", canon.ErrNonCanonical)
	}
	return v, nil
}

func parseChanges(b []byte) ([]Change, error) {
	items, err := canon.AsList(b)
	if err != nil {
		return nil, err
	}
	var out []Change
	for _, it := range items {
		fs, err := canon.Decode(it)
		if err != nil {
			return nil, err
		}
		var c Change
		for _, f := range fs {
			switch f.Tag {
			case 1:
				c.Attribute, err = canon.AsString(f.Value)
			case 2:
				var n uint64
				n, err = canon.AsUint(f.Value)
				c.Secret = n == 1
			case 3:
				c.BeforeCount, err = canon.AsUint(f.Value)
			case 4:
				c.AfterCount, err = canon.AsUint(f.Value)
			case 5:
				c.Before, err = parseRefs(f.Value)
			case 6:
				c.After, err = parseRefs(f.Value)
			default:
				err = fmt.Errorf("%w: unknown change tag %d", canon.ErrNonCanonical, f.Tag)
			}
			if err != nil {
				return nil, err
			}
		}
		out = append(out, c)
	}
	return out, nil
}

func parseDetails(b []byte) ([]Detail, error) {
	items, err := canon.AsList(b)
	if err != nil {
		return nil, err
	}
	var out []Detail
	for _, it := range items {
		fs, err := canon.Decode(it)
		if err != nil {
			return nil, err
		}
		var d Detail
		for _, f := range fs {
			switch f.Tag {
			case 1:
				d.Key, err = canon.AsString(f.Value)
			case 2:
				d.Value, err = canon.AsString(f.Value)
			default:
				err = fmt.Errorf("%w: unknown detail tag %d", canon.ErrNonCanonical, f.Tag)
			}
			if err != nil {
				return nil, err
			}
		}
		out = append(out, d)
	}
	return out, nil
}

// Detail returns the value of the named detail.
func (v Envelope) Detail(key string) (string, bool) {
	for _, d := range v.Details {
		if d.Key == key {
			return d.Value, true
		}
	}
	return "", false
}
