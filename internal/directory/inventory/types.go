package inventory

import (
	"errors"
	"regexp"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/tablekind"
)

var _ = tablekind.Declare(tablekind.Table{Name: "public.correlations", Entity: "DM-20", Kind: tablekind.Directory})

var _ = tablekind.Declare(tablekind.Table{Name: "public.tier0_designations", Entity: "DM-16", Kind: tablekind.Directory})

var _ = tablekind.Declare(tablekind.Table{Name: "public.links", Entity: "DM-17", Kind: tablekind.Directory})

// Typed errors. None carries a value from the directory or the database.
var (
	// ErrInvalid is a malformed reference.
	ErrInvalid = errors.New("inventory: invalid reference")
	// ErrNoTenant: the call named no tenant.
	ErrNoTenant = errors.New("inventory: no tenant")
	// ErrNotConfigured: the reader has no database or no group source.
	ErrNotConfigured = errors.New("inventory: not configured")
	// ErrTooMany: a result exceeded its bound. Nothing is returned, because a truncated answer is
	// an omission (contract §8.3 F6).
	ErrTooMany = errors.New("inventory: result exceeds the bound")
	// ErrCorrupt: a stored value is outside the declared domain. Fail closed.
	ErrCorrupt = errors.New("inventory: stored value outside its domain")
)

// ConnectionID is a DM-10 connection's ID, canonical lower-case UUID text.
type ConnectionID string

// GUID is a directory object's objectGUID (AD) or id (Entra) in canonical lower-case UUID text.
type GUID string

var uuidText = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func canon(s string) (string, bool) {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'F' {
			b[i] = c + 32
		}
	}
	l := string(b)
	return l, uuidText.MatchString(l) && l != "00000000-0000-0000-0000-000000000000"
}

// Ref is an object of one connection: identity is the GUID (X3).
type Ref struct {
	Connection ConnectionID
	Object     GUID
}

// Valid reports whether both parts are canonical non-nil UUIDs.
func (r Ref) Valid() bool {
	_, a := canon(string(r.Connection))
	_, b := canon(string(r.Object))
	return a && b && string(r.Connection) == lower(string(r.Connection)) && string(r.Object) == lower(string(r.Object))
}

func lower(s string) string { c, _ := canon(s); return c }

// State is a DM-20 state. removed is stored but never read out.
type State string

// The states a read returns, and the one it never does.
const (
	StateCandidate State = "candidate"
	StateMatched   State = "matched"
	StateBroken    State = "broken"
	StateRemoved   State = "removed"
)

// Match is how a correlation was made (DM-20.I1).
type Match string

// The two ways.
const (
	MatchAnchor Match = "anchor"
	MatchSID    Match = "sid"
)

// Reason is DM-20 candidate_reason; empty unless the state is candidate.
type Reason string

// Basis is a tier0 basis code of threat-model §6.4.
type Basis string

// Bases supplied by or stored for the cross-directory checks.
const (
	BasisC16        Basis = "C16"
	BasisE5         Basis = "E5"
	BasisDesignated Basis = "designated"
)

// Link is one correlation as seen from one of its objects (Self): the other object is Peer.
type Link struct {
	ID    string
	Self  Ref
	Peer  Ref
	State State
	// PeerKind is "entra_tenant" when Self is the AD object, "ad_forest" when it is the Entra object.
	PeerKind string
	Reason   Reason
	Match    Match
	// AnchorAttr and AnchorValue are set when Match is anchor. The value is opaque bytes (a binary
	// anchor in LDAP wire order, or a string anchor's UTF-8), never converted.
	AnchorAttr  string
	AnchorValue []byte
	// ADSID is the AD object's binary objectSid the correlation rests on (SID evidence).
	ADSID []byte

	// PeerTier0 and PeerBases are the peer's tier0 status in its own directory as last computed.
	PeerTier0 bool
	PeerBases []Basis
	// SelfTier0 and SelfBases are the same for Self.
	SelfTier0 bool
	SelfBases []Basis
	// FactsAsOf is the inventory as-of of the two tier0 facts; zero when neither side is tier0 and
	// none was recorded. The statement's computed_at inherits the oldest such time (contract §8.3 F3).
	FactsAsOf time.Time

	GateCheckedAt    time.Time
	EligibleSince    time.Time
	EligibilityClass string
	ReconfirmedBy    string
	ReconfirmedAt    time.Time
}
