package connection

import (
	"errors"
	"slices"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/tablekind"
)

// hybridLinksTable declares public.hybrid_links (DM-21) for fitness-domain-keys.
var hybridLinksTable = tablekind.Declare(tablekind.Table{
	Name:   "public.hybrid_links",
	Entity: "DM-21",
	Kind:   tablekind.Tenant,
})

// NCGUID is the objectGUID of an AD domain naming context, canonical lower-case UUID text.
type NCGUID string

// ParseNCGUID accepts a canonical UUID (either case). The error never echoes the input.
func ParseNCGUID(s string) (NCGUID, error) {
	v, ok := canonUUID(s)
	if !ok {
		return "", ErrInvalid
	}
	return NCGUID(v), nil
}

// HybridLinkID identifies a hybrid link.
type HybridLinkID string

// ParseHybridLinkID accepts a canonical UUID (either case).
func ParseHybridLinkID(s string) (HybridLinkID, error) {
	v, ok := canonUUID(s)
	if !ok {
		return "", ErrInvalid
	}
	return HybridLinkID(v), nil
}

// LinkOrigin says how a hybrid link came to exist (DM-21 origin).
type LinkOrigin string

// The two origins.
const (
	OriginDeclared   LinkOrigin = "declared"   // an administrator declared it: born confirmed
	OriginDiscovered LinkOrigin = "discovered" // found from correlations: born proposed (I2)
)

// LinkState is the DM-21 lifecycle state.
type LinkState string

// The DM-21 states.
const (
	LinkProposed  LinkState = "proposed"
	LinkConfirmed LinkState = "confirmed"
	LinkRemoved   LinkState = "removed"
)

// LinkStates lists every state, in lifecycle order.
func LinkStates() []LinkState { return []LinkState{LinkProposed, LinkConfirmed, LinkRemoved} }

// LinkEdge is one legal DM-21 transition.
type LinkEdge struct{ From, To LinkState }

// linkEdges is the DM-21 lifecycle (proposed → confirmed → removed, and proposed → removed for a
// rejected proposal). It is the only declaration of legal changes; the SQL guard trigger is its twin.
var linkEdges = []LinkEdge{
	{LinkProposed, LinkConfirmed},
	{LinkConfirmed, LinkRemoved},
	{LinkProposed, LinkRemoved},
}

// LinkEdges returns a copy of the declared transitions.
func LinkEdges() []LinkEdge { return slices.Clone(linkEdges) }

// CanTransitionLink reports whether from → to is a declared DM-21 edge.
func CanTransitionLink(from, to LinkState) bool {
	return slices.Contains(linkEdges, LinkEdge{from, to})
}

// Valid reports whether s is a DM-21 state.
func (s LinkState) Valid() bool { return slices.Contains(LinkStates(), s) }

// initialState is the only state a link of this origin may be created in (DM-21.I2).
func (o LinkOrigin) initialState() (LinkState, bool) {
	switch o {
	case OriginDeclared:
		return LinkConfirmed, true
	case OriginDiscovered:
		return LinkProposed, true
	}
	return "", false
}

// HybridLink is DM-21 as stored: AD domain (ADConnectionID + NCGUID) → Entra tenant.
type HybridLink struct {
	ID                HybridLinkID
	ADConnectionID    ID
	NCGUID            NCGUID
	EntraConnectionID ID
	Origin            LinkOrigin
	State             LinkState
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// NewHybridLink is what Declare and Discover need. The origin is set by the method, never the caller.
type NewHybridLink struct {
	ADConnectionID    ID
	NCGUID            NCGUID
	EntraConnectionID ID
}

// Validate checks and canonicalises the three IDs; errors wrap ErrInvalid.
func (n NewHybridLink) Validate() (NewHybridLink, error) {
	ad, err := ParseID(string(n.ADConnectionID))
	if err != nil {
		return n, err
	}
	nc, err := ParseNCGUID(string(n.NCGUID))
	if err != nil {
		return n, err
	}
	en, err := ParseID(string(n.EntraConnectionID))
	if err != nil {
		return n, err
	}
	return NewHybridLink{ad, nc, en}, nil
}

// Typed errors of DM-21.
var (
	// ErrHybridLinkNotFound: no such link in this tenant.
	ErrHybridLinkNotFound = errors.New("connection: hybrid link not found")
	// ErrDuplicateHybridLink: a link that is not removed already joins this domain and tenant.
	ErrDuplicateHybridLink = errors.New("connection: hybrid link already exists")
	// ErrIllegalLinkTransition: the requested change is not in the DM-21 table.
	ErrIllegalLinkTransition = errors.New("connection: illegal hybrid link transition")
	// ErrLinkStateConflict: the link is no longer in the state the caller saw.
	ErrLinkStateConflict = errors.New("connection: hybrid link state changed concurrently")
)
