package inventory

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/skenzeriq/activediq/internal/platform/authn"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Group attributes the sync stores in directory_objects.attributes and Membership reads (DM-16).
// A missing one is "unknown", which is never eligible and makes the answer incomplete.
const (
	// AttrGroupType is the AD groupType integer. Bit 0x80000000 is security-enabled.
	AttrGroupType = "groupType"
	// AttrSecurityEnabled is the Entra securityEnabled boolean.
	AttrSecurityEnabled = "securityEnabled"
	// AttrVisibility is the Entra group visibility ("Public" never grants, DM-36.I2). Absent is fine
	// for a security group, which has none.
	AttrVisibility = "visibility"
	// AttrBroadMembershipWrite is the sync's computed fact for an AD group (TM-D18): true when its
	// DACL lets a broad principal change membership. It is a boolean, never the DACL itself.
	AttrBroadMembershipWrite = "diq_broadMembershipWrite"
)

const adSecurityEnabled = uint32(0x80000000)

// AccountSource reads a console account. *authn.Accounts implements it.
type AccountSource interface {
	Get(ctx context.Context, t tenant.ID, id string) (authn.Account, error)
}

// TakeoverSource reports an Entra connection's takeover_protection state (DM-10.I7).
type TakeoverSource interface {
	TakeoverProtection(ctx context.Context, t tenant.ID, entra ConnectionID) (string, error)
}

// Membership is the inventory implementation of authz.Membership (DM-36.I2, TM-D17, TM-D18).
type Membership struct {
	db       *store.DB
	accounts AccountSource
	corr     CorrelationSource
	takeover TakeoverSource // nil: every derived grant is unattested, so refused by the hybrid gate
}

var _ authz.Membership = (*Membership)(nil)

// NewMembership binds the resolver. takeover may be nil (fail closed).
func NewMembership(db *store.DB, accounts AccountSource, corr CorrelationSource, takeover TakeoverSource) *Membership {
	return &Membership{db: db, accounts: accounts, corr: corr, takeover: takeover}
}

type root struct {
	ref Ref
	via *authz.Derivation // nil: same plane as the sign-in identity
}

type found struct {
	g    authz.Group
	hops int
}

// GroupsOf implements authz.Membership. Any error returns an empty, incomplete answer.
func (m *Membership) GroupsOf(ctx context.Context, tenantID, account string) (authz.Groups, error) {
	none := authz.Groups{}
	if m == nil || m.db == nil || m.accounts == nil || m.corr == nil {
		return none, ErrNotConfigured
	}
	tid, err := tenant.Parse(tenantID)
	if err != nil {
		return none, ErrNoTenant
	}
	acc, err := m.accounts.Get(ctx, tid, account)
	if err != nil {
		return none, fmt.Errorf("inventory: membership: account: %w", err)
	}
	// Only an account resting on a directory object is a member (DM-30.I5); the rest hold direct grants.
	if acc.Ref == nil || acc.State == authn.AccountDeleted {
		return authz.Groups{Groups: []authz.Group{}, Complete: true}, nil
	}
	self := Ref{ConnectionID(strings.ToLower(acc.Ref.ConnectionID)), GUID(strings.ToLower(acc.Ref.ObjectGUID))}
	if !self.Valid() {
		return none, ErrCorrupt
	}
	kinds := map[ConnectionID]string{}
	kindOf := func(c ConnectionID) (string, error) {
		if k, ok := kinds[c]; ok {
			return k, nil
		}
		var k string
		err := m.db.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) error {
			return tx.QueryRow(ctx, `SELECT kind FROM public.connections WHERE tenant_id = $1::uuid AND id = $2::uuid`,
				tid.String(), string(c)).Scan(&k)
		})
		if err != nil {
			return "", fmt.Errorf("inventory: membership: connection: %w", err)
		}
		kinds[c] = k
		return k, nil
	}
	selfKind, err := kindOf(self.Connection)
	if err != nil {
		return none, err
	}
	// The sign-in plane: an sso account signs in through Entra, any other through its own directory.
	signKind := selfKind
	if acc.Kind == authn.KindSSO {
		signKind = connKindEntraTenant
	}

	cs, err := m.corr.CorrelationsFor(ctx, tid, self)
	if err != nil {
		return none, fmt.Errorf("inventory: membership: correlations: %w", err)
	}
	complete := true
	var matched []Link
	for _, l := range cs.Links {
		if l.State == StateMatched { // candidate and broken never carry authority (DM-20.I4)
			matched = append(matched, l)
		}
	}
	if len(matched) > 0 && cs.EvaluatedAt.IsZero() {
		complete = false // a correlation with no as-of is not established
		matched = nil
	}

	derive := func(l Link) *authz.Derivation {
		entra := l.Peer.Connection
		if l.PeerKind == "ad_forest" {
			entra = l.Self.Connection
		}
		tk := ""
		if m.takeover != nil {
			var terr error
			if tk, terr = m.takeover.TakeoverProtection(ctx, tid, entra); terr != nil {
				tk = "" // unreadable counts as not attested
			}
		}
		return &authz.Derivation{Correlation: &authz.Correlation{
			State: authz.CorrelationMatched, Takeover: tk,
			Tier0Either: l.SelfTier0 || l.PeerTier0 || l.FactsAsOf.IsZero(), // no as-of: assume tier0
		}}
	}

	var roots []root
	if selfKind == signKind {
		roots = append(roots, root{ref: self})
	}
	// A derived root reaches the account through a correlation. An sso account uses those only in a
	// session that verified the authority factor (DM-30.I6), which this port cannot see: they are
	// left out by policy (not an incomplete read) until the port carries the session.
	if acc.Kind != authn.KindSSO {
		for _, l := range matched {
			peerKind := connKindEntraTenant
			if l.PeerKind == "ad_forest" {
				peerKind = connKindADForest
			}
			r := root{ref: l.Peer, via: derive(l)}
			if peerKind == signKind {
				r.via = nil
			}
			roots = append(roots, r)
		}
	} else {
		for _, l := range matched {
			if l.PeerKind == "entra_tenant" { // self is AD; the peer is the sign-in identity's object
				roots = append(roots, root{ref: l.Peer})
			}
		}
	}

	var all []found
	seen := map[Ref]bool{}
	for _, r := range roots {
		fs, ok, err := m.walk(ctx, tid, r, kindOf)
		if err != nil {
			return none, err
		}
		complete = complete && ok
		all = append(all, fs...)
	}
	// Same-plane first (rbac takes the first matching membership as the provenance), then the shortest path.
	sort.SliceStable(all, func(i, j int) bool {
		a, b := all[i], all[j]
		if (a.g.Via == nil) != (b.g.Via == nil) {
			return a.g.Via == nil
		}
		if a.hops != b.hops {
			return a.hops < b.hops
		}
		if a.g.Connection != b.g.Connection {
			return a.g.Connection < b.g.Connection
		}
		return a.g.GUID < b.g.GUID
	})
	out := make([]authz.Group, 0, len(all))
	for _, f := range all {
		k := Ref{ConnectionID(f.g.Connection), GUID(f.g.GUID)}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, f.g)
	}
	return authz.Groups{Groups: out, Complete: complete}, nil
}

// walk climbs from the root through active member and primary-group edges, level by level, and passes
// only through eligible groups: a group whose membership a broad principal can change would let that
// principal reach everything above it (TM-D18). ok is false when a group on the way could not be
// judged (the walk then does not pass through it).
func (m *Membership) walk(ctx context.Context, tid tenant.ID, r root, kindOf func(ConnectionID) (string, error)) ([]found, bool, error) {
	kind, err := kindOf(r.ref.Connection)
	if err != nil {
		return nil, false, err
	}
	paths := map[GUID][]string{r.ref.Object: {string(r.ref.Object)}}
	frontier := []GUID{r.ref.Object}
	visited := map[GUID]bool{r.ref.Object: true}
	var out []found
	complete := true
	for len(frontier) > 0 {
		edges, err := m.parents(ctx, tid, r.ref.Connection, frontier)
		if err != nil {
			return nil, false, err
		}
		var cand []GUID
		parentsOf := map[GUID][]GUID{} // group -> members in the frontier
		for _, e := range edges {
			if visited[e.group] {
				continue
			}
			if _, ok := parentsOf[e.group]; !ok {
				cand = append(cand, e.group)
			}
			parentsOf[e.group] = append(parentsOf[e.group], e.member)
		}
		if len(cand) == 0 {
			break
		}
		for _, g := range cand {
			visited[g] = true
		}
		if len(visited) > MaxGroups {
			return nil, false, ErrTooMany
		}
		verdicts, err := m.eligibility(ctx, tid, r.ref.Connection, kind, cand)
		if err != nil {
			return nil, false, err
		}
		frontier = frontier[:0:0]
		for _, g := range cand {
			switch verdicts[g] {
			case verdictUnknown:
				complete = false
			case verdictEligible:
				mem := parentsOf[g][0]
				p := append(append([]string(nil), paths[mem]...), string(g))
				paths[g] = p
				frontier = append(frontier, g)
				out = append(out, found{hops: len(p) - 1, g: authz.Group{
					Connection: string(r.ref.Connection), GUID: string(g), Via: r.via, Path: p}})
			}
		}
	}
	return out, complete, nil
}

type edge struct{ group, member GUID }

func (m *Membership) parents(ctx context.Context, tid tenant.ID, c ConnectionID, members []GUID) ([]edge, error) {
	ids := make([]string, len(members))
	for i, g := range members {
		ids[i] = string(g)
	}
	var out []edge
	err := m.db.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) error {
		rows, err := tx.Query(ctx, `SELECT source_guid::text, target_guid::text FROM public.links
			WHERE tenant_id = $1::uuid AND connection_id = $2::uuid AND link_attr IN ('member', 'primary_group')
			AND state = 'active' AND target_guid = ANY($3::uuid[]) ORDER BY source_guid, target_guid LIMIT $4`,
			tid.String(), string(c), ids, 4*MaxGroups+1)
		if err != nil {
			return fmt.Errorf("inventory: membership: edges: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var g, mem string
			if err := rows.Scan(&g, &mem); err != nil {
				return fmt.Errorf("inventory: membership: edges: %w", err)
			}
			out = append(out, edge{GUID(g), GUID(mem)})
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	if len(out) > 4*MaxGroups {
		return nil, ErrTooMany
	}
	return out, nil
}

type verdict int

const (
	verdictIneligible verdict = iota // zero value: a group with no verdict never grants
	verdictEligible
	verdictUnknown
)

func (m *Membership) eligibility(ctx context.Context, tid tenant.ID, c ConnectionID, connKind string, gs []GUID) (map[GUID]verdict, error) {
	ids := make([]string, len(gs))
	for i, g := range gs {
		ids[i] = string(g)
	}
	out := make(map[GUID]verdict, len(gs))
	for _, g := range gs {
		out[g] = verdictUnknown // no row: out of scope or not yet read
	}
	err := m.db.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) error {
		rows, err := tx.Query(ctx, `SELECT object_guid::text, kind, state, attributes FROM public.directory_objects
			WHERE tenant_id = $1::uuid AND connection_id = $2::uuid AND object_guid = ANY($3::uuid[])`,
			tid.String(), string(c), ids)
		if err != nil {
			return fmt.Errorf("inventory: membership: groups: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var g, kind, state string
			var raw []byte
			if err := rows.Scan(&g, &kind, &state, &raw); err != nil {
				return fmt.Errorf("inventory: membership: groups: %w", err)
			}
			out[GUID(g)] = judge(connKind, Kind(kind), ObjectState(state), raw)
		}
		return rows.Err()
	})
	return out, err
}

// judge decides whether a group row may grant (DM-36.I2, TM-D18). Anything it cannot establish is
// verdictUnknown; a fact that says no is verdictIneligible.
func judge(connKind string, kind Kind, state ObjectState, raw []byte) verdict {
	if kind != KindGroup {
		return verdictIneligible
	}
	var attrs map[string]any
	if err := json.Unmarshal(raw, &attrs); err != nil {
		return verdictUnknown
	}
	switch connKind {
	case connKindADForest:
		if state != ObjLive {
			return verdictIneligible
		}
		gt, ok := attrs[AttrGroupType].(float64)
		if !ok {
			return verdictUnknown
		}
		if uint32(int64(gt))&adSecurityEnabled == 0 { // a distribution group
			return verdictIneligible
		}
		broad, ok := attrs[AttrBroadMembershipWrite].(bool)
		if !ok {
			return verdictUnknown
		}
		if broad {
			return verdictIneligible
		}
		return verdictEligible
	case connKindEntraTenant:
		if state != ObjActive {
			return verdictIneligible
		}
		sec, ok := attrs[AttrSecurityEnabled].(bool)
		if !ok {
			return verdictUnknown
		}
		if !sec {
			return verdictIneligible
		}
		if v, _ := attrs[AttrVisibility].(string); strings.EqualFold(v, "public") {
			return verdictIneligible
		}
		return verdictEligible
	}
	return verdictUnknown
}
