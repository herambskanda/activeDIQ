package inventory

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"fmt"
	"sort"
	"strings"
	"time"

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
	// AttrGroupTypes is the Entra groupTypes string list. Visibility is nullable in Graph and an M365
	// (Unified) group without one is Public, so an absent visibility is judged by this list (fail closed).
	AttrGroupTypes = "groupTypes"
	// AttrBroadMembershipWrite is the sync's computed fact for an AD group (TM-D18): true when its
	// DACL lets a broad principal change membership. It is a boolean, never the DACL itself.
	AttrBroadMembershipWrite = "diq_broadMembershipWrite"
	// AttrBroadMembershipWriteAt is when AttrBroadMembershipWrite was computed (RFC 3339 string, on AD
	// groups only). Without it the fact has no age and a synced Entra copy cannot rest on it (TM-D18
	// D18-1 rule 3). The producer (T-0541) writes both together.
	AttrBroadMembershipWriteAt = "diq_broadMembershipWriteComputedAt"
	// AttrOnPremisesSyncEnabled is Graph onPremisesSyncEnabled on an Entra group: true, false, or JSON
	// null (never synced). An absent key is "not read", which is unknown (D18-1 rule 1).
	AttrOnPremisesSyncEnabled = "onPremisesSyncEnabled"

	// dynamicMembership is the groupTypes value of a dynamic-membership group (D18-2).
	dynamicMembership = "DynamicMembership"
	// MaxPairAge is the verification age of TM-D23 (26 h): an older pair is unknown, never last-good.
	MaxPairAge = 26 * time.Hour
	// maxFutureSkew bounds how far in the future an as-of may be before it is not believed.
	maxFutureSkew = 5 * time.Minute
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

	// An sso account takes groups only from its own directory_ref root. A correlation-reached root
	// would be same-plane to the walk and skip the rbac hybrid gate, and using one needs the session's
	// authority factor and issuer tenant (DM-30.I6), which this port cannot see (T-0543). Left out by
	// policy, not an incomplete read.
	var roots []root
	if acc.Kind == authn.KindSSO {
		roots = append(roots, root{ref: self})
	} else {
		if selfKind == signKind {
			roots = append(roots, root{ref: self})
		}
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
	synced := map[GUID]syncedGroup{}
	var syncedIDs []string
	err := m.db.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) error {
		rows, err := tx.Query(ctx, `SELECT object_guid::text, kind, state, attributes, on_prem_sync_enabled, on_prem_sid FROM public.directory_objects
			WHERE tenant_id = $1::uuid AND connection_id = $2::uuid AND object_guid = ANY($3::uuid[])`,
			tid.String(), string(c), ids)
		if err != nil {
			return fmt.Errorf("inventory: membership: groups: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var g, kind, state string
			var raw, sid []byte
			var col *bool
			if err := rows.Scan(&g, &kind, &state, &raw, &col, &sid); err != nil {
				return fmt.Errorf("inventory: membership: groups: %w", err)
			}
			v, isSynced := judge(connKind, Kind(kind), ObjectState(state), raw, col)
			out[GUID(g)] = v
			if isSynced {
				synced[GUID(g)] = syncedGroup{sid: sid}
				syncedIDs = append(syncedIDs, g)
			}
		}
		if err := rows.Err(); err != nil {
			return err
		}
		rows.Close()
		if len(syncedIDs) == 0 {
			return nil
		}
		// Same transaction as the Entra rows above: the verdict never rests on two different reads.
		return m.readPairs(ctx, tx, tid, c, syncedIDs, synced)
	})
	if err != nil {
		return nil, err
	}
	if len(synced) == 0 {
		return out, nil
	}
	attested := false
	if m.takeover != nil {
		if tk, terr := m.takeover.TakeoverProtection(ctx, tid, c); terr == nil && tk == "attested" {
			attested = true
		}
	}
	for g, sg := range synced {
		if !attested {
			out[g] = verdictUnknown
			continue
		}
		out[g] = judgeSynced(sg)
	}
	return out, nil
}

// syncedGroup is an Entra group with onPremisesSyncEnabled = true and what it needs to be judged
// from its AD source (D18-1). pairs holds every live correlation of the group.
type syncedGroup struct {
	sid    []byte
	dupSID bool // another Entra group of this connection carries the same onPremisesSecurityIdentifier
	pairs  []adSource
	evalAt time.Time // as-of of the last completed correlation evaluation of the Entra connection
	now    time.Time // database time of the read transaction
}

type adSource struct {
	state       State
	match       Match
	corrSID     []byte
	adSID       []byte
	adKind      Kind
	adState     ObjectState
	adAttrs     []byte
	adConnKind  string
	adTier0     bool
	entraTier0  bool
	factsAsOf   time.Time
	adObjectSet bool // the AD object row exists in the inventory
}

func (m *Membership) readPairs(ctx context.Context, tx store.Tx, tid tenant.ID, c ConnectionID, ids []string, synced map[GUID]syncedGroup) error {
	var evaluated, now time.Time
	var ev *time.Time
	if err := tx.QueryRow(ctx, `SELECT (SELECT max(evaluated_at) FROM public.correlation_evaluations
		WHERE tenant_id = $1::uuid AND connection_id = $2::uuid), now()`, tid.String(), string(c)).Scan(&ev, &now); err != nil {
		return fmt.Errorf("inventory: membership: pair as-of: %w", err)
	}
	if ev != nil {
		evaluated = ev.UTC()
	}
	dups, err := tx.Query(ctx, `SELECT e.object_guid::text FROM public.directory_objects e
		WHERE e.tenant_id = $1::uuid AND e.connection_id = $2::uuid AND e.object_guid = ANY($3::uuid[]) AND e.on_prem_sid IS NOT NULL
		AND EXISTS (SELECT 1 FROM public.directory_objects o WHERE o.tenant_id = e.tenant_id AND o.connection_id = e.connection_id
			AND o.on_prem_sid = e.on_prem_sid AND o.object_guid <> e.object_guid)`, tid.String(), string(c), ids)
	if err != nil {
		return fmt.Errorf("inventory: membership: pair sid: %w", err)
	}
	dupSet := map[GUID]bool{}
	for dups.Next() {
		var g string
		if err := dups.Scan(&g); err != nil {
			dups.Close()
			return fmt.Errorf("inventory: membership: pair sid: %w", err)
		}
		dupSet[GUID(g)] = true
	}
	dups.Close()
	if err := dups.Err(); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT co.entra_object_guid::text, co.state, co.match, co.ad_sid, co.ad_tier0, co.entra_tier0,
			LEAST(COALESCE(co.ad_facts_as_of, co.facts_as_of), COALESCE(co.entra_facts_as_of, co.facts_as_of)),
			ac.kind, a.kind, a.state, a.attributes, a.sid
		FROM public.correlations co
		JOIN public.connections ac ON ac.tenant_id = co.tenant_id AND ac.id = co.ad_connection_id
		LEFT JOIN public.directory_objects a ON a.tenant_id = co.tenant_id AND a.connection_id = co.ad_connection_id AND a.object_guid = co.ad_object_guid
		WHERE co.tenant_id = $1::uuid AND co.entra_connection_id = $2::uuid AND co.entra_object_guid = ANY($3::uuid[]) AND co.state <> 'removed'
		LIMIT $4`, tid.String(), string(c), ids, MaxLinks+1)
	if err != nil {
		return fmt.Errorf("inventory: membership: pairs: %w", err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var g, state, match, acKind string
		var corrSID, adSID, adAttrs []byte
		var adT, enT bool
		var asOf *time.Time
		var aKind, aState *string
		if err := rows.Scan(&g, &state, &match, &corrSID, &adT, &enT, &asOf, &acKind, &aKind, &aState, &adAttrs, &adSID); err != nil {
			return fmt.Errorf("inventory: membership: pairs: %w", err)
		}
		if n++; n > MaxLinks {
			return ErrTooMany
		}
		p := adSource{state: State(state), match: Match(match), corrSID: corrSID, adSID: adSID, adAttrs: adAttrs,
			adConnKind: acKind, adTier0: adT, entraTier0: enT, factsAsOf: val(asOf)}
		if aKind != nil && aState != nil {
			p.adObjectSet, p.adKind, p.adState = true, Kind(*aKind), ObjectState(*aState)
		}
		sg := synced[GUID(g)]
		sg.pairs = append(sg.pairs, p)
		synced[GUID(g)] = sg
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for g, sg := range synced {
		sg.dupSID, sg.evalAt, sg.now = dupSet[g], evaluated, now.UTC()
		synced[g] = sg
	}
	return nil
}

// judgeSynced decides a synced Entra group from its one matched AD source (D18-1 rules 2 and 3).
// Anything it cannot establish is unknown; a fact that says no is ineligible, and so is the copy.
func judgeSynced(g syncedGroup) verdict {
	if len(g.pairs) != 1 || g.dupSID || len(g.sid) == 0 {
		return verdictUnknown // exactly one AD group, and one Entra group per SID
	}
	p := g.pairs[0]
	if p.state != StateMatched || p.match != MatchSID || !p.adObjectSet || p.adConnKind != connKindADForest {
		return verdictUnknown // candidate, broken, anchor-made, or the AD group is not in inventory
	}
	if !bytes.Equal(g.sid, p.corrSID) || !bytes.Equal(g.sid, p.adSID) {
		return verdictUnknown // the SID the Entra copy claims is not the AD group's
	}
	adV, _ := judge(connKindADForest, p.adKind, p.adState, p.adAttrs, nil)
	if adV == verdictUnknown {
		return verdictUnknown
	}
	// Freshness: the older of the evaluation, the tier0 facts and the AD fact. Never the last good value.
	var attrs map[string]any
	if err := json.Unmarshal(p.adAttrs, &attrs); err != nil {
		return verdictUnknown
	}
	at, _ := attrs[AttrBroadMembershipWriteAt].(string)
	computed, err := time.Parse(time.RFC3339, at)
	if err != nil || g.evalAt.IsZero() || p.factsAsOf.IsZero() {
		return verdictUnknown
	}
	for _, t := range []time.Time{computed, g.evalAt, p.factsAsOf} {
		if g.now.Sub(t) > MaxPairAge || t.Sub(g.now) > maxFutureSkew {
			return verdictUnknown
		}
	}
	if adV != verdictEligible || p.adTier0 || p.entraTier0 {
		return verdictIneligible
	}
	return verdictEligible
}

// judge decides whether a group row may grant (DM-36.I2, TM-D18). Anything it cannot establish is
// verdictUnknown; a fact that says no is verdictIneligible. synced is true for an Entra group that
// follows an AD source (D18-1): its verdict is then only a placeholder and judgeSynced decides. col is
// the on_prem_sync_enabled column (nil for AD).
func judge(connKind string, kind Kind, state ObjectState, raw []byte, col *bool) (v verdict, synced bool) {
	if kind != KindGroup {
		return verdictIneligible, false
	}
	var attrs map[string]any
	if err := json.Unmarshal(raw, &attrs); err != nil {
		return verdictUnknown, false
	}
	switch connKind {
	case connKindADForest:
		return judgeAD(state, attrs), false
	case connKindEntraTenant:
		return judgeEntra(state, attrs, col)
	}
	return verdictUnknown, false
}

func judgeAD(state ObjectState, attrs map[string]any) verdict {
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
}

func judgeEntra(state ObjectState, attrs map[string]any, col *bool) (verdict, bool) {
	if state != ObjActive {
		return verdictIneligible, false
	}
	// D18-2: a dynamic-membership group never grants, whatever its rule or state. An unreadable
	// groupTypes cannot be told apart from one, so it is unknown.
	gts, ok := attrs[AttrGroupTypes].([]any)
	if !ok {
		return verdictUnknown, false
	}
	unified := false
	for _, t := range gts {
		s, _ := t.(string)
		if strings.EqualFold(s, dynamicMembership) {
			return verdictIneligible, false
		}
		if strings.EqualFold(s, "Unified") {
			unified = true
		}
	}
	sec, ok := attrs[AttrSecurityEnabled].(bool)
	if !ok {
		return verdictUnknown, false
	}
	if !sec {
		return verdictIneligible, false
	}
	// D18-1 rule 1: true is synced; null or false is cloud-managed; an absent key is unknown. The
	// column is the sync's typed copy: if either says true the group is synced.
	raw, present := attrs[AttrOnPremisesSyncEnabled]
	flag, isBool := raw.(bool)
	switch {
	case isBool && flag, col != nil && *col:
		return verdictUnknown, true
	case !present && col == nil:
		return verdictUnknown, false
	case present && raw != nil && !isBool:
		return verdictUnknown, false // not a value Graph returns
	}
	if v, _ := attrs[AttrVisibility].(string); v != "" {
		if strings.EqualFold(v, "public") {
			return verdictIneligible, false
		}
		return verdictEligible, false
	}
	// No stored visibility: only a group known not to be Unified (a plain security group) is safe.
	if unified {
		return verdictUnknown, false
	}
	return verdictEligible, false
}
