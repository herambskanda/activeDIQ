package inventory

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/platform/store"
)

// PairFacts is the tier0 status of the two sides of a pair, as the classifiers computed it, and the
// inventory as-of it rests on (contract §8.3 F3). "Not tier0" is a fact with a time as well.
type PairFacts struct {
	ADBases, EntraBases []Basis
	AsOf                time.Time
}

// PairClassifier supplies the tier0 facts of a candidate pair. The ingester has no opinion on them,
// and it must not guess: Form overwrites a correlation's stored bases with what it is given, so a
// missing classifier is ErrNotConfigured, never "not tier0".
type PairClassifier interface {
	Classify(ctx context.Context, tx store.Tx, ad, entra Ref) (PairFacts, error)
}

// Cycle is one sync cycle's output for one connection: what it observed, as of when.
type Cycle struct {
	Connection ConnectionID
	// Observed is the cycle's as-of (the start of the read, not its completion).
	Observed     time.Time
	Observations []Observation
	// Now is the time the gate is judged at.
	Now time.Time
	// MoreBatches says further batches of this same cycle follow in later transactions (Populate takes
	// a bounded number of objects at a time): only the last batch runs the gate, over everything the
	// cycle stored.
	MoreBatches bool
}

// Ingested is the outcome of Ingest.
type Ingested struct {
	Populated
	// Pairs is the number of pairs the gate judged; Created the number of new correlations.
	Pairs, Created int
	// Matched, Candidates and Broken count the verdicts.
	Matched, Candidates, Broken int
	// Conflicts counts new pairs not formed because one of the two objects already has a live
	// correlation to another peer in that connection (DM-20.I2). They are left alone, not re-targeted.
	Conflicts int
}

// Ingester is the sync ingester's write side (DM-16, DM-17, DM-20): it stores a cycle's observations
// and then runs the DM-20.I4 gate over every pair the cycle can have changed, all in the caller's
// tenant transaction, so a reader sees the objects, the member edges, the verdicts and the evaluation
// as-of together or not at all.
type Ingester struct {
	Populator
	Classifier PairClassifier
}

// ErrNoClassifier: the ingester has no PairClassifier.
var ErrNoClassifier = fmt.Errorf("%w: no pair classifier", ErrNotConfigured)

const (
	ingestBatch  = 500
	maxCandidate = 3
)

// Ingest populates the cycle's observations, then re-evaluates the gate for each Entra tenant the
// connection feeds or is: an Entra cycle re-judges its own users and groups, an AD cycle re-judges the
// tenants its domains are linked to (the AD side of a pair changed). Per Entra object it judges every
// live correlation plus the pair the object's anchor (user) or SID (group) newly resolves to. A pair
// it cannot judge is never left at its old verdict: any error rolls the cycle back (the caller's
// transaction), and ErrStale means a newer evaluation is already stored.
//
// The GateInput is built only from stored inventory (directory_objects), the confirmed HybridLinks
// and the Entra connection's attestation (derived now by connection.EvaluateTakeover); nothing is
// read from a directory here.
func (g Ingester) Ingest(ctx context.Context, tx store.Tx, c Cycle) (Ingested, error) {
	var out Ingested
	if g.Classifier == nil {
		return out, ErrNoClassifier
	}
	if !(Ref{c.Connection, "aaaaaaaa-0000-4000-8000-000000000000"}).Valid() || c.Observed.IsZero() || c.Now.IsZero() {
		return out, ErrInvalid
	}
	pop, err := g.Populate(ctx, tx, c.Connection, c.Observed, c.Observations)
	out.Populated = pop
	if err != nil {
		return out, err
	}
	if c.MoreBatches {
		return out, nil
	}
	var kind string
	if err := tx.QueryRow(ctx, `SELECT kind FROM public.connections
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND id = $1::uuid`, string(c.Connection)).Scan(&kind); err != nil {
		return out, fmt.Errorf("inventory: connection kind: %w", err)
	}
	var entras []ConnectionID
	switch kind {
	case connKindEntraTenant:
		entras = []ConnectionID{c.Connection}
	case connKindADForest:
		links, err := (connection.Store{}).ListHybridLinks(ctx, tx, connection.ID(c.Connection), false)
		if err != nil {
			return out, fmt.Errorf("inventory: hybrid links: %w", err)
		}
		seen := map[ConnectionID]bool{}
		for _, l := range links {
			if e := ConnectionID(l.EntraConnectionID); !seen[e] {
				seen[e] = true
				entras = append(entras, e)
			}
		}
		sort.Slice(entras, func(i, j int) bool { return entras[i] < entras[j] })
	default:
		return out, ErrCorrupt
	}
	for _, e := range entras {
		if err := g.correlate(ctx, tx, e, c, &out); err != nil {
			return out, err
		}
	}
	return out, nil
}

type entraRow struct {
	guid        GUID
	kind        Kind
	state       ObjectState
	syncEnabled *bool
	cloudMgd    *bool
	sid         []byte
	domain      string
	immutable   []byte
	cloudSeen   *time.Time
}

type adRow struct {
	conn  ConnectionID
	guid  GUID
	kind  string
	state string
	sid   []byte
	nc    string
}

type pair struct {
	ad         Ref
	match      Match
	attr       string
	anchor     []byte
	storedSID  []byte
	resolved   bool // the anchor/SID currently resolves to this AD object
	existing   bool
	matchCount int
}

type domainKey struct {
	conn ConnectionID
	nc   string
}

func (g Ingester) correlate(ctx context.Context, tx store.Tx, entra ConnectionID, c Cycle, out *Ingested) error {
	cs := connection.Store{}
	links, err := cs.ListHybridLinksForEntra(ctx, tx, connection.ID(entra))
	if err != nil {
		return fmt.Errorf("inventory: hybrid links: %w", err)
	}
	confirmed := map[domainKey]bool{}
	adSet := map[ConnectionID]bool{}
	for _, l := range links {
		adSet[ConnectionID(l.ADConnectionID)] = true
		if l.State == connection.LinkConfirmed {
			confirmed[domainKey{ConnectionID(l.ADConnectionID), string(l.NCGUID)}] = true
		}
	}
	// AD connections of correlations that outlive their link are still judged (as link_unconfirmed).
	rows, err := tx.Query(ctx, `SELECT DISTINCT ad_connection_id::text FROM public.correlations
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND entra_connection_id = $1::uuid AND state <> 'removed'`, string(entra))
	if err != nil {
		return fmt.Errorf("inventory: correlation connections: %w", err)
	}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			rows.Close()
			return fmt.Errorf("inventory: correlation connections: %w", err)
		}
		adSet[ConnectionID(s)] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("inventory: correlation connections: %w", err)
	}
	ads := make([]ConnectionID, 0, len(adSet))
	for a := range adSet {
		ads = append(ads, a)
	}
	sort.Slice(ads, func(i, j int) bool { return ads[i] < ads[j] })

	rec, err := cs.GetTakeover(ctx, tx, connection.ID(entra))
	if err != nil {
		return fmt.Errorf("inventory: takeover state: %w", err)
	}
	takeover := TakeoverOpen // never attested counts as open: only attested lets a pair match
	switch connection.EvaluateTakeover(rec, c.Now) {
	case connection.TakeoverAttested:
		takeover = TakeoverAttested
	case connection.TakeoverStale:
		takeover = TakeoverStale
	}
	var firstAttested time.Time
	if rec.FirstAttestedAt != nil {
		firstAttested = *rec.FirstAttestedAt
	}

	if err := g.recordEvaluations(ctx, tx, entra, ads, c); err != nil {
		return err
	}

	domains := map[domainKey]string{}
	var after GUID
	for {
		batch, err := entraBatch(ctx, tx, entra, after)
		if err != nil {
			return err
		}
		for _, eo := range batch {
			after = eo.guid
			pairs, err := g.pairsOf(ctx, tx, entra, eo, ads, out)
			if err != nil {
				return err
			}
			for _, p := range pairs {
				if err := g.judge(ctx, tx, entra, eo, p, takeover, firstAttested, confirmed, domains, c, out); err != nil {
					return err
				}
			}
		}
		if len(batch) < ingestBatch {
			return nil
		}
	}
}

// recordEvaluations stores the evaluation as-of first (it serialises concurrent runs, Writer.RecordEvaluation).
// The as-of is the oldest input read: the cycle's own as-of for its connection, and for every other
// connection involved the newest observation stored for it. A connection with no stored object has no
// as-of to vouch for and is not recorded.
func (g Ingester) recordEvaluations(ctx context.Context, tx store.Tx, entra ConnectionID, ads []ConnectionID, c Cycle) error {
	conns := append([]ConnectionID{entra}, ads...)
	asOf := map[ConnectionID]time.Time{}
	oldest := time.Time{}
	for _, cn := range conns {
		var t time.Time
		if cn == c.Connection {
			t = c.Observed
		} else {
			var m *time.Time
			if err := tx.QueryRow(ctx, `SELECT max(observed_at) FROM public.directory_objects
				WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND connection_id = $1::uuid`, string(cn)).Scan(&m); err != nil {
				return fmt.Errorf("inventory: connection as-of: %w", err)
			}
			if m == nil {
				continue
			}
			t = *m
		}
		asOf[cn] = t
		if oldest.IsZero() || t.Before(oldest) {
			oldest = t
		}
	}
	for _, cn := range conns {
		if _, ok := asOf[cn]; !ok {
			continue
		}
		if err := g.RecordEvaluation(ctx, tx, cn, oldest); err != nil {
			return err
		}
	}
	return nil
}

func entraBatch(ctx context.Context, tx store.Tx, entra ConnectionID, after GUID) ([]entraRow, error) {
	a := "00000000-0000-0000-0000-000000000000"
	if after != "" {
		a = string(after)
	}
	rows, err := tx.Query(ctx, `SELECT object_guid::text, kind, state, on_prem_sync_enabled, on_prem_cloud_managed, on_prem_sid,
			on_prem_domain_name, on_prem_immutable_id, cloud_seen_at
		FROM public.directory_objects
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND connection_id = $1::uuid
		AND kind IN ('user', 'group') AND object_guid > $2::uuid ORDER BY object_guid LIMIT $3`, string(entra), a, ingestBatch)
	if err != nil {
		return nil, fmt.Errorf("inventory: entra objects: %w", err)
	}
	defer rows.Close()
	var out []entraRow
	for rows.Next() {
		var r entraRow
		var gd, k, st string
		if err := rows.Scan(&gd, &k, &st, &r.syncEnabled, &r.cloudMgd, &r.sid, &r.domain, &r.immutable, &r.cloudSeen); err != nil {
			return nil, fmt.Errorf("inventory: entra objects: %w", err)
		}
		r.guid, r.kind, r.state = GUID(gd), Kind(k), ObjectState(st)
		out = append(out, r)
	}
	return out, rows.Err()
}

// pairsOf is every pair to judge for one Entra object: its live correlations, plus the AD object its
// anchor or SID newly resolves to when that is unambiguous and the object is not gone.
func (g Ingester) pairsOf(ctx context.Context, tx store.Tx, entra ConnectionID, eo entraRow, ads []ConnectionID, out *Ingested) ([]pair, error) {
	var pairs []pair
	rows, err := tx.Query(ctx, `SELECT ad_connection_id::text, ad_object_guid::text, match, anchor_attr, anchor_value, ad_sid
		FROM public.correlations
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND entra_connection_id = $1::uuid
		AND entra_object_guid = $2::uuid AND state <> 'removed' ORDER BY ad_connection_id, ad_object_guid`, string(entra), string(eo.guid))
	if err != nil {
		return nil, fmt.Errorf("inventory: live correlations: %w", err)
	}
	for rows.Next() {
		var p pair
		var ac, ag, m string
		if err := rows.Scan(&ac, &ag, &m, &p.attr, &p.anchor, &p.storedSID); err != nil {
			rows.Close()
			return nil, fmt.Errorf("inventory: live correlations: %w", err)
		}
		p.ad, p.match, p.existing = Ref{ConnectionID(ac), GUID(ag)}, Match(m), true
		pairs = append(pairs, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("inventory: live correlations: %w", err)
	}

	matches, mp, err := g.resolve(ctx, tx, eo, ads)
	if err != nil {
		return nil, err
	}
	for i := range pairs {
		pairs[i].matchCount = len(matches)
		for _, m := range matches {
			if m == pairs[i].ad {
				pairs[i].resolved = true
			}
		}
	}
	gone := eo.state != ObjActive
	if gone || len(matches) != 1 {
		return pairs, nil
	}
	m := matches[0]
	for i := range pairs {
		if pairs[i].ad == m {
			// Same pair: keep the stored shape unless the anchor is now found by the other attribute.
			if pairs[i].match == mp.match {
				pairs[i].attr, pairs[i].anchor = mp.attr, mp.anchor
			}
			return pairs, nil
		}
		if pairs[i].ad.Connection == m.Connection {
			// The Entra object already has a live peer in this AD connection: never re-target it here.
			out.Conflicts++
			return pairs, nil
		}
	}
	var taken bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM public.correlations
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND ad_connection_id = $1::uuid AND ad_object_guid = $2::uuid
		AND entra_connection_id = $3::uuid AND state <> 'removed')`, string(m.Connection), string(m.Object), string(entra)).Scan(&taken); err != nil {
		return nil, fmt.Errorf("inventory: peer taken: %w", err)
	}
	if taken {
		out.Conflicts++
		return pairs, nil
	}
	np := mp
	np.ad, np.resolved, np.matchCount = m, true, 1
	return append(pairs, np), nil
}

// resolve finds the AD objects (of the linked connections) the Entra object's anchor or SID resolves
// to: a user by onPremisesImmutableId against ms-DS-ConsistencyGuid then objectGUID (DM-20.I1a, the
// same predicate as Writer.AnchorMatches), a group by onPremisesSecurityIdentifier (I1b).
func (g Ingester) resolve(ctx context.Context, tx store.Tx, eo entraRow, ads []ConnectionID) ([]Ref, pair, error) {
	var p pair
	if len(ads) == 0 {
		return nil, p, nil
	}
	ids := make([]string, len(ads))
	for i, a := range ads {
		ids[i] = string(a)
	}
	var q string
	var args []any
	switch eo.kind {
	case KindGroup:
		if len(eo.sid) < 8 {
			return nil, p, nil
		}
		p.match = MatchSID
		q = `SELECT connection_id::text, object_guid::text, false FROM public.directory_objects
			WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND connection_id = ANY($1::uuid[])
			AND nc_guid IS NOT NULL AND kind = 'group' AND state <> 'purged' AND sid = $2
			ORDER BY connection_id, object_guid LIMIT $3`
		args = []any{ids, eo.sid, maxCandidate}
	case KindUser:
		gd, err := guid.FromBytes(eo.immutable)
		if err != nil {
			return nil, p, nil // not a GUID anchor: it matches nothing here (string anchors are separate)
		}
		p.match, p.anchor = MatchAnchor, eo.immutable
		q = `SELECT connection_id::text, object_guid::text, COALESCE(consistency_guid = $2, false) FROM public.directory_objects
			WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND connection_id = ANY($1::uuid[])
			AND nc_guid IS NOT NULL AND kind IN ('user','inetorgperson') AND state <> 'purged' AND (consistency_guid = $2 OR object_guid = $3::uuid)
			ORDER BY connection_id, object_guid LIMIT $4`
		args = []any{ids, gd.Bytes(), gd.String(), maxCandidate}
	default:
		return nil, p, nil
	}
	rows, err := tx.Query(ctx, q, args...)
	if err != nil {
		return nil, p, fmt.Errorf("inventory: resolve: %w", err)
	}
	defer rows.Close()
	var refs []Ref
	p.attr = "objectGUID"
	for rows.Next() {
		var c, o string
		var byCG bool
		if err := rows.Scan(&c, &o, &byCG); err != nil {
			return nil, p, fmt.Errorf("inventory: resolve: %w", err)
		}
		refs = append(refs, Ref{ConnectionID(c), GUID(o)})
		if byCG {
			p.attr = "ms-DS-ConsistencyGuid"
		}
	}
	if p.match == MatchSID {
		p.attr = ""
	}
	return refs, p, rows.Err()
}

// kindFits: a user pairs with an AD user or inetOrgPerson, a group with an AD group.
func kindFits(entra Kind, ad string) bool {
	switch entra {
	case KindUser:
		return ad == string(KindUser) || ad == string(KindInetOrgPerson)
	case KindGroup:
		return ad == string(KindGroup)
	}
	return false
}

func (g Ingester) judge(ctx context.Context, tx store.Tx, entra ConnectionID, eo entraRow, p pair, takeover TakeoverProtection,
	firstAttested time.Time, confirmed map[domainKey]bool, domains map[domainKey]string, c Cycle, out *Ingested) error {

	var ad adRow
	ad.conn, ad.guid = p.ad.Connection, p.ad.Object
	var nc *string
	err := tx.QueryRow(ctx, `SELECT kind, state, sid, nc_guid::text FROM public.directory_objects
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND connection_id = $1::uuid AND object_guid = $2::uuid`,
		string(p.ad.Connection), string(p.ad.Object)).Scan(&ad.kind, &ad.state, &ad.sid, &nc)
	missing := store.IsNoRows(err)
	if err != nil && !missing {
		return fmt.Errorf("inventory: ad object: %w", err)
	}
	if nc != nil {
		ad.nc = *nc
	}

	isGroup := eo.kind == KindGroup
	gone := eo.state != ObjActive || missing
	switch ObjectState(ad.state) {
	case ObjDeleted, ObjRecycled, ObjPurged, ObjOutOfScope:
		gone = true
	}
	adSID := ad.sid
	if len(adSID) == 0 && gone {
		adSID = p.storedSID // evidence for a stored SID correlation only; the gate judges it SideGone
	}
	if p.match == MatchSID && len(adSID) < 8 {
		return fmt.Errorf("%w: sid correlation without an AD SID", ErrCorrupt)
	}

	dk := domainKey{p.ad.Connection, ad.nc}
	dom, ok := domains[dk]
	if !ok && ad.nc != "" {
		var d *string
		err := tx.QueryRow(ctx, `SELECT dn FROM public.directory_objects
			WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND connection_id = $1::uuid AND object_guid = $2::uuid`,
			string(p.ad.Connection), ad.nc).Scan(&d)
		if err != nil && !store.IsNoRows(err) {
			return fmt.Errorf("inventory: domain head: %w", err)
		}
		if d != nil {
			dom = dnsName(*d)
		}
		domains[dk] = dom
	}

	matches := p.matchCount
	// A principal-type mismatch never passes the gate (DM-20.I1a is user-to-user, group-to-group): a stored
	// correlation whose AD row is no longer the right kind counts no anchor match / no AD SID.
	if !kindFits(eo.kind, ad.kind) {
		matches = 0
		adSID = nil
		p.resolved = false
	}
	if !p.resolved {
		matches = 0 // the anchor no longer resolves to this object: never carry the old pair on a count of another
	}
	in := GateInput{
		IsGroup:           isGroup,
		SideGone:          gone,
		EntraSyncEnabled:  eo.syncEnabled,
		EntraCloudManaged: eo.cloudMgd,
		EntraSID:          eo.sid,
		ADSID:             adSID,
		EntraDomainName:   eo.domain,
		ADDomainName:      dom,
		LinkConfirmed:     ad.nc != "" && confirmed[dk],
		AnchorMatches:     matches,
		Takeover:          takeover,
		FirstAttestedAt:   firstAttested,
	}
	if eo.cloudSeen != nil {
		in.CloudSeenAt = *eo.cloudSeen
	}
	facts, err := g.Classifier.Classify(ctx, tx, p.ad, Ref{entra, eo.guid})
	if err != nil {
		return fmt.Errorf("inventory: classify pair: %w", err)
	}
	f, err := g.Form(ctx, tx, Formation{
		AD: p.ad, Entra: Ref{entra, eo.guid}, Match: p.match, AnchorAttr: p.attr, AnchorValue: p.anchor,
		Gate: in, ADBases: facts.ADBases, EntraBases: facts.EntraBases, FactsAsOf: facts.AsOf, Now: c.Now,
	})
	if err != nil {
		return err
	}
	out.Pairs++
	if f.Created {
		out.Created++
	}
	switch f.Verdict.State {
	case StateMatched:
		out.Matched++
	case StateCandidate:
		out.Candidates++
	case StateBroken:
		out.Broken++
	}
	return nil
}

// dnsName is the DNS name a domain head's DN spells: DC=corp,DC=example is corp.example. It is "" for
// anything else, and the gate then fails a populated onPremisesDomainName closed.
func dnsName(dnText string) string {
	d, err := dn.Parse(dnText, dn.Strict)
	if err != nil {
		return ""
	}
	var labels []string
	for _, r := range d.RDNs() {
		if r.Type() != dn.DC {
			return ""
		}
		labels = append(labels, r.Value())
	}
	out := ""
	for i, l := range labels {
		if i > 0 {
			out += "."
		}
		out += l
	}
	return out
}
