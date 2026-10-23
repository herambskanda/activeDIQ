package rights

// AD half of the rights check: threat-model §6.5 steps 1-5, contract §8.4 (V7, V8, V9). It runs as
// the connector identity, reads only (never the SACL, never a write) and holds identifiers only
// (DM-24.I3): no DN, name or attribute value goes into a finding.
//
// Fail closed (FR-11): a read that fails never yields a pass. The step it feeds produces a
// COULD_NOT_VERIFY finding naming the object, the check's outcome is COULD_NOT_VERIFY and so is the
// verdict, unless the identity cannot be read at all, which VerifyAD returns as an error (the caller
// records FAILED).
//
// Scope (stated, not hidden): one domain (the bound DC's) plus the Configuration and Schema NCs, the
// same scope as the tier0 classifier. Windows-lab-only: exact ACE semantics of inherited
// AdminSDHolder ACEs (SDProp, CC-VER-06), `tokenGroupsGlobalAndUniversal` readability (R1), R10 and
// R11 expectations, and the second-domain and global-catalog cases.

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/tier0"
	adguid "github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	v1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// Finding codes of the AD half (DM X6 registered strings).
const (
	CodeTier0Group      = "over.tier0_group"
	CodeTier0Write      = "over.tier0_write"      // WP on an attribute of a tier0 object (step 2)
	CodeTier0Child      = "over.tier0_child"      // CC of a class under a tier0 object (step 2)
	CodeTier0WriteDACL  = "over.tier0_write_dacl" // WRITE_DAC
	CodeTier0WriteOwner = "over.tier0_write_owner"
	CodeTier0WriteSACL  = "over.tier0_write_sacl"
	CodeTier0Control    = "over.tier0_control_access"
	CodeTier0Validated  = "over.tier0_validated_write"
	CodeTier0Confid     = "over.tier0_confidential_read"
	CodeTier0GenericAll = "over.tier0_generic_all"
	CodeTier0GenericWr  = "over.tier0_generic_write"
	CodeTier0DeleteTree = "over.tier0_delete_tree"
	CodeExcessOU        = "over.managed_ou_" // + kind slug
	CodeDelegUncons     = "over.delegation_unconstrained"
	CodeDelegConstr     = "over.delegation_constrained"
	CodeDelegProto      = "over.delegation_protocol_transition"
	CodeDelegRBCD       = "over.delegation_rbcd"
	CodeMissingRead     = "missing.read_domain"
	CodeMissingFamily   = "missing.family_right"
	CodeUnverifiedAD    = "unverified.ad"
)

const (
	v7 = v1.VerificationCheck_VERIFICATION_CHECK_V7_OVER_PRIVILEGE
	v8 = v1.VerificationCheck_VERIFICATION_CHECK_V8_READ_SUFFICIENCY
	v9 = v1.VerificationCheck_VERIFICATION_CHECK_V9_EXCESS_IN_MANAGED_OUS
)

// CheckListVersionAD pins the AD check list a run executes (DM-24 `check_list_version`).
const CheckListVersionAD = "ad-1"

const (
	uacTrustedForDelegation   = 0x80000
	uacTrustedToAuthForDeleg  = 0x1000000
	uacServerTrust            = 0x2000
	uacPartialSecrets         = 0x4000000
	attrRBCD                  = "msDS-AllowedToActOnBehalfOfOtherIdentity"
	attrAllowedToDelegateTo   = "msDS-AllowedToDelegateTo"
	attrAllowedAttrs          = "allowedAttributesEffective"
	attrAllowedChild          = "allowedChildClassesEffective"
	attrSDRights              = "sDRightsEffective"
	sdRightsOwner, sdRightsGp = 1, 2
	sdRightsDACL, sdRightsSAC = 4, 8
)

// ADInput is what the server supplies (the request's fields, decoded and validated) and the
// connector's own binding: the identity it authenticated as.
type ADInput struct {
	// Identity is the connector's own account (V5), by GUID or DN.
	Identity dn.ObjectRef
	// EnabledFamilies are the families the connection has enabled; rights beyond them are excess.
	EnabledFamilies []v1.RightsFamily
	// ManagedDomains are the domain NC heads (V8) and ManagedRoots the delegation roots (V9).
	ManagedDomains, ManagedRoots []adguid.GUID
	// Designated and Correlated add to the computed tier0 set (customer designations, C16).
	Designated, Correlated []adguid.GUID
	// Snapshot computes the tier0 computed set. Nil means the AD classifier over the same directory
	// (production); tests supply a fixed set.
	Snapshot func(ctx context.Context) (*tier0.ADSet, error)
}

// ADResult is the AD rights check's outcome.
type ADResult struct {
	Findings []Finding
	// Checks has V7, V8 and V9, in that order.
	Checks  []*v1.CheckResult
	Verdict v1.VerificationVerdict
	// WriteGateOpenable is true only for a PASS verdict (overridable-finding admission is the
	// server's and the write gate's decision, contract §8.2).
	WriteGateOpenable bool
	Identity          *v1.AdObservedIdentity
	// Tier0Set is the connector's computed set plus the designated and correlated inputs, with bases.
	Tier0Set []*v1.Tier0Member
}

// Blocking reports whether any finding has block severity.
func (r *ADResult) Blocking() bool {
	for _, f := range r.Findings {
		if f.Severity == v1.FindingSeverity_FINDING_SEVERITY_BLOCK {
			return true
		}
	}
	return false
}

type member struct {
	g     adguid.GUID
	bases map[tier0.Basis]bool
}

type adCheck struct {
	ctx context.Context
	d   ADDirectory
	in  ADInput
	nm  tier0.Naming

	idGUID adguid.GUID
	idSID  sid.SID
	domSID sid.SID
	hasDom bool
	// tokens is every SID the identity's access token holds (what an access check sees); own drops
	// the universal ones every authenticated principal holds, so a right is blamed on the identity's
	// own delegation and not on a baseline ACE that grants everyone.
	tokens, own map[string]bool

	set     map[string]*member
	out     []Finding
	errs    map[v1.VerificationCheck]error
	famSet  map[v1.RightsFamily]bool
	schName map[string]*SchemaObject // by lower-case name+kind; nil = not found
	schID   map[adguid.GUID]*SchemaObject
}

// snapshotHook replaces the tier0 classifier for tests of StreamAD, which builds its own ADInput.
var snapshotHook func(ctx context.Context) (*tier0.ADSet, error)

var errNoIdentity = errors.New("rights: the connector identity could not be read")

// VerifyAD runs V7 (steps 1, 2, 3, 5), V8 and V9 as the connector identity.
func VerifyAD(ctx context.Context, d ADDirectory, in ADInput) (*ADResult, error) {
	nm, err := d.Naming(ctx)
	if err != nil {
		return nil, fmt.Errorf("naming contexts: %w", err)
	}
	c := &adCheck{ctx: ctx, d: d, in: in, nm: nm, errs: map[v1.VerificationCheck]error{},
		set: map[string]*member{}, famSet: map[v1.RightsFamily]bool{},
		schName: map[string]*SchemaObject{}, schID: map[adguid.GUID]*SchemaObject{}}
	for _, f := range in.EnabledFamilies {
		c.famSet[f] = true
	}
	id, err := d.Read(ctx, in.Identity, []string{"objectSid", "tokenGroups", "userAccountControl", attrAllowedToDelegateTo, "primaryGroupID", "memberOf"}, ad.ReadOptions{})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errNoIdentity, err)
	}
	if c.idGUID, err = id.GUID(); err != nil {
		return nil, fmt.Errorf("%w: %v", errNoIdentity, err)
	}
	sids, err := id.SIDs("objectSid")
	if err != nil || len(sids) != 1 {
		return nil, fmt.Errorf("%w: objectSid", errNoIdentity)
	}
	c.idSID = sids[0]
	c.domSID, c.hasDom = c.idSID.DomainSID()
	groups, err := id.SIDs("tokenGroups")
	if err != nil {
		return nil, fmt.Errorf("%w: tokenGroups", errNoIdentity)
	}
	c.tokens, c.own = map[string]bool{c.idSID.String(): true}, map[string]bool{c.idSID.String(): true}
	for _, g := range groups {
		c.tokens[g.String()] = true
		if !universalSID(g) {
			c.own[g.String()] = true
		}
	}

	res := &ADResult{Identity: &v1.AdObservedIdentity{ObjectGuid: pbGuid(c.idGUID), ObjectSid: &v1.Sid{Value: c.idSID.Bytes()}}}

	snap := in.Snapshot
	if snap == nil {
		snap = snapshotHook
	}
	if snap == nil {
		snap = tier0.NewAD(d).Snapshot
	}
	set, serr := snap(ctx)
	if serr != nil {
		// Without the set, steps 1-3 cannot be decided: refuse to pass (FR-11).
		c.cannot(v7, nil, serr)
	} else {
		for _, g := range set.Members() {
			m := &member{g: g, bases: map[tier0.Basis]bool{}}
			for _, b := range set.Bases(g) {
				m.bases[b] = true
			}
			c.set[g.String()] = m
		}
	}
	c.addInputs(in.Designated, tier0.Designated)
	c.addInputs(in.Correlated, tier0.C16)

	if serr == nil {
		c.step1(id)
		c.step23()
	}
	c.step5(id)
	c.v8()
	c.v9()

	res.Findings = c.out
	sort.SliceStable(res.Findings, func(i, j int) bool {
		a, b := res.Findings[i], res.Findings[j]
		if a.Check != b.Check {
			return a.Check < b.Check
		}
		if a.Code != b.Code {
			return a.Code < b.Code
		}
		if x, y := objKey(a.RightsFinding), objKey(b.RightsFinding); x != y {
			return x < y
		}
		return a.Qualifier < b.Qualifier
	})
	for _, m := range c.sortedSet() {
		tm := &v1.Tier0Member{Object: pbGuid(m.g)}
		for b := range m.bases {
			tm.Basis = append(tm.Basis, b)
		}
		sort.Slice(tm.Basis, func(i, j int) bool { return tm.Basis[i] < tm.Basis[j] })
		res.Tier0Set = append(res.Tier0Set, tm)
	}
	c.finish(res)
	return res, nil
}

func objKey(f *v1.RightsFinding) string {
	if f.Object == nil {
		return ""
	}
	return string(f.Object.Value)
}

func (c *adCheck) sortedSet() []*member {
	out := make([]*member, 0, len(c.set))
	for _, m := range c.set {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].g.String() < out[j].g.String() })
	return out
}

func (c *adCheck) addInputs(gs []adguid.GUID, b tier0.Basis) {
	for _, g := range gs {
		m := c.set[g.String()]
		if m == nil {
			m = &member{g: g, bases: map[tier0.Basis]bool{}}
			c.set[g.String()] = m
		}
		m.bases[b] = true
	}
}

func (m *member) basisList() []v1.Tier0Basis {
	out := make([]v1.Tier0Basis, 0, len(m.bases))
	for b := range m.bases {
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// universalSID reports whether every authenticated principal holds s (or a logon-session or
// asserted-identity SID the access token carries without any delegation).
func universalSID(s sid.SID) bool {
	t := s.String()
	switch t {
	case "S-1-1-0", "S-1-5-11", "S-1-5-2", "S-1-5-4", "S-1-5-14", "S-1-5-15", "S-1-5-10":
		return true
	}
	for _, p := range []string{"S-1-5-5-", "S-1-5-64-", "S-1-18-", "S-1-2-"} {
		if strings.HasPrefix(t, p) {
			return true
		}
	}
	return false
}

func pbGuid(g adguid.GUID) *v1.Guid {
	b, err := guidBytes(g.String())
	if err != nil {
		return &v1.Guid{}
	}
	return &v1.Guid{Value: b}
}

// ParseGUID decodes a v1.Guid (RFC 4122 network order) into the AD codec's GUID.
func ParseGUID(g *v1.Guid) (adguid.GUID, error) {
	if g == nil || len(g.Value) != 16 {
		return adguid.GUID{}, errors.New("not a 16-byte GUID")
	}
	h := fmt.Sprintf("%x", g.Value)
	return adguid.Parse(h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:])
}

func (c *adCheck) cannot(check v1.VerificationCheck, obj *adguid.GUID, err error) {
	if c.errs[check] == nil {
		c.errs[check] = err
	}
	f := &v1.RightsFinding{Check: check, Kind: v1.FindingKind_FINDING_KIND_COULD_NOT_VERIFY,
		Severity: v1.FindingSeverity_FINDING_SEVERITY_BLOCK, Code: CodeUnverifiedAD}
	if obj != nil {
		f.Object = pbGuid(*obj)
		f.ObjectDomainSid = c.domainSid()
	}
	c.out = append(c.out, Finding{RightsFinding: f})
}

func (c *adCheck) domainSid() *v1.Sid {
	if !c.hasDom {
		return nil
	}
	return &v1.Sid{Value: c.domSID.Bytes()}
}

func (c *adCheck) add(f *v1.RightsFinding, obj adguid.GUID, qualifier string) {
	f.Object = pbGuid(obj)
	f.ObjectDomainSid = c.domainSid()
	c.out = append(c.out, Finding{RightsFinding: f, Qualifier: qualifier})
}

func notFound(err error) bool { return ad.CodeOf(err) == ad.CodeObjectNotFound }

// ---- schema -------------------------------------------------------------------------------

func (c *adCheck) attrByName(name string) (*SchemaObject, error)  { return c.byName(name, false) }
func (c *adCheck) classByName(name string) (*SchemaObject, error) { return c.byName(name, true) }

func (c *adCheck) byName(name string, class bool) (*SchemaObject, error) {
	key := fmt.Sprintf("%v|%s", class, strings.ToLower(name))
	if o, ok := c.schName[key]; ok {
		return o, nil
	}
	o, found, err := c.d.SchemaByName(c.ctx, name, class)
	if err != nil {
		return nil, err
	}
	var p *SchemaObject
	if found {
		p = &o
		c.schID[o.ID] = p
	}
	c.schName[key] = p
	return p, nil
}

func (c *adCheck) byID(id adguid.GUID) (*SchemaObject, error) {
	if o, ok := c.schID[id]; ok {
		return o, nil
	}
	o, found, err := c.d.SchemaByID(c.ctx, id)
	if err != nil {
		return nil, err
	}
	var p *SchemaObject
	if found {
		p = &o
	}
	c.schID[id] = p
	return p, nil
}

// ---- step 1: tokenGroups ∩ C1, C13, designated -------------------------------------------------

var step1Bases = []tier0.Basis{tier0.C1, tier0.C13, tier0.Designated, tier0.C16}

type node struct {
	g       adguid.GUID
	s       sid.SID
	parents []string // lower-case DNs (memberOf)
	primary string   // SID text of the primary group
	dn      string
}

func (c *adCheck) step1(id *ad.Entry) {
	idn := c.nodeOf(id)
	// Direct parents of the identity: memberOf groups and the primary group.
	type edge struct {
		key     string // node cache key
		primary bool
	}
	var direct []edge
	for _, p := range idn.parents {
		direct = append(direct, edge{key: p})
	}
	if idn.primary != "" {
		direct = append(direct, edge{key: "sid:" + idn.primary, primary: true})
	}

	// Candidate groups: the domain and builtin groups of the token. Others (Everyone, logon SIDs)
	// are never C1, C13 or designated.
	var cands []sid.SID
	for t := range c.tokens {
		s, err := sid.Parse(t)
		if err != nil || (!strings.HasPrefix(t, "S-1-5-21-") && !strings.HasPrefix(t, "S-1-5-32-")) || s == c.idSID {
			continue
		}
		cands = append(cands, s)
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].String() < cands[j].String() })

	cache := map[string]*node{}
	read := func(ref dn.ObjectRef) (*node, error) {
		e, err := c.d.Read(c.ctx, ref, []string{"objectSid", "memberOf", "primaryGroupID"}, ad.ReadOptions{})
		if err != nil {
			return nil, err
		}
		return c.nodeOf(e), nil
	}
	// resolve a SID to a node (nil when no object has it)
	bySID := func(s sid.SID) (*node, error) {
		k := "sid:" + s.String()
		if n, ok := cache[k]; ok {
			return n, nil
		}
		n, err := read(dn.SIDRef(s))
		if err != nil && notFound(err) {
			cache[k] = nil
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		cache[k] = n
		return n, nil
	}
	byDN := func(text string) (*node, error) {
		if n, ok := cache[text]; ok {
			return n, nil
		}
		d, err := dn.Parse(text, dn.Strict)
		if err != nil {
			return nil, err
		}
		n, err := read(dn.DNRef(d))
		if err != nil {
			return nil, err
		}
		cache[text] = n
		return n, nil
	}
	// parentsOf expands a node one level, restricted to groups in the token (a group outside it
	// cannot lead to a token group).
	parentsOf := func(n *node) ([]*node, error) {
		var out []*node
		for _, p := range n.parents {
			pn, err := byDN(p)
			if err != nil {
				return nil, err
			}
			if pn != nil && c.tokens[pn.s.String()] {
				out = append(out, pn)
			}
		}
		if n.primary != "" {
			ps, err := sid.Parse(n.primary)
			if err == nil && c.tokens[ps.String()] {
				pn, err := bySID(ps)
				if err != nil {
					return nil, err
				}
				if pn != nil {
					out = append(out, pn)
				}
			}
		}
		return out, nil
	}

	for _, gs := range cands {
		gn, err := bySID(gs)
		if err != nil {
			c.cannot(v7, nil, err)
			continue
		}
		if gn == nil {
			continue
		}
		m := c.set[gn.g.String()]
		if m == nil {
			continue
		}
		var basis []v1.Tier0Basis
		for _, b := range step1Bases {
			if m.bases[b] {
				basis = append(basis, b)
			}
		}
		if len(basis) == 0 {
			continue
		}
		// One finding per direct path (first hop).
		emitted := false
		for _, e := range direct {
			var first *node
			var err error
			if e.primary {
				ps, perr := sid.Parse(strings.TrimPrefix(e.key, "sid:"))
				if perr != nil {
					continue
				}
				first, err = bySID(ps)
			} else {
				first, err = byDN(e.key)
			}
			if err != nil {
				c.cannot(v7, &gn.g, err)
				emitted = true
				continue
			}
			if first == nil || !c.tokens[first.s.String()] {
				continue
			}
			path, err := c.pathTo(first, gn, parentsOf)
			if err != nil {
				c.cannot(v7, &gn.g, err)
				emitted = true
				continue
			}
			if path == nil {
				continue
			}
			hops := make([]*v1.MembershipHop, len(path))
			for i, p := range path {
				hops[i] = &v1.MembershipHop{Group: pbGuid(p.g), Sid: &v1.Sid{Value: p.s.Bytes()}}
			}
			hops[0].PrimaryGroupEdge = e.primary
			c.add(&v1.RightsFinding{Check: v7, Kind: v1.FindingKind_FINDING_KIND_TIER0_GROUP_MEMBERSHIP,
				Severity: v1.FindingSeverity_FINDING_SEVERITY_BLOCK, Code: CodeTier0Group, ObjectTier0Basis: basis,
				Source: &v1.RightSource{Source: &v1.RightSource_Membership{Membership: &v1.MembershipPath{Hops: hops}}}},
				gn.g, path[0].g.String())
			emitted = true
		}
		if !emitted {
			// The token holds the group but no path was found through the direct edges (a group from
			// another domain's universal membership, SID history): report it with the group alone.
			c.add(&v1.RightsFinding{Check: v7, Kind: v1.FindingKind_FINDING_KIND_TIER0_GROUP_MEMBERSHIP,
				Severity: v1.FindingSeverity_FINDING_SEVERITY_BLOCK, Code: CodeTier0Group, ObjectTier0Basis: basis,
				Source: &v1.RightSource{Source: &v1.RightSource_Membership{Membership: &v1.MembershipPath{
					Hops: []*v1.MembershipHop{{Group: pbGuid(gn.g), Sid: &v1.Sid{Value: gn.s.Bytes()}}}}}}},
				gn.g, gn.g.String())
		}
	}
}

// pathTo returns the shortest chain first -> ... -> target through the token's groups, or nil.
func (c *adCheck) pathTo(first, target *node, parents func(*node) ([]*node, error)) ([]*node, error) {
	if first.g == target.g {
		return []*node{first}, nil
	}
	prev := map[adguid.GUID]*node{first.g: nil}
	queue := []*node{first}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		ps, err := parents(n)
		if err != nil {
			return nil, err
		}
		for _, p := range ps {
			if _, seen := prev[p.g]; seen {
				continue
			}
			prev[p.g] = n
			if p.g == target.g {
				var rev []*node
				for x := p; x != nil; x = prev[x.g] {
					rev = append(rev, x)
				}
				out := make([]*node, len(rev))
				for i := range rev {
					out[len(rev)-1-i] = rev[i]
				}
				return out, nil
			}
			queue = append(queue, p)
		}
	}
	return nil, nil
}

func (c *adCheck) nodeOf(e *ad.Entry) *node {
	n := &node{dn: e.DN}
	if g, err := e.GUID(); err == nil {
		n.g = g
	}
	if ss, err := e.SIDs("objectSid"); err == nil && len(ss) == 1 {
		n.s = ss[0]
		if n.s == c.idSID {
			n.s = c.idSID
		}
	}
	for _, p := range e.Strings("memberOf") {
		n.parents = append(n.parents, p)
	}
	if rid, ok, err := e.Int32("primaryGroupID"); err == nil && ok && c.hasDom {
		n.primary = c.domSIDWithRID(uint32(rid))
	}
	return n
}

func (c *adCheck) domSIDWithRID(rid uint32) string {
	s, err := sid.Parse(fmt.Sprintf("%s-%d", c.domSID.String(), rid))
	if err != nil {
		return ""
	}
	return s.String()
}

// ---- steps 2 and 3: each tier0 object ------------------------------------------------------

func (c *adCheck) step23() {
	for _, m := range c.sortedSet() {
		if err := c.ctx.Err(); err != nil {
			c.cannot(v7, &m.g, err)
			return
		}
		e, err := c.d.Read(c.ctx, dn.GUIDRef(m.g), []string{"nTSecurityDescriptor", attrAllowedAttrs, attrAllowedChild, attrSDRights}, ad.ReadOptions{SD: ad.DefaultSDFlags()})
		if err != nil {
			if notFound(err) && (m.bases[tier0.Designated] || m.bases[tier0.C16]) {
				continue // the server's designation names an object that no longer exists
			}
			c.cannot(v7, &m.g, err)
			continue
		}
		c.step2(m, e)
		c.step3(m, e)
	}
}

func (c *adCheck) step2(m *member, e *ad.Entry) {
	basis := m.basisList()
	src := func(n v1.EffectiveRightsAttributeName) *v1.RightSource {
		return &v1.RightSource{Source: &v1.RightSource_EffectiveAttribute{EffectiveAttribute: &v1.EffectiveRightsAttribute{Name: n}}}
	}
	for _, name := range e.Strings(attrAllowedAttrs) {
		o, err := c.attrByName(name)
		if err != nil || o == nil {
			if err == nil {
				err = fmt.Errorf("attribute %q is not in the schema", name)
			}
			c.cannot(v7, &m.g, err)
			continue
		}
		c.add(&v1.RightsFinding{Check: v7, Kind: v1.FindingKind_FINDING_KIND_EXCESSIVE_RIGHT, Severity: v1.FindingSeverity_FINDING_SEVERITY_BLOCK,
			Code: CodeTier0Write, ObjectTier0Basis: basis,
			Right:  adRight(v1.AdRightKind_AD_RIGHT_KIND_WRITE_PROPERTY, &o.ID, dsWriteProp, o.Name),
			Source: src(v1.EffectiveRightsAttributeName_EFFECTIVE_RIGHTS_ATTRIBUTE_NAME_ALLOWED_ATTRIBUTES_EFFECTIVE)}, m.g, o.ID.String())
	}
	for _, name := range e.Strings(attrAllowedChild) {
		o, err := c.classByName(name)
		if err != nil || o == nil {
			if err == nil {
				err = fmt.Errorf("class %q is not in the schema", name)
			}
			c.cannot(v7, &m.g, err)
			continue
		}
		c.add(&v1.RightsFinding{Check: v7, Kind: v1.FindingKind_FINDING_KIND_EXCESSIVE_RIGHT, Severity: v1.FindingSeverity_FINDING_SEVERITY_BLOCK,
			Code: CodeTier0Child, ObjectTier0Basis: basis,
			Right:  adRight(v1.AdRightKind_AD_RIGHT_KIND_CREATE_CHILD, &o.ID, dsCreateChild, o.Name),
			Source: src(v1.EffectiveRightsAttributeName_EFFECTIVE_RIGHTS_ATTRIBUTE_NAME_ALLOWED_CHILD_CLASSES_EFFECTIVE)}, m.g, o.ID.String())
	}
	if n, ok, err := e.Int32(attrSDRights); err != nil {
		c.cannot(v7, &m.g, err)
	} else if ok {
		type bit struct {
			mask int32
			kind v1.AdRightKind
			code string
			am   uint32
		}
		for _, b := range []bit{
			{sdRightsOwner | sdRightsGp, v1.AdRightKind_AD_RIGHT_KIND_WRITE_OWNER, CodeTier0WriteOwner, maskWriteOwner},
			{sdRightsDACL, v1.AdRightKind_AD_RIGHT_KIND_WRITE_DAC, CodeTier0WriteDACL, maskWriteDAC},
			{sdRightsSAC, v1.AdRightKind_AD_RIGHT_KIND_WRITE_SACL, CodeTier0WriteSACL, 0x01000000},
		} {
			if n&b.mask == 0 {
				continue
			}
			c.add(&v1.RightsFinding{Check: v7, Kind: v1.FindingKind_FINDING_KIND_EXCESSIVE_RIGHT, Severity: v1.FindingSeverity_FINDING_SEVERITY_BLOCK,
				Code: b.code, ObjectTier0Basis: basis, Right: adRight(b.kind, nil, b.am, ""),
				Source: src(v1.EffectiveRightsAttributeName_EFFECTIVE_RIGHTS_ATTRIBUTE_NAME_SD_RIGHTS_EFFECTIVE)}, m.g, "")
		}
	}
}

func adRight(kind v1.AdRightKind, objType *adguid.GUID, mask uint32, name string) *v1.RightRef {
	r := &v1.AdRight{Kind: kind, AccessMask: mask, ObjectTypeName: name}
	if objType != nil {
		r.ObjectType = pbGuid(*objType)
	}
	return &v1.RightRef{Right: &v1.RightRef_Ad{Ad: r}}
}

func aceSource(on adguid.GUID, a ace) *v1.RightSource {
	return &v1.RightSource{Source: &v1.RightSource_Ace{Ace: &v1.AceSource{
		OnObject: pbGuid(on), Inherited: a.inherited, Trustee: &v1.Sid{Value: a.trustee.Bytes()}}}}
}

func aceQualifier(a ace) string {
	if a.hasType {
		return a.objType.String()
	}
	return a.trustee.String()
}

// aceKind is one right an ACE gives that the check reports.
type aceKind struct {
	kind v1.AdRightKind
	code string
	mask uint32
	typ  *adguid.GUID
}

func (c *adCheck) step3(m *member, e *ad.Entry) {
	raw := e.Raw("nTSecurityDescriptor")
	if len(raw) != 1 {
		c.cannot(v7, &m.g, errors.New("nTSecurityDescriptor not returned"))
		return
	}
	d, err := parseSD(raw[0])
	if err != nil {
		c.cannot(v7, &m.g, err)
		return
	}
	basis := m.basisList()
	for _, g := range d.grants(c.own, false) {
		a := g.ace
		var kinds []aceKind
		var typ *adguid.GUID
		if a.hasType {
			t := a.objType
			typ = &t
		}
		switch {
		case g.genericAll():
			kinds = append(kinds, aceKind{v1.AdRightKind_AD_RIGHT_KIND_GENERIC_ALL, CodeTier0GenericAll, a.mask, nil})
		default:
			if g.genericWrite() {
				kinds = append(kinds, aceKind{v1.AdRightKind_AD_RIGHT_KIND_GENERIC_WRITE, CodeTier0GenericWr, a.mask, nil})
			}
			if g.has(maskWriteDAC) {
				kinds = append(kinds, aceKind{v1.AdRightKind_AD_RIGHT_KIND_WRITE_DAC, CodeTier0WriteDACL, maskWriteDAC, nil})
			}
			if g.has(maskWriteOwner) {
				kinds = append(kinds, aceKind{v1.AdRightKind_AD_RIGHT_KIND_WRITE_OWNER, CodeTier0WriteOwner, maskWriteOwner, nil})
			}
			if g.has(dsDeleteTree) {
				kinds = append(kinds, aceKind{v1.AdRightKind_AD_RIGHT_KIND_DELETE_TREE, CodeTier0DeleteTree, dsDeleteTree, nil})
			}
			if g.has(dsControlAccess) {
				kinds = append(kinds, aceKind{v1.AdRightKind_AD_RIGHT_KIND_CONTROL_ACCESS, CodeTier0Control, dsControlAccess, typ})
			}
			if g.has(dsSelf) {
				kinds = append(kinds, aceKind{v1.AdRightKind_AD_RIGHT_KIND_VALIDATED_WRITE, CodeTier0Validated, dsSelf, typ})
			}
			if g.has(dsReadProp) && a.hasType {
				o, err := c.byID(a.objType)
				switch {
				case err != nil:
					c.cannot(v7, &m.g, err)
				case o != nil && !o.Class && o.SearchFlags&searchFlagConfidential != 0:
					kinds = append(kinds, aceKind{v1.AdRightKind_AD_RIGHT_KIND_READ_PROPERTY, CodeTier0Confid, dsReadProp, typ})
				}
			}
		}
		for _, k := range kinds {
			name := ""
			if k.typ != nil {
				if o, err := c.byID(*k.typ); err == nil && o != nil {
					name = o.Name
				}
			}
			c.add(&v1.RightsFinding{Check: v7, Kind: v1.FindingKind_FINDING_KIND_EXCESSIVE_RIGHT, Severity: v1.FindingSeverity_FINDING_SEVERITY_BLOCK,
				Code: k.code, ObjectTier0Basis: basis, Right: adRight(k.kind, k.typ, k.mask, name), Source: aceSource(m.g, a)}, m.g, aceQualifier(a))
		}
	}
}

// ---- step 5: the identity's own delegation ---------------------------------------------------

func (c *adCheck) step5(id *ad.Entry) {
	idSrc := func(a v1.IdentityAttribute) *v1.RightSource {
		return &v1.RightSource{Source: &v1.RightSource_IdentityAttribute{IdentityAttribute: a}}
	}
	deleg := func(s v1.DelegationSetting) *v1.RightRef {
		return &v1.RightRef{Right: &v1.RightRef_Delegation{Delegation: s}}
	}
	uac, _, err := id.Int32("userAccountControl")
	if err != nil {
		c.cannot(v7, &c.idGUID, err)
	}
	src := idSrc(v1.IdentityAttribute_IDENTITY_ATTRIBUTE_USER_ACCOUNT_CONTROL)
	if uint32(uac)&uacTrustedForDelegation != 0 {
		c.add(&v1.RightsFinding{Check: v7, Kind: v1.FindingKind_FINDING_KIND_DELEGATION_CONFIGURED, Severity: v1.FindingSeverity_FINDING_SEVERITY_BLOCK,
			Code: CodeDelegUncons, Right: deleg(v1.DelegationSetting_DELEGATION_SETTING_UNCONSTRAINED), Source: src}, c.idGUID, "")
	}
	if uint32(uac)&uacTrustedToAuthForDeleg != 0 {
		c.add(&v1.RightsFinding{Check: v7, Kind: v1.FindingKind_FINDING_KIND_DELEGATION_CONFIGURED, Severity: v1.FindingSeverity_FINDING_SEVERITY_BLOCK,
			Code: CodeDelegProto, Right: deleg(v1.DelegationSetting_DELEGATION_SETTING_PROTOCOL_TRANSITION), Source: src}, c.idGUID, "")
	}
	if len(id.Raw(attrAllowedToDelegateTo)) > 0 {
		c.add(&v1.RightsFinding{Check: v7, Kind: v1.FindingKind_FINDING_KIND_DELEGATION_CONFIGURED, Severity: v1.FindingSeverity_FINDING_SEVERITY_BLOCK,
			Code: CodeDelegConstr, Right: deleg(v1.DelegationSetting_DELEGATION_SETTING_CONSTRAINED),
			Source: idSrc(v1.IdentityAttribute_IDENTITY_ATTRIBUTE_MS_DS_ALLOWED_TO_DELEGATE_TO)}, c.idGUID, "")
	}
	// RBCD: every DC (full or read-only) whose msDS-AllowedToActOnBehalfOfOtherIdentity lists the
	// identity or one of its groups.
	q := tier0.Query{Classes: []string{"computer"}, UACAny: uacServerTrust | uacPartialSecrets, Has: []string{attrRBCD}}
	type dcHit struct{ g adguid.GUID }
	var hits []dcHit
	var found []*ad.Entry
	err = c.d.Find(c.ctx, c.nm.Domain, ad.ScopeSubtree, q, []string{"objectGUID", attrRBCD}, func(e *ad.Entry) error {
		found = append(found, e)
		return nil
	})
	if err != nil {
		c.cannot(v7, nil, err)
		return
	}
	for _, e := range found {
		g, gerr := e.GUID()
		if gerr != nil {
			c.cannot(v7, nil, gerr)
			continue
		}
		raw := e.Raw(attrRBCD)
		if len(raw) != 1 {
			continue
		}
		d, perr := parseSD(raw[0])
		if perr != nil {
			c.cannot(v7, &g, perr)
			continue
		}
		listed := false
		for _, a := range d.aces {
			if !a.deny && c.tokens[a.trustee.String()] && !universalSID(a.trustee) {
				listed = true
			}
		}
		if listed {
			hits = append(hits, dcHit{g})
		}
	}
	for _, h := range hits {
		c.add(&v1.RightsFinding{Check: v7, Kind: v1.FindingKind_FINDING_KIND_DELEGATION_CONFIGURED, Severity: v1.FindingSeverity_FINDING_SEVERITY_BLOCK,
			Code: CodeDelegRBCD, Right: deleg(v1.DelegationSetting_DELEGATION_SETTING_RESOURCE_BASED),
			Source: idSrc(v1.IdentityAttribute_IDENTITY_ATTRIBUTE_MS_DS_ALLOWED_TO_ACT_ON_BEHALF_OF_OTHER_IDENTITY)}, h.g, "")
	}
}

// ---- verdict ---------------------------------------------------------------------------------

func (c *adCheck) finish(r *ADResult) {
	block, warn := v1.FindingSeverity_FINDING_SEVERITY_BLOCK, v1.FindingSeverity_FINDING_SEVERITY_WARN
	has := func(ch v1.VerificationCheck, sev v1.FindingSeverity) bool {
		for _, f := range r.Findings {
			if f.Check == ch && f.Severity == sev {
				return true
			}
		}
		return false
	}
	cnv, refused := false, false
	for _, ch := range []v1.VerificationCheck{v7, v8, v9} {
		cr := &v1.CheckResult{Check: ch, Outcome: v1.CheckOutcome_CHECK_OUTCOME_PASS}
		switch {
		case c.errs[ch] != nil:
			cr.Outcome = v1.CheckOutcome_CHECK_OUTCOME_COULD_NOT_VERIFY
			cr.Error = connectorError(c.errs[ch])
			cnv = true
		case has(ch, block):
			cr.Outcome = v1.CheckOutcome_CHECK_OUTCOME_FAIL
			refused = refused || ch != v9
		case has(ch, warn):
			cr.Outcome = v1.CheckOutcome_CHECK_OUTCOME_WARN
		}
		r.Checks = append(r.Checks, cr)
	}
	switch {
	case cnv:
		r.Verdict = v1.VerificationVerdict_VERIFICATION_VERDICT_COULD_NOT_VERIFY
	case refused:
		r.Verdict = v1.VerificationVerdict_VERIFICATION_VERDICT_REFUSED
	default:
		r.Verdict = v1.VerificationVerdict_VERIFICATION_VERDICT_PASS
	}
	r.WriteGateOpenable = r.Verdict == v1.VerificationVerdict_VERIFICATION_VERDICT_PASS
}
