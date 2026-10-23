package tier0

// AD half of the tier0 set: threat-model §6.4 C1-C16 (TM-D4, TM-D2 check 2). The connector computes
// it for its own forest from live reads, independent of the server. The server supplies only what
// the connector cannot read: customer designations and the correlation set for C16.
//
// Identity is objectGUID. DNs are used to walk structure (ancestors of DCs, SOM reach) and are
// always taken from the DC's own responses.
//
// Fail closed: any read error, unparsable gPLink or security descriptor, unresolvable target or
// missing correlation statement yields {Tier0, Unknown} plus the error. Nothing the caller passes can
// remove a computed entry.
//
// Scope limits (stated, not hidden): one domain (the bound DC's) plus the Configuration and Schema
// NCs; a target in another domain is Unknown (tier0). C9 reach over-approximates DM-23.I5: it ignores
// block-inheritance and loopback (both only narrow reach), so it may protect more than strictly
// needed, never less. Windows-only behaviour (live DACL, RODC corroboration) is Samba-lab-checked only
// for LDAP semantics; see the ticket note.

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/gplink"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// §6.4 AD rows.
const (
	C1  = connectorv1.Tier0Basis_TIER0_BASIS_C1_PROTECTED_GROUP
	C2  = connectorv1.Tier0Basis_TIER0_BASIS_C2_PROTECTED_GROUP_MEMBER
	C3  = connectorv1.Tier0Basis_TIER0_BASIS_C3_ADMIN_SD_HOLDER
	C4  = connectorv1.Tier0Basis_TIER0_BASIS_C4_KRBTGT
	C5  = connectorv1.Tier0Basis_TIER0_BASIS_C5_DOMAIN_CONTROLLER
	C6  = connectorv1.Tier0Basis_TIER0_BASIS_C6_DC_CONTAINER
	C7  = connectorv1.Tier0Basis_TIER0_BASIS_C7_NAMING_CONTEXT_HEAD
	C8  = connectorv1.Tier0Basis_TIER0_BASIS_C8_SENSITIVE_SYSTEM_OBJECT
	C9  = connectorv1.Tier0Basis_TIER0_BASIS_C9_GPO_REACHING_TIER0
	C10 = connectorv1.Tier0Basis_TIER0_BASIS_C10_PKI
	C11 = connectorv1.Tier0Basis_TIER0_BASIS_C11_DCSYNC_PRINCIPAL
	C12 = connectorv1.Tier0Basis_TIER0_BASIS_C12_DELEGATION_RISK
	C13 = connectorv1.Tier0Basis_TIER0_BASIS_C13_DEFAULT_PRIVILEGED_GROUP
	C14 = connectorv1.Tier0Basis_TIER0_BASIS_C14_SEAMLESS_SSO_ACCOUNT
	C15 = connectorv1.Tier0Basis_TIER0_BASIS_C15_DC_SITE
	C16 = connectorv1.Tier0Basis_TIER0_BASIS_C16_CORRELATED_TO_ENTRA_TIER0
)

const (
	uacServerTrust      = 0x2000
	uacPartialSecrets   = 0x4000000
	uacTrustedForDeleg  = 0x80000
	wkDomainControllers = "A361B2FFFFD211D1AA4B00C04FD7D83A" // GUID_DOMAIN_CONTROLLERS_CONTAINER_W
)

var (
	getChanges    = mustGUID("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2") // DS-Replication-Get-Changes
	getChangesAll = mustGUID("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2") // DS-Replication-Get-Changes-All
)

func mustGUID(s string) guid.GUID {
	g, err := guid.Parse(s)
	if err != nil {
		panic(err)
	}
	return g
}

// protected is one C1 principal by well-known RID (Appendix C). Builtin groups live under
// S-1-5-32; forest-wide groups (Enterprise/Schema/Enterprise Key Admins) under the root domain.
type protected struct {
	rid     uint32
	builtin bool
	root    bool
}

var protectedList = []protected{
	{rid: 500}, {rid: 502}, // Administrator, krbtgt (accounts; krbtgt is also C4)
	{rid: 512}, {rid: 516}, {rid: 521}, {rid: 526}, // Domain Admins, Domain Controllers, RODCs, Key Admins
	{rid: 518, root: true}, {rid: 519, root: true}, {rid: 527, root: true}, // Schema, Enterprise, Enterprise Key Admins
	{rid: 544, builtin: true}, {rid: 548, builtin: true}, {rid: 549, builtin: true}, // Administrators, Account/Server Operators
	{rid: 550, builtin: true}, {rid: 551, builtin: true}, {rid: 552, builtin: true}, // Print/Backup Operators, Replicator
}

// c13Groups are looked up by sAMAccountName in the domain. Group Policy Creator Owners is
// deliberately absent (§6.4 C13).
var c13Groups = []string{"DnsAdmins", "Cert Publishers", "Exchange Trusted Subsystem", "Exchange Windows Permissions"}

// c8Domain are the sensitive CN=System objects, relative to CN=System,<domain>. AdminSDHolder is C3.
var c8Domain = []string{"", "CN=RID Manager$", "CN=Password Settings Container"}

// c8SystemClasses are sensitive by class anywhere under CN=System: DPAPI backup keys (secret) and
// trust objects (trustedDomain).
var c8SystemClasses = []string{"secret", "trustedDomain"}

// ADSet is one computed snapshot of the connector's AD tier0 computed set (C1-C15), by objectGUID.
type ADSet struct {
	bases map[string]map[Basis]bool
}

func (s *ADSet) add(g guid.GUID, b Basis) {
	k := g.String()
	if s.bases[k] == nil {
		s.bases[k] = map[Basis]bool{}
	}
	s.bases[k][b] = true
}

// Len is the number of tier0 objects in the snapshot.
func (s *ADSet) Len() int { return len(s.bases) }

// Bases returns the sorted bases of the object (empty when not in C1-C15).
func (s *ADSet) Bases(g guid.GUID) []Basis { return sortedBases(s.bases[g.String()]) }

// ADClassifier computes the AD tier0 set.
type ADClassifier struct{ d ADDirectory }

// NewAD returns a classifier reading through d.
func NewAD(d ADDirectory) *ADClassifier { return &ADClassifier{d: d} }

// ADInput is the caller-supplied part of the answer.
type ADInput struct {
	// CorrelationKnown must be true: it says Correlated is the complete, current correlation set
	// (empty means none). False is "absence" and never means "no correlation" (contract §8.3 F1).
	CorrelationKnown bool
	// Correlated lists AD objects (Peer.ADObject = objectGUID) correlated to an Entra tier0
	// principal, in any state (C16). The caller (the server) has already computed Entra tier0.
	Correlated []Peer
	// Designated are customer-designated objects, by DN or GUID. They add; they never subtract.
	Designated []dn.ObjectRef
}

// ADResult is the classification of one target.
type ADResult struct {
	Tier0 bool
	// Unknown: the answer could not be computed, so Tier0 is true by the fail-closed rule.
	Unknown bool
	Bases   []Basis
	GUID    guid.GUID // the target's objectGUID when it could be resolved
}

// Classify answers whether target is tier0, re-reading the directory live on every call.
func (c *ADClassifier) Classify(ctx context.Context, target dn.ObjectRef, in ADInput) (ADResult, error) {
	unknown := ADResult{Tier0: true, Unknown: true}
	if !in.CorrelationKnown {
		return unknown, errors.New("tier0: correlation statement not supplied")
	}
	corr := map[string]bool{}
	for _, p := range in.Correlated {
		g, err := guid.Parse(p.ADObject)
		if err != nil { // a correlation we cannot read is one we cannot rule out
			return unknown, errors.New("tier0: correlation names an AD object that is not a GUID")
		}
		corr[g.String()] = true // any state, including unspecified, counts (TM §6.4)
	}
	set, err := c.Snapshot(ctx)
	if err != nil {
		return unknown, err
	}
	te, err := c.d.Get(ctx, target, []string{"objectGUID"})
	if err != nil {
		return unknown, fmt.Errorf("tier0: resolve target: %w", err)
	}
	tg, err := te.GUID()
	if err != nil {
		return unknown, fmt.Errorf("tier0: target: %w", err)
	}
	b := map[Basis]bool{}
	for x := range set.bases[tg.String()] {
		b[x] = true
	}
	if corr[tg.String()] {
		b[C16] = true
	}
	for _, ref := range in.Designated {
		e, err := c.d.Get(ctx, ref, []string{"objectGUID"})
		if err != nil {
			if ad.CodeOf(err) == ad.CodeObjectNotFound {
				continue // designates nothing that exists
			}
			return unknown, fmt.Errorf("tier0: resolve designation: %w", err)
		}
		g, err := e.GUID()
		if err != nil {
			return unknown, fmt.Errorf("tier0: designation: %w", err)
		}
		if g == tg {
			b[Designated] = true
		}
	}
	return ADResult{Tier0: len(b) > 0, Bases: sortedBases(b), GUID: tg}, nil
}

// builder carries one snapshot's working state.
type builder struct {
	ctx context.Context
	d   ADDirectory
	nm  Naming
	s   *ADSet

	domSID, rootSID sid.SID
	domHead         *ad.Entry

	accountAnc map[string]bool      // lower-case DN of every strict ancestor of a tier0 account (C2/C4/C5)
	dcDNs      []dn.DN              // DC computer objects (C5)
	dcHosts    map[string]bool      // lower-case DC host names (FQDN and short) for C12
	dcSD       map[string][]byte    // RBCD descriptors by computer GUID
	cache      map[string]*ad.Entry // Get results by lower-case DN
}

var idAttrs = []string{"objectGUID", "objectSid", "objectClass"}

// Snapshot reads the forest and computes C1-C15. Any error fails the whole snapshot: a caller that
// ignored the error must not be left holding a partial, under-protective set.
func (c *ADClassifier) Snapshot(ctx context.Context) (*ADSet, error) {
	b := &builder{ctx: ctx, d: c.d, s: &ADSet{bases: map[string]map[Basis]bool{}},
		accountAnc: map[string]bool{}, dcHosts: map[string]bool{}, dcSD: map[string][]byte{}, cache: map[string]*ad.Entry{}}
	nm, err := c.d.Naming(ctx)
	if err != nil {
		return nil, fmt.Errorf("tier0: naming contexts: %w", err)
	}
	b.nm = nm
	steps := []func() error{b.c7, b.c1c2, b.c3, b.c4, b.c5c6c15, b.c8, b.c10, b.c11, b.c12, b.c13, b.c14, b.c9}
	for _, step := range steps { // c9 last: it needs C2/C4/C5/C6/C15
		if err := step(); err != nil {
			return nil, err
		}
	}
	return b.s, nil
}

func (b *builder) mark(e *ad.Entry, basis Basis) (guid.GUID, error) {
	g, err := e.GUID()
	if err != nil {
		return g, fmt.Errorf("tier0: entry without objectGUID: %w", err)
	}
	b.s.add(g, basis)
	return g, nil
}

// get reads one object; found is false when it does not exist. Every other error is returned.
func (b *builder) get(ref dn.ObjectRef, attrs []string) (e *ad.Entry, found bool, err error) {
	e, err = b.d.Get(b.ctx, ref, attrs)
	if err != nil {
		if ad.CodeOf(err) == ad.CodeObjectNotFound {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("tier0: read: %w", err)
	}
	return e, true, nil
}

// getDN is get by DN with a per-snapshot cache of id-only reads.
func (b *builder) getDN(d dn.DN) (*ad.Entry, bool, error) {
	k := strings.ToLower(d.String())
	if e, ok := b.cache[k]; ok {
		return e, e != nil, nil
	}
	e, found, err := b.get(dn.DNRef(d), idAttrs)
	if err != nil {
		return nil, false, err
	}
	b.cache[k] = e
	return e, found, nil
}

func (b *builder) child(parent dn.DN, rdns ...string) (dn.DN, error) {
	d := parent
	for _, r := range rdns { // "CN=System" style, one RDN each, value taken verbatim
		t, v, ok := strings.Cut(r, "=")
		if !ok {
			return dn.DN{}, errors.New("tier0: internal: bad rdn")
		}
		typ, err := dn.ParseRDNType(t)
		if err != nil {
			return dn.DN{}, err
		}
		if d, err = dn.Child(d, typ, v); err != nil {
			return dn.DN{}, err
		}
	}
	return d, nil
}

func hasClass(e *ad.Entry, class string) bool {
	for _, c := range e.Strings("objectClass") {
		if strings.EqualFold(c, class) {
			return true
		}
	}
	return false
}

func entryDN(e *ad.Entry) (dn.DN, error) {
	d, err := dn.Parse(e.DN, dn.Strict)
	if err != nil {
		return d, errors.New("tier0: DC returned an unparsable DN")
	}
	return d, nil
}

// noteAccount records a tier0 account's ancestors for C6 and C9 reach.
func (b *builder) noteAccount(e *ad.Entry) error {
	if hasClass(e, "group") {
		return nil
	}
	d, err := entryDN(e)
	if err != nil {
		return err
	}
	for p := d.Parent(); p.Len() > 0; p = p.Parent() {
		b.accountAnc[strings.ToLower(p.String())] = true
	}
	return nil
}

// C7: the naming-context heads.
func (b *builder) c7() error {
	var err error
	for _, h := range []dn.DN{b.nm.Domain, b.nm.RootDomain, b.nm.Config, b.nm.Schema} {
		e, found, gerr := b.get(dn.DNRef(h), []string{"objectGUID", "objectSid", "wellKnownObjects", "gPLink"})
		if gerr != nil {
			return gerr
		}
		if !found {
			return errors.New("tier0: naming-context head not found")
		}
		if _, err = b.mark(e, C7); err != nil {
			return err
		}
		switch {
		case h.Equal(b.nm.Domain):
			b.domHead = e
			if b.domSID, err = oneSID(e); err != nil {
				return err
			}
			if h.Equal(b.nm.RootDomain) {
				b.rootSID = b.domSID
			}
		case h.Equal(b.nm.RootDomain):
			if b.rootSID, err = oneSID(e); err != nil {
				return err
			}
		}
	}
	return nil
}

func oneSID(e *ad.Entry) (sid.SID, error) {
	v, err := e.SIDs("objectSid")
	if err != nil || len(v) != 1 {
		return sid.SID{}, errors.New("tier0: domain head has no objectSid")
	}
	return v[0], nil
}

func withRID(domain sid.SID, rid uint32) (sid.SID, error) {
	return sid.Parse(fmt.Sprintf("%s-%d", domain, rid))
}

// C1 + C2: protected groups by well-known SID, then their transitive members and primary-group edges.
func (b *builder) c1c2() error {
	var groups []*ad.Entry
	for _, p := range protectedList {
		var s sid.SID
		var err error
		switch {
		case p.builtin:
			s, err = sid.Parse(fmt.Sprintf("S-1-5-32-%d", p.rid))
		case p.root:
			s, err = withRID(b.rootSID, p.rid)
		default:
			s, err = withRID(b.domSID, p.rid)
		}
		if err != nil {
			return fmt.Errorf("tier0: protected sid: %w", err)
		}
		e, found, err := b.get(dn.SIDRef(s), idAttrs)
		if err != nil {
			return err
		}
		if !found {
			continue // not every group exists in every forest (Key Admins before 2016, ...)
		}
		if _, err := b.mark(e, C1); err != nil {
			return err
		}
		if err := b.noteAccount(e); err != nil { // Administrator, krbtgt
			return err
		}
		if hasClass(e, "group") {
			groups = append(groups, e)
		}
	}
	return b.membersOf(groups, C2)
}

// membersOf marks the transitive members of the groups, and the users whose primary group is any
// group in the closure, with basis.
func (b *builder) membersOf(groups []*ad.Entry, basis Basis) error {
	closure := map[string]*ad.Entry{}
	for _, g := range groups {
		closure[strings.ToLower(g.DN)] = g
	}
	for _, g := range groups {
		gd, err := entryDN(g)
		if err != nil {
			return err
		}
		err = b.d.TransitiveMembers(b.ctx, gd, idAttrs, func(m *ad.Entry) error {
			if _, err := b.mark(m, basis); err != nil {
				return err
			}
			if basis == C2 {
				if err := b.noteAccount(m); err != nil {
					return err
				}
			}
			if hasClass(m, "group") {
				closure[strings.ToLower(m.DN)] = m
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("tier0: members: %w", err)
		}
	}
	// Primary-group edges: membership by primaryGroupID is not in `member`.
	keys := make([]string, 0, len(closure))
	for k := range closure {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		ss, err := closure[k].SIDs("objectSid")
		if err != nil || len(ss) != 1 {
			continue // a group without a readable SID cannot be anyone's primary group
		}
		dom, ok := ss[0].DomainSID()
		rid, ok2 := ss[0].RID()
		if !ok || !ok2 || dom.String() != b.domSID.String() {
			continue
		}
		q := Query{EqInt: []AttrInt{{Attr: "primaryGroupID", Value: int32(rid)}}}
		err = b.d.Find(b.ctx, b.nm.Domain, ad.ScopeSubtree, q, idAttrs, func(m *ad.Entry) error {
			if _, err := b.mark(m, basis); err != nil {
				return err
			}
			if basis == C2 {
				return b.noteAccount(m)
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("tier0: primary-group members: %w", err)
		}
	}
	return nil
}

// C3: AdminSDHolder.
func (b *builder) c3() error {
	d, err := b.child(b.nm.Domain, "CN=System", "CN=AdminSDHolder")
	if err != nil {
		return err
	}
	e, found, err := b.getDN(d)
	if err != nil {
		return err
	}
	if !found {
		return errors.New("tier0: AdminSDHolder not found")
	}
	_, err = b.mark(e, C3)
	return err
}

// C4: krbtgt (RID 502 is marked in C1) and every RODC krbtgt_NNNNN.
func (b *builder) c4() error {
	kr, err := withRID(b.domSID, 502)
	if err != nil {
		return err
	}
	e, found, err := b.get(dn.SIDRef(kr), idAttrs)
	if err != nil {
		return err
	}
	if !found {
		return errors.New("tier0: krbtgt not found")
	}
	if _, err := b.mark(e, C4); err != nil {
		return err
	}
	q := Query{Classes: []string{"user"}, Has: []string{"msDS-SecondaryKrbTgtNumber"}}
	return b.d.Find(b.ctx, b.nm.Domain, ad.ScopeSubtree, q, idAttrs, func(m *ad.Entry) error {
		if _, err := b.mark(m, C4); err != nil {
			return err
		}
		return b.noteAccount(m)
	})
}

// C5, C6, C15: DC computers (userAccountControl flags, unioned with the nTDSDSA server references),
// the containers above them, and the sites holding them.
func (b *builder) c5c6c15() error {
	seen := map[string]bool{}
	addDC := func(e *ad.Entry) error {
		g, err := b.mark(e, C5)
		if err != nil {
			return err
		}
		if seen[g.String()] {
			return nil
		}
		seen[g.String()] = true
		d, err := entryDN(e)
		if err != nil {
			return err
		}
		b.dcDNs = append(b.dcDNs, d)
		if h := e.Strings("dNSHostName"); len(h) == 1 && h[0] != "" {
			host := strings.ToLower(h[0])
			b.dcHosts[host] = true
			b.dcHosts[strings.SplitN(host, ".", 2)[0]] = true
		}
		if sam := e.Strings("sAMAccountName"); len(sam) == 1 {
			b.dcHosts[strings.ToLower(strings.TrimSuffix(sam[0], "$"))] = true
		}
		if sd := e.Raw("msDS-AllowedToActOnBehalfOfOtherIdentity"); len(sd) == 1 {
			b.dcSD[g.String()] = sd[0]
		}
		return b.noteAccount(e)
	}
	attrs := append([]string{"dNSHostName", "sAMAccountName", "msDS-AllowedToActOnBehalfOfOtherIdentity"}, idAttrs...)
	q := Query{Classes: []string{"computer"}, UACAny: uacServerTrust | uacPartialSecrets}
	if err := b.d.Find(b.ctx, b.nm.Domain, ad.ScopeSubtree, q, attrs, addDC); err != nil {
		return fmt.Errorf("tier0: domain controllers: %w", err)
	}

	// nTDSDSA objects: CN=NTDS Settings,CN=<server>,CN=Servers,CN=<site>,CN=Sites,<config>.
	sites, err := b.child(b.nm.Config, "CN=Sites")
	if err != nil {
		return err
	}
	var settings []dn.DN
	err = b.d.Find(b.ctx, sites, ad.ScopeSubtree, Query{Classes: []string{"nTDSDSA"}}, idAttrs, func(e *ad.Entry) error {
		d, err := entryDN(e)
		if err != nil {
			return err
		}
		settings = append(settings, d)
		return nil
	})
	if err != nil {
		return fmt.Errorf("tier0: NTDS settings: %w", err)
	}
	for _, ntds := range settings {
		server := ntds.Parent()
		if server.Len() < 4 { // server, Servers, site, Sites at least
			return errors.New("tier0: NTDS settings object in an unexpected place")
		}
		site := server.Parent().Parent()
		se, found, err := b.getDN(site)
		if err != nil {
			return err
		}
		if !found {
			return errors.New("tier0: site of a domain controller not found")
		}
		if _, err := b.mark(se, C15); err != nil {
			return err
		}
		srv, found, err := b.get(dn.DNRef(server), []string{"serverReference", "objectGUID"})
		if err != nil {
			return err
		}
		if !found {
			continue
		}
		for _, ref := range srv.Strings("serverReference") {
			r, err := dn.Parse(ref, dn.Strict)
			if err != nil {
				return errors.New("tier0: unparsable serverReference")
			}
			ce, found, err := b.get(dn.DNRef(r), attrs)
			if err != nil {
				return err
			}
			if found {
				if err := addDC(ce); err != nil {
					return err
				}
			}
		}
	}

	// C6: the Domain Controllers OU (live, by well-known GUID) and every container above a DC.
	wk, ok := wellKnownDN(b.domHead.Strings("wellKnownObjects"), wkDomainControllers)
	if !ok {
		return errors.New("tier0: Domain Controllers container not found in wellKnownObjects")
	}
	wd, err := dn.Parse(wk, dn.Strict)
	if err != nil {
		return errors.New("tier0: unparsable Domain Controllers container DN")
	}
	conts := map[string]dn.DN{strings.ToLower(wd.String()): wd}
	for _, dc := range b.dcDNs {
		for p := dc.Parent(); p.Len() > 0 && !p.Equal(b.nm.Domain); p = p.Parent() {
			conts[strings.ToLower(p.String())] = p
		}
	}
	keys := make([]string, 0, len(conts))
	for k := range conts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		e, found, err := b.getDN(conts[k])
		if err != nil {
			return err
		}
		if !found {
			return errors.New("tier0: a container of a domain controller disappeared")
		}
		if _, err := b.mark(e, C6); err != nil {
			return err
		}
	}
	return nil
}

// C8: sensitive CN=System objects and the KDS root keys.
func (b *builder) c8() error {
	sys, err := b.child(b.nm.Domain, "CN=System")
	if err != nil {
		return err
	}
	for _, rel := range c8Domain {
		d := sys
		if rel != "" {
			if d, err = b.child(sys, rel); err != nil {
				return err
			}
		}
		if err := b.markDN(d, C8, false); err != nil {
			return err
		}
	}
	err = b.d.Find(b.ctx, sys, ad.ScopeSubtree, Query{Classes: c8SystemClasses}, idAttrs, func(e *ad.Entry) error {
		_, err := b.mark(e, C8)
		return err
	})
	if err != nil {
		return fmt.Errorf("tier0: system objects: %w", err)
	}
	// KDS root keys live in CN=Group Key Distribution Service under Services in the Configuration NC.
	kds, err := b.child(b.nm.Config, "CN=Services", "CN=Group Key Distribution Service")
	if err != nil {
		return err
	}
	if err := b.markDN(kds, C8, false); err != nil {
		return err
	}
	return b.markTree(kds, Query{}, C8)
}

func (b *builder) markDN(d dn.DN, basis Basis, required bool) error {
	e, found, err := b.getDN(d)
	if err != nil {
		return err
	}
	if !found {
		if required {
			return errors.New("tier0: expected object not found")
		}
		return nil
	}
	_, err = b.mark(e, basis)
	return err
}

func (b *builder) markTree(base dn.DN, q Query, basis Basis) error {
	// A subtree search of a missing base fails with no-such-object, which is the empty case here.
	err := b.d.Find(b.ctx, base, ad.ScopeSubtree, q, idAttrs, func(e *ad.Entry) error {
		_, err := b.mark(e, basis)
		return err
	})
	if err != nil && ad.CodeOf(err) != ad.CodeObjectNotFound {
		return fmt.Errorf("tier0: subtree: %w", err)
	}
	return nil
}

// C10: all of Public Key Services in the Configuration NC (enrollment services, CA objects,
// NTAuthCertificates, templates, and their containers). Over-inclusive on purpose: a write anywhere
// under it can add a CA or template.
func (b *builder) c10() error {
	pks, err := b.child(b.nm.Config, "CN=Services", "CN=Public Key Services")
	if err != nil {
		return err
	}
	return b.markTree(pks, Query{}, C10)
}

// C11: principals holding Get-Changes and Get-Changes-All on the domain root, from its DACL.
func (b *builder) c11() error {
	e, found, err := b.get(dn.DNRef(b.nm.Domain), []string{"objectGUID", "nTSecurityDescriptor"})
	if err != nil {
		return err
	}
	if !found || len(e.Raw("nTSecurityDescriptor")) != 1 {
		return errors.New("tier0: domain root DACL unreadable")
	}
	aces, err := allowACEs(e.Raw("nTSecurityDescriptor")[0])
	if err != nil {
		return err
	}
	return b.markPrincipals(holders(aces, getChanges, getChangesAll), C11)
}

// holders returns the SIDs that are granted every right in rights across the ACEs.
func holders(aces []allowACE, rights ...guid.GUID) []sid.SID {
	have := map[string]map[guid.GUID]bool{}
	sids := map[string]sid.SID{}
	for _, a := range aces {
		k := a.sid.String()
		for _, r := range rights {
			if a.grants(r) {
				if have[k] == nil {
					have[k] = map[guid.GUID]bool{}
				}
				have[k][r] = true
				sids[k] = a.sid
			}
		}
	}
	var out []sid.SID
	for k, h := range have {
		if len(h) == len(rights) {
			out = append(out, sids[k])
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// markPrincipals marks the objects with these SIDs, and the transitive members of those that are
// groups. A SID with no object (orphaned ACE, well-known SID such as SYSTEM) is skipped.
func (b *builder) markPrincipals(sids []sid.SID, basis Basis) error {
	for _, s := range sids {
		e, found, err := b.get(dn.SIDRef(s), idAttrs)
		if err != nil {
			return err
		}
		if !found {
			continue
		}
		if _, err := b.mark(e, basis); err != nil {
			return err
		}
		if hasClass(e, "group") {
			gd, err := entryDN(e)
			if err != nil {
				return err
			}
			err = b.d.TransitiveMembers(b.ctx, gd, idAttrs, func(m *ad.Entry) error {
				_, err := b.mark(m, basis)
				return err
			})
			if err != nil {
				return fmt.Errorf("tier0: members: %w", err)
			}
		}
	}
	return nil
}

// C12: unconstrained delegation, constrained delegation to a DC service, and RBCD on a DC.
func (b *builder) c12() error {
	mark := func(e *ad.Entry) error { _, err := b.mark(e, C12); return err }
	q := Query{Classes: []string{"user"}, UACAny: uacTrustedForDeleg} // "user" covers computers
	if err := b.d.Find(b.ctx, b.nm.Domain, ad.ScopeSubtree, q, idAttrs, mark); err != nil {
		return fmt.Errorf("tier0: unconstrained delegation: %w", err)
	}
	attrs := append([]string{"msDS-AllowedToDelegateTo"}, idAttrs...)
	q = Query{Has: []string{"msDS-AllowedToDelegateTo"}}
	err := b.d.Find(b.ctx, b.nm.Domain, ad.ScopeSubtree, q, attrs, func(e *ad.Entry) error {
		for _, spn := range e.Strings("msDS-AllowedToDelegateTo") {
			if b.spnReachesDC(spn) {
				return mark(e)
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("tier0: constrained delegation: %w", err)
	}
	var all []sid.SID
	keys := make([]string, 0, len(b.dcSD))
	for k := range b.dcSD {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		aces, err := allowACEs(b.dcSD[k])
		if err != nil {
			return err
		}
		for _, a := range aces {
			all = append(all, a.sid)
		}
	}
	return b.markPrincipals(all, C12)
}

// spnReachesDC reports whether a service name "class/host[:port][/name]" names a DC. A value with no
// host part cannot be shown harmless and counts as reaching one.
func (b *builder) spnReachesDC(spn string) bool {
	_, rest, ok := strings.Cut(spn, "/")
	if !ok || rest == "" {
		return true
	}
	host := rest
	if i := strings.IndexAny(host, ":/"); i >= 0 {
		host = host[:i]
	}
	host = strings.ToLower(host)
	return b.dcHosts[host] || b.dcHosts[strings.SplitN(host, ".", 2)[0]]
}

// C13: default-privileged groups, and (as equivalent control) their transitive members.
func (b *builder) c13() error {
	var groups []*ad.Entry
	for _, name := range c13Groups {
		q := Query{Classes: []string{"group"}, Eq: []AttrEq{{Attr: "sAMAccountName", Value: name}}}
		err := b.d.Find(b.ctx, b.nm.Domain, ad.ScopeSubtree, q, idAttrs, func(e *ad.Entry) error {
			if _, err := b.mark(e, C13); err != nil {
				return err
			}
			groups = append(groups, e)
			return nil
		})
		if err != nil {
			return fmt.Errorf("tier0: default-privileged groups: %w", err)
		}
	}
	return b.membersOf(groups, C13)
}

// C14: the Seamless SSO computer account.
func (b *builder) c14() error {
	q := Query{Classes: []string{"computer"}, Eq: []AttrEq{{Attr: "sAMAccountName", Value: "AZUREADSSOACC$"}}}
	return b.d.Find(b.ctx, b.nm.Domain, ad.ScopeSubtree, q, idAttrs, func(e *ad.Entry) error {
		_, err := b.mark(e, C14)
		return err
	})
}

// C9: GPOs linked to a start of authority that reaches tier0. A SOM reaches tier0 when it is the
// domain head, a C6 container or a C15 site, or sits above a tier0 account (C2/C4/C5). Disabled
// links count. Block inheritance and loopback are ignored (they only narrow reach).
func (b *builder) c9() error {
	sites, err := b.child(b.nm.Config, "CN=Sites")
	if err != nil {
		return err
	}
	attrs := []string{"objectGUID", "gPLink"}
	// The Session is serialised and a Search callback must not call back into it: collect the GPO
	// DNs here and resolve them after the searches.
	var reached []dn.DN
	visit := func(e *ad.Entry) error {
		vals := e.Strings("gPLink")
		if len(vals) == 0 {
			return nil
		}
		som, err := entryDN(e)
		if err != nil {
			return err
		}
		g, err := e.GUID()
		if err != nil {
			return fmt.Errorf("tier0: SOM: %w", err)
		}
		reach := som.Equal(b.nm.Domain) || b.s.bases[g.String()][C6] || b.s.bases[g.String()][C15] ||
			b.accountAnc[strings.ToLower(som.String())]
		var links []gplink.Link
		for _, v := range vals {
			ls, err := gplink.Parse(v)
			if err != nil {
				return fmt.Errorf("tier0: gPLink: %w", err)
			}
			links = append(links, ls...)
		}
		if !reach {
			return nil
		}
		for _, l := range links {
			reached = append(reached, l.GPO)
		}
		return nil
	}
	if err := b.d.Find(b.ctx, b.nm.Domain, ad.ScopeSubtree, Query{Has: []string{"gPLink"}}, attrs, visit); err != nil {
		return fmt.Errorf("tier0: gPLink: %w", err)
	}
	if err := b.d.Find(b.ctx, sites, ad.ScopeSubtree, Query{Classes: []string{"site"}, Has: []string{"gPLink"}}, attrs, visit); err != nil {
		return fmt.Errorf("tier0: site gPLink: %w", err)
	}
	for _, g := range reached {
		ge, found, err := b.getDN(g)
		if err != nil {
			return err
		}
		if !found {
			continue // dangling link: no GPO object to protect
		}
		if _, err := b.mark(ge, C9); err != nil {
			return err
		}
	}
	return nil
}
