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
	"slices"
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
	C17 = connectorv1.Tier0Basis_TIER0_BASIS_C17_ROOT_OF_TRUST_CONTROL
	C18 = connectorv1.Tier0Basis_TIER0_BASIS_C18_PRIVILEGED_SID_HISTORY
	C19 = connectorv1.Tier0Basis_TIER0_BASIS_C19_CONTROL_OF_TIER0_OBJECT
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

// c13Groups are looked up by sAMAccountName in the domain, so an object that later takes one of these
// names is tier0 too (TM-D26 rule 10). Group Policy Creator Owners is deliberately absent (§6.4 C13).
var c13Groups = []string{"DnsAdmins", "Cert Publishers", "Exchange Trusted Subsystem", "Exchange Windows Permissions"}

// c13CertPublishersRID is the one C13 group with a well-known RID (TM-D26 rule 10). The others
// (DnsAdmins, the Exchange groups) have none and are kept by objectGUID, pinned at first discovery.
const c13CertPublishersRID = 517

// privilegedDomainRIDs are the C1 and C13 accounts and groups that make a sIDHistory value privileged
// by RID alone, whatever the domain prefix (TM-D26 rule 6a). 520 (Group Policy Creator Owners) is
// absent on purpose: sensitive, not Tier 0.
var privilegedDomainRIDs = map[uint32]bool{500: true, 502: true, 512: true, 516: true, 517: true, 518: true,
	519: true, 521: true, 525: true, 526: true, 527: true}

// privilegedBuiltinRIDs are the C1 built-in S-1-5-32 groups (Appendix C).
var privilegedBuiltinRIDs = map[uint32]bool{544: true, 548: true, 549: true, 550: true, 551: true, 552: true}

// rootOfTrustRIDMin is the first RID of an ordinary account: an unresolvable sIDHistory value at or
// above it is not tier0 (migrated users carry such SIDs by the thousand).
const rootOfTrustRIDMin = 1000

// dsHeuristicsChars are the dSHeuristics characters (1-based) TM-D26 rule 9 reports when non-default.
var dsHeuristicsChars = []struct {
	Pos  int
	Name string
}{{7, "fLDAPBlockAnonOps"}, {8, "fAllowAnonNSPI"}, {12, "fDontStandardizeSDs"}, {16, "dwAdminSDExMask"}, {29, "BlockOwnerImplicitRights"}}

// DSHeuristic is one non-default dSHeuristics character, for the health page (TM-D26 rule 9).
type DSHeuristic struct {
	Pos   int
	Name  string
	Value byte
}

// UnresolvedSIDHistory is a sIDHistory value that is not privileged and resolves to no object
// (SIDHISTORY_UNRESOLVED on the health page).
type UnresolvedSIDHistory struct {
	Object guid.GUID
	SID    sid.SID
}

// Finding codes reported by a snapshot. A finding never changes the set.
const FindingDnsAdminsMissing = "DNSADMINS_MISSING"

// Finding is an onboarding or health observation of a snapshot.
type Finding struct {
	Code   string
	Detail string
}

// c8Domain are the sensitive CN=System objects, relative to CN=System,<domain>. AdminSDHolder is C3.
var c8Domain = []string{"", "CN=RID Manager$", "CN=Password Settings Container"}

// c8SystemClasses are sensitive by class anywhere under CN=System: DPAPI backup keys (secret) and
// trust objects (trustedDomain).
var c8SystemClasses = []string{"secret", "trustedDomain"}

// ADSet is one computed snapshot of the connector's AD tier0 computed set (C1-C15), by objectGUID.
type ADSet struct {
	bases map[string]map[Basis]bool

	unresolved []UnresolvedSIDHistory
	dsh        []DSHeuristic
	c13        []guid.GUID
	findings   []Finding
}

// Findings are the onboarding observations of the snapshot (TM-D26 rule 10: no DnsAdmins in a domain
// that hosts AD-integrated DNS).
func (s *ADSet) Findings() []Finding { return s.findings }

// Unresolved lists the sIDHistory values that matched no privileged RID and no object.
func (s *ADSet) Unresolved() []UnresolvedSIDHistory { return s.unresolved }

// DSHeuristics lists the non-default dSHeuristics characters of rule 9. It never changes the set.
func (s *ADSet) DSHeuristics() []DSHeuristic { return s.dsh }

// C13Groups are the objectGUIDs of every C13 group this snapshot found; the caller pins them so a
// later rename cannot remove them (rule 10) and passes them back as ADInput.PinnedC13.
func (s *ADSet) C13Groups() []guid.GUID { return s.c13 }

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
	// PinnedC13 are the C13 group GUIDs pinned at first discovery (ADSet.C13Groups). They stay C13
	// whatever their name; a GUID that no longer exists marks nothing and is not an error.
	PinnedC13 []guid.GUID
}

// ADResult is the classification of one target.
type ADResult struct {
	Tier0 bool
	// Unknown: the answer could not be computed, so Tier0 is true by the fail-closed rule.
	Unknown bool
	Bases   []Basis
	GUID    guid.GUID // the target's objectGUID when it could be resolved
	// C13Groups are the C13 groups this snapshot found (ADSet.C13Groups); the caller pins them.
	C13Groups []guid.GUID
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
	// Designations are resolved before the snapshot: C18 applies their closure (a sIDHistory value
	// naming a designated object makes its holder tier0).
	desig := map[string]guid.GUID{}
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
		desig[g.String()] = g
	}
	var designated []guid.GUID
	for _, g := range desig {
		designated = append(designated, g)
	}
	set, err := c.snapshot(ctx, in.PinnedC13, designated)
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
	if _, ok := desig[tg.String()]; ok {
		b[Designated] = true
	}
	return ADResult{Tier0: len(b) > 0, Bases: sortedBases(b), GUID: tg, C13Groups: set.C13Groups()}, nil
}

// builder carries one snapshot's working state.
type builder struct {
	ctx context.Context
	d   ADDirectory
	nm  Naming
	s   *ADSet

	domSID, rootSID sid.SID
	domHead         *ad.Entry
	pinnedC13       []guid.GUID
	desig           map[string]bool // customer-designated objects, by GUID (closure applied in C18)
	gpLink          *guid.GUID      // schemaIDGUID of gPLink, read from the schema (C17)
	hist            []histEntry     // objects with a sIDHistory, read once per snapshot
	histRead        bool
	forest          map[sid.SID]bool // domain SIDs of the forest, read once from the GC when first needed

	accountAnc map[string]bool      // lower-case DN of every strict ancestor of a tier0 account (C2/C4/C5)
	dcDNs      []dn.DN              // DC computer objects (C5)
	dcHosts    map[string]bool      // lower-case DC host names (FQDN and short) for C12
	dcSD       map[string][]byte    // RBCD descriptors by computer GUID
	cache      map[string]*ad.Entry // Get results by lower-case DN

	c19o c19Objects // the objects whose control makes a trustee tier0 (C19), gathered by the earlier steps
}

var idAttrs = []string{"objectGUID", "objectSid", "objectClass"}

// Snapshot reads the forest and computes C1-C15 and C17-C19. pinnedC13 are the C13 groups pinned at
// first discovery. Any error fails the whole snapshot: a caller that ignored the error must not be
// left holding a partial, under-protective set.
func (c *ADClassifier) Snapshot(ctx context.Context, pinnedC13 ...guid.GUID) (*ADSet, error) {
	return c.snapshot(ctx, pinnedC13, nil)
}

// SnapshotWith is Snapshot with the customer designations, whose closure C18 applies.
func (c *ADClassifier) SnapshotWith(ctx context.Context, pinnedC13, designated []guid.GUID) (*ADSet, error) {
	return c.snapshot(ctx, pinnedC13, designated)
}

// snapshot is Snapshot with the customer designations, whose closure C18 applies.
func (c *ADClassifier) snapshot(ctx context.Context, pinnedC13, designated []guid.GUID) (*ADSet, error) {
	b := &builder{ctx: ctx, d: c.d, pinnedC13: pinnedC13, desig: map[string]bool{}, s: &ADSet{bases: map[string]map[Basis]bool{}},
		accountAnc: map[string]bool{}, dcHosts: map[string]bool{}, dcSD: map[string][]byte{}, cache: map[string]*ad.Entry{}}
	for _, g := range designated {
		b.desig[g.String()] = true
	}
	nm, err := c.d.Naming(ctx)
	if err != nil {
		return nil, fmt.Errorf("tier0: naming contexts: %w", err)
	}
	b.nm = nm
	steps := []func() error{b.c7, b.c1c2, b.c3, b.c4, b.c5c6c15, b.c8, b.c10, b.c11, b.c12, b.c13, b.c14, b.c17, b.c18, b.c9, b.c19}
	for _, step := range steps { // c18 needs every principal basis; c9 needs C2/C4/C5/C6/C15; c19 last: it needs C1/C4/C5/C9 objects
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

// dnKey is the case-folded map key for a DN. It goes through ObjectRef.ForRequest so the only DN
// text the connector ever renders is one the tier-0 guard vetted (NotRequestable, MaxDNLen).
func dnKey(d dn.DN) (string, error) {
	t, err := dn.DNRef(d).ForRequest()
	if err != nil {
		return "", fmt.Errorf("tier0: DN key: %w", err)
	}
	return strings.ToLower(t), nil
}

// getDN is get by DN with a per-snapshot cache of id-only reads.
func (b *builder) getDN(d dn.DN) (*ad.Entry, bool, error) {
	k, err := dnKey(d)
	if err != nil {
		return nil, false, err
	}
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
		k, err := dnKey(p)
		if err != nil {
			return err
		}
		b.accountAnc[k] = true
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
			b.c19o.c1Groups = append(b.c19o.c1Groups, e)
		} else {
			b.c19o.accounts = append(b.c19o.accounts, e)
		}
	}
	return b.membersOf(groups, C2)
}

// walkAttrs are read for every node of a membership walk. `member` is ranged by Read to the
// terminal range, so groups past the server's value limit are followed to the end.
var walkAttrs = []string{"objectGUID", "objectSid", "objectClass", "member"}

// membersOf marks the transitive members of the groups (roots, already marked by the caller), and
// the accounts whose primary group is any group reached, with basis. The walk reads each group
// object (ranged) and each member once, so its cost follows the size of the tier0 groups, never the
// size of the domain; the visited set ends circular nesting.
func (b *builder) membersOf(roots []*ad.Entry, basis Basis) error {
	if len(roots) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var groups []*ad.Entry
	var queue []dn.DN
	for _, r := range roots {
		d, err := entryDN(r)
		if err != nil {
			return err
		}
		k, err := dnKey(d)
		if err != nil {
			return err
		}
		seen[k] = true
		queue = append(queue, d)
	}
	isRoot := map[string]bool{}
	for k := range seen {
		isRoot[k] = true
	}
	for len(queue) > 0 {
		d := queue[0]
		queue = queue[1:]
		e, found, err := b.get(dn.DNRef(d), walkAttrs)
		if err != nil {
			return err
		}
		if !found {
			continue // a member link to an object that no longer exists
		}
		k, err := dnKey(d)
		if err != nil {
			return err
		}
		if !isRoot[k] {
			if _, err := b.mark(e, basis); err != nil {
				return err
			}
			if basis == C2 {
				if err := b.noteAccount(e); err != nil {
					return err
				}
			}
		}
		if !hasClass(e, "group") {
			continue
		}
		groups = append(groups, e)
		for _, m := range e.Strings("member") {
			md, err := dn.Parse(m, dn.Strict)
			if err != nil {
				return errors.New("tier0: DC returned an unparsable member DN")
			}
			mk, err := dnKey(md)
			if err != nil {
				return err
			}
			if !seen[mk] {
				seen[mk] = true
				queue = append(queue, md)
			}
		}
	}
	// Primary-group edges: membership by primaryGroupID is not in `member`. One scan covers every
	// group of the walk that lives in this domain.
	var rids []AttrInt
	for _, g := range groups {
		ss, err := g.SIDs("objectSid")
		if err != nil || len(ss) != 1 {
			// Its primaryGroupID members cannot be looked for: fail closed.
			return errors.New("tier0: a group in the membership walk has no readable objectSid")
		}
		dom, ok := ss[0].DomainSID()
		rid, ok2 := ss[0].RID()
		if ok && ok2 && dom.String() == b.domSID.String() {
			rids = append(rids, AttrInt{Attr: "primaryGroupID", Value: int32(rid)})
		}
	}
	if len(rids) == 0 {
		return nil
	}
	err := b.d.Find(b.ctx, b.nm.Domain, ad.ScopeSubtree, Query{AnyInt: rids}, idAttrs, func(m *ad.Entry) error {
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
	b.c19o.accounts = append(b.c19o.accounts, e)
	q := Query{Classes: []string{"user"}, Has: []string{"msDS-SecondaryKrbTgtNumber"}}
	return b.d.Find(b.ctx, b.nm.Domain, ad.ScopeSubtree, q, idAttrs, func(m *ad.Entry) error {
		if _, err := b.mark(m, C4); err != nil {
			return err
		}
		b.c19o.accounts = append(b.c19o.accounts, m)
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
		for _, h := range e.Strings("msDS-AdditionalDnsHostName") {
			b.addHost(h)
		}
		for _, spn := range e.Strings("servicePrincipalName") {
			if _, rest, ok := strings.Cut(spn, "/"); ok {
				b.addHost(spnHost(rest))
			}
		}
		if sam := e.Strings("sAMAccountName"); len(sam) == 1 {
			b.dcHosts[strings.ToLower(strings.TrimSuffix(sam[0], "$"))] = true
		}
		if sd := e.Raw("msDS-AllowedToActOnBehalfOfOtherIdentity"); len(sd) == 1 {
			b.dcSD[g.String()] = sd[0]
		}
		return b.noteAccount(e)
	}
	attrs := append([]string{"dNSHostName", "sAMAccountName", "servicePrincipalName", "msDS-AdditionalDnsHostName", "msDS-AllowedToActOnBehalfOfOtherIdentity"}, idAttrs...)
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
	wk0, err := dnKey(wd)
	if err != nil {
		return err
	}
	b.c19o.dcOU = wd
	conts := map[string]dn.DN{wk0: wd}
	for _, dc := range b.dcDNs {
		for p := dc.Parent(); p.Len() > 0 && !p.Equal(b.nm.Domain); p = p.Parent() {
			pk, err := dnKey(p)
			if err != nil {
				return err
			}
			conts[pk] = p
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
		return b.markSoft(e, C8)
	})
	if err != nil {
		return fmt.Errorf("tier0: system objects: %w", err)
	}
	// dSHeuristics (rule 9): the Directory Service object is C8, and its five security characters are
	// reported when non-default.
	if err := b.directoryService(); err != nil {
		return err
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

func (b *builder) directoryService() error {
	d, err := b.child(b.nm.Config, "CN=Services", "CN=Windows NT", "CN=Directory Service")
	if err != nil {
		return err
	}
	e, found, err := b.get(dn.DNRef(d), []string{"objectGUID", "dSHeuristics"})
	if err != nil {
		return err
	}
	if !found {
		return errors.New("tier0: Directory Service object not found")
	}
	if _, err := b.mark(e, C8); err != nil {
		return err
	}
	if v := e.Strings("dSHeuristics"); len(v) == 1 {
		for _, c := range dsHeuristicsChars {
			if c.Pos <= len(v[0]) && v[0][c.Pos-1] != '0' {
				b.s.dsh = append(b.s.dsh, DSHeuristic{Pos: c.Pos, Name: c.Name, Value: v[0][c.Pos-1]})
			}
		}
	}
	return nil
}

// markSoft marks an entry in a sensitive subtree. An entry the connector identity cannot identify
// (no readable objectGUID) is skipped: it cannot act on it, and classifying it as a target fails
// closed (Unknown) because its identity cannot be read.
func (b *builder) markSoft(e *ad.Entry, basis Basis) error {
	if _, err := e.GUID(); err != nil {
		return nil
	}
	_, err := b.mark(e, basis)
	return err
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
	if _, gerr := e.GUID(); gerr != nil && !required {
		// The connector identity cannot read this object's identity (the DC returns the entry
		// without objectGUID, as it does for CN=Password Settings Container). It cannot act on what
		// it cannot read, and classifying such an object as a target fails closed (Unknown).
		return nil
	}
	_, err = b.mark(e, basis)
	return err
}

func (b *builder) markTree(base dn.DN, q Query, basis Basis) error {
	// A subtree search of a missing base fails with no-such-object, which is the empty case here.
	err := b.d.Find(b.ctx, base, ad.ScopeSubtree, q, idAttrs, func(e *ad.Entry) error {
		return b.markSoft(e, basis)
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
	_, aces, err := grantsOf(e.Raw("nTSecurityDescriptor")[0])
	if err != nil {
		return err
	}
	// Effective rights over the token: a principal can replicate when it holds each right directly
	// or through any group, so the holders of each right are expanded to their transitive members
	// and the two sets intersected (a split grant across two groups still makes the common member
	// a DCSync principal).
	var eff []map[string]guid.GUID
	for _, r := range []guid.GUID{getChanges, getChangesAll} {
		m, err := b.expand(holders(aces, r))
		if err != nil {
			return err
		}
		eff = append(eff, m)
	}
	for k, g := range eff[0] {
		if _, ok := eff[1][k]; ok {
			b.s.add(g, C11)
		}
	}
	return nil
}

// holders returns the SIDs that are granted every right in rights across the ACEs.
func holders(aces []aceGrant, rights ...guid.GUID) []sid.SID {
	have := map[string]map[guid.GUID]bool{}
	sids := map[string]sid.SID{}
	for _, a := range aces {
		k := a.trustee.String()
		for _, r := range rights {
			if a.grants(r) {
				if have[k] == nil {
					have[k] = map[guid.GUID]bool{}
				}
				have[k][r] = true
				sids[k] = a.trustee
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

// expand resolves the SIDs and returns them plus the transitive members of those that are groups,
// by objectGUID, without marking anything.
func (b *builder) expand(sids []sid.SID) (map[string]guid.GUID, error) {
	saved := b.s
	tmp := &ADSet{bases: map[string]map[Basis]bool{}}
	b.s = tmp
	defer func() { b.s = saved }()
	if err := b.markPrincipals(sids, C11); err != nil {
		return nil, err
	}
	out := map[string]guid.GUID{}
	for k := range tmp.bases {
		g, err := guid.Parse(k)
		if err != nil {
			return nil, err
		}
		out[k] = g
	}
	return out, nil
}

// ignorableSID reports SIDs that name no directory principal and cannot carry a security principal
// into the token: SYSTEM, Enterprise Domain Controllers, SELF, Creator Owner, and orphans under
// this forest's own domain prefixes.
func (b *builder) ignorableSID(s sid.SID) bool {
	switch s.String() {
	case "S-1-5-18", "S-1-5-9", "S-1-5-10", "S-1-3-0":
		return true
	}
	if dom, ok := s.DomainSID(); ok {
		return dom.String() == b.domSID.String() || dom.String() == b.rootSID.String()
	}
	return false
}

// histEntry is an object that carries a sIDHistory, with the values decoded.
type histEntry struct {
	e    *ad.Entry
	sids []sid.SID
}

// history reads, once per snapshot, every object of the domain with a sIDHistory (one paged presence
// search through the filter builder; the attribute is indexed). An unreadable sIDHistory fails the
// snapshot (rule 8).
func (b *builder) history() ([]histEntry, error) {
	if b.histRead {
		return b.hist, nil
	}
	attrs := append([]string{"sIDHistory"}, idAttrs...)
	err := b.d.Find(b.ctx, b.nm.Domain, ad.ScopeSubtree, Query{Has: []string{"sIDHistory"}}, attrs, func(e *ad.Entry) error {
		ss, err := e.SIDs("sIDHistory")
		if err != nil {
			return fmt.Errorf("tier0: sIDHistory: %w", err)
		}
		b.hist = append(b.hist, histEntry{e: e, sids: ss})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("tier0: sIDHistory: %w", err)
	}
	b.histRead = true
	return b.hist, nil
}

// historyHolders returns the objects whose sIDHistory holds s: their token carries s, so an ACE that
// names s applies to them (TM-D26 rule 5).
func (b *builder) historyHolders(s sid.SID) ([]*ad.Entry, error) {
	h, err := b.history()
	if err != nil {
		return nil, err
	}
	var out []*ad.Entry
	for _, x := range h {
		if slices.Contains(x.sids, s) {
			out = append(out, x.e)
		}
	}
	return out, nil
}

// markPrincipals marks the objects with these SIDs, the objects whose sIDHistory holds one of them,
// and the transitive members of those that are groups. A SID with no object is skipped only when it
// is ignorable (see ignorableSID); any other (Everyone, Authenticated Users, a foreign SID) may stand
// for every principal, so the snapshot fails closed naming it.
func (b *builder) markPrincipals(sids []sid.SID, basis Basis) error {
	return b.markPrincipalsSkip(sids, basis, nil)
}

// markPrincipalsSkip is markPrincipals except that an object for which skip is true is not marked and
// its members are not walked.
func (b *builder) markPrincipalsSkip(sids []sid.SID, basis Basis, skip func(*ad.Entry) bool) error {
	var groups []*ad.Entry
	take := func(e *ad.Entry) error {
		if skip != nil && skip(e) {
			return nil
		}
		if _, err := b.mark(e, basis); err != nil {
			return err
		}
		if hasClass(e, "group") {
			groups = append(groups, e)
		}
		return nil
	}
	for _, s := range sids {
		e, found, err := b.get(dn.SIDRef(s), idAttrs)
		if err != nil {
			return err
		}
		holders, err := b.historyHolders(s)
		if err != nil {
			return err
		}
		if !found && len(holders) == 0 {
			if b.ignorableSID(s) {
				continue
			}
			return fmt.Errorf("tier0: grant to unresolvable SID %s may cover every principal", s)
		}
		if found {
			if err := take(e); err != nil {
				return err
			}
		}
		for _, h := range holders {
			if err := take(h); err != nil {
				return err
			}
		}
	}
	return b.membersOf(groups, basis)
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
		_, aces, err := grantsOf(b.dcSD[k])
		if err != nil {
			return err
		}
		for _, a := range aces {
			all = append(all, a.trustee)
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
	host := strings.ToLower(spnHost(rest))
	return b.dcHosts[host] || b.dcHosts[strings.SplitN(host, ".", 2)[0]]
}

// C13: default-privileged groups, and (as equivalent control) their transitive members. A group is
// found by well-known RID (Cert Publishers), by the GUID pinned at first discovery, and by name; the
// name lookup also catches an object that later takes a C13 name (TM-D26 rule 10).
func (b *builder) c13() error {
	var groups []*ad.Entry
	seen := map[string]bool{}
	add := func(e *ad.Entry) error {
		g, err := b.mark(e, C13)
		if err != nil {
			return err
		}
		if !seen[g.String()] {
			seen[g.String()] = true
			groups = append(groups, e)
			b.s.c13 = append(b.s.c13, g)
		}
		return nil
	}
	cp, err := withRID(b.domSID, c13CertPublishersRID)
	if err != nil {
		return err
	}
	if e, found, err := b.get(dn.SIDRef(cp), idAttrs); err != nil {
		return err
	} else if found {
		if err := add(e); err != nil {
			return err
		}
	}
	// dnsAdmins: a DnsAdmins can be found by its name, or as a pinned group that has since been
	// renamed to something that is not a C13 name. A pin carries no role, so a renamed Exchange group
	// also counts (the finding errs towards silence there).
	dnsAdmins := false
	for _, g := range b.pinnedC13 {
		e, found, err := b.get(dn.GUIDRef(g), append([]string{"sAMAccountName"}, idAttrs...))
		if err != nil {
			return err
		}
		if found {
			if err := add(e); err != nil {
				return err
			}
			if !isC13Name(e.Strings("sAMAccountName")) {
				dnsAdmins = true
			}
		}
	}
	for _, name := range c13Groups {
		q := Query{Classes: []string{"group"}, Eq: []AttrEq{{Attr: "sAMAccountName", Value: name}}}
		if err := b.d.Find(b.ctx, b.nm.Domain, ad.ScopeSubtree, q, idAttrs, func(e *ad.Entry) error {
			if strings.EqualFold(name, "DnsAdmins") {
				dnsAdmins = true
			}
			return add(e)
		}); err != nil {
			return fmt.Errorf("tier0: default-privileged groups: %w", err)
		}
	}
	if !dnsAdmins {
		hosts, err := b.hostsDNS()
		if err != nil {
			return err
		}
		if hosts {
			b.s.findings = append(b.s.findings, Finding{Code: FindingDnsAdminsMissing,
				Detail: "the domain hosts AD-integrated DNS zones and no DnsAdmins group can be found"})
		}
	}
	sort.Slice(b.s.c13, func(i, j int) bool { return b.s.c13[i].String() < b.s.c13[j].String() })
	return b.membersOf(groups, C13)
}

func isC13Name(names []string) bool {
	for _, n := range names {
		for _, c := range c13Groups {
			if strings.EqualFold(n, c) {
				return true
			}
		}
	}
	return false
}

// hostsDNS reports whether the domain holds an AD-integrated DNS zone (application partition
// DomainDnsZones, or the legacy CN=System location). A partition that does not exist or that the
// connector cannot read counts as no zones: the finding is advice, it never gates classification.
func (b *builder) hostsDNS() (bool, error) {
	// parent first: child() appends one RDN below the previous
	bases := [][]string{{"DC=DomainDnsZones", "CN=MicrosoftDNS"}, {"CN=System", "CN=MicrosoftDNS"}}
	for _, rd := range bases {
		base := b.nm.Domain
		for i := 0; i < len(rd); i++ {
			var err error
			if base, err = b.child(base, rd[i]); err != nil {
				return false, err
			}
		}
		hit := false
		err := b.d.Find(b.ctx, base, ad.ScopeOneLevel, Query{Classes: []string{"dnsZone"}}, idAttrs, func(*ad.Entry) error {
			hit = true
			return errStopFind
		})
		if err != nil && !errors.Is(err, errStopFind) {
			switch ad.CodeOf(err) {
			case ad.CodeObjectNotFound, ad.CodeInsufficientRights:
				continue
			}
			return false, fmt.Errorf("tier0: DNS zones: %w", err)
		}
		if hit {
			return true, nil
		}
	}
	return false, nil
}

var errStopFind = errors.New("stop")

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
		somKey, err := dnKey(som)
		if err != nil {
			return err
		}
		reach := som.Equal(b.nm.Domain) || b.s.bases[g.String()][C6] || b.s.bases[g.String()][C15] ||
			b.accountAnc[somKey]
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
		b.c19o.gpos = append(b.c19o.gpos, g)
	}
	return nil
}

// c17Objects are the roots of trust (TM-D26 rule 1): the domain head, the root-domain head, the
// Configuration head, the Schema head and AdminSDHolder. Scope limit as for the rest of the file: the
// domains of the forest the bound DC does not hold are not read.
func (b *builder) c17Objects() ([]dn.DN, error) {
	adh, err := b.child(b.nm.Domain, "CN=System", "CN=AdminSDHolder")
	if err != nil {
		return nil, err
	}
	out := []dn.DN{b.nm.Domain}
	if !b.nm.RootDomain.Equal(b.nm.Domain) {
		out = append(out, b.nm.RootDomain)
	}
	return append(out, b.nm.Config, b.nm.Schema, adh), nil
}

// gpLinkGUID reads the schemaIDGUID of gPLink from the schema (never a constant, rule 2).
func (b *builder) gpLinkGUID() (guid.GUID, error) {
	if b.gpLink != nil {
		return *b.gpLink, nil
	}
	var found *guid.GUID
	q := Query{Classes: []string{"attributeSchema"}, Eq: []AttrEq{{Attr: "lDAPDisplayName", Value: "gPLink"}}}
	err := b.d.Find(b.ctx, b.nm.Schema, ad.ScopeOneLevel, q, []string{"schemaIDGUID"}, func(e *ad.Entry) error {
		v := e.Raw("schemaIDGUID")
		if len(v) != 1 {
			return errors.New("tier0: gPLink schemaIDGUID unreadable")
		}
		g, err := guid.FromBytes(v[0])
		if err != nil {
			return errors.New("tier0: gPLink schemaIDGUID malformed")
		}
		found = &g
		return nil
	})
	if err != nil {
		return guid.GUID{}, fmt.Errorf("tier0: gPLink schema object: %w", err)
	}
	if found == nil {
		return guid.GUID{}, errors.New("tier0: gPLink schema object not found")
	}
	b.gpLink = found
	return *found, nil
}

// C17: control of a root of trust. From each root's live DACL and owner (rule 2, 3): every trustee of
// an allow ACE with any one of the control rights, expanded by token (members of a trustee group,
// primary-group members, accounts carrying the trustee in sIDHistory), and the owner unless it is a
// C1 principal already. A root that cannot be read, or whose DACL or owner cannot be decoded, fails
// the snapshot (rule 8).
func (b *builder) c17() error {
	roots, err := b.c17Objects()
	if err != nil {
		return err
	}
	gp, err := b.gpLinkGUID()
	if err != nil {
		return err
	}
	for _, r := range roots {
		e, found, err := b.get(dn.DNRef(r), []string{"objectGUID", "nTSecurityDescriptor"})
		if err != nil {
			return err
		}
		if !found || len(e.Raw("nTSecurityDescriptor")) != 1 {
			return errors.New("tier0: a root of trust has no readable security descriptor")
		}
		d, aces, err := grantsOf(e.Raw("nTSecurityDescriptor")[0])
		if err != nil {
			return err
		}
		if !d.HasOwner {
			return errors.New("tier0: a root of trust has no readable owner")
		}
		seen := map[string]bool{}
		var trustees []sid.SID
		for _, a := range aces {
			if a.controlsRoot(gp) && !seen[a.trustee.String()] {
				seen[a.trustee.String()] = true
				trustees = append(trustees, a.trustee)
			}
		}
		sort.Slice(trustees, func(i, j int) bool { return trustees[i].String() < trustees[j].String() })
		if err := b.markPrincipals(trustees, C17); err != nil {
			return err
		}
		// OWNER RIGHTS and dSHeuristics character 29 are ignored on purpose: the owner is tier0.
		isC1 := func(o *ad.Entry) bool {
			g, err := o.GUID()
			return err == nil && b.s.bases[g.String()][C1]
		}
		if err := b.markPrincipalsSkip([]sid.SID{d.Owner}, C17, isC1); err != nil {
			return err
		}
	}
	return nil
}

// privilegedSID reports a sIDHistory value that is privileged by RID alone, whatever the domain
// prefix (rule 6a).
func privilegedSID(s sid.SID) bool {
	dom, ok := s.DomainSID()
	rid, ok2 := s.RID()
	if !ok || !ok2 {
		return false
	}
	if dom.String() == "S-1-5-32" {
		return privilegedBuiltinRIDs[rid]
	}
	return privilegedDomainRIDs[rid]
}

// sidBatch bounds the objectSid OR-terms in one resolution search.
const sidBatch = 100

// resolveSIDs looks up every distinct non-privileged sIDHistory value in batches and calls set once
// per value (nil entry when no object holds it). Any search error fails the snapshot (fail closed).
func (b *builder) resolveSIDs(hist []histEntry, set func(sid.SID, *ad.Entry, bool)) error {
	seen := map[sid.SID]bool{}
	var todo []sid.SID
	for _, h := range hist {
		for _, s := range h.sids {
			if privilegedSID(s) || seen[s] {
				continue
			}
			seen[s] = true
			if dom, ok := s.DomainSID(); ok && dom != b.domSID {
				// Another domain: the GC path (rare, per value; fails closed on error).
				e, found, foreign, err := b.resolveHistory(s)
				if err != nil {
					return fmt.Errorf("tier0: sIDHistory lookup: %w", err)
				}
				if !found {
					e = nil
				}
				set(s, e, foreign)
				continue
			}
			todo = append(todo, s)
		}
	}
	for len(todo) > 0 {
		n := min(sidBatch, len(todo))
		batch := todo[:n]
		todo = todo[n:]
		got := map[sid.SID]*ad.Entry{}
		err := b.d.Find(b.ctx, b.nm.Domain, ad.ScopeSubtree, Query{AnySID: batch}, idAttrs, func(e *ad.Entry) error {
			ss, err := e.SIDs("objectSid")
			if err != nil {
				return fmt.Errorf("tier0: sIDHistory target: %w", err)
			}
			for _, s := range ss {
				if seen[s] && got[s] == nil {
					got[s] = e
				}
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("tier0: sIDHistory lookup: %w", err)
		}
		for _, s := range batch {
			set(s, got[s], false)
		}
	}
	return nil
}

// C18: privileged sIDHistory. An object is tier0 when a sIDHistory value is privileged by RID, or
// resolves to an object that is tier0 by another basis (iterated: such an object may itself have
// become tier0 through C18). A group that qualifies makes its members tier0 through C2 (rule 7). A
// value that is neither privileged nor resolvable is reported, not marked.
func (b *builder) c18() error {
	hist, err := b.history()
	if err != nil {
		return err
	}
	done := make([]bool, len(hist))
	// Resolution is batched and cached: ceil(distinct/sidBatch) searches, never one per value.
	type res struct {
		e              *ad.Entry
		found, foreign bool
	}
	cache := map[sid.SID]res{}
	if err := b.resolveSIDs(hist, func(s sid.SID, e *ad.Entry, foreign bool) { cache[s] = res{e, e != nil, foreign} }); err != nil {
		return err
	}
	var groups []*ad.Entry
	for changed := true; changed; {
		changed = false
		for i, h := range hist {
			if done[i] {
				continue
			}
			qualifies := false
			for _, s := range h.sids {
				if privilegedSID(s) {
					qualifies = true
					break
				}
				r := cache[s]
				if r.found && r.foreign {
					// The GC cannot clear an object of another domain (no ACLs, no nested membership
					// there), and only a positive classification may: it is tier0 (TM-D26 rules 6b, 8).
					qualifies = true
					break
				}
				if r.found {
					g, err := r.e.GUID()
					if err != nil {
						return fmt.Errorf("tier0: sIDHistory target: %w", err)
					}
					if len(b.s.bases[g.String()]) > 0 || b.desig[g.String()] {
						qualifies = true
						break
					}
				}
			}
			if !qualifies {
				continue
			}
			done[i], changed = true, true
			if _, err := b.mark(h.e, C18); err != nil {
				return err
			}
			if hasClass(h.e, "group") {
				groups = append(groups, h.e)
			}
		}
	}
	for i, h := range hist {
		if done[i] {
			continue
		}
		g, err := h.e.GUID()
		if err != nil {
			return fmt.Errorf("tier0: sIDHistory holder: %w", err)
		}
		for _, s := range h.sids {
			if !cache[s].found {
				b.s.unresolved = append(b.s.unresolved, UnresolvedSIDHistory{Object: g, SID: s})
			}
		}
	}
	return b.membersOf(groups, C2)
}

// resolveHistory resolves one sIDHistory value. A value of this domain is read from the DC. A value
// whose domain prefix is another domain of the forest goes to the Global Catalog; the lookup failing
// is an error (the snapshot fails, so the write is refused). A prefix outside the forest is not
// resolvable by anyone here and is reported unresolved.
func (b *builder) resolveHistory(s sid.SID) (e *ad.Entry, found, foreign bool, err error) {
	dom, ok := s.DomainSID()
	if !ok || dom == b.domSID {
		e, found, err = b.get(dn.SIDRef(s), idAttrs)
		return e, found, false, err
	}
	fd, ok := b.d.(ForestDirectory)
	if !ok {
		return nil, false, false, errors.New("directory cannot resolve a SID of another domain")
	}
	if b.forest == nil {
		ds, err := fd.ForestDomains(b.ctx)
		if err != nil {
			return nil, false, false, err
		}
		b.forest = map[sid.SID]bool{}
		for _, d := range ds {
			b.forest[d] = true
		}
	}
	if !b.forest[dom] {
		return nil, false, false, nil
	}
	e, found, err = fd.GCLookup(b.ctx, s, idAttrs)
	return e, found, true, err
}

// spnHost is the host part of the "host[:port][/name]" remainder of an SPN.
func spnHost(rest string) string {
	if i := strings.IndexAny(rest, ":/"); i >= 0 {
		rest = rest[:i]
	}
	return rest
}

// addHost registers a DC host name (FQDN and short form) for C12 SPN matching.
func (b *builder) addHost(h string) {
	h = strings.ToLower(strings.TrimSpace(h))
	if h == "" {
		return
	}
	b.dcHosts[h] = true
	b.dcHosts[strings.SplitN(h, ".", 2)[0]] = true
}

// Members returns the objectGUID of every object in the snapshot, in a stable order. The rights
// check (TM §6.5 steps 2 and 3) reads each one's effective rights.
func (s *ADSet) Members() []guid.GUID {
	out := make([]guid.GUID, 0, len(s.bases))
	for k := range s.bases {
		g, err := guid.Parse(k)
		if err != nil { // keys come from guid.String
			continue
		}
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// NewADSet returns an empty set, for callers that supply a snapshot from elsewhere (tests of the
// rights check).
func NewADSet() *ADSet { return &ADSet{bases: map[string]map[Basis]bool{}} }

// Add marks g with basis b.
func (s *ADSet) Add(g guid.GUID, b Basis) { s.add(g, b) }

// AddC13 marks g as a C13 group and records it for pinning, as a real snapshot does (tests of the
// rights check, which supply a snapshot from elsewhere).
func (s *ADSet) AddC13(g guid.GUID) {
	s.add(g, C13)
	s.c13 = append(s.c13, g)
}
