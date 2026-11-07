package write

import (
	"context"
	"errors"
	"strings"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/tier0"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/sd"
)

// Step 7 for the deleted target of OBJECT_RESTORE (contract §8.10.3 kind 6, TM-D33). In order:
// the grant on CN=Deleted Objects is proven from the container's DACL, the target is read once by
// GUID, an absent attribute is unreadable unless proven unset, and C2 is judged from both sides.
// Every failure to read or decide is tier0; nothing is classified on a server-supplied attribute.

// DeletedRightsError is "List Contents on Deleted Objects of <domain> is not proven": the grant
// check failed, or the container's descriptor could not be read. It maps to INSUFFICIENT_RIGHTS and
// is never OBJECT_NOT_FOUND (TM-D33 rule 4).
type DeletedRightsError struct{ Domain string }

func (e *DeletedRightsError) Error() string {
	return "write: List Contents on Deleted Objects of " + e.Domain + " is not proven"
}

// ErrNoRecycleBin is CAPABILITY_UNSUPPORTED: without the AD Recycle Bin kind 6 is refused (our
// decision, contract §8.10.3 kind 6), and asking the customer for the container grant would be
// pointless, so the flag is checked first. It is the flag, never try-and-see.
var ErrNoRecycleBin = errors.New("write: the AD Recycle Bin is not enabled")

// ErrDeletedNotFound is the OBJECT_NOT_FOUND of step 7: the target does not exist as a restorable
// deleted object (noSuchObject after the grant was proven, or isRecycled TRUE).
var ErrDeletedNotFound = errors.New("write: deleted object not found")

// DeletedClassifier is a Provider that can classify a deleted object (OBJECT_RESTORE's target).
// newParent is the live parent the object is restored under; its domain is the domain whose
// Deleted Objects container is checked.
type DeletedClassifier interface {
	ClassifyDeleted(ctx context.Context, id, newParent guid.GUID, designated []guid.GUID) (Verdict, error)
}

var _ DeletedClassifier = (*ADProvider)(nil)

// ClassifyDeleted is step 7 for a deleted restore target. See the file comment for the order.
//
//   - C1: a RID below 1000; Designated: the target itself; C18: any sIDHistory value;
//   - C3: adminCount nonzero; C5/C12: DC/RODC or unconstrained delegation by userAccountControl,
//     primaryGroupID 516/521 is C5, any other non-default primary group is C2;
//   - C2: any retained memberOf group that is tier0, designated or unreadable, and any tier0 group
//     (C1, C13, designated) whose member values hold the target;
//   - C3/C6: the last known parent, when it still exists, classifies as tier0.
func (p *ADProvider) ClassifyDeleted(ctx context.Context, id, newParent guid.GUID, designated []guid.GUID) (Verdict, error) {
	objs := p.Objects()
	if objs == nil {
		return Verdict{Tier0: true}, ErrNoBoundDC
	}
	return p.classifyDeleted(ctx, objs, id, newParent, designated)
}

// classifyDeleted is ClassifyDeleted over a given object directory.
func (p *ADProvider) classifyDeleted(ctx context.Context, objs ObjectDirectory, id, newParent guid.GUID, designated []guid.GUID) (Verdict, error) {
	unknown := Verdict{Tier0: true}
	on, err := objs.RecycleBin(ctx)
	if err != nil {
		return unknown, err
	}
	if !on {
		return unknown, ErrNoRecycleBin
	}
	// Step 1: the grant, before the target read. The domain is the new parent's: a deleted object
	// is restored inside its own domain, and the read below must come back from that same domain.
	ps, err := objs.State(ctx, newParent, false)
	if err != nil {
		return unknown, err
	}
	domain := domainOf(ps.DN)
	if domain.Len() == 0 {
		return unknown, errors.New("write: new parent has no domain")
	}
	pr, err := p.proveListContents(ctx, objs, domain)
	if err != nil {
		return unknown, err
	}
	// Step 2: the target read.
	e, err := objs.DeletedTarget(ctx, id)
	if err != nil {
		if ad.CodeOf(err) == ad.CodeObjectNotFound {
			return unknown, ErrDeletedNotFound
		}
		return unknown, err
	}
	if g, gerr := e.GUID(); gerr != nil || g != id {
		return unknown, errors.New("write: deleted target read returned another object")
	}
	if has(e, "isRecycled") && isTrue(e.Strings("isRecycled")) {
		return unknown, ErrDeletedNotFound
	}
	if !has(e, "isDeleted") {
		// Live (restored meanwhile): the ordinary live classification.
		return p.Classify(ctx, id, designated)
	}
	if !isTrue(e.Strings("isDeleted")) {
		return unknown, errors.New("write: deleted target isDeleted is not TRUE")
	}
	// The deleted object must live in the domain whose grant was proven.
	// (The DN of a deleted object carries a mangled RDN, so this is a suffix check on the rendered text.)
	if !strings.HasSuffix(strings.ToLower(e.DN), ","+strings.ToLower(domain.String())) {
		return unknown, errors.New("write: deleted target is not in the proven domain")
	}
	v, err := p.classifyDeletedEntry(ctx, objs, id, e, designated, pr)
	if err != nil || v.Tier0 {
		return v, err
	}
	// Step 4's cross-check: the target is a value of no tier0 group's member attribute.
	hit, err := p.memberCrossCheck(ctx, objs, id, designated)
	if err != nil {
		return unknown, err
	}
	if hit {
		return Verdict{Tier0: true, Bases: []Basis{tier0.C2}}, nil
	}
	return Verdict{}, nil
}

func has(e *ad.Entry, attr string) bool { return len(e.Raw(attr)) > 0 }

func isTrue(v []string) bool { return len(v) == 1 && strings.EqualFold(v[0], "TRUE") }

// domainOf is the trailing DC= run of a DN: the domain naming context head.
func domainOf(d dn.DN) dn.DN {
	rdns := d.RDNs()
	i := len(rdns)
	for i > 0 && rdns[i-1].Type() == dn.DC {
		i--
	}
	out := dn.DN{}
	for j := len(rdns) - 1; j >= i; j-- {
		next, err := dn.Child(out, dn.DC, rdns[j].Value())
		if err != nil {
			return dn.DN{}
		}
		out = next
	}
	return out
}

// principal is the connection identity's token (its objectSid and tokenGroups), read from the DC.
func (p *ADProvider) principal(ctx context.Context) (sd.Principal, error) {
	if _, err := p.Self.ForRequest(); err != nil {
		return sd.Principal{}, errors.New("write: connection identity is unknown")
	}
	e, err := p.Dir.Get(ctx, p.Self, []string{"objectSid", "tokenGroups"})
	if err != nil {
		return sd.Principal{}, err
	}
	sids, err := e.SIDs("objectSid")
	if err != nil || len(sids) != 1 {
		return sd.Principal{}, errors.New("write: connection identity has no objectSid")
	}
	groups, err := e.SIDs("tokenGroups")
	if err != nil {
		return sd.Principal{}, err
	}
	return sd.PrincipalFromToken(sids[0], groups), nil
}

// proveListContents is step 1: List Contents for the connection identity's token, proven from the
// owner and DACL of CN=Deleted Objects (TM-D33 rule 4). Never decided by trying the target read.
// Not proven, or an unreadable descriptor, is a DeletedRightsError; only a lost DC or a cancelled
// context is a plain error.
func (p *ADProvider) proveListContents(ctx context.Context, objs ObjectDirectory, domain dn.DN) (sd.Principal, error) {
	denied := &DeletedRightsError{Domain: domain.String()}
	pr, err := p.principal(ctx)
	if err != nil {
		if isTransportErr(ctx, err) {
			return sd.Principal{}, err
		}
		return sd.Principal{}, denied
	}
	_, raw, err := objs.DeletedContainer(ctx, domain)
	if err != nil {
		if isTransportErr(ctx, err) {
			return sd.Principal{}, err
		}
		return sd.Principal{}, denied
	}
	desc, err := sd.Decode(sd.Raw(raw))
	if err != nil {
		return sd.Principal{}, denied
	}
	res := sd.Grants(pr, sd.Right{Mask: sd.MaskListContents}, desc)
	if res.Decision != sd.Yes || res.Incomplete {
		return sd.Principal{}, denied
	}
	return pr, nil
}

func isTransportErr(ctx context.Context, err error) bool {
	return ctx.Err() != nil || ad.CodeOf(err) == ad.CodeUnreachable || ad.CodeOf(err) == ad.CodeCanceled
}

// classifyDeletedEntry decides over the retained attributes of one deleted object read; split out
// so the fail-closed branches are testable without a Recycle Bin.
func (p *ADProvider) classifyDeletedEntry(ctx context.Context, objs ObjectDirectory, id guid.GUID, e *ad.Entry, designated []guid.GUID, pr sd.Principal) (Verdict, error) {
	unknown := Verdict{Tier0: true}
	for _, g := range designated {
		if g == id { // a customer-designated object stays Tier-0 once deleted
			return Verdict{Tier0: true, Bases: []Basis{designatedBasis}}, nil
		}
	}
	classes := map[string]bool{}
	for _, c := range e.Strings("objectClass") {
		classes[strings.ToLower(c)] = true
	}
	account := classes["user"] || classes["computer"]
	// Only an OU or a contact has no objectSid; an unknown class is treated as a security principal.
	needSID := account || classes["group"] || !(classes["organizationalunit"] || classes["contact"])

	// Step 3, must-be-present set: any absent attribute makes the target tier0, basis unknown.
	for _, a := range ad.DeletedTargetMustBePresent {
		if !has(e, a) {
			return unknown, nil
		}
	}
	if needSID && !has(e, "objectSid") {
		return unknown, nil
	}
	if account && (!has(e, "userAccountControl") || !has(e, "primaryGroupID")) {
		return unknown, nil
	}
	for _, n := range e.Truncated {
		if strings.EqualFold(n, "memberOf") {
			return unknown, errors.New("write: deleted object memberOf cut at the value ceiling")
		}
	}
	// Step 3, optional set: an absent attribute is unreadable unless the retained descriptor proves
	// Read Property on it.
	if absent := absentOptional(e); len(absent) > 0 {
		if err := p.proveUnset(ctx, e, absent, pr); err != nil {
			return unknown, nil
		}
	}

	sids, err := e.SIDs("objectSid")
	if err != nil {
		return unknown, err
	}
	for _, s := range sids {
		if rid, ok := s.RID(); !ok || rid < 1000 {
			return Verdict{Tier0: true, Bases: []Basis{tier0.C1}}, nil
		}
	}
	if has(e, "sIDHistory") {
		return Verdict{Tier0: true, Bases: []Basis{tier0.C18}}, nil
	}
	// adminCount is set by SDProp on protected-group members and survives the delete (defence in depth).
	if n, present, err := e.Int32("adminCount"); err != nil {
		return unknown, err
	} else if present && n != 0 {
		return Verdict{Tier0: true, Bases: []Basis{tier0.C3}}, nil
	}
	if account {
		uac, _, err := e.Int32("userAccountControl")
		if err != nil {
			return unknown, err
		}
		if uac&(0x2000|0x4000000) != 0 { // DC or RODC computer
			return Verdict{Tier0: true, Bases: []Basis{tier0.C5}}, nil
		}
		if uac&0x80000 != 0 { // unconstrained delegation
			return Verdict{Tier0: true, Bases: []Basis{tier0.C12}}, nil
		}
		v := e.Strings("primaryGroupID")
		if len(v) != 1 {
			return unknown, errors.New("write: deleted object primaryGroupID unreadable")
		}
		switch v[0] {
		case "513", "514", "515":
		case "516", "521":
			return Verdict{Tier0: true, Bases: []Basis{tier0.C5}}, nil
		default:
			return Verdict{Tier0: true, Bases: []Basis{tier0.C2}}, nil
		}
	}
	// Step 4, retained side: every memberOf group, judged against the set and by its own live token.
	des := map[guid.GUID]bool{}
	for _, g := range designated {
		des[g] = true
	}
	for _, m := range e.Strings("memberOf") {
		gid, err := p.linkGUID(ctx, m)
		if err != nil {
			return Verdict{Tier0: true, Bases: []Basis{tier0.C2}}, nil // unreadable group: tier0
		}
		if des[gid] {
			return Verdict{Tier0: true, Bases: []Basis{tier0.C2}}, nil
		}
		gv, err := p.Classify(ctx, gid, designated)
		if err != nil || gv.Tier0 {
			return Verdict{Tier0: true, Bases: []Basis{tier0.C2}}, nil
		}
	}
	if v := e.Strings("lastKnownParent"); len(v) == 1 {
		pid, found, err := p.linkGUIDOpt(ctx, v[0])
		if err != nil {
			return unknown, err
		}
		if found {
			pv, err := p.Classify(ctx, pid, designated)
			if err != nil || pv.Tier0 {
				return Verdict{Tier0: true, Bases: []Basis{tier0.C3}}, nil
			}
		}
	}
	return Verdict{}, nil
}

// linkGUID is the objectGUID a DN-syntax value names: the extended-DN GUID when the DC sent one,
// else a read by the plain DN. A value that names no readable object is an error.
func (p *ADProvider) linkGUID(ctx context.Context, v string) (guid.GUID, error) {
	g, found, err := p.linkGUIDOpt(ctx, v)
	if err != nil {
		return guid.GUID{}, err
	}
	if !found {
		return guid.GUID{}, ErrDeletedNotFound
	}
	return g, nil
}

// linkGUIDOpt is linkGUID where a value naming an object that no longer exists is found false.
func (p *ADProvider) linkGUIDOpt(ctx context.Context, v string) (guid.GUID, bool, error) {
	lv, err := dn.ParseLinkValue(v)
	if err != nil {
		return guid.GUID{}, false, err
	}
	var ref dn.ObjectRef
	if lv.HasGUID {
		ref = dn.GUIDRef(lv.GUID)
	} else if ref, err = dn.ParseObjectRef(lv.DN); err != nil {
		return guid.GUID{}, false, err
	}
	e, err := p.Dir.Get(ctx, ref, []string{"objectGUID"})
	if ad.CodeOf(err) == ad.CodeObjectNotFound {
		return guid.GUID{}, false, nil
	}
	if err != nil {
		return guid.GUID{}, false, err
	}
	g, err := e.GUID()
	if err != nil {
		return guid.GUID{}, false, err
	}
	return g, true, nil
}

// absentOptional lists the optional-set attributes the entry did not carry.
func absentOptional(e *ad.Entry) []string {
	var out []string
	for _, a := range ad.DeletedTargetOptional {
		if !has(e, a) {
			out = append(out, a)
		}
	}
	return out
}

// proveUnset is the exception of step 3: every absent optional attribute must be proven readable,
// so its absence means "not set". Proof is the retained nTSecurityDescriptor of the same response,
// evaluated for the connection identity's token with the shared effective-rights primitive: Read
// Property on the attribute's schemaIDGUID (or all properties), no applicable deny, no ACE the
// primitive cannot decide, and for a confidential attribute (searchFlags 0x80) Control Access too.
// An ACE on a property set that might cover the attribute makes the primitive answer Unknown, which
// is not proof. Any error is "not proven".
func (p *ADProvider) proveUnset(ctx context.Context, e *ad.Entry, absent []string, pr sd.Principal) error {
	raw := e.Raw("nTSecurityDescriptor")
	if len(raw) != 1 {
		return errors.New("write: no retained descriptor")
	}
	desc, err := sd.Decode(sd.Raw(raw[0]))
	if err != nil {
		return err
	}
	if sids, serr := e.SIDs("objectSid"); serr == nil && len(sids) == 1 {
		pr = pr.WithObjectSID(sids[0])
	}
	nm, err := p.Dir.Naming(ctx)
	if err != nil {
		return err
	}
	for _, name := range absent {
		var id guid.GUID
		var flags int32
		found := false
		err := p.Dir.Find(ctx, nm.Schema, ad.ScopeSubtree, tier0.Query{
			Classes: []string{"attributeSchema"},
			Eq:      []tier0.AttrEq{{Attr: "lDAPDisplayName", Value: name}},
		}, []string{"schemaIDGUID", "searchFlags"}, func(se *ad.Entry) error {
			r := se.Raw("schemaIDGUID")
			if len(r) != 1 || found {
				return nil
			}
			g, gerr := guid.FromBytes(r[0])
			if gerr != nil {
				return gerr
			}
			id, found = g, true
			flags, _, _ = se.Int32("searchFlags")
			return nil
		})
		if err != nil {
			return err
		}
		if !found {
			return errors.New("write: attribute not in the schema")
		}
		if r := sd.Grants(pr, sd.Right{Mask: sd.MaskReadProp, Object: &id, Kind: sd.Attribute}, desc); r.Decision != sd.Yes || r.Incomplete {
			return errors.New("write: Read Property not proven")
		}
		if flags&0x80 != 0 { // fCONFIDENTIAL needs Control Access as well
			if r := sd.Grants(pr, sd.Right{Mask: sd.MaskControlAccess}, desc); r.Decision != sd.Yes || r.Incomplete {
				return errors.New("write: Control Access not proven")
			}
		}
	}
	return nil
}

// tier0Set is the connector's computed tier0 set; tests substitute p.snapshot.
func (p *ADProvider) tier0Set(ctx context.Context, designated []guid.GUID) (*tier0.ADSet, error) {
	if p.snapshot != nil {
		return p.snapshot(ctx, designated)
	}
	if p.Pins == nil {
		return nil, ErrNoPins
	}
	pins, err := p.Pins.PinnedC13(ctx)
	if err != nil {
		return nil, err
	}
	return tier0.NewAD(p.Dir).SnapshotWith(ctx, pins, designated)
}

// memberCrossCheck is the second half of step 4: the member attribute of every group the connector's
// set holds as tier0 by C1, C13 or designation, read with the show-deactivated-link control and
// ranged retrieval; a value whose extended-DN GUID is the target makes it tier0 (basis C2), whatever
// memberOf said. A failed or partial read is an error (tier0). Deleted member values are the point
// here, so the "drop values under CN=Deleted Objects" rule of ordinary member reads does not apply.
func (p *ADProvider) memberCrossCheck(ctx context.Context, objs ObjectDirectory, id guid.GUID, designated []guid.GUID) (bool, error) {
	set, err := p.tier0Set(ctx, designated)
	if err != nil {
		return false, err
	}
	for _, g := range set.Members() {
		if !anyBasis(set.Bases(g), tier0.C1, tier0.C13, tier0.Designated) {
			continue
		}
		ge, err := p.Dir.Get(ctx, dn.GUIDRef(g), []string{"objectClass"})
		if err != nil {
			return false, err
		}
		isGroup := false
		for _, c := range ge.Strings("objectClass") {
			if strings.EqualFold(c, "group") {
				isGroup = true
			}
		}
		if !isGroup {
			continue
		}
		members, truncated, err := objs.GroupMembers(ctx, g)
		if err != nil {
			return false, err
		}
		if truncated {
			return false, errors.New("write: group member list cut at the value ceiling")
		}
		for _, m := range members {
			lv, err := dn.ParseLinkValue(m)
			if err != nil {
				return false, err
			}
			if !lv.HasGUID { // the DC did not honour the extended-DN control: the value cannot be matched
				return false, errors.New("write: group member value carries no GUID")
			}
			if lv.GUID == id {
				return true, nil
			}
		}
	}
	return false, nil
}

func anyBasis(have []Basis, want ...Basis) bool {
	for _, h := range have {
		for _, w := range want {
			if h == w {
				return true
			}
		}
	}
	return false
}
