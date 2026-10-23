package rights

import (
	"errors"
	"sort"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	adguid "github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	v1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

func isDeniedRead(err error) bool {
	return notFound(err) || ad.CodeOf(err) == ad.CodeInsufficientRights
}

// v8: R1 and R2 on every managed domain NC. A head the identity cannot read means it lacks the
// read right every feature needs (block, never overridable). Other errors are COULD_NOT_VERIFY.
// Not checked here (Windows lab, T-0096 note): tokenGroupsGlobalAndUniversal readability via the
// Windows Authorization Access Group.
func (c *adCheck) v8() {
	for _, dg := range c.in.ManagedDomains {
		_, err := c.d.Read(c.ctx, dn.GUIDRef(dg), []string{"objectSid"}, ad.ReadOptions{})
		switch {
		case err == nil:
		case isDeniedRead(err):
			c.add(&v1.RightsFinding{Check: v8, Kind: v1.FindingKind_FINDING_KIND_MISSING_RIGHT, Severity: v1.FindingSeverity_FINDING_SEVERITY_BLOCK,
				Code: CodeMissingRead, Right: adRight(v1.AdRightKind_AD_RIGHT_KIND_READ_PROPERTY, nil, dsReadProp, ""),
				Source: &v1.RightSource{Source: &v1.RightSource_ExpectedBy{ExpectedBy: v1.RightsFamily_RIGHTS_FAMILY_AD_R1_INVENTORY}},
				Family: v1.RightsFamily_RIGHTS_FAMILY_AD_R1_INVENTORY}, dg, "")
		default:
			c.cannot(v8, &dg, err)
		}
	}
}

// lowestWriteFamily is the family an excess finding is reported against: the first enabled write
// family, or unset.
func (c *adCheck) lowestWriteFamily() v1.RightsFamily {
	var fs []int
	for f := range c.famSet {
		if f >= v1.RightsFamily_RIGHTS_FAMILY_AD_R3_USER_LIFECYCLE && f <= v1.RightsFamily_RIGHTS_FAMILY_AD_R12_HOME_FOLDERS {
			fs = append(fs, int(f))
		}
	}
	if len(fs) == 0 {
		return 0
	}
	sort.Ints(fs)
	return v1.RightsFamily(fs[0])
}

func (c *adCheck) v9() {
	// Resolve the never-delegate attributes and the dMSA class once.
	never := map[adguid.GUID]string{}
	for _, n := range neverDelegateAttrs {
		o, err := c.attrByName(n)
		if err != nil {
			c.cannot(v9, nil, err)
			return
		}
		if o != nil {
			never[o.ID] = o.Name
		}
	}
	var dsa *SchemaObject
	if o, err := c.classByName(dsaClass); err != nil {
		c.cannot(v9, nil, err)
		return
	} else {
		dsa = o
	}
	fam := c.lowestWriteFamily()
	for _, rg := range c.in.ManagedRoots {
		if _, isT0 := c.set[rg.String()]; isT0 {
			continue // a tier0 object is judged, and blocks, in V7
		}
		d, ok := c.readDACL(rg)
		if !ok {
			continue
		}
		for _, g := range d.grants(c.own, true) {
			for _, k := range c.ouExcess(g, never, dsa) {
				name := ""
				if k.typ != nil {
					if o, err := c.byID(*k.typ); err == nil && o != nil {
						name = o.Name
					}
				}
				c.add(&v1.RightsFinding{Check: v9, Kind: v1.FindingKind_FINDING_KIND_EXCESSIVE_RIGHT, Severity: v1.FindingSeverity_FINDING_SEVERITY_WARN,
					Code: CodeExcessOU + k.slug, Right: adRight(k.kind, k.typ, k.mask, name), Source: aceSource(rg, g.ace), Family: fam}, rg, aceQualifier(g.ace))
			}
		}
		c.missing(rg, d, false)
	}
	for _, dg := range c.in.ManagedDomains {
		if c.famSet[v1.RightsFamily_RIGHTS_FAMILY_AD_R9_RECYCLE_BIN_RESTORE] {
			if d, ok := c.readDACL(dg); ok {
				c.missing(dg, d, true)
			}
		}
	}
}

// readDACL reads an object's DACL. A denied or missing object is a V9 warning; any other error is
// COULD_NOT_VERIFY.
func (c *adCheck) readDACL(g adguid.GUID) (*descriptor, bool) {
	e, err := c.d.Read(c.ctx, dn.GUIDRef(g), []string{"nTSecurityDescriptor"}, ad.ReadOptions{SD: ad.DefaultSDFlags()})
	if err != nil {
		if isDeniedRead(err) {
			c.add(&v1.RightsFinding{Check: v9, Kind: v1.FindingKind_FINDING_KIND_MISSING_RIGHT, Severity: v1.FindingSeverity_FINDING_SEVERITY_WARN,
				Code: CodeMissingRead, Right: adRight(v1.AdRightKind_AD_RIGHT_KIND_READ_PROPERTY, nil, dsReadProp, ""),
				Source: &v1.RightSource{Source: &v1.RightSource_ExpectedBy{ExpectedBy: v1.RightsFamily_RIGHTS_FAMILY_AD_R1_INVENTORY}},
				Family: v1.RightsFamily_RIGHTS_FAMILY_AD_R1_INVENTORY}, g, "")
			return nil, false
		}
		c.cannot(v9, &g, err)
		return nil, false
	}
	raw := e.Raw("nTSecurityDescriptor")
	if len(raw) != 1 {
		c.cannot(v9, &g, errors.New("nTSecurityDescriptor not returned"))
		return nil, false
	}
	d, err := parseSD(raw[0])
	if err != nil {
		c.cannot(v9, &g, err)
		return nil, false
	}
	return d, true
}

type ouKind struct {
	aceKind
	slug string
}

// ouExcess lists what an ACE grants beyond the §6.3 mask: GenericAll, GenericWrite, WRITE_DAC,
// WRITE_OWNER, Delete-Tree, write of every property or a never-delegate one, create of every child
// class or of a dMSA, every extended right or Get-Changes(-All), and the never-delegate validated
// writes.
func (c *adCheck) ouExcess(g grant, never map[adguid.GUID]string, dsa *SchemaObject) []ouKind {
	a := g.ace
	var typ *adguid.GUID
	if a.hasType {
		t := a.objType
		typ = &t
	}
	mk := func(kind v1.AdRightKind, slug string, mask uint32, t *adguid.GUID) ouKind {
		return ouKind{aceKind{kind: kind, mask: mask, typ: t}, slug}
	}
	if g.genericAll() {
		return []ouKind{mk(v1.AdRightKind_AD_RIGHT_KIND_GENERIC_ALL, "generic_all", a.mask, nil)}
	}
	var out []ouKind
	if g.genericWrite() {
		out = append(out, mk(v1.AdRightKind_AD_RIGHT_KIND_GENERIC_WRITE, "generic_write", a.mask, nil))
	}
	if g.has(maskWriteDAC) {
		out = append(out, mk(v1.AdRightKind_AD_RIGHT_KIND_WRITE_DAC, "write_dacl", maskWriteDAC, nil))
	}
	if g.has(maskWriteOwner) {
		out = append(out, mk(v1.AdRightKind_AD_RIGHT_KIND_WRITE_OWNER, "write_owner", maskWriteOwner, nil))
	}
	if g.has(dsDeleteTree) {
		out = append(out, mk(v1.AdRightKind_AD_RIGHT_KIND_DELETE_TREE, "delete_tree", dsDeleteTree, nil))
	}
	if g.has(dsWriteProp) && !g.genericWrite() {
		if !a.hasType {
			out = append(out, mk(v1.AdRightKind_AD_RIGHT_KIND_WRITE_PROPERTY, "write_all_properties", dsWriteProp, nil))
		} else if _, bad := never[a.objType]; bad || neverDelegateRights[a.objType] {
			out = append(out, mk(v1.AdRightKind_AD_RIGHT_KIND_WRITE_PROPERTY, "write_never_delegate", dsWriteProp, typ))
		}
	}
	if g.has(dsSelf) && !g.genericWrite() && (!a.hasType || neverDelegateRights[a.objType]) {
		out = append(out, mk(v1.AdRightKind_AD_RIGHT_KIND_VALIDATED_WRITE, "validated_write", dsSelf, typ))
	}
	if g.has(dsCreateChild) && (!a.hasType || (dsa != nil && a.objType == dsa.ID)) {
		out = append(out, mk(v1.AdRightKind_AD_RIGHT_KIND_CREATE_CHILD, "create_child", dsCreateChild, typ))
	}
	if g.has(dsControlAccess) && (!a.hasType || a.objType == rightGetChanges || a.objType == rightGetChangesAll) {
		out = append(out, mk(v1.AdRightKind_AD_RIGHT_KIND_CONTROL_ACCESS, "control_access", dsControlAccess, typ))
	}
	return out
}

// covers reports whether the identity's grants include the expected right.
func covers(gs []grant, e expectation, typ adguid.GUID) bool {
	for _, g := range gs {
		if g.genericAll() {
			return true
		}
		if !g.has(e.bit) {
			continue
		}
		if !g.ace.hasType || g.ace.objType == typ {
			return true
		}
	}
	return false
}

// missing reports, per enabled family, each expected right the identity does not hold on the object.
// The token (baseline SIDs included) decides: what the identity effectively has.
func (c *adCheck) missing(obj adguid.GUID, d *descriptor, domain bool) {
	gs := d.grants(c.tokens, true)
	var fams []int
	for f := range c.famSet {
		fams = append(fams, int(f))
	}
	sort.Ints(fams)
	for _, fi := range fams {
		f := v1.RightsFamily(fi)
		for _, e := range expectations[f] {
			if e.onDomain != domain {
				continue
			}
			var typ adguid.GUID
			name := ""
			switch {
			case e.ext != nil:
				typ = *e.ext
			case e.attr != "" || e.class != "":
				var o *SchemaObject
				var err error
				if e.attr != "" {
					o, err = c.attrByName(e.attr)
				} else {
					o, err = c.classByName(e.class)
				}
				if err != nil {
					c.cannot(v9, &obj, err)
					continue
				}
				if o == nil {
					continue // the forest's schema has no such object: nothing to expect
				}
				typ, name = o.ID, o.Name
			}
			if covers(gs, e, typ) {
				continue
			}
			c.add(&v1.RightsFinding{Check: v9, Kind: v1.FindingKind_FINDING_KIND_MISSING_RIGHT, Severity: v1.FindingSeverity_FINDING_SEVERITY_WARN,
				Code: CodeMissingFamily, Family: f, Right: adRight(e.kind, &typ, e.bit, name),
				Source: &v1.RightSource{Source: &v1.RightSource_ExpectedBy{ExpectedBy: f}}}, obj, typ.String())
		}
	}
}
