package write

import (
	"bytes"
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/tier0"
	"github.com/skenzeriq/activediq/internal/connector/write/ops"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// Kinds 11 and 12 (GROUP_MEMBER_ADD, GROUP_MEMBER_REMOVE; contract §8.10.3, v1.6, T-1913). One shape,
// two verbs. The request's target is the group; the member is a GUID read live and turned into a DN by
// the DN type. The Tier-0 guard (§8.1 step 7) classifies both touched objects before this code runs, so
// a Tier-0 group or member never reaches it, and the §8.9 GROUP_MEMBERSHIP declaration covers the
// dynamic-group rules (CC-WK-62). The group's `member` list is never read: membership is decided from
// the member's side (memberOf and primaryGroupID), so a 50,000-member group costs the same as an empty one.

func init() {
	operations[connectorv1.WriteKind_WRITE_KIND_GROUP_MEMBER_ADD] = groupOp(true)
	operations[connectorv1.WriteKind_WRITE_KIND_GROUP_MEMBER_REMOVE] = groupOp(false)
}

func groupOp(add bool) WriteOp {
	return WriteOp{
		Arm: func(c *connectorv1.WriteChange) bool {
			if add {
				return c.GetGroupMemberAdd() != nil
			}
			return c.GetGroupMemberRemove() != nil
		},
		Touched: func(target guid.GUID, c *connectorv1.WriteChange) ([]guid.GUID, error) {
			m, _, err := memberOfChange(c, add)
			if err != nil {
				return nil, err
			}
			return []guid.GUID{target, m}, nil
		},
		PropertyWrite: func(c *connectorv1.WriteChange) (tier0.PropertyWrite, error) {
			if _, _, err := memberOfChange(c, add); err != nil {
				return tier0.PropertyWrite{}, err
			}
			return tier0.PropertyWrite{Plane: tier0.PlaneAD, Kind: tier0.WriteGroup, Op: tier0.OpGroupMembership}, nil
		},
		Digest: objectDigest,
		Plan: func(ctx context.Context, a Authorised, req *connectorv1.PlanRequest) (*connectorv1.PlanResponse, error) {
			return planGroupMember(ctx, a, req, add)
		},
		Apply: func(ctx context.Context, a Authorised, req *connectorv1.ApplyRequest) (*connectorv1.ApplyResponse, error) {
			return applyGroupMember(ctx, a, req, add)
		},
	}
}

// memberOfChange returns the member GUID and declared class of the kind's arm.
func memberOfChange(c *connectorv1.WriteChange, add bool) (guid.GUID, connectorv1.DirectoryObjectClass, error) {
	var g *connectorv1.Guid
	var cls connectorv1.DirectoryObjectClass
	if add {
		x := c.GetGroupMemberAdd()
		if x == nil {
			return guid.GUID{}, 0, errBadChange
		}
		g, cls = x.GetMember(), x.GetMemberClass()
	} else {
		x := c.GetGroupMemberRemove()
		if x == nil {
			return guid.GUID{}, 0, errBadChange
		}
		g, cls = x.GetMember(), x.GetMemberClass()
	}
	m, err := fromWire(g)
	if err != nil {
		return guid.GUID{}, 0, errBadChange
	}
	return m, cls, nil
}

// groupTx is the part of *ad.Tx the group kinds use, so the bodies have non-lab tests.
type groupTx interface {
	DCTime() (time.Time, error)
	Read(ref dn.ObjectRef, attrs []string) (*ad.Entry, error)
	Send(send func(ad.WriteConn) error) error
}

type memberRead struct {
	group, member *ad.Entry
	class         connectorv1.DirectoryObjectClass
	inGroup       bool // memberOf holds the group
	primary       bool // the group is the member's primary group (not stored in `member`)
	dig           []byte
	obs           *connectorv1.Observation
}

// satisfied: the target state of the verb already holds. A primary group is "already a member" and,
// for remove, is refused before this is asked (PrimaryGroupMember).
func (r *memberRead) satisfied(add bool) bool {
	if add {
		return r.inGroup || r.primary
	}
	return !r.inGroup && !r.primary
}

var (
	groupAttrs  = []string{"objectClass", "objectSid", "groupType", "tokenGroups", "adminCount"}
	memberAttrs = []string{"objectClass", "objectSid", "primaryGroupID", "memberOf", "adminCount"}
)

func memberClassAllowed(c connectorv1.DirectoryObjectClass) bool {
	switch c {
	case connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_USER, connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_COMPUTER,
		connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_CONTACT, connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_GROUP:
		return true
	}
	return false
}

// domainOf is the DC= suffix of a DN: the domain naming context of a single-domain-NC object.
func dcSuffix(d dn.DN) string {
	var parts []string
	for _, r := range d.RDNs() {
		if r.Type() == dn.DC {
			parts = append(parts, strings.ToLower(r.Value()))
		}
	}
	return strings.Join(parts, ",")
}

// sidText is the SID's text form, or "" for the zero SID (a contact has none).
func sidText(s sid.SID) string {
	if len(s.Bytes()) <= 8 {
		return ""
	}
	return s.String()
}

func sidOf(e *ad.Entry) (sid.SID, bool) {
	s, err := e.SIDs("objectSid")
	if err != nil || len(s) != 1 {
		return sid.SID{}, false
	}
	return s[0], true
}

// readMembership is the read set of Plan and Apply step 7 and all the refusals of contract §8.10.3.
func readMembership(tx groupTx, add bool, group, member guid.GUID, declared connectorv1.DirectoryObjectClass) (*memberRead, *Refusal) {
	if add && group == member {
		return nil, invalid("5", "SelfMembership", "member")
	}
	obs, _, r := dcTimes(tx)
	if r != nil {
		return nil, r
	}
	ge, err := tx.Read(dn.GUIDRef(group), groupAttrs)
	if err != nil {
		return nil, fromDir(err)
	}
	if g, gerr := ge.GUID(); gerr != nil || g != group {
		return nil, invalid("5", "TargetRequired", "target.object")
	}
	if c, r := liveClass(ge); r != nil || c != connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_GROUP {
		return nil, invalid("5", "ClassNotAllowed", "target")
	}
	me, err := tx.Read(dn.GUIDRef(member), memberAttrs)
	if err != nil {
		return nil, fromDir(err)
	}
	if g, gerr := me.GUID(); gerr != nil || g != member {
		return nil, invalid("5", "TargetRequired", "member")
	}
	live, r := liveClass(me)
	if r != nil || !memberClassAllowed(live) {
		return nil, invalid("5", "ClassNotAllowed", "member")
	}
	if live != declared {
		return nil, invalid("5", "MemberClassMismatch", "member_class")
	}
	gdn, gerr := dn.Parse(ge.DN, dn.Strict)
	mdn, merr := dn.Parse(me.DN, dn.Strict)
	if gerr != nil || merr != nil {
		return nil, invalid("5", "TargetRequired", "target.object")
	}
	if dcSuffix(gdn) != dcSuffix(mdn) {
		return nil, invalid("5", "CrossDomainMemberUnsupported", "member")
	}
	gsid, gok := sidOf(ge)
	msid, mok := sidOf(me)
	// A contact has no objectSid; every other member class has one (the loop check and the digest use it).
	if !gok || (!mok && live != connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_CONTACT) {
		return nil, invalid("5", "UnreadableAttribute", "target")
	}
	if add && live == connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_GROUP {
		// The member's SID already in the group's tokenGroups means the group sits below the member.
		toks, terr := ge.SIDs("tokenGroups")
		if terr != nil {
			return nil, invalid("5", "UnreadableAttribute", "target")
		}
		for _, t := range toks {
			if t.String() == msid.String() {
				return nil, invalid("5", "NestingCycle", "member")
			}
		}
	}
	rd := &memberRead{group: ge, member: me, class: live, obs: obs}
	if rid, ok := gsid.RID(); ok {
		if raw := me.Raw("primaryGroupID"); len(raw) == 1 {
			if n, perr := strconv.ParseUint(string(raw[0]), 10, 32); perr == nil && uint32(n) == rid {
				rd.primary = true
			}
		}
	}
	for _, v := range me.Strings("memberOf") {
		// AD compares DN values case-insensitively; both spellings come from the same DC, so this is belt and braces.
		if d, perr := dn.Parse(v, dn.Strict); perr == nil && (dn.Equal(d, gdn) || strings.EqualFold(d.CanonicalString(), gdn.CanonicalString())) {
			rd.inGroup = true
			break
		}
	}
	if !add && rd.primary {
		return nil, invalid("5", "PrimaryGroupMember", "member")
	}
	rd.dig = membershipDigest(ge, me, gsid, msid, live, mdn)
	return rd, nil
}

// membershipDigest is the precondition: {group objectSid, groupType, group adminCount, member objectSid,
// member class, member parent, member adminCount}. It does not cover the group's uSNChanged or its
// member list, so a race on a different member does not fail (contract §8.10.3). Whether the group or
// member is Tier-0 is not hashed: the guard re-reads that at step 7 on Apply and refuses with
// TIER0_REFUSED, which is a stronger answer than a changed digest; adminCount stands for it in the digest.
func membershipDigest(ge, me *ad.Entry, gsid, msid sid.SID, cls connectorv1.DirectoryObjectClass, mdn dn.DN) []byte {
	raw := func(e *ad.Entry, n string) string {
		v := e.Raw(n)
		sort.Slice(v, func(i, j int) bool { return bytes.Compare(v[i], v[j]) < 0 })
		return string(bytes.Join(v, []byte{0}))
	}
	return hashParts("adq-group-member/1", gsid.String(), raw(ge, "groupType"), raw(ge, "adminCount"),
		sidText(msid), cls.String(), strings.ToLower(mdn.Parent().CanonicalString()), raw(me, "adminCount"))
}

func memberEntry(rd *memberRead, member guid.GUID, group *ad.Entry) *connectorv1.DirectoryEntry {
	e := &connectorv1.DirectoryEntry{ObjectGuid: toWire(member), Dn: targetEntryDN(rd.member, member)}
	if rd.inGroup {
		e.Attributes = []*connectorv1.Attribute{{Name: "memberOf", Complete: false,
			Values: []*connectorv1.AttributeValue{{Value: &connectorv1.AttributeValue_Text{Text: group.DN}}}}}
	}
	return e
}

func planGroupMember(ctx context.Context, a Authorised, req *connectorv1.PlanRequest, add bool) (*connectorv1.PlanResponse, error) {
	group, err := targetOf(req)
	if err != nil {
		return nil, invalid("1", "TargetRequired", "target.object")
	}
	member, cls, err := memberOfChange(req.GetChange(), add)
	if err != nil {
		return nil, invalid("1", "WriteChangeArmMismatch", "change")
	}
	var resp *connectorv1.PlanResponse
	err = run(ctx, a, func(tx *ad.Tx) *Refusal {
		rd, r := readMembership(tx, add, group, member, cls)
		if r != nil {
			return r
		}
		resp = &connectorv1.PlanResponse{TargetDn: targetEntryDN(rd.group, group), Observed: rd.obs, NoOp: rd.satisfied(add),
			Before:       memberEntry(rd, member, rd.group),
			Precondition: &connectorv1.TargetPrecondition{StateDigest: rd.dig, PlanObservedAt: timestamppb.Now()}}
		return nil
	})
	return resp, err
}

func applyGroupMember(ctx context.Context, a Authorised, req *connectorv1.ApplyRequest, add bool) (*connectorv1.ApplyResponse, error) {
	group, err := targetOf(req)
	if err != nil {
		return nil, invalid("1", "TargetRequired", "target.object")
	}
	member, cls, err := memberOfChange(req.GetChange(), add)
	if err != nil {
		return nil, invalid("1", "WriteChangeArmMismatch", "change")
	}
	var resp *connectorv1.ApplyResponse
	err = run(ctx, a, func(tx *ad.Tx) *Refusal {
		var r *Refusal
		resp, r = applyGroupMemberIn(tx, req.GetPrecondition(), add, group, member, cls)
		return r
	})
	return resp, err
}

func applyGroupMemberIn(tx groupTx, pre *connectorv1.TargetPrecondition, add bool, group, member guid.GUID, cls connectorv1.DirectoryObjectClass) (*connectorv1.ApplyResponse, *Refusal) {
	rd, r := readMembership(tx, add, group, member, cls)
	if r != nil {
		return nil, r
	}
	already := func(rd *memberRead) *connectorv1.ApplyResponse {
		return &connectorv1.ApplyResponse{Outcome: connectorv1.ApplyOutcome_APPLY_OUTCOME_ALREADY_APPLIED, Written: rd.obs,
			ReadBack: memberEntry(rd, member, rd.group)}
	}
	// Already in the target state: ALREADY_APPLIED, never TARGET_CHANGED, whoever changed it (CC-WK-49, 56).
	if rd.satisfied(add) {
		return already(rd), nil
	}
	if !bytes.Equal(pre.GetStateDigest(), rd.dig) {
		return nil, targetChanged("5")
	}
	mdn, merr := dn.Parse(rd.member.DN, dn.Strict)
	if merr != nil {
		return nil, invalid("5", "TargetRequired", "member")
	}
	target, terr := dn.GUIDRef(group).ForRequest() // the group is addressed by the GUID just read
	if terr != nil {
		return nil, invalid("5", "TargetRequired", "target.object")
	}
	change := ops.Change{Add: add, Name: "member", Values: []string{string(mdn.Render())}}
	if err := tx.Send(func(c ad.WriteConn) error { return ops.ModifyObject(c, target, []ops.Change{change}) }); err != nil {
		switch ad.CodeOf(err) {
		case ad.CodeConflict:
			// The DC refused a value already present (add) or absent (delete): a second writer got
			// there. ALREADY_APPLIED when the member's side confirms the target state, else changed.
			if again, rr := readMembership(tx, add, group, member, cls); rr == nil && again.satisfied(add) {
				return already(again), nil
			}
			return nil, targetChanged("5")
		case ad.CodeConstraint:
			return nil, invalid("5", "GroupScopeRule", "member")
		}
		return nil, fromDir(err)
	}
	after, rr := readMembership(tx, add, group, member, cls) // read-after-write on the same bound DC
	if rr != nil {
		return nil, rr
	}
	if !after.satisfied(add) {
		return nil, coded(connectorv1.ErrorCode_ERROR_CODE_PROVIDER_FAILURE, errNever, "8", "write not visible on the bound domain controller")
	}
	return &connectorv1.ApplyResponse{Outcome: connectorv1.ApplyOutcome_APPLY_OUTCOME_APPLIED, Written: rd.obs,
		ReadBack: memberEntry(after, member, after.group)}, nil
}
