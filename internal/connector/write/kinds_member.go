package write

import (
	"bytes"
	"context"
	"crypto/sha256"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/tier0"
	"github.com/skenzeriq/activediq/internal/connector/write/ops"
	"github.com/skenzeriq/activediq/internal/directory/accountkind"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/platform/operation/digest"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// Kinds 11 and 12 (contract §8.10.3, v1.6, T-1586): add a member to a group, remove one. The target is
// the GROUP; the member is a GUID resolved live, and the `member` value is built from the DN the
// directory returned for it, parsed and rendered by the DN type. The group's own `member` list is never
// read: membership is decided from the member's side (`memberOf`, `primaryGroupID`), so a group of
// 50,000 members is added to as cheaply as an empty one.

func init() {
	operations[connectorv1.WriteKind_WRITE_KIND_GROUP_MEMBER_ADD] = memberOp(true)
	operations[connectorv1.WriteKind_WRITE_KIND_GROUP_MEMBER_REMOVE] = memberOp(false)
}

func memberKey(add bool) string {
	if add {
		return accountkind.KeyGroupMemberAdd
	}
	return accountkind.KeyGroupMemberRemove
}

// memberRef is the member of a typed change: its GUID and the class the Action declared.
func memberRef(c *connectorv1.WriteChange) (guid.GUID, connectorv1.DirectoryObjectClass, error) {
	var g *connectorv1.Guid
	var cl connectorv1.DirectoryObjectClass
	switch x := c.GetChange().(type) {
	case *connectorv1.WriteChange_GroupMemberAdd:
		g, cl = x.GroupMemberAdd.GetMember(), x.GroupMemberAdd.GetMemberClass()
	case *connectorv1.WriteChange_GroupMemberRemove:
		g, cl = x.GroupMemberRemove.GetMember(), x.GroupMemberRemove.GetMemberClass()
	default:
		return guid.GUID{}, 0, errBadGUID
	}
	id, err := fromWire(g)
	return id, cl, err
}

func memberOp(add bool) WriteOp {
	key := memberKey(add)
	return WriteOp{
		Arm: func(c *connectorv1.WriteChange) bool {
			_, err := accountkind.GroupAttrsOf(key, c)
			return err == nil
		},
		// The group and the member: each needs its own CorrelationStatement and Tier-0 verdict.
		Touched: func(target guid.GUID, c *connectorv1.WriteChange) ([]guid.GUID, error) {
			m, _, err := memberRef(c)
			if err != nil {
				return nil, err
			}
			return []guid.GUID{target, m}, nil
		},
		// GROUP_MEMBERSHIP on a group: a group in a designated dynamic closure with a membership-based
		// rule refuses the write on either plane (§8.9).
		PropertyWrite: func(*connectorv1.WriteChange) (tier0.PropertyWrite, error) {
			return tier0.PropertyWrite{Plane: tier0.PlaneAD, Kind: tier0.WriteGroup, Op: tier0.OpGroupMembership}, nil
		},
		Digest: func(req *connectorv1.ApplyRequest) ([]byte, error) { return memberDigest(key, req) },
		Plan: func(ctx context.Context, a Authorised, req *connectorv1.PlanRequest) (*connectorv1.PlanResponse, error) {
			target, err := targetOf(req)
			if err != nil {
				return nil, invalid("5", "TargetRequired", "target.object")
			}
			m, cl, err := memberRef(req.GetChange())
			if err != nil {
				return nil, invalid("5", "MemberRequired", "change")
			}
			var resp *connectorv1.PlanResponse
			err = run(ctx, a, func(tx *ad.Tx) *Refusal {
				var r *Refusal
				resp, r = planMemberIn(a, tx, add, target, m, cl)
				return r
			})
			return resp, err
		},
		Apply: func(ctx context.Context, a Authorised, req *connectorv1.ApplyRequest) (*connectorv1.ApplyResponse, error) {
			target, err := targetOf(req)
			if err != nil {
				return nil, invalid("5", "TargetRequired", "target.object")
			}
			m, cl, err := memberRef(req.GetChange())
			if err != nil {
				return nil, invalid("5", "MemberRequired", "change")
			}
			var resp *connectorv1.ApplyResponse
			err = run(ctx, a, func(tx *ad.Tx) *Refusal {
				var r *Refusal
				resp, r = applyMemberIn(a, tx, add, target, m, cl, req.GetPrecondition())
				return r
			})
			return resp, err
		},
	}
}

// memberDigest recomputes the plan digest the server's step carries: the group is the target with the
// class label "group", and the member's GUID and class are digested attributes.
func memberDigest(key string, req *connectorv1.ApplyRequest) ([]byte, error) {
	obj, err := uuidText(req.GetTarget().GetObject())
	if err != nil {
		return nil, err
	}
	nc, err := uuidText(req.GetTarget().GetNcGuid())
	if err != nil {
		return nil, err
	}
	attrs, err := accountkind.GroupAttrsOf(key, req.GetChange())
	if err != nil {
		return nil, err
	}
	d := digest.Compute(key, accountkind.Target(req.GetConnection().GetConnectionId(), obj, accountkind.ClassGroup, nc), attrs)
	return d[:], nil
}

// memberTx is the part of *ad.Tx the member bodies use, so Plan and Apply have non-lab tests.
type memberTx interface {
	DCTime() (time.Time, error)
	Read(ref dn.ObjectRef, attrs []string) (*ad.Entry, error)
	Send(send func(ad.WriteConn) error) error
}

// memberRead is what Plan and Apply learn from the two live reads.
type memberRead struct {
	group, member *ad.Entry
	groupDN       dn.DN
	memberDN      dn.DN
	groupSID      sid.SID
	memberSID     sid.SID
	in            bool // the member is in the group (memberOf lists it, or it is the primary group)
	digest        []byte
}

var (
	groupAttrs  = []string{"objectClass", "objectSid", "groupType", "memberOf"}
	memberAttrs = []string{"objectClass", "objectSid", "primaryGroupID", "memberOf"}
)

// domainSuffix is the trailing run of DC= RDNs of a DN: the domain NC it lives in.
func domainSuffix(d dn.DN) string {
	r := d.RDNs()
	i := len(r)
	for i > 0 && strings.EqualFold(r[i-1].Type().String(), "DC") {
		i--
	}
	var parts []string
	for _, x := range r[i:] {
		parts = append(parts, strings.ToLower(x.Value()))
	}
	return strings.Join(parts, ",")
}

// readMember reads the group and the member live and applies every rule of §8.10.3 kinds 11 and 12 that
// needs no write. It is the whole of Plan, and Apply repeats it against the live state before the write.
func readMember(tx memberTx, add bool, target, member guid.GUID, declared connectorv1.DirectoryObjectClass) (*memberRead, *Refusal) {
	if add && target == member {
		return nil, invalid("5", "SelfMembership", "change")
	}
	g, err := tx.Read(dn.GUIDRef(target), groupAttrs)
	if err != nil {
		return nil, fromDir(err)
	}
	if cl, r := liveClass(g); r != nil || cl != connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_GROUP {
		return nil, invalid("5", "ClassNotAllowed", "target")
	}
	m, err := tx.Read(dn.GUIDRef(member), memberAttrs)
	if err != nil {
		return nil, fromDir(err)
	}
	live, r := liveClass(m)
	if r != nil || accountkind.MemberClassLabel(live) == "" {
		return nil, invalid("5", "ClassNotAllowed", "change")
	}
	if live != declared {
		return nil, invalid("5", "MemberClassMismatch", "change")
	}
	gd, gerr := dn.Parse(g.DN, dn.Strict)
	md, merr := dn.Parse(m.DN, dn.Strict)
	if gerr != nil || merr != nil {
		return nil, invalid("5", "TargetRequired", "target.object")
	}
	if domainSuffix(gd) != domainSuffix(md) {
		return nil, invalid("5", "CrossDomainMemberUnsupported", "change")
	}
	gs, serr := sidOf(g)
	if serr != nil {
		return nil, invalid("5", "UnreadableAttribute", "target")
	}
	// A contact has no objectSid (it is no security principal): it is identified by its GUID in the digest.
	var ms sid.SID
	msBytes := member[:]
	if live != connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_CONTACT {
		var merr2 error
		if ms, merr2 = sidOf(m); merr2 != nil {
			return nil, invalid("5", "UnreadableAttribute", "target")
		}
		msBytes = ms.Bytes()
	}
	grid, ok := gs.RID()
	if !ok {
		return nil, invalid("5", "UnreadableAttribute", "target")
	}
	primary := false
	if raw := m.Raw("primaryGroupID"); len(raw) == 1 {
		primary = string(raw[0]) == strconv.FormatUint(uint64(grid), 10)
	}
	if add && live == connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_GROUP {
		// The group already sits below the member: adding the member would close a loop.
		below, r := groupBelow(tx, g, md)
		if r != nil {
			return nil, r
		}
		if below {
			return nil, invalid("5", "NestingCycle", "change")
		}
	}
	if !add && primary {
		return nil, invalid("5", "PrimaryGroupMember", "change")
	}
	listed := false
	for _, v := range m.Raw("memberOf") {
		if d, err := dn.Parse(string(v), dn.Strict); err == nil && d.Equal(gd) {
			listed = true
			break
		}
	}
	in := listed || primary
	h := sha256.New()
	for _, p := range [][]byte{[]byte("adq-group-member/1"), gs.Bytes(), firstRaw(g, "groupType"), msBytes, []byte(strings.ToLower(declaredLabel(declared))),
		[]byte(strings.ToLower(md.Parent().String()))} {
		var n [8]byte
		for i := 0; i < 8; i++ {
			n[7-i] = byte(uint64(len(p)) >> (8 * i))
		}
		h.Write(n[:])
		h.Write(p)
	}
	return &memberRead{group: g, member: m, groupDN: gd, memberDN: md, groupSID: gs, memberSID: ms, in: in, digest: h.Sum(nil)}, nil
}

// nestingWalkLimit bounds the groups read to decide a nesting loop; past it the answer is unknown and the
// write is refused (UnreadableAttribute), never guessed.
const nestingWalkLimit = 256

// groupBelow reports whether the group sits (transitively) below the group named by member: it walks the
// group's memberOf upward, one read per distinct group, and stops at nestingWalkLimit. tokenGroups is not
// used: Samba does not compute it for group objects and Windows behaviour is unverified.
func groupBelow(tx memberTx, g *ad.Entry, member dn.DN) (bool, *Refusal) {
	seen := map[string]bool{}
	queue := []*ad.Entry{g}
	for len(queue) > 0 {
		e := queue[0]
		queue = queue[1:]
		for _, v := range e.Raw("memberOf") {
			pd, err := dn.Parse(string(v), dn.Strict)
			if err != nil {
				return false, invalid("5", "UnreadableAttribute", "target")
			}
			if pd.Equal(member) {
				return true, nil
			}
			key := strings.ToLower(pd.String())
			if seen[key] {
				continue
			}
			if len(seen) >= nestingWalkLimit {
				return false, invalid("5", "UnreadableAttribute", "target")
			}
			seen[key] = true
			pe, err := tx.Read(dn.DNRef(pd), []string{"memberOf"})
			if err != nil {
				return false, fromDir(err)
			}
			queue = append(queue, pe)
		}
	}
	return false, nil
}

func declaredLabel(c connectorv1.DirectoryObjectClass) string { return accountkind.MemberClassLabel(c) }

func firstRaw(e *ad.Entry, name string) []byte {
	if r := e.Raw(name); len(r) > 0 {
		return r[0]
	}
	return nil
}

func sidOf(e *ad.Entry) (sid.SID, error) {
	raw := e.Raw("objectSid")
	if len(raw) != 1 {
		return sid.SID{}, errBadGUID
	}
	return sid.FromBytes(raw[0])
}

func planMemberIn(a Authorised, tx memberTx, add bool, target, member guid.GUID, declared connectorv1.DirectoryObjectClass) (*connectorv1.PlanResponse, *Refusal) {
	obs, _, r := dcTimes(tx)
	if r != nil {
		return nil, r
	}
	obs.Dc = a.dcID()
	rd, r := readMember(tx, add, target, member, declared)
	if r != nil {
		return nil, r
	}
	return &connectorv1.PlanResponse{
		Observed: obs,
		TargetDn: targetEntryDN(rd.group, target),
		// No uSNChanged: another membership change on a busy group moves it, and a race on different
		// members must not fail (§8.10.3).
		Precondition: &connectorv1.TargetPrecondition{StateDigest: rd.digest},
		NoOp:         rd.in == add,
		Before:       &connectorv1.DirectoryEntry{ObjectGuid: toWire(member), Dn: targetEntryDN(rd.member, member)},
	}, nil
}

func applyMemberIn(a Authorised, tx memberTx, add bool, target, member guid.GUID, declared connectorv1.DirectoryObjectClass, pre *connectorv1.TargetPrecondition) (*connectorv1.ApplyResponse, *Refusal) {
	obs, _, r := dcTimes(tx)
	if r != nil {
		return nil, r
	}
	obs.Dc = a.dcID()
	rd, r := readMember(tx, add, target, member, declared)
	if r != nil {
		return nil, r
	}
	readBack := &connectorv1.DirectoryEntry{ObjectGuid: toWire(member), Dn: targetEntryDN(rd.member, member)}
	if rd.in == add {
		return &connectorv1.ApplyResponse{Outcome: connectorv1.ApplyOutcome_APPLY_OUTCOME_ALREADY_APPLIED, Written: obs, ReadBack: readBack}, nil
	}
	if !bytes.Equal(pre.GetStateDigest(), rd.digest) {
		return nil, targetChanged("5")
	}
	// The value is the member's DN as the directory returned it, parsed and rendered by the DN type.
	value := string(rd.memberDN.Render())
	groupRef, rerr := dn.DNRef(rd.groupDN).ForRequest()
	if rerr != nil {
		return nil, invalid("5", "TargetRequired", "target.object")
	}
	err := tx.Send(func(c ad.WriteConn) error {
		return ops.ModifyObject(c, groupRef, []ops.Change{{Add: add, Name: "member", Values: []string{value}}})
	})
	switch ad.CodeOf(err) {
	case "":
	case ad.CodeConflict:
		// The DC refused an add of a present value or a delete of an absent one: confirm from the
		// member's side on this DC, else it is a changed target.
		again, rr := readMember(tx, add, target, member, declared)
		if rr == nil && again.in == add {
			return &connectorv1.ApplyResponse{Outcome: connectorv1.ApplyOutcome_APPLY_OUTCOME_ALREADY_APPLIED, Written: obs, ReadBack: readBack}, nil
		}
		return nil, targetChanged("8")
	case ad.CodeConstraint:
		return nil, invalid("8", "GroupScopeRule", "change")
	default:
		return nil, fromDir(err)
	}
	after, rr := readMember(tx, add, target, member, declared)
	if rr != nil || after.in != add {
		return nil, coded(connectorv1.ErrorCode_ERROR_CODE_PROVIDER_FAILURE, errNever, "8", "write not visible on the bound domain controller")
	}
	obs.ReceivedAt = timestamppb.Now()
	return &connectorv1.ApplyResponse{Outcome: connectorv1.ApplyOutcome_APPLY_OUTCOME_APPLIED, Written: obs, ReadBack: &connectorv1.DirectoryEntry{ObjectGuid: toWire(member), Dn: targetEntryDN(after.member, member)}}, nil
}
