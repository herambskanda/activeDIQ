package write

import (
	"context"
	"crypto/sha256"
	"errors"
	"strconv"
	"strings"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/tier0"
	"github.com/skenzeriq/activediq/internal/connector/write/ops"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// The plan-digest keys of the object move, rename and restore kinds (contract §8.10.1) and the
// attribute names their digest covers. They are compile-time constants; directory/client holds the
// same strings and TestObjectKindsMatchClient pins the two.
const (
	DigestObjectMove    = "ad.object.move"
	DigestObjectRename  = "ad.object.rename"
	DigestObjectRestore = "ad.object.restore"

	AttrNewParent   = "newParent"
	AttrNewParentNC = "newParentNC"
	AttrNewRDN      = "newRDN"
	AttrRDN         = "rdn"
)

// ObjectDirectory is what the object kinds need from the directory. Every method acts on the one DC
// the provider's session is bound to (rule 5); Move, Rename and Restore re-check under the session
// lock and send exactly one write.
type ObjectDirectory interface {
	// State reads one object by GUID. With deleted set the show-deleted control is sent, and a
	// deleted object is returned with Deleted true.
	State(ctx context.Context, id guid.GUID, deleted bool) (ad.ObjectState, error)
	// RecycleBin reports whether the AD Recycle Bin is enabled for the forest.
	RecycleBin(ctx context.Context) (bool, error)
	Move(ctx context.Context, r ad.MoveRequest) error
	Rename(ctx context.Context, r ad.RenameRequest) error
	Restore(ctx context.Context, r ad.RestoreRequest) error
}

// ObjectProvider is a Provider that can reach the directory to write objects. The Entra provider
// and a test double without one answer CAPABILITY_UNSUPPORTED.
type ObjectProvider interface {
	Objects() ObjectDirectory
}

// SessionObjects is ObjectDirectory over an *ad.Session; the LDAP writes are the ops package's.
type SessionObjects struct{ S *ad.Session }

func (o SessionObjects) State(ctx context.Context, id guid.GUID, deleted bool) (ad.ObjectState, error) {
	return o.S.ObjectState(ctx, id, deleted)
}

func (o SessionObjects) Move(ctx context.Context, r ad.MoveRequest) error {
	return o.S.MoveObject(ctx, r, ops.ModifyDN)
}

func (o SessionObjects) Rename(ctx context.Context, r ad.RenameRequest) error {
	return o.S.RenameObject(ctx, r, ops.ModifyDN)
}

func (o SessionObjects) Restore(ctx context.Context, r ad.RestoreRequest) error {
	return o.S.RestoreObject(ctx, r, ops.Restore)
}

// RecycleBin reads msDS-EnabledFeature on CN=Partitions and looks for the Recycle Bin Feature. A
// directory that cannot answer (an attribute the schema lacks, an unreadable object) is "no": the
// restore is then CAPABILITY_UNSUPPORTED, never an attempt to reanimate a tombstone.
func (o SessionObjects) RecycleBin(ctx context.Context) (bool, error) {
	rd, err := o.S.RootDSE(ctx)
	if err != nil {
		return false, err
	}
	cfg, err := dn.Parse(rd.ConfigurationNamingContext, dn.Strict)
	if err != nil {
		return false, nil
	}
	parts, err := dn.Child(cfg, dn.CN, "Partitions")
	if err != nil {
		return false, nil
	}
	e, err := o.S.Read(ctx, dn.DNRef(parts), []string{"msDS-EnabledFeature"}, ad.ReadOptions{})
	if err != nil {
		if ad.CodeOf(err) == ad.CodeInvalidArgument || ad.CodeOf(err) == ad.CodeObjectNotFound {
			return false, nil
		}
		return false, err
	}
	for _, v := range e.Strings("msDS-EnabledFeature") {
		if strings.HasPrefix(strings.ToLower(v), "cn=recycle bin feature,") {
			return true, nil
		}
	}
	return false, nil
}

// Objects implements ObjectProvider when the directory and the bound DC are one session.
func (p *ADProvider) Objects() ObjectDirectory {
	var s *ad.Session
	switch d := p.Dir.(type) {
	case tier0.SessionDirectory:
		s = d.S
	case *tier0.SessionDirectory:
		if d != nil {
			s = d.S
		}
	}
	if s == nil || !p.OverSession(s) {
		return nil
	}
	return SessionObjects{S: s}
}

// objectClassOK reports whether the most specific objectClass is one of the kinds' classes
// (contract §8.10.1 class matrix). inetOrgPerson counts as user; a managed service account and
// every other class is "not in this slice".
func objectClassOK(classes []string) bool {
	if len(classes) == 0 {
		return false
	}
	switch strings.ToLower(classes[len(classes)-1]) {
	case "user", "inetorgperson", "group", "computer", "contact", "organizationalunit":
		return true
	}
	return false
}

func rdnTypeFor(classes []string) dn.RDNType {
	if len(classes) > 0 && strings.EqualFold(classes[len(classes)-1], "organizationalUnit") {
		return dn.OU
	}
	return dn.CN
}

func classNotAllowed() *Refusal { return invalid("5", "ClassNotAllowed", "target") }

// adRefusal maps a directory error to a connector refusal. No directory text goes into it.
func adRefusal(err error) error {
	var r *Refusal
	if errors.As(err, &r) {
		return err
	}
	switch ad.CodeOf(err) {
	case ad.CodeObjectNotFound:
		return newRefusal(connectorv1.ErrorCode_ERROR_CODE_OBJECT_NOT_FOUND, connectorv1.RetryAdvice_RETRY_ADVICE_AFTER_REPLAN, "5", "object not found")
	case ad.CodeInsufficientRights:
		return newRefusal(connectorv1.ErrorCode_ERROR_CODE_INSUFFICIENT_RIGHTS, connectorv1.RetryAdvice_RETRY_ADVICE_AFTER_OPERATOR_ACTION, "5", "insufficient rights")
	case ad.CodeTargetChanged:
		return newRefusal(connectorv1.ErrorCode_ERROR_CODE_TARGET_CHANGED, connectorv1.RetryAdvice_RETRY_ADVICE_AFTER_REPLAN, "5", "target changed since plan")
	case ad.CodeNameInUse:
		return invalid("5", "NameInUse", "change")
	case ad.CodeNotLeaf:
		return invalid("5", "NotLeaf", "change")
	case ad.CodeUnreachable, ad.CodeCanceled, ad.CodeUnexpectedReferral:
		return newRefusal(connectorv1.ErrorCode_ERROR_CODE_UNREACHABLE_DC, connectorv1.RetryAdvice_RETRY_ADVICE_AFTER_REPLAN, "5", "pinned domain controller unavailable")
	}
	return newRefusal(connectorv1.ErrorCode_ERROR_CODE_PROVIDER_FAILURE, connectorv1.RetryAdvice_RETRY_ADVICE_NEVER, "5", "directory failure")
}

func (a Authorised) objects() (ObjectDirectory, error) {
	if a.p == nil || a.p.dir == nil {
		return nil, unsupported()
	}
	return a.p.dir, nil
}

// ---- change extraction (the typed change, never a list the server sent) ----

func moveChange(c *connectorv1.WriteChange) (*connectorv1.ObjectMove, error) {
	m := c.GetObjectMove()
	if m == nil {
		return nil, errors.New("write: not an object_move change")
	}
	return m, nil
}

func newParentOf(t *connectorv1.WriteTarget) (guid.GUID, guid.GUID, error) {
	p, err := fromWire(t.GetObject())
	if err != nil {
		return guid.GUID{}, guid.GUID{}, err
	}
	nc, err := fromWire(t.GetNcGuid())
	if err != nil {
		return guid.GUID{}, guid.GUID{}, err
	}
	return p, nc, nil
}

// objectOps is the three rows of the operation table (contract §8.10.1 kinds 4 to 6).
func objectOps() map[connectorv1.WriteKind]WriteOp {
	return map[connectorv1.WriteKind]WriteOp{
		connectorv1.WriteKind_WRITE_KIND_OBJECT_MOVE:    moveOp(),
		connectorv1.WriteKind_WRITE_KIND_OBJECT_RENAME:  renameOp(),
		connectorv1.WriteKind_WRITE_KIND_OBJECT_RESTORE: restoreOp(),
	}
}

func moveOp() WriteOp {
	return WriteOp{
		Touched: func(_ guid.GUID, c *connectorv1.WriteChange) ([]guid.GUID, error) {
			m, err := moveChange(c)
			if err != nil {
				return nil, err
			}
			np, _, err := newParentOf(m.GetNewParent())
			if err != nil {
				return nil, err
			}
			return []guid.GUID{np}, nil
		},
		TouchedLive: func(ctx context.Context, d ObjectDirectory, target guid.GUID, _ *connectorv1.WriteChange) ([]guid.GUID, error) {
			st, err := d.State(ctx, target, false)
			if err != nil {
				return nil, err
			}
			if st.Parent == (guid.GUID{}) || st.Deleted {
				return nil, errors.New("write: no live parent")
			}
			return []guid.GUID{st.Parent}, nil // the old parent
		},
		PropertyWrite: func(c *connectorv1.WriteChange) (tier0.PropertyWrite, error) {
			if _, err := moveChange(c); err != nil {
				return tier0.PropertyWrite{}, err
			}
			return tier0.PropertyWrite{Plane: tier0.PlaneAD, Kind: tier0.WriteUser, Op: tier0.OpMoveOrRename, Keys: []string{"distinguishedName"}}, nil
		},
		Digest: func(req *connectorv1.ApplyRequest) ([]byte, error) {
			m, err := moveChange(req.GetChange())
			if err != nil {
				return nil, err
			}
			np, nc, err := newParentOf(m.GetNewParent())
			if err != nil {
				return nil, err
			}
			return objectDigest(DigestObjectMove, req.GetConnection(), req.GetTarget(), []step.Attr{
				{Name: AttrNewParent, Values: []string{np.String()}}, {Name: AttrNewParentNC, Values: []string{nc.String()}}})
		},
		Plan:  planMove,
		Apply: applyMove,
	}
}

func renameOp() WriteOp {
	get := func(c *connectorv1.WriteChange) (string, error) {
		r := c.GetObjectRename()
		if r == nil || r.GetNewRdnValue() == "" {
			return "", errors.New("write: not an object_rename change")
		}
		return r.GetNewRdnValue(), nil
	}
	return WriteOp{
		Touched: func(guid.GUID, *connectorv1.WriteChange) ([]guid.GUID, error) { return nil, nil },
		PropertyWrite: func(c *connectorv1.WriteChange) (tier0.PropertyWrite, error) {
			if _, err := get(c); err != nil {
				return tier0.PropertyWrite{}, err
			}
			return tier0.PropertyWrite{Plane: tier0.PlaneAD, Kind: tier0.WriteUser, Op: tier0.OpMoveOrRename, Keys: []string{"distinguishedName"}}, nil
		},
		Digest: func(req *connectorv1.ApplyRequest) ([]byte, error) {
			v, err := get(req.GetChange())
			if err != nil {
				return nil, err
			}
			return objectDigest(DigestObjectRename, req.GetConnection(), req.GetTarget(), []step.Attr{{Name: AttrNewRDN, Values: []string{v}}})
		},
		Plan:  planRename,
		Apply: applyRename,
	}
}

func restoreOp() WriteOp {
	get := func(c *connectorv1.WriteChange) (guid.GUID, guid.GUID, string, error) {
		r := c.GetObjectRestore()
		if r == nil || r.GetRdnValue() == "" {
			return guid.GUID{}, guid.GUID{}, "", errors.New("write: not an object_restore change")
		}
		np, nc, err := newParentOf(r.GetNewParent())
		return np, nc, r.GetRdnValue(), err
	}
	return WriteOp{
		DeletedTarget: true,
		Touched: func(_ guid.GUID, c *connectorv1.WriteChange) ([]guid.GUID, error) {
			np, _, _, err := get(c)
			if err != nil {
				return nil, err
			}
			return []guid.GUID{np}, nil
		},
		PropertyWrite: func(c *connectorv1.WriteChange) (tier0.PropertyWrite, error) {
			if _, _, _, err := get(c); err != nil {
				return tier0.PropertyWrite{}, err
			}
			// A restored object matches a dynamic rule by absence (contract §8.10.3 kind 6): CREATE.
			return tier0.PropertyWrite{Plane: tier0.PlaneAD, Kind: tier0.WriteUser, Op: tier0.OpCreate, Keys: []string{"distinguishedName"}}, nil
		},
		Digest: func(req *connectorv1.ApplyRequest) ([]byte, error) {
			np, nc, v, err := get(req.GetChange())
			if err != nil {
				return nil, err
			}
			return objectDigest(DigestObjectRestore, req.GetConnection(), req.GetTarget(), []step.Attr{
				{Name: AttrNewParent, Values: []string{np.String()}}, {Name: AttrNewParentNC, Values: []string{nc.String()}},
				{Name: AttrRDN, Values: []string{v}}})
		},
		Plan:  planRestore,
		Apply: applyRestore,
	}
}

// objectDigest is the digest the Action's step carries: the kinds put nothing in Class, Parent or
// RDN of the target; everything the write adds is an attribute.
func objectDigest(key string, conn *connectorv1.ConnectionRef, t *connectorv1.WriteTarget, attrs []step.Attr) ([]byte, error) {
	obj, err := fromWire(t.GetObject())
	if err != nil {
		return nil, err
	}
	nc, err := fromWire(t.GetNcGuid())
	if err != nil {
		return nil, err
	}
	d := step.Compute(key, authority.TargetRef{Connection: conn.GetConnectionId(), GUID: obj.String(), NC: authority.NamingContextID(nc.String())}, attrs)
	return d[:], nil
}

// ---- plan and apply ----

func stateDigest(parts ...string) []byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(strconv.Itoa(len(p)) + ":" + p))
	}
	return h.Sum(nil)
}

func precondition(st ad.ObjectState, digest []byte) *connectorv1.TargetPrecondition {
	pc := &connectorv1.TargetPrecondition{StateDigest: digest}
	if v := st.Entry.Strings("uSNChanged"); len(v) == 1 {
		if n, err := strconv.ParseUint(v[0], 10, 64); err == nil {
			pc.UsnChanged = &n
		}
	}
	return pc
}

// liveTarget reads and class-checks the target.
func liveTarget(ctx context.Context, d ObjectDirectory, id guid.GUID) (ad.ObjectState, error) {
	st, err := d.State(ctx, id, false)
	if err != nil {
		return st, adRefusal(err)
	}
	if st.Deleted || !objectClassOK(st.Entry.Strings("objectClass")) {
		return st, classNotAllowed()
	}
	return st, nil
}

// checkSameNC refuses a destination in another domain (CrossDomainMoveUnsupported): the new
// parent's naming context must be the target's.
func checkSameNC(target *connectorv1.WriteTarget, nc guid.GUID) error {
	t, err := fromWire(target.GetNcGuid())
	if err != nil || t != nc {
		return invalid("5", "CrossDomainMoveUnsupported", "change.new_parent.nc_guid")
	}
	return nil
}

func planMove(ctx context.Context, a Authorised, req *connectorv1.PlanRequest) (*connectorv1.PlanResponse, error) {
	d, err := a.objects()
	if err != nil {
		return nil, err
	}
	m, err := moveChange(req.GetChange())
	if err != nil {
		return nil, invalid("5", "WriteChangeArmMismatch", "change")
	}
	np, nc, err := newParentOf(m.GetNewParent())
	if err != nil {
		return nil, invalid("5", "TargetRequired", "change.new_parent")
	}
	if err := checkSameNC(req.GetTarget(), nc); err != nil {
		return nil, err
	}
	id, _ := fromWire(req.GetTarget().GetObject())
	st, err := liveTarget(ctx, d, id)
	if err != nil {
		return nil, err
	}
	resp := &connectorv1.PlanResponse{Precondition: precondition(st, stateDigest("move", id.String(), st.Parent.String(), np.String()))}
	resp.NoOp = st.Parent == np
	return resp, nil
}

func applyMove(ctx context.Context, a Authorised, req *connectorv1.ApplyRequest) (*connectorv1.ApplyResponse, error) {
	d, err := a.objects()
	if err != nil {
		return nil, err
	}
	m, _ := moveChange(req.GetChange())
	np, nc, err := newParentOf(m.GetNewParent())
	if err != nil {
		return nil, invalid("5", "TargetRequired", "change.new_parent")
	}
	if err := checkSameNC(req.GetTarget(), nc); err != nil {
		return nil, err
	}
	id, _ := fromWire(req.GetTarget().GetObject())
	st, err := liveTarget(ctx, d, id)
	if err != nil {
		return nil, err
	}
	if st.Parent == np {
		return &connectorv1.ApplyResponse{Outcome: connectorv1.ApplyOutcome_APPLY_OUTCOME_ALREADY_APPLIED}, nil
	}
	if !equalBytes(stateDigest("move", id.String(), st.Parent.String(), np.String()), req.GetPrecondition().GetStateDigest()) {
		return nil, adRefusal(ad.NewError(ad.CodeTargetChanged))
	}
	if err := d.Move(ctx, ad.MoveRequest{Object: id, ExpectParent: st.Parent, NewParent: np}); err != nil {
		return nil, adRefusal(err)
	}
	after, err := d.State(ctx, id, false)
	if err != nil || after.Parent != np {
		return nil, newRefusal(connectorv1.ErrorCode_ERROR_CODE_PROVIDER_FAILURE, connectorv1.RetryAdvice_RETRY_ADVICE_NEVER, "5", "read-back after write differs")
	}
	return &connectorv1.ApplyResponse{Outcome: connectorv1.ApplyOutcome_APPLY_OUTCOME_APPLIED}, nil
}

func rdnValueOf(st ad.ObjectState) string {
	if st.DN.Len() == 0 {
		return ""
	}
	return st.DN.RDNs()[0].Value()
}

func planRename(ctx context.Context, a Authorised, req *connectorv1.PlanRequest) (*connectorv1.PlanResponse, error) {
	d, err := a.objects()
	if err != nil {
		return nil, err
	}
	v := req.GetChange().GetObjectRename().GetNewRdnValue()
	if v == "" {
		return nil, invalid("5", "WriteChangeArmMismatch", "change")
	}
	id, _ := fromWire(req.GetTarget().GetObject())
	st, err := liveTarget(ctx, d, id)
	if err != nil {
		return nil, err
	}
	if _, err := dn.Child(dn.DN{}, st.DN.RDNs()[0].Type(), v); err != nil {
		return nil, invalid("5", "RdnInvalid", "change.new_rdn_value")
	}
	cur := rdnValueOf(st)
	return &connectorv1.PlanResponse{NoOp: cur == v, Precondition: precondition(st, stateDigest("rename", id.String(), st.Parent.String(), cur, v))}, nil
}

func applyRename(ctx context.Context, a Authorised, req *connectorv1.ApplyRequest) (*connectorv1.ApplyResponse, error) {
	d, err := a.objects()
	if err != nil {
		return nil, err
	}
	v := req.GetChange().GetObjectRename().GetNewRdnValue()
	id, _ := fromWire(req.GetTarget().GetObject())
	st, err := liveTarget(ctx, d, id)
	if err != nil {
		return nil, err
	}
	cur := rdnValueOf(st)
	if cur == v {
		return &connectorv1.ApplyResponse{Outcome: connectorv1.ApplyOutcome_APPLY_OUTCOME_ALREADY_APPLIED}, nil
	}
	if !equalBytes(stateDigest("rename", id.String(), st.Parent.String(), cur, v), req.GetPrecondition().GetStateDigest()) {
		return nil, adRefusal(ad.NewError(ad.CodeTargetChanged))
	}
	if err := d.Rename(ctx, ad.RenameRequest{Object: id, NewValue: v}); err != nil {
		return nil, adRefusal(err)
	}
	after, err := d.State(ctx, id, false)
	if err != nil || rdnValueOf(after) != v {
		return nil, newRefusal(connectorv1.ErrorCode_ERROR_CODE_PROVIDER_FAILURE, connectorv1.RetryAdvice_RETRY_ADVICE_NEVER, "5", "read-back after write differs")
	}
	return &connectorv1.ApplyResponse{Outcome: connectorv1.ApplyOutcome_APPLY_OUTCOME_APPLIED}, nil
}

// restoreState reads the object with the show-deleted control and decides what it is: a deleted
// object to restore, or one that is already live at the planned parent and RDN.
func restoreState(ctx context.Context, d ObjectDirectory, id, np guid.GUID, rdn string) (st ad.ObjectState, already bool, err error) {
	st, err = d.State(ctx, id, true)
	if err != nil {
		return st, false, adRefusal(err)
	}
	if !objectClassOK(st.Entry.Strings("objectClass")) {
		return st, false, classNotAllowed()
	}
	if !st.Deleted {
		if st.Parent == np && rdnValueOf(st) == rdn {
			return st, true, nil
		}
		return st, false, invalid("5", "NotDeleted", "target")
	}
	return st, false, nil
}

func planRestore(ctx context.Context, a Authorised, req *connectorv1.PlanRequest) (*connectorv1.PlanResponse, error) {
	d, err := a.objects()
	if err != nil {
		return nil, err
	}
	r := req.GetChange().GetObjectRestore()
	np, _, err := newParentOf(r.GetNewParent())
	if err != nil || r.GetRdnValue() == "" {
		return nil, invalid("5", "WriteChangeArmMismatch", "change")
	}
	on, err := d.RecycleBin(ctx)
	if err != nil {
		return nil, adRefusal(err)
	}
	if !on {
		return nil, unsupported() // reanimating a tombstone loses most attributes; not offered
	}
	id, _ := fromWire(req.GetTarget().GetObject())
	st, already, err := restoreState(ctx, d, id, np, r.GetRdnValue())
	if err != nil {
		return nil, err
	}
	if _, err := dn.Child(dn.DN{}, rdnTypeFor(st.Entry.Strings("objectClass")), r.GetRdnValue()); err != nil {
		return nil, invalid("5", "RdnInvalid", "change.rdn_value")
	}
	return &connectorv1.PlanResponse{NoOp: already, Precondition: precondition(st, stateDigest("restore", id.String(), np.String(), r.GetRdnValue()))}, nil
}

func applyRestore(ctx context.Context, a Authorised, req *connectorv1.ApplyRequest) (*connectorv1.ApplyResponse, error) {
	d, err := a.objects()
	if err != nil {
		return nil, err
	}
	r := req.GetChange().GetObjectRestore()
	np, _, err := newParentOf(r.GetNewParent())
	if err != nil {
		return nil, invalid("5", "WriteChangeArmMismatch", "change")
	}
	on, err := d.RecycleBin(ctx)
	if err != nil {
		return nil, adRefusal(err)
	}
	if !on {
		return nil, unsupported()
	}
	id, _ := fromWire(req.GetTarget().GetObject())
	st, already, err := restoreState(ctx, d, id, np, r.GetRdnValue())
	if err != nil {
		return nil, err
	}
	if already {
		return &connectorv1.ApplyResponse{Outcome: connectorv1.ApplyOutcome_APPLY_OUTCOME_ALREADY_APPLIED}, nil
	}
	if !equalBytes(stateDigest("restore", id.String(), np.String(), r.GetRdnValue()), req.GetPrecondition().GetStateDigest()) {
		return nil, adRefusal(ad.NewError(ad.CodeTargetChanged))
	}
	if err := d.Restore(ctx, ad.RestoreRequest{Object: id, NewParent: np, RDNType: rdnTypeFor(st.Entry.Strings("objectClass")), Value: r.GetRdnValue()}); err != nil {
		return nil, adRefusal(err)
	}
	after, err := d.State(ctx, id, true)
	if err != nil || after.Deleted || after.Parent != np || rdnValueOf(after) != r.GetRdnValue() {
		return nil, newRefusal(connectorv1.ErrorCode_ERROR_CODE_PROVIDER_FAILURE, connectorv1.RetryAdvice_RETRY_ADVICE_NEVER, "5", "read-back after write differs")
	}
	return &connectorv1.ApplyResponse{Outcome: connectorv1.ApplyOutcome_APPLY_OUTCOME_APPLIED}, nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// ClassifyDeleted is step 7 for the deleted target of OBJECT_RESTORE (contract §8.10.3 kind 6): a
// deleted object has no tokenGroups, so the connector classifies on a fixed read set. Anything it
// cannot read or decide is tier0.
//
//   - C1: a RID below 1000 (a built-in or well-known account);
//   - Designated: the target itself is customer-designated;
//   - C18: any sIDHistory value (history is a privilege path);
//   - C3: adminCount nonzero (the deleted object was a protected-group member);
//   - C5/C12: userAccountControl marks a DC/RODC or unconstrained delegation; primaryGroupID 516/521 is C5,
//     any primary group other than Domain Users, Guests and Computers is C2; a user or computer whose
//     userAccountControl or primaryGroupID cannot be read is unknown;
//   - C2: any retained memberOf group the live classifier calls tier0, or that is designated, or
//     that cannot be read;
//   - C3/C6: the last known parent, when it still exists, classifies as tier0.
func (p *ADProvider) ClassifyDeleted(ctx context.Context, id guid.GUID, designated []guid.GUID) (Verdict, error) {
	unknown := Verdict{Tier0: true}
	objs := p.Objects()
	if objs == nil {
		return unknown, ErrNoBoundDC
	}
	st, err := objs.State(ctx, id, true)
	if err != nil {
		return unknown, err
	}
	if !st.Deleted {
		return p.Classify(ctx, id, designated) // restored meanwhile: the ordinary live classification
	}
	return p.classifyDeletedEntry(ctx, id, st.Entry, designated)
}

// classifyDeletedEntry is the fixed-read-set decision over the deleted object's retained
// attributes; split out so the fail-closed branches are testable without a Recycle Bin.
func (p *ADProvider) classifyDeletedEntry(ctx context.Context, id guid.GUID, e *ad.Entry, designated []guid.GUID) (Verdict, error) {
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
	principal := classes["user"] || classes["computer"] || classes["group"]
	// Only an OU or a contact has no objectSid; an unknown class is treated as a security principal.
	needSID := principal || !(classes["organizationalunit"] || classes["contact"])
	if len(e.Truncated) > 0 {
		for _, n := range e.Truncated {
			if strings.EqualFold(n, "memberOf") {
				return unknown, errors.New("write: deleted object memberOf cut at the value ceiling")
			}
		}
	}
	sids, err := e.SIDs("objectSid")
	if err != nil {
		return unknown, err
	}
	if needSID && len(sids) == 0 { // a SID that cannot be read is unknown, never "not tier0"
		return unknown, errors.New("write: deleted object has no readable objectSid")
	}
	for _, s := range sids {
		if rid, ok := s.RID(); !ok || rid < 1000 {
			return Verdict{Tier0: true, Bases: []Basis{tier0.C1}}, nil
		}
	}
	if len(e.Raw("sIDHistory")) > 0 {
		return Verdict{Tier0: true, Bases: []Basis{tier0.C18}}, nil
	}
	// adminCount is set by SDProp on protected-group members and survives the delete (defence in depth).
	if n, has, err := e.Int32("adminCount"); err != nil {
		return unknown, err
	} else if has && n != 0 {
		return Verdict{Tier0: true, Bases: []Basis{tier0.C3}}, nil
	}
	if classes["user"] || classes["computer"] { // userAccountControl and primaryGroupID must be readable
		uac, has, err := e.Int32("userAccountControl")
		if err != nil {
			return unknown, err
		}
		if !has {
			return unknown, errors.New("write: deleted object has no readable userAccountControl")
		}
		if uac&(0x2000|0x4000000) != 0 { // DC or RODC computer
			return Verdict{Tier0: true, Bases: []Basis{tier0.C5}}, nil
		}
		if uac&0x80000 != 0 { // unconstrained delegation
			return Verdict{Tier0: true, Bases: []Basis{tier0.C12}}, nil
		}
		v := e.Strings("primaryGroupID")
		if len(v) != 1 {
			return unknown, errors.New("write: deleted object has no readable primaryGroupID")
		}
		switch v[0] {
		case "513", "514", "515":
		case "516", "521":
			return Verdict{Tier0: true, Bases: []Basis{tier0.C5}}, nil
		default:
			return Verdict{Tier0: true, Bases: []Basis{tier0.C2}}, nil
		}
	}
	des := map[guid.GUID]bool{}
	for _, g := range designated {
		des[g] = true
	}
	for _, m := range e.Strings("memberOf") {
		ref, err := dn.ParseObjectRef(m)
		if err != nil {
			return unknown, err
		}
		ge, err := p.Dir.Get(ctx, ref, []string{"objectGUID"})
		if err != nil {
			return Verdict{Tier0: true, Bases: []Basis{tier0.C2}}, nil
		}
		gid, err := ge.GUID()
		if err != nil {
			return unknown, err
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
		ref, err := dn.ParseObjectRef(v[0])
		if err != nil {
			return unknown, err
		}
		pe, err := p.Dir.Get(ctx, ref, []string{"objectGUID"})
		switch {
		case ad.CodeOf(err) == ad.CodeObjectNotFound: // the parent is gone: nothing to inherit
		case err != nil:
			return unknown, err
		default:
			pid, err := pe.GUID()
			if err != nil {
				return unknown, err
			}
			pv, err := p.Classify(ctx, pid, designated)
			if err != nil || pv.Tier0 {
				return Verdict{Tier0: true, Bases: []Basis{tier0.C3}}, nil
			}
		}
	}
	return Verdict{}, nil
}
