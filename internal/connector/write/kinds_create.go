package write

import (
	"context"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/write/ops"
	"github.com/skenzeriq/activediq/internal/directory/attr/unicodepwd"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/writechange"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

const (
	ctUser     = connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_USER
	ctGroup    = connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_GROUP
	ctComputer = connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_COMPUTER
	ctContact  = connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_CONTACT
	ctOU       = connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_ORGANIZATIONAL_UNIT
)

// uacFor is the only userAccountControl a create ever sets (no other bit, contract §8.10.3).
func uacFor(c connectorv1.DirectoryObjectClass, enabled bool) (int32, bool) {
	switch {
	case c == ctUser && enabled:
		return 512, true
	case c == ctUser:
		return 514, true
	case c == ctComputer && enabled:
		return 4096, true
	case c == ctComputer:
		return 4098, true
	}
	return 0, false
}

// groupTypeFor derives groupType from the scope and the security flag; it is never an edit.
func groupTypeFor(s connectorv1.GroupScope, security bool) (int32, bool) {
	var v int32
	switch s {
	case connectorv1.GroupScope_GROUP_SCOPE_GLOBAL:
		v = 2
	case connectorv1.GroupScope_GROUP_SCOPE_DOMAIN_LOCAL:
		v = 4
	case connectorv1.GroupScope_GROUP_SCOPE_UNIVERSAL:
		v = 8
	default:
		return 0, false
	}
	if security {
		v |= -2147483648
	}
	return v, true
}

func vetCreate(d ObjectDirectory, c *connectorv1.WriteChange) *Refusal {
	_, r := vetCreateFields(d, c.GetObjectCreate())
	return r
}

// createPlanned is a vetted create.
type createPlanned struct {
	oc      *connectorv1.ObjectCreate
	edits   []edit
	rdnType dn.RDNType
	class   string // objectClass value
	sam     string
}

var ldapClass = map[connectorv1.DirectoryObjectClass]string{
	ctUser: "user", ctGroup: "group", ctComputer: "computer", ctContact: "contact", ctOU: "organizationalUnit",
}

func vetCreateFields(d ObjectDirectory, oc *connectorv1.ObjectCreate) (*createPlanned, *Refusal) {
	if oc == nil {
		return nil, invalid("4", "WriteChangeArmMismatch", "change")
	}
	if writechange.ClassName(oc.GetObjectClass()) == "" {
		return nil, invalid("4", "ClassNotAllowed", "change.object_class")
	}
	if oc.GetRdnValue() == "" {
		return nil, invalid("4", "RdnRequired", "change.rdn_value")
	}
	edits, r := prepareEdits(d, oc.GetInitial(), true)
	if r != nil {
		return nil, r
	}
	cls := oc.GetObjectClass()
	switch {
	case oc.GetHasSecretInput() && cls != ctUser:
		return nil, invalid("4", "SecretInputMismatch", "change.has_secret_input")
	case oc.GetAccountEnabled() && cls != ctUser && cls != ctComputer:
		return nil, invalid("4", "CreateFields", "change.account_enabled")
	case cls == ctUser && oc.GetAccountEnabled() && !oc.GetHasSecretInput():
		return nil, invalid("4", "EnabledNeedsPassword", "change.account_enabled")
	case cls == ctGroup:
		if _, ok := groupTypeFor(oc.GetGroupScope(), oc.GetGroupIsSecurity()); !ok {
			return nil, invalid("4", "CreateFields", "change.group_scope")
		}
	case oc.GetGroupScope() != connectorv1.GroupScope_GROUP_SCOPE_UNSPECIFIED || oc.GetGroupIsSecurity():
		return nil, invalid("4", "CreateFields", "change.group_scope")
	}
	p := &createPlanned{oc: oc, edits: edits, rdnType: dn.CN, class: ldapClass[cls]}
	if cls == ctOU {
		p.rdnType = dn.OU
	}
	for _, e := range edits {
		if e.op != connectorv1.EditOp_EDIT_OP_SET {
			return nil, invalid("4", "EditShape", "change")
		}
		if strings.EqualFold(e.name, "sAMAccountName") {
			if t, ok := e.vals[0].GetValue().(*connectorv1.EditValue_Text); ok {
				p.sam = t.Text
			}
		}
	}
	switch cls {
	case ctUser, ctGroup, ctComputer:
		if p.sam == "" {
			return nil, invalid("4", "CreateFields", "change.initial")
		}
	}
	if cls == ctComputer && !strings.HasSuffix(p.sam, "$") {
		return nil, invalid("4", "CreateFields", "change.initial")
	}
	return p, nil
}

// attrs are the AddRequest attributes in a fixed order; password is appended by the caller.
func (p *createPlanned) attrs(tx *ad.Tx) ([]ops.Attr, *Refusal) {
	oc := p.oc
	rdn := "cn"
	if p.rdnType == dn.OU {
		rdn = "ou"
	}
	out := []ops.Attr{{Name: "objectClass", Values: []string{p.class}}, {Name: rdn, Values: []string{oc.GetRdnValue()}}}
	for _, e := range p.edits {
		var vals []string
		for _, v := range e.vals {
			s, r := wireValue(tx, v)
			if r != nil {
				return nil, r
			}
			vals = append(vals, s)
		}
		out = append(out, ops.Attr{Name: e.name, Values: vals})
	}
	if v, ok := groupTypeFor(oc.GetGroupScope(), oc.GetGroupIsSecurity()); ok && oc.GetObjectClass() == ctGroup {
		out = append(out, ops.Attr{Name: "groupType", Values: []string{strconv.FormatInt(int64(v), 10)}})
	}
	if v, ok := uacFor(oc.GetObjectClass(), oc.GetAccountEnabled()); ok {
		out = append(out, ops.Attr{Name: "userAccountControl", Values: []string{strconv.FormatInt(int64(v), 10)}})
	}
	return out, nil
}

type createRead struct {
	parentDN dn.DN
	child    dn.DN
	existing *ad.Entry
	obs      *connectorv1.Observation
	dct      time.Time
	digest   []byte
}

func readForCreate(a Authorised, tx *ad.Tx, req interface {
	GetTarget() *connectorv1.WriteTarget
}, p *createPlanned) (*createRead, *Refusal) {
	parent, err := targetOf(req)
	if err != nil {
		return nil, invalid("5", "TargetRequired", "target.object")
	}
	pe, err := tx.Read(dn.GUIDRef(parent), []string{"objectClass"})
	if err != nil {
		return nil, fromDir(err)
	}
	pd, err := dn.Parse(pe.DN, dn.Strict)
	if err != nil {
		return nil, invalid("5", "TargetRequired", "target.object")
	}
	child, err := dn.Child(pd, p.rdnType, p.oc.GetRdnValue())
	if err != nil {
		return nil, invalid("5", "RdnInvalid", "change.rdn_value")
	}
	obs, dct, r := dcTimes(tx)
	if r != nil {
		return nil, r
	}
	obs.Dc = a.dcID()
	names := []string{"objectClass", "whenCreated", "groupType", "userAccountControl"}
	for _, e := range p.edits {
		names = append(names, e.name)
	}
	ex, err := tx.Read(dn.DNRef(child), names)
	switch ad.CodeOf(err) {
	case "":
	case ad.CodeObjectNotFound:
		ex = nil
	default:
		return nil, fromDir(err)
	}
	return &createRead{parentDN: pd, child: child, existing: ex, obs: obs, dct: dct,
		digest: hashParts(pe.DN, p.class, p.oc.GetRdnValue())}, nil
}

func planCreate(ctx context.Context, a Authorised, req *connectorv1.PlanRequest) (*connectorv1.PlanResponse, error) {
	p, r := vetCreateFields(a.dir(), req.GetChange().GetObjectCreate())
	if r != nil {
		return nil, r
	}
	var resp *connectorv1.PlanResponse
	err := run(ctx, a, func(tx *ad.Tx) *Refusal {
		c, r := readForCreate(a, tx, req, p)
		if r != nil {
			return r
		}
		if c.existing != nil { // Plan never adopts: anything at the name is NameInUse
			return invalid("5", "NameInUse", "change.rdn_value")
		}
		resp = &connectorv1.PlanResponse{Observed: c.obs, TargetDn: &connectorv1.DnValue{DisplayDn: c.child.String()},
			Precondition: &connectorv1.TargetPrecondition{StateDigest: c.digest, PlanObservedAt: timestamppb.New(c.dct)}}
		return nil
	})
	return resp, err
}

func applyCreate(ctx context.Context, a Authorised, req *connectorv1.ApplyRequest) (*connectorv1.ApplyResponse, error) {
	p, r := vetCreateFields(a.dir(), req.GetChange().GetObjectCreate())
	if r != nil {
		return nil, r
	}
	var resp *connectorv1.ApplyResponse
	err := run(ctx, a, func(tx *ad.Tx) *Refusal {
		c, r := readForCreate(a, tx, req, p)
		if r != nil {
			return r
		}
		pre := req.GetPrecondition()
		if c.existing != nil {
			if !p.matches(c.existing, tx) || pre.GetPlanObservedAt() == nil {
				return invalid("5", "NameInUse", "change.rdn_value")
			}
			wc, err := ad.ParseGeneralizedTime(strings.Join(rawStrings(c.existing, "whenCreated"), ""))
			if err != nil || wc.Before(pre.GetPlanObservedAt().AsTime()) {
				return invalid("5", "NameInUse", "change.rdn_value")
			}
			resp = &connectorv1.ApplyResponse{Outcome: connectorv1.ApplyOutcome_APPLY_OUTCOME_ALREADY_APPLIED, Written: c.obs}
			return p.fillBack(resp, tx, c)
		}
		if string(pre.GetStateDigest()) != string(c.digest) {
			return targetChanged("5")
		}
		attrs, r := p.attrs(tx)
		if r != nil {
			return r
		}
		var pw []byte
		if p.oc.GetHasSecretInput() {
			if !tx.Secure() {
				return transportSecurity("5")
			}
			mat := req.GetSecretInput().GetMaterial()
			s := secret.FromBytes(mat)
			enc, err := unicodepwd.Encode(s)
			(&s).Destroy()
			clear(mat)
			if err != nil {
				return invalid("5", "PasswordPolicy", "secret_input")
			}
			pw = enc
			attrs = append(attrs, ops.Attr{Name: "unicodePwd", Values: []string{string(enc)}})
		}
		dnText, err := dn.DNRef(c.child).ForRequest()
		if err != nil {
			return invalid("5", "RdnInvalid", "change.rdn_value")
		}
		err = tx.Send(func(w ad.WriteConn) error { return ops.AddObject(w, dnText, attrs) })
		clear(pw)
		if err != nil {
			if ad.CodeOf(err) == ad.CodeConstraint && p.oc.GetHasSecretInput() {
				return invalid("5", "PasswordPolicy", "secret_input")
			}
			return fromDir(err)
		}
		resp = &connectorv1.ApplyResponse{Outcome: connectorv1.ApplyOutcome_APPLY_OUTCOME_APPLIED, Written: c.obs}
		back, err2 := tx.Read(dn.DNRef(c.child), append([]string{"whenCreated", "groupType", "userAccountControl"}, editNamesOnly(p.edits)...))
		if err2 != nil {
			return coded(connectorv1.ErrorCode_ERROR_CODE_PROVIDER_FAILURE, connectorv1.RetryAdvice_RETRY_ADVICE_NEVER, "5", "read-back failed after write")
		}
		c.existing = back
		return p.fillBack(resp, tx, c)
	})
	return resp, err
}

func editNamesOnly(edits []edit) []string {
	var out []string
	for _, e := range edits {
		out = append(out, e.name)
	}
	return out
}

// fillBack sets read_back from the object found or created.
func (p *createPlanned) fillBack(resp *connectorv1.ApplyResponse, tx *ad.Tx, c *createRead) *Refusal {
	g, err := c.existing.GUID()
	if err != nil {
		return coded(connectorv1.ErrorCode_ERROR_CODE_PROVIDER_FAILURE, connectorv1.RetryAdvice_RETRY_ADVICE_NEVER, "5", "read-back failed after write")
	}
	resp.ReadBack = entryOf(c.existing, g, p.edits)
	usn, ok := usnOf(c.existing)
	if ok {
		resp.UsnChangedAfter = &usn
	}
	return nil
}

// matches is the ALREADY_APPLIED comparison: class, groupType and every planned initial value.
func (p *createPlanned) matches(e *ad.Entry, tx *ad.Tx) bool {
	if cls, r := liveClass(e); r != nil || cls != p.oc.GetObjectClass() {
		return false
	}
	if v, ok := groupTypeFor(p.oc.GetGroupScope(), p.oc.GetGroupIsSecurity()); ok && p.oc.GetObjectClass() == ctGroup {
		if strings.Join(rawStrings(e, "groupType"), "") != strconv.FormatInt(int64(v), 10) {
			return false
		}
	}
	// userAccountControl is compared exactly: an object carrying any bit beyond the one value a
	// create sets is not activeDIQ's own create and must not be reported ALREADY_APPLIED.
	if v, ok := uacFor(p.oc.GetObjectClass(), p.oc.GetAccountEnabled()); ok {
		if strings.Join(rawStrings(e, "userAccountControl"), "") != strconv.FormatInt(int64(v), 10) {
			return false
		}
	}
	for _, ed := range p.edits {
		var want []string
		for _, v := range ed.vals {
			s, r := wireValue(tx, v)
			if r != nil {
				return false
			}
			want = append(want, s)
		}
		if !sameSet(rawStrings(e, ed.name), want) {
			return false
		}
	}
	return true
}
