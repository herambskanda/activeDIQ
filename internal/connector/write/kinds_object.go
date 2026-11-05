package write

import (
	"bytes"
	"context"
	"crypto/sha256"
	"sort"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/tier0"
	"github.com/skenzeriq/activediq/internal/connector/write/ops"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/ldapfilter"
	"github.com/skenzeriq/activediq/internal/directory/writechange"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// ObjectDirectory is what kinds 1 to 3 need from the directory session; *ad.Session is the AD
// implementation. Every call of Do runs on the one DC the session is bound to.
type ObjectDirectory interface {
	Do(ctx context.Context, fn func(*ad.Tx) error) error
	EditableAttr(name string) (string, ldapfilter.Syntax, error)
}

// writeDirectory is implemented by a Provider that can run object writes.
type writeDirectory interface{ WriteDirectory() ObjectDirectory }

// The three object kinds (contract §8.10.3 kinds 1 to 3). Each row is registered together with its
// client kindTable row (internal/directory/client) and its writechange codec.
var (
	objectCreateOp = WriteOp{Touched: objectTouched, PropertyWrite: createPropertyWrite, Vet: vetCreate,
		Digest: objectDigest, Plan: planCreate, Apply: applyCreate}
	objectUpdateOp = WriteOp{Touched: objectTouched, PropertyWrite: updatePropertyWrite, Vet: vetUpdate,
		Digest: objectDigest, Plan: planUpdate, Apply: applyUpdate}
	objectDeleteOp = WriteOp{Touched: objectTouched, PropertyWrite: deletePropertyWrite,
		Digest: objectDigest, Plan: planDelete, Apply: applyDelete, RemovesTarget: true, TargetGone: targetDeleted}
)

func objectTouched(target guid.GUID, _ *connectorv1.WriteChange) ([]guid.GUID, error) {
	return []guid.GUID{target}, nil
}

// ---- declarations (derived from the typed change only) -------------------------------------------

func createPropertyWrite(c *connectorv1.WriteChange) (tier0.PropertyWrite, error) {
	oc := c.GetObjectCreate()
	k := tier0.WriteUser
	switch oc.GetObjectClass() {
	case connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_COMPUTER:
		k = tier0.WriteDevice
	case connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_GROUP, connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_ORGANIZATIONAL_UNIT:
		k = tier0.WriteGroup
	case connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_USER, connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_CONTACT: // a contact fails closed as a user
	default:
		return tier0.PropertyWrite{}, errBadChange
	}
	return tier0.PropertyWrite{Plane: tier0.PlaneAD, Kind: k, Op: tier0.OpCreate}, nil
}

func updatePropertyWrite(c *connectorv1.WriteChange) (tier0.PropertyWrite, error) {
	u := c.GetObjectUpdate()
	if u == nil {
		return tier0.PropertyWrite{}, errBadChange
	}
	pw := tier0.PropertyWrite{Plane: tier0.PlaneAD, Kind: tier0.WriteUser, Op: tier0.OpUpdate}
	for _, e := range u.GetEdits() {
		if strings.EqualFold(e.GetAttribute(), "manager") {
			pw.Op = tier0.OpSetManager
			if e.GetOp() == connectorv1.EditOp_EDIT_OP_CLEAR || e.GetOp() == connectorv1.EditOp_EDIT_OP_REMOVE_VALUE {
				pw.Op = tier0.OpClearManager
			}
			continue
		}
		pw.Keys = append(pw.Keys, e.GetAttribute())
	}
	if pw.Op == tier0.OpUpdate && len(pw.Keys) == 0 {
		return tier0.PropertyWrite{}, errBadChange
	}
	if pw.Op != tier0.OpUpdate {
		pw.Keys = nil // the manager op is checked here; the other keys are checked in the body (editsRecheck)
	}
	return pw, nil
}

func deletePropertyWrite(c *connectorv1.WriteChange) (tier0.PropertyWrite, error) {
	if c.GetObjectDelete() == nil {
		return tier0.PropertyWrite{}, errBadChange
	}
	return tier0.PropertyWrite{Plane: tier0.PlaneAD, Kind: tier0.WriteGroup, Op: tier0.OpUpdate}, nil
}

type constErr string

func (e constErr) Error() string { return string(e) }

const errBadChange = constErr("write: change does not match the kind")

// ---- the digest ---------------------------------------------------------------------------------

func objectDigest(req *connectorv1.ApplyRequest) ([]byte, error) {
	key, attrs, err := writechange.Encode(req.GetChange())
	if err != nil {
		return nil, err
	}
	tr := authority.TargetRef{Connection: req.GetConnection().GetConnectionId(), NC: authority.NamingContextID(guidText(req.GetTarget().GetNcGuid()))}
	obj := guidText(req.GetTarget().GetObject())
	switch key {
	case writechange.KeyObjectCreate:
		oc := req.GetChange().GetObjectCreate()
		tr.Class, tr.Parent, tr.RDN = writechange.ClassName(oc.GetObjectClass()), obj, oc.GetRdnValue()
	default:
		tr.GUID = obj
	}
	d := step.Compute(key, tr, attrs)
	return d[:], nil
}

// ---- common helpers -----------------------------------------------------------------------------

// run executes fn in one Tx on the bound DC and returns its refusal, or the mapped directory error.
func run(ctx context.Context, a Authorised, fn func(tx *ad.Tx) *Refusal) error {
	d := a.dir()
	if d == nil {
		return unsupported()
	}
	err := d.Do(ctx, func(tx *ad.Tx) error {
		if r := fn(tx); r != nil {
			return r
		}
		return nil
	})
	if err == nil {
		return nil
	}
	if r, ok := err.(*Refusal); ok {
		return r
	}
	return fromDir(err)
}

// fromDir maps a directory error to a fixed-text refusal; no DN, value or response text goes in it.
func fromDir(err error) *Refusal {
	switch ad.CodeOf(err) {
	case ad.CodeObjectNotFound:
		return coded(connectorv1.ErrorCode_ERROR_CODE_OBJECT_NOT_FOUND, errReplan, "5", "object not found")
	case ad.CodeInsufficientRights:
		return coded(connectorv1.ErrorCode_ERROR_CODE_INSUFFICIENT_RIGHTS, errOperator, "5", "insufficient rights")
	case ad.CodeConflict:
		return targetChanged("5")
	case ad.CodeEntryExists:
		return invalid("5", "NameInUse", "change")
	case ad.CodeNotLeaf:
		return invalid("5", "NotLeaf", "target")
	case ad.CodeConstraint:
		return invalid("5", "DirectoryRefused", "change")
	case ad.CodeAttributeNotAllowed, ad.CodeSecretAttribute:
		return attrNotAllowed("5")
	case ad.CodeUnreachable:
		return coded(connectorv1.ErrorCode_ERROR_CODE_UNREACHABLE_DC, errReplan, "5", "domain controller unreachable")
	}
	return coded(connectorv1.ErrorCode_ERROR_CODE_PROVIDER_FAILURE, connectorv1.RetryAdvice_RETRY_ADVICE_SAME_DC_AFTER_BACKOFF, "5", "directory failure")
}

var classByObjectClass = map[string]connectorv1.DirectoryObjectClass{
	"user":               connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_USER,
	"inetorgperson":      connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_USER,
	"computer":           connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_COMPUTER,
	"group":              connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_GROUP,
	"contact":            connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_CONTACT,
	"organizationalunit": connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_ORGANIZATIONAL_UNIT,
}

// liveClass is the class of an object read live: its most specific objectClass (the last value of the
// hierarchy), so a msDS-ManagedServiceAccount, whose chain contains computer, is not a computer.
func liveClass(e *ad.Entry) (connectorv1.DirectoryObjectClass, *Refusal) {
	oc := e.Raw("objectClass")
	if len(oc) == 0 {
		return 0, invalid("5", "ClassNotAllowed", "target")
	}
	c, ok := classByObjectClass[strings.ToLower(string(oc[len(oc)-1]))]
	if !ok {
		return 0, invalid("5", "ClassNotAllowed", "target")
	}
	return c, nil
}

func dcTimes(tx *ad.Tx) (*connectorv1.Observation, time.Time, *Refusal) {
	t, err := tx.DCTime()
	if err != nil {
		return nil, time.Time{}, fromDir(err)
	}
	return &connectorv1.Observation{DcTime: timestamppb.New(t), ReceivedAt: timestamppb.Now()}, t, nil
}

func usnOf(e *ad.Entry) (uint64, bool) {
	raw := e.Raw("uSNChanged")
	if len(raw) != 1 {
		return 0, false
	}
	n, err := strconv.ParseUint(string(raw[0]), 10, 64)
	return n, err == nil
}

func targetEntryDN(e *ad.Entry, g guid.GUID) *connectorv1.DnValue {
	return &connectorv1.DnValue{DisplayDn: e.DN, Guid: toWire(g)}
}

func hashParts(parts ...string) []byte {
	h := sha256.New()
	for _, p := range parts {
		var n [8]byte
		for i := 0; i < 8; i++ {
			n[7-i] = byte(uint64(len(p)) >> (8 * i))
		}
		h.Write(n[:])
		h.Write([]byte(p))
	}
	return h.Sum(nil)
}

// ---- edits (kind 2 and the initial attributes of kind 1) -----------------------------------------

type edit struct {
	name string
	syn  ldapfilter.Syntax
	op   connectorv1.EditOp
	vals []*connectorv1.EditValue
}

// prepareEdits vets edits without a directory call: limits, the deny-list (first, by canonical name,
// case-insensitively, by OID and by option), the schema, and the shape of each edit.
func prepareEdits(d ObjectDirectory, in []*connectorv1.AttributeEdit, createInitial bool) ([]edit, *Refusal) {
	if len(in) > maxEdits {
		return nil, limitExceeded("4")
	}
	for _, e := range in {
		if len(e.GetValues()) > maxEditValues {
			return nil, limitExceeded("4")
		}
	}
	if d == nil {
		return nil, unsupported()
	}
	out := make([]edit, 0, len(in))
	seen := map[string]bool{}
	for _, e := range in {
		base, opts := attrBase(e.GetAttribute())
		if opts || isDenied(base) {
			return nil, attrNotAllowed("4")
		}
		name, syn, err := d.EditableAttr(base)
		if err != nil || isDenied(name) {
			return nil, attrNotAllowed("4")
		}
		if seen[strings.ToLower(name)] {
			return nil, invalid("4", "DuplicateAttribute", "change")
		}
		seen[strings.ToLower(name)] = true
		switch e.GetOp() {
		case connectorv1.EditOp_EDIT_OP_CLEAR:
			if len(e.GetValues()) != 0 || createInitial {
				return nil, invalid("4", "EditShape", "change")
			}
		case connectorv1.EditOp_EDIT_OP_SET:
			if len(e.GetValues()) == 0 {
				return nil, invalid("4", "EditShape", "change")
			}
		case connectorv1.EditOp_EDIT_OP_ADD_VALUE, connectorv1.EditOp_EDIT_OP_REMOVE_VALUE:
			if len(e.GetValues()) == 0 || createInitial {
				return nil, invalid("4", "EditShape", "change")
			}
		default:
			return nil, invalid("4", "EditShape", "change")
		}
		for _, v := range e.GetValues() {
			if r := checkValue(syn, v); r != nil {
				return nil, r
			}
		}
		out = append(out, edit{name: name, syn: syn, op: e.GetOp(), vals: e.GetValues()})
	}
	return out, nil
}

func checkValue(syn ldapfilter.Syntax, v *connectorv1.EditValue) *Refusal {
	bad := invalid("4", "ValueSyntax", "change")
	switch syn {
	case ldapfilter.SynString:
		t, ok := v.GetValue().(*connectorv1.EditValue_Text)
		if !ok {
			return bad
		}
		if len(t.Text) > maxTextBytes {
			return limitExceeded("4")
		}
		if strings.IndexByte(t.Text, 0) >= 0 {
			return bad
		}
	case ldapfilter.SynInt32:
		if _, ok := v.GetValue().(*connectorv1.EditValue_Int32Value); !ok {
			return bad
		}
	case ldapfilter.SynInt64:
		if _, ok := v.GetValue().(*connectorv1.EditValue_Int64Value); !ok {
			return bad
		}
	case ldapfilter.SynBool:
		if _, ok := v.GetValue().(*connectorv1.EditValue_Boolean); !ok {
			return bad
		}
	case ldapfilter.SynGenTime:
		if t, ok := v.GetValue().(*connectorv1.EditValue_Time); !ok || t.Time.GetAt() == nil {
			return bad
		}
	case ldapfilter.SynDN:
		if r, ok := v.GetValue().(*connectorv1.EditValue_ObjectRef); !ok || len(r.ObjectRef.GetValue()) != 16 {
			return bad
		}
	case ldapfilter.SynOctet:
		o, ok := v.GetValue().(*connectorv1.EditValue_Octets)
		if !ok {
			return bad
		}
		if len(o.Octets) > maxOctetsLength {
			return limitExceeded("4")
		}
	default: // GUID and SID syntaxes have their own kinds
		return attrNotAllowed("4")
	}
	return nil
}

// wireValue is the LDAP string of a vetted value. An object reference is resolved to its live DN.
func wireValue(tx *ad.Tx, v *connectorv1.EditValue) (string, *Refusal) {
	switch x := v.GetValue().(type) {
	case *connectorv1.EditValue_Text:
		return x.Text, nil
	case *connectorv1.EditValue_Int32Value:
		return strconv.FormatInt(int64(x.Int32Value), 10), nil
	case *connectorv1.EditValue_Int64Value:
		return strconv.FormatInt(x.Int64Value, 10), nil
	case *connectorv1.EditValue_Boolean:
		if x.Boolean {
			return "TRUE", nil
		}
		return "FALSE", nil
	case *connectorv1.EditValue_Time:
		return ad.FormatGeneralizedTime(x.Time.GetAt().AsTime()), nil
	case *connectorv1.EditValue_Octets:
		return string(x.Octets), nil
	case *connectorv1.EditValue_ObjectRef:
		g, err := fromWire(x.ObjectRef)
		if err != nil {
			return "", invalid("5", "ValueSyntax", "change")
		}
		e, err := tx.Read(dn.GUIDRef(g), []string{"objectClass"})
		if err != nil {
			return "", fromDir(err)
		}
		return e.DN, nil
	}
	return "", invalid("5", "ValueSyntax", "change")
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if !strings.EqualFold(x[i], y[i]) && x[i] != y[i] {
			return false
		}
	}
	return true
}

func contains(set []string, v string) bool {
	for _, s := range set {
		if s == v || strings.EqualFold(s, v) && len(v) > 0 && strings.Contains(v, "=") { // DNs compare case-insensitively
			return true
		}
	}
	return false
}

func rawStrings(e *ad.Entry, name string) []string {
	var out []string
	for _, b := range e.Raw(name) {
		out = append(out, string(b))
	}
	return out
}

// modPlan is the compare-and-set built from the live values.
type modPlan struct {
	changes []ops.Change
	digest  []byte
}

func buildChanges(tx *ad.Tx, e *ad.Entry, cls connectorv1.DirectoryObjectClass, edits []edit) (*modPlan, *Refusal) {
	p := &modPlan{}
	parts := []string{cls.String()}
	for _, ed := range edits {
		for _, tr := range e.Truncated {
			if strings.EqualFold(tr, ed.name) {
				return nil, limitExceeded("5")
			}
		}
		old := rawStrings(e, ed.name)
		parts = append(parts, ed.name, strconv.Itoa(len(old)))
		parts = append(parts, old...)
		var vals []string
		for _, v := range ed.vals {
			s, r := wireValue(tx, v)
			if r != nil {
				return nil, r
			}
			vals = append(vals, s)
		}
		var del, add []string
		switch ed.op {
		case connectorv1.EditOp_EDIT_OP_SET:
			if !sameSet(old, vals) {
				del, add = old, vals
			}
		case connectorv1.EditOp_EDIT_OP_CLEAR:
			del = old
		case connectorv1.EditOp_EDIT_OP_ADD_VALUE:
			for _, v := range vals {
				if !contains(old, v) {
					add = append(add, v)
				}
			}
		case connectorv1.EditOp_EDIT_OP_REMOVE_VALUE:
			for _, v := range vals {
				if contains(old, v) {
					del = append(del, v)
				}
			}
		}
		if len(del) > 0 {
			p.changes = append(p.changes, ops.Change{Name: ed.name, Values: del})
		}
		if len(add) > 0 {
			p.changes = append(p.changes, ops.Change{Add: true, Name: ed.name, Values: add})
		}
	}
	p.digest = hashParts(parts...)
	return p, nil
}

func editNames(edits []edit) []string {
	out := []string{"objectClass", "uSNChanged"}
	for _, e := range edits {
		out = append(out, e.name)
	}
	return out
}

func attrValue(syn ldapfilter.Syntax, raw []byte) *connectorv1.AttributeValue {
	s := string(raw)
	switch syn {
	case ldapfilter.SynInt32:
		if n, err := strconv.ParseInt(s, 10, 32); err == nil {
			return &connectorv1.AttributeValue{Value: &connectorv1.AttributeValue_Int32Value{Int32Value: int32(n)}}
		}
	case ldapfilter.SynInt64:
		if n, err := strconv.ParseInt(s, 10, 64); err == nil {
			return &connectorv1.AttributeValue{Value: &connectorv1.AttributeValue_Int64Value{Int64Value: n}}
		}
	case ldapfilter.SynBool:
		return &connectorv1.AttributeValue{Value: &connectorv1.AttributeValue_Boolean{Boolean: strings.EqualFold(s, "TRUE")}}
	case ldapfilter.SynGenTime:
		if t, err := ad.ParseGeneralizedTime(s); err == nil {
			return &connectorv1.AttributeValue{Value: &connectorv1.AttributeValue_Time{Time: &connectorv1.TimeValue{Kind: &connectorv1.TimeValue_At{At: timestamppb.New(t)}}}}
		}
	case ldapfilter.SynDN:
		return &connectorv1.AttributeValue{Value: &connectorv1.AttributeValue_Dn{Dn: &connectorv1.DnValue{DisplayDn: s}}}
	case ldapfilter.SynOctet:
		return &connectorv1.AttributeValue{Value: &connectorv1.AttributeValue_Octets{Octets: append([]byte(nil), raw...)}}
	}
	return &connectorv1.AttributeValue{Value: &connectorv1.AttributeValue_Text{Text: s}}
}

func entryOf(e *ad.Entry, g guid.GUID, edits []edit) *connectorv1.DirectoryEntry {
	out := &connectorv1.DirectoryEntry{ObjectGuid: toWire(g), Dn: targetEntryDN(e, g)}
	for _, ed := range edits {
		if !e.Has(ed.name) {
			continue
		}
		a := &connectorv1.Attribute{Name: ed.name, Complete: true}
		for _, r := range e.Raw(ed.name) {
			a.Values = append(a.Values, attrValue(ed.syn, r))
		}
		out.Attributes = append(out.Attributes, a)
	}
	return out
}

func targetOf(req interface {
	GetTarget() *connectorv1.WriteTarget
}) (guid.GUID, error) {
	return fromWire(req.GetTarget().GetObject())
}

// editsRecheck repeats the §8.9 check for what the declaration at step 4 could not know: the other
// edits of a manager change, and the device kind for a computer.
func editsRecheck(ctx context.Context, a Authorised, cls connectorv1.DirectoryObjectClass, edits []edit, target guid.GUID) *Refusal {
	var other []string
	hasManager := false
	for _, e := range edits {
		if strings.EqualFold(e.name, "manager") {
			hasManager = true
			continue
		}
		other = append(other, e.name)
	}
	refuse := func() *Refusal { return tier0Refusal(toWire(target), []basis{tier0.Designated}, stConnectorSet, "5") }
	if len(other) > 0 && hasManager {
		if !a.checkProperty(ctx, tier0.PropertyWrite{Plane: tier0.PlaneAD, Kind: tier0.WriteUser, Op: tier0.OpUpdate, Keys: other}) {
			return refuse()
		}
	}
	if cls == connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_COMPUTER {
		keys := append([]string(nil), other...)
		if hasManager {
			keys = append(keys, "manager")
		}
		if len(keys) > 0 && !a.checkProperty(ctx, tier0.PropertyWrite{Plane: tier0.PlaneAD, Kind: tier0.WriteDevice, Op: tier0.OpUpdate, Keys: keys}) {
			return refuse()
		}
	}
	return nil
}

func vetUpdate(d ObjectDirectory, c *connectorv1.WriteChange) *Refusal {
	u := c.GetObjectUpdate()
	if u == nil {
		return invalid("4", "WriteChangeArmMismatch", "change")
	}
	_, r := prepareEdits(d, u.GetEdits(), false)
	return r
}

// ---- kind 2: OBJECT_UPDATE ----------------------------------------------------------------------

type updateRead struct {
	entry *ad.Entry
	cls   connectorv1.DirectoryObjectClass
	plan  *modPlan
	edits []edit
	obs   *connectorv1.Observation
	dct   time.Time
	usn   uint64
}

func readForUpdate(ctx context.Context, a Authorised, tx *ad.Tx, target guid.GUID, c *connectorv1.WriteChange) (*updateRead, *Refusal) {
	edits, r := prepareEdits(a.dir(), c.GetObjectUpdate().GetEdits(), false)
	if r != nil {
		return nil, r
	}
	e, err := tx.Read(dn.GUIDRef(target), editNames(edits))
	if err != nil {
		return nil, fromDir(err)
	}
	cls, r := liveClass(e)
	if r != nil {
		return nil, r
	}
	if r := editsRecheck(ctx, a, cls, edits, target); r != nil {
		return nil, r
	}
	obs, dct, r := dcTimes(tx)
	if r != nil {
		return nil, r
	}
	obs.Dc = a.dcID()
	plan, r := buildChanges(tx, e, cls, edits)
	if r != nil {
		return nil, r
	}
	usn, _ := usnOf(e)
	return &updateRead{entry: e, cls: cls, plan: plan, edits: edits, obs: obs, dct: dct, usn: usn}, nil
}

func planUpdate(ctx context.Context, a Authorised, req *connectorv1.PlanRequest) (*connectorv1.PlanResponse, error) {
	target, err := targetOf(req)
	if err != nil {
		return nil, invalid("5", "TargetRequired", "target.object")
	}
	var resp *connectorv1.PlanResponse
	err = run(ctx, a, func(tx *ad.Tx) *Refusal {
		u, r := readForUpdate(ctx, a, tx, target, req.GetChange())
		if r != nil {
			return r
		}
		usn := u.usn
		resp = &connectorv1.PlanResponse{TargetDn: targetEntryDN(u.entry, target), Observed: u.obs, Before: entryOf(u.entry, target, u.edits),
			NoOp:         len(u.plan.changes) == 0,
			Precondition: &connectorv1.TargetPrecondition{UsnChanged: &usn, StateDigest: u.plan.digest, PlanObservedAt: timestamppb.New(u.dct)}}
		return nil
	})
	return resp, err
}

func applyUpdate(ctx context.Context, a Authorised, req *connectorv1.ApplyRequest) (*connectorv1.ApplyResponse, error) {
	target, err := targetOf(req)
	if err != nil {
		return nil, invalid("5", "TargetRequired", "target.object")
	}
	var resp *connectorv1.ApplyResponse
	err = run(ctx, a, func(tx *ad.Tx) *Refusal {
		u, r := readForUpdate(ctx, a, tx, target, req.GetChange())
		if r != nil {
			return r
		}
		if len(u.plan.changes) == 0 {
			resp = &connectorv1.ApplyResponse{Outcome: connectorv1.ApplyOutcome_APPLY_OUTCOME_ALREADY_APPLIED, Written: u.obs, ReadBack: entryOf(u.entry, target, u.edits)}
			return nil
		}
		pre := req.GetPrecondition()
		if pre.UsnChanged == nil || *pre.UsnChanged != u.usn || !bytes.Equal(pre.GetStateDigest(), u.plan.digest) {
			return targetChanged("5")
		}
		ref, rerr := dn.GUIDRef(target).ForRequest()
		if rerr != nil {
			return invalid("5", "TargetRequired", "target.object")
		}
		if err := tx.Send(func(c ad.WriteConn) error { return ops.ModifyObject(c, ref, u.plan.changes) }); err != nil {
			return fromDir(err)
		}
		back, err := tx.Read(dn.GUIDRef(target), editNames(u.edits))
		if err != nil {
			return coded(connectorv1.ErrorCode_ERROR_CODE_PROVIDER_FAILURE, connectorv1.RetryAdvice_RETRY_ADVICE_NEVER, "5", "read-back failed after write")
		}
		usn, _ := usnOf(back)
		resp = &connectorv1.ApplyResponse{Outcome: connectorv1.ApplyOutcome_APPLY_OUTCOME_APPLIED, Written: u.obs, UsnChangedAfter: &usn, ReadBack: entryOf(back, target, u.edits)}
		return nil
	})
	return resp, err
}

// ---- kind 3: OBJECT_DELETE ----------------------------------------------------------------------

// targetDeleted is the step-7 exemption of kind 3: an object that the show-deleted read finds
// deleted cannot be classified, and nothing is written to it. Anything else stays a live-read failure.
func targetDeleted(ctx context.Context, d ObjectDirectory, id guid.GUID) bool {
	if d == nil {
		return false
	}
	deleted := false
	err := d.Do(ctx, func(tx *ad.Tx) error {
		e, err := tx.ReadDeleted(dn.GUIDRef(id), []string{"isDeleted"})
		if err == nil {
			deleted = strings.EqualFold(strings.Join(rawStrings(e, "isDeleted"), ""), "TRUE")
		}
		return err
	})
	return err == nil && deleted
}

type deleteRead struct {
	entry *ad.Entry
	obs   *connectorv1.Observation
	dct   time.Time
	usn   uint64
	dig   []byte
	gone  bool
}

func readForDelete(tx *ad.Tx, a Authorised, target guid.GUID) (*deleteRead, *Refusal) {
	obs, dct, r := dcTimes(tx)
	if r != nil {
		return nil, r
	}
	obs.Dc = a.dcID()
	if e, err := tx.ReadDeleted(dn.GUIDRef(target), []string{"isDeleted"}); err == nil && strings.EqualFold(strings.Join(rawStrings(e, "isDeleted"), ""), "TRUE") {
		return &deleteRead{entry: e, obs: obs, dct: dct, gone: true}, nil
	}
	e, err := tx.Read(dn.GUIDRef(target), []string{"objectClass", "uSNChanged"})
	if err != nil {
		return nil, fromDir(err)
	}
	cls, r := liveClass(e)
	if r != nil {
		return nil, r
	}
	kids, err := tx.HasChildren(dn.GUIDRef(target))
	if err != nil {
		return nil, fromDir(err)
	}
	if kids {
		return nil, invalid("5", "NotLeaf", "target")
	}
	usn, _ := usnOf(e)
	return &deleteRead{entry: e, obs: obs, dct: dct, usn: usn, dig: hashParts(cls.String(), e.DN)}, nil
}

func planDelete(ctx context.Context, a Authorised, req *connectorv1.PlanRequest) (*connectorv1.PlanResponse, error) {
	target, err := targetOf(req)
	if err != nil {
		return nil, invalid("5", "TargetRequired", "target.object")
	}
	var resp *connectorv1.PlanResponse
	err = run(ctx, a, func(tx *ad.Tx) *Refusal {
		d, r := readForDelete(tx, a, target)
		if r != nil {
			return r
		}
		usn := d.usn
		resp = &connectorv1.PlanResponse{TargetDn: targetEntryDN(d.entry, target), Observed: d.obs, NoOp: d.gone,
			Before:       &connectorv1.DirectoryEntry{ObjectGuid: toWire(target), Dn: targetEntryDN(d.entry, target)},
			Precondition: &connectorv1.TargetPrecondition{UsnChanged: &usn, StateDigest: d.dig, PlanObservedAt: timestamppb.New(d.dct)}}
		return nil
	})
	return resp, err
}

func applyDelete(ctx context.Context, a Authorised, req *connectorv1.ApplyRequest) (*connectorv1.ApplyResponse, error) {
	target, err := targetOf(req)
	if err != nil {
		return nil, invalid("5", "TargetRequired", "target.object")
	}
	var resp *connectorv1.ApplyResponse
	err = run(ctx, a, func(tx *ad.Tx) *Refusal {
		d, r := readForDelete(tx, a, target)
		if r != nil {
			return r
		}
		if d.gone {
			resp = &connectorv1.ApplyResponse{Outcome: connectorv1.ApplyOutcome_APPLY_OUTCOME_ALREADY_APPLIED, Written: d.obs,
				ReadBack: &connectorv1.DirectoryEntry{ObjectGuid: toWire(target), Dn: targetEntryDN(d.entry, target)}}
			return nil
		}
		pre := req.GetPrecondition()
		if pre.UsnChanged == nil || *pre.UsnChanged != d.usn || !bytes.Equal(pre.GetStateDigest(), d.dig) {
			return targetChanged("5")
		}
		live, perr := dn.Parse(d.entry.DN, dn.Strict)
		if perr != nil {
			return invalid("5", "TargetRequired", "target.object")
		}
		ref, rerr := dn.DNRef(live).ForRequest()
		if rerr != nil {
			return invalid("5", "TargetRequired", "target.object")
		}
		if err := tx.Send(func(c ad.WriteConn) error { return ops.DeleteObject(c, ref) }); err != nil {
			return fromDir(err)
		}
		resp = &connectorv1.ApplyResponse{Outcome: connectorv1.ApplyOutcome_APPLY_OUTCOME_APPLIED, Written: d.obs,
			ReadBack: &connectorv1.DirectoryEntry{ObjectGuid: toWire(target), Dn: targetEntryDN(d.entry, target)}}
		return nil
	})
	return resp, err
}
