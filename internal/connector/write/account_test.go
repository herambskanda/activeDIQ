package write

import (
	"context"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/tier0"
	"github.com/skenzeriq/activediq/internal/directory/accountkind"
	"github.com/skenzeriq/activediq/internal/directory/attr/unicodepwd"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/platform/operation/digest"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// fakeSession is the AccountSession of the unit tests. It is a fake of the DC's account state, not of
// the connector: the guard, the digest and the ops that build the Modify are the real ones, and the
// Modify is recorded as the LDAP request it is.
type fakeSession struct {
	calls   int
	state   ad.AccountState
	secure  bool
	sent    []*ldap.ModifyRequest
	stateFn func(*ad.AccountState)
}

func (f *fakeSession) DCIdentity(context.Context) (ad.DCIdentity, error) {
	f.calls++
	g, _ := fromWire(testDC().GetDsaGuid())
	return ad.DCIdentity{DSAGUID: g}, nil
}

func (f *fakeSession) ReadAccount(context.Context, dn.ObjectRef) (ad.AccountState, error) {
	f.calls++
	return f.state, nil
}

type recMod struct{ f *fakeSession }

func (m recMod) Modify(r *ldap.ModifyRequest) error {
	m.f.sent = append(m.f.sent, r)
	if m.f.stateFn != nil {
		m.f.stateFn(&m.f.state)
	}
	return nil
}

func (f *fakeSession) ModifyAccount(_ context.Context, _ dn.ObjectRef, check ad.AccountCheck, send ad.AccountSender, needSecure bool) error {
	f.calls++
	if needSecure && !f.secure {
		return ad.NewError(ad.CodeInsecure)
	}
	if err := check(f.state); err != nil {
		return err
	}
	return send(recMod{f}, "<GUID=x>", unicodepwd.SecureConn{})
}

type acctProv struct {
	*fakeProv
	s *fakeSession
}

func (p acctProv) AccountSession() AccountSession { return p.s }

func acctRig(t *testing.T, set map[string][]Basis, st ad.AccountState) (*rig, *fakeSession) {
	t.Helper()
	run := passRun(set)
	r := newRig(t, &run)
	r.prov.guard = &stubGuard{} // an allowing dynamic-group snapshot; nil would refuse every write (§8.9)
	fs := &fakeSession{state: st}
	var err error
	r.h, err = New(acctProv{r.prov, fs}, r.gate, WithRecorder(r.rec), WithClock(func() time.Time { return r.now }))
	if err != nil {
		t.Fatal(err)
	}
	return r, fs
}

func userState(id guidT, uac int32, lock int64) ad.AccountState {
	return ad.AccountState{GUID: id, Classes: []string{"top", "person", "organizationalPerson", "user"}, HasUAC: true, UAC: uac, LockoutTime: lock, USN: 100, PwdLastSet: 5}
}

var ncWire = toWire(mk(77))

func kindReqs(sp accountkind.Spec, id guidT, withSecret bool) (*connectorv1.PlanRequest, *connectorv1.ApplyRequest) {
	attrs := []digest.Attr(nil)
	var ch *connectorv1.WriteChange
	var err error
	if sp.Key == accountkind.KeyResetPassword {
		attrs = []digest.Attr{{Name: accountkind.AttrMustChange, Values: []string{"true"}}, {Name: accountkind.AttrSecret, Secret: true}}
	}
	if ch, err = accountkind.ChangeFromAttrs(sp.Key, attrs); err != nil {
		panic(err)
	}
	p := planReq(id, ctxFor(id))
	p.Kind, p.Change = sp.Kind, ch
	p.Target.NcGuid = ncWire
	a := applyReq(id, ctxFor(id))
	a.Kind, a.Change = sp.Kind, ch
	a.Target.NcGuid = ncWire
	if withSecret {
		a.SecretInput = &connectorv1.SecretValue{Material: []byte("Passw0rd!")}
	}
	a.PlanDigest = clientDigest(sp, a, attrs)
	return p, a
}

// clientDigest is what the server's step carries: digest.Compute over the canonical texts, the way
// client.Write checks it.
func clientDigest(sp accountkind.Spec, a *connectorv1.ApplyRequest, attrs []digest.Attr) []byte {
	obj, _ := uuidText(a.Target.Object)
	nc, _ := uuidText(a.Target.NcGuid)
	d := digest.Compute(sp.Key, accountkind.Target(connID, obj, sp.Classes[len(sp.Classes)-1], nc), attrs)
	return d[:]
}

// Acceptance 2 (T-1583): a tier0 target is refused for every one of the four kinds on both RPCs
// before the session is touched at all.
func TestAccountKindsTier0RefusedBeforeAnyDirectoryCall(t *testing.T) {
	id := mk(30)
	r, fs := acctRig(t, map[string][]Basis{id.String(): {tier0.C2}}, userState(id, 512, 0))
	for _, sp := range accountkind.Specs() {
		p, a := kindReqs(sp, id, sp.Key == accountkind.KeyResetPassword)
		_, err := r.h.Plan(context.Background(), p)
		wantTier0(t, err, connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_CONNECTOR_SET)
		_, err = r.h.Apply(context.Background(), a)
		wantTier0(t, err, connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_CONNECTOR_SET)
	}
	if fs.calls != 0 || len(fs.sent) != 0 {
		t.Fatalf("session touched %d times, %d modifies sent", fs.calls, len(fs.sent))
	}
}

// The connector recomputes the very digest the server's step carries, for every kind and class.
func TestAccountDigestAgreesWithServerFunction(t *testing.T) {
	id := mk(31)
	for _, sp := range accountkind.Specs() {
		_, a := kindReqs(sp, id, sp.Key == accountkind.KeyResetPassword)
		got, err := accountDigest(sp, a)
		if err != nil || string(got) != string(a.PlanDigest) {
			t.Errorf("%s: digest differs (%v)", sp.Key, err)
		}
		for _, cls := range sp.Classes { // either class label the kind allows verifies
			obj, _ := uuidText(a.Target.Object)
			nc, _ := uuidText(a.Target.NcGuid)
			attrs, _ := accountkind.AttrsOf(sp.Key, a.Change, a.SecretInput != nil)
			d := digest.Compute(sp.Key, accountkind.Target(connID, obj, cls, nc), attrs)
			a.PlanDigest = d[:]
			if g, _ := accountDigest(sp, a); string(g) != string(d[:]) {
				t.Errorf("%s/%s not verified", sp.Key, cls)
			}
		}
	}
}

func TestAccountEnableDisableUnlockWriteTheMinimalConditionalModify(t *testing.T) {
	id := mk(32)
	cases := []struct {
		key   string
		state ad.AccountState
		attr  string
		ops   []string // ldap change operations in order
		vals  [][]string
	}{
		{accountkind.KeyDisable, userState(id, 512, 0), "userAccountControl", []string{"delete", "add"}, [][]string{{"512"}, {"514"}}},
		{accountkind.KeyEnable, userState(id, 514, 0), "userAccountControl", []string{"delete", "add"}, [][]string{{"514"}, {"512"}}},
		{accountkind.KeyUnlock, userState(id, 512, 133), "lockoutTime", []string{"replace"}, [][]string{{"0"}}},
	}
	for _, c := range cases {
		sp, _ := accountkind.ByKey(c.key)
		r, fs := acctRig(t, nil, c.state)
		fs.stateFn = func(s *ad.AccountState) { // the DC applies the modify
			switch c.key {
			case accountkind.KeyDisable:
				s.UAC |= 2
			case accountkind.KeyEnable:
				s.UAC &^= 2
			default:
				s.LockoutTime = 0
			}
		}
		p, a := kindReqs(sp, id, false)
		pr, err := r.h.Plan(context.Background(), p)
		if err != nil || pr.GetNoOp() || len(pr.GetPrecondition().GetStateDigest()) != 32 {
			t.Fatalf("%s plan: %v %v %v", c.key, err, pr, connErr(t, err).GetTier0Refused())
		}
		a.Precondition = pr.Precondition
		resp, err := r.h.Apply(context.Background(), a)
		if err != nil || resp.GetOutcome() != connectorv1.ApplyOutcome_APPLY_OUTCOME_APPLIED {
			t.Fatalf("%s apply: %v %v", c.key, err, resp)
		}
		if len(fs.sent) != 1 || len(fs.sent[0].Changes) != len(c.ops) {
			t.Fatalf("%s: sent %v", c.key, fs.sent)
		}
		for i, ch := range fs.sent[0].Changes {
			op := map[uint]string{0: "add", 1: "delete", 2: "replace"}[ch.Operation]
			if op != c.ops[i] || ch.Modification.Type != c.attr || len(ch.Modification.Vals) != 1 || ch.Modification.Vals[0] != c.vals[i][0] {
				t.Errorf("%s change %d: %s %s %v", c.key, i, op, ch.Modification.Type, ch.Modification.Vals)
			}
		}
		// Repeat after success: nothing more is written.
		resp, err = r.h.Apply(context.Background(), a)
		if err != nil || resp.GetOutcome() != connectorv1.ApplyOutcome_APPLY_OUTCOME_ALREADY_APPLIED || len(fs.sent) != 1 {
			t.Errorf("%s repeat: %v %v", c.key, err, resp)
		}
		if pr, _ := r.h.Plan(context.Background(), p); !pr.GetNoOp() {
			t.Errorf("%s: plan after success is not a no-op", c.key)
		}
	}
}

func TestAccountApplyRefusesChangedTargetAndWrongClass(t *testing.T) {
	id := mk(33)
	sp, _ := accountkind.ByKey(accountkind.KeyDisable)
	r, fs := acctRig(t, nil, userState(id, 512, 0))
	p, a := kindReqs(sp, id, false)
	pr, _ := r.h.Plan(context.Background(), p)
	a.Precondition = pr.Precondition
	fs.state.UAC = 512 | 0x10000 // a second writer changed another bit between Plan and Apply
	_, err := r.h.Apply(context.Background(), a)
	if c := connErr(t, err).GetCode(); c != connectorv1.ErrorCode_ERROR_CODE_TARGET_CHANGED || len(fs.sent) != 0 {
		t.Fatalf("got %s, %d sent", c, len(fs.sent))
	}
	for name, classes := range map[string][]string{"group": {"top", "group"}, "gmsa": {"top", "computer", "msDS-GroupManagedServiceAccount"}} {
		fs.state = userState(id, 512, 0)
		fs.state.Classes = classes
		_, err = r.h.Plan(context.Background(), p)
		if ce := connErr(t, err); ce.GetRejectedInput().GetRuleId() != "ClassNotAllowed" {
			t.Errorf("%s: %v", name, ce)
		}
	}
	// A reset and an unlock are users only: a computer is ClassNotAllowed.
	for _, k := range []string{accountkind.KeyUnlock, accountkind.KeyResetPassword} {
		ks, _ := accountkind.ByKey(k)
		fs.state = userState(id, 4096, 5)
		fs.state.Classes = []string{"top", "person", "organizationalPerson", "user", "computer"}
		kp, _ := kindReqs(ks, id, k == accountkind.KeyResetPassword)
		_, err = r.h.Plan(context.Background(), kp)
		if ce := connErr(t, err); ce.GetRejectedInput().GetRuleId() != "ClassNotAllowed" {
			t.Errorf("%s on a computer: %v", k, ce)
		}
	}
}

// CC-WK-29: the arm and the secret presence are checked before any directory call.
func TestAccountArmAndSecretMismatchBeforeDirectoryCall(t *testing.T) {
	id := mk(34)
	r, fs := acctRig(t, nil, userState(id, 512, 5))
	unlock, _ := accountkind.ByKey(accountkind.KeyUnlock)
	disable, _ := accountkind.ByKey(accountkind.KeyDisable)
	reset, _ := accountkind.ByKey(accountkind.KeyResetPassword)

	_, a := kindReqs(unlock, id, false)
	_, other := kindReqs(disable, id, false)
	a.Change = other.Change
	_, err := r.h.Apply(context.Background(), a)
	expectRule(t, err, "WriteChangeArmMismatch")

	_, a = kindReqs(unlock, id, true) // secret on a kind that has none
	_, err = r.h.Apply(context.Background(), a)
	expectRule(t, err, "SecretInputMismatch")

	_, a = kindReqs(reset, id, false) // reset without its secret
	_, err = r.h.Apply(context.Background(), a)
	expectRule(t, err, "SecretInputMismatch")

	_, a = kindReqs(unlock, id, false) // digest of another payload
	a.PlanDigest = other.PlanDigest
	_, err = r.h.Apply(context.Background(), a)
	expectRule(t, err, "PlanDigestMismatch")
	if fs.calls != 0 {
		t.Fatalf("session touched %d times", fs.calls)
	}
}

func expectRule(t *testing.T, err error, rule string) {
	t.Helper()
	if ce := connErr(t, err); ce.GetCode() != connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT || ce.GetRejectedInput().GetRuleId() != rule {
		t.Fatalf("got %s %q, want %s", ce.GetCode(), ce.GetRejectedInput().GetRuleId(), rule)
	}
}

// A reset needs an encrypted, verified connection; without one nothing is built or sent.
func TestAccountResetNeedsSecureTransport(t *testing.T) {
	id := mk(35)
	reset, _ := accountkind.ByKey(accountkind.KeyResetPassword)
	r, fs := acctRig(t, nil, userState(id, 512, 0))
	p, a := kindReqs(reset, id, true)
	pr, err := r.h.Plan(context.Background(), p)
	if err != nil || pr.GetNoOp() {
		t.Fatalf("plan: %v", err)
	}
	a.Precondition = pr.Precondition
	_, err = r.h.Apply(context.Background(), a)
	if c := connErr(t, err).GetCode(); c != connectorv1.ErrorCode_ERROR_CODE_TRANSPORT_SECURITY || len(fs.sent) != 0 {
		t.Fatalf("got %s, %d sent", c, len(fs.sent))
	}
}

// The Entra provider has no account session: every one of the kinds is CAPABILITY_UNSUPPORTED there.
func TestAccountKindsUnsupportedWithoutSession(t *testing.T) {
	id := mk(36)
	run := passRun(nil)
	r := newRig(t, &run) // the fake provider is not an AccountProvider
	r.prov.guard = &stubGuard{}
	for _, sp := range accountkind.Specs() {
		p, _ := kindReqs(sp, id, false)
		_, err := r.h.Plan(context.Background(), p)
		if c := connErr(t, err).GetCode(); c != connectorv1.ErrorCode_ERROR_CODE_CAPABILITY_UNSUPPORTED {
			t.Errorf("%s: %s", sp.Key, c)
		}
	}
}

// deviceRuleGuard models a designated dynamic device group whose rule references
// device.accountEnabled: it refuses any declaration of userAccountControl as a device write.
type deviceRuleGuard struct{ seen []tier0.PropertyWrite }

func (g *deviceRuleGuard) CheckPropertyWrite(_ context.Context, w tier0.PropertyWrite) (tier0.DynamicRuleRefusal, error) {
	g.seen = append(g.seen, w)
	if w.Kind == tier0.WriteDevice {
		for _, k := range w.Keys {
			if k == "userAccountControl" {
				return tier0.DynamicRuleRefusal{Refused: true, Reason: tier0.ReasonDesignatedDynamicRule,
					Stage: tier0.StageConnectorSet, Op: w.Op, Keys: w.Keys}, nil
			}
		}
	}
	return tier0.DynamicRuleRefusal{}, nil
}

// Security review T-1583 finding 1: userAccountControl feeds device.accountEnabled too, so enabling or
// disabling a computer that a designated dynamic device group's rule depends on must be refused by the
// property guard before any directory call. Both the user and the device declarations are checked.
func TestAccountEnableDisableComputerRefusedByDeviceRule(t *testing.T) {
	id := mk(36)
	for _, key := range []string{accountkind.KeyEnable, accountkind.KeyDisable} {
		sp, _ := accountkind.ByKey(key)
		r, fs := acctRig(t, nil, userState(id, 4096, 0))
		g := &deviceRuleGuard{}
		r.prov.guard = g
		p, a := kindReqs(sp, id, false)
		_, err := r.h.Plan(context.Background(), p)
		wantTier0(t, err, connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_CONNECTOR_SET)
		_, err = r.h.Apply(context.Background(), a)
		wantTier0(t, err, connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_CONNECTOR_SET)
		if fs.calls != 0 || len(fs.sent) != 0 {
			t.Fatalf("%s: session touched %d times, %d modifies sent", key, fs.calls, len(fs.sent))
		}
		var user, device bool
		for _, w := range g.seen {
			user = user || w.Kind == tier0.WriteUser
			device = device || w.Kind == tier0.WriteDevice
		}
		if !user || !device {
			t.Fatalf("%s: guard saw user=%v device=%v declarations", key, user, device)
		}
	}
}
