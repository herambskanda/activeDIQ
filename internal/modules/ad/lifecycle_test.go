package ad_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/directory/writechange"
	"github.com/skenzeriq/activediq/internal/modules/ad"
	"github.com/skenzeriq/activediq/internal/modules/objects"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

const (
	ouA     = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	ouB     = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	grpLive = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	grpDead = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
)

// dirFake is the object reader and writer the lifecycle Actions are tested against: a map of objects.
type dirFake struct {
	objs   map[string]client.ObjectState
	bin    bool
	writes []client.WriteOp
}

func newDir() *dirFake {
	return &dirFake{objs: map[string]client.ObjectState{
		ouA: {Exists: true, Class: "organizationalUnit"},
		ouB: {Exists: true, Class: "organizationalUnit"},
		obj: {Exists: true, Class: "user", Parent: ouA, RDN: "Ann Smith",
			Attrs: map[string][]string{"description": {"old"}, "memberOf": {"g1", "g2"}}},
	}, bin: true}
}

func (d *dirFake) Object(_ context.Context, _ authority.Pins, t authority.TargetRef, _ []string, deleted bool) (client.ObjectState, error) {
	st, ok := d.objs[t.GUID]
	if !ok || st.Deleted != deleted {
		return client.ObjectState{}, nil
	}
	return st, nil
}

func (d *dirFake) RecycleBin(context.Context, authority.Pins, authority.NamingContextID) (bool, error) {
	return d.bin, nil
}

func (d *dirFake) Write(_ context.Context, s step.Step, op client.WriteOp) (client.Result, error) {
	if step.Compute(op.DigestKind, op.Target, op.Attrs) != s.Digest() {
		return client.Result{}, client.ErrDigest
	}
	d.writes = append(d.writes, op)
	st := d.objs[op.Target.GUID]
	attr := func(n string) string {
		for _, a := range op.Attrs {
			if a.Name == n && len(a.Values) > 0 {
				return a.Values[0]
			}
		}
		return ""
	}
	switch op.DigestKind {
	case client.DigestObjectMove:
		st.Parent = attr(client.AttrNewParent)
	case client.DigestObjectRename:
		st.RDN = attr(client.AttrNewRDN)
	case writechange.KeyObjectDelete:
		delete(d.objs, op.Target.GUID)
		return client.Result{}, nil
	}
	d.objs[op.Target.GUID] = st
	return client.Result{}, nil
}

func lifeActions(t *testing.T, d *dirFake, defs ad.Definitions) map[operation.ActionID]operation.Action {
	t.Helper()
	as, err := ad.LifecycleActions(ad.LifecyclePorts{Reader: d, Writer: d, Definitions: defs})
	if err != nil {
		t.Fatal(err)
	}
	m := map[operation.ActionID]operation.Action{}
	for _, a := range as {
		m[a.Describe().ID] = a
	}
	return m
}

func plan1(t *testing.T, a operation.Action, in any) operation.StepPlan {
	t.Helper()
	steps, err := a.Plan(context.Background(), operation.PlanContext{Pins: pins(), Tx: &storetest.FakeTx{}}, input(t, in))
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if len(steps) != 1 {
		t.Fatalf("planned %d steps", len(steps))
	}
	return steps[0]
}

func planErr(a operation.Action, in operation.Input) error {
	_, err := a.Plan(context.Background(), operation.PlanContext{Pins: pins(), Tx: &storetest.FakeTx{}}, in)
	return err
}

// defsFake serves one Template and its two naming formats.
type defsFake struct{ tpl objects.Template }

func (f defsFake) Template(_ context.Context, _ store.Tx, ref ad.TemplateRef) (objects.Stored[objects.Template], error) {
	if ref.ID != "t1" {
		return objects.Stored[objects.Template]{}, objects.ErrNotFound
	}
	return objects.Stored[objects.Template]{ID: "t1", Version: 3, State: objects.StatePublished, Def: f.tpl}, nil
}

func (f defsFake) NamingFormat(_ context.Context, _ store.Tx, pin objects.Pin) (objects.Stored[objects.NamingFormat], error) {
	tok := func(a string, take int) objects.Token {
		return objects.Token{Kind: objects.TokenAttr, Attr: a, Take: take, Case: objects.CaseLower}
	}
	var nf objects.NamingFormat
	switch pin.ID {
	case "sam":
		nf = objects.NamingFormat{Name: "sam", Purpose: objects.PurposeSAMAccountName, Alternatives: []objects.Alternative{{Tokens: []objects.Token{tok("givenName", 1), tok("sn", 0)}}}}
	case "cn":
		nf = objects.NamingFormat{Name: "cn", Purpose: objects.PurposeCN, Alternatives: []objects.Alternative{{Tokens: []objects.Token{
			{Kind: objects.TokenAttr, Attr: "givenName"}, {Kind: objects.TokenLiteral, Literal: " "}, {Kind: objects.TokenAttr, Attr: "sn"}}}}}
	}
	return objects.Stored[objects.NamingFormat]{ID: pin.ID, Version: pin.Version, State: objects.StateActive, Def: nf}, nil
}

func userTemplate() objects.Template {
	return objects.Template{
		Name: "Staff", Kind: objects.KindUser, Provider: objects.ProviderAD, Purpose: objects.PurposeCreate,
		Fields: []objects.FieldRule{
			{Attribute: "givenName", Mode: objects.ModeEditable, Mandatory: true},
			{Attribute: "sn", Mode: objects.ModeEditable, Mandatory: true},
			{Attribute: "department", Mode: objects.ModeReadOnly, Default: "IT"},
		},
		NamingFormats: map[objects.NamePurpose]objects.Pin{
			objects.PurposeSAMAccountName: {ID: "sam", Version: 1}, objects.PurposeCN: {ID: "cn", Version: 1},
		},
	}
}

func createIn(attrs map[string]string) ad.CreateInput {
	return ad.CreateInput{ConnectionID: conn, NamingContext: nc, ParentGuid: ouA, Template: &ad.TemplateRef{ID: "t1"}, Attributes: attrs, Enabled: true}
}

// AC1: a Template-driven create shows every attribute the Template sets, the planned parent and RDN,
// and is Reversible; the plan's attributes decode to the very change the connector would apply.
func TestCreatePlanShowsTemplateAttributes(t *testing.T) {
	d := newDir()
	act := lifeActions(t, d, defsFake{userTemplate()})[ad.CreateID]
	if dd := act.Describe(); !dd.SecretInput || dd.Permission != ad.PermCreate {
		t.Fatalf("descriptor %+v", dd)
	}
	sp := plan1(t, act, createIn(map[string]string{"givenName": "Ann", "sn": "Smith"}))
	if sp.Reversibility != operation.Reversible || sp.Kind != writechange.KeyObjectCreate || !sp.Credential {
		t.Fatalf("plan %+v", sp)
	}
	if sp.Target.Parent != ouA || sp.Target.RDN != "Ann Smith" || sp.Target.Class != "user" || sp.Target.GUID != "" {
		t.Fatalf("target %+v", sp.Target)
	}
	got := map[string]string{}
	for _, c := range sp.Diff {
		if len(c.After) == 1 {
			got[c.Attribute] = c.After[0]
		}
	}
	for k, v := range map[string]string{
		"set:sAMAccountName": "s:asmith", "set:givenName": "s:Ann", "set:sn": "s:Smith", "set:department": "s:IT",
		"~rdn": "Ann Smith", "~enabled": "true", "~class": "user",
	} {
		if got[k] != v {
			t.Errorf("diff %s = %q, want %q (diff %+v)", k, got[k], v, sp.Diff)
		}
	}
	if !slices.ContainsFunc(sp.Diff, func(c operation.Change) bool { return c.Attribute == "~secret" && c.Secret && len(c.After) == 0 }) {
		t.Errorf("no secret presence in diff: %+v", sp.Diff)
	}
	var attrs []step.Attr
	for _, c := range sp.Diff {
		attrs = append(attrs, step.Attr{Name: c.Attribute, Values: c.After, Secret: c.Secret})
	}
	if _, err := writechange.Decode(sp.Kind, attrs); err != nil {
		t.Fatalf("the plan's attributes do not decode: %v", err)
	}
}

func TestCreateRefusals(t *testing.T) {
	d := newDir()
	act := lifeActions(t, d, defsFake{userTemplate()})[ad.CreateID]
	cases := map[string]struct {
		in   ad.CreateInput
		want string
	}{
		"mandatory field missing": {createIn(map[string]string{"givenName": "Ann"}), "sn"},
		"read-only field changed": {createIn(map[string]string{"givenName": "Ann", "sn": "S", "department": "HR"}), "department"},
		"sign-in attribute":       {createIn(map[string]string{"givenName": "Ann", "sn": "S", "userAccountControl": "512"}), "attribute_not_allowed"},
		"unknown template":        {ad.CreateInput{ConnectionID: conn, NamingContext: nc, ParentGuid: ouA, Template: &ad.TemplateRef{ID: "zz"}}, "template_refused"},
		"parent not a container":  {ad.CreateInput{ConnectionID: conn, NamingContext: nc, ParentGuid: obj, Attributes: map[string]string{"cn": "X", "sAMAccountName": "x"}}, "parent_not_a_container"},
		"no sam, no template":     {ad.CreateInput{ConnectionID: conn, NamingContext: nc, ParentGuid: ouA, Attributes: map[string]string{"cn": "X"}}, "sAMAccountName"},
	}
	for name, tc := range cases {
		err := planErr(act, input(t, tc.in))
		if !errors.Is(err, operation.ErrInvalid) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A container outside the template's allowed list.
	tpl := userTemplate()
	tpl.AllowedContainers = []string{ouB}
	err := planErr(lifeActions(t, d, defsFake{tpl})[ad.CreateID], input(t, createIn(map[string]string{"givenName": "A", "sn": "S"})))
	if !errors.Is(err, operation.ErrInvalid) || !strings.Contains(err.Error(), "container") {
		t.Errorf("container: %v", err)
	}
	// A Tier-0 parent is denied.
	d.objs[ouB] = client.ObjectState{Exists: true, Class: "organizationalUnit", Tier0: true}
	in := createIn(map[string]string{"givenName": "A", "sn": "S"})
	in.ParentGuid = ouB
	if err := planErr(lifeActions(t, d, defsFake{userTemplate()})[ad.CreateID], input(t, in)); !errors.Is(err, operation.ErrDenied) {
		t.Errorf("tier0 parent: %v", err)
	}
}

func TestUpdatePlansOnlyRealChangesAndRefusesSignInAttributes(t *testing.T) {
	d := newDir()
	act := lifeActions(t, d, nil)[ad.UpdateID]
	sp := plan1(t, act, ad.UpdateInput{Target: target(), Set: map[string]string{"description": "new", "title": "Dev"}})
	if len(sp.Diff) != 2 || sp.Reversibility != operation.Reversible {
		t.Fatalf("plan %+v", sp)
	}
	for _, c := range sp.Diff {
		if c.Attribute == "set:description" && (c.Before[0] != "old" || c.After[0] != "s:new") {
			t.Errorf("description change %+v", c)
		}
	}
	// Setting the value it already has is no step.
	steps, err := act.Plan(context.Background(), operation.PlanContext{Pins: pins()}, input(t, ad.UpdateInput{Target: target(), Set: map[string]string{"description": "old"}}))
	if err != nil || len(steps) != 0 {
		t.Fatalf("unchanged update: %v %d", err, len(steps))
	}
	for _, bad := range []string{"userAccountControl", "sAMAccountName", "userPrincipalName", "unicodePwd", "memberOf", "primaryGroupID", "nTSecurityDescriptor", "pwdLastSet"} {
		err := planErr(act, input(t, ad.UpdateInput{Target: target(), Set: map[string]string{bad: "1"}}))
		if !errors.Is(err, operation.ErrInvalid) {
			t.Errorf("%s accepted: %v", bad, err)
		}
	}
}

func TestMoveRenamePlanAndInverse(t *testing.T) {
	d := newDir()
	acts := lifeActions(t, d, nil)
	sp := plan1(t, acts[ad.MoveID], ad.MoveInput{Target: target(), NewParentGuid: ouB})
	if sp.Kind != client.DigestObjectMove || sp.Target.Class != "" || sp.Target.Parent != "" || sp.Reversibility != operation.Reversible {
		t.Fatalf("move plan %+v", sp)
	}
	if sp.Diff[0].Before[0] != ouA || sp.Diff[0].After[0] != ouB {
		t.Fatalf("move diff %+v", sp.Diff)
	}
	touched := acts[ad.MoveID].(operation.Toucher).Touched(sp)
	also := acts[ad.MoveID].(operation.AlsoAuthorizer).AlsoAuthorize(sp)
	if len(touched) != 2 || len(also) != 1 || also[0].GUID != ouB || also[0].NC != nc {
		t.Fatalf("touched %+v also %+v", touched, also)
	}
	in, err := acts[ad.MoveID].Inverse(sp, operation.Outcome{Payload: []byte(`{}`)})
	if err != nil || !strings.Contains(string(in), ouA) {
		t.Fatalf("inverse %s %v", in, err)
	}
	// Same parent: nothing to do. Non-container destination: refused.
	if steps, err := acts[ad.MoveID].Plan(context.Background(), operation.PlanContext{Pins: pins()}, input(t, ad.MoveInput{Target: target(), NewParentGuid: ouA})); err != nil || len(steps) != 0 {
		t.Fatalf("same-parent move: %v %d", err, len(steps))
	}
	if err := planErr(acts[ad.MoveID], input(t, ad.MoveInput{Target: target(), NewParentGuid: obj})); !errors.Is(err, operation.ErrInvalid) {
		t.Fatalf("move into a user: %v", err)
	}
	// Rename: the new name is a value; commas and Unicode are fine, control characters are not.
	sp = plan1(t, acts[ad.RenameID], ad.RenameInput{Target: target(), NewName: "Smith, Ann Ü"})
	if sp.Kind != client.DigestObjectRename || sp.Diff[0].Before[0] != "Ann Smith" || sp.Diff[0].After[0] != "Smith, Ann Ü" {
		t.Fatalf("rename plan %+v", sp)
	}
	for _, bad := range []string{"", " x", "a\x00b", strings.Repeat("x", 65)} {
		if err := planErr(acts[ad.RenameID], input(t, ad.RenameInput{Target: target(), NewName: bad})); !errors.Is(err, operation.ErrInvalid) {
			t.Errorf("name %q accepted: %v", bad, err)
		}
	}
}

func TestDeleteClassFollowsRecycleBin(t *testing.T) {
	d := newDir()
	act := lifeActions(t, d, nil)[ad.DeleteID]
	if act.Describe().Reversibility != operation.Irreversible {
		t.Fatal("descriptor worst case must be Irreversible")
	}
	if sp := plan1(t, act, ad.DeleteInput{Target: target()}); sp.Reversibility != operation.Lossy || sp.Kind != writechange.KeyObjectDelete || len(sp.Diff) != 0 {
		t.Fatalf("with bin: %+v", sp)
	}
	d.bin = false
	if sp := plan1(t, act, ad.DeleteInput{Target: target()}); sp.Reversibility != operation.Irreversible {
		t.Fatalf("without bin: %+v", sp)
	}
	d.objs[obj] = client.ObjectState{Exists: true, Class: "user", Tier0: true}
	if err := planErr(act, input(t, ad.DeleteInput{Target: target()})); !errors.Is(err, operation.ErrDenied) {
		t.Fatalf("tier0 delete: %v", err)
	}
}

// AC3 (fake directory; the lab proof is T-1585's follow-up): restore reports the link values that
// stay dormant, by name, and is Lossy exactly then.
func TestRestorePlanListsLinkValues(t *testing.T) {
	d := newDir()
	d.objs[obj] = client.ObjectState{Exists: true, Class: "user", Deleted: true, LastKnownParent: ouA, LastKnownRDN: "Ann Smith",
		Links: []client.LinkValue{{Attribute: "memberOf", Object: grpLive}, {Attribute: "memberOf", Object: grpDead, Dormant: true}}}
	act := lifeActions(t, d, nil)[ad.RestoreID]
	sp := plan1(t, act, ad.RestoreInput{Target: target()})
	if sp.Reversibility != operation.Lossy || sp.Kind != client.DigestObjectRestore {
		t.Fatalf("plan %+v", sp)
	}
	all := strings.Join(sp.Preconditions, "\n")
	if !strings.Contains(all, "will not return: memberOf -> "+grpDead) || !strings.Contains(all, "re-granted: memberOf -> "+grpLive) {
		t.Fatalf("preconditions %q", all)
	}
	if !strings.Contains(sp.ReversibilityReason, "1 link value") {
		t.Fatalf("reason %q", sp.ReversibilityReason)
	}
	// No dormant link: Reversible.
	st := d.objs[obj]
	st.Links = st.Links[:1]
	d.objs[obj] = st
	if sp := plan1(t, act, ad.RestoreInput{Target: target()}); sp.Reversibility != operation.Reversible {
		t.Fatalf("no dormant link: %+v", sp)
	}
	// Without the Recycle Bin restore is refused, never tried; a live object is not restorable.
	d.bin = false
	if err := planErr(act, input(t, ad.RestoreInput{Target: target()})); !errors.Is(err, operation.ErrInvalid) || !strings.Contains(err.Error(), ad.ReasonNoRecycleBin) {
		t.Fatalf("no bin: %v", err)
	}
	d.bin = true
	d.objs[obj] = client.ObjectState{Exists: true, Class: "user"}
	if err := planErr(act, input(t, ad.RestoreInput{Target: target()})); err == nil {
		t.Fatal("a live object was planned for restore")
	}
}

// face presents a Directory Action to the runner's inline path and forwards AlsoAuthorize/Touched.
type face struct{ storeFace }

func (f face) AlsoAuthorize(p operation.StepPlan) []authority.TargetRef {
	return f.Action.(operation.AlsoAuthorizer).AlsoAuthorize(p)
}

// AC2 (TM-F-AUTHZ): a move re-checks the destination parent live immediately before the write; a
// destination that left the actor's scope between Plan and Apply fails denied and nothing is written.
func TestMoveDestinationRecheckedAtApply(t *testing.T) {
	for _, tc := range []struct {
		name   string
		refuse string
		wrote  int
	}{{"in scope", "", 1}, {"destination out of scope", ouB, 0}, {"source out of scope", obj, 0}} {
		d := newDir()
		sk := &sink{}
		reg, err := operation.NewRegistry(face{storeFace{lifeActions(t, d, nil)[ad.MoveID]}})
		if err != nil {
			t.Fatal(err)
		}
		// Plan's own checks (target, destination) pass; the refusal arms for the Apply-time ones.
		r2, err := operation.NewRunner(operation.Config{DB: fakeDB{}, Audit: sk, Authz: &armedAuthz{armAfter: 2, refuse: tc.refuse}, Registry: reg})
		if err != nil {
			t.Fatal(err)
		}
		_, err = r2.RunStore(context.Background(), operation.Request{
			Tenant: tenanttest.NewID(t), Action: ad.MoveID, Input: input(t, ad.MoveInput{Target: target(), NewParentGuid: ouB}),
			Pins: pins(), Operation: "op-mv-1", Actor: authority.Chain{Requester: authority.Principal{ID: "tech", Kind: authority.Human}},
		})
		if tc.wrote == 1 && err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if tc.wrote == 0 && !errors.Is(err, operation.ErrDenied) {
			t.Fatalf("%s: want denied, got %v", tc.name, err)
		}
		if len(d.writes) != tc.wrote {
			t.Errorf("%s: %d writes", tc.name, len(d.writes))
		}
	}
}

// armedAuthz allows the first armAfter-1... calls (Plan), then refuses the GUID (Apply).
type armedAuthz struct {
	armAfter, calls int
	refuse          string
}

func (a *armedAuthz) FactsQuery(_ authority.Chain, _ authz.Permission, t authority.TargetRef) authority.FactsQuery {
	return authority.FactsQuery{Target: t}
}

func (a *armedAuthz) Authorize(ctx context.Context, c authority.Chain, p authz.Permission, t authority.TargetRef, f authority.Facts) error {
	a.calls++
	if a.calls > a.armAfter && t.GUID == a.refuse {
		return operation.ErrDenied
	}
	return nil
}
