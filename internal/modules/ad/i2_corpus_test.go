package ad_test

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/modules/ad"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

// I-2 corpus (impersonate-as-admin-attribution §6.2, T-1629): no registered Action's plan diff carries a
// technician, token or account identifier into a directory attribute. The AST check in tools/fitness/operation
// reads the source; this test reads the behaviour of every Action in the real registry, so a new Action
// cannot skip it:
//
//   - a Store Action writes only the store; it has no connector, so no directory attribute. That is pinned
//     here by its declared Target, and a change of Target to a directory kind then needs a fixture;
//   - an AD or Entra Action must have a fixture in i2Fixtures (an Input whose every identity-shaped field
//     is a sentinel), and its Plan diff must hold no sentinel, not even as a substring.
//
// An Action that is neither Store nor fixtured fails the test.

const i2Sentinel = "SENTINEL-i2-7f3a9c"

// i2Fixtures maps a directory-writing Action to the Input its Plan is run with. A registered Action
// has no connector in this test (the boot has no directory services), so the fixture also names how
// to build the same Action over a fake directory (i2Planners); both must exist for an ID.
var i2Fixtures = map[operation.ActionID]func(sentinel string) operation.Input{
	ad.ResetPasswordID: func(string) operation.Input {
		return i2JSON(ad.ResetInput{Target: i2Target, MustChangeAtNextLogon: true})
	},
	ad.UnlockID:  func(string) operation.Input { return i2JSON(ad.AccountInput{Target: i2Target}) },
	ad.EnableID:  func(string) operation.Input { return i2JSON(ad.AccountInput{Target: i2Target}) },
	ad.DisableID: func(string) operation.Input { return i2JSON(ad.AccountInput{Target: i2Target}) },
	ad.CreateID: func(string) operation.Input {
		return i2JSON(ad.CreateInput{ConnectionID: i2Conn, NamingContext: i2NC, ParentGuid: i2Parent, Enabled: true,
			Attributes: map[string]string{"cn": "Ann Smith", "sAMAccountName": "asmith", "givenName": "Ann", "sn": "Smith"}, UPNSuffix: "example.test"})
	},
	ad.UpdateID: func(string) operation.Input {
		return i2JSON(ad.UpdateInput{Target: i2Target, Set: map[string]string{"description": "new"}, Clear: []string{"title"}})
	},
	ad.DeleteID: func(string) operation.Input { return i2JSON(ad.DeleteInput{Target: i2Target}) },
	ad.MoveID:   func(string) operation.Input { return i2JSON(ad.MoveInput{Target: i2Target, NewParentGuid: i2Parent2}) },
	ad.RenameID: func(string) operation.Input { return i2JSON(ad.RenameInput{Target: i2Target, NewName: "Ann Jones"}) },
	ad.RestoreID: func(string) operation.Input {
		return i2JSON(ad.RestoreInput{Target: i2Target, NewParentGuid: i2Parent, Name: "Ann Smith"})
	},
}

func init() {
	for _, c := range []string{"group", "computer", "contact", "ou"} {
		c := c
		g := i2ClassGuid[c]
		tg := ad.Target{ConnectionID: i2Conn, ObjectGUID: g, NamingContext: i2NC}
		i2Fixtures[operation.ActionID("ad."+c+".create")] = func(string) operation.Input {
			in := ad.ObjectCreateInput{ConnectionID: i2Conn, NamingContext: i2NC, ParentGuid: i2Parent, Name: "Fixture One",
				Attributes: map[string]string{"description": "new"}}
			if c == "group" {
				in.GroupScope = "global"
			}
			return i2JSON(in)
		}
		i2Fixtures[operation.ActionID("ad."+c+".update")] = func(string) operation.Input {
			return i2JSON(ad.UpdateInput{Target: tg, Set: map[string]string{"description": "new"}})
		}
		i2Fixtures[operation.ActionID("ad."+c+".delete")] = func(string) operation.Input { return i2JSON(ad.DeleteInput{Target: tg}) }
		i2Fixtures[operation.ActionID("ad."+c+".move")] = func(string) operation.Input {
			return i2JSON(ad.MoveInput{Target: tg, NewParentGuid: i2Parent2})
		}
		i2Fixtures[operation.ActionID("ad."+c+".rename")] = func(string) operation.Input {
			return i2JSON(ad.RenameInput{Target: tg, NewName: "Fixture Two"})
		}
		i2Fixtures[operation.ActionID("ad."+c+".restore")] = func(string) operation.Input {
			return i2JSON(ad.RestoreInput{Target: tg, NewParentGuid: i2Parent, Name: "Fixture One"})
		}
	}
	tc := ad.Target{ConnectionID: i2Conn, ObjectGUID: i2ClassGuid["computer"], NamingContext: i2NC}
	i2Fixtures[ad.ComputerResetID] = func(string) operation.Input { return i2JSON(ad.AccountInput{Target: tc}) }
	member := func(class string) func(string) operation.Input {
		return func(string) operation.Input {
			return i2JSON(ad.MemberInput{ConnectionID: i2Conn, NamingContext: i2NC, GroupGuid: i2ClassGuid["group"], MemberGuid: i2Obj, MemberClass: class})
		}
	}
	i2Fixtures[ad.AddMemberID] = member("user")
	i2Fixtures[ad.RemoveMemberID] = member("user")
	i2Fixtures[ad.NestGroupID] = func(string) operation.Input {
		return i2JSON(ad.MemberInput{ConnectionID: i2Conn, NamingContext: i2NC, GroupGuid: i2ClassGuid["group"], MemberGuid: i2ClassGuid["group2"], MemberClass: "group"})
	}
}

// i2ClassGuid is the object GUID of the live fixture object of each non-user class.
var i2ClassGuid = map[string]string{
	"group":    "33333333-3333-4333-8333-333333333333",
	"computer": "44444444-4444-4444-8444-444444444444",
	"contact":  "55555555-5555-4555-8555-555555555555",
	"ou":       "66666666-6666-4666-8666-666666666666",
	"group2":   "77777777-7777-4777-8777-777777777777",
}

var i2ClassLive = map[string]string{"group": "group", "computer": "computer", "contact": "contact", "ou": "organizationalUnit", "group2": "group"}

const (
	i2Conn    = "conn-1"
	i2NC      = "11111111-1111-4111-8111-111111111111"
	i2Obj     = "22222222-2222-4222-8222-222222222222"
	i2Parent  = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	i2Parent2 = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
)

var i2Target = ad.Target{ConnectionID: i2Conn, ObjectGUID: i2Obj, NamingContext: i2NC}

func i2JSON(v any) operation.Input {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// i2Dir is the fake directory the fixture Actions plan against: a live user, two containers and one
// deleted user. It holds no identity, so any identity in a diff came from the Plan's own context.
type i2Dir struct{}

func (i2Dir) Account(_ context.Context, _ authority.Pins, t authority.TargetRef) (client.AccountState, error) {
	if t.GUID == i2ClassGuid["computer"] {
		return client.AccountState{Exists: true, Class: "computer", UserAccountControl: "4096", PwdLastSet: "133400000000000000"}, nil
	}
	return client.AccountState{Exists: true, Class: "user", UserAccountControl: "66048", LockoutTime: "133500000000000000", PwdLastSet: "133400000000000000"}, nil
}

func (i2Dir) Object(_ context.Context, _ authority.Pins, t authority.TargetRef, _ []string, deleted bool) (client.ObjectState, error) {
	for c, g := range i2ClassGuid {
		if t.GUID == g {
			st := client.ObjectState{Exists: true, Class: i2ClassLive[c], Parent: i2Parent, RDN: "Fixture One", Deleted: deleted,
				Attrs: map[string][]string{"description": {"old"}, "info": {"x"}}}
			if deleted {
				st.LastKnownParent, st.LastKnownRDN = i2Parent, "Fixture One"
			}
			return st, nil
		}
	}
	switch t.GUID {
	case i2Parent, i2Parent2:
		if deleted {
			return client.ObjectState{}, nil
		}
		return client.ObjectState{Exists: true, Class: "organizationalUnit"}, nil
	case i2Obj:
		st := client.ObjectState{Exists: true, Class: "user", Parent: i2Parent, RDN: "Ann Smith", Deleted: deleted,
			Attrs: map[string][]string{"description": {"old"}, "title": {"Engineer"}}}
		if deleted {
			st.LastKnownParent, st.LastKnownRDN = i2Parent, "Ann Smith"
		}
		return st, nil
	}
	return client.ObjectState{}, nil
}

func (i2Dir) DirectMember(context.Context, authority.Pins, authority.TargetRef, authority.TargetRef) (bool, error) {
	return false, nil
}

func (d i2Dir) ObjectWithChildCount(ctx context.Context, pins authority.Pins, t authority.TargetRef) (client.ObjectState, error) {
	st, err := d.Object(ctx, pins, t, nil, false)
	st.ChildCount = &client.ChildCount{}
	return st, err
}

func (i2Dir) RecycleBin(context.Context, authority.Pins, authority.NamingContextID) (bool, error) {
	return true, nil
}

// i2Planners builds the AD Actions over the fake directory, keyed by ID.
func i2Planners() (map[operation.ActionID]operation.Action, error) {
	out := map[operation.ActionID]operation.Action{}
	as, err := ad.Actions(i2Dir{}, nil)
	if err != nil {
		return nil, err
	}
	ls, err := ad.LifecycleActions(ad.LifecyclePorts{Reader: i2Dir{}})
	if err != nil {
		return nil, err
	}
	ms, err := ad.MemberActions(ad.LifecyclePorts{Reader: i2Dir{}})
	if err != nil {
		return nil, err
	}
	for _, a := range append(append(as, ls...), ms...) {
		out[a.Describe().ID] = a
	}
	return out, nil
}

// i2Facts answers a Plan's live read with nothing, so a Plan that needs a fact fails closed.
type i2Facts struct{}

func (i2Facts) Facts(context.Context, authority.FactsQuery) (authority.Facts, error) {
	return authority.Facts{}, fmt.Errorf("no facts in the corpus test")
}

// i2Leaks plans act with the fixture and returns the diff cells that contain the sentinel.
func i2Leaks(ctx context.Context, act operation.Action, in operation.Input) ([]string, error) {
	// The only identity a Plan could reach is the context's: carry the sentinel there.
	ctx = authority.WithTenant(ctx, i2Sentinel)
	steps, err := act.Plan(ctx, operation.PlanContext{Facts: i2Facts{}, Pins: authority.Pins{i2NC: "dc1.example"}, Tx: &storetest.FakeTx{}}, in)
	if err != nil {
		return nil, err
	}
	var leaks []string
	for _, s := range steps {
		for _, c := range s.Diff {
			for _, v := range append(append([]string{c.Attribute}, c.Before...), c.After...) {
				if strings.Contains(v, i2Sentinel) {
					leaks = append(leaks, fmt.Sprintf("%s.%s=%q", s.Kind, c.Attribute, v))
				}
			}
		}
	}
	return leaks, nil
}

// leaky is a directory Action whose Plan copies a field of its Input into the diff. The harness must
// catch it, or the corpus test above proves nothing.
type leaky struct{ operation.Action }

func (leaky) Plan(_ context.Context, _ operation.PlanContext, in operation.Input) ([]operation.StepPlan, error) {
	var v struct{ Technician string }
	if err := json.Unmarshal(in, &v); err != nil {
		return nil, err
	}
	return []operation.StepPlan{{Kind: "x", Diff: []operation.Change{{Attribute: "description", After: []string{"changed by " + v.Technician}}}}}, nil
}

type honest struct{ operation.Action }

func (honest) Plan(context.Context, operation.PlanContext, operation.Input) ([]operation.StepPlan, error) {
	return []operation.StepPlan{{Kind: "x", Diff: []operation.Change{{Attribute: "description", After: []string{"new"}}}}}, nil
}

func TestI2CorpusHarnessCatchesALeak(t *testing.T) {
	in, _ := json.Marshal(map[string]string{"Technician": i2Sentinel})
	if leaks, err := i2Leaks(context.Background(), leaky{}, in); err != nil || len(leaks) != 1 {
		t.Fatalf("a leaking Plan was not caught: %v %v", leaks, err)
	}
	if leaks, err := i2Leaks(context.Background(), honest{}, in); err != nil || len(leaks) != 0 {
		t.Fatalf("an honest Plan was flagged: %v %v", leaks, err)
	}
}

// TestI2CorpusEveryADAction is the per-module half of the corpus: every Action this module builds has a
// fixture and plans without leaking an identity. The registry half (no unfixtured directory Action is
// registered anywhere) is in internal/compose/server, which may not name this module (blueprint §2.5).
func TestI2CorpusEveryADAction(t *testing.T) {
	planners, err := i2Planners()
	if err != nil {
		t.Fatalf("fixture actions: %v", err)
	}
	if len(planners) == 0 {
		t.Fatal("no Actions: the corpus is empty")
	}
	for id, pl := range planners {
		if pl.Describe().Target == operation.TargetStore {
			continue
		}
		mk, ok := i2Fixtures[id]
		if !ok {
			t.Errorf("%s targets %s and has no I-2 fixture in i2Fixtures", id, pl.Describe().Target)
			continue
		}
		leaks, err := i2Leaks(context.Background(), pl, mk(i2Sentinel))
		if err != nil {
			t.Errorf("%s: its I-2 fixture does not plan (a fixture that cannot plan proves nothing): %v", id, err)
			continue
		}
		if len(leaks) != 0 {
			t.Errorf("%s writes an identity into a directory attribute (I-2): %v", id, leaks)
		}
	}
	for id := range i2Fixtures {
		if _, ok := planners[id]; !ok {
			t.Errorf("i2Fixtures names %s, which no Action builds", id)
		}
	}
}
