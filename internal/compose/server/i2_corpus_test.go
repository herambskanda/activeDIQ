package server

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory"
	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/modules/ad"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/capability"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/store/owners"
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

func (i2Dir) Account(context.Context, authority.Pins, authority.TargetRef) (client.AccountState, error) {
	return client.AccountState{Exists: true, Class: "user", UserAccountControl: "66048", LockoutTime: "133500000000000000", PwdLastSet: "133400000000000000"}, nil
}

func (i2Dir) Object(_ context.Context, _ authority.Pins, t authority.TargetRef, _ []string, deleted bool) (client.ObjectState, error) {
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
	for _, a := range append(as, ls...) {
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

func TestI2CorpusEveryRegisteredAction(t *testing.T) {
	c, _, err := bootReport(context.Background(), capability.NewSet(capability.DirectoryAD, capability.DirectoryEntra, capability.TenantProvisioning), directory.Services{}, owners.Lookup)
	if err != nil {
		t.Fatalf("boot: %v", err)
	}
	acts := c.Actions()
	if len(acts) == 0 {
		t.Fatal("no registered Actions: the corpus is empty")
	}
	seen := map[operation.ActionID]bool{}
	planners, err := i2Planners()
	if err != nil {
		t.Fatalf("fixture actions: %v", err)
	}
	for _, act := range acts {
		d := act.Describe()
		seen[d.ID] = true
		if d.Target == operation.TargetStore {
			continue
		}
		mk, ok := i2Fixtures[d.ID]
		if !ok {
			t.Errorf("%s targets %s and has no I-2 fixture in i2Fixtures", d.ID, d.Target)
			continue
		}
		pl, ok := planners[d.ID]
		if !ok {
			t.Errorf("%s has an I-2 fixture input but no fixture Action in i2Planners", d.ID)
			continue
		}
		leaks, err := i2Leaks(context.Background(), pl, mk(i2Sentinel))
		if err != nil {
			t.Errorf("%s: its I-2 fixture does not plan (a fixture that cannot plan proves nothing): %v", d.ID, err)
			continue
		}
		if len(leaks) != 0 {
			t.Errorf("%s writes an identity into a directory attribute (I-2): %v", d.ID, leaks)
		}
	}
	for id := range i2Fixtures {
		if !seen[id] {
			t.Errorf("i2Fixtures names %s, which is not registered", id)
		}
	}
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
