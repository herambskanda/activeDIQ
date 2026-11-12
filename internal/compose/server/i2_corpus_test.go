package server

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/capability"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/store/owners"
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

// i2Fixtures maps a directory-writing Action to the Input its Plan is run with. There are none yet: every
// registered Action targets the store. The first directory Action adds its fixture in the same change.
var i2Fixtures = map[operation.ActionID]func(sentinel string) operation.Input{}

// i2Facts answers a Plan's live read with nothing, so a Plan that needs a fact fails closed.
type i2Facts struct{}

func (i2Facts) Facts(context.Context, authority.FactsQuery) (authority.Facts, error) {
	return authority.Facts{}, fmt.Errorf("no facts in the corpus test")
}

// i2Leaks plans act with the fixture and returns the diff cells that contain the sentinel.
func i2Leaks(ctx context.Context, act operation.Action, in operation.Input) ([]string, error) {
	steps, err := act.Plan(ctx, operation.PlanContext{Facts: i2Facts{}}, in)
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
		leaks, err := i2Leaks(context.Background(), act, mk(i2Sentinel))
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
