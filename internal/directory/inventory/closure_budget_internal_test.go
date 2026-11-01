package inventory

import (
	"slices"
	"testing"
)

func Test_splitByBudget(t *testing.T) {
	// big (600) is contained by a1..a4; a_i holds one link of its own (to big), so est(a_i) = 601
	edges := map[string][]string{"a1": {"big"}, "a2": {"big"}, "a3": {"big"}, "a4": {"big"}}
	counts := map[string]int{"big": 600, "a1": 1, "a2": 1, "a3": 1, "a4": 1}
	groups := []string{"a3", "a1", "big", "a4", "a2"}
	b := budget{root: 1000, conn: 2000}
	adm, over := splitByBudget(groups, nil, edges, counts, b)
	slices.Sort(adm)
	slices.Sort(over)
	if !slices.Equal(adm, []string{"a1", "a2", "big"}) || !slices.Equal(over, []string{"a3", "a4"}) {
		t.Fatalf("admitted %v, over %v; want big, a1, a2 admitted and a3, a4 over (est 600, 601, 601 fit 1,802 of 2,000)", adm, over)
	}
	for i := 0; i < 5; i++ {
		slices.Reverse(groups)
		groups = append(groups[1:], groups[0])
		adm2, over2 := splitByBudget(groups, nil, edges, counts, b)
		slices.Sort(adm2)
		slices.Sort(over2)
		if !slices.Equal(adm, adm2) || !slices.Equal(over, over2) {
			t.Fatalf("order %v changed the decision: %v / %v", groups, adm2, over2)
		}
	}
	// no room at all
	adm, over = splitByBudget(groups, nil, edges, counts, budget{root: 1000, conn: 0})
	if len(adm) != 0 || len(over) != 5 {
		t.Errorf("with no budget: admitted %v, over %v", adm, over)
	}
	// the per-group limit
	adm, _ = splitByBudget(groups, nil, edges, counts, budget{root: 600, conn: 100000})
	if !slices.Equal(adm, []string{"big"}) {
		t.Errorf("with a per-group limit of 600 admitted %v, want only big", adm)
	}
	// a group that reaches itself is counted once
	loop := map[string][]string{"x": {"y"}, "y": {"x"}}
	adm, over = splitByBudget([]string{"x", "y"}, nil, loop, map[string]int{"x": 1, "y": 1}, budget{root: 2, conn: 10})
	if len(adm) != 2 || len(over) != 0 {
		t.Errorf("cycle: admitted %v, over %v", adm, over)
	}
}

// Displacement (security review of T-0961): small groups that fill the connection budget must not push out a
// privileged group, and a smaller group pre-empts a larger one however the larger got there.
func Test_splitByBudget_privileged_and_small_first(t *testing.T) {
	counts := map[string]int{"da": 3, "f1": 1, "f2": 1, "f3": 1, "big": 50}
	groups := []string{"f1", "f2", "f3", "big", "da"}
	// connection budget 4: without priority da (3) comes after the three fillers and is left out
	adm, over := splitByBudget(groups, nil, nil, counts, budget{root: 100, conn: 4})
	if slices.Contains(adm, "da") {
		t.Fatalf("test setup: expected da to lose to the fillers without priority, admitted %v", adm)
	}
	// privileged: da is decided first whatever else exists
	adm, over = splitByBudget(groups, map[string]bool{"da": true}, nil, counts, budget{root: 100, conn: 4})
	slices.Sort(adm)
	if !slices.Contains(adm, "da") || len(adm) != 2 || !slices.Contains(over, "big") {
		t.Errorf("privileged da: admitted %v, over %v; want da and one filler", adm, over)
	}
	// the decision is a function of the graph: the same groups in any order, same result
	adm2, _ := splitByBudget([]string{"da", "big", "f3", "f2", "f1"}, map[string]bool{"da": true}, nil, counts, budget{root: 100, conn: 4})
	slices.Sort(adm2)
	if !slices.Equal(adm, adm2) {
		t.Errorf("order changed the decision: %v vs %v", adm, adm2)
	}
}
