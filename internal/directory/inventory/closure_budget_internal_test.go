package inventory

import (
	"slices"
	"testing"
)

// The decision depends on the graph and the counts, never on the order the roots arrive in; a container
// never displaces the group it contains; a root over its own limit is left out whatever room remains.
func Test_splitByBudget(t *testing.T) {
	// big (600) is contained by a1..a4; a_i holds one link of its own (to big), so est(a_i) = 601
	edges := map[string][]string{"a1": {"big"}, "a2": {"big"}, "a3": {"big"}, "a4": {"big"}}
	counts := map[string]int{"big": 600, "a1": 1, "a2": 1, "a3": 1, "a4": 1}
	roots := []string{"a3", "a1", "big", "a4", "a2"}
	b := budget{root: 1000, conn: 2000}
	adm, over := splitByBudget(roots, edges, counts, b, 0)
	slices.Sort(adm)
	slices.Sort(over)
	if !slices.Equal(adm, []string{"a1", "a2", "big"}) || !slices.Equal(over, []string{"a3", "a4"}) {
		t.Fatalf("admitted %v, over %v; want big, a1, a2 admitted and a3, a4 over (est 600, 601, 601 fit 1,802 of 2,000)", adm, over)
	}
	for i := 0; i < 5; i++ {
		slices.Reverse(roots)
		roots = append(roots[1:], roots[0])
		adm2, over2 := splitByBudget(roots, edges, counts, b, 0)
		slices.Sort(adm2)
		slices.Sort(over2)
		if !slices.Equal(adm, adm2) || !slices.Equal(over, over2) {
			t.Fatalf("order %v changed the decision: %v / %v", roots, adm2, over2)
		}
	}
	// rows held by roots that are not recomputed come off the connection budget
	adm, over = splitByBudget(roots, edges, counts, b, 1300)
	if !slices.Equal(adm, []string{"big"}) || len(over) != 4 {
		t.Errorf("with 1,300 rows held: admitted %v, over %v; want only big (700 left holds big, then nothing more)", adm, over)
	}
	// a held count above the budget leaves no room at all, never a negative one
	adm, over = splitByBudget(roots, edges, counts, b, 9999)
	if len(adm) != 0 || len(over) != 5 {
		t.Errorf("with the budget spent: admitted %v, over %v", adm, over)
	}
	// the per-root limit
	adm, _ = splitByBudget(roots, edges, counts, budget{root: 600, conn: 100000}, 0)
	if !slices.Equal(adm, []string{"big"}) {
		t.Errorf("with a per-root limit of 600 admitted %v, want only big", adm)
	}
	// a group that reaches itself is counted once
	loop := map[string][]string{"x": {"y"}, "y": {"x"}}
	adm, over = splitByBudget([]string{"x", "y"}, loop, map[string]int{"x": 1, "y": 1}, budget{root: 2, conn: 10}, 0)
	if len(adm) != 2 || len(over) != 0 {
		t.Errorf("cycle: admitted %v, over %v", adm, over)
	}
}
