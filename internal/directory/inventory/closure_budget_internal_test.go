package inventory

import (
	"fmt"
	"math/rand/v2"
	"runtime"
	"slices"
	"testing"
	"time"
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

// hubFan is the attack of security review 3 of T-0961: a hub group that holds w groups, and k groups that
// each hold the hub. Building each group's reach set made the decision cost k x w.
func hubFan(k, w int) (groups []string, edges map[string][]string, counts map[string]int) {
	edges, counts = map[string][]string{}, map[string]int{}
	for i := 0; i < w; i++ {
		leaf := fmt.Sprintf("leaf%05d", i)
		groups = append(groups, leaf)
		edges["hub"] = append(edges["hub"], leaf)
	}
	groups = append(groups, "hub")
	counts["hub"] = w
	for i := 0; i < k; i++ {
		g := fmt.Sprintf("top%05d", i)
		groups = append(groups, g)
		edges[g] = []string{"hub"}
		counts[g] = 1
	}
	return groups, edges, counts
}

// The decision's work must not grow with attacker-chosen fan-out. At the declared budget and 4,000 + 4,000
// groups (16,000 writes) it built 16 million reach rows: 18.6 s and 9.3 GB per refresh. Now it is linear,
// asserted on measured time and bytes allocated, not just logged.
func Test_splitByBudget_work_is_linear_in_the_graph(t *testing.T) {
	const k, w = 4000, 4000
	groups, edges, counts := hubFan(k, w)
	b := budget{root: defaultRootRows, conn: defaultConnRows}
	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	start := time.Now()
	adm, over := splitByBudget(groups, nil, edges, counts, b)
	took := time.Since(start)
	runtime.ReadMemStats(&m1)
	alloc := m1.TotalAlloc - m0.TotalAlloc
	t.Logf("%d groups, %d edges: %v, %d MB allocated; admitted %d, over %d", len(groups), 2*k+w, took, alloc>>20, len(adm), len(over))
	if took > time.Second {
		t.Errorf("decision took %v at k = w = %d, want under 1 s (it was 18.6 s)", took, k)
	}
	if alloc > 64<<20 {
		t.Errorf("decision allocated %d MB at k = w = %d, want under 64 MB (it was 9.3 GB)", alloc>>20, k)
	}
	// Each top group is hub + itself = 4,001 rows: 123 fit the 500,000-row connection budget after the
	// 4,000 leaves (0 rows each) and the hub (4,000). Nothing is left to chance: the rest read Unknown.
	if len(adm)+len(over) != len(groups) {
		t.Fatalf("admitted %d + over %d != %d groups", len(adm), len(over), len(groups))
	}
	if !slices.Contains(adm, "hub") || !slices.Contains(adm, "leaf00000") {
		t.Errorf("hub and leaves cost almost nothing and must be admitted")
	}
	tops := 0
	for _, g := range adm {
		if len(g) == 8 && g[:3] == "top" {
			tops++
		}
	}
	if want := (defaultConnRows - w) / (w + 1); tops != want {
		t.Errorf("%d top groups admitted, want %d (the connection budget bounds what is written)", tops, want)
	}
}

// Diamonds are counted once per path: the bound is never below the exact reach count (so the row budget
// holds), and it is equal on a tree.
func Test_estimates_are_an_upper_bound_of_the_reach_set(t *testing.T) {
	rng := rand.New(rand.NewPCG(7, 11))
	for round := 0; round < 200; round++ {
		n := 2 + rng.IntN(25)
		var groups []string
		edges, counts := map[string][]string{}, map[string]int{}
		for i := 0; i < n; i++ {
			groups = append(groups, fmt.Sprintf("g%02d", i))
		}
		tree := round%4 == 0
		for _, g := range groups {
			counts[g] = rng.IntN(5)
			for _, c := range groups {
				if tree && c <= g { // a forest: edges only to a later group that has no other parent
					continue
				}
				if !tree && rng.IntN(n) > 1 {
					continue
				}
				if tree && !(rng.IntN(3) == 0) {
					continue
				}
				edges[g] = append(edges[g], c)
			}
			counts[g] += len(edges[g])
		}
		if tree { // keep each child under its first parent only
			parent := map[string]string{}
			for _, g := range groups {
				var keep []string
				for _, c := range edges[g] {
					if _, ok := parent[c]; !ok {
						parent[c] = g
						keep = append(keep, c)
					}
				}
				counts[g] -= len(edges[g]) - len(keep)
				edges[g] = keep
			}
		}
		got := estimates(groups, edges, counts, 1<<40)
		for _, g := range groups {
			reach, _ := reachFrom(g, edges)
			exact := 0
			for _, r := range reach {
				exact += counts[r.Grp]
			}
			if got[g] < exact {
				t.Fatalf("round %d: %s bound %d below the exact %d", round, g, got[g], exact)
			}
			if tree && got[g] != exact {
				t.Fatalf("round %d (forest): %s bound %d, exact %d, want equal", round, g, got[g], exact)
			}
		}
	}
	// saturation: nothing overflows and nothing falls below the limit once it is reached
	groups := []string{"a", "b", "c"}
	got := estimates(groups, map[string][]string{"a": {"b"}, "b": {"c"}}, map[string]int{"a": 1 << 60, "b": 1 << 60, "c": 1 << 60}, 100)
	if got["a"] != 100 || got["b"] != 100 || got["c"] != 100 {
		t.Errorf("saturated bounds %v, want 100 each", got)
	}
}

// A diamond turns a group Unknown rather than giving it a wrong count: the exact reach of top is
// 1+1+1+100 = 103 rows, the bound counts the shared group once per path (203).
func Test_splitByBudget_diamond_turns_a_group_unknown(t *testing.T) {
	edges := map[string][]string{"top": {"l", "r"}, "l": {"shared"}, "r": {"shared"}}
	counts := map[string]int{"top": 2, "l": 1, "r": 1, "shared": 100}
	groups := []string{"top", "l", "r", "shared"}
	got := estimates(groups, edges, counts, 1<<40)
	if got["top"] != 2+101+101 {
		t.Errorf("bound of top = %d, want 204 (shared counted once per path)", got["top"])
	}
	adm, over := splitByBudget(groups, nil, edges, counts, budget{root: 150, conn: 1000})
	slices.Sort(adm)
	if !slices.Equal(adm, []string{"l", "r", "shared"}) || !slices.Equal(over, []string{"top"}) {
		t.Errorf("admitted %v, over %v; want top left out (Unknown) and the rest listed", adm, over)
	}
	// and with room, the same group is listed with its exact rows (the bound only gates admission)
	adm, over = splitByBudget(groups, nil, edges, counts, budget{root: 250, conn: 1000})
	if len(over) != 0 || len(adm) != 4 {
		t.Errorf("with room: admitted %v, over %v", adm, over)
	}
}

// A deep chain is not recursion: 100,000 nested groups neither overflow the stack nor cost more than linear.
func Test_estimates_deep_chain(t *testing.T) {
	const n = 100_000
	groups := make([]string, n)
	edges, counts := map[string][]string{}, map[string]int{}
	for i := range groups {
		groups[i] = fmt.Sprintf("c%06d", i)
		counts[groups[i]] = 1
		if i+1 < n {
			edges[groups[i]] = []string{fmt.Sprintf("c%06d", i+1)}
		}
	}
	start := time.Now()
	got := estimates(groups, edges, counts, 1<<40)
	if got[groups[0]] != n || got[groups[n-1]] != 1 {
		t.Errorf("chain bounds %d and %d, want %d and 1", got[groups[0]], got[groups[n-1]], n)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Errorf("chain of %d took %v", n, took)
	}
}
