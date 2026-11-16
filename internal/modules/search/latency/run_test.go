package latency_test

// The benchmark driver, the oracle comparison and the plan probes.

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/searchkey"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/reportsql"
)

// budget is ADR-0011 rule 14.
const budget = 200 * time.Millisecond

// classes of the benchmark, in report order.
var classOrder = []string{"exact", "prefix", "fuzzy1", "nomatch", "oneletter", "ceiling"}

type class struct {
	name  string
	texts []string
}

func typeOf(k inventory.Kind) string {
	switch k {
	case inventory.KindUser, inventory.KindInetOrgPerson:
		return "users"
	case inventory.KindGroup:
		return "groups"
	case inventory.KindComputer, inventory.KindGMSA:
		return "computers"
	}
	return "contacts"
}

// calibrate returns the one- and two-letter texts whose prefix class holds between lo and hi matched key rows
// (the "just under W" class of ADR-0011 rule 14), the largest first. Their exact class must stay under hi too,
// or the text would not be a ceiling-sized prefix query but a refused one.
func (w *world) calibrate(lo, hi int) (texts []string, rows []int) {
	type cand struct {
		text string
		rows int
	}
	var cs []cand
	letters := "abcdefghijklmnopqrstuvwxyz"
	var all []string
	for _, a := range letters {
		all = append(all, string(a))
		for _, b := range letters {
			all = append(all, string(a)+string(b))
		}
	}
	for _, t := range all {
		m := w.match(t)
		if m.prefixRows >= lo && m.prefixRows <= hi && m.exactRows <= hi {
			cs = append(cs, cand{t, m.prefixRows})
		}
	}
	sort.Slice(cs, func(i, j int) bool {
		if cs[i].rows != cs[j].rows {
			return cs[i].rows > cs[j].rows
		}
		return cs[i].text < cs[j].text
	})
	for _, c := range cs {
		texts, rows = append(texts, c.text), append(rows, c.rows)
	}
	return texts, rows
}

// workload builds n texts for every class from the seed, deterministically. The ceiling class cycles the
// calibrated texts for ceil (the largest prefix class that stays under it).
func (w *world) workload(n, ceil int) []class {
	r := rand.New(rand.NewPCG(seedA^0x51, seedB^0x77))
	pick := func(kinds ...inventory.Kind) seedObj {
		for {
			o := w.seed.Objs[r.IntN(len(w.seed.Objs))]
			if slices.Contains(kinds, o.Kind) {
				return o
			}
		}
	}
	var exact, prefix, fuzzy, nomatch, one []string
	for i := 0; i < n; i++ {
		// exact identifiers: a sam, a UPN, a host name or a mail address, in the proportion of the directory.
		switch o := pick(inventory.KindUser, inventory.KindUser, inventory.KindUser, inventory.KindComputer, inventory.KindGroup, inventory.KindContact); {
		case o.Kind == inventory.KindUser && i%2 == 0:
			exact = append(exact, o.UPN)
		case o.Kind == inventory.KindUser:
			exact = append(exact, o.Sam)
		case o.Kind == inventory.KindComputer && i%2 == 0:
			exact = append(exact, o.Host)
		case o.Kind == inventory.KindComputer:
			exact = append(exact, strings.TrimSuffix(o.Sam, "$"))
		case o.Kind == inventory.KindContact:
			exact = append(exact, o.Mail)
		default:
			exact = append(exact, o.Sam)
		}
		// prefix: the front of a display name, 3 characters at least, never the whole name.
		o := pick(inventory.KindUser, inventory.KindUser, inventory.KindGroup, inventory.KindComputer, inventory.KindContact)
		runes := []rune(strings.ToLower(o.Display))
		cut := max(3, (len(runes)*55+99)/100)
		prefix = append(prefix, strings.TrimSpace(string(runes[:min(cut, len(runes)-1)])))
		// one typo: two neighbouring letters of the first word swapped (never the first letter).
		o = pick(inventory.KindUser, inventory.KindUser, inventory.KindUser, inventory.KindGroup, inventory.KindContact)
		fuzzy = append(fuzzy, typo(strings.ToLower(o.Display), r))
		// no match: letters that no generated name uses together, with digits.
		var b strings.Builder
		for j := 0; j < 6+r.IntN(5); j++ {
			b.WriteByte("qxzjvwk0123456789"[r.IntN(17)])
		}
		nomatch = append(nomatch, b.String())
		one = append(one, string(rune('a'+i%26)))
	}
	cal, _ := w.calibrate(ceil*6/10, ceil)
	if len(cal) > 8 {
		cal = cal[:8]
	}
	var ceilTexts []string
	for i := 0; len(cal) > 0 && i < n; i++ {
		ceilTexts = append(ceilTexts, cal[i%len(cal)])
	}
	return []class{{"exact", exact}, {"prefix", prefix}, {"fuzzy1", fuzzy}, {"nomatch", nomatch}, {"oneletter", one}, {"ceiling", ceilTexts}}
}

// typo swaps two neighbouring letters inside the first word, leaving the first letter alone.
func typo(s string, r *rand.Rand) string {
	rs := []rune(s)
	end := slices.Index(rs, ' ')
	if end < 0 {
		end = len(rs)
	}
	for tries := 0; tries < 20 && end >= 4; tries++ {
		i := 1 + r.IntN(end-2)
		if rs[i] != rs[i+1] {
			rs[i], rs[i+1] = rs[i+1], rs[i]
			return string(rs)
		}
	}
	rs = slices.Delete(rs, min(2, len(rs)-1), min(3, len(rs))) // one letter dropped
	return string(rs)
}

// ---- the oracle comparison ----

// expect is what a caller must receive for a query: the refine state, the exact set per type when it is not a
// refine state, and the superset the hits must stay within when it is.
func (w *world) expect(caller string, m *matched, ceil int) (refine bool, sets map[string]map[int]bool) {
	c := 0
	switch {
	case m.exactRows > ceil:
		c = 1
	case m.prefixRows > ceil:
		c = 2
	case m.fuzzyRows > ceil:
		c = 3
	}
	sets = map[string]map[int]bool{}
	add := func(src map[int]bool) {
		for i := range src {
			if w.seed.Visible(caller, i) {
				t := typeOf(w.seed.Objs[i].Kind)
				if sets[t] == nil {
					sets[t] = map[int]bool{}
				}
				sets[t][i] = true
			}
		}
	}
	// Classes at or below the overflowing one are withheld (reportsql: cand).
	if c == 0 || c > 1 {
		add(m.exact)
	}
	if c == 0 || c > 2 {
		add(m.prefix)
	}
	if c == 0 {
		add(m.fuzzy)
	}
	return c > 0, sets
}

// check compares one HTTP answer with the oracle. limit is the groupLimit the request asked for (50 in the
// verification pass). It returns the disagreements, empty when the answer is right.
func (w *world) check(caller, text string, body []byte, m *matched, ceil, limit int) []string {
	var resp response
	if err := json.Unmarshal(body, &resp); err != nil {
		return []string{fmt.Sprintf("%s %q: undecodable answer: %v", caller, text, err)}
	}
	var bad []string
	fail := func(f string, a ...any) { bad = append(bad, fmt.Sprintf("%s %q: ", caller, text)+fmt.Sprintf(f, a...)) }
	refine, sets := w.expect(caller, m, ceil)
	seen := map[string]map[int]bool{}
	for _, g := range resp.Groups {
		if seen[g.Type] == nil {
			seen[g.Type] = map[int]bool{}
		}
		for _, it := range g.Items {
			i, ok := w.byID[it.ObjectID]
			switch {
			case !ok:
				fail("returned an object the seed does not hold: %s", it.ObjectID)
			case !w.seed.Visible(caller, i):
				fail("HIDDEN OBJECT RETURNED: %s (%s)", it.ObjectID, w.seed.Objs[i].Kind)
			case typeOf(w.seed.Objs[i].Kind) != g.Type:
				fail("%s listed under %s", it.ObjectID, g.Type)
			case !sets[g.Type][i] && !refine:
				fail("%s (%s) is not a match the oracle knows", it.ObjectID, w.seed.Objs[i].Display)
			}
			if ok {
				seen[g.Type][i] = true
			}
		}
	}
	if resp.Refine != refine {
		fail("refine = %v, oracle says %v (exact rows %d, prefix rows %d, fuzzy rows %d, W %d)", resp.Refine, refine, m.exactRows, m.prefixRows, m.fuzzyRows, ceil)
	}
	if resp.Refine {
		return bad
	}
	for _, t := range []string{"users", "groups", "computers", "contacts"} {
		want := sets[t]
		var count *int
		for _, g := range resp.Groups {
			if g.Type == t {
				count = g.Count
			}
		}
		if m.parsed.Runes >= 3 {
			if count == nil && len(want) > 0 {
				fail("%s: no count, the oracle has %d visible matches", t, len(want))
			} else if count != nil && *count != len(want) {
				fail("%s: count %d, the oracle has %d visible matches", t, *count, len(want))
			}
		} else if count != nil {
			fail("%s: a count on a query under 3 characters", t)
		}
		got := seen[t]
		if len(want) <= limit {
			if len(got) != len(want) {
				fail("%s: %d hits, the oracle has exactly %d", t, len(got), len(want))
			}
		} else if len(got) != limit {
			fail("%s: %d hits, want a full page of %d of %d", t, len(got), limit, len(want))
		}
	}
	return bad
}

// ---- plan probes ----

type planNode struct {
	Type     string     `json:"Node Type"`
	Relation string     `json:"Relation Name"`
	Index    string     `json:"Index Name"`
	Rows     float64    `json:"Actual Rows"`
	Loops    float64    `json:"Actual Loops"`
	Filter   float64    `json:"Rows Removed by Filter"`
	Recheck  float64    `json:"Rows Removed by Index Recheck"`
	Subplan  string     `json:"Subplan Name"`
	Children []planNode `json:"Plans"`
}

func (n *planNode) walk(cte string, fn func(n *planNode, cte string)) {
	if strings.HasPrefix(n.Subplan, "CTE ") {
		cte = strings.TrimPrefix(n.Subplan, "CTE ")
	}
	fn(n, cte)
	for i := range n.Children {
		n.Children[i].walk(cte, fn)
	}
}

// planFacts is what the latency report keeps of one EXPLAIN (ANALYZE) of a search.
type planFacts struct {
	rows       map[string]float64 // key rows read per CTE (m_exact, m_prefix, m_fuzzy)
	recheck    float64            // Rows Removed by Index Recheck, all nodes of m_fuzzy
	filtered   float64            // Rows Removed by Filter on the key table, m_fuzzy
	fuzzyScan  string             // node type and index of the m_fuzzy read of the key table
	seqScans   []string
	objLoops   float64
	execTimeMS float64
}

// explain compiles text for scope exactly as inventory.Searcher does and runs it under EXPLAIN ANALYZE.
func (w *world) explain(scope authz.ReadScope, text string, ceil int) planFacts {
	w.t.Helper()
	ctx := context.Background()
	p, err := searchkey.Classify(text)
	if err != nil {
		w.t.Fatal(err)
	}
	if !w.srcOK {
		if err := w.db.WithTenant(ctx, w.tid, func(ctx context.Context, tx store.Tx) error {
			sc, err := reportsql.CatalogSchema(ctx, tx)
			if err != nil {
				return err
			}
			w.src, err = reportsql.NewSearchSource(sc, "inventory_search_keys", "inventory_search_trigrams", report.Anchor{ID: "t", Table: "directory_objects", Mode: report.RowAnchor,
				Project: []report.Ident{"object_guid"}, Connection: "connection_id", NC: "nc_guid", Object: "object_guid", Parent: "parent_guid",
				Ancestry: "ancestry", Complete: "ancestry_complete"}, "kind", "state", "enabled", "display_name")
			w.srcOK = err == nil
			return err
		}); err != nil {
			w.t.Fatal(err)
		}
	}
	cq, err := reportsql.CompileSearch(w.src, reportsql.SearchQuery{Exact: p.Exact, Prefix: p.Prefix, Fuzzy: p.Fuzzy, GroupLimit: 5, Ceiling: ceil, Threshold: fuzzyThreshold},
		reportsql.SearchScopes{"directory.read": scope})
	if err != nil {
		w.t.Fatal(err)
	}
	sql, args := cq.Statement()
	var doc []byte
	if err := w.db.WithTenant(ctx, w.tid, func(ctx context.Context, tx store.Tx) error {
		if p.Fuzzy != "" {
			restore, err := store.SetTrigramThreshold(ctx, tx, fuzzyThreshold)
			if err != nil {
				return err
			}
			defer restore()
		}
		return tx.QueryRow(ctx, "EXPLAIN (ANALYZE, FORMAT JSON) "+sql, args...).Scan(&doc)
	}); err != nil {
		w.t.Fatalf("explain %q: %v", text, err)
	}
	var top []struct {
		Plan  planNode `json:"Plan"`
		ExecT float64  `json:"Execution Time"`
	}
	if err := json.Unmarshal(doc, &top); err != nil || len(top) != 1 {
		w.t.Fatalf("plan: %v", err)
	}
	f := planFacts{rows: map[string]float64{}, execTimeMS: top[0].ExecT}
	top[0].Plan.walk("", func(n *planNode, cte string) {
		switch n.Relation {
		case "inventory_search_keys":
			f.rows[cte] += n.Rows * n.Loops
			if strings.Contains(n.Type, "Seq Scan") {
				f.seqScans = append(f.seqScans, n.Relation+" ("+cte+")")
			}
			if cte == "m_fuzzy" {
				f.recheck += n.Recheck * n.Loops
				f.filtered += n.Filter * n.Loops
			}
		case "directory_objects":
			if strings.Contains(n.Type, "Seq Scan") {
				f.seqScans = append(f.seqScans, n.Relation)
			}
			f.objLoops += n.Loops
		}
		if cte == "m_fuzzy" && n.Relation == "inventory_search_keys" {
			f.fuzzyScan = n.Type + " " + n.Index
		}
	})
	return f
}
