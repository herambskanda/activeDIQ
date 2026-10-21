package operation

import (
	"bufio"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

const adrRelPath = "knowledge/development/decisions/0005-operation-pipeline-and-audit-trail.md"

// adrTable is what the ADR's rule 3 declares: the edges of the `transitions` block and the
// terminal states of the "Terminal states" bullet.
type adrTable struct {
	edges    []Edge
	terminal map[Kind][]string
}

func repoRoot(t *testing.T) string {
	t.Helper()
	d, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d
		}
		p := filepath.Dir(d)
		if p == d {
			t.Fatal("no go.mod above the test directory")
		}
		d = p
	}
}

func headerKind(h string) (Kind, bool) {
	switch {
	case strings.HasPrefix(h, "Operation "):
		return KindOperation, true
	case strings.HasPrefix(h, "OperationItem "):
		return KindItem, true
	case strings.HasPrefix(h, "Step "):
		return KindStep, true
	}
	return "", false
}

// parseTransitions parses the ```transitions block. Every line must be a "# Kind (...)" header, a
// "from -> to  comment" edge under a header, or blank; anything else is an error, so a format
// drift in the ADR cannot make the parity test pass vacuously.
func parseTransitions(doc string) ([]Edge, error) {
	var (
		edges []Edge
		kind  Kind
		in    bool
		found bool
		seen  = map[Edge]int{}
	)
	sc := bufio.NewScanner(strings.NewReader(doc))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if !in {
			if line == "```transitions" {
				in, found = true, true
			}
			continue
		}
		switch {
		case line == "```":
			in = false
		case line == "":
		case strings.HasPrefix(line, "# "):
			k, ok := headerKind(strings.TrimPrefix(line, "# "))
			if !ok {
				return nil, errLine(n, "unknown section header "+strconv.Quote(line))
			}
			kind = k
		default:
			f := strings.Fields(line)
			if kind == "" || len(f) < 3 || f[1] != "->" {
				return nil, errLine(n, "not an edge: "+strconv.Quote(line))
			}
			e := Edge{Kind: kind, From: f[0], To: f[2]}
			if seen[e]++; seen[e] > 1 {
				return nil, errLine(n, "duplicate edge "+e.String())
			}
			edges = append(edges, e)
		}
	}
	if !found {
		return nil, errLine(0, "no ```transitions block")
	}
	if in {
		return nil, errLine(0, "unterminated ```transitions block")
	}
	return edges, sc.Err()
}

type lineError struct {
	line int
	msg  string
}

func (e lineError) Error() string     { return "ADR line " + strconv.Itoa(e.line) + ": " + e.msg }
func errLine(n int, msg string) error { return lineError{n, msg} }

// parseTerminal reads the "**Terminal states.** Operation: `a`, `b`. Item: ... Step: ..." bullet.
func parseTerminal(doc string) (map[Kind][]string, error) {
	for _, line := range strings.Split(doc, "\n") {
		rest, ok := strings.CutPrefix(line, "- **Terminal states.**")
		if !ok {
			continue
		}
		out := map[Kind][]string{}
		for _, part := range strings.Split(rest, ". ") {
			label, list, ok := strings.Cut(strings.TrimSpace(part), ":")
			if !ok {
				continue
			}
			var k Kind
			switch strings.TrimSpace(label) {
			case "Operation":
				k = KindOperation
			case "Item":
				k = KindItem
			case "Step":
				k = KindStep
			default:
				continue
			}
			for _, s := range strings.Split(list, ",") {
				s = strings.Trim(strings.TrimSpace(s), "`.")
				if s != "" {
					out[k] = append(out[k], s)
				}
			}
			sort.Strings(out[k])
		}
		if len(out[KindOperation]) == 0 || len(out[KindItem]) == 0 || len(out[KindStep]) == 0 {
			return nil, errLine(0, "terminal states bullet is missing a kind")
		}
		return out, nil
	}
	return nil, errLine(0, "no Terminal states bullet")
}

func loadADR(t *testing.T) adrTable {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), filepath.FromSlash(adrRelPath)))
	if err != nil {
		t.Fatal(err)
	}
	edges, err := parseTransitions(string(b))
	if err != nil {
		t.Fatal(err)
	}
	term, err := parseTerminal(string(b))
	if err != nil {
		t.Fatal(err)
	}
	return adrTable{edges, term}
}

// diffEdges returns the edges only in want (missing from got) and only in got (extra), each sorted.
func diffEdges(want, got []Edge) (missing, extra []Edge) {
	in := func(set []Edge) map[Edge]bool {
		m := map[Edge]bool{}
		for _, e := range set {
			m[e] = true
		}
		return m
	}
	w, g := in(want), in(got)
	for e := range w {
		if !g[e] {
			missing = append(missing, e)
		}
	}
	for e := range g {
		if !w[e] {
			extra = append(extra, e)
		}
	}
	less := func(s []Edge) { sort.Slice(s, func(i, j int) bool { return s[i].String() < s[j].String() }) }
	less(missing)
	less(extra)
	return
}

// parity is the O4 comparison: nil when the two tables declare exactly the same edges, otherwise
// one message per differing edge, naming it.
func parity(adr, code []Edge) []string {
	missing, extra := diffEdges(adr, code)
	var msgs []string
	for _, e := range missing {
		msgs = append(msgs, "declared in the ADR but missing in code: "+e.String())
	}
	for _, e := range extra {
		msgs = append(msgs, "declared in code but not in the ADR: "+e.String())
	}
	return msgs
}

func TestTableMatchesADR(t *testing.T) {
	adr := loadADR(t)
	if len(adr.edges) < 40 {
		t.Fatalf("parsed only %d edges from the ADR; parser is not reading the block", len(adr.edges))
	}
	for _, m := range parity(adr.edges, Edges()) {
		t.Error(m)
	}
	for _, k := range Kinds() {
		got := TerminalStates(k)
		if strings.Join(got, ",") != strings.Join(adr.terminal[k], ",") {
			t.Errorf("%s terminal states: code %v, ADR %v", k, got, adr.terminal[k])
		}
	}
}

func TestParityDetectsMutations(t *testing.T) {
	adr := loadADR(t).edges
	code := Edges()

	t.Run("edge removed from code", func(t *testing.T) {
		removed := code[3]
		mut := append(append([]Edge(nil), code[:3]...), code[4:]...)
		msgs := parity(adr, mut)
		if len(msgs) != 1 || !strings.Contains(msgs[0], removed.String()) || !strings.Contains(msgs[0], "missing in code") {
			t.Fatalf("want one message naming %q as missing, got %v", removed, msgs)
		}
	})
	t.Run("edge added to code", func(t *testing.T) {
		added := Edge{KindStep, "planned", "verified"}
		msgs := parity(adr, append(append([]Edge(nil), code...), added))
		if len(msgs) != 1 || !strings.Contains(msgs[0], added.String()) || !strings.Contains(msgs[0], "not in the ADR") {
			t.Fatalf("want one message naming %q as extra, got %v", added, msgs)
		}
	})
	t.Run("same states, different kind", func(t *testing.T) {
		// planned -> running is an item edge; it must not satisfy the step table.
		mut := append([]Edge(nil), code...)
		for i, e := range mut {
			if e == (Edge{KindItem, "planned", "running"}) {
				mut[i].Kind = KindStep
			}
		}
		if len(parity(adr, mut)) != 2 {
			t.Fatal("moving an edge to another kind must register as one missing and one extra edge")
		}
	})
}

func TestParserRejectsMalformedBlocks(t *testing.T) {
	for name, doc := range map[string]string{
		"no block":        "nothing here",
		"unterminated":    "```transitions\n# Operation (DM-41)\na -> b\n",
		"edge before hdr": "```transitions\na -> b\n```\n",
		"bad arrow":       "```transitions\n# Operation (DM-41)\na => b\n```\n",
		"unknown header":  "```transitions\n# Widget (DM-1)\na -> b\n```\n",
		"duplicate":       "```transitions\n# Operation (DM-41)\na -> b\na -> b  again\n```\n",
	} {
		if _, err := parseTransitions(doc); err == nil {
			t.Errorf("%s: parser accepted the block", name)
		}
	}
}

func TestTransitionExhaustive(t *testing.T) {
	declared := map[Edge]bool{}
	for _, e := range Edges() {
		declared[e] = true
	}
	for _, k := range Kinds() {
		states := States(k)
		for _, from := range states {
			for _, to := range states {
				e := Edge{k, from, to}
				err := Transition(k, from, to)
				if declared[e] {
					if err != nil {
						t.Errorf("%s: declared edge refused: %v", e, err)
					}
					continue
				}
				te, ok := err.(*TransitionError)
				if !ok {
					t.Errorf("%s: undeclared edge accepted or wrong error type: %v", e, err)
					continue
				}
				for _, want := range []string{string(k), from, to} {
					if !strings.Contains(te.Error(), want) {
						t.Errorf("%s: error %q does not name %q", e, te.Error(), want)
					}
				}
			}
		}
	}
}

func TestTransitionErrorEchoesNoInput(t *testing.T) {
	const secret = "CN=Jane Doe,OU=Users"
	for _, c := range []struct {
		k        Kind
		from, to string
	}{
		{KindOperation, secret, "planning"},
		{KindOperation, "draft", secret},
		{KindItem, secret, secret},
		{Kind(secret), "draft", "planning"},
		{KindStep, "planned", "succeeded"}, // a state of another kind
	} {
		err := Transition(c.k, c.from, c.to)
		if err == nil {
			t.Fatalf("%v accepted", c)
		}
		if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "succeeded") {
			t.Errorf("error echoes an undeclared value: %q", err)
		}
		if !strings.Contains(err.Error(), Unknown) {
			t.Errorf("error does not mark the unknown value: %q", err)
		}
	}
}

func TestTerminalShape(t *testing.T) {
	for _, k := range Kinds() {
		for _, s := range TerminalStates(k) {
			if !Known(k, s) {
				t.Errorf("%s: terminal state %q is not in the table", k, s)
			}
			for _, to := range Next(k, s) {
				if to != "undone" {
					t.Errorf("%s: terminal %s -> %s is not an `undone` row", k, s, to)
				}
			}
		}
		for _, s := range States(k) {
			if !IsTerminal(k, s) && len(Next(k, s)) == 0 {
				t.Errorf("%s: non-terminal %q is a dead end", k, s)
			}
		}
	}
}

// TestPropertyRandomEvents drives random event sequences. The oracle is the ADR text parsed in
// this test, not the code's table, so the two cannot drift together.
func TestPropertyRandomEvents(t *testing.T) {
	adr := loadADR(t)
	oracle := map[Edge]bool{}
	for _, e := range adr.edges {
		oracle[e] = true
	}
	starts := map[Kind]string{KindOperation: "draft", KindItem: "pending", KindStep: "planned"}
	seeds := []int64{1, 20261021, time.Now().UnixNano()}
	if s := os.Getenv("OPERATION_PROP_SEED"); s != "" {
		v, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		seeds = []int64{v}
	}
	for _, seed := range seeds {
		t.Run("seed="+strconv.FormatInt(seed, 10), func(t *testing.T) {
			t.Logf("seed %d (replay with OPERATION_PROP_SEED=%d)", seed, seed)
			rng := rand.New(rand.NewSource(seed))
			var accepted, refused int
			for _, k := range Kinds() {
				states := States(k)
				visited := map[string]bool{starts[k]: true}
				cur := starts[k]
				for i := 0; i < 20000; i++ {
					// Mostly valid-state events, sometimes junk, to exercise unknown inputs.
					to := states[rng.Intn(len(states))]
					if rng.Intn(20) == 0 {
						to = "junk-" + strconv.Itoa(rng.Intn(5))
					}
					err := Transition(k, cur, to)
					e := Edge{k, cur, to}
					switch {
					case err == nil && !oracle[e]:
						t.Fatalf("undeclared transition accepted: %s", e)
					case err != nil && oracle[e]:
						t.Fatalf("declared transition refused: %s", e)
					case err == nil:
						if IsTerminal(k, cur) && to != "undone" {
							t.Fatalf("left terminal state: %s", e)
						}
						accepted++
						cur = to
						visited[cur] = true
						// A walk that ends in a dead end restarts, as a new entity would.
						if len(Next(k, cur)) == 0 {
							cur = starts[k]
						}
					default:
						refused++
					}
				}
				for _, s := range states {
					if !visited[s] {
						t.Errorf("%s: state %q was never reached from %q", k, s, starts[k])
					}
				}
			}
			t.Logf("seed %d: %d accepted, %d refused", seed, accepted, refused)
		})
	}
}
