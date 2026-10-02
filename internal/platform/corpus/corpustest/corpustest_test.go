package corpustest

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/corpus"
)

func rec(id, call, expectKey, expectVal string, hostile bool) corpus.Record {
	h := hostile
	return corpus.Record{
		ID: id, Primitive: "pslit", Call: call, Hostile: &h, Verified: "doc",
		Expect: map[string]rawJSON{expectKey: rawJSON(expectVal)},
	}
}

type rawJSON = json.RawMessage

func file(rs ...corpus.Record) *corpus.File {
	return &corpus.File{Unit: "pslit", SHA256: "abc", Records: rs}
}

func TestCheck(t *testing.T) {
	f := file(
		rec("A", "Quote", "render", `"'x'"`, true),
		rec("B", "Quote", "error", `"NulInString"`, true),
		rec("C", "Quote", "bytes_hex", `"0a0B"`, false),
		rec("D", "Quote", "value", `{"a":1,"b":[2]}`, false),
		rec("E", "Other", "render", `"x"`, true),
		rec("F", "Quote", "render", `"never"`, true),
		rec("G", "Quote", "render", `"boom"`, true),
	)
	got := Check("go/x", f, func(r corpus.Record) (corpus.Result, error) {
		switch r.ID {
		case "A":
			return Render("'x'"), nil
		case "B":
			return Err("NulInString"), nil
		case "C":
			return BytesHex([]byte{0x0a, 0x0b}), nil
		case "D":
			return Value(map[string]any{"b": []int{2}, "a": 1})
		case "E":
			return corpus.Result{}, Skip("call family not routed")
		case "F":
			return Render("different"), nil
		}
		panic("boom")
	})
	if got.CorpusSHA != "abc" || got.Unit != "pslit" || got.Impl != "go/x" {
		t.Fatalf("report header: %+v", got)
	}
	ok := map[string]bool{}
	for _, r := range got.Ran {
		ok[r.ID] = r.OK
	}
	for id, want := range map[string]bool{"A": true, "B": true, "C": true, "D": true, "F": false, "G": false} {
		if ok[id] != want {
			t.Errorf("record %s ok = %v, want %v", id, ok[id], want)
		}
	}
	if len(got.Skipped) != 1 || got.Skipped[0].ID != "E" || got.Skipped[0].Why != "call family not routed" {
		t.Fatalf("skipped: %+v", got.Skipped)
	}
	for _, r := range got.Ran {
		if r.ID == "G" && !strings.Contains(r.Why, "panic: boom") {
			t.Errorf("a panicking handler must be a failed record, got %q", r.Why)
		}
	}
}

func TestCheckSkipsNonRuntime(t *testing.T) {
	r := rec("S", "", "render", `"x"`, true)
	r.Kind = corpus.KindStatic
	got := Check("go/x", file(r), func(corpus.Record) (corpus.Result, error) { return corpus.Result{}, errors.New("must not run") })
	if len(got.Ran)+len(got.Skipped) != 0 {
		t.Fatalf("a static record is not run by an implementation: %+v", got)
	}
}

func TestCheckArgv(t *testing.T) {
	guid := func(v string) error {
		if len(v) != 36 {
			return fmt.Errorf("not a GUID")
		}
		return nil
	}
	tpl := []Elem{C("--mailbox"), Slot("guid", guid), Joined("/s", ":", "host", nil)}
	ok := []string{"--mailbox", "04030201-0605-0807-090a-0b0c0d0e0f10", "/s:dc01"}
	if err := CheckArgv(tpl, ok); err != nil {
		t.Fatal(err)
	}
	bad := map[string][]string{
		"extra element":        {"--mailbox", ok[1], "/s:dc01", "--evil"},
		"missing element":      {"--mailbox", ok[1]},
		"changed constant":     {"--mailbox2", ok[1], "/s:dc01"},
		"option in slot":       {"--mailbox", "-04030201-0605-0807-090a-0b0c0d0e0f1", "/s:dc01"},
		"en dash in slot":      {"--mailbox", "–4030201-0605-0807-090a-0b0c0d0e0f10", "/s:dc01"},
		"control char":         {"--mailbox", "0403020\n-0605-0807-090a-0b0c0d0e0f10", "/s:dc01"},
		"typed check fails":    {"--mailbox", "x", "/s:dc01"},
		"joined second option": {"--mailbox", ok[1], "/s:dc01 /u:evil"},
		"joined separator":     {"--mailbox", ok[1], "/s:dc01:x"},
		"joined wrong flag":    {"--mailbox", ok[1], "/t:dc01"},
		"empty value":          {"--mailbox", "", "/s:dc01"},
	}
	for name, argv := range bad {
		if err := CheckArgv(tpl, argv); err == nil {
			t.Errorf("%s: accepted %q", name, argv)
		}
	}
}

func TestConstantArgvRunsAndReportsMismatch(t *testing.T) {
	spec := ArgvSpec{
		Impl: "go/x", Requests: 200, Seed: 7,
		Gen:      func(rng *rand.Rand) any { return Mutate(rng, "a'b; c") },
		Template: func(any) []Elem { return []Elem{C("sidecar"), C("--stdio")} },
		Observe:  func(any) ([]string, error) { return []string{"sidecar", "--stdio"}, nil },
	}
	ConstantArgv(t, spec) // a constant argv passes

	if err := CheckArgv(spec.Template(nil), []string{"sidecar", "--stdio", "x"}); err == nil {
		t.Fatal("a request-dependent argv must differ from the manifest")
	}
}

func TestMutateIsDeterministic(t *testing.T) {
	a := Mutate(rand.New(rand.NewSource(3)), "hello")
	b := Mutate(rand.New(rand.NewSource(3)), "hello")
	if a != b {
		t.Fatal("mutation must depend on the seed only")
	}
}
