package main

import (
	"context"
	"strings"
	"testing"
)

func ev(action, test string) string {
	return `{"Action":"` + action + `","Package":"p","Test":"` + test + `"}` + "\n"
}

func fake(out string) func(context.Context, string, string, []string) ([]byte, error) {
	return func(context.Context, string, string, []string) ([]byte, error) { return []byte(out), nil }
}

func TestBindings(t *testing.T) {
	bs := []binding{{"A5", "tamper", "./p", []string{"TestA", "TestB"}}}
	cases := []struct {
		name, out, want string
	}{
		{"all pass", ev("pass", "TestA") + ev("pass", "TestB"), ""},
		{"one fails", ev("pass", "TestA") + ev("fail", "TestB"), "A5 ./p TestB [test-failed]"},
		{"one missing", ev("pass", "TestA"), "A5 ./p TestB [test-missing]"},
		{"one skipped", ev("pass", "TestA") + ev("skip", "TestB"), "A5 ./p TestB [test-skipped]"},
		{"subtest skipped", ev("skip", "TestA/pg16") + ev("pass", "TestA") + ev("pass", "TestB"), "A5 ./p TestA [test-skipped]"},
		{"build failure", `{"Action":"output","Package":"p","Output":"undefined: x\n"}` + "\n", "undefined: x"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			vs, err := runBindings(context.Background(), ".", bs, fake(c.out))
			if err != nil {
				t.Fatal(err)
			}
			var all []string
			for _, v := range vs {
				all = append(all, v.String())
			}
			got := strings.Join(all, "\n")
			if c.want == "" && got != "" || !strings.Contains(got, c.want) {
				t.Fatalf("want %q, got %q", c.want, got)
			}
		})
	}
}

// The default bindings name only audit checks that exist, and every one of A2, A3, A5, A6 and A9 is bound.
func TestDefaultBindingsCoverTheBoundChecks(t *testing.T) {
	seen := map[string]bool{}
	for _, b := range defaultBindings {
		seen[b.Check] = true
		if len(b.Tests) == 0 {
			t.Errorf("%s: binding %q has no tests", b.Check, b.What)
		}
	}
	for _, k := range []string{"A2", "A3", "A5", "A6", "A9"} {
		if !seen[k] {
			t.Errorf("%s is not bound to any test", k)
		}
	}
}
