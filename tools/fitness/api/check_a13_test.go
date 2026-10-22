package main

import "testing"

// A13 host-binding and served-route fixtures (T-0018).
func init() { fixtures = append(fixtures, a13Fixtures...) }

const tmAN5 = "| AN-1 | Health | x | None |\n| AN-2 | Static | x | None |\n| AN-5 | Enrolment | x | None |\n"

var a13Fixtures = []fixture{
	{"host binding that apihost does not declare", "A13", func(f map[string]string) {
		repl(f, pol, "    path: /healthz\n", "    path: /healthz\n    host: no-such-binding\n")
	}, pol, "is not in apihost's binding table"},
	{"host binding justified by another AN row", "A13", func(f map[string]string) {
		repl(f, pol, "    path: /healthz\n", "    path: /healthz\n    host: totp-enrolment\n")
	}, pol, "is justified by AN-5"},
}

func TestA13AcceptsADeclaredHostBinding(t *testing.T) {
	f := base()
	repl(f, pol, "    path: /healthz\n    ref: AN-1\n", "    path: /healthz\n    host: totp-enrolment\n    ref: AN-5\n")
	f["knowledge/development/architecture/threat-model.md"] = tmAN5
	for _, v := range run(t, f) {
		if v.Check == "A13" {
			t.Errorf("a binding in the table with its own AN row must pass: %s", v)
		}
	}
}

func TestA13MatchesRoutesOutsideTheDocumentToTheServedSet(t *testing.T) {
	old := nonAPIServedSource
	t.Cleanup(func() { nonAPIServedSource = old })
	// Nothing mounted: not checked, and the status line says so.
	for _, v := range run(t, base()) {
		if v.Check == "A13" {
			t.Fatalf("with no server mounting routes, entries are not failed on a guess: %s", v)
		}
	}
	// A server that mounts /readyz only: the anonymous /healthz and the nonApiRoutes entry differ.
	nonAPIServedSource = func(string) ([]string, bool) { return []string{"GET /readyz"}, true }
	var got []string
	for _, v := range run(t, base()) {
		if v.Check == "A13" {
			got = append(got, v.Msg)
		}
	}
	if len(got) != 1 {
		t.Fatalf("want exactly the anonymous GET /healthz reported stale, got %v", got)
	}
}
