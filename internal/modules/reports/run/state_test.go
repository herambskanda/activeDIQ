package run_test

import (
	"regexp"
	"slices"
	"sort"
	"testing"

	"github.com/skenzeriq/activediq/internal/modules/reports/run"
	"github.com/skenzeriq/activediq/migrations"
)

// checkList reads the quoted values of `<column> text ... CHECK (<column> IN (...))` from the migration.
func checkList(t *testing.T, column string) []string {
	t.Helper()
	b, err := migrations.FS.ReadFile("0063_reports_runs.sql")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`(?s)` + column + ` text (?:NOT NULL )?CHECK \(` + column + ` IN \((.*?)\)\)`)
	m := re.FindSubmatch(b)
	if m == nil {
		t.Fatalf("no CHECK list for %s in 0063", column)
	}
	var out []string
	for _, v := range regexp.MustCompile(`'([a-z_]+)'`).FindAllSubmatch(m[1], -1) {
		out = append(out, string(v[1]))
	}
	sort.Strings(out)
	return out
}

func TestGoConstantsEqualTheCheckLists(t *testing.T) {
	var states, reasons []string
	for _, s := range run.States {
		states = append(states, string(s))
	}
	for _, r := range run.FailureReasons {
		reasons = append(reasons, string(r))
	}
	sort.Strings(states)
	sort.Strings(reasons)
	if got := checkList(t, "state"); !slices.Equal(got, states) {
		t.Errorf("state CHECK %v != Go %v", got, states)
	}
	if got := checkList(t, "failure_reason"); !slices.Equal(got, reasons) {
		t.Errorf("failure_reason CHECK %v != Go %v", got, reasons)
	}
}

func TestStateEdges(t *testing.T) {
	want := map[[2]run.State]bool{
		{run.StateQueued, run.StateRunning}: true, {run.StateQueued, run.StateCancelled}: true, {run.StateQueued, run.StateFailed}: true,
		{run.StateRunning, run.StateSucceeded}: true, {run.StateRunning, run.StateFailed}: true, {run.StateRunning, run.StateCancelled}: true,
		{run.StateSucceeded, run.StateExpired}: true,
	}
	for _, a := range run.States {
		for _, b := range run.States {
			if got := a.CanMoveTo(b); got != want[[2]run.State{a, b}] {
				t.Errorf("%s -> %s = %v", a, b, got)
			}
		}
	}
	for _, s := range []run.State{run.StateFailed, run.StateCancelled, run.StateExpired} {
		if !s.Final() || !s.Terminal() {
			t.Errorf("%s should be final", s)
		}
	}
}
