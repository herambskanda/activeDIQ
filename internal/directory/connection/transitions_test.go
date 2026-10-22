package connection

import (
	"regexp"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/migrations"
)

// Acceptance 1: every ordered pair of states is legal exactly when DM-10 declares it.
func TestEveryStatePairAgainstTheDM10Table(t *testing.T) {
	legal := map[[2]State]bool{
		{StateDraft, StateVerifying}:           true, // L2
		{StateVerifying, StateDraft}:           true, // L3
		{StateDraft, StateActive}:              true, // L4
		{StateVerifying, StateActive}:          true, // L4
		{StateActive, StateSuspended}:          true, // L5
		{StateSuspended, StateActive}:          true, // L6
		{StateActive, StateDecommissioning}:    true, // L7
		{StateSuspended, StateDecommissioning}: true, // L7
		{StateDecommissioning, StateRemoved}:   true, // L8
		{StateDraft, StateDiscarded}:           true, // L9
	}
	if len(States()) != 7 {
		t.Fatalf("DM-10 has 7 states, got %d", len(States()))
	}
	n := 0
	for _, from := range States() {
		for _, to := range States() {
			n++
			if got, want := CanTransition(from, to), legal[[2]State{from, to}]; got != want {
				t.Errorf("%s → %s: CanTransition = %v, DM-10 says %v", from, to, got, want)
			}
		}
	}
	if n != 49 || len(Edges()) != len(legal) {
		t.Fatalf("pairs %d, edges %d (want 49 and %d)", n, len(Edges()), len(legal))
	}
}

func TestTerminalStates(t *testing.T) {
	for _, s := range States() {
		want := s == StateRemoved || s == StateDiscarded
		if s.Terminal() != want {
			t.Errorf("%s Terminal = %v, want %v", s, s.Terminal(), want)
		}
	}
	if State("bogus").Valid() || CanTransition("bogus", StateDraft) {
		t.Error("an unknown state must be neither valid nor transitionable")
	}
}

// TestMigrationEdgesMatchTheGoTable keeps the guard trigger's edge list and edges from drifting.
func TestMigrationEdgesMatchTheGoTable(t *testing.T) {
	b, err := migrations.FS.ReadFile("0004_connection_connections.sql")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	i := strings.Index(src, "(OLD.state, NEW.state) NOT IN (")
	if i < 0 {
		t.Fatal("no edge list in the guard trigger")
	}
	list := src[i : i+strings.Index(src[i:], ") THEN")]
	got := map[[2]string]bool{}
	for _, m := range regexp.MustCompile(`\('(\w+)', '(\w+)'\)`).FindAllStringSubmatch(list, -1) {
		got[[2]string{m[1], m[2]}] = true
	}
	if len(got) != len(Edges()) {
		t.Fatalf("SQL lists %d edges, Go declares %d", len(got), len(Edges()))
	}
	for _, e := range Edges() {
		if !got[[2]string{string(e.From), string(e.To)}] {
			t.Errorf("edge %s → %s missing from the guard trigger", e.From, e.To)
		}
	}
}
