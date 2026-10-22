package connection

import "testing"

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
