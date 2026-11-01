package audit_test

import (
	"errors"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
)

const vGUID = "11111111-1111-4111-8111-111111111111"

func validateEvent(class string) audit.Event {
	return audit.Event{
		ID: "e1", Kind: "x.y", At: time.Unix(1, 0), Outcome: audit.Success,
		Actor:   authority.Chain{Requester: authority.Principal{ID: "alice", Kind: authority.Human}},
		Target:  authority.TargetRef{Connection: vGUID, GUID: vGUID, Class: class},
		Changes: []audit.Change{{Attribute: "state", After: []string{"active"}}},
	}
}

// A connection (or Entra tenant) names itself as Connection and GUID; that is not a personal subject.
func TestValidateConnectionTargetIsNotPersonal(t *testing.T) {
	for _, c := range []string{"connection", "entra_tenant"} {
		if err := validateEvent(c).Validate(); err != nil {
			t.Fatalf("%s target with unsubjected changes: %v", c, err)
		}
	}
}

// A directory-object event with the same unsubjected value changes is still refused.
func TestValidateDirectoryObjectStillNeedsSubject(t *testing.T) {
	if err := validateEvent("user").Validate(); !errors.Is(err, audit.ErrInvalidEvent) {
		t.Fatalf("directory object with unsubjected changes: got %v, want ErrInvalidEvent", err)
	}
}
