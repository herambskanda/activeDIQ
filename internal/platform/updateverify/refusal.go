package updateverify

import (
	"fmt"
	"time"
)

// Reason is the closed set of refusal reasons; it equals the audit reasons of spec section 8
// (update.refused).
type Reason string

const (
	ReasonTamper         Reason = "tamper"
	ReasonRollback       Reason = "rollback"
	ReasonFreeze         Reason = "freeze"
	ReasonRevokedKey     Reason = "revoked_key"
	ReasonUnsignedByRoot Reason = "unsigned_by_root"
	ReasonWithdrawn      Reason = "withdrawn"
)

// Reasons lists the closed enum.
func Reasons() []Reason {
	return []Reason{ReasonTamper, ReasonRollback, ReasonFreeze, ReasonRevokedKey, ReasonUnsignedByRoot, ReasonWithdrawn}
}

// Refusal is returned (as error) whenever an update must not be installed for a security reason.
// Detail is a short machine-readable hint; it never carries metadata or artefact content.
type Refusal struct {
	Reason Reason
	// Role is the metadata role involved ("root", "timestamp", "snapshot", "targets", "artefact"), if any.
	Role   string
	Detail string
	// Expiry is set for freeze caused by expired metadata, so the console can say "stale since ...".
	Expiry time.Time
}

func (r *Refusal) Error() string {
	s := "updateverify: refused (" + string(r.Reason) + ")"
	if r.Role != "" {
		s += " " + r.Role
	}
	if r.Detail != "" {
		s += ": " + r.Detail
	}
	return s
}

func refuse(reason Reason, role, detail string) *Refusal {
	return &Refusal{Reason: reason, Role: role, Detail: detail}
}

func refusef(reason Reason, role, format string, a ...any) *Refusal {
	return &Refusal{Reason: reason, Role: role, Detail: fmt.Sprintf(format, a...)}
}
