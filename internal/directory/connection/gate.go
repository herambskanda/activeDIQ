package connection

import (
	"slices"
	"time"
)

// FreshnessWindow is how old a verification may be and still open the activation gate (DM-10.I9,
// spec FR-17) or back an override (DM-25.I1).
const FreshnessWindow = 15 * time.Minute

// overPrivilegeFingerprints returns the fingerprints of the run's over-privilege findings: the set an
// override acknowledges whole (DM-25.I1) and the set a later run is compared with (a new finding is
// one not in it).
func overPrivilegeFingerprints(kind Kind, v Verification) []string {
	chk := overPrivilegeCheck(kind)
	var out []string
	for _, f := range v.Findings {
		if f.Check == chk {
			out = append(out, f.Fingerprint)
		}
	}
	slices.Sort(out)
	return out
}

// onlyOverPrivilege reports whether over-privilege is the one thing wrong with a refused run
// (DM-10.I9 (b)): its check failed, no other check failed, and no check could not be answered.
// An override never covers a read-sufficiency failure, an unanswered question or a failed bind
// (TM-D1, spec FR-13).
func onlyOverPrivilege(kind Kind, v Verification) (bool, string) {
	switch v.Verdict {
	case VerdictRefused:
	case VerdictCouldNotVerify:
		return false, ReasonCouldNotVerify
	case VerdictFailed:
		return false, ReasonVerdictFailed
	default: // a pass has nothing to override
		return false, ReasonNotOverridable
	}
	chk := overPrivilegeCheck(kind)
	for c, o := range v.Outcomes {
		if o == OutcomeCouldNotVerify {
			return false, ReasonCouldNotVerify
		}
		if c != chk && o == OutcomeFail {
			return false, ReasonNotOverridable
		}
	}
	if v.Outcomes[chk] != OutcomeFail {
		return false, ReasonNotOverridable
	}
	return true, ""
}

// Qualifies decides DM-10.I9 for a run that is fresh and belongs to the current credential: it
// qualifies if its verdict is pass, or if it is refused for over-privilege alone and every
// over-privilege finding is in the acknowledged set of the override in force (nil for none). The
// second return is the stable refusal reason. It fails closed: anything it does not recognise as a
// pass is a refusal.
//
// The same answer opens the write gate on an active connection (DM-10.I11), which reads it with the
// connection's newest run.
func Qualifies(kind Kind, v Verification, ov *Tier0Override) (bool, string) {
	switch v.Verdict {
	case VerdictPass:
		// Defence in depth for rows already stored: a pass counts only when its over-privilege
		// check is itself a pass (RecordVerification refuses to store one that is not).
		if v.Outcomes[overPrivilegeCheck(kind)] != OutcomePass {
			return false, ReasonVerdictFailed
		}
		return true, ""
	case VerdictFailed:
		return false, ReasonVerdictFailed
	case VerdictCouldNotVerify:
		return false, ReasonCouldNotVerify
	case VerdictRefused:
	default:
		return false, ReasonVerdictFailed
	}
	if ok, why := onlyOverPrivilege(kind, v); !ok {
		return false, why
	}
	fps := overPrivilegeFingerprints(kind, v)
	if ov == nil || len(fps) == 0 {
		return false, ReasonOverPrivileged
	}
	for _, fp := range fps {
		if !slices.Contains(ov.AcknowledgedFingerprints, fp) {
			return false, ReasonNewFinding
		}
	}
	return true, ""
}

// WriteGateOpen is DM-10.I11: the gate for directory writes on an active connection is open only
// when the newest run's over-privilege outcome is pass, or fail with every over-privilege fingerprint
// acknowledged by the override in force. could_not_verify and not_run close it: an unanswered rights
// question fails closed, with no grace period. It reads the over-privilege check alone: a
// read-sufficiency failure stops activation but does not close the write gate. An empty run (nil
// verification) is closed.
func WriteGateOpen(kind Kind, v *Verification, ov *Tier0Override) bool {
	if v == nil {
		return false
	}
	switch v.Outcomes[overPrivilegeCheck(kind)] {
	case OutcomePass:
		return true
	case OutcomeFail:
		fps := overPrivilegeFingerprints(kind, *v)
		if ov == nil || len(fps) == 0 {
			return false
		}
		for _, fp := range fps {
			if !slices.Contains(ov.AcknowledgedFingerprints, fp) {
				return false
			}
		}
		return true
	}
	return false
}
