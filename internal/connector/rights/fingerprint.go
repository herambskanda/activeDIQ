package rights

import (
	"crypto/sha256"
	"strings"

	"github.com/skenzeriq/activediq/internal/platform/audit/canon"
	v1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// findingFingerprintTag is the DM-24.I4 domain tag. A change to the encoding below is a new tag.
const findingFingerprintTag = "adq-finding/1"

// Fingerprint is DM-24.I4: SHA-256 over the adq-canon/1 encoding of
// ("adq-finding/1", check, code, object, qualifier), where check is the registry name ("V7", "EV3"),
// object is the 16 GUID bytes exactly as the finding carries them (omitted when no object applies)
// and qualifier is the per-kind text of connector contract §8.4 (omitted when empty). The connector
// computes it so the value a Tier0Override acknowledges is the value the write gate compares; the
// server stores it and never recomputes it. The same exposure gets the same value in every run.
func Fingerprint(f *v1.RightsFinding, qualifier string) []byte {
	var e canon.Encoder
	e.String(1, findingFingerprintTag)
	e.String(2, checkName(f.GetCheck()))
	e.String(3, f.GetCode())
	if o := f.GetObject().GetValue(); len(o) > 0 {
		e.Bytes(4, o)
	}
	if qualifier != "" {
		e.String(5, qualifier)
	}
	enc, err := e.Result()
	if err != nil {
		// Unreachable for a registered code: tags ascend and the strings are ASCII. Return no
		// fingerprint; the server refuses a finding without one rather than storing a wrong value.
		return nil
	}
	sum := sha256.Sum256(enc)
	return sum[:]
}

// checkName is the registry name of a check: V7_OVER_PRIVILEGE -> "V7", EV3_OVER_PRIVILEGE -> "EV3".
func checkName(c v1.VerificationCheck) string {
	s := strings.TrimPrefix(c.String(), "VERIFICATION_CHECK_")
	name, _, _ := strings.Cut(s, "_")
	return name
}
