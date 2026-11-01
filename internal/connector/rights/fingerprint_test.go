package rights

import (
	"bytes"
	"testing"

	v1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

func TestCheckName(t *testing.T) {
	for c, want := range map[v1.VerificationCheck]string{
		v1.VerificationCheck_VERIFICATION_CHECK_V7_OVER_PRIVILEGE:   "V7",
		v1.VerificationCheck_VERIFICATION_CHECK_V8_READ_SUFFICIENCY: "V8",
		v1.VerificationCheck_VERIFICATION_CHECK_EV3_OVER_PRIVILEGE:  "EV3",
	} {
		if got := checkName(c); got != want {
			t.Errorf("checkName(%v) = %q, want %q", c, got, want)
		}
	}
}

func TestFingerprintRecipe(t *testing.T) {
	base := func() *v1.RightsFinding {
		return &v1.RightsFinding{Check: v7, Code: CodeTier0Group, Object: pbGuid(guidN(1))}
	}
	fp := Fingerprint(base(), "q1")
	if len(fp) != 32 {
		t.Fatalf("len %d", len(fp))
	}
	if !bytes.Equal(fp, Fingerprint(base(), "q1")) {
		t.Fatal("not deterministic")
	}
	// Fields outside the recipe (severity, source, tier0 basis) do not move it.
	other := base()
	other.Severity = v1.FindingSeverity_FINDING_SEVERITY_WARN
	if !bytes.Equal(fp, Fingerprint(other, "q1")) {
		t.Fatal("severity is not part of the recipe")
	}
	// Each recipe input does.
	diff := map[string][]byte{"qualifier": Fingerprint(base(), "q2"), "no qualifier": Fingerprint(base(), "")}
	c := base()
	c.Code = "over.tier0_write"
	diff["code"] = Fingerprint(c, "q1")
	c = base()
	c.Check = v8
	diff["check"] = Fingerprint(c, "q1")
	c = base()
	c.Object = pbGuid(guidN(2))
	diff["object"] = Fingerprint(c, "q1")
	c = base()
	c.Object = nil
	diff["no object"] = Fingerprint(c, "q1")
	seen := map[string]string{string(fp): "base"}
	for name, d := range diff {
		if len(d) != 32 {
			t.Fatalf("%s: len %d", name, len(d))
		}
		if prev, dup := seen[string(d)]; dup {
			t.Errorf("%s collides with %s", name, prev)
		}
		seen[string(d)] = name
	}
}

// Every finding a run returns has a fingerprint and no two EXCESSIVE or tier0-membership findings
// share one: the server refuses a run that repeats a fingerprint ("duplicate fingerprint").
func TestEveryFindingHasAUniqueFingerprintForExposures(t *testing.T) {
	c := &adCheck{}
	obj := guidN(4)
	for range 3 { // the same exposure reported by three ACEs
		c.add(&v1.RightsFinding{Check: v7, Kind: v1.FindingKind_FINDING_KIND_EXCESSIVE_RIGHT, Code: "over.tier0_c19_control"}, obj, "c19:S-1-5-32-544:000f01bd")
	}
	c.add(&v1.RightsFinding{Check: v7, Kind: v1.FindingKind_FINDING_KIND_EXCESSIVE_RIGHT, Code: "over.tier0_c19_control"}, obj, "c19:S-1-5-32-544:000f01ff")
	if len(c.out) != 2 {
		t.Fatalf("%d findings, want the 2 distinct exposures", len(c.out))
	}
	for _, f := range c.out {
		if len(f.Fingerprint) != 32 {
			t.Errorf("finding %s has no fingerprint", f.Code)
		}
	}
}
