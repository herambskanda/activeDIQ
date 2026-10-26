package rights

import (
	"context"
	"errors"
	"testing"

	"github.com/skenzeriq/activediq/internal/connector/tier0"
	adguid "github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
	v1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// TM-D27 rule 8 / T0-RIGHTS-C19: the connector identity holding a rule-2 right on, or owning, a C19
// object refuses activation, naming the object and the right.
func TestC19IdentityRights(t *testing.T) {
	mustSID := func(s string) sid.SID {
		x, err := sid.Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		return x
	}
	const dcOUWP = 0x20
	var gpLink, member, keyCred adguid.GUID
	gpLink[0], member[0], keyCred[0] = 0xA1, 0xA2, 0xA3
	cases := []struct {
		name  string
		right tier0.C19Right
		kind  v1.AdRightKind
		hit   bool
	}{
		{"reset password on krbtgt", tier0.C19Right{Trustee: mustSID(idSIDt), Mask: dsControlAccess, ObjectType: &rightResetPassword}, v1.AdRightKind_AD_RIGHT_KIND_CONTROL_ACCESS, true},
		{"WP msDS-KeyCredentialLink on a DC", tier0.C19Right{Trustee: mustSID(idSIDt), Mask: dcOUWP, ObjectType: &keyCred}, v1.AdRightKind_AD_RIGHT_KIND_WRITE_PROPERTY, true},
		{"WP member on a C1 group via nested group", tier0.C19Right{Trustee: mustSID(nestSID), Mask: dcOUWP, ObjectType: &member}, v1.AdRightKind_AD_RIGHT_KIND_WRITE_PROPERTY, true},
		{"owner of a DC object", tier0.C19Right{Trustee: mustSID(idSIDt), Owner: true}, v1.AdRightKind_AD_RIGHT_KIND_WRITE_DAC, true},
		{"WP gPLink on the DC OU", tier0.C19Right{Trustee: mustSID(idSIDt), Mask: dcOUWP, ObjectType: &gpLink}, v1.AdRightKind_AD_RIGHT_KIND_WRITE_PROPERTY, true},
		{"generic all", tier0.C19Right{Trustee: mustSID(idSIDt), Mask: dsFullControl | 0x10000000}, v1.AdRightKind_AD_RIGHT_KIND_GENERIC_ALL, true},
		{"delete child on the DC OU", tier0.C19Right{Trustee: mustSID(idSIDt), Mask: 0x2}, v1.AdRightKind_AD_RIGHT_KIND_DELETE_CHILD, true},
		{"someone else's right", tier0.C19Right{Trustee: mustSID(daSID), Mask: dsControlAccess}, 0, false},
		{"someone else owns it", tier0.C19Right{Trustee: mustSID(daSID), Owner: true}, 0, false},
		{"authenticated users hold WP member (token SID)", tier0.C19Right{Trustee: mustSID("S-1-5-11"), Mask: dcOUWP, ObjectType: &member}, v1.AdRightKind_AD_RIGHT_KIND_WRITE_PROPERTY, true},
		{"everyone holds WP member (token SID)", tier0.C19Right{Trustee: mustSID("S-1-1-0"), Mask: dcOUWP, ObjectType: &member}, v1.AdRightKind_AD_RIGHT_KIND_WRITE_PROPERTY, true},
		{"interactive holds a C19 right (token SID)", tier0.C19Right{Trustee: mustSID("S-1-5-4"), Mask: dsControlAccess}, v1.AdRightKind_AD_RIGHT_KIND_CONTROL_ACCESS, true},
		{"network holds a C19 right (not in tokenGroups)", tier0.C19Right{Trustee: mustSID("S-1-5-2"), Mask: dsControlAccess}, v1.AdRightKind_AD_RIGHT_KIND_CONTROL_ACCESS, true},
		{"this organization holds a C19 right (not in tokenGroups)", tier0.C19Right{Trustee: mustSID("S-1-5-15"), Mask: dsControlAccess}, v1.AdRightKind_AD_RIGHT_KIND_CONTROL_ACCESS, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			// Realistic token: real tokenGroups never lists Everyone / Authenticated Users / NETWORK.
			w.tokens = []string{dusSID, "S-1-5-32-545", nestSID}
			w.f.schemaAttr("gPLink", 0)
			tc.right.Object = w.t0G
			w.set.AddC19Right(tc.right)
			r := w.run(t, ADInput{})
			n := count(r, CodeTier0C19)
			if !tc.hit {
				if n != 0 || r.Verdict != v1.VerificationVerdict_VERIFICATION_VERDICT_PASS {
					t.Fatalf("%v %v", r.Verdict, codes(r))
				}
				return
			}
			if n != 1 || r.Verdict != v1.VerificationVerdict_VERIFICATION_VERDICT_REFUSED || r.WriteGateOpenable {
				t.Fatalf("%v %v", r.Verdict, codes(r))
			}
			var f Finding
			for _, x := range r.Findings {
				if x.Code == CodeTier0C19 {
					f = x
				}
			}
			if f.Severity != v1.FindingSeverity_FINDING_SEVERITY_BLOCK || f.Object == nil || len(f.Object.Value) != 16 {
				t.Fatalf("finding does not name the object: %+v", f.RightsFinding)
			}
			if got := f.Right.GetAd().GetKind(); got != tc.kind {
				t.Fatalf("right %v, want %v", got, tc.kind)
			}
		})
	}
}

// A C19 DACL or owner read that fails fails the snapshot, and the check refuses to pass (FR-11).
func TestC19SnapshotFailureFailsClosed(t *testing.T) {
	w := newWorld(t)
	w.setTokens()
	ref := w.idRef(t)
	r, err := VerifyAD(context.Background(), w.f, ADInput{Identity: ref,
		Snapshot: func(context.Context) (*tier0.ADSet, error) {
			return nil, errors.New("tier0: a Tier-0 object has no readable security descriptor")
		}})
	if err != nil {
		t.Fatal(err)
	}
	if r.Verdict == v1.VerificationVerdict_VERIFICATION_VERDICT_PASS || r.WriteGateOpenable {
		t.Fatalf("passed: %v", codes(r))
	}
}
