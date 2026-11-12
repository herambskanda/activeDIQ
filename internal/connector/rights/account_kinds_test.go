package rights

import (
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/accountkind"
	v1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// Each account write kind (T-1583) names rights families that VerifyConnection checks; the families
// must exist in the policy and cover what the connector's modifies write.
func TestAccountKindFamiliesAreCoveredByPolicy(t *testing.T) {
	wp := func(fam v1.RightsFamily, attr string) bool {
		for _, e := range expectations[fam] {
			if e.kind == v1.AdRightKind_AD_RIGHT_KIND_WRITE_PROPERTY && e.attr == attr {
				return true
			}
		}
		return false
	}
	for _, sp := range accountkind.Specs() {
		if len(sp.Families) == 0 {
			t.Errorf("%s names no rights family", sp.Key)
		}
		for _, f := range sp.Families {
			if len(expectations[f]) == 0 {
				t.Errorf("%s: family %v has no expectations", sp.Key, f)
			}
		}
	}
	r4 := v1.RightsFamily_RIGHTS_FAMILY_AD_R4_ACCOUNT_STATE
	for _, a := range []string{"userAccountControl", "lockoutTime", "pwdLastSet"} {
		if !wp(r4, a) {
			t.Errorf("R4 lacks WriteProperty %s", a)
		}
	}
	found := false
	for _, e := range expectations[v1.RightsFamily_RIGHTS_FAMILY_AD_R5_PASSWORD_RESET] {
		found = found || (e.kind == v1.AdRightKind_AD_RIGHT_KIND_CONTROL_ACCESS && e.ext != nil && *e.ext == rightResetPassword)
	}
	if !found {
		t.Error("R5 lacks the Reset Password control right")
	}
}
