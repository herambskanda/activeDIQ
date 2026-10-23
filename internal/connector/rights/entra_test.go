package rights_test

import (
	"context"
	"crypto/sha1" //nolint:gosec // certificate thumbprints are SHA-1 by definition
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/connector/graph"
	"github.com/skenzeriq/activediq/internal/connector/graph/graphtest"
	"github.com/skenzeriq/activediq/internal/connector/rights"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	v1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

const (
	tenantID = "11111111-1111-1111-1111-111111111111"
	clientID = "22222222-2222-2222-2222-222222222222"
	spID     = "33333333-3333-3333-3333-333333333333"
	appObj   = "44444444-4444-4444-4444-444444444444"
	graphSP  = "55555555-5555-5555-5555-555555555555"
)

// permissions the baseline (read-only connection) needs: all granted in the correct setup.
var baseline = []string{"Organization.Read.All", "User.Read.All", "GroupMember.Read.All", "Directory.Read.All", "RoleManagement.Read.Directory"}

func gid(n int) string { return fmt.Sprintf("77777777-7777-7777-7777-%012d", n) }

type rig struct {
	t     *testing.T
	srv   *graphtest.Server
	c     *graph.Client
	thumb []byte
	n     int
}

// newRig starts a fake tenant whose app holds exactly the given Graph permissions, one certificate
// (the held one), no roles, no owners.
func newRig(t *testing.T, perms ...string) *rig {
	t.Helper()
	cred := graphtest.NewCredential(t)
	sum := sha1.Sum(cred.Cert.Raw) //nolint:gosec
	tn := &graphtest.Tenant{
		TenantID: tenantID, ClientID: clientID, SPID: spID, AppObjectID: appObj,
		ServicePrincipals: map[string]graph.ServicePrincipal{spID: {ID: spID, AppID: clientID, DisplayName: "activeDIQ"}},
		Assignments:       map[string][]graph.AppRoleAssignment{},
		KeyCredentials:    []graph.KeyCredential{{KeyID: gid(900), CustomKeyIdentifier: sum[:], Key: cred.Cert.Raw, Type: "AsymmetricX509Cert", Usage: "Verify"}},
		Owners:            map[string][]graph.DirectoryObject{},
	}
	srv := graphtest.New(t, tn, cred)
	c, err := graph.New(srv.Config(cred))
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{t: t, srv: srv, c: c, thumb: sum[:]}
	tn.ServicePrincipals[graphSP] = graph.ServicePrincipal{ID: graphSP, AppID: rights.GraphResourceAppID, DisplayName: "Microsoft Graph"}
	for _, p := range perms {
		r.grant(p)
	}
	return r
}

func (r *rig) grant(perm string) string {
	r.n++
	roleID := gid(1000 + r.n)
	tn := r.srv.T
	g := tn.ServicePrincipals[graphSP]
	g.AppRoles = append(g.AppRoles, graph.AppRole{ID: roleID, Value: perm})
	tn.ServicePrincipals[graphSP] = g
	aid := gid(2000 + r.n)
	tn.Assignments[spID] = append(tn.Assignments[spID], graph.AppRoleAssignment{ID: aid, AppRoleID: roleID, PrincipalID: spID, ResourceID: graphSP})
	return roleID
}

func (r *rig) verify(families ...v1.RightsFamily) *rights.Result {
	r.t.Helper()
	res, err := rights.VerifyEntra(context.Background(), r.c, rights.EntraInput{EnabledFamilies: families, HeldThumbprint: r.thumb, Now: func() time.Time { return time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC) }})
	if err != nil {
		r.t.Fatal(err)
	}
	return res
}

func byKind(res *rights.Result, k v1.FindingKind) []rights.Finding {
	var out []rights.Finding
	for _, f := range res.Findings {
		if f.Kind == k {
			out = append(out, f)
		}
	}
	return out
}

func permValue(f rights.Finding) string { return f.Right.GetEntra().GetAppPermission().GetValue() }

func TestCorrectlyGrantedAppPasses(t *testing.T) { // AC5
	r := newRig(t, append(append([]string{}, baseline...), "User.Create", "Group.Create")...)
	res := r.verify(v1.RightsFamily_RIGHTS_FAMILY_ENTRA_USER_CREATE, v1.RightsFamily_RIGHTS_FAMILY_ENTRA_GROUP_CREATE)
	if res.Verdict != v1.VerificationVerdict_VERIFICATION_VERDICT_PASS || !res.WriteGateOpenable || len(res.Findings) != 0 {
		t.Fatalf("verdict %v gate %v findings %v", res.Verdict, res.WriteGateOpenable, res.Findings)
	}
	for _, c := range res.Checks {
		if c.Outcome != v1.CheckOutcome_CHECK_OUTCOME_PASS {
			t.Fatalf("check %v = %v", c.Check, c.Outcome)
		}
	}
	if res.Identity.GetServicePrincipalId() == nil || res.Identity.GetApplicationObjectId() == nil {
		t.Fatal("identity not reported")
	}
}

// concreteDeny expands the '*' in each deny pattern with a plausible concrete suffix or prefix.
func concreteDeny() []string {
	var out []string
	for _, p := range rights.DenyPatterns() {
		switch {
		case strings.HasPrefix(p, "*"):
			for _, k := range []string{"User", "Group", "OrgContact"} {
				out = append(out, k+p[1:])
			}
		case strings.HasSuffix(p, ".*"):
			for _, s := range []string{"All", "Directory", "AzureADGroup"} {
				out = append(out, strings.TrimSuffix(p, "*")+s)
			}
		default:
			out = append(out, p)
		}
	}
	return out
}

func TestEveryDenyListPermissionRefuses(t *testing.T) { // AC1
	deny := concreteDeny()
	for _, must := range []string{"Directory.ReadWrite.All", "RoleManagement.ReadWrite.Directory", "AppRoleAssignment.ReadWrite.All"} {
		found := false
		for _, d := range deny {
			found = found || d == must
		}
		if !found {
			t.Fatalf("%s missing from the deny list", must)
		}
	}
	for _, perm := range deny {
		t.Run(perm, func(t *testing.T) {
			r := newRig(t, baseline...)
			roleID := r.grant(perm)
			res := r.verify()
			if res.Verdict != v1.VerificationVerdict_VERIFICATION_VERDICT_REFUSED || res.WriteGateOpenable {
				t.Fatalf("verdict %v gate %v", res.Verdict, res.WriteGateOpenable)
			}
			fs := byKind(res, v1.FindingKind_FINDING_KIND_ENTRA_DENY_LIST_PERMISSION)
			if len(fs) != 1 || permValue(fs[0]) != perm {
				t.Fatalf("findings = %v", res.Findings)
			}
			f := fs[0]
			if f.Severity != v1.FindingSeverity_FINDING_SEVERITY_BLOCK || f.Check != v1.VerificationCheck_VERIFICATION_CHECK_EV3_OVER_PRIVILEGE {
				t.Fatalf("finding %v", f)
			}
			if f.Qualifier != roleID {
				t.Fatalf("qualifier %q, want the app role id %q", f.Qualifier, roleID)
			}
			if f.Source.GetEntraAssignment() == nil || f.Object == nil {
				t.Fatalf("source/object unset: %v", f)
			}
			// A deny-list permission is never also reported as merely extra.
			if len(byKind(res, v1.FindingKind_FINDING_KIND_EXCESSIVE_RIGHT)) != 0 {
				t.Fatalf("deny-list permission double reported: %v", res.Findings)
			}
		})
	}
}

func TestDenyListMatching(t *testing.T) {
	for v, want := range map[string]bool{
		"directory.readwrite.all":                         true, // case-insensitive
		"Policy.ReadWrite.ConditionalAccess":              true,
		"PrivilegedAccess.ReadWrite.AzureResources":       true,
		"Policy.Read.All":                                 false,
		"Directory.Read.All":                              false,
		"User.ReadWrite.All":                              false, // allowed, feature-gated
		"Group.ReadWrite.All":                             false,
		"User-OnPremisesSyncBehavior.ReadWrite.All":       true,
		"OrgContact-OnPremisesSyncBehavior.ReadWrite.All": true,
		"": false,
	} {
		if got := rights.DenyListed(v); got != want {
			t.Errorf("DenyListed(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestAnyDirectoryRoleRefuses(t *testing.T) { // AC2
	for _, eligible := range []bool{false, true} {
		t.Run(fmt.Sprintf("eligible=%v", eligible), func(t *testing.T) {
			r := newRig(t, baseline...)
			def := gid(3000)
			r.srv.T.Roles = []graph.RoleAssignment{
				{ID: gid(3001), PrincipalID: spID, RoleDefinitionID: def, DirectoryScopeID: "/", Eligible: eligible, Role: graph.RoleDefinition{ID: def, DisplayName: "Directory Readers"}},
				{ID: gid(3002), PrincipalID: gid(1), RoleDefinitionID: def, DirectoryScopeID: "/", Role: graph.RoleDefinition{ID: def}}, // someone else's
			}
			res := r.verify()
			fs := byKind(res, v1.FindingKind_FINDING_KIND_ENTRA_DIRECTORY_ROLE)
			if res.Verdict != v1.VerificationVerdict_VERIFICATION_VERDICT_REFUSED || len(fs) != 1 {
				t.Fatalf("verdict %v findings %v", res.Verdict, res.Findings)
			}
			role := fs[0].Right.GetEntra().GetDirectoryRole()
			wantKind := v1.EntraRoleAssignmentKind_ENTRA_ROLE_ASSIGNMENT_KIND_ACTIVE
			if eligible {
				wantKind = v1.EntraRoleAssignmentKind_ENTRA_ROLE_ASSIGNMENT_KIND_ELIGIBLE
			}
			if role.Assignment != wantKind || role.DirectoryScopeId != "/" || fs[0].Severity != v1.FindingSeverity_FINDING_SEVERITY_BLOCK {
				t.Fatalf("role finding %v", fs[0])
			}
		})
	}
}

func TestExtraAndMissingPermissionsReported(t *testing.T) { // AC3
	// Granted: baseline minus User.Read.All, plus Group.Create (family not enabled) and an
	// unrelated Graph permission. Enabled: USER_CREATE, which is not granted.
	var perms []string
	for _, p := range baseline {
		if p != "User.Read.All" {
			perms = append(perms, p)
		}
	}
	perms = append(perms, "Group.Create", "Mail.Read")
	r := newRig(t, perms...)
	res := r.verify(v1.RightsFamily_RIGHTS_FAMILY_ENTRA_USER_CREATE)

	extra := map[string]bool{}
	for _, f := range byKind(res, v1.FindingKind_FINDING_KIND_EXCESSIVE_RIGHT) {
		extra[permValue(f)] = true
		if f.Severity != v1.FindingSeverity_FINDING_SEVERITY_WARN || f.Check != v1.VerificationCheck_VERIFICATION_CHECK_EV5_EXCESS {
			t.Fatalf("extra finding %v", f)
		}
	}
	if len(extra) != 2 || !extra["Group.Create"] || !extra["Mail.Read"] {
		t.Fatalf("extra = %v", extra)
	}
	missing := map[string]rights.Finding{}
	for _, f := range byKind(res, v1.FindingKind_FINDING_KIND_MISSING_RIGHT) {
		missing[permValue(f)] = f
		if f.Check != v1.VerificationCheck_VERIFICATION_CHECK_EV4_SUFFICIENCY {
			t.Fatalf("missing finding %v", f)
		}
	}
	if len(missing) != 2 {
		t.Fatalf("missing = %v", res.Findings)
	}
	// User.Read.All is a read row the connection cannot work without: block. User.Create is a write row: warn.
	if missing["User.Read.All"].Severity != v1.FindingSeverity_FINDING_SEVERITY_BLOCK ||
		missing["User.Create"].Severity != v1.FindingSeverity_FINDING_SEVERITY_WARN ||
		missing["User.Create"].Family != v1.RightsFamily_RIGHTS_FAMILY_ENTRA_USER_CREATE ||
		missing["User.Create"].Source.GetExpectedBy() != v1.RightsFamily_RIGHTS_FAMILY_ENTRA_USER_CREATE {
		t.Fatalf("missing = %v", missing)
	}
	if res.Verdict != v1.VerificationVerdict_VERIFICATION_VERDICT_REFUSED {
		t.Fatalf("a missing blocking read row must refuse: %v", res.Verdict)
	}
}

func TestMissingWriteRowOnlyWarns(t *testing.T) {
	r := newRig(t, baseline...)
	res := r.verify(v1.RightsFamily_RIGHTS_FAMILY_ENTRA_GROUP_CREATE)
	if res.Verdict != v1.VerificationVerdict_VERIFICATION_VERDICT_PASS || len(res.Findings) != 1 ||
		res.Checks[1].Outcome != v1.CheckOutcome_CHECK_OUTCOME_WARN {
		t.Fatalf("verdict %v findings %v checks %v", res.Verdict, res.Findings, res.Checks)
	}
}

func TestAlternativeSatisfiesNeed(t *testing.T) {
	// Organization.Read.All also covers subscribedSkus, so SKU_READ is met without LicenseAssignment.Read.All.
	r := newRig(t, baseline...)
	res := r.verify(v1.RightsFamily_RIGHTS_FAMILY_ENTRA_SKU_READ)
	if len(res.Findings) != 0 {
		t.Fatalf("findings = %v", res.Findings)
	}
}

func TestPermissionOnAnotherResourceSatisfiesNothing(t *testing.T) {
	r := newRig(t, baseline...)
	// Re-home User.Read.All's grant onto a non-Graph resource.
	other := gid(4000)
	tn := r.srv.T
	tn.ServicePrincipals[other] = graph.ServicePrincipal{ID: other, AppID: "99999999-9999-9999-9999-999999999999",
		AppRoles: []graph.AppRole{{ID: gid(4001), Value: "User.Read.All"}}}
	tn.Assignments[spID] = append(tn.Assignments[spID], graph.AppRoleAssignment{ID: gid(4002), AppRoleID: gid(4001), PrincipalID: spID, ResourceID: other})
	g := tn.ServicePrincipals[graphSP]
	var kept []graph.AppRole
	for _, ar := range g.AppRoles {
		if ar.Value != "User.Read.All" {
			kept = append(kept, ar)
		}
	}
	g.AppRoles = kept
	tn.ServicePrincipals[graphSP] = g
	var as []graph.AppRoleAssignment
	for _, a := range tn.Assignments[spID] {
		if a.AppRoleID != "" && !roleIs(kept, a.AppRoleID) && a.ResourceID == graphSP {
			continue
		}
		as = append(as, a)
	}
	tn.Assignments[spID] = as
	res := r.verify()
	if res.Verdict != v1.VerificationVerdict_VERIFICATION_VERDICT_REFUSED {
		t.Fatalf("verdict %v findings %v", res.Verdict, res.Findings)
	}
}

func roleIs(roles []graph.AppRole, id string) bool {
	for _, r := range roles {
		if r.ID == id {
			return true
		}
	}
	return false
}

func TestExtraKeyCredentialsSecretsAndOwnersFlagged(t *testing.T) { // AC4
	r := newRig(t, baseline...)
	tn := r.srv.T
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	tn.KeyCredentials = append(tn.KeyCredentials, graph.KeyCredential{KeyID: gid(901), CustomKeyIdentifier: []byte("attacker-thumb"), Type: "AsymmetricX509Cert", StartDateTime: now, EndDateTime: now.Add(24 * time.Hour)})
	sp := tn.ServicePrincipals[spID]
	sp.KeyCredentials = []graph.KeyCredential{{KeyID: gid(902), CustomKeyIdentifier: r.thumb, Key: r.srv.T.KeyCredentials[0].Key, Type: "AsymmetricX509Cert"}} // even the held thumbprint is extra here
	sp.PasswordCredentials = []graph.PasswordCredential{{KeyID: gid(903), StartDateTime: now, EndDateTime: now.Add(time.Hour)}}
	tn.ServicePrincipals[spID] = sp
	// 904 has no end and 905 starts in the future: both unexpired at the test clock.
	tn.PasswordCredentials = []graph.PasswordCredential{{KeyID: gid(904)},
		{KeyID: gid(905), StartDateTime: now.AddDate(1, 0, 0), EndDateTime: now.AddDate(2, 0, 0)}}
	tn.Owners[appObj] = []graph.DirectoryObject{{ID: gid(10), ODataType: "#microsoft.graph.user"}}
	tn.Owners[spID] = []graph.DirectoryObject{{ID: gid(11), ODataType: "#microsoft.graph.user"}}

	res := r.verify()
	if res.Verdict != v1.VerificationVerdict_VERIFICATION_VERDICT_REFUSED {
		t.Fatalf("an unexpired password credential refuses (EV3): %v", res.Verdict)
	}
	holders := map[string]v1.EntraCredentialHolder{}
	for _, f := range byKind(res, v1.FindingKind_FINDING_KIND_ENTRA_EXTRA_KEY_CREDENTIAL) {
		k := f.Right.GetEntra().GetKeyCredential()
		holders[f.Qualifier] = k.Holder
		wantObj := appObj
		if k.Holder == v1.EntraCredentialHolder_ENTRA_CREDENTIAL_HOLDER_SERVICE_PRINCIPAL {
			wantObj = spID
		}
		if !guidEq(f.Object, wantObj) || f.Severity != v1.FindingSeverity_FINDING_SEVERITY_WARN {
			t.Fatalf("key finding %v", f)
		}
	}
	if len(holders) != 2 || holders[gid(901)] != v1.EntraCredentialHolder_ENTRA_CREDENTIAL_HOLDER_APPLICATION ||
		holders[gid(902)] != v1.EntraCredentialHolder_ENTRA_CREDENTIAL_HOLDER_SERVICE_PRINCIPAL {
		t.Fatalf("holders = %v", holders)
	}
	pw := map[string]v1.FindingSeverity{}
	for _, f := range byKind(res, v1.FindingKind_FINDING_KIND_ENTRA_PASSWORD_CREDENTIAL) {
		pw[f.Qualifier] = f.Severity
		wantCheck := ev3check
		if f.Severity == v1.FindingSeverity_FINDING_SEVERITY_WARN {
			wantCheck = v1.VerificationCheck_VERIFICATION_CHECK_EV5_EXCESS
		}
		if f.Check != wantCheck {
			t.Fatalf("password finding %s: check %v severity %v", f.Qualifier, f.Check, f.Severity)
		}
	}
	block, warn := v1.FindingSeverity_FINDING_SEVERITY_BLOCK, v1.FindingSeverity_FINDING_SEVERITY_WARN
	if len(pw) != 3 || pw[gid(903)] != warn || pw[gid(904)] != block || pw[gid(905)] != block {
		t.Fatalf("password credential severities = %v", pw)
	}
	owners := map[string]bool{}
	for _, f := range byKind(res, v1.FindingKind_FINDING_KIND_ENTRA_OWNER) {
		owners[f.Qualifier] = true
	}
	if len(owners) != 2 || !owners[gid(10)] || !owners[gid(11)] {
		t.Fatalf("owners = %v", owners)
	}
	if res.Checks[2].Outcome != v1.CheckOutcome_CHECK_OUTCOME_WARN {
		t.Fatalf("EV5 = %v", res.Checks[2].Outcome)
	}
}

const ev3check = v1.VerificationCheck_VERIFICATION_CHECK_EV3_OVER_PRIVILEGE

func guidEq(g *v1.Guid, text string) bool {
	if g == nil || len(g.Value) != 16 {
		return false
	}
	var s string
	for i, b := range g.Value {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			s += "-"
		}
		s += fmt.Sprintf("%02x", b)
	}
	return s == text
}

func TestHeldCertificateAloneIsNotFlagged(t *testing.T) {
	r := newRig(t, baseline...)
	if res := r.verify(); len(res.Findings) != 0 {
		t.Fatalf("findings = %v", res.Findings)
	}
	// With no thumbprint held, nothing can be called "the held one": every credential is extra.
	res, err := rights.VerifyEntra(context.Background(), r.c, rights.EntraInput{})
	if err != nil || len(byKind(res, v1.FindingKind_FINDING_KIND_ENTRA_EXTRA_KEY_CREDENTIAL)) != 1 {
		t.Fatalf("res %v err %v", res, err)
	}
}

func TestUnresolvableGrantNeverPasses(t *testing.T) { // FR-11
	r := newRig(t, baseline...)
	tn := r.srv.T
	tn.Assignments[spID] = append(tn.Assignments[spID], graph.AppRoleAssignment{ID: gid(5000), AppRoleID: gid(5001), PrincipalID: spID, ResourceID: graphSP})
	res := r.verify()
	if res.Verdict != v1.VerificationVerdict_VERIFICATION_VERDICT_COULD_NOT_VERIFY || res.WriteGateOpenable {
		t.Fatalf("verdict %v gate %v", res.Verdict, res.WriteGateOpenable)
	}
	if len(byKind(res, v1.FindingKind_FINDING_KIND_COULD_NOT_VERIFY)) != 1 {
		t.Fatalf("findings %v", res.Findings)
	}
}

type failingRoles struct{ *graph.Client }

func (failingRoles) DirectoryRoleAssignments(context.Context, guid.GUID) ([]graph.RoleAssignment, error) {
	return nil, errors.New("403 forbidden")
}

func TestRoleReadFailureNeverPasses(t *testing.T) {
	r := newRig(t, baseline...)
	res, err := rights.VerifyEntra(context.Background(), failingRoles{r.c}, rights.EntraInput{HeldThumbprint: r.thumb})
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != v1.VerificationVerdict_VERIFICATION_VERDICT_COULD_NOT_VERIFY || res.WriteGateOpenable ||
		res.Checks[0].Outcome != v1.CheckOutcome_CHECK_OUTCOME_COULD_NOT_VERIFY {
		t.Fatalf("verdict %v checks %v", res.Verdict, res.Checks)
	}
}

func TestDenyListWithUnreadableRolesStillShowsBlock(t *testing.T) {
	r := newRig(t, baseline...)
	r.grant("Directory.ReadWrite.All")
	res, _ := rights.VerifyEntra(context.Background(), failingRoles{r.c}, rights.EntraInput{HeldThumbprint: r.thumb})
	if len(byKind(res, v1.FindingKind_FINDING_KIND_ENTRA_DENY_LIST_PERMISSION)) != 1 || res.WriteGateOpenable {
		t.Fatalf("findings %v", res.Findings)
	}
}

func TestIdentityReadFailureIsAnError(t *testing.T) {
	r := newRig(t, baseline...)
	r.srv.FailGraph(graphtest.Failure{Status: 403, Body: "{}"})
	if _, err := rights.VerifyEntra(context.Background(), r.c, rights.EntraInput{}); err == nil {
		t.Fatal("expected an error: nothing can be named, so no verdict")
	}
}

func TestFindingsHoldIdentifiersOnly(t *testing.T) {
	r := newRig(t, baseline...)
	r.srv.T.Owners[appObj] = []graph.DirectoryObject{{ID: gid(10), ODataType: "#microsoft.graph.user", UserPrincipalName: "alice@example.test", DisplayName: "Alice Admin"}}
	r.srv.T.KeyCredentials = append(r.srv.T.KeyCredentials, graph.KeyCredential{KeyID: gid(901), DisplayName: "attacker-label", CustomKeyIdentifier: []byte{1}})
	res := r.verify()
	for _, f := range res.Findings {
		s := f.RightsFinding.String()
		for _, bad := range []string{"alice@example.test", "Alice Admin", "attacker-label"} {
			if strings.Contains(s, bad) {
				t.Fatalf("finding leaks %q: %s", bad, s)
			}
		}
	}
}

func TestSpoofedCustomKeyIdentifierIsExtra(t *testing.T) {
	r := newRig(t, baseline...)
	tn := r.srv.T
	other := graphtest.NewCredential(t)
	// (a) a different certificate labelled with our thumbprint
	tn.KeyCredentials = append(tn.KeyCredentials, graph.KeyCredential{KeyID: gid(901), CustomKeyIdentifier: r.thumb, Key: other.Cert.Raw})
	// (c) a key with our label and no certificate bytes
	tn.KeyCredentials = append(tn.KeyCredentials, graph.KeyCredential{KeyID: gid(902), CustomKeyIdentifier: r.thumb})
	res := r.verify()
	got := map[string]bool{}
	for _, f := range byKind(res, v1.FindingKind_FINDING_KIND_ENTRA_EXTRA_KEY_CREDENTIAL) {
		got[f.Qualifier] = true
	}
	if len(got) != 2 || !got[gid(901)] || !got[gid(902)] {
		t.Fatalf("extra keys = %v, findings %v", got, res.Findings)
	}
}

func TestHeldCertificateWithoutLabelIsRecognisedOnce(t *testing.T) {
	r := newRig(t, baseline...)
	tn := r.srv.T
	tn.KeyCredentials[0].CustomKeyIdentifier = nil // (b)
	if res := r.verify(); len(res.Findings) != 0 {
		t.Fatalf("findings = %v", res.Findings)
	}
	// The same certificate added a second time is extra: at most one key is exempt.
	tn.KeyCredentials = append(tn.KeyCredentials, graph.KeyCredential{KeyID: gid(905), Key: tn.KeyCredentials[0].Key})
	res := r.verify()
	if n := len(byKind(res, v1.FindingKind_FINDING_KIND_ENTRA_EXTRA_KEY_CREDENTIAL)); n != 1 {
		t.Fatalf("extra keys = %d", n)
	}
}

func roleViaGroup(r *rig, eligible bool) string {
	grp := gid(6000)
	def := gid(6001)
	tn := r.srv.T
	tn.Memberships = map[string][]graph.Group{spID: {{ID: grp, IsAssignableToRole: true}, {ID: gid(6002)}}}
	tn.Roles = []graph.RoleAssignment{{ID: gid(6003), PrincipalID: grp, RoleDefinitionID: def, DirectoryScopeID: "/", Eligible: eligible, Role: graph.RoleDefinition{ID: def}}}
	return grp
}

func TestRoleHeldThroughRoleAssignableGroupRefuses(t *testing.T) {
	for _, eligible := range []bool{false, true} {
		t.Run(fmt.Sprintf("eligible=%v", eligible), func(t *testing.T) {
			r := newRig(t, baseline...)
			grp := roleViaGroup(r, eligible)
			res := r.verify()
			fs := byKind(res, v1.FindingKind_FINDING_KIND_ENTRA_DIRECTORY_ROLE)
			if res.Verdict != v1.VerificationVerdict_VERIFICATION_VERDICT_REFUSED || len(fs) != 1 || !strings.HasSuffix(fs[0].Qualifier, "@"+grp) {
				t.Fatalf("verdict %v findings %v", res.Verdict, res.Findings)
			}
		})
	}
}

func TestRoleOnNonAssignableGroupIsNotCounted(t *testing.T) {
	r := newRig(t, baseline...)
	roleViaGroup(r, false)
	r.srv.T.Memberships[spID] = []graph.Group{{ID: gid(6000)}} // not role-assignable
	if res := r.verify(); res.Verdict != v1.VerificationVerdict_VERIFICATION_VERDICT_PASS {
		t.Fatalf("verdict %v", res.Verdict)
	}
}

// A role-assignable group whose id is not a GUID cannot be read for roles: it must not pass, and
// the write gate stays closed (T-0117 review; fails closed by construction).
func TestNonGUIDRoleAssignableGroupIDNeverPasses(t *testing.T) {
	for _, id := range []string{"not-a-guid", "00000000-0000-0000-0000-000000000000"} {
		t.Run(id, func(t *testing.T) {
			r := newRig(t, baseline...)
			r.srv.T.Memberships = map[string][]graph.Group{spID: {{ID: id, IsAssignableToRole: true}}}
			res := r.verify()
			if res.Verdict != v1.VerificationVerdict_VERIFICATION_VERDICT_COULD_NOT_VERIFY || res.WriteGateOpenable {
				t.Fatalf("verdict %v gate %v", res.Verdict, res.WriteGateOpenable)
			}
		})
	}
}

// An app-role assignment whose resource id is not a GUID cannot be named, so it cannot be classified.
func TestNonGUIDAppRoleResourceIDNeverPasses(t *testing.T) {
	r := newRig(t, baseline...)
	tn := r.srv.T
	tn.Assignments[spID] = append(tn.Assignments[spID], graph.AppRoleAssignment{ID: gid(5000), AppRoleID: gid(5001), PrincipalID: spID, ResourceID: "not-a-guid"})
	res := r.verify()
	if res.Verdict != v1.VerificationVerdict_VERIFICATION_VERDICT_COULD_NOT_VERIFY || res.WriteGateOpenable {
		t.Fatalf("verdict %v gate %v", res.Verdict, res.WriteGateOpenable)
	}
}

type failingGroups struct{ *graph.Client }

func (failingGroups) ServicePrincipalGroups(context.Context, guid.GUID) ([]graph.Group, error) {
	return nil, errors.New("403 forbidden")
}

func TestGroupMembershipReadFailureNeverPasses(t *testing.T) {
	r := newRig(t, baseline...)
	res, err := rights.VerifyEntra(context.Background(), failingGroups{r.c}, rights.EntraInput{HeldThumbprint: r.thumb})
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != v1.VerificationVerdict_VERIFICATION_VERDICT_COULD_NOT_VERIFY || res.WriteGateOpenable ||
		res.Checks[0].Outcome != v1.CheckOutcome_CHECK_OUTCOME_COULD_NOT_VERIFY || res.Checks[0].Error == nil {
		t.Fatalf("verdict %v checks %v", res.Verdict, res.Checks)
	}
}

func TestOwnerReadFailureIsReported(t *testing.T) {
	r := newRig(t, baseline...)
	r.srv.T.Owners[appObj] = nil
	res, err := rights.VerifyEntra(context.Background(), failingOwners{r.c}, rights.EntraInput{HeldThumbprint: r.thumb})
	if err != nil {
		t.Fatal(err)
	}
	ev5 := res.Checks[2]
	if ev5.Outcome != v1.CheckOutcome_CHECK_OUTCOME_WARN || ev5.Error == nil || ev5.Error.Code != v1.ErrorCode_ERROR_CODE_PROVIDER_FAILURE {
		t.Fatalf("EV5 = %v", ev5)
	}
	if strings.Contains(ev5.Error.Message, "forbidden") {
		t.Fatalf("error leaks the read's message: %q", ev5.Error.Message)
	}
}

type failingOwners struct{ *graph.Client }

func (failingOwners) ApplicationOwners(context.Context, guid.GUID) ([]graph.DirectoryObject, error) {
	return nil, errors.New("403 forbidden")
}
