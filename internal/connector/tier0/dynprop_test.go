package tier0_test

import (
	"context"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/connector/graph"
	"github.com/skenzeriq/activediq/internal/connector/graph/graphtest"
	"github.com/skenzeriq/activediq/internal/connector/tier0"
)

// The T-0230 proof table (threat-model.md "Proof TM-F-T0GUARD (T-0230 additions)"): every row has
// a negative twin that is allowed.

const (
	seed    = 100 // designated seed S
	dynID   = 150 // the dynamic group D
	nestOne = 151
	nestTwo = 152
)

func grp(id string) graph.DirectoryObject {
	return graph.DirectoryObject{ID: id, ODataType: "#microsoft.graph.group"}
}

// nested builds S -> (depth-1 plain groups) -> D, with D's rule. inClosure false hangs D under no
// designated seed (the negative twin).
func nested(rule string, depth int, inClosure bool) (*graphtest.Tenant, []tier0.Designation) {
	tn := tenant()
	chain := []string{g(seed)}
	for i := 1; i < depth; i++ {
		id := g(nestOne + i - 1)
		tn.Groups = append(tn.Groups, graph.Group{ID: id})
		chain = append(chain, id)
	}
	tn.Groups = append(tn.Groups, graph.Group{ID: g(seed)}, graph.Group{ID: g(dynID), GroupTypes: []string{"DynamicMembership"}, MembershipRule: rule})
	if inClosure {
		chain = append(chain, g(dynID))
	}
	for i := 0; i+1 < len(chain); i++ {
		tn.Members[chain[i]] = []graph.DirectoryObject{grp(chain[i+1])}
	}
	return tn, []tier0.Designation{{ID: g(seed), Kind: tier0.KindGroup}}
}

func snap(t *testing.T, tn *graphtest.Tenant, des []tier0.Designation, opts ...func(*tier0.Classifier)) (*tier0.Set, *graphtest.Server) {
	t.Helper()
	cl, srv := newClientSrv(t, tn)
	c := tier0.New(cl)
	for _, o := range opts {
		o(c)
	}
	set, err := c.Snapshot(context.Background(), des...)
	if err != nil {
		t.Fatal(err)
	}
	return set, srv
}

func check(t *testing.T, s *tier0.Set, w tier0.PropertyWrite) tier0.DynamicRuleRefusal {
	t.Helper()
	r, err := s.CheckPropertyWrite(context.Background(), w)
	if err != nil {
		t.Fatal(err)
	}
	if r.Refused && r.Reason != tier0.ReasonDesignatedDynamicRule {
		t.Fatalf("reason %q", r.Reason)
	}
	return r
}

func w(plane tier0.Plane, kind tier0.WriteKind, op tier0.Op, keys ...string) tier0.PropertyWrite {
	return tier0.PropertyWrite{Plane: plane, Kind: kind, Op: op, Keys: keys}
}

var (
	E, A = tier0.PlaneEntra, tier0.PlaneAD
	U, D = tier0.WriteUser, tier0.WriteDevice
)

func expect(t *testing.T, name string, s *tier0.Set, pw tier0.PropertyWrite, refused bool) {
	t.Helper()
	if got := check(t, s, pw); got.Refused != refused {
		t.Errorf("%s: %+v -> %+v, want refused=%v", name, pw, got, refused)
	}
}

func TestT0DynNest(t *testing.T) {
	for _, depth := range []int{1, 3} {
		tn, des := nested(`user.department -eq "X"`, depth, true)
		set, _ := snap(t, tn, des)
		expect(t, "in closure", set, w(E, U, tier0.OpUpdate, "department"), true)
		expect(t, "twin unrelated", set, w(E, U, tier0.OpUpdate, "jobTitle"), false)
		tn, des = nested(`user.department -eq "X"`, depth, false)
		set, _ = snap(t, tn, des)
		expect(t, "twin outside closure", set, w(E, U, tier0.OpUpdate, "department"), false)
		expect(t, "twin outside closure create", set, w(E, U, tier0.OpCreate), false)
	}
}

func TestT0DynNestFail(t *testing.T) {
	tn, des := nested(`user.department -eq "X"`, 3, true)
	cl, srv := newClientSrv(t, tn)
	srv.PathFailures = map[string]graphtest.Failure{"groups/" + g(dynID): {Status: 500}}
	if _, err := tier0.New(cl).Snapshot(context.Background(), des...); err == nil {
		t.Fatal("a failed read in the closure must fail the snapshot")
	}
}

func TestT0DynDevice(t *testing.T) {
	tn, des := nested(`device.extensionAttribute3 -eq "x"`, 1, true)
	set, _ := snap(t, tn, des)
	expect(t, "container", set, w(E, D, tier0.OpUpdate, "extensionAttributes"), true)
	expect(t, "twin displayName", set, w(E, D, tier0.OpUpdate, "displayName"), false)
	expect(t, "twin user container", set, w(E, U, tier0.OpUpdate, "onPremisesExtensionAttributes"), false)
	expect(t, "device create", set, w(E, D, tier0.OpCreate), true)
	expect(t, "twin user create", set, w(E, U, tier0.OpCreate), false)
}

func TestT0DynDirectReports(t *testing.T) {
	tn, des := nested(`Direct Reports for "`+g(7)+`"`, 1, true)
	set, _ := snap(t, tn, des)
	expect(t, "set", set, w(E, U, tier0.OpSetManager), true)
	expect(t, "clear", set, w(E, U, tier0.OpClearManager), true)
	expect(t, "twin jobTitle", set, w(E, U, tier0.OpUpdate, "jobTitle"), false)
	// AD (T0-DYN-DR-AD)
	expect(t, "ad manager", set, w(A, U, tier0.OpUpdate, "manager"), true)
	expect(t, "ad set manager op", set, w(A, U, tier0.OpSetManager), true)
	expect(t, "twin ad title", set, w(A, U, tier0.OpUpdate, "title"), false)
	if sc := tier0.ScopeOfRule(`Direct Reports for "x"`); sc.RefuseAll || !sc.Properties["user.manager"] {
		t.Fatalf("lexer returned an empty scope: %+v", sc)
	}
	// twin: a different rule leaves manager writes alone
	tn, des = nested(`user.department -eq "X"`, 1, true)
	set, _ = snap(t, tn, des)
	expect(t, "twin set manager", set, w(E, U, tier0.OpSetManager), false)
}

func TestT0DynCreateInviteNull(t *testing.T) {
	for _, rule := range []string{`user.department -eq "X"`, `user.userType -eq "Guest"`, `user.department -eq null`} {
		tn, des := nested(rule, 1, true)
		set, _ := snap(t, tn, des)
		expect(t, rule, set, w(E, U, tier0.OpCreate), true)
		expect(t, rule, set, w(E, U, tier0.OpInvite), true)
		expect(t, rule+" AD create", set, w(A, U, tier0.OpCreate), true)
	}
	set, _ := snap(t, tenant(), nil)
	expect(t, "no closure dynamic group", set, w(E, U, tier0.OpCreate), false)
	expect(t, "no closure dynamic group", set, w(E, U, tier0.OpInvite), false)
}

func TestT0DynLicense(t *testing.T) {
	tn, des := nested(`user.assignedPlans -any (assignedPlan.service -eq "x" -and assignedPlan.capabilityStatus -eq "Enabled")`, 1, true)
	set, _ := snap(t, tn, des)
	expect(t, "user", set, w(E, U, tier0.OpAssignLicense), true)
	expect(t, "group", set, w(E, tier0.WriteGroup, tier0.OpAssignLicense), true)
	tn, des = nested(`user.city -eq "x"`, 1, true)
	set, _ = snap(t, tn, des)
	expect(t, "twin user", set, w(E, U, tier0.OpAssignLicense), false)
	expect(t, "twin group", set, w(E, tier0.WriteGroup, tier0.OpAssignLicense), false)
}

func TestT0DynExtensionContainer(t *testing.T) {
	tn, des := nested(`user.extensionAttribute5 -eq "x"`, 1, true)
	set, _ := snap(t, tn, des)
	expect(t, "other subkey", set, w(E, U, tier0.OpUpdate, "onPremisesExtensionAttributes.extensionAttribute9"), true)
	expect(t, "container", set, w(E, U, tier0.OpUpdate, "onPremisesExtensionAttributes"), true)
	expect(t, "ad ext", set, w(A, U, tier0.OpUpdate, "extensionAttribute5"), true)
	expect(t, "twin", set, w(E, U, tier0.OpUpdate, "department"), false)
	const app = "0123456789abcdef0123456789abcdef"
	tn, des = nested(`user.extension_`+app+`_costCentre -eq "x"`, 1, true)
	set, _ = snap(t, tn, des)
	expect(t, "directory extension", set, w(E, U, tier0.OpUpdate, "extension_"+app+"_costCentre"), true)
	expect(t, "twin other extension", set, w(E, U, tier0.OpUpdate, "extension_"+app+"_other"), false)
	// AD side: unmapped extension refuses AD updates; mapped refuses only the mapped attribute.
	expect(t, "ad unmapped", set, w(A, U, tier0.OpUpdate, "description"), true)
	set, _ = snap(t, tn, des, func(c *tier0.Classifier) {
		c.WithDirectoryExtensions(map[string]string{"msDS-cc": "extension_" + app + "_costCentre"})
	})
	expect(t, "ad mapped", set, w(A, U, tier0.OpUpdate, "msDS-cc"), true)
	expect(t, "twin ad mapped", set, w(A, U, tier0.OpUpdate, "description"), false)
}

func TestT0DynUnknownAndUnlexable(t *testing.T) {
	for _, rule := range []string{`user.fooBar -eq "x"`, `user.department -eq "unterminated`, `True -eq True`, `user.employeeOrgData.division -eq "x"`} {
		tn, des := nested(rule, 1, true)
		set, _ := snap(t, tn, des)
		expect(t, rule, set, w(E, U, tier0.OpUpdate, "jobTitle"), true)
		expect(t, rule, set, w(E, D, tier0.OpUpdate, "displayName"), true)
		expect(t, rule, set, w(E, U, tier0.OpCreate), true)
		expect(t, rule, set, w(E, U, tier0.OpInvite), true)
		expect(t, rule, set, w(E, U, tier0.OpAssignLicense), true)
		expect(t, rule, set, w(E, U, tier0.OpSetManager), true)
		expect(t, rule+" AD", set, w(A, U, tier0.OpUpdate, "description"), true)
		expect(t, rule+" move", set, w(A, U, tier0.OpMoveOrRename), true)
		// not the membership case: group membership writes stay allowed
		expect(t, rule+" membership", set, w(E, tier0.WriteGroup, tier0.OpGroupMembership), false)
	}
}

func TestT0DynMemberOf(t *testing.T) {
	tn, des := nested(`user.memberOf -any (group.objectId -in ["`+g(9)+`"])`, 1, true)
	set, _ := snap(t, tn, des)
	expect(t, "update", set, w(E, U, tier0.OpUpdate, "jobTitle"), true)
	expect(t, "membership", set, w(E, tier0.WriteGroup, tier0.OpGroupMembership), true)
	expect(t, "ad membership", set, w(A, tier0.WriteGroup, tier0.OpGroupMembership), true)
	tn, des = nested(`user.department -eq "x"`, 1, true)
	set, _ = snap(t, tn, des)
	expect(t, "twin membership", set, w(E, tier0.WriteGroup, tier0.OpGroupMembership), false)
}

func TestT0DynADHybrid(t *testing.T) {
	tn, des := nested(`user.jobTitle -eq "Admin"`, 1, true)
	set, _ := snap(t, tn, des)
	expect(t, "title", set, w(A, U, tier0.OpUpdate, "title"), true)
	expect(t, "description", set, w(A, U, tier0.OpUpdate, "description"), false)
	expect(t, "ModifyDN without OU rule", set, w(A, U, tier0.OpMoveOrRename), false)
	tn, des = nested(`user.onPremisesDistinguishedName -startsWith "OU=Staff"`, 1, true)
	set, _ = snap(t, tn, des)
	expect(t, "ModifyDN", set, w(A, U, tier0.OpMoveOrRename), true)
	expect(t, "distinguishedName pseudo-attr", set, w(A, U, tier0.OpUpdate, "distinguishedName"), true)
	expect(t, "twin title", set, w(A, U, tier0.OpUpdate, "title"), false)
	tn, des = nested(`user.accountEnabled -eq true`, 1, true)
	set, _ = snap(t, tn, des)
	expect(t, "uac", set, w(A, U, tier0.OpUpdate, "userAccountControl"), true)
	expect(t, "twin description", set, w(A, U, tier0.OpUpdate, "description"), false)
	tn, des = nested(`device.displayName -eq "x"`, 1, true)
	set, _ = snap(t, tn, des)
	expect(t, "computer displayName", set, w(A, D, tier0.OpUpdate, "displayName"), true)
	expect(t, "twin user displayName", set, w(A, U, tier0.OpUpdate, "displayName"), false)
}

func TestT0DynLiveReread(t *testing.T) {
	tn, des := nested(`user.department -eq "X"`, 1, true)
	set, srv := snap(t, tn, des)
	expect(t, "before edit", set, w(E, U, tier0.OpUpdate, "city"), false)
	for i := range tn.Groups {
		if tn.Groups[i].ID == g(dynID) {
			tn.Groups[i].MembershipRule = `user.city -eq "Y"`
		}
	}
	expect(t, "after edit", set, w(E, U, tier0.OpUpdate, "city"), true)
	if r := check(t, set, w(E, U, tier0.OpUpdate, "city")); r.Stage != tier0.StageLiveReread || r.Op != tier0.OpUpdate || len(r.Keys) != 1 {
		t.Fatalf("%+v", r)
	}
	// a rule edited to something unlexable
	for i := range tn.Groups {
		if tn.Groups[i].ID == g(dynID) {
			tn.Groups[i].MembershipRule = `user.city -eq "`
		}
	}
	expect(t, "unlexable edit", set, w(E, U, tier0.OpUpdate, "jobTitle"), true)
	// a failed re-read refuses and reports the error
	srv.PathFailures = map[string]graphtest.Failure{"groups/" + g(dynID): {Status: 500}}
	r, err := set.CheckPropertyWrite(context.Background(), w(E, U, tier0.OpUpdate, "jobTitle"))
	if err == nil || !r.Refused || r.Stage != tier0.StageLiveReread {
		t.Fatalf("%+v %v", r, err)
	}
}

// A paused group still counts: the check never reads membershipRuleProcessingState, so no state
// exempts a rule (rule 7a). The closure carries the rule hash for the report.
func TestT0DynClosureCarriesHash(t *testing.T) {
	tn, des := nested(`user.department -eq "X"`, 3, true)
	set, _ := snap(t, tn, des)
	c := set.DynamicClosure()
	if len(c) != 1 || c[0].GroupID != g(dynID) || !c[0].User || c[0].Device || len(c[0].RuleHash) != 64 {
		t.Fatalf("%+v", c)
	}
}

func TestPropertyWriteMalformedIsRefused(t *testing.T) {
	set, _ := snap(t, tenant(), nil) // no closure dynamic group
	for _, pw := range []tier0.PropertyWrite{
		{Plane: 0, Kind: U, Op: tier0.OpUpdate, Keys: []string{"x"}},
		{Plane: E, Kind: 0, Op: tier0.OpUpdate},
		{Plane: E, Kind: U, Op: 0},
		{Plane: E, Kind: U, Op: tier0.OpMoveOrRename},    // AD only
		{Plane: A, Kind: U, Op: tier0.OpInvite},          // Entra only
		{Plane: E, Kind: D, Op: tier0.OpAssignLicense},   // devices hold no licence
		{Plane: E, Kind: U, Op: tier0.OpGroupMembership}, // groups only
		{Plane: E, Kind: D, Op: tier0.OpSetManager},      // users only
	} {
		expect(t, "malformed", set, pw, true)
	}
	var nilSet *tier0.Set
	if r, _ := nilSet.CheckPropertyWrite(context.Background(), w(E, U, tier0.OpUpdate, "x")); !r.Refused {
		t.Fatal("nil set must refuse")
	}
	if !strings.Contains(tier0.OpMoveOrRename.String(), "MOVE") {
		t.Fatal("op name")
	}
}
