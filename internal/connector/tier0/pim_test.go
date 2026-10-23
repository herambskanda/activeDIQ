package tier0_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/connector/graph"
	"github.com/skenzeriq/activediq/internal/connector/graph/graphtest"
	"github.com/skenzeriq/activediq/internal/connector/tier0"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
)

// Placeholders for the values lab G11 will pin (TM-D25 rule 5).
const (
	unlicensedCode = "G11PlaceholderNoPimLicence"
	pimPlan        = "eec0eb4f-6444-4f95-aba0-50c24d67f998" // [UNVERIFIED — lab G11]
)

var pinned = tier0.PIMUnlicensed{HTTPStatus: 403, GraphCode: unlicensedCode, PlanIDs: []string{pimPlan}}

func sched(group, principal, ptype, access string, eligible bool) graph.GroupSchedule {
	return graph.GroupSchedule{ID: "s-" + principal + group[len(group)-3:], GroupID: group, PrincipalID: principal, PrincipalType: ptype,
		AccessID: access, Status: "Provisioned", Eligible: eligible}
}

func withSchedules(scs ...graph.GroupSchedule) *graphtest.Tenant {
	tn := tenant()
	tn.Schedules = scs
	return tn
}

func TestPIMSchedulesAreE2(t *testing.T) {
	future := time.Now().Add(48 * time.Hour)
	pend := sched(roleGroup, g(82), "user", "member", true)
	pend.Status = "PendingApproval"
	fut := sched(roleGroup, g(83), "user", "member", false)
	fut.Start = &future
	cases := []struct {
		name string
		tn   *graphtest.Tenant
		id   string
	}{
		{"eligible-only member", withSchedules(sched(roleGroup, g(80), "user", "member", true)), g(80)},
		{"eligible-only owner", withSchedules(sched(roleGroup, g(81), "user", "owner", true)), g(81)},
		{"pending approval", withSchedules(pend), g(82)},
		{"future-dated assignment member", withSchedules(fut), g(83)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := classifyWith(t, tc.tn, tc.id, known)
			wantBases(t, r, err, tier0.E2)
		})
	}
}

func TestExpiredScheduleIsNotTier0(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	sc := sched(roleGroup, g(84), "user", "member", true)
	sc.End = &past
	r, err := classifyWith(t, withSchedules(sc), g(84), known)
	if err != nil || r.Tier0 {
		t.Fatalf("expired schedule must not count: %+v %v", r, err)
	}
	// ...unless the principal is in the closure some other way.
	tn := withSchedules(sc)
	tn.Members[roleGroup] = append(tn.Members[roleGroup], userObj(g(84)))
	r, err = classifyWith(t, tn, g(84), known)
	wantBases(t, r, err, tier0.E2)
}

// Group A is an eligible member of role-assignable B: A's members reach B.
func TestGroupTypeSchedulePrincipalJoinsClosure(t *testing.T) {
	grpA := g(90)
	tn := withSchedules(sched(roleGroup, grpA, "group", "member", true))
	tn.Groups = append(tn.Groups, graph.Group{ID: grpA})
	tn.Members[grpA] = []graph.DirectoryObject{userObj(g(91)), {ID: g(95), ODataType: "#microsoft.graph.group"}}
	tn.Members[g(95)] = []graph.DirectoryObject{userObj(g(96))}
	tn.Owners[grpA] = []graph.DirectoryObject{userObj(g(92))}
	// A's own eligible member is reached through A's schedules.
	tn.Schedules = append(tn.Schedules, sched(grpA, g(93), "user", "member", true))
	for _, id := range []string{grpA, g(91), g(92), g(93), g(95), g(96)} {
		r, err := classifyWith(t, tn, id, known)
		wantBases(t, r, err, tier0.E2)
	}
}

func TestClosureEndsOnCycle(t *testing.T) {
	a, b := g(90), g(97)
	tn := withSchedules(sched(roleGroup, a, "group", "member", true), sched(a, b, "group", "member", true), sched(b, a, "group", "member", true))
	tn.Members[a] = []graph.DirectoryObject{{ID: b, ODataType: "#microsoft.graph.group"}}
	tn.Members[b] = []graph.DirectoryObject{{ID: a, ODataType: "#microsoft.graph.group"}, userObj(g(98))}
	r, err := classifyWith(t, tn, g(98), known)
	wantBases(t, r, err, tier0.E2)
}

func TestSPInScheduleSeedsOwnerClosure(t *testing.T) {
	tn := withSchedules(sched(roleGroup, plainSP, "servicePrincipal", "member", true))
	r, err := classifyWith(t, tn, plainOwner, known)
	wantBases(t, r, err, tier0.E3)
}

func designatedGroupTenant() (*graphtest.Tenant, tier0.Input) {
	d, n := g(100), g(101)
	tn := tenant()
	tn.Groups = append(tn.Groups, graph.Group{ID: d, DisplayName: "CA exclusion"}, graph.Group{ID: n})
	tn.Members[d] = []graph.DirectoryObject{userObj(g(102)), {ID: n, ODataType: "#microsoft.graph.group"}}
	tn.Members[n] = []graph.DirectoryObject{userObj(g(103))}
	tn.Owners[d] = []graph.DirectoryObject{userObj(g(104))}
	return tn, tier0.Input{CorrelationKnown: true, Designated: []tier0.Designation{{ID: d, Kind: tier0.KindGroup}}}
}

func TestDesignatedGroupReach(t *testing.T) {
	tn, in := designatedGroupTenant()
	for _, id := range []string{g(100), g(101), g(102), g(103), g(104)} { // group, nested group, member, nested member, owner
		r, err := classifyWith(t, tn, id, in)
		wantBases(t, r, err, tier0.Designated)
	}
	r, err := classifyWith(t, tn, plainUser, in)
	if err != nil || r.Tier0 {
		t.Fatalf("outsider: %+v %v", r, err)
	}
}

// Both bases apply when both do.
func TestDesignatedAndRoleAssignableBasesBoth(t *testing.T) {
	tn, in := designatedGroupTenant()
	tn.Members[roleGroup] = append(tn.Members[roleGroup], userObj(g(102)))
	r, err := classifyWith(t, tn, g(102), in)
	wantBases(t, r, err, tier0.E2, tier0.Designated)
}

func TestDesignatedKindMustBeKnown(t *testing.T) {
	r, err := classifyWith(t, tenant(), plainUser, tier0.Input{CorrelationKnown: true, Designated: []tier0.Designation{{ID: plainUser}}})
	wantRefused(t, r, err)
	// A set computed for other designations cannot answer for a designated group it never walked.
	tn, in := designatedGroupTenant()
	cl := newClient(t, tn)
	set, err := tier0.New(cl).Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r, err := set.Classify(g(102), in); err == nil || !r.Unknown {
		t.Fatalf("must refuse: %+v %v", r, err)
	}
}

func newClient(t *testing.T, tn *graphtest.Tenant) *graph.Client {
	c, _ := newClientSrv(t, tn)
	return c
}

func newClientSrv(t *testing.T, tn *graphtest.Tenant) (*graph.Client, *graphtest.Server) {
	t.Helper()
	cred := graphtest.NewCredential(t)
	srv := graphtest.New(t, tn, cred)
	cl, err := graph.New(srv.Config(cred))
	if err != nil {
		t.Fatal(err)
	}
	return cl, srv
}

// ---- fail closed ----

func TestScheduleReadFailureRefusesEveryTarget(t *testing.T) {
	for _, ep := range []string{"eligibilitySchedules", "assignmentSchedules"} {
		for _, status := range []int{403, 500, 404} {
			t.Run(fmt.Sprintf("%s-%d", ep, status), func(t *testing.T) {
				cl, srv := newClientSrv(t, tenant())
				srv.PathFailures = map[string]graphtest.Failure{ep: {Status: status}}
				for _, id := range []string{plainUser, roleHolder, g(1234)} {
					r, err := tier0.New(cl).Classify(context.Background(), id, known)
					wantRefused(t, r, err)
				}
			})
		}
	}
}

func unlicensedFailure() graphtest.Failure {
	return graphtest.Failure{Status: 403, Body: `{"error":{"code":"` + unlicensedCode + `","message":"x"}}`}
}

func TestUnlicensedNeedsCorroboration(t *testing.T) {
	noPIM := []graph.SubscribedSKU{{SKUID: "k1", ServicePlans: []graph.ServicePlan{{ServicePlanID: "00000000-0000-0000-0000-00000000aaaa", ProvisioningStatus: "Success"}}}}
	disabled := []graph.SubscribedSKU{{SKUID: "k2", ServicePlans: []graph.ServicePlan{{ServicePlanID: strings.ToUpper(pimPlan), ProvisioningStatus: "Disabled"}}}}
	enabled := []graph.SubscribedSKU{{SKUID: "k3", ServicePlans: []graph.ServicePlan{{ServicePlanID: pimPlan, ProvisioningStatus: "Success"}}}}
	run := func(t *testing.T, skus []graph.SubscribedSKU, pin tier0.PIMUnlicensed, skuFail bool, f graphtest.Failure) (tier0.Result, error, *tier0.Set) {
		tn := withSchedules(sched(roleGroup, g(80), "user", "member", true))
		tn.SubscribedSKUs = skus
		cl, srv := newClientSrv(t, tn)
		srv.PathFailures = map[string]graphtest.Failure{"eligibilitySchedules": f}
		if skuFail {
			srv.PathFailures["subscribedSkus"] = graphtest.Failure{Status: 500}
		}
		c := tier0.New(cl).WithPIMUnlicensed(pin)
		r, err := c.Classify(context.Background(), g(80), known)
		set, _ := c.Snapshot(context.Background())
		return r, err, set
	}
	for name, skus := range map[string][]graph.SubscribedSKU{"no PIM plan": noPIM, "plan disabled": disabled} {
		t.Run("corroborated, "+name, func(t *testing.T) {
			r, err, set := run(t, skus, pinned, false, unlicensedFailure())
			if err != nil || r.Tier0 {
				t.Fatalf("unlicensed set is empty: %+v %v", r, err)
			}
			if set == nil || !set.PIMNotLicensed() {
				t.Fatal("the assumption must be exposed for connection health")
			}
		})
	}
	t.Run("a PIM plan is enabled", func(t *testing.T) {
		r, err, _ := run(t, enabled, pinned, false, unlicensedFailure())
		wantRefused(t, r, err)
	})
	t.Run("no corroborating SKU read", func(t *testing.T) {
		r, err, _ := run(t, noPIM, pinned, true, unlicensedFailure())
		wantRefused(t, r, err)
	})
	t.Run("G11 not run (nothing pinned)", func(t *testing.T) {
		r, err, _ := run(t, noPIM, tier0.PIMUnlicensed{}, false, unlicensedFailure())
		wantRefused(t, r, err)
	})
	t.Run("pinned plans unknown", func(t *testing.T) {
		r, err, _ := run(t, noPIM, tier0.PIMUnlicensed{HTTPStatus: 403, GraphCode: unlicensedCode}, false, unlicensedFailure())
		wantRefused(t, r, err)
	})
	t.Run("different error code", func(t *testing.T) {
		r, err, _ := run(t, noPIM, pinned, false, graphtest.Failure{Status: 403, Body: `{"error":{"code":"Authorization_RequestDenied"}}`})
		wantRefused(t, r, err)
	})
	t.Run("different status", func(t *testing.T) {
		r, err, _ := run(t, noPIM, pinned, false, graphtest.Failure{Status: 400, Body: `{"error":{"code":"` + unlicensedCode + `"}}`})
		wantRefused(t, r, err)
	})
}

func TestScheduleShapesFailTheSnapshot(t *testing.T) {
	mut := map[string]func(*graph.GroupSchedule){
		"unknown accessId":   func(s *graph.GroupSchedule) { s.AccessID = "admin" },
		"empty accessId":     func(s *graph.GroupSchedule) { s.AccessID = "" },
		"unknown principal":  func(s *graph.GroupSchedule) { s.PrincipalType = "device" },
		"no principal type":  func(s *graph.GroupSchedule) { s.PrincipalType = "" },
		"no status":          func(s *graph.GroupSchedule) { s.Status = "" },
		"principal not GUID": func(s *graph.GroupSchedule) { s.PrincipalID = "not-a-guid" },
	}
	for name, m := range mut {
		t.Run(name, func(t *testing.T) {
			sc := sched(roleGroup, g(80), "user", "member", true)
			m(&sc)
			r, err := classifyWith(t, withSchedules(sc), plainUser, known)
			wantRefused(t, r, err)
		})
	}
}

// reader that answers the snapshot's reads empty but the live per-principal read with a schedule.
type liveOnly struct {
	tier0.Reader
	sc  graph.GroupSchedule
	err error
}

func (l liveOnly) GroupSchedules(context.Context, guid.GUID) ([]graph.GroupSchedule, error) {
	return nil, nil
}
func (l liveOnly) PrincipalSchedules(context.Context, guid.GUID) ([]graph.GroupSchedule, error) {
	if l.err != nil {
		return nil, l.err
	}
	return []graph.GroupSchedule{l.sc}, nil
}

func TestLiveScheduleCheckPerWrite(t *testing.T) {
	cl := newClient(t, tenant())
	r, err := tier0.New(liveOnly{Reader: cl, sc: sched(roleGroup, g(80), "user", "member", true)}).Classify(context.Background(), g(80), known)
	wantBases(t, r, err, tier0.E2)
	// A schedule on a group that is not in the closure is nothing.
	r, err = tier0.New(liveOnly{Reader: cl, sc: sched(g(11), g(80), "user", "member", true)}).Classify(context.Background(), g(80), known)
	if err != nil || r.Tier0 {
		t.Fatalf("%+v %v", r, err)
	}
	// A failed live read refuses.
	r, err = tier0.New(liveOnly{Reader: cl, err: fmt.Errorf("boom")}).Classify(context.Background(), g(80), known)
	wantRefused(t, r, err)
	// A schedule for someone else than the target is a malformed answer.
	r, err = tier0.New(liveOnly{Reader: cl, sc: sched(roleGroup, g(81), "user", "member", true)}).Classify(context.Background(), g(80), known)
	wantRefused(t, r, err)
}

func TestScheduleFiltersGoThroughBuilder(t *testing.T) {
	// The fake accepts only the exact eq filters the odata primitive emits; a request reaching the
	// handler with a schedule answer proves the filter parsed.
	tn := withSchedules(sched(roleGroup, g(80), "user", "member", true))
	cl := newClient(t, tn)
	gid, _ := guid.Parse(roleGroup)
	scs, err := cl.GroupSchedules(context.Background(), gid)
	if err != nil || len(scs) != 1 || scs[0].PrincipalType != "user" {
		t.Fatalf("%+v %v", scs, err)
	}
	pid, _ := guid.Parse(g(80))
	scs, err = cl.PrincipalSchedules(context.Background(), pid)
	if err != nil || len(scs) != 1 {
		t.Fatalf("%+v %v", scs, err)
	}
	if _, err := cl.PrincipalSchedules(context.Background(), guid.GUID{}); graph.CodeOf(err) != graph.CodeInvalidArgument {
		t.Fatalf("zero principal must be refused: %v", err)
	}
}

// ---- deny list ----

func TestRoleManagementPolicyGrantMakesOwnersE3(t *testing.T) {
	for _, perm := range []string{"RoleManagementPolicy.ReadWrite.Directory", "RoleManagementPolicy.ReadWrite.AzureADGroup", "RoleManagementPolicy.ReadWrite.EntraAppRole"} {
		t.Run(perm, func(t *testing.T) {
			tn := tenant()
			const roleID = "ab000000-0000-0000-0000-000000000003"
			sp := tn.ServicePrincipals[graphSP]
			sp.AppRoles = append(sp.AppRoles, graph.AppRole{ID: roleID, Value: perm})
			tn.ServicePrincipals[graphSP] = sp
			tn.Assignments[plainSP] = append(tn.Assignments[plainSP], graph.AppRoleAssignment{ID: "a9", AppRoleID: roleID, PrincipalID: plainSP, ResourceID: graphSP, PrincipalType: "ServicePrincipal"})
			r, err := classifyWith(t, tn, plainOwner, known)
			wantBases(t, r, err, tier0.E3)
		})
	}
}

// ---- dynamic rules ----

func dynamicTenant(rule string) (*graphtest.Tenant, tier0.Input) {
	d := g(110)
	tn := tenant()
	tn.Groups = append(tn.Groups, graph.Group{ID: d, GroupTypes: []string{"DynamicMembership"}, MembershipRule: rule})
	return tn, tier0.Input{CorrelationKnown: true, Designated: []tier0.Designation{{ID: d, Kind: tier0.KindGroup}}}
}

func snapshotFor(t *testing.T, rule string) *tier0.Set {
	tn, in := dynamicTenant(rule)
	set, err := tier0.New(newClient(t, tn)).Snapshot(context.Background(), in.Designated...)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func TestDynamicRuleRefusesReferencedProperty(t *testing.T) {
	set := snapshotFor(t, `(user.department -eq "Finance") -and (user.accountEnabled -eq true) -or (device.deviceOSType -startsWith "Win")`)
	for _, tc := range []struct {
		kind  tier0.WriteKind
		props []string
		want  bool
	}{
		{tier0.WriteUser, []string{"department"}, true},
		{tier0.WriteUser, []string{"Department"}, true},
		{tier0.WriteUser, []string{"jobTitle", "accountEnabled"}, true},
		{tier0.WriteUser, []string{"jobTitle"}, false},
		{tier0.WriteUser, []string{"deviceOSType"}, false},
		{tier0.WriteDevice, []string{"deviceOSType"}, true},
		{tier0.WriteDevice, []string{"department"}, false},
		{0, []string{"jobTitle"}, true}, // unknown kind
	} {
		got := set.CheckPropertyWrite(tc.kind, tc.props)
		if got.Refused != tc.want || (got.Refused && got.Reason != tier0.ReasonDesignatedDynamicRule) {
			t.Errorf("%v %v: %+v", tc.kind, tc.props, got)
		}
	}
}

func TestDynamicRuleUntokenisableOrMemberOfRefusesAll(t *testing.T) {
	for _, rule := range []string{`user.department -eq "unterminated`, `user.department -eq #`, `user.memberOf -any (group.objectId -in ["x"])`,
		`(user.department -eq "a") -and (user.x -memberOf "g")`, ``} {
		set := snapshotFor(t, rule)
		if !set.CheckPropertyWrite(tier0.WriteUser, []string{"jobTitle"}).Refused {
			t.Errorf("rule %q must refuse every user write", rule)
		}
	}
}

func TestNoDynamicGroupRefusesNothing(t *testing.T) {
	set := snapshotFor(t, `user.department -eq "x"`)
	_ = set
	cl := newClient(t, tenant())
	plain, err := tier0.New(cl).Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if plain.CheckPropertyWrite(tier0.WriteUser, []string{"department"}).Refused {
		t.Fatal("no designated dynamic group: nothing to protect")
	}
}

func TestDynamicRuleLexer(t *testing.T) {
	toks, err := tier0.Lex(`(user.assignedPlans -any (assignedPlan.service -eq "x\"y" -and assignedPlan.capabilityStatus -eq "Enabled")) -and user.age -ge 18 -and user.tags -in ["a","b"] -and user.v -eq $null`)
	if err != nil {
		t.Fatal(err)
	}
	var props []string
	for _, tk := range toks {
		if tk.Kind == tier0.TokProperty {
			props = append(props, tk.Text)
		}
	}
	if fmt.Sprint(props) != "[user.assignedPlans user.age user.tags user.v]" {
		t.Fatalf("%v", props)
	}
	// A property named inside a string is not a reference.
	sc := tier0.ScopeOfRule(`user.a -eq "user.b"`)
	if len(sc.Properties) != 1 || !sc.Properties["user.a"] || sc.RefuseAll {
		t.Fatalf("%+v", sc)
	}
}

func FuzzLexRule(f *testing.F) {
	for _, s := range []string{``, `user.department -eq "x"`, `(user.a -eq "b\"c")`, `-`, `"`, `user.`, `user..a`, "\x00", `user.memberOf`, `{"a",1.2.3}`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, rule string) {
		toks, err := tier0.Lex(rule)
		sc := tier0.ScopeOfRule(rule)
		if err != nil && !sc.RefuseAll {
			t.Fatal("untokenisable rule must refuse every write")
		}
		if err == nil {
			// every property reference reported is a user./device. token of the rule
			n := 0
			for _, tk := range toks {
				if tk.Kind == tier0.TokProperty {
					p := strings.ToLower(tk.Text)
					if !strings.HasPrefix(p, "user.") && !strings.HasPrefix(p, "device.") {
						t.Fatalf("property token %q", tk.Text)
					}
					if !sc.Properties[p] {
						t.Fatalf("property %q lost", p)
					}
					n++
				}
			}
			if n < len(sc.Properties) {
				t.Fatal("scope has properties no token backs")
			}
		}
	})
}
