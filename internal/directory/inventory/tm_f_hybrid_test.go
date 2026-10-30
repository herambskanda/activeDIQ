package inventory_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/authz"
)

// TM-F-HYBRID (threat model §6.8, §6.9, §15). Covers TM-TB7-T8 to T13 and TM-TB8-T8.
//
// The composed half: every correlation case runs the real DM-20.I4 gate (inventory.Evaluate) and then
// hands its verdict to the real authorisation evaluator, as the membership resolver does. A case
// passes only when authority is REFUSED. The component halves (attestation flow, authority factor,
// console-backing objects) live in their own packages; TestTMFHybridTraceability pins each §15 case
// to the named test that proves it, so a rename or deletion fails here.

const (
	resetPW authz.Permission = "objects.user.reset_password"
	ouID                     = "ou-sales"
)

var hybridClock = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)

func oid(name string) authz.ObjectID {
	var o authz.ObjectID
	o[0] = 0xCC
	copy(o[1:], name)
	return o
}

// authorize asks the evaluator whether a session that arrived at a reset-password grant through the
// correlation (verdict v, tenant takeover state tk) may reset a user under the OU. factor is the
// session's verified authority factor. owner marks the tenant-owner role.
func authorize(v inventory.Verdict, tk inventory.TakeoverProtection, factor, owner bool, perm authz.Permission) authz.Decision {
	p := &authz.Principal{ID: "sso-tech", AuthorityFactor: factor, Assignments: []authz.Assignment{{
		Role:  authz.Role{Permissions: []authz.Permission{perm}, TenantOwner: owner},
		Scope: authz.Scope{Include: []authz.ScopeRoot{{ID: oid(ouID), Complete: true}}},
		Via: &authz.Derivation{Correlation: &authz.Correlation{
			State: string(v.State), Reason: string(v.Reason), Takeover: string(tk),
		}},
	}}}
	tgt := authz.Target{ID: oid("u1"), Ancestors: []authz.ObjectID{oid(ouID)}, Complete: true}
	return authz.Evaluator{Now: func() time.Time { return hybridClock }}.Authorize(p, nil, perm, tgt)
}

func refused(t *testing.T, name string, d authz.Decision, v inventory.Verdict) {
	t.Helper()
	if d.Allowed {
		t.Fatalf("%s: authorised through verdict %s/%q", name, v.State, v.Reason)
	}
	if len(d.HybridRefusals) != 1 {
		t.Fatalf("%s: the refusal must be returned for the audit trail: %+v", name, d)
	}
}

// Sanity: the harness grants when everything is genuinely matched, so the refusals below are the gate's.
func TestTMFHybridControl(t *testing.T) {
	v := inventory.Evaluate(good(), t1)
	if v.State != inventory.StateMatched {
		t.Fatalf("control must be matched: %+v", v)
	}
	if d := authorize(v, inventory.TakeoverAttested, true, false, resetPW); !d.Allowed {
		t.Fatalf("control must be authorised: %+v", d)
	}
}

// TB7-T8: onPremisesImmutableId stamped on a cloud-only user. onPremisesSyncEnabled is not writable
// through Graph, so a forged anchor has it false or null.
func TestTMFHybridForgedAnchor(t *testing.T) {
	for name, flag := range map[string]*bool{"null": nil, "false": &no} {
		in := good()
		in.EntraSyncEnabled = flag
		v := inventory.Evaluate(in, t1)
		if v.State != inventory.StateCandidate || v.Reason != inventory.ReasonNotSynced {
			t.Fatalf("%s: %+v", name, v)
		}
		refused(t, "forged/"+name, authorize(v, in.Takeover, true, false, resetPW), v)
	}
}

// TB7-T10: SOA transferred. isCloudManaged is set although the SID still equals objectSid.
func TestTMFHybridSOATransferred(t *testing.T) {
	in := good()
	in.EntraCloudManaged = &yes
	v := inventory.Evaluate(in, t1)
	if v.State != inventory.StateCandidate || v.Reason != inventory.ReasonCloudManaged {
		t.Fatalf("%+v", v)
	}
	refused(t, "soa", authorize(v, in.Takeover, true, false, resetPW), v)
}

// TB7-T8: the SID on the Entra object differs from the AD objectSid (or is absent, or AD's is unknown).
func TestTMFHybridSIDMismatch(t *testing.T) {
	for name, mut := range map[string]func(*inventory.GateInput){
		"differs":    func(g *inventory.GateInput) { g.EntraSID = []byte{9, 9, 9, 9, 9, 9, 9, 9} },
		"absent":     func(g *inventory.GateInput) { g.EntraSID = nil },
		"ad unknown": func(g *inventory.GateInput) { g.ADSID, g.EntraSID = nil, nil },
	} {
		in := good()
		mut(&in)
		v := inventory.Evaluate(in, t1)
		if v.State != inventory.StateCandidate || v.Reason != inventory.ReasonSIDMismatch {
			t.Fatalf("%s: %+v", name, v)
		}
		refused(t, "sid/"+name, authorize(v, in.Takeover, true, false, resetPW), v)
	}
}

// TB7-T9: the attestation is missing, expired or voided by a monitored feature change. The gate sees
// open or stale (or nothing); the evaluator independently refuses on the takeover state it is given.
func TestTMFHybridUnattested(t *testing.T) {
	for _, tk := range []inventory.TakeoverProtection{inventory.TakeoverOpen, inventory.TakeoverStale, ""} {
		in := good()
		in.Takeover = tk
		v := inventory.Evaluate(in, t1)
		if v.State != inventory.StateCandidate || v.Reason != inventory.ReasonTenantTakeoverOpen {
			t.Fatalf("takeover %q: %+v", tk, v)
		}
		refused(t, "unattested/"+string(tk), authorize(v, tk, true, false, resetPW), v)
	}
	// Defence in depth: even a stale matched row cannot authorise once the tenant is no longer attested.
	m := inventory.Evaluate(good(), t1)
	for _, tk := range []inventory.TakeoverProtection{inventory.TakeoverOpen, inventory.TakeoverStale, ""} {
		d := authorize(m, tk, true, false, resetPW)
		refused(t, "voided/"+string(tk), d, m)
		if d.Reason != authz.ReasonHybridUnattested {
			t.Fatalf("voided attestation must refuse as unattested: %+v", d)
		}
	}
}

// TB7-T9 / DM-16.I9: an object once seen cloud-only stays a candidate until a tenant-owner re-confirms.
func TestTMFHybridOnceCloudOnly(t *testing.T) {
	in := good()
	in.CloudSeenAt = t0.Add(time.Hour)
	v := inventory.Evaluate(in, t1)
	if v.State != inventory.StateCandidate || v.Reason != inventory.ReasonReconfirmRequired {
		t.Fatalf("%+v", v)
	}
	refused(t, "once-cloud-only", authorize(v, in.Takeover, true, false, resetPW), v)
	// A re-confirmation older than the cloud observation does not count.
	in.Prior = &inventory.Prior{State: inventory.StateCandidate, ReconfirmedAt: t0}
	if v := inventory.Evaluate(in, t1); v.State == inventory.StateMatched {
		t.Fatalf("a stale re-confirmation must not match: %+v", v)
	}
}

// Install-time population: eligible before the first attestation, it becomes matched when the first
// attested state lands, without re-confirmation. If its Entra object was once cloud-only it does not.
func TestTMFHybridInstallTimePopulation(t *testing.T) {
	// Before the first attestation: eligible, class recorded, still a candidate.
	pre := good()
	pre.Takeover, pre.FirstAttestedAt = inventory.TakeoverOpen, time.Time{}
	v0 := inventory.Evaluate(pre, t0)
	if v0.State != inventory.StateCandidate || v0.EligibilityClass != inventory.ClassInstallTime {
		t.Fatalf("pre-attestation: %+v", v0)
	}
	refused(t, "install-time/pre", authorize(v0, pre.Takeover, true, false, resetPW), v0)

	// The first attestation lands: the stored marker carries over; no ReconfirmedAt is needed.
	post := good()
	post.FirstAttestedAt = t1
	post.Prior = &inventory.Prior{State: v0.State, EligibleSince: v0.EligibleSince, EligibilityClass: v0.EligibilityClass}
	v1 := inventory.Evaluate(post, t1)
	if v1.State != inventory.StateMatched || v1.EligibilityClass != inventory.ClassInstallTime {
		t.Fatalf("install-time correlation must become matched on the first attestation: %+v", v1)
	}

	// ...unless its Entra object was once seen cloud-only.
	post.CloudSeenAt = t0
	if v2 := inventory.Evaluate(post, t1); v2.State != inventory.StateCandidate || v2.Reason != inventory.ReasonReconfirmRequired {
		t.Fatalf("once-cloud-only install-time object must stay candidate: %+v", v2)
	}
}

// A correlation that first becomes eligible while the state is open or stale AFTER an earlier
// attestation is lapsed: it stays a candidate after re-attestation until a tenant-owner re-confirms.
func TestTMFHybridLapseWindowNeedsReconfirmation(t *testing.T) {
	for _, tk := range []inventory.TakeoverProtection{inventory.TakeoverOpen, inventory.TakeoverStale} {
		lapse := good() // FirstAttestedAt is set: this tenant attested before.
		lapse.Takeover = tk
		v0 := inventory.Evaluate(lapse, t0)
		if v0.State != inventory.StateCandidate || v0.EligibilityClass != inventory.ClassLapsed {
			t.Fatalf("%s: eligibility during the lapse must be lapsed: %+v", tk, v0)
		}
		prior := &inventory.Prior{State: v0.State, EligibleSince: v0.EligibleSince, EligibilityClass: v0.EligibilityClass}

		// Re-attestation: attested again, but the lapsed marker survives (eligibility only goes down).
		re := good()
		re.Prior = prior
		v1 := inventory.Evaluate(re, t1)
		if v1.State != inventory.StateCandidate || v1.Reason != inventory.ReasonReconfirmRequired {
			t.Fatalf("%s: re-attestation alone must not match a lapsed correlation: %+v", tk, v1)
		}
		refused(t, "lapse/"+string(tk), authorize(v1, re.Takeover, true, false, resetPW), v1)

		// A tenant-owner re-confirmation after eligibility lifts it.
		prior.ReconfirmedAt = t1
		if v2 := inventory.Evaluate(re, t1.Add(time.Minute)); v2.State != inventory.StateMatched {
			t.Fatalf("%s: re-confirmed correlation must match: %+v", tk, v2)
		}
	}
}

// TB7-T9 (h): the tenant-owner role, and permissions administering RBAC, delegation or connections,
// never cross a correlation, even a genuinely matched one with a current authority factor.
func TestTMFHybridTenantOwnerNeverCrosses(t *testing.T) {
	v := inventory.Evaluate(good(), t1)
	d := authorize(v, inventory.TakeoverAttested, true, true, resetPW)
	if d.Allowed || d.Reason != authz.ReasonHybridNeverCrosses {
		t.Fatalf("tenant-owner across a correlation: %+v", d)
	}
	for _, p := range []authz.Permission{"rbac.assign", "authz.grant", "delegation.scope.edit", "connections.takeover.attest",
		"connections.correlation.reconfirm", "tenant.settings.edit", "inventory.tier0_designation.manage"} {
		d := authorize(v, inventory.TakeoverAttested, true, false, p)
		if d.Allowed || d.Reason != authz.ReasonHybridNeverCrosses {
			t.Fatalf("%s across a correlation: %+v", p, d)
		}
	}
}

// TB7-T13 / TB8-T8 (TM-D19 rule 1): an Entra-only session, with a legitimately matched correlation and
// an AD group grant, holds no AD-side grant until its authority factor verifies.
func TestTMFHybridEntraOnlySessionHoldsNoGrant(t *testing.T) {
	v := inventory.Evaluate(good(), t1)
	d := authorize(v, inventory.TakeoverAttested, false, false, resetPW)
	if d.Allowed || d.Reason != authz.ReasonAuthorityFactorMissing {
		t.Fatalf("Entra-only session: %+v", d)
	}
	if len(d.HybridRefusals) != 1 {
		t.Fatalf("refusal must be audited: %+v", d)
	}
}

// TB7-T11: an AD object correlated to an Entra tier0 principal is tier0 whatever the correlation state.
func TestTMFHybridTier0CorrelationRefused(t *testing.T) {
	v := inventory.Evaluate(good(), t1)
	p := &authz.Principal{ID: "sso-tech", AuthorityFactor: true, Assignments: []authz.Assignment{{
		Role:  authz.Role{Permissions: []authz.Permission{resetPW}},
		Scope: authz.Scope{Include: []authz.ScopeRoot{{ID: oid(ouID), Complete: true}}},
		Via:   &authz.Derivation{Correlation: &authz.Correlation{State: string(v.State), Takeover: "attested"}},
	}}}
	tgt := authz.Target{ID: oid("ga"), Ancestors: []authz.ObjectID{oid(ouID)}, Complete: true, CorrelatedTier0: true}
	d := authz.Evaluator{Now: func() time.Time { return hybridClock }}.Authorize(p, nil, resetPW, tgt)
	if d.Allowed {
		t.Fatalf("object correlated to a tier0 principal: %+v", d)
	}
}

// traceability: the §15 cases proven in the component packages, pinned by test name. A missing or
// renamed test fails here, so the matrix cannot silently lose a case.
func TestTMFHybridTraceability(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	pinned := []struct{ c, file, test string }{
		{"attestation flow keeps no token (§6.8)", "internal/modules/connections/attest_test.go", "TestAttestNoTokenRetained"},
		{"attestation flow asks for no scope beyond the one listed (§6.8)", "internal/modules/connections/attest_test.go", "TestAttestScopeAndTid"},
		{"authority factor enrols without AD-plane proof or owner approval (TM-D19 r2)", "internal/platform/authn/authority_factor_test.go", "Test_enrol_requires_ad_proof_or_owner"},
		{"owner-approved enrolment still audited and notified (TM-D19 r2)", "internal/platform/authn/authority_factor_test.go", "Test_enrol_audit_notify_reset_owner_only"},
		{"Entra-side method reset touches the activeDIQ factor (TM-D19 r2)", "internal/platform/authn/authority_factor_test.go", "Test_entra_reset_leaves_factor"},
		{"authority factor gates correlation grants per session (TM-D19 r1)", "internal/platform/authn/authority_factor_test.go", "Test_authority_factor_gates_correlation_grants"},
		{"less-privileged technician resets a console-backing object (TM-D19 r5)", "internal/platform/rbac/backing_test.go", "TestBackingObjectResetRefused"},
		{"console-backing guard fails closed (TM-D19 r5)", "internal/platform/rbac/backing_test.go", "TestBackingObjectGuardFailsClosed"},
		{"sso-bound console-backing object (TM-D19 r5)", "internal/platform/rbac/backing_test.go", "TestBackingObjectSSOBinding"},
		{"re-confirmation needs a tenant-owner with step-up (TM-D17 r4 g)", "internal/modules/connections/reconfirm_test.go", "Test_reconfirm_refused"},
		{"install-time population vs re-confirmation (TM-D17 r4 g)", "internal/modules/connections/reconfirm_test.go", "Test_reconfirm_vs_install_population"},
		{"forged peer never grants membership", "internal/directory/inventory/membership_synced_test.go", "TestMembership_forged_peer"},
	}
	fset := token.NewFileSet()
	cache := map[string]map[string]bool{}
	for _, p := range pinned {
		names, ok := cache[p.file]
		if !ok {
			f, err := parser.ParseFile(fset, filepath.Join(root, filepath.FromSlash(p.file)), nil, 0)
			if err != nil {
				t.Fatalf("%s: %v", p.c, err)
			}
			names = map[string]bool{}
			for _, d := range f.Decls {
				if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil {
					names[fd.Name.Name] = true
				}
			}
			cache[p.file] = names
		}
		if !names[p.test] {
			t.Errorf("TM-F-HYBRID case %q: %s no longer defines %s", p.c, p.file, p.test)
		}
	}
}
