package operation

// The O8 manifest maps every clause of ADR-0005's fitness row O8 ("Pipeline behaviour") to the named
// tests that pin it, and TestO8ManifestNamesRealTests fails when a named test does not exist, so a
// renamed or deleted test cannot leave a clause silently unguarded. tools/fitness/operation (T-0393)
// reads the same list. A clause with no test is listed under Gap with the ticket that closes it; the
// manifest never claims coverage it does not have.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

type o8Test struct{ Dir, Name string } // Dir relative to the repository root

type o8Clause struct {
	ID     string
	Rule   string
	Tests  []o8Test
	Gap    string // non-empty: not yet pinned; must start with the ticket ID that closes it
	Needs  string // what the tests need: "pg" (Postgres), "lab" (Samba, -tags lab), "fake" (Graph fake)
	Detail string
}

const (
	opDir  = "internal/platform/operation"
	srvDir = "internal/compose/server"
	stepD  = "internal/platform/operation/step"
	cliDir = "internal/directory/client"
)

var o8Manifest = []o8Clause{
	{ID: "O8.reconcile", Rule: "a step killed after its claim is reconciled to applied, re-applied, not_run (cancelling) or stale_state, never left applying", Needs: "pg",
		Tests: []o8Test{{opDir, "TestReconcileLapsedClaim"}}},
	{ID: "O8.password-no-reapply", Rule: "a password step is never re-applied by reconciliation", Needs: "pg",
		Tests: []o8Test{{opDir, "TestReconcileLapsedClaim"}}},
	{ID: "O8.superseded", Rule: "a superseded attempt's late result changes nothing", Needs: "pg",
		Tests: []o8Test{{opDir, "TestSupersededAttemptChangesNothing"}, {opDir, "TestTier0AfterWriteFromSupersededAttempt"}}},
	{ID: "O8.retries-exhausted", Rule: "retries exhausted with the after-state in place is not recorded failed", Needs: "pg",
		Tests: []o8Test{{opDir, "TestRetriesExhausted"}}},
	{ID: "O8.sweeper", Rule: "a lost chunk job is re-driven by the sweeper", Needs: "pg",
		Tests: []o8Test{{opDir, "TestLostJobRedrivenBySweeper"}, {opDir, "TestSweepSettlesFinishedOperationAndDropsExpiredSecrets"}}},
	{ID: "O8.stale-state", Rule: "a target changed between Plan and Apply fails stale_state and is not overwritten", Needs: "pg",
		Tests: []o8Test{{opDir, "TestStaleStateAndOutcomeUnknown"}}},
	{ID: "O8.scope.ad-ou", Rule: "removed from scope: an AD object moved out of an OU root is refused", Needs: "pg",
		Tests: []o8Test{{opDir, "TestO8RemovedFromScopeADOUMovedOut"}, {opDir, "TestO8RemovedFromScopeADExcludedSubOU"}, {opDir, "TestO8ScopeControlInScopeStillApplies"}, {srvDir, "TestLabRule5LiveFactsDecideBackingObject"}, {srvDir, "TestLabO8RemovedFromScopeADOUMovedOut"}}},
	{ID: "O8.scope.ad-group", Rule: "removed from scope: an AD object removed from a group_members root is refused", Needs: "pg",
		Gap: "T-0824: rbac does not evaluate group_members roots; real assertions exist, skipped, in TestO8RemovedFromScopeNonAncestryRoots"},
	{ID: "O8.scope.entra-au", Rule: "removed from scope: an Entra object removed from an administrative_unit root is refused", Needs: "fake",
		Gap: "T-0824: administrative_unit roots are not evaluated, and the Graph fake behind authority.Facts is added once they are"},
	{ID: "O8.scope.entra-group", Rule: "removed from scope: an Entra object removed from an Entra group_members root is refused", Needs: "fake",
		Gap: "T-0824: as O8.scope.entra-au"},
	{ID: "O8.scope.correlated", Rule: "removed from scope: an include_correlated Entra target whose AD object left scope or whose correlation dropped to candidate is refused", Needs: "fake",
		Gap: "T-0824: include_correlated roots are not evaluated"},
	{ID: "O8.scope.unknown", Rule: "a target whose include or exclude root comes back unknown is refused", Needs: "pg",
		Tests:  []o8Test{{opDir, "TestO8ScopeFactsThatCannotBeProvenAreRefusedAtApply"}},
		Detail: "pinned for ancestry roots (ou_subtree, naming_context); for group_members, administrative_unit and include_correlated roots, including an exclude that reads unknown or member, the open gap is T-0824 (skipped TestO8UnknownRootIsRefused)"},
	{ID: "O8.digest", Rule: "client.Write refuses an operation whose digest differs from the step's plan", Needs: "fake",
		Tests: []o8Test{{cliDir, "TestDigestMismatchRefused"}, {stepD, "TestDigest"}}},
	{ID: "O8.approval-refusals", Rule: "an approval with a stale plan_hash, by the initiator, by an API token, without step-up for an Irreversible operation, or by a sock-puppet account in either direction is refused", Needs: "pg",
		Tests: []o8Test{{opDir, "TestApprovals"}}},
	{ID: "O8.approver-credential-change", Rule: "an approver whose password or sign-in binding the initiator changed is refused", Needs: "pg",
		Gap: "the runner asks Provenance.Tied in both directions (TestApprovals, sock puppet); the production Provenance implementation that answers (e) does not exist on main yet, so only the port contract is pinned — follow-up T-0831"},
	{ID: "O8.clearance-replay", Rule: "a Clearance replayed for a different step or operation is refused", Needs: "fake",
		Tests: []o8Test{{stepD, "TestClearanceReplayRefused"}, {stepD, "TestRevokedStepAndClearanceDie"}}},
	{ID: "O8.approval-accepted", Rule: "an approval by a directory-admitted account not tied to the initiator is accepted", Needs: "pg",
		Tests: []o8Test{{opDir, "TestApprovals"}}},
	{ID: "O8.replan-keeps-approval", Rule: "a held operation re-planned on a different DC with the same before-state keeps its approvals", Needs: "pg",
		Tests: []o8Test{{opDir, "TestApprovals"}, {opDir, "TestBadDSAPinFailsPlanAndIsNotPersisted"}}},
	{ID: "O8.stepup-token", Rule: "a StepUp Action initiated by a token is held or refused", Needs: "pg",
		Tests: []o8Test{{opDir, "TestKernelHolds"}}},
	{ID: "O8.max-objects", Rule: "an automation run over max_objects is held", Needs: "pg",
		Tests: []o8Test{{opDir, "TestKernelHolds"}}},
	{ID: "O8.gate-error", Rule: "a gate error leaves the operation unapproved", Needs: "pg",
		Tests: []o8Test{{opDir, "TestGateErrorLeavesOperationPlannedAndAlerts"}}},
	{ID: "O8.secret-expired", Rule: "an expired transient secret fails its step secret_expired and nothing is written", Needs: "pg",
		Tests: []o8Test{{opDir, "TestSweepSettlesFinishedOperationAndDropsExpiredSecrets"}, {opDir, "TestSecretUsedThenDeleted"}}},
	{ID: "O8.store-outcome", Rule: "a Store Action whose Apply fails or is denied still has its outcome event, including when the first recording attempt hits lock_timeout", Needs: "pg",
		Tests: []o8Test{{opDir, "TestApplyFailureRollsBackAndRecordsFailure"}, {opDir, "TestOutcomeRecordRetriesThenSurfacesErrRecord"}, {opDir, "TestDeniedAtPlanWritesNothingAndRecordsDenial"}}},
	{ID: "O8.undo-failed-item", Rule: "an undo of a failed item restores the before-state of its verify_failed steps, except tier0_after_write, whose inverse is blocked", Needs: "pg",
		Gap: "the runner has no undo planner on main (only the OriginUndo hold, TestKernelHolds); the undo operation is not implemented, follow-up T-0830"},
	{ID: "O8.tier0-after-write", Rule: "tier0 after the write: verify_failed tier0_after_write with basis, critical alert, operation cancelling; connector step 9 disabled; server re-read unknown; empty basis recorded unclassified; the dc_unavailable split", Needs: "pg",
		Tests: []o8Test{{opDir, "TestTier0AfterWriteCancelsRunningOperation"}, {opDir, "TestTier0AfterWriteFromDeferredVerify"}, {opDir, "TestTier0AfterWriteOnSettledOperationIsOnlyAudited"}, {opDir, "TestConnectorReportProducesTier0AfterWrite"}, {opDir, "TestServerRereadProducesTier0AfterWrite"}, {opDir, "TestServerRereadUnknownCountsAsTier0"}, {opDir, "TestServerRereadCleanVerifies"}, {opDir, "TestServerRereadFallbackDC"}, {opDir, "TestNoTier0KeepsOtherReasons"}}},
}

var gapTicket = regexp.MustCompile(`(^T-\d{4}\b)|(follow-up T-\d{4}\b)`)

// testFuncs returns the top-level Test functions declared in the _test.go files of dir (all build tags).
func testFuncs(t *testing.T, dir string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	files, err := filepath.Glob(filepath.Join(dir, "*_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		af, err := parser.ParseFile(token.NewFileSet(), f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range af.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok && fn.Recv == nil && strings.HasPrefix(fn.Name.Name, "Test") {
				out[fn.Name.Name] = true
			}
		}
	}
	return out
}

// TestO8ManifestNamesRealTests: every clause names at least one real test or states its gap.
func TestO8ManifestNamesRealTests(t *testing.T) {
	root := repoRoot(t)
	cache := map[string]map[string]bool{}
	seen := map[string]bool{}
	for _, c := range o8Manifest {
		if seen[c.ID] {
			t.Errorf("%s: duplicate clause", c.ID)
		}
		seen[c.ID] = true
		if (len(c.Tests) == 0) == (c.Gap == "") {
			t.Errorf("%s: needs tests or a gap, not both and not neither", c.ID)
		}
		if c.Gap != "" && !gapTicket.MatchString(c.Gap) {
			t.Errorf("%s: Gap must start with the ticket ID that closes it (T-nnnn), got %q", c.ID, c.Gap)
		}
		for _, tc := range c.Tests {
			fns, ok := cache[tc.Dir]
			if !ok {
				fns = testFuncs(t, filepath.Join(root, tc.Dir))
				cache[tc.Dir] = fns
			}
			if !fns[tc.Name] {
				t.Errorf("%s: %s/%s does not exist", c.ID, tc.Dir, tc.Name)
			}
		}
	}
}
