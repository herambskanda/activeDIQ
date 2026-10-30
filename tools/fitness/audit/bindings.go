package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strings"
)

// binding ties one ADR-0005 audit check (or part of it) to the Go tests that prove the behaviour. The
// behaviour lives in the audit package's own integration tests, which run against real PostgreSQL; the
// job's part is to run them and to fail when one is missing, fails or is skipped, so that deleting or
// skipping a test cannot silently weaken the check.
type binding struct {
	Check string   // A2..A9
	What  string   // the clause of ADR-0005 the tests prove
	Pkg   string   // package path relative to the repository root
	Tests []string // top-level test names
}

const (
	auditPkg  = "./internal/platform/audit"
	chainPkg  = "./internal/platform/audit/chain"
	verifyPkg = "./cmd/auditverify"
)

var defaultBindings = []binding{
	{"A2", "AG-1/AG-2: rolled-back append leaves nothing, non-READ COMMITTED refused, miswired store fails closed", auditPkg,
		[]string{"TestRolledBackAppendLeavesNothingAndTheChainStaysGapless", "TestA2NonReadCommittedAppendIsRefusedAndChainStaysGapless", "TestFailsClosedWhenMiswired", "TestHeadGuards"}},
	{"A3", "32 concurrent appenders leave no gap; two tenants never interleave", auditPkg,
		[]string{"TestConcurrentAppendersLeaveNoGapAndTenantsStaySeparate"}},
	{"A5", "tamper corpus in the verifier: edited, deleted, reordered, inserted, spliced, retired-key checkpoint, whole chain re-signed", chainPkg,
		[]string{"TestTamperEditedEvent", "TestTamperDeletedEvent", "TestTamperReorderedEvents", "TestTamperInsertedEvent", "TestTamperSplicedFromAnotherTenant",
			"TestCheckpointSignedByRetiredKey", "TestWholeChainRebuiltUnderFreshKey", "TestVerifyWithoutTrustRootIsUnanchoredNeverOK", "TestTailTruncationFails"}},
	{"A5", "tamper corpus through the database and through the adq-audit-verify exit codes", auditPkg,
		[]string{"TestTamperedDatabaseFailsVerification"}},
	{"A5", "adq-audit-verify exits non-zero for an edited, deleted or reordered event", verifyPkg,
		[]string{"TestExitCodes", "TestEditedDeletedReorderedEventsFail"}},
	{"A6", "every checkpoint reaches the anchor sink and the export; an anchor failure keeps the checkpoint", auditPkg,
		[]string{"TestChainVerifiesAndEveryCheckpointIsAnchoredAndExported", "TestAnchorFailureKeepsTheCheckpoint"}},
	{"A9", "retention: purge deletes personal values only purged events reference; a hold suspends the purge from the held partition", auditPkg,
		[]string{"TestPurgeDeletesPersonalValuesOnlyPurgedEventsReference", "TestPartitionBoundaryCheckpointsAndRetentionPurge",
			"TestLegalHoldSuspendsPurgeFromHeldPartition", "TestLegalHoldInOldestPartitionPurgesNothing", "TestLegalHoldSetDuringPurgeIsSeen"}},
}

// pendingChecks are ADR-0005 audit checks whose guarded code or seed has not landed. They are listed on
// every run, never skipped silently; the owning ticket removes its line when it lands the check.
var pendingChecks = []struct{ id, what, ticket string }{
	{"A4", "seeded-tenant verification: the lab seed (operations, sign-ins, setting changes, rotation, erasure, purge) exported and verified by adq-audit-verify with the pinned fingerprint", "T-0638"},
	{"A6", "seven days with no anchor raises an alert (the alerting half)", "T-0638"},
	{"A7", "audit detail types: every string field tagged personal or public; no secret.Secret; personal fields reach the canonical form only as PersonalRef", "T-0639"},
	{"A8", "AG-8 coverage: audit read, export, retention change and SIEM-sink change each emit an event and need step-up", "T-0640"},
}

type testEvent struct {
	Action  string
	Package string
	Test    string
	Output  string
}

// runBindings runs the bound tests of the selected checks, one `go test -json` per package, and returns
// a violation for each test that is missing, failed or was skipped (a skipped test proves nothing).
func runBindings(ctx context.Context, root string, bs []binding, run func(ctx context.Context, root, pkg string, tests []string) ([]byte, error)) ([]Violation, error) {
	byPkg := map[string][]binding{}
	var pkgs []string
	for _, b := range bs {
		if _, ok := byPkg[b.Pkg]; !ok {
			pkgs = append(pkgs, b.Pkg)
		}
		byPkg[b.Pkg] = append(byPkg[b.Pkg], b)
	}
	sort.Strings(pkgs)
	var vs []Violation
	for _, pkg := range pkgs {
		var names []string
		for _, b := range byPkg[pkg] {
			names = append(names, b.Tests...)
		}
		out, err := run(ctx, root, pkg, names)
		if err != nil && len(out) == 0 {
			return nil, fmt.Errorf("go test %s: %w", pkg, err)
		}
		result := map[string]string{} // test -> pass|fail|skip, worst wins
		skipped := map[string]bool{}
		var buildOut strings.Builder
		sc := bufio.NewScanner(bytes.NewReader(out))
		sc.Buffer(make([]byte, 1<<20), 1<<24)
		for sc.Scan() {
			var e testEvent
			if json.Unmarshal(sc.Bytes(), &e) != nil {
				buildOut.WriteString(sc.Text() + "\n")
				continue
			}
			if e.Test == "" {
				if e.Action == "output" {
					buildOut.WriteString(e.Output)
				}
				continue
			}
			top := e.Test
			if i := strings.IndexByte(top, '/'); i >= 0 {
				top = top[:i]
			}
			switch e.Action {
			case "pass", "fail", "skip":
				if top == e.Test { // the top-level verdict
					result[top] = e.Action
				} else if e.Action == "skip" {
					skipped[top] = true
				}
			}
		}
		for _, b := range byPkg[pkg] {
			for _, t := range b.Tests {
				where := pkg + " " + t
				switch result[t] {
				case "pass":
					if skipped[t] {
						vs = append(vs, Violation{b.Check, "test-skipped", where, "a subtest was skipped (no Docker?): the check is not proven. " + b.What})
					}
				case "fail":
					vs = append(vs, Violation{b.Check, "test-failed", where, b.What})
				case "skip":
					vs = append(vs, Violation{b.Check, "test-skipped", where, "skipped: the check is not proven. " + b.What})
				default:
					msg := "the bound test did not run: it was renamed or deleted, or the package does not build. " + b.What
					if s := strings.TrimSpace(buildOut.String()); s != "" {
						msg += " go test said: " + firstLines(s, 6)
					}
					vs = append(vs, Violation{b.Check, "test-missing", where, msg})
				}
			}
		}
	}
	return vs, nil
}

func firstLines(s string, n int) string {
	l := strings.Split(s, "\n")
	if len(l) > n {
		l = l[:n]
	}
	return strings.Join(l, " | ")
}

// goTest runs the named top-level tests of one package. -count=1 defeats the test cache: a cached pass
// is not a run against today's database image.
func goTest(ctx context.Context, root, pkg string, tests []string) ([]byte, error) {
	re := "^(" + strings.Join(tests, "|") + ")$"
	cmd := exec.CommandContext(ctx, "go", "test", "-json", "-count=1", "-run", re, pkg)
	cmd.Dir = root
	out, err := cmd.Output()
	return out, err
}
