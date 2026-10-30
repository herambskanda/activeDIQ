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

// binding ties part of an FF-KEY check to the Go tests that prove the behaviour. The job runs them and
// fails when one is missing, failed or skipped, so deleting or skipping a test cannot weaken the check.
type binding struct {
	Check string
	What  string
	Pkg   string
	Tests []string
}

var defaultBindings = []binding{
	{"FF-KEY-1", "transition matrix and runtime grants on the real migrated schema (retired->active refused, no DELETE/TRUNCATE, identity columns immutable)", "./internal/platform/keys",
		[]string{"TestSchemaShape", "TestTransitionTriggerAndRuntimeGrants"}},
	{"FF-KEY-3", "the KEK settings are only read in the composition root; provider unset, passphrase env, unknown or foreign settings are refused (no default)", "./internal/compose/server",
		[]string{"TestKEKSettingsAreReadOnlyInComposeServer", "TestLoadKEKConfigRefusals", "TestRunFailsWithoutKEKProvider"}},
	{"FF-KEY-4", "provider unset, keystore missing, wrong passphrase: the provider refuses with one code and never falls back", "./internal/compose/server",
		[]string{"TestPlatformKeyProviderRefusals", "TestPlatformKeyProviderUnlock"}},
	{"FF-KEY-5", "Provision is idempotent and fails closed on a provider outage; KeySource has no INSERT path", "./internal/platform/keys",
		[]string{"TestProvisionInsertsOnceAndDestroysPlaintext", "TestProvisionFailsClosedWhenProviderDown", "TestOnlyProvisionAndRotateInsert"}},
	{"FF-KEY-6", "errors carry only 'keys: <Code>'; cross-tenant and unknown version are identical; a wrap moved to another tenant/version or with an edited KEK ref fails UnwrapFailed", "./internal/platform/keys",
		[]string{"TestKeySourceResolution", "TestKeySourceProviderOutageAndTampering", "TestKeySourceLocalProviderBindsTenant", "TestUnwrapUnderOtherTenantFails",
			"TestLocalProviderTamperAndForeignKEK", "TestTMFSealDEKBoundToTenantContext"}},
}

// pendingChecks are FF-KEY parts whose guarded code has not landed. They are listed on every run, never
// skipped silently and never counted as a pass; the owning ticket removes its line when it lands.
var pendingChecks = []struct{ id, what, ticket string }{
	{"FF-KEY-4", "boot tests with rows and no tenant context: KekMismatch, NoInstallationKek, NoActiveKey, repair by provision --missing (needs the boot self-test, installation_kek and keys provision)", "boot self-test ticket (keys-custody-design §5)"},
	{"FF-KEY-5", "provision --missing skips shredded and deleting tenants; eager creation with a failing provider; trigger refuses the runtime role's active->same re-wrap end to end", "keys provision ticket"},
	{"FF-KEY-6", "the audit event and API problem body of each §6 failure row carry none of the secret fields; FF-KEY-4 against a non-exportable provider; property test on the transition table", "T-0526 and the boot ticket"},
}

type testEvent struct{ Action, Package, Test, Output string }

func goTest(ctx context.Context, root, pkg string, tests []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "go", "test", "-count=1", "-json", "-run", "^("+strings.Join(tests, "|")+")$", pkg)
	cmd.Dir = root
	return cmd.CombinedOutput()
}

// runBindings returns a violation for each bound test that is missing, failed or skipped.
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
		result, skipped := map[string]string{}, map[string]bool{}
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
			top, _, _ := strings.Cut(e.Test, "/")
			if e.Action == "pass" || e.Action == "fail" || e.Action == "skip" {
				if top == e.Test {
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
						vs = append(vs, Violation{b.Check, "test-skipped", where, "a subtest was skipped (no Docker?): not proven. " + b.What})
					}
				case "fail":
					vs = append(vs, Violation{b.Check, "test-failed", where, b.What})
				case "skip":
					vs = append(vs, Violation{b.Check, "test-skipped", where, "skipped: not proven. " + b.What})
				default:
					msg := "the bound test did not run: renamed, deleted or the package does not build. " + b.What
					if s := strings.TrimSpace(buildOut.String()); s != "" {
						l := strings.Split(s, "\n")
						if len(l) > 6 {
							l = l[:6]
						}
						msg += " go test said: " + strings.Join(l, " | ")
					}
					vs = append(vs, Violation{b.Check, "test-missing", where, msg})
				}
			}
		}
	}
	return vs, nil
}
