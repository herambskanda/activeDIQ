package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"os/exec"
	"sort"
	"strings"
)

// binding ties part of an FCS check to the Go tests that prove the behaviour. Landed is set by the ticket
// that adds those tests (it is a review-visible edit of this table); a landed binding fails when a test is
// missing, failed or skipped, so deleting or skipping one cannot weaken the check. A binding that is not
// landed is listed as pending on every run, never as a pass, and fails if its tests already exist
// (someone landed them without flipping the flag).
type binding struct {
	Check  string
	What   string
	Pkg    string
	Tests  []string
	Landed bool
}

var defaultBindings = []binding{
	{"FCS-1", "SignServerLeaf is the only user of the server CA key: unseal only inside the call, zeroised, audited", "./internal/platform/fleet/fleetsql",
		[]string{"TestServerCAKeyUsedOnlyBySignServerLeaf"}, false},
	{"FCS-2", "SignServerLeaf output table: ServerAuth only, not a CA, no URI SAN, no wildcard, lifetime <= 30 days and <= CA not_after; each of those, a caller key or CSR, a name outside the endpoint set, and an inactive or near-expiry CA is refused", "./internal/platform/fleet/fleetsql",
		[]string{"TestSignServerLeafOutput", "TestSignServerLeafRefusals"}, false},
	{"FCS-3", "integration: the server CA is absent from the gateway client pool and TenantCAs, and a ClientAuth leaf signed by it is refused", "./internal/platform/fleet/gateway",
		[]string{"TestServerCAAbsentFromClientPool", "TestClientAuthLeafSignedByServerCARefused"}, false},
	{"FCS-4", "integration, two tenants on one listener: a tenant CA is never a dial root (a leaf signed by a tenant CA presented as the server is refused) and both tenants' enrolment material carries the same pin", "./internal/platform/fleet/dial",
		[]string{"TestTenantCANeverDialRoot", "TestTwoTenantsSamePin"}, false},
	{"FCS-5", "keys AAD: fleet_ca rows do not open under the installation DEK, fleet_server_ca values do not open under a tenant DEK", "./internal/platform/keys",
		[]string{"TestInstallationDEKCannotOpenFleetCA"}, false},
	{"FCS-6", "the presented Certificate[] has length 2 (leaf, server CA) in the composed listener", "./internal/compose/server",
		[]string{"TestFleetListenerPresentsLeafAndServerCA"}, false},
}

// testDeclared returns the Test functions declared in the tree, for the not-landed consistency check.
func testDeclared(files []goFile) map[string]bool {
	m := map[string]bool{}
	for _, g := range files {
		if !g.Test {
			continue
		}
		for _, d := range g.File.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && strings.HasPrefix(fd.Name.Name, "Test") {
				m[fd.Name.Name] = true
			}
		}
	}
	return m
}

// runBindings runs the landed bindings, and reports the others as pending.
func runBindings(ctx context.Context, root string, files []goFile, bs []binding, run func(ctx context.Context, root, pkg string, tests []string) ([]byte, error)) ([]Violation, []string, error) {
	declared := testDeclared(files)
	var landed []binding
	var vs []Violation
	var pending []string
	for _, b := range bs {
		if b.Landed {
			landed = append(landed, b)
			continue
		}
		for _, t := range b.Tests {
			if declared[t] {
				vs = append(vs, Violation{b.Check, "binding-not-landed", b.Pkg + " " + t, "the bound test exists but its binding is not marked Landed in tools/fitness/fleetca/bindings.go: flip it so the job runs it"})
			}
		}
		pending = append(pending, b.Check+" "+b.What+" (tests "+strings.Join(b.Tests, ", ")+" not landed)")
	}
	rv, err := runLanded(ctx, root, landed, run)
	return append(vs, rv...), pending, err
}

type testEvent struct{ Action, Package, Test, Output string }

func goTest(ctx context.Context, root, pkg string, tests []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "go", "test", "-count=1", "-json", "-run", "^("+strings.Join(tests, "|")+")$", pkg)
	cmd.Dir = root
	return cmd.CombinedOutput()
}

// runBindings returns a violation for each bound test that is missing, failed or skipped.
func runLanded(ctx context.Context, root string, bs []binding, run func(ctx context.Context, root, pkg string, tests []string) ([]byte, error)) ([]Violation, error) {
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
