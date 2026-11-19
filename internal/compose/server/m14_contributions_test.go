package server

import (
	"slices"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory"
	"github.com/skenzeriq/activediq/internal/platform"
	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/module"
	"github.com/skenzeriq/activediq/internal/platform/module/moduletest"
)

// contributionViolations is the M14 judgement (ADR-0013, fitness-modules): every module-owned tag of
// the contract has exactly one registering module, and every x-permission of the contract is a
// kernel permission, a built-in marker or in the permissions the modules registered. A hand-mounted
// tag or permission built from kernel types alone shows up here, because it is in no module's
// Contributions.
func contributionViolations(ops []apihost.Operation, byModule map[module.ID][]string, perms []string, kernel []string) []string {
	var bad []string
	owners := map[string][]string{}
	for id, tags := range byModule {
		for _, tag := range tags {
			owners[tag] = append(owners[tag], string(id))
		}
	}
	seen := map[string]bool{}
	for _, op := range ops {
		if !strings.HasPrefix(op.Tag, "platform.") && !seen[op.Tag] {
			seen[op.Tag] = true
			switch n := len(owners[op.Tag]); {
			case n == 0:
				bad = append(bad, "tag "+op.Tag+" is registered by no module")
			case n > 1:
				slices.Sort(owners[op.Tag])
				bad = append(bad, "tag "+op.Tag+" is registered by "+strings.Join(owners[op.Tag], ", "))
			}
		}
		switch op.Permission {
		case "authenticated", "anonymous":
		default:
			if !slices.Contains(perms, op.Permission) && !slices.Contains(kernel, op.Permission) {
				bad = append(bad, "operation "+op.ID+" names x-permission "+op.Permission+" that is in no Contributions.Permissions")
			}
		}
	}
	for tag, ids := range owners {
		if !seen[tag] {
			bad = append(bad, "module "+strings.Join(ids, ", ")+" registers tag "+tag+" that is not in the contract")
		}
	}
	slices.Sort(bad)
	return bad
}

// m14Pending lists the module tags whose builder has not moved into its module yet (ADR-0013
// decision 3, sequencing). It is the only allowance: each entry names the ticket that moves the
// builder and deletes the entry, and an entry whose tag is now registered fails as stale, so the
// list can only shrink. M3 in fitness-modules fails until the same moves land.
var m14Pending = map[string]string{
	"directory":   "T-1865",
	"connections": "T-1867",
	"reports":     "T-1866",
	"helpdesk":    "T-2336",
}

func Test_M14_registrar_contributions_cover_the_contract(t *testing.T) {
	doc, err := apihost.LoadDocument()
	if err != nil {
		t.Fatal(err)
	}
	byModule := map[module.ID][]string{}
	var perms []string
	for _, m := range generatedModules(platform.Deps{}, directory.Services{}) {
		c, err := moduletest.Register(m.Module)
		if err != nil {
			t.Fatalf("register %s: %v", m.ID, err)
		}
		for _, th := range c.API() {
			byModule[m.ID] = append(byModule[m.ID], th.Tag())
		}
		for _, p := range c.Permissions() {
			perms = append(perms, string(p))
		}
	}
	registered := map[string]bool{}
	for _, tags := range byModule {
		for _, tag := range tags {
			registered[tag] = true
		}
	}
	var pending []string
	for tag, ticket := range m14Pending {
		if registered[tag] {
			t.Errorf("M14: m14Pending entry %q (%s) is stale: the tag is registered now, delete the entry", tag, ticket)
		}
		pending = append(pending, tag)
	}
	var bad []string
	for _, b := range contributionViolations(doc.Operations(), byModule, perms, kernelPermissions()) {
		if tag, ok := strings.CutPrefix(b, "tag "); ok && strings.HasSuffix(tag, " is registered by no module") && slices.Contains(pending, strings.TrimSuffix(tag, " is registered by no module")) {
			continue
		}
		bad = append(bad, b)
	}
	if len(bad) > 0 {
		t.Errorf("M14 (ADR-0013): %s", strings.Join(bad, "\n  "))
	}
}

// The check bites: a tag nobody registers, a tag two modules register and an x-permission in no
// catalogue are each reported; a clean set is not.
func Test_M14_failing_fixture(t *testing.T) {
	ops := []apihost.Operation{
		{ID: "a.list", Tag: "alpha", Permission: "alpha.read"},
		{ID: "b.list", Tag: "beta", Permission: "beta.read"},
		{ID: "g.list", Tag: "gamma", Permission: "gamma.missing"},
		{ID: "k.get", Tag: "platform.health", Permission: "anonymous"},
	}
	clean := map[module.ID][]string{"alpha": {"alpha"}, "beta": {"beta"}, "gamma": {"gamma"}}
	if bad := contributionViolations(ops, clean, []string{"alpha.read", "beta.read", "gamma.missing"}, nil); len(bad) != 0 {
		t.Fatalf("clean fixture reported %v", bad)
	}
	dup := map[module.ID][]string{"alpha": {"alpha"}, "beta": {"beta", "alpha"}}
	bad := strings.Join(contributionViolations(ops, dup, []string{"alpha.read", "beta.read"}, nil), "\n")
	for _, want := range []string{"tag alpha is registered by alpha, beta", "tag gamma is registered by no module", "x-permission gamma.missing"} {
		if !strings.Contains(bad, want) {
			t.Errorf("want %q in:\n%s", want, bad)
		}
	}
}
