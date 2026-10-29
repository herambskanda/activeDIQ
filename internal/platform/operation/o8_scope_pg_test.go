package operation

// ADR-0005 O8, "removed from scope between Plan and Apply is refused" (TM-F-AUTHZ), driven through
// the real pipeline on Postgres with the real rbac.Authorizer deciding at Plan and again at Apply on
// facts read live inside the Action's Apply, as client.Write reads them.
//
// The directory is a fake whose facts a test mutates between Plan and Apply. The Samba lab arm of the
// same rule (an object moved out of an OU, read from a real DC) is
// internal/compose/server TestLabRule5LiveFactsDecideBackingObject and the lab tests in this ticket's
// runbook entry; Samba has no Entra, so the Entra root kinds can only be driven against a fake.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/rbac"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

const (
	o8Conn   = "11111111-1111-4111-8111-111111111111"
	o8OUA    = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	o8OUB    = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	o8NCHead = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	o8Obj    = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	o8Group  = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
	o8Perm   = authz.Permission("ad.user.set")
)

// Root kinds ADR-0005 rule 7 names that the product's rbac.RootKind does not define yet (T-0824).
const (
	rootGroupMembers    rbac.RootKind = "group_members"
	rootAdminUnit       rbac.RootKind = "administrative_unit"
	rootIncludeCorrelat rbac.RootKind = "include_correlated"
)

// memSource is an rbac.Source over fixed assignments for every account.
type memSource struct{ as []rbac.Assignment }

func (m memSource) Assignments(context.Context, tenant.ID, string, time.Time) ([]rbac.Assignment, error) {
	return m.as, nil
}
func (m memSource) SubjectAssignments(context.Context, tenant.ID, rbac.Subjects, time.Time, bool) ([]rbac.Assignment, error) {
	return nil, nil
}
func (m memSource) PendingOrActive(context.Context, tenant.ID, string, time.Time) ([]rbac.Assignment, error) {
	return m.as, nil
}

// world is the directory as the live Facts port reads it; tests mutate it between Plan and Apply.
type world struct {
	mu        sync.Mutex
	ancestors []string
	complete  bool
	roots     map[authority.Root]authority.Membership
	readErr   error
}

func (w *world) set(f func(*world)) { w.mu.Lock(); f(w); w.mu.Unlock() }

func (w *world) facts() (authority.Facts, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.readErr != nil {
		return authority.Facts{}, w.readErr
	}
	roots := map[authority.Root]authority.Membership{}
	for k, v := range w.roots {
		roots[k] = v
	}
	return authority.Facts{Exists: true, Ancestors: append([]string(nil), w.ancestors...), AncestorsComplete: w.complete, Roots: roots}, nil
}

// Facts is the LiveFacts port the Runner reads at Plan and at the gate.
func (w *world) Facts(_ context.Context, _ authority.Pins, _ authority.FactsQuery) (authority.Facts, error) {
	return w.facts()
}

type scopeRig struct {
	*prig
	w *world
}

// newScopeRig wires a pipeline whose Authz is the real rbac.Authorizer over one assignment holding
// roots, and whose Apply re-reads the live facts and re-checks them.
func newScopeRig(t *testing.T, s *storetest.Server, roots ...rbac.Root) *scopeRig {
	t.Helper()
	p := newPRig(t, s, rigOpt{})
	p.dir.conn = o8Conn
	w := &world{ancestors: []string{o8OUA, o8NCHead}, complete: true, roots: map[authority.Root]authority.Membership{}}
	a, err := rbac.New(memSource{as: []rbac.Assignment{{ID: "a1", Permissions: []authz.Permission{o8Perm}, Roots: roots}}})
	if err != nil {
		t.Fatal(err)
	}
	p.r.cfg.Authz = a
	p.r.cfg.Facts = w
	p.dir.live = func(context.Context, authority.FactsQuery) (authority.Facts, error) { return w.facts() }
	return &scopeRig{prig: p, w: w}
}

func ouRoot(g string, exclude bool) rbac.Root {
	return rbac.Root{Kind: rbac.OUSubtree, Connection: o8Conn, GUID: g, Exclude: exclude}
}

// applyAfterChange plans an operation on o8Obj, lets change run in the Plan -> Apply window, applies, and
// returns the step row and whether the directory was written.
func (r *scopeRig) applyAfterChange(change func(*world)) (row string, written bool, err error) {
	r.dir.set(o8Obj, "old")
	sub, err := r.r.SubmitDirectory(context.Background(), r.req(itemIn{GUID: o8Obj, Want: "new"}))
	if err != nil {
		return "", false, fmt.Errorf("plan refused: %w", err)
	}
	if sub.State != OpQueued {
		return "", false, fmt.Errorf("plan state %s, want queued", sub.State)
	}
	r.w.set(change)
	r.runChunks(sub.Operation)
	return r.stepRow(sub.Operation, 0), r.dir.get(o8Obj) == "new", nil
}

// TestO8ScopeControlInScopeStillApplies is the control for every removed-from-scope case: with nothing
// changed in the window the same operation applies, so a refusal below is about the change.
func TestO8ScopeControlInScopeStillApplies(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		r := newScopeRig(t, s, ouRoot(o8OUA, false))
		row, written, err := r.applyAfterChange(func(*world) {})
		if err != nil || row != "verified||1|false" || !written {
			t.Fatalf("row=%q written=%v err=%v", row, written, err)
		}
	})
}

// TestO8RemovedFromScopeADOUMovedOut: an AD object moved out of an OU root between Plan and Apply is
// refused at Apply (step failed, reason denied), is not written, and the operation does not succeed.
func TestO8RemovedFromScopeADOUMovedOut(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		r := newScopeRig(t, s, ouRoot(o8OUA, false))
		row, written, err := r.applyAfterChange(func(w *world) { w.ancestors = []string{o8OUB, o8NCHead} })
		if err != nil {
			t.Fatal(err)
		}
		if row != "failed|denied|1|false" || written || r.dir.applies[o8Obj] != 0 {
			t.Fatalf("row=%q written=%v applies=%d", row, written, r.dir.applies[o8Obj])
		}
	})
}

// TestO8RemovedFromScopeADExcludedSubOU: the object moved into an OU the delegation excludes.
func TestO8RemovedFromScopeADExcludedSubOU(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		r := newScopeRig(t, s, ouRoot(o8NCHead, false), ouRoot(o8OUB, true))
		row, written, err := r.applyAfterChange(func(w *world) { w.ancestors = []string{o8OUB, o8NCHead} })
		if err != nil {
			t.Fatal(err)
		}
		if row != "failed|denied|1|false" || written {
			t.Fatalf("row=%q written=%v", row, written)
		}
	})
}

// TestO8ScopeFactsThatCannotBeProvenAreRefusedAtApply: a live read that errors, or returns a parent chain
// that is not complete, decides nothing and refuses the write (fail closed, rule 7).
func TestO8ScopeFactsThatCannotBeProvenAreRefusedAtApply(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		for name, change := range map[string]func(*world){
			"read error":       func(w *world) { w.readErr = errors.New("dc timeout") },
			"incomplete chain": func(w *world) { w.complete = false },
		} {
			t.Run(name, func(t *testing.T) {
				r := newScopeRig(t, s, ouRoot(o8OUA, false))
				row, written, err := r.applyAfterChange(change)
				if err != nil {
					t.Fatal(err)
				}
				if written || r.dir.applies[o8Obj] != 0 || row[:7] != "failed|" {
					t.Fatalf("row=%q written=%v applies=%d", row, written, r.dir.applies[o8Obj])
				}
			})
		}
	})
}

// ---- root kinds the product does not evaluate yet: expected to fail, bug T-0824 ----

// knownBug runs check, which returns nil when the product behaves as ADR-0005 requires and an error
// describing the deviation otherwise. While bug is open the deviation is logged; when the product is
// fixed the test fails and says to promote it to a plain assertion, so it can never rot green.
func knownBug(t *testing.T, bug string, check func() error) {
	t.Helper()
	if err := check(); err != nil {
		t.Logf("EXPECTED FAILURE (%s): %v", bug, err)
		return
	}
	t.Fatalf("%s is fixed: this case now behaves as ADR-0005 requires; delete knownBug and assert it directly", bug)
}

// removedFromRoot checks one non-ancestry root kind: with the target a member of the root the operation
// plans and applies; once membership flips to NotMember in the window, Apply refuses it.
func removedFromRoot(t *testing.T, s *storetest.Server, kind rbac.RootKind, flipTo authority.Membership) error {
	root := rbac.Root{Kind: kind, Connection: o8Conn, GUID: o8Group}
	r := newScopeRig(t, s, root)
	key := authority.Root{Kind: string(kind), ID: o8Group}
	r.w.set(func(w *world) { w.roots[key] = authority.Member })
	row, written, err := r.applyAfterChange(func(w *world) { w.roots[key] = flipTo })
	if err != nil {
		return fmt.Errorf("a member of a %s root is not planned: %w", kind, err)
	}
	if written || row != "failed|denied|1|false" {
		return fmt.Errorf("removed from a %s root, row=%q written=%v", kind, row, written)
	}
	return nil
}

func TestO8RemovedFromScopeADGroupMembers(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		knownBug(t, "T-0824", func() error { return removedFromRoot(t, s, rootGroupMembers, authority.NotMember) })
	})
}

func TestO8RemovedFromScopeEntraAdministrativeUnit(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		knownBug(t, "T-0824", func() error { return removedFromRoot(t, s, rootAdminUnit, authority.NotMember) })
	})
}

func TestO8RemovedFromScopeEntraGroupMembers(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		knownBug(t, "T-0824", func() error { return removedFromRoot(t, s, rootGroupMembers, authority.NotMember) })
	})
}

// An include_correlated entry: the Entra target is in scope through its correlated AD object. It leaves
// scope when that AD object moves out (membership NotMember) or the correlation drops to candidate
// (the fact reads NotMember too).
func TestO8RemovedFromScopeIncludeCorrelatedADObjectMovedOut(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		knownBug(t, "T-0824", func() error { return removedFromRoot(t, s, rootIncludeCorrelat, authority.NotMember) })
	})
}

func TestO8RemovedFromScopeIncludeCorrelatedDroppedToCandidate(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		knownBug(t, "T-0824", func() error { return removedFromRoot(t, s, rootIncludeCorrelat, authority.NotMember) })
	})
}

// TestO8UnknownRootIsRefused: a target whose exclude root reads unknown (a hidden-membership Entra group,
// a read error or timeout, a partial batch) is refused, as is one that reads Member. Today an exclude of
// a kind the evaluator does not know is silently ignored, so the write goes through (fail-open).
func TestO8UnknownRootIsRefused(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		for _, m := range []authority.Membership{authority.Unknown, authority.Member} {
			knownBug(t, "T-0824", func() error {
				excl := rbac.Root{Kind: rootGroupMembers, Connection: o8Conn, GUID: o8Group, Exclude: true}
				r := newScopeRig(t, s, ouRoot(o8OUA, false), excl)
				key := authority.Root{Kind: string(rootGroupMembers), ID: o8Group}
				r.w.set(func(w *world) { w.roots[key] = m })
				r.dir.set(o8Obj, "old")
				if _, err := r.r.SubmitDirectory(context.Background(), r.req(itemIn{GUID: o8Obj, Want: "new"})); err == nil {
					return fmt.Errorf("a target whose exclude root reads %q was planned", m)
				}
				return nil
			})
		}
	})
}
