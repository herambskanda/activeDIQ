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
	"strings"
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
				if written || r.dir.applies[o8Obj] != 0 || !strings.HasPrefix(row, "failed|") {
					t.Fatalf("row=%q written=%v applies=%d", row, written, r.dir.applies[o8Obj])
				}
			})
		}
	})
}

// ---- root kinds the product does not evaluate yet: bug T-0824 ----
//
// ADR-0005 rule 7 names group_members, administrative_unit and include_correlated roots; rbac.RootKind
// does not define them and Facts.Roots is never read, so none of this is evaluated today (an exclude of
// those kinds is ignored: fail-open). These tests are real assertions, skipped only by the ticket id so
// they are not counted as passing; when T-0824 lands, delete the Skip lines and they run unchanged.
// They are deliberately absent from the O8 manifest's Tests (listed there as a Gap on T-0824), so
// nothing reads them as coverage. The Entra arms (administrative_unit, Entra group_members and the
// Entra side of include_correlated) additionally need a Graph fake behind authority.Facts; the kinds
// here drive the same Facts.Roots seam, so a fake is added then, not before the product reads it.

const skipT0824 = "T-0824: group_members, administrative_unit and include_correlated roots are not evaluated by rbac"

var nonAncestryKinds = []rbac.RootKind{rootGroupMembers, rootAdminUnit, rootIncludeCorrelat}

// TestO8RemovedFromScopeNonAncestryRoots: with the target a member of the root the operation plans and
// applies; once membership flips to NotMember in the window (removed from the group or AU, the correlated
// AD object moved out, or the correlation dropped to candidate), Apply refuses it and writes nothing.
func TestO8RemovedFromScopeNonAncestryRoots(t *testing.T) {
	t.Skip(skipT0824)
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		for _, kind := range nonAncestryKinds {
			t.Run(string(kind), func(t *testing.T) {
				r := newScopeRig(t, s, rbac.Root{Kind: kind, Connection: o8Conn, GUID: o8Group})
				key := authority.Root{Kind: string(kind), ID: o8Group}
				r.w.set(func(w *world) { w.roots[key] = authority.Member })
				row, written, err := r.applyAfterChange(func(w *world) { w.roots[key] = authority.NotMember })
				if err != nil {
					t.Fatalf("a member of a %s root must be planned: %v", kind, err)
				}
				if written || row != "failed|denied|1|false" {
					t.Fatalf("removed from a %s root: row=%q written=%v", kind, row, written)
				}
			})
		}
	})
}

// TestO8UnknownRootIsRefused: a target whose exclude root reads unknown (a hidden-membership Entra group,
// a read error or timeout, a partial batch) is refused, as is one that reads Member (excluded). Both must
// fail at Plan; today an exclude of a kind the evaluator does not know is ignored, so the write goes through.
func TestO8UnknownRootIsRefused(t *testing.T) {
	t.Skip(skipT0824)
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		for _, kind := range nonAncestryKinds {
			for _, m := range []authority.Membership{authority.Unknown, authority.Member} {
				t.Run(fmt.Sprintf("%s/%s", kind, m), func(t *testing.T) {
					excl := rbac.Root{Kind: kind, Connection: o8Conn, GUID: o8Group, Exclude: true}
					r := newScopeRig(t, s, ouRoot(o8OUA, false), excl)
					key := authority.Root{Kind: string(kind), ID: o8Group}
					r.w.set(func(w *world) { w.roots[key] = m })
					r.dir.set(o8Obj, "old")
					if _, err := r.r.SubmitDirectory(context.Background(), r.req(itemIn{GUID: o8Obj, Want: "new"})); err == nil {
						t.Fatalf("a target whose exclude %s root reads %q was planned", kind, m)
					}
					if r.dir.applies[o8Obj] != 0 {
						t.Fatalf("a write reached the directory (%d applies)", r.dir.applies[o8Obj])
					}
				})
			}
		}
	})
}
