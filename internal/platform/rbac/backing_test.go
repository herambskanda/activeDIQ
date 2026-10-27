package rbac

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

const (
	tech    = "aaaaaaaa-0000-4000-8000-000000000001" // the actor
	console = "aaaaaaaa-0000-4000-8000-000000000002" // the backed console account
	ouC     = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
	ouCSub  = "ffffffff-ffff-4fff-8fff-ffffffffffff"
	entraC  = "12121212-1212-4212-8212-121212121212" // the Entra connection
)

type acctSrc map[string][]Assignment

func (m acctSrc) Assignments(_ context.Context, _ tenant.ID, account string, _ time.Time) ([]Assignment, error) {
	return m[account], nil
}

func (m acctSrc) SubjectAssignments(context.Context, tenant.ID, Subjects, time.Time, bool) ([]Assignment, error) {
	return nil, nil
}

func (m acctSrc) PendingOrActive(_ context.Context, _ tenant.ID, account string, _ time.Time) ([]Assignment, error) {
	return m[account], nil
}

// scheduledSrc is time-aware like Store: the accounts listed hold their assignments only from a
// future valid_from, so Assignments (current) omits them and PendingOrActive includes them.
type scheduledSrc struct {
	acctSrc
	scheduled map[string]bool
}

func (s scheduledSrc) Assignments(ctx context.Context, tn tenant.ID, account string, now time.Time) ([]Assignment, error) {
	if s.scheduled[account] {
		return nil, nil
	}
	return s.acctSrc.Assignments(ctx, tn, account, now)
}

type fakeBacking struct {
	got BackedAccounts
	err error
	ref []authority.TargetRef
}

func (f *fakeBacking) BackedBy(_ context.Context, _ tenant.ID, t authority.TargetRef) (BackedAccounts, error) {
	f.ref = append(f.ref, t)
	return f.got, f.err
}

// fakeRoots resolves ouCSub under ouC, everything else as a top-level root.
type fakeRoots struct{ fail bool }

func (f fakeRoots) Resolve(_ context.Context, _ tenant.ID, r Root) (authz.ScopeRoot, error) {
	if f.fail {
		return authz.ScopeRoot{}, errors.New("unreadable")
	}
	id, _ := authz.ParseObjectID(r.GUID)
	sr := authz.ScopeRoot{ID: id, Complete: true}
	if r.GUID == ouCSub {
		p, _ := authz.ParseObjectID(ouC)
		sr.Ancestors = []authz.ObjectID{p}
	}
	return sr, nil
}

var allPerms = append([]authz.Permission{"objects.user.disable"}, BackingObjectPermissions...)

func ou(guid string) []Root { return []Root{{Kind: OUSubtree, Connection: conn, GUID: guid}} }
func asg(p []authz.Permission, rs ...Root) Assignment {
	return Assignment{ID: "x", Permissions: p, Roots: rs}
}

func guarded(t *testing.T, src acctSrc, b *fakeBacking, r RootResolver) *Authorizer {
	t.Helper()
	a, err := New(src, WithBackingGuard(b, r))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// run authorises perm on obj as the technician, with the object existing under ouA.
func run(a *Authorizer, perm authz.Permission) error {
	tgt := authority.TargetRef{Connection: conn, GUID: obj, Class: "user"}
	f := authority.Facts{Exists: true, AncestorsComplete: true, Ancestors: []string{ouA}}
	return a.Authorize(ctxT(), human(tech), perm, tgt, f)
}

func helpdesk() Assignment { return asg(BackingObjectPermissions, ou(ouA)...) }

func TestBackingObjectResetRefused(t *testing.T) {
	// backing_object_reset_refused: the console account holds more than the technician.
	src := acctSrc{
		tech:    {helpdesk()},
		console: {asg([]authz.Permission{"objects.user.reset_password", "objects.user.delete"}, ou(ouA)...)},
	}
	for name, got := range map[string]BackedAccounts{
		"the AD object of a directory account":      {Accounts: []string{console}, Complete: true},
		"an object correlated to a backing object":  {Accounts: []string{console}, Complete: true},
		"one of several backed accounts is greater": {Accounts: []string{tech, console}, Complete: true},
	} {
		t.Run(name, func(t *testing.T) {
			err := run(guarded(t, src, &fakeBacking{got: got}, fakeRoots{}), "objects.user.reset_password")
			if !errors.Is(err, ErrDenied) || !contains(err, ReasonBackingObject) {
				t.Fatalf("want %s refusal, got %v", ReasonBackingObject, err)
			}
		})
	}
}

func contains(err error, r authz.Reason) bool {
	return err != nil && errors.Is(err, ErrDenied) && stringsContains(err.Error(), string(r))
}

func stringsContains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestBackingObjectOpsSupersetRule(t *testing.T) {
	backed := BackedAccounts{Accounts: []string{console}, Complete: true}
	for _, perm := range BackingObjectPermissions {
		t.Run(string(perm), func(t *testing.T) {
			cases := []struct {
				name    string
				tech    []Assignment
				console []Assignment
				allow   bool
			}{
				{"fewer privileges", []Assignment{helpdesk()}, []Assignment{asg(append([]authz.Permission{"objects.user.delete"}, BackingObjectPermissions...), ou(ouA)...)}, false},
				{"same privileges, same scope", []Assignment{helpdesk()}, []Assignment{helpdesk()}, true},
				{"superset of privileges", []Assignment{asg(append([]authz.Permission{"objects.user.delete"}, BackingObjectPermissions...), ou(ouA)...)}, []Assignment{helpdesk()}, true},
				{"console reaches a wider scope", []Assignment{helpdesk()}, []Assignment{asg(BackingObjectPermissions, append(ou(ouA), ou(ouB)...)...)}, false},
				{"console scope is inside the actor's", []Assignment{helpdesk(), asg(BackingObjectPermissions, ou(ouC)...)}, []Assignment{asg(BackingObjectPermissions, ou(ouCSub)...)}, true},
				{"actor has the console's scope but excludes more", []Assignment{helpdesk(), asg(BackingObjectPermissions, append(ou(ouC), Root{Kind: OUSubtree, Connection: conn, GUID: ouCSub, Exclude: true})...)}, []Assignment{asg(BackingObjectPermissions, ou(ouC)...)}, false},
				{"console has no assignment", []Assignment{helpdesk()}, nil, true},
				{"console holds in another connection only", []Assignment{helpdesk()}, []Assignment{asg(BackingObjectPermissions, Root{Kind: OUSubtree, Connection: conn2, GUID: ouA})}, false},
			}
			for _, c := range cases {
				a := guarded(t, acctSrc{tech: c.tech, console: c.console}, &fakeBacking{got: backed}, fakeRoots{})
				err := run(a, perm)
				if c.allow && err != nil {
					t.Errorf("%s: want allowed, got %v", c.name, err)
				}
				if !c.allow && !contains(err, ReasonBackingObject) {
					t.Errorf("%s: want %s, got %v", c.name, ReasonBackingObject, err)
				}
			}
		})
	}
}

func TestBackingObjectGuardFailsClosed(t *testing.T) {
	src := acctSrc{tech: {helpdesk()}, console: {helpdesk()}}
	ok := BackedAccounts{Accounts: []string{console}, Complete: true}
	t.Run("no guard wired refuses every backing permission", func(t *testing.T) {
		a, _ := New(src)
		for _, p := range BackingObjectPermissions {
			if err := run(a, p); !contains(err, ReasonBackingNoResolver) {
				t.Fatalf("%s: got %v", p, err)
			}
		}
	})
	t.Run("incomplete backing answer", func(t *testing.T) {
		err := run(guarded(t, src, &fakeBacking{got: BackedAccounts{Accounts: nil, Complete: false}}, fakeRoots{}), "objects.user.unlock")
		if !contains(err, ReasonBackingIncomplete) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("backing read error", func(t *testing.T) {
		err := run(guarded(t, src, &fakeBacking{err: errors.New("db down")}, fakeRoots{}), "objects.user.unlock")
		if err == nil || errors.Is(err, ErrDenied) == false && err.Error() == "" {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("unresolvable scope root", func(t *testing.T) {
		err := run(guarded(t, src, &fakeBacking{got: ok}, fakeRoots{fail: true}), "objects.user.unlock")
		if !contains(err, ReasonBackingIncomplete) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("a permission outside the list is not guarded", func(t *testing.T) {
		s := acctSrc{tech: {asg([]authz.Permission{"objects.user.disable"}, ou(ouA)...)}, console: {helpdesk()}}
		if err := run(guarded(t, s, &fakeBacking{got: ok}, fakeRoots{}), "objects.user.disable"); err != nil {
			t.Fatalf("disable must not need the superset: %v", err)
		}
	})
	t.Run("no base permission still refuses before the guard", func(t *testing.T) {
		s := acctSrc{tech: nil, console: {helpdesk()}}
		b := &fakeBacking{got: ok}
		err := run(guarded(t, s, b, fakeRoots{}), "objects.user.unlock")
		if !errors.Is(err, ErrDenied) || len(b.ref) != 0 {
			t.Fatalf("got %v, guard consulted %d times", err, len(b.ref))
		}
	})
}

func TestBackingObjectSSOBinding(t *testing.T) {
	// backing_object_sso_binding: the target is the object an sso account is bound to (oid or
	// onprem_sid), or an object correlated to it. The Backing port expands both; rule 5 applies
	// identically, including for an Entra-connection target.
	src := acctSrc{
		tech:    {asg(BackingObjectPermissions, Root{Kind: EntraTenant, Connection: entraC, GUID: entraC})},
		console: {asg([]authz.Permission{"objects.user.reset_password", "objects.user.delete"}, Root{Kind: EntraTenant, Connection: entraC, GUID: entraC})},
	}
	b := &fakeBacking{got: BackedAccounts{Accounts: []string{console}, Complete: true}}
	a := guarded(t, src, b, fakeRoots{})
	tgt := authority.TargetRef{Connection: entraC, GUID: obj, Class: "user"}
	f := authority.Facts{Exists: true, AncestorsComplete: true}
	for _, p := range BackingObjectPermissions {
		err := a.Authorize(ctxT(), human(tech), p, tgt, f)
		if !contains(err, ReasonBackingObject) {
			t.Fatalf("%s: want refusal, got %v", p, err)
		}
	}
	if len(b.ref) != len(BackingObjectPermissions) || b.ref[0].GUID != obj || b.ref[0].Connection != entraC {
		t.Fatalf("backing was asked about %v", b.ref)
	}
	src[tech] = append(src[tech], asg([]authz.Permission{"objects.user.delete"}, Root{Kind: EntraTenant, Connection: entraC, GUID: entraC}))
	for _, p := range BackingObjectPermissions {
		if err := a.Authorize(ctxT(), human(tech), p, tgt, f); err != nil {
			t.Fatalf("%s: actor holding every privilege must be allowed: %v", p, err)
		}
	}
}

func TestBackingObjectTier0ScopeIsNotCoveredByTenantRoot(t *testing.T) {
	// An entra_tenant root whose GUID equals the connection must not stand in for a tier0_scope root.
	src := acctSrc{
		tech:    {helpdesk(), asg(BackingObjectPermissions, Root{Kind: EntraTenant, Connection: conn, GUID: conn})},
		console: {asg(BackingObjectPermissions, Root{Kind: Tier0Scope, Connection: conn, GUID: conn})},
	}
	err := run(guarded(t, src, &fakeBacking{got: BackedAccounts{Accounts: []string{console}, Complete: true}}, fakeRoots{}), "objects.user.move")
	if !contains(err, ReasonBackingObject) {
		t.Fatalf("got %v", err)
	}
}

func TestBackingObjectFutureGrantRefused(t *testing.T) {
	// The console account's grant starts tomorrow: resetting its AD object now would keep the
	// password past the start. The backed side counts scheduled grants.
	src := scheduledSrc{
		acctSrc:   acctSrc{tech: {helpdesk()}, console: {asg(append([]authz.Permission{"objects.user.delete"}, BackingObjectPermissions...), ou(ouA)...)}},
		scheduled: map[string]bool{console: true},
	}
	a, err := New(src, WithBackingGuard(&fakeBacking{got: BackedAccounts{Accounts: []string{console}, Complete: true}}, fakeRoots{}))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range BackingObjectPermissions {
		if err := run(a, p); !contains(err, ReasonBackingObject) {
			t.Errorf("%s: want %s, got %v", p, ReasonBackingObject, err)
		}
	}
	// The actor side stays current-only: a scheduled grant on the actor does not authorise.
	src2 := scheduledSrc{acctSrc: acctSrc{tech: {helpdesk()}, console: {helpdesk()}}, scheduled: map[string]bool{tech: true}}
	a2, _ := New(src2, WithBackingGuard(&fakeBacking{got: BackedAccounts{Accounts: []string{console}, Complete: true}}, fakeRoots{}))
	if err := run(a2, "objects.user.unlock"); !errors.Is(err, ErrDenied) {
		t.Errorf("scheduled actor grant must not authorise, got %v", err)
	}
}

func TestBackingObjectRootlessBackedGrantRefused(t *testing.T) {
	src := acctSrc{tech: {helpdesk()}, console: {asg([]authz.Permission{"objects.user.delete"})}}
	a := guarded(t, src, &fakeBacking{got: BackedAccounts{Accounts: []string{console}, Complete: true}}, fakeRoots{})
	if err := run(a, "objects.user.reset_password"); !contains(err, ReasonBackingIncomplete) {
		t.Fatalf("want %s, got %v", ReasonBackingIncomplete, err)
	}
	// An exclude-only scope reaches nothing and is still skipped.
	src[console] = []Assignment{asg([]authz.Permission{"objects.user.delete"}, Root{Kind: OUSubtree, Connection: conn, GUID: ouB, Exclude: true})}
	if err := run(a, "objects.user.reset_password"); err != nil {
		t.Fatalf("exclude-only grant reaches nothing: %v", err)
	}
}
