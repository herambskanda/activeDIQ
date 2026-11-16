package rbac

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

const (
	tplOne = "ffffffff-0000-4000-8000-000000000001"
	tplTwo = "ffffffff-0000-4000-8000-000000000002"
	permHD = authz.Permission("objects.user.reset_password") // held by the built-in helpdesk-operator
)

// ADM-132 and ADM-133 over the real store: the gate refuses a Template the technician is not restricted
// to, is deny-wins across assignments, cannot be escaped by regranting, and sites come back in order.
func TestAssignmentConstraints(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e, g, root := grantsSetup(t, s)
		src, err := NewStore(e.db)
		if err != nil {
			t.Fatal(err)
		}
		az, err := New(src)
		if err != nil {
			t.Fatal(err)
		}
		ctx := authority.WithTenant(context.Background(), e.a.String())
		hd := e.roleID(t, "helpdesk-operator")
		grant := func(by authority.Chain, n int, subj string, templates, sites []string) error {
			return e.do(t, func(ctx context.Context, tx store.Tx) error {
				return g.Grant(ctx, tx, by, GrantInput{ID: gid(n), RoleID: hd, Subject: SubjectRef{Kind: SubjectAccount, Account: subj},
					Roots: []Root{root}, Templates: templates, Sites: sites})
			})
		}
		owner, admin, user := human(ownerAcct), human(adminAcct), human(userAcct)

		// Malformed constraints are refused whole.
		for name, c := range map[string]struct{ tpl, sites []string }{
			"duplicate template": {[]string{tplOne, tplOne}, nil},
			"nil template":       {[]string{"00000000-0000-0000-0000-000000000000"}, nil},
			"not a uuid":         {[]string{"nope"}, nil},
			"duplicate site":     {nil, []string{"HQ", "hq"}},
			"site with a slash":  {nil, []string{"HQ/../x"}},
			"nine sites":         {nil, []string{"1", "2", "3", "4", "5", "6", "7", "8", "9"}},
		} {
			if err := grant(owner, 9, userAcct, c.tpl, c.sites); !errors.Is(err, ErrInvalid) {
				t.Errorf("%s: want ErrInvalid, got %v", name, err)
			}
		}

		if err := grant(owner, 1, userAcct, []string{tplOne}, []string{"Branch", "HQ"}); err != nil {
			t.Fatalf("restricted grant: %v", err)
		}

		// AC1: a different Template is refused, naming the reason; the permitted one passes.
		if err := az.CheckTemplate(ctx, user, permHD, tplOne); err != nil {
			t.Errorf("permitted template: %v", err)
		}
		err = az.CheckTemplate(ctx, user, permHD, tplTwo)
		var te *TemplateError
		if !errors.As(err, &te) || te.Reason != ReasonTemplateNotPermitted || te.Template != tplTwo || !errors.Is(err, ErrDenied) {
			t.Errorf("other template: want a template_not_permitted denial, got %v", err)
		}
		// An unrestricted holder (the admin) may use either; a person holding no such permission may not.
		if err := az.CheckTemplate(ctx, admin, permHD, tplTwo); err != nil {
			t.Errorf("unrestricted holder: %v", err)
		}
		if err := az.CheckTemplate(ctx, user, "objects.user.disable", tplOne); !errors.As(err, &te) {
			t.Errorf("permission not held: want a denial, got %v", err)
		}
		if err := az.CheckTemplate(ctx, user, permHD, "not-a-guid"); !errors.As(err, &te) {
			t.Errorf("malformed template: want a denial, got %v", err)
		}
		if err := az.CheckTemplate(context.Background(), user, permHD, tplOne); !errors.Is(err, ErrDenied) {
			t.Errorf("no tenant: want a denial, got %v", err)
		}

		// Deny-wins: a second, unrestricted assignment of the same permission does not lift the restriction.
		if err := grant(owner, 2, userAcct, nil, nil); err != nil {
			t.Fatal(err)
		}
		if err := az.CheckTemplate(ctx, user, permHD, tplTwo); !errors.As(err, &te) {
			t.Errorf("deny-wins: want a denial, got %v", err)
		}

		// No escape by regranting: the restricted technician (who may grant what they hold) can hand out
		// the role only inside their own list.
		for name, tpl := range map[string][]string{"unrestricted": nil, "another template": {tplTwo}, "both": {tplOne, tplTwo}} {
			if err := grant(user, 3, adminAcct, tpl, nil); !errors.Is(err, ErrEscalation) {
				t.Errorf("regrant %s: want ErrEscalation, got %v", name, err)
			}
		}
		if err := grant(user, 3, adminAcct, []string{tplOne}, nil); err != nil {
			t.Errorf("regrant inside the list: %v", err)
		}

		// ADM-133: sites in the order they were granted, de-duplicated across assignments.
		got, err := az.PreferredSites(ctx, user)
		if err != nil || !slices.Equal(got, []string{"Branch", "HQ"}) {
			t.Errorf("PreferredSites = %v, %v", got, err)
		}
		if got, err := az.PreferredSites(ctx, human("aaaaaaaa-0000-4000-8000-0000000000ff")); err != nil || len(got) != 0 {
			t.Errorf("no assignments: PreferredSites = %v, %v", got, err)
		}
	})
}
