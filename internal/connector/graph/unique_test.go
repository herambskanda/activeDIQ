package graph_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/connector/graph"
	"github.com/skenzeriq/activediq/internal/directory/odata"
	gs "github.com/skenzeriq/activediq/internal/directory/odata/graphschema"
)

func userLookup(t *testing.T, upn string) odata.Request {
	t.Helper()
	s, err := odata.Str(upn)
	if err != nil {
		t.Fatal(err)
	}
	return odata.Get(odata.Seg(gs.SetUsers)).With(odata.Query{}.
		Filter(odata.Eq(gs.UserPrincipalName, s)).Select(gs.ID, gs.UserPrincipalName).Top(2))
}

// AC3: zero results is NotFound, two is NotUnique, and neither yields an identity to act on.
func TestUniqueZeroAndManyNeverReturnAnIdentity(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.srv.T.Users = []graph.DirectoryObject{
		{ID: guid(1), UserPrincipalName: "alice@contoso.com"},
		{ID: guid(2), UserPrincipalName: "dup@contoso.com"},
		{ID: guid(3), UserPrincipalName: "DUP@contoso.com"},
		{ID: guid(4), UserPrincipalName: "O'Neil@contoso.com"},
	}
	cases := []struct {
		upn  string
		want graph.Code
	}{
		{"nobody@contoso.com", graph.CodeNotFound},
		{"dup@contoso.com", graph.CodeNotUnique},
		{"x' or 1 eq 1 or userPrincipalName eq 'y", graph.CodeNotFound}, // an injection attempt matches nothing
	}
	for _, tc := range cases {
		id, err := r.c.Unique(ctx, userLookup(t, tc.upn), graph.FieldUPN, tc.upn)
		if graph.CodeOf(err) != tc.want || id != (graph.Identity{}) {
			t.Errorf("%q: id=%+v err=%v, want %s", tc.upn, id, err, tc.want)
		}
	}
	id, err := r.c.Unique(ctx, userLookup(t, "alice@contoso.com"), graph.FieldUPN, "Alice@Contoso.com")
	if err != nil || id.ID != G(guid(1)) {
		t.Fatalf("unique lookup: %+v %v", id, err)
	}
	if id, err = r.c.Unique(ctx, userLookup(t, "O'Neil@contoso.com"), graph.FieldUPN, "O'Neil@contoso.com"); err != nil || id.ID != G(guid(4)) {
		t.Fatalf("quote in UPN: %+v %v", id, err)
	}
}

// A hit that does not carry the requested value (server-side folding, OD-L5) is refused.
func TestUniqueMismatchIsRefused(t *testing.T) {
	r := newRig(t)
	r.srv.T.Users = []graph.DirectoryObject{{ID: guid(1), UserPrincipalName: "o’neil@contoso.com"}}
	id, err := r.c.Unique(context.Background(), userLookup(t, "o’neil@contoso.com"), graph.FieldUPN, "o'neil@contoso.com")
	if graph.CodeOf(err) != graph.CodeIdentityMismatch || id != (graph.Identity{}) {
		t.Fatalf("id=%+v err=%v", id, err)
	}
}

func TestUniqueRefusesNonGUIDIDFromGraph(t *testing.T) {
	r := newRig(t)
	r.srv.T.Users = []graph.DirectoryObject{{ID: "not-a-guid", UserPrincipalName: "a@contoso.com"}}
	if _, err := r.c.Unique(context.Background(), userLookup(t, "a@contoso.com"), graph.FieldUPN, "a@contoso.com"); graph.CodeOf(err) != graph.CodeProviderFailure {
		t.Fatalf("err = %v", err)
	}
}

// AC2: no hand-built OData text is left in the Graph client or its fake.
func TestNoHandBuiltODataText(t *testing.T) {
	banned := []string{"$filter", "$expand", "$select", "$top", "$count", "appId='", "url.PathEscape", "RawQuery", "RawPath", "needGUID", "guidRE"}
	for _, dir := range []string{".", "graphtest"} {
		files, _ := filepath.Glob(filepath.Join(dir, "*.go"))
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			for _, bad := range banned {
				if strings.Contains(string(b), bad) {
					t.Errorf("%s contains %q: OData text belongs to internal/directory/odata", f, bad)
				}
			}
		}
	}
}
