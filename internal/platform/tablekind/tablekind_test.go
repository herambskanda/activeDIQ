package tablekind

import "testing"

func TestValidate(t *testing.T) {
	ok := Table{Name: "public.tenants", Entity: "DM-01", Kind: Platform}
	if err := ok.Validate(); err != nil {
		t.Fatalf("a well-formed declaration was rejected: %v", err)
	}
	bad := map[string]Table{
		"unqualified name":    {Name: "tenants", Entity: "DM-01", Kind: Platform},
		"upper-case name":     {Name: "public.Tenants", Entity: "DM-01", Kind: Platform},
		"entity not DM-nn":    {Name: "public.t", Entity: "DM-1", Kind: Platform},
		"kind R":              {Name: "public.t", Entity: "DM-01", Kind: "R"},
		"empty kind":          {Name: "public.t", Entity: "DM-01"},
		"malformed sealed":    {Name: "public.t", Entity: "DM-01", Kind: Tenant, Sealed: []string{"Bad Col"}},
		"duplicate name-ok":   {Name: "public.t", Entity: "DM-01", Kind: Tenant, NameOK: []string{"a", "a"}},
		"sealed upper column": {Name: "public.t", Entity: "DM-01", Kind: Tenant, Sealed: []string{"Sealed"}},
	}
	for name, tb := range bad {
		if tb.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestDeclarePanicsOnMalformed(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("Declare accepted a malformed table")
		}
	}()
	Declare(Table{Name: "x"})
}
