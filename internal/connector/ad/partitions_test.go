package ad

import (
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/dn"
)

func TestNamingContextKinds(t *testing.T) {
	mk := func(s string) dn.DN {
		d, err := dn.Parse(s, dn.Strict)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	cfg, sch, loc := mk("CN=Configuration,DC=lab,DC=test"), mk("CN=Schema,CN=Configuration,DC=lab,DC=test"), mk("DC=lab,DC=test")
	rd := &RootDSE{DomainFunctionality: 7}
	const g = "<GUID=11111111-2222-3333-4444-555555555555>;"
	const sidv = "<SID=S-1-5-21-1-2-3>;"
	for name, c := range map[string]struct {
		attrs  map[string][][]byte
		kind   NCKind
		listed bool
		sid    bool
		level  bool
	}{
		"domain (local)":  {map[string][][]byte{"nCName": {[]byte(g + sidv + "DC=lab,DC=test")}, "systemFlags": {[]byte("3")}}, NCDomain, true, true, true},
		"domain (child)":  {map[string][][]byte{"nCName": {[]byte(g + sidv + "DC=child,DC=lab,DC=test")}, "systemFlags": {[]byte("3")}}, NCDomain, true, true, false},
		"configuration":   {map[string][][]byte{"nCName": {[]byte(g + "CN=Configuration,DC=lab,DC=test")}, "systemFlags": {[]byte("1")}}, NCConfiguration, true, false, false},
		"schema":          {map[string][][]byte{"nCName": {[]byte(g + "CN=Schema,CN=Configuration,DC=lab,DC=test")}, "systemFlags": {[]byte("1")}}, NCSchema, true, false, false},
		"application":     {map[string][][]byte{"nCName": {[]byte(g + "DC=DomainDnsZones,DC=lab,DC=test")}, "systemFlags": {[]byte("5")}}, NCApplication, true, false, false},
		"not yet enabled": {map[string][][]byte{"nCName": {[]byte(g + "DC=new,DC=lab,DC=test")}, "systemFlags": {[]byte("3")}, "enabled": {[]byte("FALSE")}}, 0, false, false, false},
	} {
		t.Run(name, func(t *testing.T) {
			nc, listed, err := namingContextOf(NewEntry("CN=x", c.attrs), cfg, sch, loc, true, rd)
			if err != nil || listed != c.listed {
				t.Fatalf("listed=%v err=%v", listed, err)
			}
			if !listed {
				return
			}
			if nc.Kind != c.kind || nc.HasSID != c.sid || nc.HasFunctionalLevel != c.level || nc.GUID.String() != "11111111-2222-3333-4444-555555555555" {
				t.Errorf("nc = %+v", nc)
			}
		})
	}
	for name, attrs := range map[string]map[string][][]byte{
		"no GUID in nCName": {"nCName": {[]byte("DC=lab,DC=test")}, "systemFlags": {[]byte("3")}},
		"no systemFlags":    {"nCName": {[]byte(g + "DC=lab,DC=test")}},
		"no nCName":         {"systemFlags": {[]byte("3")}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := namingContextOf(NewEntry("CN=x", attrs), cfg, sch, loc, true, rd); err == nil {
				t.Fatal("a crossRef the connector cannot classify was listed")
			}
		})
	}
}
