package ad

import "testing"

func TestSiteOf(t *testing.T) {
	for in, want := range map[string]string{
		"CN=NTDS Settings,CN=DC1,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=corp,DC=example": "Default-First-Site-Name",
		"CN=NTDS Settings,CN=DC1,CN=Servers,CN=Branch\\, East,CN=Sites,CN=Configuration,DC=corp,DC=example":          "Branch, East",
		"": "", "garbage": "", "CN=a": "",
	} {
		if got := siteOf(in); got != want {
			t.Errorf("siteOf(%q) = %q, want %q", in, got, want)
		}
	}
}
