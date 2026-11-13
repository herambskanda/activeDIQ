package ad

import (
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/attr/secretattr"
	"github.com/skenzeriq/activediq/internal/directory/ldapfilter"
	dirsync "github.com/skenzeriq/activediq/internal/directory/sync"
)

// syncSyntax is the syntax each non-obvious closed-list attribute must carry. The rest are strings
// or already pinned by the tier-0/rights tests.
var syncSyntax = map[string]ldapfilter.Syntax{
	"managedBy":             ldapfilter.SynDN,
	"lastKnownParent":       ldapfilter.SynDN,
	"member":                ldapfilter.SynDN,
	"mS-DS-ConsistencyGuid": ldapfilter.SynOctet,
	"lockoutTime":           ldapfilter.SynInt64,
	"pwdLastSet":            ldapfilter.SynInt64,
	"accountExpires":        ldapfilter.SynInt64,
	"lastLogonTimestamp":    ldapfilter.SynInt64,
	"isDeleted":             ldapfilter.SynBool,
	"isRecycled":            ldapfilter.SynBool,
	"mail":                  ldapfilter.SynString,
	"company":               ldapfilter.SynString,
	"operatingSystem":       ldapfilter.SynString,
	"userAccountControl":    ldapfilter.SynInt32,
	"primaryGroupID":        ldapfilter.SynInt32,
	"groupType":             ldapfilter.SynInt32,
	"whenCreated":           ldapfilter.SynGenTime,
	"whenChanged":           ldapfilter.SynGenTime,
}

// T-1203: every name on directory/sync's closed attribute list is requestable through a session opened
// with the default schema (ScopedSearch, checkAttrs allowConstructed=false), is none of SecretAttrs,
// nTSecurityDescriptor or a constructed attribute, and carries the right syntax. It fails when a name is
// added to sync.Attributes() without a DefaultSchema entry.
func Test_DefaultSchema_covers_sync_list(t *testing.T) {
	names := dirsync.Attributes()
	if len(names) == 0 {
		t.Fatal("empty closed list")
	}
	sc := DefaultSchema()
	secrets := map[string]struct{}{"ntsecuritydescriptor": {}}
	for _, n := range secretattr.Static() {
		secrets[strings.ToLower(n)] = struct{}{}
	}
	s := newOffline()
	for _, n := range names {
		if _, bad := secrets[strings.ToLower(n)]; bad {
			t.Errorf("%s is a secret or refused attribute and must not be on the closed list", n)
		}
		if _, ro := constructedReadOnly[strings.ToLower(n)]; ro {
			t.Errorf("%s is constructed read-only", n)
		}
		if sc.IsSecret(n) {
			t.Errorf("%s is secret in the default schema", n)
		}
		got, err := s.checkAttrs([]string{n}, false)
		if err != nil {
			t.Errorf("%s: ScopedSearch would refuse it: %v", n, err)
			continue
		}
		if len(got) != 1 || !strings.EqualFold(got[0], n) {
			t.Errorf("%s: resolved to %v", n, got)
		}
		if want, ok := syncSyntax[n]; ok {
			if syn, _ := sc.Syntax(n); syn != want {
				t.Errorf("%s: syntax %v, want %v", n, syn, want)
			}
		}
	}
	// The whole list in one request, as the sync cycle sends it.
	if _, err := s.checkAttrs(names, false); err != nil {
		t.Errorf("full closed list refused: %v", err)
	}
	// Every pinned syntax names a list member, so the table cannot rot silently.
	for n := range syncSyntax {
		found := false
		for _, m := range names {
			found = found || m == n
		}
		if !found {
			t.Errorf("syntax table names %s, which is not on the closed list", n)
		}
	}
}
