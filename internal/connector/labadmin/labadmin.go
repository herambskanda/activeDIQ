// Package labadmin is the lab-test fixture connection: an administrator LDAPS session that creates
// and deletes the OUs and users a lab test needs, and reads their objectGUID. It lives under
// internal/connector because only the connector root talks LDAP (ADR-0005 rule 2, fitness O2); tests
// outside it (internal/compose/server) use this seam instead of importing the LDAP library.
// It is test support: product code must not import it.
package labadmin

import (
	"crypto/tls"
	"crypto/x509"
	"strconv"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
)

// Admin is a bound administrator session on the lab DC.
type Admin struct {
	tb   testing.TB
	conn *ldap.Conn
}

// Dial opens an LDAPS session to localhost:port trusting pool and binds as bindName. The session is
// closed when the test ends. Failure fails the test.
func Dial(tb testing.TB, port string, pool *x509.CertPool, bindName, password string) *Admin {
	tb.Helper()
	c, err := ldap.DialURL("ldaps://localhost:"+port, ldap.DialWithTLSConfig(&tls.Config{RootCAs: pool, ServerName: "localhost"}))
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { c.Close() })
	if err := c.Bind(bindName, password); err != nil {
		tb.Fatal(err)
	}
	return &Admin{tb: tb, conn: c}
}

// ObjectGUID returns the raw objectGUID bytes of the object at dn.
func (a *Admin) ObjectGUID(dn string) []byte {
	a.tb.Helper()
	r, err := a.conn.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"objectGUID"}, nil))
	if err != nil || len(r.Entries) != 1 {
		a.tb.Fatalf("guid of %s: %v", dn, err)
	}
	return r.Entries[0].GetRawAttributeValue("objectGUID")
}

// CreateOU adds OU=name,parent and deletes it when the test ends. It returns the DN.
func (a *Admin) CreateOU(name, parent string) string {
	a.tb.Helper()
	return a.add("OU="+name+","+parent, map[string][]string{"objectClass": {"top", "organizationalUnit"}})
}

// CreateUser adds CN=cn,parent with sAMAccountName cn and deletes it when the test ends.
func (a *Admin) CreateUser(cn, parent string) string {
	a.tb.Helper()
	return a.add("CN="+cn+","+parent, map[string][]string{
		"objectClass":    {"top", "person", "organizationalPerson", "user"},
		"sAMAccountName": {cn},
	})
}

func (a *Admin) add(dn string, attrs map[string][]string) string {
	a.tb.Helper()
	req := ldap.NewAddRequest(dn, nil)
	for k, v := range attrs {
		req.Attribute(k, v)
	}
	if err := a.conn.Add(req); err != nil {
		a.tb.Fatal(err)
	}
	a.tb.Cleanup(func() { _ = a.conn.Del(ldap.NewDelRequest(dn, nil)) })
	return dn
}

// AddMember makes the account with sAMAccountName sam a member of the group at groupDN, and removes
// the membership when the test ends, so a test that puts the service account in a Tier-0 group
// leaves the shared lab as it found it. Failure fails the test.
func (a *Admin) AddMember(groupDN, sam string) {
	a.tb.Helper()
	r, err := a.conn.Search(ldap.NewSearchRequest(a.baseDN(), ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 0, false,
		"(&(objectClass=user)(sAMAccountName="+ldap.EscapeFilter(sam)+"))", []string{"distinguishedName"}, nil))
	if err != nil || len(r.Entries) != 1 {
		a.tb.Fatalf("find account %q: %v", sam, err)
	}
	member := r.Entries[0].DN
	mod := ldap.NewModifyRequest(groupDN, nil)
	mod.Add("member", []string{member})
	if err := a.conn.Modify(mod); err != nil {
		a.tb.Fatal(err)
	}
	a.tb.Cleanup(func() {
		undo := ldap.NewModifyRequest(groupDN, nil)
		undo.Delete("member", []string{member})
		if err := a.conn.Modify(undo); err != nil {
			a.tb.Errorf("LAB DIRTY: could not remove %q from %s: %v", sam, groupDN, err)
		}
	})
}

// baseDN is the domain naming context of the session's DC.
func (a *Admin) baseDN() string {
	a.tb.Helper()
	r, err := a.conn.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"defaultNamingContext"}, nil))
	if err != nil || len(r.Entries) != 1 {
		a.tb.Fatalf("rootDSE: %v", err)
	}
	return r.Entries[0].GetAttributeValue("defaultNamingContext")
}

// Move renames dn's parent to newParent (an LDAP ModifyDN keeping the RDN) and deletes the object at its
// new DN when the test ends. The objectGUID is unchanged. It returns the new DN.
func (a *Admin) Move(dn, newParent string) string {
	a.tb.Helper()
	rdn := dn[:indexUnescapedComma(dn)]
	if err := a.conn.ModifyDN(ldap.NewModifyDNRequest(dn, rdn, true, newParent)); err != nil {
		a.tb.Fatal(err)
	}
	newDN := rdn + "," + newParent
	a.tb.Cleanup(func() { _ = a.conn.Del(ldap.NewDelRequest(newDN, nil)) })
	return newDN
}

// indexUnescapedComma is the offset of the first comma of dn not preceded by a backslash.
func indexUnescapedComma(dn string) int {
	for i := 0; i < len(dn); i++ {
		switch dn[i] {
		case '\\':
			i++
		case ',':
			return i
		}
	}
	return len(dn)
}

// Partitions is a direct administrator read of the DC's naming contexts, for tests that compare a
// connector's Describe against the directory itself.
type Partitions struct {
	DomainDN, ConfigDN, SchemaDN string
	// RootDomainGUID is the raw objectGUID of the forest root domain head.
	RootDomainGUID []byte
	// Heads are the nCName DNs of every enabled crossRef in CN=Partitions.
	Heads []string
}

// ReadPartitions reads the rootDSE and the enabled crossRefs under CN=Partitions. Failure fails the test.
func (a *Admin) ReadPartitions() Partitions {
	a.tb.Helper()
	search := func(base string, scope int, filter string, attrs ...string) []*ldap.Entry {
		a.tb.Helper()
		r, err := a.conn.Search(ldap.NewSearchRequest(base, scope, ldap.NeverDerefAliases, 0, 0, false, filter, attrs, nil))
		if err != nil {
			a.tb.Fatalf("direct read %s: %v", base, err)
		}
		return r.Entries
	}
	root := search("", ldap.ScopeBaseObject, "(objectClass=*)", "defaultNamingContext", "configurationNamingContext", "schemaNamingContext", "rootDomainNamingContext")
	if len(root) != 1 {
		a.tb.Fatalf("rootDSE: %d entries", len(root))
	}
	p := Partitions{
		DomainDN: root[0].GetAttributeValue("defaultNamingContext"),
		ConfigDN: root[0].GetAttributeValue("configurationNamingContext"),
		SchemaDN: root[0].GetAttributeValue("schemaNamingContext"),
	}
	p.RootDomainGUID = a.ObjectGUID(root[0].GetAttributeValue("rootDomainNamingContext"))
	for _, x := range search("CN=Partitions,"+p.ConfigDN, ldap.ScopeSingleLevel, "(&(objectClass=crossRef)(!(enabled=FALSE)))", "nCName") {
		p.Heads = append(p.Heads, x.GetAttributeValue("nCName"))
	}
	return p
}

// AddValues adds vals to the multi-valued attribute attr of the object at dn (for example a
// servicePrincipalName on a seeded user) and removes exactly those values when the test ends, so the
// shared lab is left as it was found. Failure fails the test.
func (a *Admin) AddValues(dn, attr string, vals ...string) {
	a.tb.Helper()
	mod := ldap.NewModifyRequest(dn, nil)
	mod.Add(attr, vals)
	if err := a.conn.Modify(mod); err != nil {
		a.tb.Fatalf("add %s on %s: %v", attr, dn, err)
	}
	a.tb.Cleanup(func() {
		undo := ldap.NewModifyRequest(dn, nil)
		undo.Delete(attr, vals)
		if err := a.conn.Modify(undo); err != nil {
			a.tb.Errorf("LAB DIRTY: could not remove %s values from %s: %v", attr, dn, err)
		}
	})
}

// DNOf returns the DN of the one account whose sAMAccountName is sam. Failure fails the test.
func (a *Admin) DNOf(sam string) string {
	a.tb.Helper()
	r, err := a.conn.Search(ldap.NewSearchRequest(a.baseDN(), ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 0, false,
		"(&(objectClass=user)(sAMAccountName="+ldap.EscapeFilter(sam)+"))", []string{"distinguishedName"}, nil))
	if err != nil || len(r.Entries) != 1 {
		a.tb.Fatalf("find account %q: %v", sam, err)
	}
	return r.Entries[0].DN
}

// CreateLoginUser adds an enabled account CN=cn,parent with sAMAccountName cn, userPrincipalName
// cn@upnSuffix and the given password, and deletes it when the test ends. It returns the DN. A lab test
// binds as such an account to observe what the DC records for a logon.
func (a *Admin) CreateLoginUser(cn, parent, upnSuffix, password string) string {
	a.tb.Helper()
	utf16 := make([]byte, 0, 2*(len(password)+2))
	for _, r := range `"` + password + `"` { // password is ASCII in the lab tests: one UTF-16LE unit each
		utf16 = append(utf16, byte(r), byte(r>>8))
	}
	req := ldap.NewAddRequest("CN="+cn+","+parent, nil)
	req.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "user"})
	req.Attribute("sAMAccountName", []string{cn})
	req.Attribute("userPrincipalName", []string{cn + "@" + upnSuffix})
	req.Attribute("userAccountControl", []string{"512"})
	req.Attribute("unicodePwd", []string{string(utf16)})
	if err := a.conn.Add(req); err != nil {
		a.tb.Fatalf("create login user %s: %v", cn, err)
	}
	dn := "CN=" + cn + "," + parent
	a.tb.Cleanup(func() { _ = a.conn.Del(ldap.NewDelRequest(dn, nil)) })
	return dn
}

// computedUACLockout is UF_LOCKOUT in msDS-User-Account-Control-Computed: the DC's own verdict that the
// account is locked out now (lockoutTime inside the lockout duration).
const computedUACLockout = 0x10

// LockedOutGUIDs returns the lower-case canonical objectGUIDs of the user accounts the DC itself reports
// as locked out now: lockoutTime set and the constructed msDS-User-Account-Control-Computed carrying
// UF_LOCKOUT. The filter is a constant. Failure fails the test.
func (a *Admin) LockedOutGUIDs() map[string]struct{} {
	a.tb.Helper()
	r, err := a.conn.SearchWithPaging(ldap.NewSearchRequest(a.baseDN(), ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(objectClass=user)(!(objectClass=computer))(lockoutTime>=1))", []string{"objectGUID", "msDS-User-Account-Control-Computed"}, nil), 500)
	if err != nil {
		a.tb.Fatalf("locked-out search: %v", err)
	}
	out := map[string]struct{}{}
	for _, e := range r.Entries {
		n, err := strconv.ParseInt(e.GetAttributeValue("msDS-User-Account-Control-Computed"), 10, 64)
		if err != nil || n&computedUACLockout == 0 {
			continue
		}
		g, err := guid.FromBytes(e.GetRawAttributeValue("objectGUID"))
		if err != nil {
			a.tb.Fatalf("objectGUID: %v", err)
		}
		out[strings.ToLower(g.String())] = struct{}{}
	}
	return out
}

// LogonAttrs returns lastLogon and lastLogonTimestamp (each possibly empty) of the account with
// sAMAccountName sam, read through the administrator session. Failure fails the test.
func (a *Admin) LogonAttrs(sam string) (lastLogon, lastLogonTimestamp []string) {
	a.tb.Helper()
	r, err := a.conn.Search(ldap.NewSearchRequest(a.baseDN(), ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 0, false,
		"(&(objectClass=user)(sAMAccountName="+ldap.EscapeFilter(sam)+"))", []string{"lastLogon", "lastLogonTimestamp"}, nil))
	if err != nil || len(r.Entries) != 1 {
		a.tb.Fatalf("logon attributes of %q: %v", sam, err)
	}
	return r.Entries[0].GetAttributeValues("lastLogon"), r.Entries[0].GetAttributeValues("lastLogonTimestamp")
}
