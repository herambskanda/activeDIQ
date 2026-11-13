// Package labadmin is the lab-test fixture connection: an administrator LDAPS session that creates
// and deletes the OUs and users a lab test needs, and reads their objectGUID. It lives under
// internal/connector because only the connector root talks LDAP (ADR-0005 rule 2, fitness O2); tests
// outside it (internal/compose/server) use this seam instead of importing the LDAP library.
// It is test support: product code must not import it.
package labadmin

import (
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/go-ldap/ldap/v3"
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
