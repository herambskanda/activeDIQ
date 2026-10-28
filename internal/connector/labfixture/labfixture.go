//go:build lab

// Package labfixture is the lab-only LDAP admin fixture helper. Tests outside internal/connector
// (e.g. internal/compose/server) need to create and look up directory objects on the lab DC; the
// directory protocol library may only be imported under internal/connector (ADR-0005 O2), so that
// access lives here. It carries the `lab` build tag and is never part of a ship build.
package labfixture

import (
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
)

// Admin is an administrator LDAPS session to the lab DC, closed at test cleanup.
type Admin struct {
	t *testing.T
	c *ldap.Conn
}

// Dial connects to ldaps://localhost:port and binds as bindName.
func Dial(t *testing.T, port string, pool *x509.CertPool, bindName, password string) *Admin {
	t.Helper()
	c, err := ldap.DialURL("ldaps://localhost:"+port, ldap.DialWithTLSConfig(&tls.Config{RootCAs: pool, ServerName: "localhost"}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if err := c.Bind(bindName, password); err != nil {
		t.Fatal(err)
	}
	return &Admin{t: t, c: c}
}

// GUID returns the objectGUID of dn.
func (a *Admin) GUID(dn string) guid.GUID {
	a.t.Helper()
	r, err := a.c.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"objectGUID"}, nil))
	if err != nil || len(r.Entries) != 1 {
		a.t.Fatalf("guid of %s: %v", dn, err)
	}
	g, err := guid.FromBytes(r.Entries[0].GetRawAttributeValue("objectGUID"))
	if err != nil {
		a.t.Fatal(err)
	}
	return g
}

// MkOU creates OU=name,parent and deletes it at cleanup. The caller supplies a fixed, trusted name.
func (a *Admin) MkOU(name, parent string) string {
	a.t.Helper()
	return a.add("OU="+name+","+parent, []string{"top", "organizationalUnit"}, nil)
}

// MkUser creates CN=cn,parent as a user with sAMAccountName=cn and deletes it at cleanup.
func (a *Admin) MkUser(cn, parent string) string {
	a.t.Helper()
	return a.add("CN="+cn+","+parent, []string{"top", "person", "organizationalPerson", "user"}, map[string][]string{"sAMAccountName": {cn}})
}

func (a *Admin) add(dn string, classes []string, attrs map[string][]string) string {
	a.t.Helper()
	req := ldap.NewAddRequest(dn, nil)
	req.Attribute("objectClass", classes)
	for k, v := range attrs {
		req.Attribute(k, v)
	}
	if err := a.c.Add(req); err != nil {
		a.t.Fatal(err)
	}
	a.t.Cleanup(func() { _ = a.c.Del(ldap.NewDelRequest(dn, nil)) })
	return dn
}
