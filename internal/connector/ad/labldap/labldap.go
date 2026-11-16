//go:build lab && windowslab

// Package labldap is a thin LDAPS client for lab tests that live outside internal/connector (T-1880's
// sync tests). It exists so go-ldap stays imported only under internal/connector (ADR-0005 rule 2, O2).
// Build-tagged lab+windowslab: it ships in no product binary and nothing in product code may import it.
package labldap

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/go-ldap/ldap/v3"
)

// Conn is a bound LDAPS connection to a lab DC.
type Conn struct{ c *ldap.Conn }

// Dial connects to addr:636 trusting the CA at caPath, verifying tlsHost, and binds as bindName.
func Dial(addr, caPath, tlsHost, bindName, pw string) (*Conn, error) {
	pem, err := os.ReadFile(caPath)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	c, err := ldap.DialURL("ldaps://"+addr+":636", ldap.DialWithTLSConfig(&tls.Config{RootCAs: pool, ServerName: tlsHost}))
	if err != nil {
		return nil, err
	}
	if err := c.Bind(bindName, pw); err != nil {
		c.Close()
		return nil, fmt.Errorf("bind %s: %w", bindName, err)
	}
	return &Conn{c}, nil
}

func (c *Conn) Close() { c.c.Close() }

// Read returns the raw values of attrs on the base object (or, with scopeOne, on the children of base
// matching filter). Entries are returned in server order.
func (c *Conn) read(base string, scope int, filter string, attrs []string) ([]map[string][][]byte, error) {
	r, err := c.c.Search(ldap.NewSearchRequest(base, scope, ldap.NeverDerefAliases, 0, 0, false, filter, attrs, nil))
	if err != nil {
		return nil, err
	}
	var out []map[string][][]byte
	for _, e := range r.Entries {
		m := map[string][][]byte{}
		for _, a := range attrs {
			m[a] = e.GetRawAttributeValues(a)
		}
		out = append(out, m)
	}
	return out, nil
}

// ReadObject reads attrs of the object at dn; filter must be a rendered filter.
func (c *Conn) ReadObject(dn, filter string, attrs []string) ([]map[string][][]byte, error) {
	return c.read(dn, ldap.ScopeBaseObject, filter, attrs)
}

// SearchChildren searches the direct children of base with a rendered filter.
func (c *Conn) SearchChildren(base, filter string, attrs []string) ([]map[string][][]byte, error) {
	return c.read(base, ldap.ScopeSingleLevel, filter, attrs)
}

// Add creates dn with the given attributes.
func (c *Conn) Add(dn string, attrs map[string][]string) error {
	r := ldap.NewAddRequest(dn, nil)
	for k, v := range attrs {
		r.Attribute(k, v)
	}
	return c.c.Add(r)
}

// Replace replaces attr on dn with vals (nil clears it).
func (c *Conn) Replace(dn, attr string, vals []string) error {
	m := ldap.NewModifyRequest(dn, nil)
	m.Replace(attr, vals)
	return c.c.Modify(m)
}

// DeleteIfPresent deletes dn; an already-absent object is not an error.
func (c *Conn) DeleteIfPresent(dn string) error {
	err := c.c.Del(ldap.NewDelRequest(dn, nil))
	if err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
		return err
	}
	return nil
}

