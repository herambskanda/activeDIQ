package ops

import (
	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/connector/ad"
)

// Attr is one attribute with its already-encoded LDAP values. Values of unicodePwd are binary.
type Attr struct {
	Name   string
	Values []string
}

// Change is one change of a Modify: Delete of exactly Values, or Add of Values. There is no replace
// (contract §8.10.3 kind 2): a replace is not a compare-and-set.
type Change struct {
	Add    bool
	Name   string
	Values []string
}

// AddObject sends one AddRequest for the DN the caller built with the DN type.
func AddObject(c ad.WriteConn, objectDN string, attrs []Attr) error {
	req := ldap.NewAddRequest(objectDN, nil)
	for _, a := range attrs {
		req.Attribute(a.Name, a.Values)
	}
	return c.Add(req)
}

// ModifyObject sends one ModifyRequest holding every change (atomic per RFC 4511 section 4.6).
func ModifyObject(c ad.WriteConn, target string, changes []Change) error {
	req := ldap.NewModifyRequest(target, nil)
	for _, ch := range changes {
		if ch.Add {
			req.Add(ch.Name, ch.Values)
		} else {
			req.Delete(ch.Name, ch.Values)
		}
	}
	return c.Modify(req)
}

// DeleteObject sends one DelRequest without the tree-delete control.
func DeleteObject(c ad.WriteConn, target string) error {
	return c.Del(ldap.NewDelRequest(target, nil))
}
