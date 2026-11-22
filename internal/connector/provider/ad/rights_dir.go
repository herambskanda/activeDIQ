package ad

import (
	"context"

	adconn "github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/provider"
	"github.com/skenzeriq/activediq/internal/connector/tier0"
	adguid "github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/ldapfilter"
)

// SessionDirectory adapts an *adconn.Session.
type SessionDirectory struct {
	tier0.SessionDirectory
}

// NewSessionDirectory wraps s.
func NewSessionDirectory(s *adconn.Session) SessionDirectory {
	return SessionDirectory{tier0.SessionDirectory{S: s}}
}

var _ provider.RightsDirectory = SessionDirectory{}

func (d SessionDirectory) Read(ctx context.Context, ref dn.ObjectRef, attrs []string, opts adconn.ReadOptions) (*adconn.Entry, error) {
	return d.S.Read(ctx, ref, attrs, opts)
}

func (d SessionDirectory) SchemaByName(ctx context.Context, name string, class bool) (provider.SchemaObject, bool, error) {
	sc := adconn.DefaultSchema()
	an, err := ldapfilter.ParseAttrName("lDAPDisplayName", sc)
	if err != nil {
		return provider.SchemaObject{}, false, err
	}
	return d.schema(ctx, ldapfilter.Eq(an, ldapfilter.String(name)), class, true, sc)
}

func (d SessionDirectory) SchemaByID(ctx context.Context, id adguid.GUID) (provider.SchemaObject, bool, error) {
	sc := adconn.DefaultSchema()
	an, err := ldapfilter.ParseAttrName("schemaIDGUID", sc)
	if err != nil {
		return provider.SchemaObject{}, false, err
	}
	return d.schema(ctx, ldapfilter.Eq(an, ldapfilter.Bytes(id.Bytes())), false, false, sc)
}

// schema searches the Schema NC. When byName the class flag picks the object class; by id either
// class matches.
func (d SessionDirectory) schema(ctx context.Context, term ldapfilter.Filter, class, byName bool, sc *ldapfilter.Schema) (provider.SchemaObject, bool, error) {
	nm, err := d.Naming(ctx)
	if err != nil {
		return provider.SchemaObject{}, false, err
	}
	oc, err := ldapfilter.ParseAttrName("objectClass", sc)
	if err != nil {
		return provider.SchemaObject{}, false, err
	}
	var kind ldapfilter.Filter
	switch {
	case !byName:
		kind = ldapfilter.Or(ldapfilter.Eq(oc, ldapfilter.String("attributeSchema")), ldapfilter.Eq(oc, ldapfilter.String("classSchema")))
	case class:
		kind = ldapfilter.Eq(oc, ldapfilter.String("classSchema"))
	default:
		kind = ldapfilter.Eq(oc, ldapfilter.String("attributeSchema"))
	}
	var out provider.SchemaObject
	var found bool
	err = d.S.Search(ctx, adconn.SearchRequest{
		Base: dn.DNRef(nm.Schema), Scope: adconn.ScopeSubtree, Filter: ldapfilter.And(kind, term),
		Attributes: []string{"objectGUID", "lDAPDisplayName", "schemaIDGUID", "searchFlags", "objectClass", "attributeSecurityGUID"},
	}, func(e *adconn.Entry) error {
		raw := e.Raw("schemaIDGUID")
		if len(raw) != 1 || found {
			return nil
		}
		g, gerr := adguid.FromBytes(raw[0])
		if gerr != nil {
			return gerr
		}
		sf, _, _ := e.Int32("searchFlags")
		names := e.Strings("lDAPDisplayName")
		if len(names) != 1 {
			return nil
		}
		out = provider.SchemaObject{Name: names[0], ID: g, SearchFlags: sf}
		if ps := e.Raw("attributeSecurityGUID"); len(ps) == 1 {
			if pg, perr := adguid.FromBytes(ps[0]); perr == nil {
				out.PropSet = &pg
			}
		}
		for _, c := range e.Strings("objectClass") {
			if c == "classSchema" {
				out.Class = true
			}
		}
		found = true
		return nil
	})
	return out, found, err
}

// RightsDirectory implements provider.RightsSource: the rights check reads through the provider's own
// session, so the rights verdict and the reads and writes it gates reach the same DC. A provider that
// is no longer over its session returns nil, which the verify handler answers as unsupported.
func (p *ADProvider) RightsDirectory() provider.RightsDirectory {
	if !p.sessionOK() {
		return nil
	}
	return NewSessionDirectory(p.sess)
}
