package rights

import (
	"context"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/tier0"
	adguid "github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/ldapfilter"
)

// SchemaObject is one attribute or class of the forest's schema.
type SchemaObject struct {
	Name        string // lDAPDisplayName
	ID          adguid.GUID
	Class       bool // classSchema, not attributeSchema
	SearchFlags int32
}

// searchFlagConfidential is fCONFIDENTIAL (searchFlags bit 7): reading the attribute needs
// CONTROL_ACCESS as well as READ_PROPERTY.
const searchFlagConfidential = 0x80

// ADDirectory is everything the AD rights check reads through. The session adapter is
// SessionDirectory; tests use an in-memory forest and the Samba lab.
type ADDirectory interface {
	tier0.ADDirectory
	// Read is a base-scope read that serves the constructed attributes, follows ranges and sends the
	// SD flags control (never SACL).
	Read(ctx context.Context, ref dn.ObjectRef, attrs []string, opts ad.ReadOptions) (*ad.Entry, error)
	// SchemaByName resolves a schema attribute or class by lDAPDisplayName. found is false when the
	// schema has none.
	SchemaByName(ctx context.Context, name string, class bool) (obj SchemaObject, found bool, err error)
	// SchemaByID resolves an attribute or class by schemaIDGUID.
	SchemaByID(ctx context.Context, id adguid.GUID) (obj SchemaObject, found bool, err error)
}

// SessionDirectory adapts an *ad.Session.
type SessionDirectory struct {
	tier0.SessionDirectory
}

// NewSessionDirectory wraps s.
func NewSessionDirectory(s *ad.Session) SessionDirectory {
	return SessionDirectory{tier0.SessionDirectory{S: s}}
}

var _ ADDirectory = SessionDirectory{}

func (d SessionDirectory) Read(ctx context.Context, ref dn.ObjectRef, attrs []string, opts ad.ReadOptions) (*ad.Entry, error) {
	return d.S.Read(ctx, ref, attrs, opts)
}

func (d SessionDirectory) SchemaByName(ctx context.Context, name string, class bool) (SchemaObject, bool, error) {
	sc := ad.DefaultSchema()
	an, err := ldapfilter.ParseAttrName("lDAPDisplayName", sc)
	if err != nil {
		return SchemaObject{}, false, err
	}
	return d.schema(ctx, ldapfilter.Eq(an, ldapfilter.String(name)), class, true, sc)
}

func (d SessionDirectory) SchemaByID(ctx context.Context, id adguid.GUID) (SchemaObject, bool, error) {
	sc := ad.DefaultSchema()
	an, err := ldapfilter.ParseAttrName("schemaIDGUID", sc)
	if err != nil {
		return SchemaObject{}, false, err
	}
	return d.schema(ctx, ldapfilter.Eq(an, ldapfilter.Bytes(id.Bytes())), false, false, sc)
}

// schema searches the Schema NC. When byName the class flag picks the object class; by id either
// class matches.
func (d SessionDirectory) schema(ctx context.Context, term ldapfilter.Filter, class, byName bool, sc *ldapfilter.Schema) (SchemaObject, bool, error) {
	nm, err := d.Naming(ctx)
	if err != nil {
		return SchemaObject{}, false, err
	}
	oc, err := ldapfilter.ParseAttrName("objectClass", sc)
	if err != nil {
		return SchemaObject{}, false, err
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
	var out SchemaObject
	var found bool
	err = d.S.Search(ctx, ad.SearchRequest{
		Base: dn.DNRef(nm.Schema), Scope: ad.ScopeSubtree, Filter: ldapfilter.And(kind, term),
		Attributes: []string{"objectGUID", "lDAPDisplayName", "schemaIDGUID", "searchFlags", "objectClass"},
	}, func(e *ad.Entry) error {
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
		out = SchemaObject{Name: names[0], ID: g, SearchFlags: sf}
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
