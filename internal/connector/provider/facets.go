package provider

import (
	"context"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/tier0"
	adguid "github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/ldapfilter"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// DCBound is the facet of a directory that has domain controllers. BoundDC reads, live, the
// identity of the DC the provider's session is bound to (ADR-0005 rule 5). A handler pins on it:
// a provider with DCs pins, one without does not. A provider that implements DCBound and cannot
// answer fails closed: every pinned call is refused.
type DCBound interface {
	BoundDC(ctx context.Context) (*connectorv1.DcIdentity, error)
}

// ObjectReader is the facet behind the Read RPC. Every method works on the one session, hence on
// the one DC BoundDC names. The entry type is *ad.Entry until the Entra read spec fixes a
// provider-neutral one.
type ObjectReader interface {
	// Read reads the object with every range followed (ad.Session.Read semantics).
	Read(ctx context.Context, id adguid.GUID, attrs []string, maxValues int) (*ad.Entry, error)
	// Parent returns the objectGUID of the entry's parent; ok is false only for a naming-context head.
	// A parent that cannot be read or decoded is an error: "no parent" is an authoritative claim.
	// The entry carries instanceType (the handler asks for it).
	Parent(ctx context.Context, e *ad.Entry) (g adguid.GUID, ok bool, err error)
	// Syntax is the value syntax of an attribute.
	Syntax(name string) (ldapfilter.Syntax, bool)
	// CanonicalAttr resolves a requested name (ldapDisplayName in any case, or the schema's numeric
	// OID). An OID returns the ldapDisplayName; a descr returns in the case typed, so compare
	// case-insensitively. An attribute outside the schema is an error.
	CanonicalAttr(name string) (string, error)
}

// Searcher is the search half of the object-reading facets, behind ScopedSearch. A provider without
// it answers ScopedSearch with CAPABILITY_UNSUPPORTED.
type Searcher interface {
	// ParseFilter validates the request's filter AST against the session schema. The caller-rights
	// check of LF-36 is not available on the connector, so a filter that names a DN is refused.
	ParseFilter(f *connectorv1.Filter) (ldapfilter.Filter, error)
	// ScopedSearch streams the matches under each root (ad.Session.ScopedSearch semantics).
	ScopedSearch(ctx context.Context, req ad.ScopedRequest, fn func(*ad.Entry) error) (ad.ScopedResult, error)
}

// SchemaObject is one attribute or class of the forest's schema.
type SchemaObject struct {
	Name        string // lDAPDisplayName
	ID          adguid.GUID
	Class       bool // classSchema, not attributeSchema
	SearchFlags int32
}

// RightsDirectory is everything the AD rights check reads through.
type RightsDirectory interface {
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

// RightsSource is the facet behind VerifyConnection: the directory the rights check reads through,
// bound to the provider's own session.
type RightsSource interface {
	RightsDirectory() RightsDirectory
}
