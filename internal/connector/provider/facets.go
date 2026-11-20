package provider

import (
	"context"
	"time"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/tier0"
	adguid "github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/ldapfilter"
	"github.com/skenzeriq/activediq/internal/directory/sd"
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

// PasswordChanger is the optional Cannot Change Password half of the object-reading facets. A
// provider without it answers include_password_change with NOT_CONFIRMED (CAPABILITY_UNSUPPORTED as
// the code).
type PasswordChanger interface {
	// ReadPasswordChange reads the object's DACL (DACL-only SD flags, never the SACL) and classifies
	// it. It returns the objectGUID the state belongs to; the state is NotConfirmed exactly when err
	// is non-nil. No descriptor byte leaves the connector.
	ReadPasswordChange(ctx context.Context, id adguid.GUID) (adguid.GUID, sd.PasswordChange, error)
}

// ChildCounter is the optional child-count half of the object-reading facets (§5.3a). A provider
// without it answers a request with include_child_count with CAPABILITY_UNSUPPORTED.
type ChildCounter interface {
	// CountChildren counts the immediate children of the object, at most limit (ad.Session.CountChildren).
	CountChildren(ctx context.Context, id adguid.GUID, limit uint32) (n uint32, capped bool, err error)
}

// Feeder is the change-feed half of the object-reading facets (connector-contract §6). A provider
// without it answers ChangeFeed with CAPABILITY_UNSUPPORTED.
type Feeder interface {
	// ManagesNC reports whether the connection manages the naming context with this objectGUID: the
	// domain NC the bound DC serves, and nothing else.
	ManagesNC(ctx context.Context, nc adguid.GUID) (bool, error)
	// CheckFeedAttributes refuses wildcards, read-only constructed attributes and SecretAttrs members
	// before any request reaches the DC.
	CheckFeedAttributes(names []string) error
	// HighestCommittedUSN is the bound DC's highestCommittedUSN, read now.
	HighestCommittedUSN(ctx context.Context) (int64, error)
	// DeletionLifetime is the smaller of tombstoneLifetime and msDS-DeletedObjectLifetime.
	DeletionLifetime(ctx context.Context) (time.Duration, error)
	// DirSyncCycle runs DirSync responses from the request's cookie to the end of the cycle
	// (ad.Session.DirSyncCycle semantics).
	DirSyncCycle(ctx context.Context, req ad.DirSyncRequest, fn func(ad.DirSyncPage) error) (ad.DirSyncPage, error)
}

// Describer is the optional topology half of the object-reading facets. A provider without it
// answers Describe with CAPABILITY_UNSUPPORTED.
type Describer interface {
	// Topology reads the forest's naming contexts and the bound DC's paging limits on the one session.
	Topology(ctx context.Context) (*ad.Topology, error)
	// IsSamba reports whether the bound DC's vendor is Samba; it labels capabilities and gates nothing.
	IsSamba(ctx context.Context) (bool, error)
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

// ObjectDirectory is what the object create, update and delete kinds need from the directory
// session; *ad.Session is the AD implementation. Every call of Do runs on the one DC the session is
// bound to.
type ObjectDirectory interface {
	Do(ctx context.Context, fn func(*ad.Tx) error) error
	EditableAttr(name string) (string, ldapfilter.Syntax, error)
	// AttrOID is the schema attributeID of a resolved ldapDisplayName ("" if unknown).
	AttrOID(name string) string
}

// AccountSession is what the account kinds need from a directory session; *ad.Session implements it.
type AccountSession interface {
	DCIdentity(ctx context.Context) (ad.DCIdentity, error)
	ReadAccount(ctx context.Context, ref dn.ObjectRef) (ad.AccountState, error)
	ModifyAccount(ctx context.Context, ref dn.ObjectRef, check ad.AccountCheck, send ad.AccountSender, needSecure bool) error
}

// StructureDirectory is what the object move, rename and restore kinds need from the directory.
// Every method acts on the one DC the provider's session is bound to (rule 5); Move, Rename and
// Restore re-check under the session lock and send exactly one write.
type StructureDirectory interface {
	// State reads one live object by GUID; a deleted object is not visible to it.
	State(ctx context.Context, id adguid.GUID) (ad.ObjectState, error)
	// DeletedState is the deleted-state read of kind 6 Plan and Apply (fixed shape, TM-D33 rule 3):
	// a deleted object comes back with Deleted true, a live one with Deleted false.
	DeletedState(ctx context.Context, id adguid.GUID) (ad.ObjectState, error)
	// RecycleBin reports whether the AD Recycle Bin is enabled for the forest.
	RecycleBin(ctx context.Context) (bool, error)
	Move(ctx context.Context, r ad.MoveRequest) error
	Rename(ctx context.Context, r ad.RenameRequest) error
	Restore(ctx context.Context, r ad.RestoreRequest) error
	// DeletedTarget is the deleted-target read of kind 6 step 7 (TM-F-RIGHTS (b1)); its only caller
	// is the deleted-object classifier, after the container grant was proven.
	DeletedTarget(ctx context.Context, id adguid.GUID) (*ad.Entry, error)
	// DeletedContainer is the container descriptor read (TM-F-RIGHTS (b2)): the DN and the raw
	// owner+DACL descriptor of CN=Deleted Objects of domain.
	DeletedContainer(ctx context.Context, domain dn.DN) (dn.DN, []byte, error)
	// GroupMembers reads a live group's member values with the show-deactivated-link and extended-DN
	// controls and no show-deleted (so a deleted member's value is visible), ranged to the end.
	// truncated reports a cut.
	GroupMembers(ctx context.Context, group adguid.GUID) (members []string, truncated bool, err error)
}

// SessionBacked is the facet of a provider built over one directory session: the parts the write
// group's AD kinds are assembled from. OneSession is non-nil only while the provider's directory and
// its bound-DC binder are both still over that session (rule 5: the DC whose identity a call is
// pinned to is the DC the reads and the writes reach).
type SessionBacked interface {
	// Directory is the classifier's directory.
	Directory() tier0.ADDirectory
	// PinStore is the C13 pin store.
	PinStore() PinStore
	// SelfRef is the connector's own account (the identity of every step-7 read), unset if unknown.
	SelfRef() dn.ObjectRef
	// OneSession is the session, or nil when the provider is not provably over one.
	OneSession() *ad.Session
	// WriteDirectory is the session the object kinds write through (nil: those kinds answer unsupported).
	WriteDirectory() ObjectDirectory
	// AccountSession is the session the account kinds read and write on (nil: unsupported).
	AccountSession() AccountSession
}
