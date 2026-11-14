package read

import (
	"context"
	"errors"
	"time"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/write"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/ldapfilter"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// ADSource is the Source over an AD session. The reads, the classification and the DC identity
// must all come from one DC, so the only way to build one is NewADSource, which refuses a provider
// that is not over the very session it reads on. The fields are unexported: a struct literal
// cannot bypass the check, and the zero value fails every Read at the DC-identity step.
type ADSource struct {
	sess *ad.Session
	prov *write.ADProvider
}

var _ Source = (*ADSource)(nil)

// NewADSource returns the source for sess. prov's directory and bound-DC binder must both be over
// sess (write.NewADProvider(sess, …) does that); otherwise a pinned Read could be answered by one
// DC while the pin and the verdict name another.
func NewADSource(sess *ad.Session, prov *write.ADProvider) (*ADSource, error) {
	if sess == nil || prov == nil {
		return nil, errors.New("read: a session and a provider are required")
	}
	if !prov.OverSession(sess) {
		return nil, errors.New("read: the provider is not over the reading session")
	}
	return &ADSource{sess: sess, prov: prov}, nil
}

func (a *ADSource) ok() bool { return a != nil && a.sess != nil && a.prov != nil }

func (a *ADSource) Identity() *connectorv1.DirectoryIdentity {
	if !a.ok() {
		return nil
	}
	return a.prov.Identity()
}

func (a *ADSource) BoundDC(ctx context.Context) (*connectorv1.DcIdentity, error) {
	if !a.ok() {
		return nil, write.ErrNoBoundDC
	}
	return a.prov.BoundDC(ctx)
}

func (a *ADSource) Read(ctx context.Context, id guid.GUID, attrs []string, maxValues int) (*ad.Entry, error) {
	return a.sess.Read(ctx, dn.GUIDRef(id), attrs, ad.ReadOptions{MaxValues: maxValues, ExtendedDN: true})
}

// Parent returns the parent's objectGUID. ok is false only for a naming-context head, which the
// directory says about itself (instanceType, requested with the entry); an unreadable or
// undecodable parent is an error, never "no parent", because the ancestry feeds authorisation.
func (a *ADSource) Parent(ctx context.Context, e *ad.Entry) (guid.GUID, bool, error) {
	if !a.ok() {
		return guid.GUID{}, false, write.ErrNoBoundDC
	}
	return a.sess.Parent(ctx, e)
}

func (a *ADSource) Syntax(name string) (ldapfilter.Syntax, bool) {
	if !a.ok() {
		return 0, false
	}
	return a.sess.AttrSyntax(name)
}

func (a *ADSource) CanonicalAttr(name string) (string, error) {
	if !a.ok() {
		return "", write.ErrNoBoundDC
	}
	return a.sess.CanonicalAttr(name)
}

func (a *ADSource) Classify(ctx context.Context, id guid.GUID) (write.Verdict, error) {
	if !a.ok() {
		return write.Verdict{}, write.ErrNoBoundDC
	}
	return a.prov.Classify(ctx, id, nil)
}

// Searcher is the optional search half of a Source. A Source without it answers ScopedSearch with
// CAPABILITY_UNSUPPORTED.
type Searcher interface {
	// ParseFilter validates the request's filter AST against the session schema. The caller-rights
	// check of LF-36 is not available on the connector, so a filter that names a DN is refused.
	ParseFilter(f *connectorv1.Filter) (ldapfilter.Filter, error)
	// ScopedSearch streams the matches under each root (ad.Session.ScopedSearch semantics).
	ScopedSearch(ctx context.Context, req ad.ScopedRequest, fn func(*ad.Entry) error) (ad.ScopedResult, error)
}

var _ Searcher = (*ADSource)(nil)

func (a *ADSource) ParseFilter(f *connectorv1.Filter) (ldapfilter.Filter, error) {
	if !a.ok() {
		return nil, write.ErrNoBoundDC
	}
	return ldapfilter.ParseFilterAST(f, a.sess.FilterSchema(), nil, ldapfilter.Limits{})
}

func (a *ADSource) ScopedSearch(ctx context.Context, req ad.ScopedRequest, fn func(*ad.Entry) error) (ad.ScopedResult, error) {
	if !a.ok() {
		return ad.ScopedResult{}, write.ErrNoBoundDC
	}
	req.ExtendedDN = true // DN-valued attributes carry the target's GUID and SID (T-1202)
	return a.sess.ScopedSearch(ctx, req, fn)
}

// Feeder is the change-feed half of a Source (connector-contract §6). A Source without it answers
// ChangeFeed with CAPABILITY_UNSUPPORTED.
type Feeder interface {
	// ManagesNC reports whether the connection manages the naming context with this objectGUID: the
	// domain NC the bound DC serves, and nothing else (not Configuration, Schema or an application
	// partition, which DirSync would otherwise follow).
	ManagesNC(ctx context.Context, nc guid.GUID) (bool, error)
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

var _ Feeder = (*ADSource)(nil)

func (a *ADSource) ManagesNC(ctx context.Context, nc guid.GUID) (bool, error) {
	if !a.ok() {
		return false, write.ErrNoBoundDC
	}
	dom, err := a.sess.DomainNCGUID(ctx)
	if err != nil {
		return false, err
	}
	return dom == nc, nil
}

func (a *ADSource) CheckFeedAttributes(names []string) error {
	if !a.ok() {
		return write.ErrNoBoundDC
	}
	return a.sess.CheckDirSyncAttributes(names)
}

func (a *ADSource) HighestCommittedUSN(ctx context.Context) (int64, error) {
	if !a.ok() {
		return 0, write.ErrNoBoundDC
	}
	return a.sess.HighestCommittedUSN(ctx)
}

func (a *ADSource) DeletionLifetime(ctx context.Context) (time.Duration, error) {
	if !a.ok() {
		return 0, write.ErrNoBoundDC
	}
	return a.sess.DeletionLifetime(ctx)
}

func (a *ADSource) DirSyncCycle(ctx context.Context, req ad.DirSyncRequest, fn func(ad.DirSyncPage) error) (ad.DirSyncPage, error) {
	if !a.ok() {
		return ad.DirSyncPage{}, write.ErrNoBoundDC
	}
	return a.sess.DirSyncCycle(ctx, req, fn)
}

// Describer is the optional topology half of a Source. A Source without it answers Describe with
// CAPABILITY_UNSUPPORTED.
type Describer interface {
	// Topology reads the forest's naming contexts and the bound DC's paging limits on the one session.
	Topology(ctx context.Context) (*ad.Topology, error)
}

var _ Describer = (*ADSource)(nil)

func (a *ADSource) Topology(ctx context.Context) (*ad.Topology, error) {
	if !a.ok() {
		return nil, write.ErrNoBoundDC
	}
	return a.sess.Topology(ctx)
}

// IsSamba reports whether the bound DC's rootDSE names Samba as its vendor; it labels the
// ReadReplicationStatus capability and gates nothing.
func (a *ADSource) IsSamba(ctx context.Context) (bool, error) {
	if !a.ok() {
		return false, write.ErrNoBoundDC
	}
	rd, err := a.sess.RootDSE(ctx)
	if err != nil {
		return false, err
	}
	return rd.IsSamba(), nil
}
