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
	"github.com/skenzeriq/activediq/internal/directory/sd"
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

// PasswordChanger is the optional Cannot Change Password half of a Source. A Source without it
// answers include_password_change with NOT_CONFIRMED (CAPABILITY_UNSUPPORTED as the code).
type PasswordChanger interface {
	// ReadPasswordChange reads the object's DACL (DACL-only SD flags, never the SACL) and classifies
	// it. It returns the objectGUID the state belongs to; the state is NotConfirmed exactly when err
	// is non-nil. No descriptor byte leaves the connector.
	ReadPasswordChange(ctx context.Context, id guid.GUID) (guid.GUID, sd.PasswordChange, error)
}

var _ PasswordChanger = (*ADSource)(nil)

func (a *ADSource) ReadPasswordChange(ctx context.Context, id guid.GUID) (guid.GUID, sd.PasswordChange, error) {
	if !a.ok() {
		return guid.GUID{}, sd.PasswordChangeNotConfirmed, write.ErrNoBoundDC
	}
	return a.sess.ReadPasswordChange(ctx, dn.GUIDRef(id))
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

// OpenFunc opens a session bound to one named DC with the connection's credential. The credential
// stays with the caller: the Session never holds it, so the per-DC source cannot open a session by
// itself. It must dial that host only and never fall back to another server.
type OpenFunc func(ctx context.Context, host string) (*ad.Session, error)

// ADPerDCSource is an ADSource that can also read per DC: it lists the DCs from the configuration
// NC through the reading session and opens one short-lived session per DC read.
type ADPerDCSource struct {
	*ADSource
	open OpenFunc
}

var _ PerDCSource = (*ADPerDCSource)(nil)

// NewADPerDCSource adds per-DC reads to src. open is required.
func NewADPerDCSource(src *ADSource, open OpenFunc) (*ADPerDCSource, error) {
	if src == nil || !src.ok() || open == nil {
		return nil, errors.New("read: a source and an opener are required")
	}
	return &ADPerDCSource{ADSource: src, open: open}, nil
}

func (a *ADPerDCSource) DomainDCs(ctx context.Context, nc guid.GUID) ([]DC, error) {
	head, err := a.sess.Read(ctx, dn.GUIDRef(nc), []string{"distinguishedName", "instanceType"}, ad.ReadOptions{})
	if err != nil {
		return nil, err
	}
	d, err := dn.Parse(head.DN, dn.Strict)
	if err != nil {
		return nil, err
	}
	// Only a domain naming-context head names a domain: instanceType has the head bit (IT_NC_HEAD, 0x1).
	if it, ok, err := head.Int32("instanceType"); err != nil || !ok || it&1 == 0 {
		return nil, &ad.Error{Code: ad.CodeObjectNotFound}
	}
	list, err := a.sess.DomainControllers(ctx, d)
	if err != nil {
		return nil, err
	}
	out := make([]DC, len(list))
	for i, c := range list {
		out[i] = DC{Host: c.Host, Site: c.Site, DSAGUID: c.DSAGUID, RODC: c.RODC, RODCKnown: c.RODCKnown}
	}
	return out, nil
}

func (a *ADPerDCSource) ReadOnDC(ctx context.Context, dc DC, id guid.GUID, attrs []string) (*ad.Entry, *connectorv1.DcIdentity, error) {
	s, err := a.open(ctx, dc.Host)
	if err != nil {
		return nil, nil, err
	}
	defer s.Close()
	ident, err := s.DCIdentity(ctx)
	if err != nil {
		return nil, nil, err
	}
	who := &connectorv1.DcIdentity{DsaGuid: write.GUIDToWire(ident.DSAGUID), InvocationId: write.GUIDToWire(ident.InvocationID),
		DnsHostname: ident.DNSHostName, Site: ident.Site}
	if ident.DSAGUID != dc.DSAGUID {
		return nil, who, &ad.Error{Code: ad.CodeUnreachable} // another DC answered at this host
	}
	e, err := s.Read(ctx, dn.GUIDRef(id), attrs, ad.ReadOptions{})
	return e, who, err
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

// ChildCounter is the optional child-count half of a Source (§5.3a). A Source without it answers a
// request with include_child_count with CAPABILITY_UNSUPPORTED.
type ChildCounter interface {
	// CountChildren counts the immediate children of the object, at most limit (ad.Session.CountChildren).
	CountChildren(ctx context.Context, id guid.GUID, limit uint32) (n uint32, capped bool, err error)
}
