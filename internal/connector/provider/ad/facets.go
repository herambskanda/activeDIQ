package ad

import (
	"context"
	"time"

	adconn "github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/provider"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/ldapfilter"
	"github.com/skenzeriq/activediq/internal/directory/sd"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

var (
	_ provider.DCBound         = (*ADProvider)(nil)
	_ provider.ObjectReader    = (*ADProvider)(nil)
	_ provider.Searcher        = (*ADProvider)(nil)
	_ provider.RightsSource    = (*ADProvider)(nil)
	_ provider.Describer       = (*ADProvider)(nil)
	_ provider.PasswordChanger = (*ADProvider)(nil)
	_ provider.Feeder          = (*ADProvider)(nil)
	_ provider.ChangeTimer     = (*ADProvider)(nil)
	_ provider.SignInResolver  = (*ADProvider)(nil)
	_ provider.PerDCReader     = (*ADProvider)(nil)
)

// sessionOK is true only when the provider's directory and bound-DC binder are still both over the
// session the facets read on. The reads, the classification and the DC identity must all come from
// one DC, or a pinned Read could be answered by one DC while the pin and the verdict name another;
// a provider that fails it (a zero value, a replaced Dir or Bound) fails every facet closed.
func (p *ADProvider) sessionOK() bool { return p != nil && p.sess != nil && p.OverSession(p.sess) }

// Read implements provider.ObjectReader.
func (p *ADProvider) Read(ctx context.Context, id guid.GUID, attrs []string, maxValues int) (*adconn.Entry, error) {
	if !p.sessionOK() {
		return nil, provider.ErrNoBoundDC
	}
	return p.sess.Read(ctx, dn.GUIDRef(id), attrs, adconn.ReadOptions{MaxValues: maxValues, ExtendedDN: true})
}

// Parent returns the parent's objectGUID. ok is false only for a naming-context head, which the
// directory says about itself (instanceType, requested with the entry); an unreadable or
// undecodable parent is an error, never "no parent", because the ancestry feeds authorisation.
func (p *ADProvider) Parent(ctx context.Context, e *adconn.Entry) (guid.GUID, bool, error) {
	if !p.sessionOK() {
		return guid.GUID{}, false, provider.ErrNoBoundDC
	}
	return p.sess.Parent(ctx, e)
}

// Syntax implements provider.ObjectReader.
func (p *ADProvider) Syntax(name string) (ldapfilter.Syntax, bool) {
	if !p.sessionOK() {
		return 0, false
	}
	return p.sess.AttrSyntax(name)
}

// CanonicalAttr implements provider.ObjectReader.
func (p *ADProvider) CanonicalAttr(name string) (string, error) {
	if !p.sessionOK() {
		return "", provider.ErrNoBoundDC
	}
	return p.sess.CanonicalAttr(name)
}

// ParseFilter implements provider.Searcher.
func (p *ADProvider) ParseFilter(f *connectorv1.Filter) (ldapfilter.Filter, error) {
	if !p.sessionOK() {
		return nil, provider.ErrNoBoundDC
	}
	return ldapfilter.ParseFilterAST(f, p.sess.FilterSchema(), nil, ldapfilter.Limits{})
}

// ScopedSearch implements provider.Searcher.
func (p *ADProvider) ScopedSearch(ctx context.Context, req adconn.ScopedRequest, fn func(*adconn.Entry) error) (adconn.ScopedResult, error) {
	if !p.sessionOK() {
		return adconn.ScopedResult{}, provider.ErrNoBoundDC
	}
	req.ExtendedDN = true // DN-valued attributes carry the target's GUID and SID (T-1202)
	return p.sess.ScopedSearch(ctx, req, fn)
}

// Topology implements provider.Describer: the forest's naming contexts and the bound DC's paging
// limits, read on the one session.
func (p *ADProvider) Topology(ctx context.Context) (*adconn.Topology, error) {
	if !p.sessionOK() {
		return nil, provider.ErrNoBoundDC
	}
	return p.sess.Topology(ctx)
}

// IsSamba reports whether the bound DC's rootDSE names Samba as its vendor; it labels the
// ReadReplicationStatus capability and gates nothing.
func (p *ADProvider) IsSamba(ctx context.Context) (bool, error) {
	if !p.sessionOK() {
		return false, provider.ErrNoBoundDC
	}
	rd, err := p.sess.RootDSE(ctx)
	if err != nil {
		return false, err
	}
	return rd.IsSamba(), nil
}

// ReadPasswordChange implements provider.PasswordChanger.
func (p *ADProvider) ReadPasswordChange(ctx context.Context, id guid.GUID) (guid.GUID, sd.PasswordChange, error) {
	if !p.sessionOK() {
		return guid.GUID{}, sd.PasswordChangeNotConfirmed, provider.ErrNoBoundDC
	}
	return p.sess.ReadPasswordChange(ctx, dn.GUIDRef(id))
}

// AttrChangeTimes implements provider.ChangeTimer.
func (p *ADProvider) AttrChangeTimes(ctx context.Context, id guid.GUID, attrs []string) (map[string]adconn.AttrChange, error) {
	if !p.sessionOK() {
		return nil, provider.ErrNoBoundDC
	}
	return p.sess.AttrChangeTimes(ctx, id, attrs)
}

// ResolveSignInName implements provider.SignInResolver.
func (p *ADProvider) ResolveSignInName(ctx context.Context, name string) (adconn.SignInUser, error) {
	if !p.sessionOK() {
		return adconn.SignInUser{}, provider.ErrNoBoundDC
	}
	return p.sess.ResolveSignInName(ctx, name)
}

// DomainDCs implements provider.PerDCReader: the DCs of the domain from the configuration NC,
// listed through the reading session.
func (p *ADProvider) DomainDCs(ctx context.Context, nc guid.GUID) ([]provider.DC, error) {
	if p == nil || p.OpenDC == nil {
		return nil, provider.ErrPerDCUnavailable
	}
	if !p.sessionOK() {
		return nil, provider.ErrNoBoundDC
	}
	head, err := p.sess.Read(ctx, dn.GUIDRef(nc), []string{"distinguishedName", "instanceType"}, adconn.ReadOptions{})
	if err != nil {
		return nil, err
	}
	d, err := dn.Parse(head.DN, dn.Strict)
	if err != nil {
		return nil, err
	}
	// Only a domain naming-context head names a domain: instanceType has the head bit (IT_NC_HEAD, 0x1).
	if it, ok, err := head.Int32("instanceType"); err != nil || !ok || it&1 == 0 {
		return nil, &adconn.Error{Code: adconn.CodeObjectNotFound}
	}
	list, err := p.sess.DomainControllers(ctx, d)
	if err != nil {
		return nil, err
	}
	out := make([]provider.DC, len(list))
	for i, c := range list {
		out[i] = provider.DC{Host: c.Host, Site: c.Site, DSAGUID: c.DSAGUID, RODC: c.RODC, RODCKnown: c.RODCKnown}
	}
	return out, nil
}

// ReadOnDC implements provider.PerDCReader: one short-lived session per read, on that host only.
func (p *ADProvider) ReadOnDC(ctx context.Context, dc provider.DC, id guid.GUID, attrs []string) (*adconn.Entry, *connectorv1.DcIdentity, error) {
	if p == nil || p.OpenDC == nil {
		return nil, nil, provider.ErrPerDCUnavailable
	}
	s, err := p.OpenDC(ctx, dc.Host)
	if err != nil {
		return nil, nil, err
	}
	defer s.Close()
	ident, err := s.DCIdentity(ctx)
	if err != nil {
		return nil, nil, err
	}
	who := &connectorv1.DcIdentity{DsaGuid: provider.GUIDToWire(ident.DSAGUID), InvocationId: provider.GUIDToWire(ident.InvocationID),
		DnsHostname: ident.DNSHostName, Site: ident.Site}
	if ident.DSAGUID != dc.DSAGUID {
		return nil, who, &adconn.Error{Code: adconn.CodeUnreachable} // another DC answered at this host
	}
	e, err := s.Read(ctx, dn.GUIDRef(id), attrs, adconn.ReadOptions{})
	return e, who, err
}

// ManagesNC implements provider.Feeder.
func (p *ADProvider) ManagesNC(ctx context.Context, nc guid.GUID) (bool, error) {
	if !p.sessionOK() {
		return false, provider.ErrNoBoundDC
	}
	dom, err := p.sess.DomainNCGUID(ctx)
	if err != nil {
		return false, err
	}
	return dom == nc, nil
}

// CheckFeedAttributes implements provider.Feeder.
func (p *ADProvider) CheckFeedAttributes(names []string) error {
	if !p.sessionOK() {
		return provider.ErrNoBoundDC
	}
	return p.sess.CheckDirSyncAttributes(names)
}

// HighestCommittedUSN implements provider.Feeder.
func (p *ADProvider) HighestCommittedUSN(ctx context.Context) (int64, error) {
	if !p.sessionOK() {
		return 0, provider.ErrNoBoundDC
	}
	return p.sess.HighestCommittedUSN(ctx)
}

// DeletionLifetime implements provider.Feeder.
func (p *ADProvider) DeletionLifetime(ctx context.Context) (time.Duration, error) {
	if !p.sessionOK() {
		return 0, provider.ErrNoBoundDC
	}
	return p.sess.DeletionLifetime(ctx)
}

// DirSyncCycle implements provider.Feeder.
func (p *ADProvider) DirSyncCycle(ctx context.Context, req adconn.DirSyncRequest, fn func(adconn.DirSyncPage) error) (adconn.DirSyncPage, error) {
	if !p.sessionOK() {
		return adconn.DirSyncPage{}, provider.ErrNoBoundDC
	}
	return p.sess.DirSyncCycle(ctx, req, fn)
}
