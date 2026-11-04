package ad

import (
	"context"

	adconn "github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/provider"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/ldapfilter"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

var (
	_ provider.DCBound      = (*ADProvider)(nil)
	_ provider.ObjectReader = (*ADProvider)(nil)
	_ provider.Searcher     = (*ADProvider)(nil)
	_ provider.RightsSource = (*ADProvider)(nil)
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
	return p.sess.Read(ctx, dn.GUIDRef(id), attrs, adconn.ReadOptions{MaxValues: maxValues})
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
	return p.sess.ScopedSearch(ctx, req, fn)
}
