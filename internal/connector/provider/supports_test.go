package provider_test

import (
	"context"
	"testing"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/provider"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/ldapfilter"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

type core struct{}

func (core) Kind() connectorv1.ProviderKind           { return connectorv1.ProviderKind_PROVIDER_KIND_AD }
func (core) Identity() *connectorv1.DirectoryIdentity { return nil }
func (core) Classify(context.Context, guid.GUID, []guid.GUID) (provider.Verdict, error) {
	return provider.Verdict{}, nil
}
func (core) Anchors(context.Context, guid.GUID) (provider.Anchors, error) {
	return provider.Anchors{}, nil
}
func (core) PropertyGuard(context.Context) (provider.PropertyGuard, error) {
	return provider.GuardOrRefuse(nil), nil
}

type withDC struct{ core }

func (withDC) BoundDC(context.Context) (*connectorv1.DcIdentity, error) { return nil, nil }

type reader struct{ core }

func (reader) Read(context.Context, guid.GUID, []string, int) (*ad.Entry, error) { return nil, nil }
func (reader) Parent(context.Context, *ad.Entry) (guid.GUID, bool, error) {
	return guid.GUID{}, false, nil
}
func (reader) Syntax(string) (ldapfilter.Syntax, bool) { return 0, false }
func (reader) CanonicalAttr(s string) (string, error)  { return s, nil }

type readerDC struct {
	reader
	withDC
}

func (readerDC) Kind() connectorv1.ProviderKind           { return connectorv1.ProviderKind_PROVIDER_KIND_AD }
func (readerDC) Identity() *connectorv1.DirectoryIdentity { return nil }
func (readerDC) Classify(context.Context, guid.GUID, []guid.GUID) (provider.Verdict, error) {
	return provider.Verdict{}, nil
}
func (readerDC) Anchors(context.Context, guid.GUID) (provider.Anchors, error) {
	return provider.Anchors{}, nil
}
func (readerDC) PropertyGuard(context.Context) (provider.PropertyGuard, error) { return nil, nil }

type searcher struct{ readerDC }

func (searcher) ParseFilter(*connectorv1.Filter) (ldapfilter.Filter, error) { return nil, nil }
func (searcher) ScopedSearch(context.Context, ad.ScopedRequest, func(*ad.Entry) error) (ad.ScopedResult, error) {
	return ad.ScopedResult{}, nil
}

func states(p provider.Provider) map[connectorv1.Operation]bool {
	out := map[connectorv1.Operation]bool{}
	for _, r := range provider.Supports(p) {
		out[r.GetOperation()] = r.GetState() == connectorv1.SupportState_SUPPORT_STATE_SUPPORTED
	}
	return out
}

// Supports derives each row from the facets and nothing else: Read needs the reader and the DC
// binding together; ScopedSearch also needs the searcher.
func TestSupportsDerivedFromFacets(t *testing.T) {
	const (
		verify = connectorv1.Operation_OPERATION_VERIFY_CONNECTION
		read   = connectorv1.Operation_OPERATION_READ
		search = connectorv1.Operation_OPERATION_SCOPED_SEARCH
	)
	for name, tc := range map[string]struct {
		p                  provider.Provider
		verify, read, srch bool
	}{
		"core only":   {core{}, false, false, false},
		"dc only":     {withDC{}, false, false, false},
		"reader only": {reader{}, false, false, false},
		"reader + dc": {readerDC{}, false, true, false},
		"searcher":    {searcher{}, false, true, true},
	} {
		got := states(tc.p)
		if got[verify] != tc.verify || got[read] != tc.read || got[search] != tc.srch {
			t.Errorf("%s: %v", name, got)
		}
	}
}
