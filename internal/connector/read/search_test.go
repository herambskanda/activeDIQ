package read_test

import (
	"context"
	"errors"
	"io"
	"strconv"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/read"
	"github.com/skenzeriq/activediq/internal/connector/write"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/ldapfilter"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// ssrc adds the search half to the Read fake.
type ssrc struct {
	*src
	entries []*ad.Entry
	err     error
	got     ad.ScopedRequest
	filtErr error
}

func (s *ssrc) ParseFilter(f *connectorv1.Filter) (ldapfilter.Filter, error) {
	if s.filtErr != nil {
		return nil, s.filtErr
	}
	return ldapfilter.ParseFilterAST(f, ldapfilter.NewSchema(ldapfilter.AttrInfo{Name: "cn", Syntax: ldapfilter.SynString}), nil, ldapfilter.Limits{})
}

func (s *ssrc) ScopedSearch(_ context.Context, r ad.ScopedRequest, fn func(*ad.Entry) error) (ad.ScopedResult, error) {
	s.got = r
	for _, e := range s.entries {
		if err := fn(e); err != nil {
			return ad.ScopedResult{}, err
		}
	}
	return ad.ScopedResult{Returned: len(s.entries)}, s.err
}

func sreq() *connectorv1.ScopedSearchRequest {
	return &connectorv1.ScopedSearchRequest{
		Connection: &connectorv1.ConnectionRef{ConnectionId: "c1", DirectoryIdentity: ident},
		Roots:      []*connectorv1.SearchRoot{{Guid: write.GUIDToWire(g(parGUID))}},
		Depth:      connectorv1.SearchDepth_SEARCH_DEPTH_SUBTREE,
		Filter: &connectorv1.Filter{Node: &connectorv1.Filter_Equal{Equal: &connectorv1.Comparison{Attribute: "cn",
			Value: &connectorv1.FilterValue{Value: &connectorv1.FilterValue_Text{Text: "a*)(b"}}}}},
		Attributes: []string{"cn"},
	}
}

func searchAll(c connectorv1.ConnectorClient, r *connectorv1.ScopedSearchRequest) ([]*connectorv1.ScopedSearchResponse, error) {
	st, err := c.ScopedSearch(context.Background(), r)
	if err != nil {
		return nil, err
	}
	var out []*connectorv1.ScopedSearchResponse
	for {
		m, err := st.Recv()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		out = append(out, m)
	}
}

func mk(i int) *ad.Entry {
	id := g(objGUID)
	id[15] = byte(i)
	return ad.NewEntry("CN=u"+strconv.Itoa(i)+",DC=lab", map[string][][]byte{"objectGUID": {id[:]}, "cn": {[]byte("u" + strconv.Itoa(i))}})
}

func TestScopedSearchStreamsBatchesThenCompleted(t *testing.T) {
	s := &ssrc{src: &src{dsa: dsaA}}
	for i := 0; i < 450; i++ {
		s.entries = append(s.entries, mk(i%250))
	}
	ms, err := searchAll(start(t, s), sreq())
	if err != nil {
		t.Fatal(err)
	}
	n, batches := 0, 0
	for _, m := range ms[:len(ms)-1] {
		b := m.GetBatch()
		if b == nil {
			t.Fatalf("event before completion is not a batch: %v", m)
		}
		batches++
		n += len(b.GetEntries())
		if b.GetObserved().GetDc() == nil {
			t.Fatal("batch has no observation")
		}
	}
	if n != 450 || batches != 3 || ms[len(ms)-1].GetCompleted() == nil {
		t.Fatalf("entries=%d batches=%d last=%v", n, batches, ms[len(ms)-1])
	}
	if s.got.Depth != ad.ScopeSubtree || len(s.got.Roots) != 1 || s.got.Attributes[0] != "cn" {
		t.Fatalf("request not carried: %+v", s.got)
	}
}

func TestScopedSearchLongAttributeIsFirstRangeIncomplete(t *testing.T) {
	var vals [][]byte
	for i := 0; i < 1600; i++ {
		vals = append(vals, []byte("CN=m"+strconv.Itoa(i)+",DC=lab"))
	}
	id := g(objGUID)
	e := ad.NewEntry("CN=grp,DC=lab", map[string][][]byte{"objectGUID": {id[:]}, "member": vals})
	r := sreq()
	r.Attributes = []string{"member"}
	ms, err := searchAll(start(t, &ssrc{src: &src{dsa: dsaA}, entries: []*ad.Entry{e}}), r)
	if err != nil {
		t.Fatal(err)
	}
	a := ms[0].GetBatch().GetEntries()[0].GetAttributes()[0]
	if a.GetComplete() || len(a.GetValues()) != 1500 || a.GetRange().GetEnd() != 1499 {
		t.Fatalf("attr %v complete=%v n=%d", a.GetName(), a.GetComplete(), len(a.GetValues()))
	}
}

func TestScopedSearchRefusals(t *testing.T) {
	bad := func(f func(*connectorv1.ScopedSearchRequest)) *connectorv1.ScopedSearchRequest {
		r := sreq()
		f(r)
		return r
	}
	other := &connectorv1.DirectoryIdentity{Identity: &connectorv1.DirectoryIdentity_AdForest{AdForest: &connectorv1.AdForestIdentity{
		ForestRootNcGuid: &connectorv1.Guid{Value: []byte("fedcba9876543210")}}}}
	for name, c := range map[string]struct {
		r    *connectorv1.ScopedSearchRequest
		want connectorv1.ErrorCode
	}{
		"no connection":   {bad(func(r *connectorv1.ScopedSearchRequest) { r.Connection = nil }), connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT},
		"wrong directory": {bad(func(r *connectorv1.ScopedSearchRequest) { r.Connection.DirectoryIdentity = other }), connectorv1.ErrorCode_ERROR_CODE_DIRECTORY_IDENTITY_MISMATCH},
		"no roots":        {bad(func(r *connectorv1.ScopedSearchRequest) { r.Roots = nil }), connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT},
		"65 roots": {bad(func(r *connectorv1.ScopedSearchRequest) {
			for len(r.Roots) < 65 {
				r.Roots = append(r.Roots, r.Roots[0])
			}
		}), connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT},
		"bad root guid": {bad(func(r *connectorv1.ScopedSearchRequest) { r.Roots[0].Guid = &connectorv1.Guid{Value: []byte{1}} }), connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT},
		"no depth":      {bad(func(r *connectorv1.ScopedSearchRequest) { r.Depth = 0 }), connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT},
		"no filter":     {bad(func(r *connectorv1.ScopedSearchRequest) { r.Filter = nil }), connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT},
		"no attributes": {bad(func(r *connectorv1.ScopedSearchRequest) { r.Attributes = nil }), connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT},
		"sd attribute":  {bad(func(r *connectorv1.ScopedSearchRequest) { r.Attributes = []string{"nTSecurityDescriptor"} }), connectorv1.ErrorCode_ERROR_CODE_ATTRIBUTE_NOT_ALLOWED},
		"pinned elsewhere": {bad(func(r *connectorv1.ScopedSearchRequest) {
			r.Dc = &connectorv1.DcSelection{PinnedDsaGuid: write.GUIDToWire(g(dsaB))}
		}), connectorv1.ErrorCode_ERROR_CODE_UNREACHABLE_DC},
	} {
		s := &ssrc{src: &src{dsa: dsaA}, entries: []*ad.Entry{mk(1)}}
		ms, err := searchAll(start(t, s), c.r)
		if code(err) != c.want || len(ms) != 0 || s.got.Filter != nil {
			t.Errorf("%s: code=%v (%v) msgs=%d searched=%v", name, code(err), err, len(ms), s.got.Filter != nil)
		}
	}
}

func TestScopedSearchFilterRejectedCarriesRuleNotValue(t *testing.T) {
	r := sreq()
	r.Filter.GetEqual().Attribute = "notInSchema"
	_, err := searchAll(start(t, &ssrc{src: &src{dsa: dsaA}}), r)
	if code(err) != connectorv1.ErrorCode_ERROR_CODE_FILTER_REJECTED {
		t.Fatalf("code=%v err=%v", code(err), err)
	}
	if got := err.Error(); len(got) > 0 && (contains(got, "a*)(b") || contains(got, "notInSchema")) {
		t.Fatalf("rejection echoes input: %q", got)
	}
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }

func TestScopedSearchRootGoneAndMidStreamFailureAreErrorsNotCompletion(t *testing.T) {
	for name, c := range map[string]struct {
		err  error
		want connectorv1.ErrorCode
	}{
		"root gone": {ad.NewError(ad.CodeDelegationRootGone), connectorv1.ErrorCode_ERROR_CODE_DELEGATION_ROOT_GONE},
		"referral":  {ad.NewError(ad.CodeUnexpectedReferral), connectorv1.ErrorCode_ERROR_CODE_UNEXPECTED_REFERRAL},
		"dc down":   {ad.NewError(ad.CodeUnreachable), connectorv1.ErrorCode_ERROR_CODE_UNREACHABLE_DC},
	} {
		ms, err := searchAll(start(t, &ssrc{src: &src{dsa: dsaA}, entries: []*ad.Entry{mk(1)}, err: c.err}), sreq())
		if code(err) != c.want {
			t.Errorf("%s: code=%v", name, code(err))
		}
		for _, m := range ms {
			if m.GetCompleted() != nil {
				t.Errorf("%s: failed search ended with SearchCompleted", name)
			}
		}
	}
}

func TestScopedSearchDCSwitchDuringSearchIsRefused(t *testing.T) {
	s := &ssrc{src: &src{dsa: dsaA, dcAfter: dsaB}, entries: []*ad.Entry{mk(1)}}
	ms, err := searchAll(start(t, s), sreq())
	if code(err) != connectorv1.ErrorCode_ERROR_CODE_UNREACHABLE_DC {
		t.Fatalf("code=%v", code(err))
	}
	for _, m := range ms {
		if m.GetCompleted() != nil {
			t.Fatal("completed on another DC")
		}
	}
}

func TestScopedSearchWithoutSearcherIsUnsupported(t *testing.T) {
	_, err := searchAll(start(t, &src{dsa: dsaA}), sreq())
	if code(err) != connectorv1.ErrorCode_ERROR_CODE_CAPABILITY_UNSUPPORTED {
		t.Fatalf("code=%v", code(err))
	}
}

var _ = guid.GUID{}
var _ read.Searcher = (*ssrc)(nil)
