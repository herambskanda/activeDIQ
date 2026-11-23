package read_test

import (
	"context"
	"errors"
	"github.com/skenzeriq/activediq/internal/connector/provider"
	"io"
	"net"
	"strconv"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/read"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/directory/ldapfilter"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

const (
	objGUID = "aaaaaaaa-0000-0000-0000-000000000003"
	parGUID = "aaaaaaaa-0000-0000-0000-000000000002"
	dsaA    = "22222222-2222-2222-2222-222222222222"
	dsaB    = "44444444-4444-4444-4444-444444444444"
)

func g(s string) guid.GUID {
	v, err := guid.Parse(s)
	if err != nil {
		panic(err)
	}
	return v
}

var ident = &connectorv1.DirectoryIdentity{Identity: &connectorv1.DirectoryIdentity_AdForest{AdForest: &connectorv1.AdForestIdentity{
	ForestRootNcGuid: &connectorv1.Guid{Value: []byte("0123456789abcdef")}}}}

type src struct {
	dsa      string
	entry    *ad.Entry
	readErr  error
	classify provider.Verdict
	clsErr   error
	calls    []string
	parErr   error
	parNone  bool   // naming-context head
	dcAfter  string // identity reported from the second BoundDC call on
	boundN   int
}

func (s *src) Identity() *connectorv1.DirectoryIdentity { return ident }
func (s *src) Kind() connectorv1.ProviderKind           { return connectorv1.ProviderKind_PROVIDER_KIND_AD }
func (s *src) Anchors(context.Context, guid.GUID) (provider.Anchors, error) {
	return provider.Anchors{}, nil
}
func (s *src) PropertyGuard(context.Context) (provider.PropertyGuard, error) {
	return provider.GuardOrRefuse(nil), nil
}
func (s *src) BoundDC(context.Context) (*connectorv1.DcIdentity, error) {
	s.boundN++
	d := s.dsa
	if s.boundN > 1 && s.dcAfter != "" {
		d = s.dcAfter
	}
	return &connectorv1.DcIdentity{DsaGuid: provider.GUIDToWire(g(d)), DnsHostname: "dc1"}, nil
}
func (s *src) Read(context.Context, guid.GUID, []string, int) (*ad.Entry, error) {
	s.calls = append(s.calls, "read")
	return s.entry, s.readErr
}
func (s *src) Parent(context.Context, *ad.Entry) (guid.GUID, bool, error) {
	if s.parErr != nil {
		return guid.GUID{}, false, s.parErr
	}
	return g(parGUID), !s.parNone, nil
}
func (s *src) Syntax(n string) (ldapfilter.Syntax, bool) {
	switch n {
	case "member", "distinguishedname":
		return ldapfilter.SynDN, true
	case "useraccountcontrol":
		return ldapfilter.SynInt32, true
	case "accountexpires", "pwdlastset":
		return ldapfilter.SynInt64, true
	case "whencreated":
		return ldapfilter.SynGenTime, true
	}
	return ldapfilter.SynString, true
}
func (s *src) CanonicalAttr(n string) (string, error) {
	// The real built-in schema, so OID spellings are checked against the shipped table.
	a, err := ldapfilter.ParseAttrName(n, ad.DefaultSchema())
	if err != nil {
		if n != "" && (n[0] < '0' || n[0] > '9') { // descr outside the built-in table: pass through
			return n, nil
		}
		return "", err
	}
	return a.String(), nil
}
func (s *src) Classify(context.Context, guid.GUID, []guid.GUID) (provider.Verdict, error) {
	s.calls = append(s.calls, "classify")
	return s.classify, s.clsErr
}

func entry(attrs map[string][][]byte) *ad.Entry {
	attrs["objectGUID"] = [][]byte{g(objGUID).Bytes()}
	return ad.NewEntry("CN=Smith\\, Ann,OU=Ü,DC=lab,DC=test", attrs)
}

func start(t *testing.T, s provider.Provider, opts ...read.Option) connectorv1.ConnectorClient {
	t.Helper()
	h, err := read.New(s, opts...)
	if err != nil {
		t.Fatal(err)
	}
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	read.Register(srv, h)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	cc, err := grpc.NewClient("passthrough:///b", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	return connectorv1.NewConnectorClient(cc)
}

func req(pin string, tier0 bool) *connectorv1.ReadRequest {
	r := &connectorv1.ReadRequest{Connection: &connectorv1.ConnectionRef{ConnectionId: "c1", DirectoryIdentity: ident},
		Guid: provider.GUIDToWire(g(objGUID)), Attributes: []string{"cn"}, IncludeTier0: tier0}
	if pin != "" {
		r.Dc = &connectorv1.DcSelection{PinnedDsaGuid: provider.GUIDToWire(g(pin))}
	}
	return r
}

func collect(t *testing.T, c connectorv1.ConnectorClient, r *connectorv1.ReadRequest) ([]*connectorv1.ReadResponse, error) {
	t.Helper()
	st, err := c.Read(context.Background(), r)
	if err != nil {
		return nil, err
	}
	var out []*connectorv1.ReadResponse
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

func code(err error) connectorv1.ErrorCode {
	var re *client.RemoteError
	if errors.As(client.FromStatus(err), &re) {
		return re.Err.GetCode()
	}
	return connectorv1.ErrorCode_ERROR_CODE_UNSPECIFIED
}

func TestPinnedReadIsServedByThePinnedDCWithVerdict(t *testing.T) {
	s := &src{dsa: dsaA, entry: entry(map[string][][]byte{"cn": {[]byte("Smith, Ann")}}),
		classify: provider.Verdict{Tier0: true, Bases: []provider.Basis{connectorv1.Tier0Basis_TIER0_BASIS_C2_PROTECTED_GROUP_MEMBER, connectorv1.Tier0Basis_TIER0_BASIS_C2_PROTECTED_GROUP_MEMBER}}}
	ms, err := collect(t, start(t, s), req(dsaA, true))
	if err != nil || len(ms) != 2 {
		t.Fatalf("%v %d", err, len(ms))
	}
	h := ms[0].GetHeader()
	if !h.GetTier0().GetTier0() || len(h.GetTier0().GetBasis()) != 1 {
		t.Fatalf("verdict %v", h.GetTier0())
	}
	if !proto3Eq(h.GetObserved().GetDc().GetDsaGuid(), provider.GUIDToWire(g(dsaA))) {
		t.Fatal("observation does not name the pinned DC")
	}
	if string(h.GetEntry().GetParentGuid().GetValue()) != string(provider.GUIDToWire(g(parGUID)).GetValue()) {
		t.Fatal("parent")
	}
	if ms[1].GetCompleted() == nil {
		t.Fatal("no completed")
	}
}

func proto3Eq(a, b *connectorv1.Guid) bool { return string(a.GetValue()) == string(b.GetValue()) }

func TestPinToAnotherDCFailsBeforeAnyRead(t *testing.T) {
	s := &src{dsa: dsaA, entry: entry(map[string][][]byte{"cn": {[]byte("x")}})}
	_, err := collect(t, start(t, s), req(dsaB, true))
	if code(err) != connectorv1.ErrorCode_ERROR_CODE_UNREACHABLE_DC || len(s.calls) != 0 {
		t.Fatalf("code %v calls %v err %v", code(err), s.calls, err)
	}
}

func TestDCChangingDuringTheReadFails(t *testing.T) {
	s := &src{dsa: dsaA, dcAfter: dsaB, entry: entry(map[string][][]byte{"cn": {[]byte("x")}})}
	ms, err := collect(t, start(t, s), req("", true))
	if code(err) != connectorv1.ErrorCode_ERROR_CODE_UNREACHABLE_DC || len(ms) != 0 {
		t.Fatalf("code %v msgs %d", code(err), len(ms))
	}
}

func TestVerdictFailureIsAnErrorNeverFalse(t *testing.T) {
	s := &src{dsa: dsaA, entry: entry(map[string][][]byte{"cn": {[]byte("x")}}), clsErr: errors.New("ldap down")}
	ms, err := collect(t, start(t, s), req(dsaA, true))
	if err == nil || len(ms) != 0 {
		t.Fatalf("err %v msgs %d", err, len(ms))
	}
	if st, _ := status.FromError(err); st.Message() != "tier0 classification failed" {
		t.Fatalf("message %q", st.Message())
	}
}

func TestNoVerdictUnlessAsked(t *testing.T) {
	s := &src{dsa: dsaA, entry: entry(map[string][][]byte{"cn": {[]byte("x")}})}
	ms, err := collect(t, start(t, s), req(dsaA, false))
	if err != nil || ms[0].GetHeader().GetTier0() != nil {
		t.Fatalf("%v %v", err, ms)
	}
	for _, c := range s.calls {
		if c == "classify" {
			t.Fatal("classified without being asked")
		}
	}
}

func TestObjectNotFound(t *testing.T) {
	s := &src{dsa: dsaA, readErr: errors.New("x")}
	s.readErr = notFound()
	_, err := collect(t, start(t, s), req(dsaA, true))
	if code(err) != connectorv1.ErrorCode_ERROR_CODE_OBJECT_NOT_FOUND {
		t.Fatalf("code %v", code(err))
	}
}

func TestRequestShapeIsRefused(t *testing.T) {
	s := &src{dsa: dsaA, entry: entry(map[string][][]byte{"cn": {[]byte("x")}})}
	c := start(t, s)
	bad := map[string]func(*connectorv1.ReadRequest){
		"no connection": func(r *connectorv1.ReadRequest) { r.Connection = nil },
		"no guid":       func(r *connectorv1.ReadRequest) { r.Guid = nil },
		"no attributes": func(r *connectorv1.ReadRequest) { r.Attributes = nil },
		"short pin": func(r *connectorv1.ReadRequest) {
			r.Dc = &connectorv1.DcSelection{PinnedDsaGuid: &connectorv1.Guid{Value: []byte{1}}}
		},
	}
	for n, f := range bad {
		r := req(dsaA, false)
		f(r)
		if _, err := collect(t, c, r); code(err) != connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT {
			t.Errorf("%s: %v", n, err)
		}
	}
	r := req(dsaA, false)
	r.Connection.DirectoryIdentity = &connectorv1.DirectoryIdentity{Identity: &connectorv1.DirectoryIdentity_EntraTenantId{EntraTenantId: "t"}}
	if _, err := collect(t, c, r); code(err) != connectorv1.ErrorCode_ERROR_CODE_DIRECTORY_IDENTITY_MISMATCH {
		t.Errorf("identity: %v", err)
	}
	if len(s.calls) != 0 {
		t.Fatal("directory reached for a refused request")
	}
}

func TestTypedValuesAndRangedChunks(t *testing.T) {
	members := make([][]byte, 3200)
	for i := range members {
		members[i] = []byte("CN=u" + strconv.Itoa(i) + ",DC=lab,DC=test")
	}
	s := &src{dsa: dsaA, entry: entry(map[string][][]byte{
		"member": members, "userAccountControl": {[]byte("-2147483648")},
		"accountExpires": {[]byte("9223372036854775807")}, "pwdLastSet": {[]byte("0")},
		"whenCreated": {[]byte("20240102030405.0Z")}, "cn": {[]byte("Smith, Ann")},
	})}
	r := req("", false)
	r.Attributes = []string{"member", "userAccountControl", "accountExpires", "pwdLastSet", "whenCreated", "cn"}
	ms, err := collect(t, start(t, s), r)
	if err != nil {
		t.Fatal(err)
	}
	attrs := map[string]*connectorv1.Attribute{}
	for _, a := range ms[0].GetHeader().GetEntry().GetAttributes() {
		attrs[a.Name] = a
	}
	if m := attrs["member"]; m.Complete || len(m.Values) != 1500 || m.Range.GetEnd() != 1499 {
		t.Fatalf("member header range %+v", m.GetRange())
	}
	if attrs["useraccountcontrol"].Values[0].GetInt32Value() != -2147483648 {
		t.Fatal("uac sign")
	}
	if attrs["accountexpires"].Values[0].GetTime().GetSentinel() != connectorv1.TimeSentinel_TIME_SENTINEL_MAX ||
		attrs["pwdlastset"].Values[0].GetTime().GetSentinel() != connectorv1.TimeSentinel_TIME_SENTINEL_ZERO {
		t.Fatal("time sentinels")
	}
	if attrs["whencreated"].Values[0].GetTime().GetAt().AsTime().Year() != 2024 {
		t.Fatal("generalized time")
	}
	var chunks, total int
	var last *connectorv1.ValueChunk
	for _, m := range ms[1 : len(ms)-1] {
		c := m.GetChunk()
		if c == nil || (last != nil && c.Range.Start != last.Range.End+1) {
			t.Fatalf("chunk order %v", m)
		}
		chunks++
		total += len(c.Values)
		last = c
	}
	if chunks != 2 || total != 1700 || !last.Range.Terminal || ms[len(ms)-1].GetCompleted() == nil {
		t.Fatalf("chunks %d total %d", chunks, total)
	}
}

func TestUnreadableParentFailsTheRead(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		want connectorv1.ErrorCode
	}{
		"no rights": {ad.NewError(ad.CodeInsufficientRights), connectorv1.ErrorCode_ERROR_CODE_INSUFFICIENT_RIGHTS},
		"not found": {ad.NewError(ad.CodeObjectNotFound), connectorv1.ErrorCode_ERROR_CODE_PROVIDER_FAILURE},
		"undecoded": {errors.New("parent GUID does not decode"), connectorv1.ErrorCode_ERROR_CODE_PROVIDER_FAILURE},
	} {
		s := &src{dsa: dsaA, entry: entry(map[string][][]byte{"cn": {[]byte("x")}}), parErr: tc.err}
		ms, err := collect(t, start(t, s), req(dsaA, false))
		if code(err) != tc.want || len(ms) != 0 {
			t.Fatalf("%s: code %v msgs %d err %v", name, code(err), len(ms), err)
		}
	}
}

func TestNamingContextHeadHasNoParent(t *testing.T) {
	s := &src{dsa: dsaA, parNone: true, entry: entry(map[string][][]byte{"cn": {[]byte("x")}})}
	ms, err := collect(t, start(t, s), req(dsaA, false))
	if err != nil || ms[0].GetHeader().GetEntry().GetParentGuid() != nil {
		t.Fatalf("err %v", err)
	}
}

func TestInstanceTypeIsAskedForButNotReturnedUnlessRequested(t *testing.T) {
	s := &src{dsa: dsaA, entry: entry(map[string][][]byte{"cn": {[]byte("x")}, "instanceType": {[]byte("4")}})}
	ms, err := collect(t, start(t, s), req(dsaA, false))
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range ms[0].GetHeader().GetEntry().GetAttributes() {
		if a.GetName() == "instancetype" {
			t.Fatal("instanceType leaked into the entry")
		}
	}
}

func TestSecurityDescriptorIsRefusedUntilItsTicket(t *testing.T) {
	s := &src{dsa: dsaA, entry: entry(map[string][][]byte{"cn": {[]byte("x")}})}
	r := req(dsaA, false)
	r.Attributes = []string{"cn", "nTSecurityDescriptor"}
	if _, err := collect(t, start(t, s), r); code(err) != connectorv1.ErrorCode_ERROR_CODE_ATTRIBUTE_NOT_ALLOWED || len(s.calls) != 0 {
		t.Fatalf("code %v", code(err))
	}
}

func TestSecurityDescriptorByOIDIsRefused(t *testing.T) {
	s := &src{dsa: dsaA, entry: entry(map[string][][]byte{"cn": {[]byte("x")}})}
	r := req(dsaA, false)
	r.Attributes = []string{"cn", "1.2.840.113556.1.2.281"}
	if _, err := collect(t, start(t, s), r); code(err) != connectorv1.ErrorCode_ERROR_CODE_ATTRIBUTE_NOT_ALLOWED || len(s.calls) != 0 {
		t.Fatalf("code %v", code(err))
	}
}

// 1.2.840.113556.1.4.151 is oEMInformation, not the SD: it must not trip the SD hold.
func TestOEMInformationOIDIsNotTheSecurityDescriptor(t *testing.T) {
	s := &src{dsa: dsaA, entry: entry(map[string][][]byte{"cn": {[]byte("x")}})}
	r := req(dsaA, false)
	r.Attributes = []string{"1.2.840.113556.1.4.151"}
	if _, err := collect(t, start(t, s), r); code(err) == connectorv1.ErrorCode_ERROR_CODE_ATTRIBUTE_NOT_ALLOWED {
		t.Fatalf("oEMInformation OID wrongly refused as the SD")
	}
}

func TestAttributeRequestedByOIDIsReturned(t *testing.T) {
	s := &src{dsa: dsaA, entry: entry(map[string][][]byte{"cn": {[]byte("x")}})}
	r := req(dsaA, false)
	r.Attributes = []string{"2.5.4.3"}
	ms, err := collect(t, start(t, s), r)
	if err != nil {
		t.Fatal(err)
	}
	as := ms[0].GetHeader().GetEntry().GetAttributes()
	if len(as) != 1 || as[0].GetName() != "cn" {
		t.Fatalf("attributes %v", as)
	}
}

// A provider without the facets Read needs builds a handler whose groups answer
// CAPABILITY_UNSUPPORTED: never a nil dereference, never a stream.
func TestHandlerWithoutFacetsIsUnsupported(t *testing.T) {
	for name, p := range map[string]provider.Provider{
		"core only":    coreOnly{},
		"reader no DC": noDC{&src{dsa: dsaA}},
	} {
		h, err := read.New(p)
		if err != nil {
			t.Fatal(err)
		}
		err = h.Read(context.Background(), req(dsaA, true), nopSender{})
		if code(err) != connectorv1.ErrorCode_ERROR_CODE_CAPABILITY_UNSUPPORTED {
			t.Errorf("%s read: code=%v", name, code(err))
		}
		err = h.ScopedSearch(context.Background(), sreq(), nopSearchSender{})
		if code(err) != connectorv1.ErrorCode_ERROR_CODE_CAPABILITY_UNSUPPORTED {
			t.Errorf("%s search: code=%v", name, code(err))
		}
	}
	if _, err := read.New(nil); err == nil {
		t.Error("nil provider accepted")
	}
}

// coreOnly is a provider with the core and no facet.
type coreOnly struct{}

func (coreOnly) Kind() connectorv1.ProviderKind           { return connectorv1.ProviderKind_PROVIDER_KIND_AD }
func (coreOnly) Identity() *connectorv1.DirectoryIdentity { return ident }
func (coreOnly) Classify(context.Context, guid.GUID, []guid.GUID) (provider.Verdict, error) {
	return provider.Verdict{}, nil
}
func (coreOnly) Anchors(context.Context, guid.GUID) (provider.Anchors, error) {
	return provider.Anchors{}, nil
}
func (coreOnly) PropertyGuard(context.Context) (provider.PropertyGuard, error) {
	return provider.GuardOrRefuse(nil), nil
}

// noDC hides the DCBound facet of a source.
type noDC struct{ s *src }

func (n noDC) Kind() connectorv1.ProviderKind           { return n.s.Kind() }
func (n noDC) Identity() *connectorv1.DirectoryIdentity { return n.s.Identity() }
func (n noDC) Classify(c context.Context, g guid.GUID, d []guid.GUID) (provider.Verdict, error) {
	return n.s.Classify(c, g, d)
}
func (n noDC) Anchors(c context.Context, g guid.GUID) (provider.Anchors, error) {
	return n.s.Anchors(c, g)
}
func (n noDC) PropertyGuard(c context.Context) (provider.PropertyGuard, error) {
	return n.s.PropertyGuard(c)
}
func (n noDC) Read(c context.Context, g guid.GUID, a []string, m int) (*ad.Entry, error) {
	return n.s.Read(c, g, a, m)
}
func (n noDC) Parent(c context.Context, e *ad.Entry) (guid.GUID, bool, error) {
	return n.s.Parent(c, e)
}
func (n noDC) Syntax(a string) (ldapfilter.Syntax, bool) { return n.s.Syntax(a) }
func (n noDC) CanonicalAttr(a string) (string, error)    { return n.s.CanonicalAttr(a) }

type nopSearchSender struct{}

func (nopSearchSender) Send(*connectorv1.ScopedSearchResponse) error { return errors.New("streamed") }

type nopSender struct{}

func (nopSender) Send(*connectorv1.ReadResponse) error { return errors.New("streamed") }
