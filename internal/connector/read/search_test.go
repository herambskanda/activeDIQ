package read_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/write"
	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/directory/ldapfilter"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// ssrc is a SearchSource whose ScopedSearch records what the handler would send to the DC (the
// rendered filter, the attributes, the roots) and answers canned entries.
type ssrc struct {
	*src
	entries []*ad.Entry
	err     error
	got     ad.ScopedRequest
	text    string
	calls   int
}

func (s *ssrc) FilterSchema() *ldapfilter.Schema { return ad.DefaultSchema() }
func (s *ssrc) ScopedSearch(_ context.Context, r ad.ScopedRequest, fn func(*ad.Entry) error) (ad.ScopedResult, error) {
	s.calls++
	s.got = r
	t, err := ldapfilter.Render(r.Filter, ad.DefaultSchema())
	if err != nil {
		return ad.ScopedResult{}, err
	}
	s.text = string(t)
	if s.err != nil {
		return ad.ScopedResult{}, s.err
	}
	for _, e := range s.entries {
		if err := fn(e); err != nil {
			return ad.ScopedResult{}, err
		}
	}
	return ad.ScopedResult{Returned: len(s.entries), RootsCompleted: 1}, nil
}

func user(guidText, display, sam, upn, uac string) *ad.Entry {
	return ad.NewEntry("CN=x,DC=lab,DC=test", map[string][][]byte{
		"objectGUID": {g(guidText).Bytes()}, "displayName": {[]byte(display)}, "sAMAccountName": {[]byte(sam)},
		"userPrincipalName": {[]byte(upn)}, "userAccountControl": {[]byte(uac)},
	})
}

const (
	forest = "30313233-3435-3637-3839-616263646566" // the bytes of ident, as the connection record carries them
	connID = "11111111-1111-4111-8111-111111111111"
)

type conns struct{ c connection.Connection }

func (c conns) Get(context.Context, tenant.ID, connection.ID) (connection.Connection, error) {
	return c.c, nil
}

type direct struct{ cc connectorv1.ConnectorClient }

func (d direct) Connector(context.Context, string) (connectorv1.ConnectorClient, error) {
	return d.cc, nil
}

func activeConn() connection.Connection {
	return connection.Connection{ID: connID, Kind: connection.KindADForest, State: connection.StateActive,
		DirectoryIdentity: forest, Transport: connection.TransportLDAPS}
}

func searcher(t *testing.T, s *ssrc, c connection.Connection) *client.UserSearch {
	t.Helper()
	us, err := client.NewUserSearch(conns{c}, direct{startS(t, s)})
	if err != nil {
		t.Fatal(err)
	}
	return us
}

var tid = tenant.ID{}

func TestUserSearchOverGRPCReturnsOnlyAllowedFieldsSorted(t *testing.T) {
	s := &ssrc{src: &src{dsa: dsaA}, entries: []*ad.Entry{
		user("aaaaaaaa-0000-0000-0000-00000000000b", "Zed Lab", "lab-user-02", "lab-user-02@lab.test", "514"), // disabled
		user("aaaaaaaa-0000-0000-0000-00000000000a", "Ann Lab", "lab-user-01", "lab-user-01@lab.test", "512"),
	}}
	res, err := searcher(t, s, activeConn()).Users(context.Background(), tid, connID, "lab-user", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Users) != 2 || res.Users[0].SAMAccountName != "lab-user-01" || !res.Users[0].Enabled || res.Users[1].Enabled {
		t.Fatalf("users: %+v", res.Users)
	}
	if res.Users[0].ObjectGUID != "aaaaaaaa-0000-0000-0000-00000000000a" {
		t.Fatalf("guid text: %q", res.Users[0].ObjectGUID)
	}
	// Only the closed attribute list is asked for, below the forest root, subtree.
	if strings.Join(s.got.Attributes, ",") != "displayName,sAMAccountName,userPrincipalName,userAccountControl" {
		t.Fatalf("attributes: %v", s.got.Attributes)
	}
	if s.got.Depth != ad.ScopeSubtree || len(s.got.Roots) != 1 {
		t.Fatalf("scope: %+v", s.got)
	}
	want := `(&(objectClass=user)(!(objectClass=computer))(|(displayName=*lab-user*)(sAMAccountName=*lab-user*)(userPrincipalName=*lab-user*)))`
	if s.text != want {
		t.Fatalf("filter:\n got %s\nwant %s", s.text, want)
	}
}

func TestUserSearchTextIsNeverSyntax(t *testing.T) {
	// The API refuses these characters, but the client and the connector must hold on their own.
	s := &ssrc{src: &src{dsa: dsaA}}
	_, err := searcher(t, s, activeConn()).Users(context.Background(), tid, connID, `a*)(uid=*\`+"\x00x", 5)
	if !errors.Is(err, client.ErrSearchTextInvalid) {
		t.Fatalf("NUL must be refused before any call: %v", err)
	}
	if s.calls != 0 {
		t.Fatal("a refused text reached the directory")
	}
	_, err = searcher(t, s, activeConn()).Users(context.Background(), tid, connID, `a*)(uid=*\`, 5)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s.text, `*a\2a\29\28uid=\2a\5c*`) || strings.Count(s.text, "(") != 8 {
		t.Fatalf("text was not escaped as a value: %s", s.text)
	}
}

func TestUserSearchLimitAndTruncation(t *testing.T) {
	var es []*ad.Entry
	for i := 0; i < client.MaxSearchMatches+5; i++ {
		es = append(es, user("aaaaaaaa-0000-0000-0000-"+pad(i), "U", "u", "u@x", "512"))
	}
	s := &ssrc{src: &src{dsa: dsaA}, entries: es}
	res, err := searcher(t, s, activeConn()).Users(context.Background(), tid, connID, "u", 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Users) != 3 || !res.Truncated {
		t.Fatalf("limit/truncation: %d %v", len(res.Users), res.Truncated)
	}
}

func dsaWire(s string) *connectorv1.Guid { return write.GUIDToWire(g(s)) }

func pad(i int) string {
	const d = "0123456789"
	b := []byte("000000000000")
	for k := 11; k >= 0 && i > 0; k-- {
		b[k] = d[i%10]
		i /= 10
	}
	return string(b)
}

func TestUserSearchRefusesAConnectionThatIsNotActive(t *testing.T) {
	s := &ssrc{src: &src{dsa: dsaA}}
	for name, c := range map[string]connection.Connection{
		"draft":       func() connection.Connection { c := activeConn(); c.State = connection.StateDraft; return c }(),
		"suspended":   func() connection.Connection { c := activeConn(); c.State = connection.StateSuspended; return c }(),
		"no identity": func() connection.Connection { c := activeConn(); c.DirectoryIdentity = ""; return c }(),
		"entra":       func() connection.Connection { c := activeConn(); c.Kind = connection.KindEntraTenant; return c }(),
	} {
		_, err := searcher(t, s, c).Users(context.Background(), tid, connID, "u", 3)
		if !errors.Is(err, client.ErrSearchConnection) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if s.calls != 0 {
		t.Fatal("a refused connection reached the directory")
	}
}

func TestConnectorErrorsKeepTheirCodeAndNothingElse(t *testing.T) {
	s := &ssrc{src: &src{dsa: dsaA}, err: ad.NewError(ad.CodeInsufficientRights)}
	_, err := searcher(t, s, activeConn()).Users(context.Background(), tid, connID, "u", 3)
	var re *client.RemoteError
	if !errors.As(err, &re) || re.Err.GetCode() != connectorv1.ErrorCode_ERROR_CODE_INSUFFICIENT_RIGHTS {
		t.Fatalf("error: %v", err)
	}
}

func TestScopedSearchHandlerRefusesWhatItShouldNotRun(t *testing.T) {
	s := &ssrc{src: &src{dsa: dsaA}}
	cc := startS(t, s)
	root := &connectorv1.SearchRoot{Guid: &connectorv1.Guid{Value: []byte("0123456789abcdef")}}
	eq := func(attr, v string) *connectorv1.Filter {
		return &connectorv1.Filter{Node: &connectorv1.Filter_Equal{Equal: &connectorv1.Comparison{Attribute: attr,
			Value: &connectorv1.FilterValue{Value: &connectorv1.FilterValue_Text{Text: v}}}}}
	}
	base := func() *connectorv1.ScopedSearchRequest {
		return &connectorv1.ScopedSearchRequest{Connection: &connectorv1.ConnectionRef{ConnectionId: connID, DirectoryIdentity: ident},
			Roots: []*connectorv1.SearchRoot{root}, Depth: connectorv1.SearchDepth_SEARCH_DEPTH_SUBTREE,
			Filter: eq("objectClass", "user"), Attributes: []string{"cn"}}
	}
	other := &connectorv1.DirectoryIdentity{Identity: &connectorv1.DirectoryIdentity_AdForest{AdForest: &connectorv1.AdForestIdentity{
		ForestRootNcGuid: &connectorv1.Guid{Value: []byte("fedcba9876543210")}}}}
	cases := map[string]func(*connectorv1.ScopedSearchRequest){
		"wrong identity": func(r *connectorv1.ScopedSearchRequest) { r.Connection.DirectoryIdentity = other },
		"no roots":       func(r *connectorv1.ScopedSearchRequest) { r.Roots = nil },
		"bad root": func(r *connectorv1.ScopedSearchRequest) {
			r.Roots = []*connectorv1.SearchRoot{{Guid: &connectorv1.Guid{Value: []byte("x")}}}
		},
		"no depth":       func(r *connectorv1.ScopedSearchRequest) { r.Depth = connectorv1.SearchDepth_SEARCH_DEPTH_UNSPECIFIED },
		"no attributes":  func(r *connectorv1.ScopedSearchRequest) { r.Attributes = nil },
		"security desc":  func(r *connectorv1.ScopedSearchRequest) { r.Attributes = []string{"nTSecurityDescriptor"} },
		"unknown filter": func(r *connectorv1.ScopedSearchRequest) { r.Filter = eq("unicodePwd", "x") },
		"empty filter":   func(r *connectorv1.ScopedSearchRequest) { r.Filter = &connectorv1.Filter{} },
		"pin elsewhere": func(r *connectorv1.ScopedSearchRequest) {
			r.Dc = &connectorv1.DcSelection{PinnedDsaGuid: dsaWire(dsaB)}
		},
	}
	for name, mut := range cases {
		r := base()
		mut(r)
		st, err := cc.ScopedSearch(context.Background(), r)
		if err == nil {
			_, err = st.Recv()
		}
		if err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	if s.calls != 0 {
		t.Fatalf("a refused request reached the directory (%d calls)", s.calls)
	}
}

func TestScopedSearchStreamEndsWithCompletion(t *testing.T) {
	s := &ssrc{src: &src{dsa: dsaA}, entries: []*ad.Entry{user("aaaaaaaa-0000-0000-0000-00000000000a", "A", "a", "a@x", "512")}}
	cc := startS(t, s)
	st, err := cc.ScopedSearch(context.Background(), &connectorv1.ScopedSearchRequest{
		Connection: &connectorv1.ConnectionRef{ConnectionId: connID, DirectoryIdentity: ident},
		Roots:      []*connectorv1.SearchRoot{{Guid: &connectorv1.Guid{Value: []byte("0123456789abcdef")}}},
		Depth:      connectorv1.SearchDepth_SEARCH_DEPTH_SUBTREE, Attributes: []string{"displayName"},
		Filter: &connectorv1.Filter{Node: &connectorv1.Filter_Present{Present: "objectClass"}}})
	if err != nil {
		t.Fatal(err)
	}
	var batches, done int
	for {
		m, err := st.Recv()
		if err != nil {
			break
		}
		switch m.GetEvent().(type) {
		case *connectorv1.ScopedSearchResponse_Batch:
			batches++
		case *connectorv1.ScopedSearchResponse_Completed:
			done++
		}
	}
	if batches != 1 || done != 1 {
		t.Fatalf("batches=%d completed=%d", batches, done)
	}
}
