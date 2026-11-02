package read_test

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/read"
	"github.com/skenzeriq/activediq/internal/connector/write"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/client"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// The handler logic of ChangeFeed over a scripted directory. What DirSync does on a real DC is the
// lab's (feed_lab_test.go); this file proves the ORDER of the checks, what is sent when, and that
// a refused call never reaches the DC.

const (
	ncGUID  = "bbbbbbbb-0000-0000-0000-000000000001"
	invA    = "55555555-5555-5555-5555-555555555555"
	invB    = "66666666-6666-6666-6666-666666666666"
	feedLif = 10 * 24 * time.Hour // margin = 1 day, so the boundary is 9 days
)

type fsrc struct {
	*src
	inv      string
	invAfter string // invocation id reported from the second BoundDC call on
	boundErr error
	usn      int64
	usnErr   error
	life     time.Duration
	managed  bool
	secret   bool
	pages    []ad.DirSyncPage // returned in order; the last should have More = false
	cycleErr error
	endless  bool // answer More forever with a new cookie
	block    bool // answer nothing until the context ends
	log      []string
	got      ad.DirSyncRequest
}

func (f *fsrc) BoundDC(ctx context.Context) (*connectorv1.DcIdentity, error) {
	f.log = append(f.log, "bound")
	if f.boundErr != nil {
		return nil, f.boundErr
	}
	f.boundN++
	inv := f.inv
	if f.boundN > 1 && f.invAfter != "" {
		inv = f.invAfter
	}
	return &connectorv1.DcIdentity{DsaGuid: write.GUIDToWire(g(f.dsa)), InvocationId: write.GUIDToWire(g(inv)), DnsHostname: "dc1", Site: "Default"}, nil
}

func (f *fsrc) ManagesNC(_ context.Context, nc guid.GUID) (bool, error) {
	f.log = append(f.log, "manages")
	return f.managed && nc == g(ncGUID), nil
}
func (f *fsrc) CheckFeedAttributes([]string) error {
	f.log = append(f.log, "check")
	if f.secret {
		return ad.NewError(ad.CodeSecretAttribute)
	}
	return nil
}
func (f *fsrc) HighestCommittedUSN(context.Context) (int64, error) {
	f.log = append(f.log, "usn")
	return f.usn, f.usnErr
}
func (f *fsrc) DeletionLifetime(context.Context) (time.Duration, error) {
	f.log = append(f.log, "lifetime")
	return f.life, nil
}
func (f *fsrc) DirSyncCycle(ctx context.Context, r ad.DirSyncRequest, fn func(ad.DirSyncPage) error) (ad.DirSyncPage, error) {
	f.log = append(f.log, "cycle")
	f.got = r
	if f.cycleErr != nil {
		return ad.DirSyncPage{}, f.cycleErr
	}
	if f.block {
		<-ctx.Done()
		return ad.DirSyncPage{}, ad.NewError(ad.CodeCanceled)
	}
	if f.endless {
		for i := byte(1); ; i++ {
			if err := fn(ad.DirSyncPage{Cookie: []byte{i, i >> 1}, More: true}); err != nil {
				return ad.DirSyncPage{}, err
			}
		}
	}
	for _, p := range f.pages {
		if err := fn(p); err != nil {
			return ad.DirSyncPage{}, err
		}
	}
	last := f.pages[len(f.pages)-1]
	last.Changes = nil
	return last, nil
}

func newFsrc() *fsrc {
	return &fsrc{src: &src{dsa: dsaA}, inv: invA, usn: 5000, life: feedLif, managed: true,
		pages: []ad.DirSyncPage{{Cookie: []byte("ck1")}}}
}

func startFeed(t *testing.T, s read.Source, opts ...read.Option) connectorv1.ConnectorClient {
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

func feedReq() *connectorv1.ChangeFeedRequest {
	return &connectorv1.ChangeFeedRequest{
		Connection: &connectorv1.ConnectionRef{ConnectionId: "c1", DirectoryIdentity: ident},
		Partition:  &connectorv1.FeedPartition{Partition: &connectorv1.FeedPartition_AdNcGuid{AdNcGuid: write.GUIDToWire(g(ncGUID))}},
		Start:      &connectorv1.ChangeFeedRequest_Prime{Prime: &connectorv1.FeedPrime{}},
		Attributes: []string{"cn"},
	}
}

func validCookie() *connectorv1.FeedCookie {
	usn := uint64(4000)
	return &connectorv1.FeedCookie{ProviderState: []byte("ck0"), ProviderKind: connectorv1.ProviderKind_PROVIDER_KIND_AD, FormatVersion: 1,
		Issuer:                    &connectorv1.DcIdentity{DsaGuid: write.GUIDToWire(g(dsaA)), InvocationId: write.GUIDToWire(g(invA))},
		HighestCommittedUsnBefore: &usn, IssuedAt: timestamppb.New(time.Now().Add(-time.Hour))}
}

func resumeReq(c *connectorv1.FeedCookie) *connectorv1.ChangeFeedRequest {
	r := feedReq()
	r.Start = &connectorv1.ChangeFeedRequest_Resume{Resume: &connectorv1.FeedResume{Cookie: c}}
	return r
}

func feedAll(c connectorv1.ConnectorClient, r *connectorv1.ChangeFeedRequest) ([]*connectorv1.ChangeBatch, error) {
	st, err := c.ChangeFeed(context.Background(), r)
	if err != nil {
		return nil, err
	}
	var out []*connectorv1.ChangeBatch
	for {
		m, err := st.Recv()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		out = append(out, m.GetBatch())
	}
}

func staleReason(t *testing.T, err error) connectorv1.ResyncReason {
	t.Helper()
	var re *client.RemoteError
	if !errors.As(client.FromStatus(err), &re) || re.Err.GetCode() != connectorv1.ErrorCode_ERROR_CODE_STALE_COOKIE {
		t.Fatalf("not a STALE_COOKIE: %v", err)
	}
	return re.Err.GetStaleCookie().GetReason()
}

func TestFeedPrimeIsOneEmptyBatchWithTheCookie(t *testing.T) {
	f := newFsrc()
	f.pages = []ad.DirSyncPage{
		{Cookie: []byte("a"), More: true, Changes: []ad.ObjectChange{{GUID: g(objGUID), State: ad.StateLive}}, SecretAttributesDropped: 2},
		{Cookie: []byte("b"), More: true, SecretAttributesDropped: 1},
		{Cookie: []byte("c"), Changes: []ad.ObjectChange{{GUID: g(parGUID), State: ad.StateLive}}},
	}
	bs, err := feedAll(startFeed(t, f), feedReq())
	if err != nil || len(bs) != 1 {
		t.Fatalf("%v %d", err, len(bs))
	}
	b := bs[0]
	if !b.GetCycleComplete() || len(b.GetChanges()) != 0 || b.GetSequence() != 1 || b.GetSecretAttributesDropped() != 3 {
		t.Fatalf("batch %v", b)
	}
	c := b.GetCookieAfter()
	if string(c.GetProviderState()) != "c" || c.GetFormatVersion() != 1 || c.GetProviderKind() != connectorv1.ProviderKind_PROVIDER_KIND_AD ||
		c.GetHighestCommittedUsnBefore() != 5000 || c.GetIssuedAt() == nil ||
		string(c.GetIssuer().GetDsaGuid().GetValue()) != string(write.GUIDToWire(g(dsaA)).GetValue()) ||
		string(c.GetIssuer().GetInvocationId().GetValue()) != string(write.GUIDToWire(g(invA)).GetValue()) {
		t.Fatalf("cookie %v", c)
	}
	// The USN is read before the search; the mandatory set is the connector's, the names are the caller's.
	if i, j := idx(f.log, "usn"), idx(f.log, "cycle"); i < 0 || j < 0 || i > j {
		t.Fatalf("order %v", f.log)
	}
	if len(f.got.Cookie) != 0 || len(f.got.Attributes) != 1 || f.got.Attributes[0] != "cn" {
		t.Fatalf("request %+v", f.got)
	}
}

func idx(l []string, s string) int {
	for i, x := range l {
		if x == s {
			return i
		}
	}
	return -1
}

func TestFeedRequestRefusalsNeverReachTheDC(t *testing.T) {
	big := make([]byte, 64<<10+1)
	cases := []struct {
		name string
		mut  func(*connectorv1.ChangeFeedRequest)
		code connectorv1.ErrorCode
		secr bool
	}{
		{"star", func(r *connectorv1.ChangeFeedRequest) { r.Attributes = []string{"*"} }, connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, false},
		{"plus", func(r *connectorv1.ChangeFeedRequest) { r.Attributes = []string{"cn", "+"} }, connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, false},
		{"sd", func(r *connectorv1.ChangeFeedRequest) { r.Attributes = []string{"nTSecurityDescriptor"} }, connectorv1.ErrorCode_ERROR_CODE_ATTRIBUTE_NOT_ALLOWED, false},
		{"secret", func(r *connectorv1.ChangeFeedRequest) { r.Attributes = []string{"unicodePwd"} }, connectorv1.ErrorCode_ERROR_CODE_SECRET_ATTRIBUTE, true},
		{"full", func(r *connectorv1.ChangeFeedRequest) {
			r.Start = &connectorv1.ChangeFeedRequest_Full{Full: &connectorv1.FeedFull{}}
		}, connectorv1.ErrorCode_ERROR_CODE_CAPABILITY_UNSUPPORTED, false},
		{"no start", func(r *connectorv1.ChangeFeedRequest) { r.Start = nil }, connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, false},
		{"no partition", func(r *connectorv1.ChangeFeedRequest) { r.Partition = nil }, connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, false},
		{"entra partition", func(r *connectorv1.ChangeFeedRequest) {
			r.Partition = &connectorv1.FeedPartition{Partition: &connectorv1.FeedPartition_EntraResource{EntraResource: connectorv1.EntraResource_ENTRA_RESOURCE_USERS}}
		}, connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, false},
		{"foreign identity", func(r *connectorv1.ChangeFeedRequest) {
			r.Connection.DirectoryIdentity = &connectorv1.DirectoryIdentity{Identity: &connectorv1.DirectoryIdentity_AdForest{AdForest: &connectorv1.AdForestIdentity{ForestRootNcGuid: &connectorv1.Guid{Value: []byte("fedcba9876543210")}}}}
		}, connectorv1.ErrorCode_ERROR_CODE_DIRECTORY_IDENTITY_MISMATCH, false},
		{"oversize cookie", func(r *connectorv1.ChangeFeedRequest) {
			c := validCookie()
			c.ProviderState = big
			r.Start = &connectorv1.ChangeFeedRequest_Resume{Resume: &connectorv1.FeedResume{Cookie: c}}
		}, connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, false},
		{"empty cookie state", func(r *connectorv1.ChangeFeedRequest) {
			c := validCookie()
			c.ProviderState = nil
			r.Start = &connectorv1.ChangeFeedRequest_Resume{Resume: &connectorv1.FeedResume{Cookie: c}}
		}, connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, false},
		{"entra cookie", func(r *connectorv1.ChangeFeedRequest) {
			c := validCookie()
			c.ProviderKind = connectorv1.ProviderKind_PROVIDER_KIND_ENTRA
			r.Start = &connectorv1.ChangeFeedRequest_Resume{Resume: &connectorv1.FeedResume{Cookie: c}}
		}, connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, false},
		{"no cookie", func(r *connectorv1.ChangeFeedRequest) {
			r.Start = &connectorv1.ChangeFeedRequest_Resume{Resume: &connectorv1.FeedResume{}}
		}, connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, false},
		{"no issuer", func(r *connectorv1.ChangeFeedRequest) {
			c := validCookie()
			c.Issuer = nil
			r.Start = &connectorv1.ChangeFeedRequest_Resume{Resume: &connectorv1.FeedResume{Cookie: c}}
		}, connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, false},
		{"no usn", func(r *connectorv1.ChangeFeedRequest) {
			c := validCookie()
			c.HighestCommittedUsnBefore = nil
			r.Start = &connectorv1.ChangeFeedRequest_Resume{Resume: &connectorv1.FeedResume{Cookie: c}}
		}, connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, false},
		{"no issued_at", func(r *connectorv1.ChangeFeedRequest) {
			c := validCookie()
			c.IssuedAt = nil
			r.Start = &connectorv1.ChangeFeedRequest_Resume{Resume: &connectorv1.FeedResume{Cookie: c}}
		}, connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFsrc()
			f.secret = c.secr
			r := feedReq()
			c.mut(r)
			_, err := feedAll(startFeed(t, f), r)
			if got := code(err); got != c.code {
				t.Fatalf("code %v (%v), want %v", got, err, c.code)
			}
			for _, call := range f.log {
				if call == "cycle" || call == "usn" || call == "bound" || call == "manages" {
					t.Fatalf("the DC was reached before the refusal: %v", f.log)
				}
			}
		})
	}
}

func TestFeedPartitionMustBeAManagedNC(t *testing.T) {
	f := newFsrc()
	f.managed = false
	_, err := feedAll(startFeed(t, f), feedReq())
	if code(err) != connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT || idx(f.log, "cycle") >= 0 {
		t.Fatalf("%v %v", err, f.log)
	}
	// An NC GUID the connection does not manage (Configuration, Schema, a stranger) is the same refusal.
	f = newFsrc()
	r := feedReq()
	r.Partition = &connectorv1.FeedPartition{Partition: &connectorv1.FeedPartition_AdNcGuid{AdNcGuid: write.GUIDToWire(g(parGUID))}}
	if _, err = feedAll(startFeed(t, f), r); code(err) != connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT || idx(f.log, "cycle") >= 0 {
		t.Fatalf("%v %v", err, f.log)
	}
}

func TestFeedResumePreChecksAreStaleCookieBeforeAnyBatch(t *testing.T) {
	cases := []struct {
		name   string
		cookie func(*connectorv1.FeedCookie)
		dir    func(*fsrc)
		want   connectorv1.ResyncReason
		search bool // the DirSync search may have been sent
	}{
		{"edited invocation", func(c *connectorv1.FeedCookie) { c.Issuer.InvocationId = write.GUIDToWire(g(invB)) }, nil,
			connectorv1.ResyncReason_RESYNC_REASON_INVOCATION_ID_CHANGED, false},
		{"restored DC", nil, func(f *fsrc) { f.inv = invB }, connectorv1.ResyncReason_RESYNC_REASON_INVOCATION_ID_CHANGED, false},
		{"edited dsa", func(c *connectorv1.FeedCookie) { c.Issuer.DsaGuid = write.GUIDToWire(g(dsaB)) }, nil,
			connectorv1.ResyncReason_RESYNC_REASON_ISSUER_MISMATCH, false},
		{"usn rollback", func(c *connectorv1.FeedCookie) { u := uint64(5001); c.HighestCommittedUsnBefore = &u }, nil,
			connectorv1.ResyncReason_RESYNC_REASON_USN_ROLLBACK, false},
		{"at the boundary", func(c *connectorv1.FeedCookie) {
			c.IssuedAt = timestamppb.New(time.Now().Add(-(feedLif - 24*time.Hour) - time.Minute))
		}, nil, connectorv1.ResyncReason_RESYNC_REASON_COOKIE_TOO_OLD, false},
		{"beyond the lifetime", func(c *connectorv1.FeedCookie) { c.IssuedAt = timestamppb.New(time.Now().Add(-2 * feedLif)) }, nil,
			connectorv1.ResyncReason_RESYNC_REASON_COOKIE_TOO_OLD, false},
		{"unknown format", func(c *connectorv1.FeedCookie) { c.FormatVersion = 99 }, nil, connectorv1.ResyncReason_RESYNC_REASON_COOKIE_FORMAT_UNKNOWN, false},
		{"corrupted state", nil, func(f *fsrc) { f.cycleErr = ad.NewError(ad.CodeCookieRejected) }, connectorv1.ResyncReason_RESYNC_REASON_SERVER_REJECTED, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFsrc()
			ck := validCookie()
			if c.cookie != nil {
				c.cookie(ck)
			}
			if c.dir != nil {
				c.dir(f)
			}
			bs, err := feedAll(startFeed(t, f), resumeReq(ck))
			if len(bs) != 0 {
				t.Fatalf("a batch preceded the refusal: %d", len(bs))
			}
			if got := staleReason(t, err); got != c.want {
				t.Fatalf("reason %v, want %v", got, c.want)
			}
			if !c.search && idx(f.log, "cycle") >= 0 {
				t.Fatalf("the DirSync search was sent: %v", f.log)
			}
		})
	}
}

func TestFeedResumeJustInsideTheMarginIsServed(t *testing.T) {
	f := newFsrc()
	ck := validCookie()
	ck.IssuedAt = timestamppb.New(time.Now().Add(-(feedLif - 24*time.Hour) + time.Minute))
	bs, err := feedAll(startFeed(t, f), resumeReq(ck))
	if err != nil || len(bs) != 1 || !bs[0].GetCycleComplete() {
		t.Fatalf("%v %v", err, bs)
	}
	if string(f.got.Cookie) != "ck0" {
		t.Fatalf("the cookie was not passed on: %q", f.got.Cookie)
	}
}

func TestFeedUnreachableIssuerIsRetryTheSameDCNeverStale(t *testing.T) {
	f := newFsrc()
	f.boundErr = errors.New("down")
	_, err := feedAll(startFeed(t, f), resumeReq(validCookie()))
	var re *client.RemoteError
	if !errors.As(client.FromStatus(err), &re) || re.Err.GetCode() != connectorv1.ErrorCode_ERROR_CODE_UNREACHABLE_DC ||
		re.Err.GetRetry() != connectorv1.RetryAdvice_RETRY_ADVICE_SAME_DC_AFTER_BACKOFF {
		t.Fatalf("%v", err)
	}
	if idx(f.log, "cycle") >= 0 {
		t.Fatal("searched")
	}
	// A DC that drops during the cycle is the same answer.
	f = newFsrc()
	f.cycleErr = ad.NewError(ad.CodeUnreachable)
	_, err = feedAll(startFeed(t, f), resumeReq(validCookie()))
	if !errors.As(client.FromStatus(err), &re) || re.Err.GetCode() != connectorv1.ErrorCode_ERROR_CODE_UNREACHABLE_DC ||
		re.Err.GetRetry() != connectorv1.RetryAdvice_RETRY_ADVICE_SAME_DC_AFTER_BACKOFF {
		t.Fatalf("%v", err)
	}
}

func TestFeedResumeStreamsPagesAndEndsWithTheCompleteBatchOnly(t *testing.T) {
	f := newFsrc()
	mem := []byte("CN=m,DC=lab")
	f.pages = []ad.DirSyncPage{
		{Cookie: []byte("p1"), More: true, Changes: []ad.ObjectChange{{GUID: g(objGUID), State: ad.StateLive, DN: "CN=a,DC=lab", Parent: g(parGUID), HasParent: true,
			Attributes: []ad.AttributeChange{{Name: "cn", Op: ad.OpSet, Values: [][]byte{[]byte("a")}}, {Name: "member", Op: ad.OpValuesAdded, Values: [][]byte{mem}},
				{Name: "description", Op: ad.OpCleared}}}}},
		{Cookie: []byte("p2"), More: true},
		{Cookie: []byte("p3"), Changes: []ad.ObjectChange{{GUID: g(parGUID), State: ad.StateRecycled, DN: "CN=x\\0ADEL:y,CN=Deleted Objects,DC=lab"}}},
	}
	bs, err := feedAll(startFeed(t, f), resumeReq(validCookie()))
	if err != nil || len(bs) != 3 {
		t.Fatalf("%v %d", err, len(bs))
	}
	for i, b := range bs {
		if b.GetSequence() != uint64(i+1) || b.GetCycleComplete() != (i == 2) {
			t.Fatalf("batch %d: seq %d complete %v", i, b.GetSequence(), b.GetCycleComplete())
		}
		if i < 2 && b.GetCookieAfter().GetIssuedAt() == nil {
			t.Fatal("mid-cycle cookie without issued_at")
		}
	}
	oc := bs[0].GetChanges()[0]
	if oc.GetState() != connectorv1.ObjectState_OBJECT_STATE_LIVE || oc.GetDn().GetDisplayDn() != "CN=a,DC=lab" || oc.GetParentGuid() == nil || len(oc.GetAttributes()) != 3 {
		t.Fatalf("change %v", oc)
	}
	ops := map[string]connectorv1.ChangeOp{}
	for _, a := range oc.GetAttributes() {
		ops[a.GetName()] = a.GetOp()
	}
	if ops["cn"] != connectorv1.ChangeOp_CHANGE_OP_SET || ops["member"] != connectorv1.ChangeOp_CHANGE_OP_VALUES_ADDED || ops["description"] != connectorv1.ChangeOp_CHANGE_OP_CLEARED {
		t.Fatalf("ops %v", ops)
	}
	if oc.GetAttributes()[1].GetValues()[0].GetDn().GetDisplayDn() != "CN=m,DC=lab" {
		t.Fatalf("member value %v", oc.GetAttributes()[1])
	}
	if bs[2].GetChanges()[0].GetState() != connectorv1.ObjectState_OBJECT_STATE_RECYCLED || string(bs[2].GetCookieAfter().GetProviderState()) != "p3" {
		t.Fatalf("last %v", bs[2])
	}
}

func TestFeedDCChangeDuringTheCycleWithholdsTheCompleteBatch(t *testing.T) {
	f := newFsrc()
	f.invAfter = invB // the DC reports another invocation id after the cycle
	f.pages = []ad.DirSyncPage{{Cookie: []byte("p1"), More: true}, {Cookie: []byte("p2")}}
	bs, err := feedAll(startFeed(t, f), resumeReq(validCookie()))
	if got := staleReason(t, err); got != connectorv1.ResyncReason_RESYNC_REASON_INVOCATION_ID_CHANGED {
		t.Fatalf("reason %v", got)
	}
	for _, b := range bs {
		if b.GetCycleComplete() {
			t.Fatal("cycle_complete after the DC changed")
		}
	}
	// A prime that sees the DC change gives no cookie at all.
	f = newFsrc()
	f.invAfter = invB
	if bs, err = feedAll(startFeed(t, f), feedReq()); err == nil || len(bs) != 0 {
		t.Fatalf("prime kept a cookie from a changed DC: %v %d", err, len(bs))
	}
}

func TestFeedPrimePinnedToAnotherDCIsRefused(t *testing.T) {
	f := newFsrc()
	r := feedReq()
	r.GetPrime().Dc = &connectorv1.DcSelection{PinnedDsaGuid: write.GUIDToWire(g(dsaB))}
	if _, err := feedAll(startFeed(t, f), r); code(err) != connectorv1.ErrorCode_ERROR_CODE_UNREACHABLE_DC || idx(f.log, "cycle") >= 0 {
		t.Fatalf("%v %v", err, f.log)
	}
}

func TestFeedIsBoundedByPagesAndByTime(t *testing.T) {
	f := newFsrc()
	f.endless = true
	for _, r := range []*connectorv1.ChangeFeedRequest{feedReq(), resumeReq(validCookie())} {
		_, err := feedAll(startFeed(t, f, read.WithFeedLimits(50, time.Minute)), r)
		if code(err) != connectorv1.ErrorCode_ERROR_CODE_LIMIT_EXCEEDED {
			t.Fatalf("endless More: %v", err)
		}
	}
	f = newFsrc()
	f.block = true
	start := time.Now()
	_, err := feedAll(startFeed(t, f, read.WithFeedLimits(50, 200*time.Millisecond)), feedReq())
	if code(err) != connectorv1.ErrorCode_ERROR_CODE_LIMIT_EXCEEDED || time.Since(start) > 5*time.Second {
		t.Fatalf("stuck DC: %v after %v", err, time.Since(start))
	}
}

func TestFeedPageWithoutACookieIsAnErrorNotARestart(t *testing.T) {
	f := newFsrc()
	f.pages = []ad.DirSyncPage{{More: true}}
	if _, err := feedAll(startFeed(t, f), resumeReq(validCookie())); code(err) != connectorv1.ErrorCode_ERROR_CODE_PROVIDER_FAILURE {
		t.Fatalf("%v", err)
	}
}

func TestFeedWithoutFeederIsUnsupported(t *testing.T) {
	_, err := feedAll(startFeed(t, &src{dsa: dsaA}), feedReq())
	if code(err) != connectorv1.ErrorCode_ERROR_CODE_CAPABILITY_UNSUPPORTED {
		t.Fatalf("%v", err)
	}
}
