package client_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

const feedNC = "11111111-0000-4000-8000-000000000001" // gH, the head of the domain NC in conns

// feedStep is one thing the fake stream does: yield a batch or fail.
type feedStep struct {
	batch *connectorv1.ChangeBatch
	err   error
}

// fakeFeed is a ConnectorSource whose ChangeFeed plays steps, then EOF. It records its calls.
type fakeFeed struct {
	connectorv1.ConnectorClient
	steps    []feedStep
	openErr  error
	calls    atomic.Int32
	requests []*connectorv1.ChangeFeedRequest
}

func (f *fakeFeed) Connector(context.Context, string) (connectorv1.ConnectorClient, error) {
	return f, nil
}

func (f *fakeFeed) ChangeFeed(_ context.Context, in *connectorv1.ChangeFeedRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[connectorv1.ChangeFeedResponse], error) {
	f.calls.Add(1)
	f.requests = append(f.requests, in)
	if f.openErr != nil {
		return nil, f.openErr
	}
	return &feedStream{steps: f.steps}, nil
}

type feedStream struct {
	grpc.ClientStream
	steps []feedStep
}

func (s *feedStream) Recv() (*connectorv1.ChangeFeedResponse, error) {
	if len(s.steps) == 0 {
		return nil, io.EOF
	}
	st := s.steps[0]
	s.steps = s.steps[1:]
	if st.err != nil {
		return nil, st.err
	}
	return &connectorv1.ChangeFeedResponse{Event: &connectorv1.ChangeFeedResponse_Batch{Batch: st.batch}}, nil
}

func cookie(n int) *connectorv1.FeedCookie {
	return &connectorv1.FeedCookie{ProviderState: []byte{byte(n)}, ProviderKind: connectorv1.ProviderKind_PROVIDER_KIND_AD, FormatVersion: 1}
}

func batch(seq uint64, complete bool) feedStep {
	return feedStep{batch: &connectorv1.ChangeBatch{
		Sequence: seq, CookieAfter: cookie(int(seq)), CycleComplete: complete,
		Changes: []*connectorv1.ObjectChange{{ObjectGuid: &connectorv1.Guid{Value: make([]byte, 16)}}},
	}}
}

type managedSet map[string]bool

func (m managedSet) Managed(_ context.Context, _ tenant.ID, _ connection.ID, nc string) (bool, error) {
	return m[nc], nil
}

type feedConns struct{ c connection.Connection }

func (f feedConns) Get(context.Context, tenant.ID, connection.ID) (connection.Connection, error) {
	return f.c, nil
}

func activeAD() connection.Connection {
	return connection.Connection{ID: connUUID, Kind: connection.KindADForest, State: connection.StateActive, DirectoryIdentity: gH}
}

func newFeed(t *testing.T, c connection.Connection, f *fakeFeed, managed client.ManagedPartitions) *client.ChangeFeedReader {
	t.Helper()
	r, err := client.NewChangeFeedReader(feedConns{c}, f, managed)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func readFeed(r *client.ChangeFeedReader, req client.FeedRequest) ([]*connectorv1.ChangeBatch, client.FeedResult, error) {
	var got []*connectorv1.ChangeBatch
	res, err := r.Read(context.Background(), tenant.ID{}, req, func(_ context.Context, b *connectorv1.ChangeBatch) error {
		got = append(got, b)
		return nil
	})
	return got, res, err
}

func feedReq() client.FeedRequest {
	return client.FeedRequest{Connection: connUUID, NC: feedNC, Resume: cookie(0)}
}

func TestChangeFeedCompletedYieldsBatchesInOrder(t *testing.T) {
	f := &fakeFeed{steps: []feedStep{batch(1, false), batch(2, false), batch(3, true)}}
	r := newFeed(t, activeAD(), f, managedSet{feedNC: true})
	got, res, err := readFeed(r, feedReq())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || res.Batches != 3 || res.Changes != 3 {
		t.Fatalf("got %d batches, result %+v", len(got), res)
	}
	for i, b := range got {
		if b.GetSequence() != uint64(i+1) || !proto.Equal(b.GetCookieAfter(), cookie(i+1)) {
			t.Fatalf("batch %d out of order or wrong cookie: %v", i, b)
		}
	}
	if !proto.Equal(res.Cookie, cookie(3)) {
		t.Fatalf("result cookie %v", res.Cookie)
	}
	req := f.requests[0]
	if req.GetResume().GetCookie() == nil || req.GetPrime() != nil || req.GetFull() != nil {
		t.Fatalf("not a resume: %v", req)
	}
}

func TestChangeFeedPrimeIsOneCompleteBatchWithNoChanges(t *testing.T) {
	f := &fakeFeed{steps: []feedStep{{batch: &connectorv1.ChangeBatch{Sequence: 1, CookieAfter: cookie(9), CycleComplete: true}}}}
	r := newFeed(t, activeAD(), f, managedSet{feedNC: true})
	_, res, err := readFeed(r, client.FeedRequest{Connection: connUUID, NC: feedNC})
	if err != nil || res.Batches != 1 || res.Changes != 0 || !proto.Equal(res.Cookie, cookie(9)) {
		t.Fatalf("%+v %v", res, err)
	}
	if f.requests[0].GetPrime() == nil || f.requests[0].GetResume() != nil {
		t.Fatalf("not a prime: %v", f.requests[0])
	}
}

func TestChangeFeedCutOffIsNotSuccess(t *testing.T) {
	t.Run("ends after batch 2 without cycle_complete", func(t *testing.T) {
		f := &fakeFeed{steps: []feedStep{batch(1, false), batch(2, false)}}
		got, res, err := readFeed(newFeed(t, activeAD(), f, managedSet{feedNC: true}), feedReq())
		if !errors.Is(err, client.ErrFeedIncomplete) {
			t.Fatalf("err %v", err)
		}
		if len(got) != 2 || res.Batches != 2 || !proto.Equal(res.Cookie, cookie(2)) {
			t.Fatalf("saw %d batches, %+v", len(got), res)
		}
	})
	t.Run("errors mid-stream", func(t *testing.T) {
		f := &fakeFeed{steps: []feedStep{batch(1, false), {err: status.Error(codes.Unavailable, "connection reset by 10.0.0.5")}, batch(2, true)}}
		got, _, err := readFeed(newFeed(t, activeAD(), f, managedSet{feedNC: true}), feedReq())
		if err == nil || errors.Is(err, client.ErrFeedIncomplete) {
			t.Fatalf("err %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("saw %d batches, want 1", len(got))
		}
	})
	t.Run("connector error mid-stream is mapped", func(t *testing.T) {
		f := &fakeFeed{steps: []feedStep{batch(1, false), {err: connErr(connectorv1.ErrorCode_ERROR_CODE_UNREACHABLE_DC, nil)}}}
		got, _, err := readFeed(newFeed(t, activeAD(), f, managedSet{feedNC: true}), feedReq())
		if !errors.Is(err, client.ErrUnreachableDC) || len(got) != 1 {
			t.Fatalf("err %v, %d batches", err, len(got))
		}
	})
}

func TestChangeFeedProtocolViolationsAreNotYielded(t *testing.T) {
	noCookie := feedStep{batch: &connectorv1.ChangeBatch{Sequence: 2}}
	for name, steps := range map[string][]feedStep{
		"batch after the last":  {batch(1, true), batch(2, true)},
		"sequence gap":          {batch(1, false), batch(3, true)},
		"sequence repeat":       {batch(1, false), batch(1, true)},
		"starts at 2":           {batch(2, true)},
		"no cookie":             {batch(1, false), noCookie},
		"empty event":           {batch(1, false), {}},
		"complete then nothing": {batch(1, true), {}},
	} {
		t.Run(name, func(t *testing.T) {
			f := &fakeFeed{steps: steps}
			got, _, err := readFeed(newFeed(t, activeAD(), f, managedSet{feedNC: true}), feedReq())
			if !errors.Is(err, client.ErrFeedProtocol) {
				t.Fatalf("err %v", err)
			}
			if len(got) > 1 {
				t.Fatalf("yielded %d batches past a violation", len(got))
			}
		})
	}
}

func TestChangeFeedHandlerErrorStopsTheFeed(t *testing.T) {
	f := &fakeFeed{steps: []feedStep{batch(1, false), batch(2, false), batch(3, true)}}
	r := newFeed(t, activeAD(), f, managedSet{feedNC: true})
	boom := errors.New("commit failed")
	n := 0
	res, err := r.Read(context.Background(), tenant.ID{}, feedReq(), func(context.Context, *connectorv1.ChangeBatch) error {
		n++
		if n == 2 {
			return boom
		}
		return nil
	})
	if !errors.Is(err, client.ErrFeedHandler) || !errors.Is(err, boom) || n != 2 {
		t.Fatalf("err %v after %d batches", err, n)
	}
	if res.Batches != 1 || !proto.Equal(res.Cookie, cookie(1)) {
		t.Fatalf("the failed batch counted as committed: %+v", res)
	}
}

func connErr(code connectorv1.ErrorCode, mod func(*connectorv1.ConnectorError)) error {
	ce := &connectorv1.ConnectorError{Code: code, Message: "secret detail CN=Admin,DC=corp,DC=example"}
	if mod != nil {
		mod(ce)
	}
	st, err := status.New(codes.FailedPrecondition, "failed on dc1.corp.example").WithDetails(ce)
	if err != nil {
		panic(err)
	}
	return st.Err()
}

func TestChangeFeedErrorMapping(t *testing.T) {
	const leak = "corp.example"
	stale := func(r connectorv1.ResyncReason) func(*connectorv1.ConnectorError) {
		return func(ce *connectorv1.ConnectorError) {
			ce.Details = &connectorv1.ConnectorError_StaleCookie{StaleCookie: &connectorv1.StaleCookieDetails{Reason: r,
				Issuer:   &connectorv1.DcIdentity{DnsHostname: "dc1.corp.example"},
				Observed: &connectorv1.DcIdentity{DnsHostname: "dc2.corp.example"}}}
		}
	}
	type sent struct {
		name   string
		code   connectorv1.ErrorCode
		mod    func(*connectorv1.ConnectorError)
		is     error
		resync bool
		check  func(*testing.T, error)
	}
	cases := []sent{
		{name: "unreachable", code: connectorv1.ErrorCode_ERROR_CODE_UNREACHABLE_DC, is: client.ErrUnreachableDC,
			mod: func(ce *connectorv1.ConnectorError) {
				ce.Details = &connectorv1.ConnectorError_Unreachable{Unreachable: &connectorv1.UnreachableDetails{
					Attempts: []*connectorv1.DcAttempt{{DnsHostname: "dc1.corp.example"}}}}
			}},
		{name: "throttled with retry_after", code: connectorv1.ErrorCode_ERROR_CODE_THROTTLED, is: client.ErrThrottled,
			mod: func(ce *connectorv1.ConnectorError) {
				ce.Details = &connectorv1.ConnectorError_Throttled{Throttled: &connectorv1.ThrottledDetails{RetryAfter: durationpb.New(42 * time.Second)}}
			},
			check: func(t *testing.T, err error) {
				var te *client.ThrottledError
				if !errors.As(err, &te) || te.RetryAfter != 42*time.Second {
					t.Fatalf("retry_after: %v", err)
				}
			}},
		{name: "throttled without retry_after", code: connectorv1.ErrorCode_ERROR_CODE_THROTTLED, is: client.ErrThrottled,
			check: func(t *testing.T, err error) {
				var te *client.ThrottledError
				if !errors.As(err, &te) || te.RetryAfter != 0 {
					t.Fatalf("retry_after: %v", err)
				}
			}},
		{name: "throttled with absurd retry_after is capped", code: connectorv1.ErrorCode_ERROR_CODE_THROTTLED, is: client.ErrThrottled,
			mod: func(ce *connectorv1.ConnectorError) {
				ce.Details = &connectorv1.ConnectorError_Throttled{Throttled: &connectorv1.ThrottledDetails{RetryAfter: durationpb.New(1000 * time.Hour)}}
			},
			check: func(t *testing.T, err error) {
				var te *client.ThrottledError
				if !errors.As(err, &te) || te.RetryAfter != client.MaxFeedRetryAfter {
					t.Fatalf("retry_after: %v", err)
				}
			}},
		{name: "secret attribute", code: connectorv1.ErrorCode_ERROR_CODE_SECRET_ATTRIBUTE, is: client.ErrSecretAttribute},
	}
	for r := connectorv1.ResyncReason_RESYNC_REASON_INVOCATION_ID_CHANGED; r <= connectorv1.ResyncReason_RESYNC_REASON_DELTA_TOKEN_EXPIRED; r++ {
		cases = append(cases, sent{name: "stale " + r.String(), code: connectorv1.ErrorCode_ERROR_CODE_STALE_COOKIE, mod: stale(r),
			is: client.ErrStaleCookie, resync: true,
			check: func(t *testing.T, err error) {
				var se *client.StaleCookieError
				if !errors.As(err, &se) || se.Reason != r {
					t.Fatalf("reason: %v", err)
				}
			}})
	}
	cases = append(cases, sent{name: "stale without details", code: connectorv1.ErrorCode_ERROR_CODE_STALE_COOKIE, is: client.ErrStaleCookie, resync: true})
	sentinels := []error{client.ErrStaleCookie, client.ErrUnreachableDC, client.ErrThrottled, client.ErrSecretAttribute}

	for _, tc := range cases {
		for _, where := range []string{"open", "first recv", "after a batch"} {
			t.Run(tc.name+"/"+where, func(t *testing.T) {
				f := &fakeFeed{}
				e := connErr(tc.code, tc.mod)
				switch where {
				case "open":
					f.openErr = e
				case "first recv":
					f.steps = []feedStep{{err: e}}
				default:
					f.steps = []feedStep{batch(1, false), {err: e}}
				}
				_, _, err := readFeed(newFeed(t, activeAD(), f, managedSet{feedNC: true}), feedReq())
				if !errors.Is(err, tc.is) {
					t.Fatalf("err %v, want %v", err, tc.is)
				}
				for _, s := range sentinels {
					if s != tc.is && errors.Is(err, s) {
						t.Fatalf("also matches %v", s)
					}
				}
				if client.ResyncRequired(err) != tc.resync {
					t.Fatalf("ResyncRequired = %v", !tc.resync)
				}
				if tc.check != nil {
					tc.check(t, err)
				}
				for _, s := range []string{err.Error(), fmt.Sprintf("%v %+v %#v", err, err, err)} {
					if strings.Contains(s, leak) || strings.Contains(s, "CN=") || strings.Contains(s, "secret detail") {
						t.Fatalf("error leaks a directory value: %s", s)
					}
				}
			})
		}
	}
}

func TestChangeFeedOtherErrorsDoNotRequireResync(t *testing.T) {
	for name, err := range map[string]error{
		"unmapped connector code": connErr(connectorv1.ErrorCode_ERROR_CODE_INSUFFICIENT_RIGHTS, nil),
		"transport":               status.Error(codes.Unavailable, "down"),
		"incomplete":              client.ErrFeedIncomplete,
	} {
		t.Run(name, func(t *testing.T) {
			f := &fakeFeed{openErr: err}
			_, _, got := readFeed(newFeed(t, activeAD(), f, managedSet{feedNC: true}), feedReq())
			if got == nil || client.ResyncRequired(got) {
				t.Fatalf("err %v", got)
			}
			if strings.Contains(got.Error(), "secret detail") {
				t.Fatalf("leaks the connector message: %v", got)
			}
		})
	}
}

func TestChangeFeedRefusedBeforeAnyConnectorCall(t *testing.T) {
	now := time.Now()
	notActive := activeAD()
	notActive.State = connection.StateDraft
	retired := activeAD()
	retired.RetiredAt = &now
	entra := activeAD()
	entra.Kind = connection.KindEntraTenant
	noIdentity := activeAD()
	noIdentity.DirectoryIdentity = ""
	otherID := activeAD()
	otherID.ID = "c0c0c0c0-0000-4000-8000-0000000000ff"

	good := managedSet{feedNC: true}
	for _, tc := range []struct {
		name    string
		conn    connection.Connection
		managed client.ManagedPartitions
		req     func(*client.FeedRequest)
		want    error
	}{
		{"draft connection", notActive, good, nil, client.ErrFeedConnection},
		{"retired connection", retired, good, nil, client.ErrFeedConnection},
		{"entra connection", entra, good, nil, client.ErrFeedConnection},
		{"no verified identity", noIdentity, good, nil, client.ErrFeedConnection},
		{"connection of another id", otherID, good, nil, client.ErrFeedConnection},
		{"partition outside the managed set", activeAD(), managedSet{"22222222-0000-4000-8000-000000000002": true}, nil, client.ErrFeedPartition},
		{"empty managed set", activeAD(), managedSet{}, nil, client.ErrFeedPartition},
		{"managed set unreadable", activeAD(), failingManaged{}, nil, client.ErrFeedPartition},
		{"partition not a guid", activeAD(), good, func(r *client.FeedRequest) { r.NC = "CN=Configuration,DC=corp" }, client.ErrFeedPartition},
		{"empty cookie state", activeAD(), good, func(r *client.FeedRequest) {
			r.Resume = &connectorv1.FeedCookie{ProviderKind: connectorv1.ProviderKind_PROVIDER_KIND_AD}
		}, client.ErrFeedRequest},
		{"entra cookie", activeAD(), good, func(r *client.FeedRequest) { r.Resume.ProviderKind = connectorv1.ProviderKind_PROVIDER_KIND_ENTRA }, client.ErrFeedRequest},
		{"wildcard attribute", activeAD(), good, func(r *client.FeedRequest) { r.Attributes = []string{"cn", "*"} }, client.ErrFeedRequest},
		{"plus attribute", activeAD(), good, func(r *client.FeedRequest) { r.Attributes = []string{"+"} }, client.ErrFeedRequest},
		{"empty attribute", activeAD(), good, func(r *client.FeedRequest) { r.Attributes = []string{""} }, client.ErrFeedRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeFeed{steps: []feedStep{batch(1, true)}}
			req := feedReq()
			req.Resume = cookie(0)
			if tc.req != nil {
				tc.req(&req)
			}
			got, _, err := readFeed(newFeed(t, tc.conn, f, tc.managed), req)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err %v, want %v", err, tc.want)
			}
			if f.calls.Load() != 0 || len(got) != 0 {
				t.Fatalf("the connector was called %d times", f.calls.Load())
			}
		})
	}
}

type failingManaged struct{}

func (failingManaged) Managed(context.Context, tenant.ID, connection.ID, string) (bool, error) {
	return false, errors.New("store down")
}

func TestChangeFeedRequestCarriesTheDirectoryIdentityAndPartition(t *testing.T) {
	f := &fakeFeed{steps: []feedStep{batch(1, true)}}
	req := feedReq()
	req.NC = strings.ToUpper(feedNC)
	req.Attributes = []string{"displayName", "member"}
	if _, _, err := readFeed(newFeed(t, activeAD(), f, managedSet{feedNC: true}), req); err != nil {
		t.Fatal(err)
	}
	cr := f.requests[0]
	if cr.GetConnection().GetConnectionId() != connUUID || cr.GetConnection().GetDirectoryIdentity().GetAdForest() == nil {
		t.Fatalf("connection: %v", cr.GetConnection())
	}
	if len(cr.GetPartition().GetAdNcGuid().GetValue()) != 16 || cr.GetPartition().GetAdNcGuid().GetValue()[0] != 0x11 {
		t.Fatalf("partition: %v", cr.GetPartition())
	}
	if len(cr.GetAttributes()) != 2 {
		t.Fatalf("attributes: %v", cr.GetAttributes())
	}
}

func TestNewChangeFeedReaderRequiresItsPorts(t *testing.T) {
	f := &fakeFeed{}
	if _, err := client.NewChangeFeedReader(nil, f, managedSet{}); err == nil {
		t.Fatal("no connections")
	}
	if _, err := client.NewChangeFeedReader(feedConns{}, nil, managedSet{}); !errors.Is(err, client.ErrNoFeedSource) {
		t.Fatal(err)
	}
	if _, err := client.NewChangeFeedReader(feedConns{}, f, nil); !errors.Is(err, client.ErrNoManagedSet) {
		t.Fatal(err)
	}
}
