package replstatus

// Handler tests over scripted DC readers (CC-REPL-01..03, -07, -10, -11; CC-REPLXML-02/03; contract
// §5.6 rules 1 to 7). FAKES: the DC readers are scripts, so these prove the handler's mapping,
// coverage and bounds, not what a real DC returns. The wire shape is proved in ad/replread_test.go
// (fault-injection proxy) and the Samba answers in lab_test.go. No Windows behaviour is claimed.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/write"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

var testIdentity = &connectorv1.DirectoryIdentity{Identity: &connectorv1.DirectoryIdentity_EntraTenantId{EntraTenantId: "lab"}}

func dcID(n byte) *connectorv1.DcIdentity {
	g := make([]byte, 16)
	g[0] = n
	return &connectorv1.DcIdentity{DsaGuid: &connectorv1.Guid{Value: g}, DnsHostname: fmt.Sprintf("dc%d.lab.test", n)}
}

type reader func(attrs []ad.ReplAttr) (ad.ReplRead, error)

func (r reader) ReadReplication(_ context.Context, attrs []ad.ReplAttr) (ad.ReplRead, error) {
	return r(attrs)
}

type fakeSrc struct {
	dcs      []DC
	listErr  error
	readers  map[byte]reader
	opens    atomic.Int32
	reads    atomic.Int32
	inFlight atomic.Int32
	maxIn    atomic.Int32
}

func (f *fakeSrc) Identity() *connectorv1.DirectoryIdentity { return testIdentity }
func (f *fakeSrc) DCs(context.Context) ([]DC, error)        { return f.dcs, f.listErr }
func (f *fakeSrc) Open(_ context.Context, d DC) (DCReader, func(), error) {
	f.opens.Add(1)
	r, ok := f.readers[d.Identity.DsaGuid.Value[0]]
	if !ok {
		return nil, nil, errors.New("dial: connection refused")
	}
	return reader(func(a []ad.ReplAttr) (ad.ReplRead, error) {
		f.reads.Add(1)
		n := f.inFlight.Add(1)
		defer f.inFlight.Add(-1)
		for {
			m := f.maxIn.Load()
			if n <= m || f.maxIn.CompareAndSwap(m, n) {
				break
			}
		}
		return r(a)
	}), func() {}, nil
}

type collector struct {
	mu      sync.Mutex
	results []*connectorv1.ReplicationDcResult
	summary *connectorv1.ReplicationSummary
	order   []string
}

func (c *collector) Send(r *connectorv1.ReadReplicationStatusResponse) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if r.GetResult() != nil {
		c.results = append(c.results, r.GetResult())
		c.order = append(c.order, "result")
	}
	if r.GetSummary() != nil {
		c.summary = r.GetSummary()
		c.order = append(c.order, "summary")
	}
	return nil
}

func newReq(mut func(*connectorv1.ReadReplicationStatusRequest)) *connectorv1.ReadReplicationStatusRequest {
	r := &connectorv1.ReadReplicationStatusRequest{
		Connection: &connectorv1.ConnectionRef{ConnectionId: "c1", DirectoryIdentity: testIdentity},
		Scope:      connectorv1.PerDcScope_PER_DC_SCOPE_ALL,
	}
	if mut != nil {
		mut(r)
	}
	return r
}

func run(t *testing.T, src *fakeSrc, req *connectorv1.ReadReplicationStatusRequest) (*collector, error) {
	t.Helper()
	h, err := New(src)
	if err != nil {
		t.Fatal(err)
	}
	c := &collector{}
	return c, h.ReadReplicationStatus(context.Background(), req, c)
}

func code(err error) connectorv1.ErrorCode {
	var r *write.Refusal
	if errors.As(err, &r) {
		return r.Err.GetCode()
	}
	return connectorv1.ErrorCode_ERROR_CODE_UNSPECIFIED
}

func file(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "ad", "replxml", "testdata", rel))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func vals(b ...[]byte) ad.ReplValues { return ad.ReplValues{Present: true, Values: b} }

func outcomes(st *connectorv1.ReplicationState) map[connectorv1.ReplicationAttribute]*connectorv1.AttributeOutcome {
	m := map[connectorv1.ReplicationAttribute]*connectorv1.AttributeOutcome{}
	for _, o := range st.GetAttributes() {
		m[o.GetAttribute()] = o
	}
	return m
}

const partGUID = "4f7a1c2e-0b3d-4c5e-8a9f-1234567890ab"

// CC-REPL-01: one DC, summary 1/1 COMPLETE, every requested attribute has an outcome, results
// precede the summary.
func TestSingleDCComplete(t *testing.T) {
	src := &fakeSrc{dcs: []DC{{Identity: dcID(1)}}, readers: map[byte]reader{1: func([]ad.ReplAttr) (ad.ReplRead, error) {
		return ad.ReplRead{
			ad.ReplInboundNeighbors: vals(file(t, "valid/neighbor.xml"), file(t, "valid/neighbor_failing.xml")),
			ad.ReplPendingOps:       vals(file(t, "valid/pending_op.xml")),
			ad.ReplLinkFailures:     vals(file(t, "valid/failure.xml")),
		}, nil
	}}}
	c, err := run(t, src, newReq(nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.results) != 1 || c.summary.GetDcsInScope() != 1 || c.summary.GetDcsAnswered() != 1 || c.summary.GetCoverage() != connectorv1.Coverage_COVERAGE_COMPLETE {
		t.Fatalf("results=%d summary=%v", len(c.results), c.summary)
	}
	if c.order[len(c.order)-1] != "summary" {
		t.Errorf("order %v", c.order)
	}
	st := c.results[0].GetState()
	o := outcomes(st)
	if len(st.Attributes) != 4 || len(o) != 4 {
		t.Fatalf("outcomes %v", st.Attributes)
	}
	for a, want := range map[connectorv1.ReplicationAttribute]connectorv1.OutcomeKind{
		connectorv1.ReplicationAttribute_REPLICATION_ATTRIBUTE_INBOUND_NEIGHBORS:   connectorv1.OutcomeKind_RETURNED,
		connectorv1.ReplicationAttribute_REPLICATION_ATTRIBUTE_PENDING_OPS:         connectorv1.OutcomeKind_RETURNED,
		connectorv1.ReplicationAttribute_REPLICATION_ATTRIBUTE_LINK_FAILURES:       connectorv1.OutcomeKind_RETURNED,
		connectorv1.ReplicationAttribute_REPLICATION_ATTRIBUTE_CONNECTION_FAILURES: connectorv1.OutcomeKind_NOT_RETURNED,
	} {
		if o[a].GetKind() != want || o[a].GetDetailCode() != "" {
			t.Errorf("%v: %v", a, o[a])
		}
	}
	if len(st.Neighbors) != 2 || len(st.PendingOps) != 1 || len(st.LinkFailures) == 0 || len(st.ConnectionFailures) != 0 {
		t.Fatalf("state %v", st)
	}
	n0, n1 := st.Neighbors[0], st.Neighbors[1]
	if n0.Partition == nil || len(n0.Partition.Value) != 16 || n0.Partition.Value[0] != 0x4f || n0.Partition.Value[1] != 0x7a {
		t.Errorf("partition not in RFC 4122 order: %x", n0.GetPartition().GetValue())
	}
	// rule 10: ZERO is "never", unset is "not reported", a count of 0 is a fact only if reported.
	if n0.LastSuccess.GetAt() == nil || n0.ConsecutiveFailures == nil || *n0.ConsecutiveFailures != 0 {
		t.Errorf("neighbor 0: %v", n0)
	}
	if n1.LastSuccess.GetSentinel() != connectorv1.TimeSentinel_TIME_SENTINEL_ZERO || n1.GetConsecutiveFailures() != 14 || n1.GetLastResultWin32() != 1722 {
		t.Errorf("neighbor 1: %v", n1)
	}
	if n1.Flags != nil || n1.SourceDsa == nil {
		t.Errorf("neighbor 1 flags must be unset, not 0: %v", n1)
	}
}

// CC-REPL-02: nothing returned is a result with four NOT_RETURNED, never an error, never an empty
// RETURNED list; an attribute present with no values is also NOT_RETURNED.
func TestNotReturnedIsNeverHealthy(t *testing.T) {
	src := &fakeSrc{dcs: []DC{{Identity: dcID(1)}}, readers: map[byte]reader{1: func([]ad.ReplAttr) (ad.ReplRead, error) {
		return ad.ReplRead{ad.ReplPendingOps: {Present: true}}, nil
	}}}
	c, err := run(t, src, newReq(nil))
	if err != nil {
		t.Fatal(err)
	}
	st := c.results[0].GetState()
	if st == nil || len(st.Attributes) != 4 {
		t.Fatalf("%v", c.results[0])
	}
	for _, o := range st.Attributes {
		if o.Kind != connectorv1.OutcomeKind_NOT_RETURNED {
			t.Errorf("%v", o)
		}
	}
	if len(st.Neighbors)+len(st.PendingOps)+len(st.ConnectionFailures)+len(st.LinkFailures) != 0 {
		t.Errorf("facts invented: %v", st)
	}
	if c.summary.Coverage != connectorv1.Coverage_COVERAGE_COMPLETE {
		t.Errorf("a DC that answered with nothing is still answered: %v", c.summary)
	}
}

// CC-REPL-03 (fault-injected; the two-DC lab with a stopped DC is the lab-tier run): PARTIAL, the
// stopped DC is a result with an error and is counted in dcs_in_scope, the other DC is read.
func TestStoppedDCIsPartialAndCounted(t *testing.T) {
	src := &fakeSrc{dcs: []DC{{Identity: dcID(1)}, {Identity: dcID(2)}}, readers: map[byte]reader{1: func([]ad.ReplAttr) (ad.ReplRead, error) {
		return ad.ReplRead{ad.ReplInboundNeighbors: vals(file(t, "valid/neighbor.xml"))}, nil
	}}}
	c, err := run(t, src, newReq(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.summary.DcsInScope != 2 || c.summary.DcsAnswered != 1 || c.summary.Coverage != connectorv1.Coverage_COVERAGE_PARTIAL {
		t.Fatalf("summary %v", c.summary)
	}
	if len(c.results) != 2 {
		t.Fatalf("results %d", len(c.results))
	}
	for _, r := range c.results {
		switch r.Dc.DsaGuid.Value[0] {
		case 1:
			if r.GetState() == nil {
				t.Errorf("dc1: %v", r)
			}
		case 2:
			e := r.GetError()
			if e == nil || e.Code != connectorv1.ErrorCode_ERROR_CODE_UNREACHABLE_DC || e.Dc == nil || bytes.Contains([]byte(e.Message), []byte("refused")) {
				t.Errorf("dc2: %v", r)
			}
		}
	}
}

// A DC whose read fails after it opened is an error result as well.
func TestReadFailureIsAnErrorResult(t *testing.T) {
	src := &fakeSrc{dcs: []DC{{Identity: dcID(1)}}, readers: map[byte]reader{1: func([]ad.ReplAttr) (ad.ReplRead, error) {
		return nil, errors.New("connection reset by peer 10.1.2.3")
	}}}
	c, err := run(t, src, newReq(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.summary.DcsAnswered != 0 || c.summary.Coverage != connectorv1.Coverage_COVERAGE_PARTIAL || c.results[0].GetError() == nil {
		t.Fatalf("%v %v", c.summary, c.results)
	}
	if bytes.Contains([]byte(prototext.Format(c.results[0])), []byte("10.1.2.3")) {
		t.Error("error text from the transport leaked")
	}
}

// CC-REPL-07: more than 100 DCs is LIMIT_EXCEEDED before any directory call; 100 is fine. An RODC
// does not count against WRITABLE scope.
func TestMoreThanHundredDCs(t *testing.T) {
	mk := func(n int, ro func(int) bool) *fakeSrc {
		src := &fakeSrc{readers: map[byte]reader{}}
		for i := 0; i < n; i++ {
			g := make([]byte, 16)
			g[0], g[1] = byte(i), byte(i>>8)
			src.dcs = append(src.dcs, DC{Identity: &connectorv1.DcIdentity{DsaGuid: &connectorv1.Guid{Value: g}}, ReadOnly: ro(i)})
		}
		return src
	}
	src := mk(101, func(int) bool { return false })
	c, err := run(t, src, newReq(nil))
	if code(err) != connectorv1.ErrorCode_ERROR_CODE_LIMIT_EXCEEDED || len(c.results) != 0 || c.summary != nil {
		t.Fatalf("err=%v results=%d", err, len(c.results))
	}
	if src.opens.Load() != 0 || src.reads.Load() != 0 {
		t.Errorf("directory touched: %d opens, %d reads", src.opens.Load(), src.reads.Load())
	}
	// 101 DCs of which one is an RODC: WRITABLE has 100 in scope and is allowed; ALL is not.
	src = mk(101, func(i int) bool { return i == 100 })
	if _, err := run(t, src, newReq(func(r *connectorv1.ReadReplicationStatusRequest) {
		r.Scope = connectorv1.PerDcScope_PER_DC_SCOPE_WRITABLE
	})); err != nil {
		t.Errorf("100 writable DCs: %v", err)
	}
	if _, err := run(t, mk(101, func(i int) bool { return i == 100 }), newReq(nil)); code(err) != connectorv1.ErrorCode_ERROR_CODE_LIMIT_EXCEEDED {
		t.Errorf("ALL with 101: %v", err)
	}
}

// Zero DCs in scope must not read as "complete".
func TestNoDCInScopeIsAnError(t *testing.T) {
	src := &fakeSrc{dcs: []DC{{Identity: dcID(1), ReadOnly: true}}}
	c, err := run(t, src, newReq(func(r *connectorv1.ReadReplicationStatusRequest) {
		r.Scope = connectorv1.PerDcScope_PER_DC_SCOPE_WRITABLE
	}))
	if code(err) != connectorv1.ErrorCode_ERROR_CODE_UNREACHABLE_DC || c.summary != nil {
		t.Fatalf("%v %v", err, c.summary)
	}
}

// CC-REPL-11: an unspecified or unknown attribute, an unspecified scope, a malformed partition and
// a foreign connection are INVALID_ARGUMENT / mismatch before any directory call. (A DN-shaped
// partition is not representable: the field is a Guid, and a Guid that is not 16 bytes is refused.)
func TestInvalidRequests(t *testing.T) {
	for name, mut := range map[string]func(*connectorv1.ReadReplicationStatusRequest){
		"unspecified attribute": func(r *connectorv1.ReadReplicationStatusRequest) {
			r.Attributes = []connectorv1.ReplicationAttribute{connectorv1.ReplicationAttribute_REPLICATION_ATTRIBUTE_UNSPECIFIED}
		},
		"unknown attribute": func(r *connectorv1.ReadReplicationStatusRequest) {
			r.Attributes = []connectorv1.ReplicationAttribute{connectorv1.ReplicationAttribute_REPLICATION_ATTRIBUTE_PENDING_OPS, 99}
		},
		"unspecified scope": func(r *connectorv1.ReadReplicationStatusRequest) {
			r.Scope = connectorv1.PerDcScope_PER_DC_SCOPE_UNSPECIFIED
		},
		"dn as partition": func(r *connectorv1.ReadReplicationStatusRequest) {
			r.Partitions = []*connectorv1.Guid{{Value: []byte("DC=lab,DC=test")}}
		},
		"nil partition":    func(r *connectorv1.ReadReplicationStatusRequest) { r.Partitions = []*connectorv1.Guid{nil} },
		"no connection id": func(r *connectorv1.ReadReplicationStatusRequest) { r.Connection.ConnectionId = "" },
	} {
		t.Run(name, func(t *testing.T) {
			src := &fakeSrc{dcs: []DC{{Identity: dcID(1)}}}
			c, err := run(t, src, newReq(mut))
			if code(err) != connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT || len(c.results) != 0 || src.opens.Load() != 0 {
				t.Fatalf("%v", err)
			}
		})
	}
	src := &fakeSrc{dcs: []DC{{Identity: dcID(1)}}}
	_, err := run(t, src, newReq(func(r *connectorv1.ReadReplicationStatusRequest) {
		r.Connection.DirectoryIdentity = &connectorv1.DirectoryIdentity{Identity: &connectorv1.DirectoryIdentity_EntraTenantId{EntraTenantId: "other"}}
	}))
	if code(err) != connectorv1.ErrorCode_ERROR_CODE_DIRECTORY_IDENTITY_MISMATCH || src.opens.Load() != 0 {
		t.Errorf("identity: %v", err)
	}
}

// The attributes asked for are the attributes read, once each, in enum order.
func TestRequestedAttributesAreDeduplicated(t *testing.T) {
	var asked []ad.ReplAttr
	src := &fakeSrc{dcs: []DC{{Identity: dcID(1)}}, readers: map[byte]reader{1: func(a []ad.ReplAttr) (ad.ReplRead, error) {
		asked = a
		return ad.ReplRead{}, nil
	}}}
	c, err := run(t, src, newReq(func(r *connectorv1.ReadReplicationStatusRequest) {
		r.Attributes = []connectorv1.ReplicationAttribute{
			connectorv1.ReplicationAttribute_REPLICATION_ATTRIBUTE_LINK_FAILURES,
			connectorv1.ReplicationAttribute_REPLICATION_ATTRIBUTE_PENDING_OPS,
			connectorv1.ReplicationAttribute_REPLICATION_ATTRIBUTE_LINK_FAILURES,
		}
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(asked) != 2 || asked[0] != ad.ReplPendingOps || asked[1] != ad.ReplLinkFailures || len(c.results[0].GetState().Attributes) != 2 {
		t.Fatalf("asked %v, outcomes %v", asked, c.results[0].GetState().Attributes)
	}
}

// CC-REPLXML-02 (fault-injected DC answers): a hostile value fails that attribute on that DC with
// the decoder's fixed code; the other attributes still decode; the hostile text is in neither the
// response nor a log line.
func TestHostileXMLIsDecodeFailedAndNeverLeaks(t *testing.T) {
	var logs bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(old)

	for _, tc := range []struct {
		file, code string
		marker     string
	}{
		{"hostile/billion_laughs.xml", "forbidden_directive", "lolz"},
		{"hostile/external_entity_file.xml", "forbidden_directive", "/etc/passwd"},
		{"hostile/oversize_64k_plus_1.xml", "too_large", "xxxxxxxx"},
		{"hostile/utf16_bom.xml", "bad_encoding", ""},
	} {
		t.Run(tc.file, func(t *testing.T) {
			bad := file(t, tc.file)
			src := &fakeSrc{dcs: []DC{{Identity: dcID(1)}}, readers: map[byte]reader{1: func([]ad.ReplAttr) (ad.ReplRead, error) {
				return ad.ReplRead{
					ad.ReplInboundNeighbors: vals(file(t, "valid/neighbor.xml"), bad), // one bad value fails the attribute
					ad.ReplPendingOps:       vals(file(t, "valid/pending_op.xml")),
				}, nil
			}}}
			c, err := run(t, src, newReq(nil))
			if err != nil {
				t.Fatal(err)
			}
			st := c.results[0].GetState()
			o := outcomes(st)[connectorv1.ReplicationAttribute_REPLICATION_ATTRIBUTE_INBOUND_NEIGHBORS]
			if o.Kind != connectorv1.OutcomeKind_DECODE_FAILED || o.DetailCode != tc.code {
				t.Fatalf("outcome %v", o)
			}
			if len(st.Neighbors) != 0 {
				t.Errorf("a partial list of the failed attribute survived: %d", len(st.Neighbors))
			}
			if outcomes(st)[connectorv1.ReplicationAttribute_REPLICATION_ATTRIBUTE_PENDING_OPS].Kind != connectorv1.OutcomeKind_RETURNED || len(st.PendingOps) != 1 {
				t.Errorf("an unrelated attribute was lost: %v", st.PendingOps)
			}
			wire, _ := proto.Marshal(c.results[0])
			for _, hay := range [][]byte{wire, []byte(prototext.Format(c.results[0])), logs.Bytes()} {
				if tc.marker != "" && bytes.Contains(hay, []byte(tc.marker)) {
					t.Errorf("hostile text %q reached the response or a log", tc.marker)
				}
			}
			if c.summary.Coverage != connectorv1.Coverage_COVERAGE_COMPLETE {
				t.Errorf("a decode failure does not make the DC unanswered: %v", c.summary)
			}
		})
	}
}

// The 8 MiB per DC per call budget (X2) spans the four attributes.
func TestPerDCByteBudget(t *testing.T) {
	big := bytes.Repeat([]byte(" "), 60<<10)
	v := append([]byte("<DS_REPL_KCC_DSA_FAILURE></DS_REPL_KCC_DSA_FAILURE>"), big...)
	many := make([][]byte, 150) // 150 x ~60 KiB > 8 MiB
	for i := range many {
		many[i] = v
	}
	src := &fakeSrc{dcs: []DC{{Identity: dcID(1)}}, readers: map[byte]reader{1: func([]ad.ReplAttr) (ad.ReplRead, error) {
		return ad.ReplRead{ad.ReplLinkFailures: vals(many...)}, nil
	}}}
	c, err := run(t, src, newReq(nil))
	if err != nil {
		t.Fatal(err)
	}
	o := outcomes(c.results[0].GetState())[connectorv1.ReplicationAttribute_REPLICATION_ATTRIBUTE_LINK_FAILURES]
	if o.Kind != connectorv1.OutcomeKind_DECODE_FAILED || o.DetailCode == "" {
		t.Fatalf("%v", o)
	}
}

// Rule 5 and 6: an incomplete range is DECODE_FAILED / RANGE_INCOMPLETE; a refused attribute is
// PERMISSION_DENIED for that attribute; the summary is still COMPLETE for a DC that answered.
func TestRangeIncompleteAndPermissionDenied(t *testing.T) {
	src := &fakeSrc{dcs: []DC{{Identity: dcID(1)}}, readers: map[byte]reader{1: func([]ad.ReplAttr) (ad.ReplRead, error) {
		return ad.ReplRead{
			ad.ReplInboundNeighbors:   {Present: true, RangeIncomplete: true, Values: [][]byte{file(t, "valid/neighbor.xml")}},
			ad.ReplPendingOps:         {Denied: true},
			ad.ReplConnectionFailures: vals(file(t, "valid/failure.xml")),
		}, nil
	}}}
	c, err := run(t, src, newReq(nil))
	if err != nil {
		t.Fatal(err)
	}
	st := c.results[0].GetState()
	o := outcomes(st)
	if k := o[connectorv1.ReplicationAttribute_REPLICATION_ATTRIBUTE_INBOUND_NEIGHBORS]; k.Kind != connectorv1.OutcomeKind_DECODE_FAILED || k.DetailCode != "RANGE_INCOMPLETE" {
		t.Errorf("%v", k)
	}
	if o[connectorv1.ReplicationAttribute_REPLICATION_ATTRIBUTE_PENDING_OPS].Kind != connectorv1.OutcomeKind_PERMISSION_DENIED {
		t.Errorf("%v", o)
	}
	if len(st.Neighbors) != 0 || len(st.ConnectionFailures) != 1 || c.summary.Coverage != connectorv1.Coverage_COVERAGE_COMPLETE {
		t.Errorf("%v %v", st, c.summary)
	}
}

// Partitions restrict neighbours and pending ops by NC GUID; an item the DC gave no partition is
// left out rather than assumed to match.
func TestPartitionFilter(t *testing.T) {
	want := []byte{0x4f, 0x7a, 0x1c, 0x2e, 0x0b, 0x3d, 0x4c, 0x5e, 0x8a, 0x9f, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab}
	other := bytes.Repeat([]byte{9}, 16)
	src := &fakeSrc{dcs: []DC{{Identity: dcID(1)}}, readers: map[byte]reader{1: func([]ad.ReplAttr) (ad.ReplRead, error) {
		return ad.ReplRead{
			ad.ReplInboundNeighbors: vals(file(t, "valid/neighbor.xml"), file(t, "valid/neighbor_failing.xml")),
		}, nil
	}}}
	for _, tc := range []struct {
		part []byte
		n    int
	}{{want, 2}, {other, 0}} {
		c, err := run(t, src, newReq(func(r *connectorv1.ReadReplicationStatusRequest) {
			r.Partitions = []*connectorv1.Guid{{Value: tc.part}}
		}))
		if err != nil {
			t.Fatal(err)
		}
		if got := len(c.results[0].GetState().Neighbors); got != tc.n {
			t.Errorf("partition %x: %d neighbours, want %d", tc.part, got, tc.n)
		}
	}
}

// CC-REPL-08 shape: the fan-out never exceeds the requested concurrency, and the connector's cap
// is not raised by a larger request.
func TestConcurrencyIsBounded(t *testing.T) {
	for _, tc := range []struct {
		ask uint32
		max int32
	}{{1, 1}, {2, 2}, {0, DefaultConcurrency}, {1000, DefaultConcurrency}} {
		release := make(chan struct{})
		src := &fakeSrc{readers: map[byte]reader{}}
		for i := byte(1); i <= 12; i++ {
			src.dcs = append(src.dcs, DC{Identity: dcID(i)})
			src.readers[i] = func([]ad.ReplAttr) (ad.ReplRead, error) {
				<-release
				return ad.ReplRead{}, nil
			}
		}
		done := make(chan error)
		go func() {
			_, err := run(t, src, newReq(func(r *connectorv1.ReadReplicationStatusRequest) { r.MaxConcurrency = tc.ask }))
			done <- err
		}()
		for i := 0; i < 2000 && src.inFlight.Load() < tc.max; i++ { // let the pool fill to its cap
			time.Sleep(time.Millisecond)
		}
		time.Sleep(20 * time.Millisecond) // and give an over-cap worker the chance to show itself
		close(release)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if got := src.maxIn.Load(); got != tc.max {
			t.Errorf("ask %d: %d in flight, want exactly the cap %d", tc.ask, got, tc.max)
		}
	}
}

// CC-REPL-10: an Entra connection has no replication; its provider does not serve the RPC (the
// generated default answers Unimplemented, which the transports map to CAPABILITY_UNSUPPORTED,
// contract §7) and its Describe row says UNSUPPORTED.
func TestEntraIsUnsupported(t *testing.T) {
	var s connectorv1.ConnectorServer = connectorv1.UnimplementedConnectorServer{}
	if err := s.ReadReplicationStatus(&connectorv1.ReadReplicationStatusRequest{}, nil); status.Code(err) != codes.Unimplemented {
		t.Errorf("%v", err)
	}
	row := UnsupportedCapability()
	if row.Operation != connectorv1.Operation_OPERATION_READ_REPLICATION_STATUS || row.State != connectorv1.SupportState_SUPPORT_STATE_UNSUPPORTED || row.Reason == "" {
		t.Errorf("%v", row)
	}
}

// Rule 7: SUPPORTED for AD with a reachable DC, UNVERIFIED with a reason for Samba, UNSUPPORTED
// with none.
func TestCapabilityRow(t *testing.T) {
	for _, tc := range []struct {
		n     int
		samba bool
		want  connectorv1.SupportState
		why   bool
	}{
		{1, false, connectorv1.SupportState_SUPPORT_STATE_SUPPORTED, false},
		{1, true, connectorv1.SupportState_SUPPORT_STATE_UNVERIFIED, true},
		{0, false, connectorv1.SupportState_SUPPORT_STATE_UNSUPPORTED, true},
	} {
		r := Capability(tc.n, tc.samba)
		if r.Operation != connectorv1.Operation_OPERATION_READ_REPLICATION_STATUS || r.State != tc.want || (r.Reason != "") != tc.why {
			t.Errorf("%+v: %v", tc, r)
		}
	}
}
