package rights

import (
	"context"
	"errors"
	"fmt"
	"github.com/skenzeriq/activediq/internal/connector/write"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"
	grpccodes "google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/tier0"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	v1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

const secretDN = "CN=Secret Admin,OU=Tier0,DC=lab,DC=test"

type failingDir struct {
	ADDirectory
	err error
}

func (d failingDir) Read(ctx context.Context, ref dn.ObjectRef, attrs []string, o ad.ReadOptions) (*ad.Entry, error) {
	return nil, d.err
}

type fakeStream struct {
	grpc.ServerStream
	sent []*v1.VerifyConnectionResponse
}

func (f *fakeStream) Context() context.Context { return context.Background() }
func (f *fakeStream) Send(m *v1.VerifyConnectionResponse) error {
	f.sent = append(f.sent, m)
	return nil
}

func (w *world) handler(t *testing.T, ep *EpochState, dir ADDirectory) *VerifyHandler {
	t.Helper()
	w.setTokens()
	ref, _ := dn.ParseObjectRef(w.id.DN)
	if dir == nil {
		dir = w.f
	}
	snapshotHook = func(context.Context) (*tier0.ADSet, error) { return w.set, nil }
	t.Cleanup(func() { snapshotHook = nil })
	if ep == nil {
		d := t.TempDir()
		ep = NewEpochState(FileBaselineStore{filepath.Join(d, "baseline.json")}, FileRecordSink{filepath.Join(d, "records.log")}, nil)
	}
	gate, err := write.NewGateBook(nopBaseline{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewVerifyHandler(VerifyConfig{Dir: dir, Epoch: ep, Identity: ref, Directory: testDirectory(),
		Gate: gate, OnLocalRecordFailed: gate.CloseLocalRecordFailed})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

type nopBaseline struct{}

func (nopBaseline) Append(string, []write.Mark) error { return nil }

func connErr(t *testing.T, err error) *v1.ConnectorError {
	t.Helper()
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("not a status: %v", err)
	}
	for _, d := range st.Details() {
		if ce, ok := d.(*v1.ConnectorError); ok {
			return ce
		}
	}
	t.Fatalf("no ConnectorError detail: %v", err)
	return nil
}

func TestVerify_error_no_dn(t *testing.T) {
	w := newWorld(t)
	raw := fmt.Errorf("LDAP Result Code 50 \"Insufficient Access Rights\": 00002098: %s: %w", secretDN, ad.NewError(ad.CodeInsufficientRights))
	for _, e := range []error{raw, errors.New("some diagnostic for " + secretDN)} {
		st := &fakeStream{}
		err := w.handler(t, nil, failingDir{w.f, e}).VerifyConnection(context.Background(), request(w), st)
		if err == nil {
			t.Fatal("expected an error")
		}
		s, _ := status.FromError(err)
		all := s.Message() + err.Error() + fmt.Sprint(s.Proto())
		if strings.Contains(all, "Secret Admin") || strings.Contains(all, "DC=lab") || strings.Contains(all, "LDAP Result") {
			t.Fatalf("status leaks directory text: %q", all)
		}
		if len(st.sent) != 0 {
			t.Fatal("events sent before the failure")
		}
	}
}

func TestVerifyADFailureKinds(t *testing.T) {
	w := newWorld(t)
	for _, tc := range []struct {
		name string
		err  error
		code v1.ErrorCode
		grpc grpccodes.Code
	}{
		{"insufficient", ad.NewError(ad.CodeInsufficientRights), v1.ErrorCode_ERROR_CODE_INSUFFICIENT_RIGHTS, grpccodes.PermissionDenied},
		{"unreachable", ad.NewError(ad.CodeUnreachable), v1.ErrorCode_ERROR_CODE_UNREACHABLE_DC, grpccodes.Unavailable},
		{"bind", ad.NewError(ad.CodeBindFailed), v1.ErrorCode_ERROR_CODE_BIND_FAILED, grpccodes.Internal},
		{"not found", ad.NewError(ad.CodeObjectNotFound), v1.ErrorCode_ERROR_CODE_OBJECT_NOT_FOUND, grpccodes.NotFound},
		{"unclassified", errors.New("boom " + secretDN), v1.ErrorCode_ERROR_CODE_PROVIDER_FAILURE, grpccodes.Internal},
	} {
		err := w.handler(t, nil, failingDir{w.f, tc.err}).VerifyConnection(context.Background(), request(w), &fakeStream{})
		ce := connErr(t, err)
		if ce.Code != tc.code || status.Code(err) != tc.grpc {
			t.Errorf("%s: got %v / %v", tc.name, ce.Code, status.Code(err))
		}
		if ce.Code == v1.ErrorCode_ERROR_CODE_PROVIDER_FAILURE && tc.name != "unclassified" {
			t.Errorf("%s reported as PROVIDER_FAILURE", tc.name)
		}
	}
}

// A failed AD check inside a run (CHECK_OUTCOME_COULD_NOT_VERIFY) carries the AD code, not an Entra
// PROVIDER_FAILURE.
func TestConnectorErrorMapsADCodes(t *testing.T) {
	for code, want := range map[ad.Code]v1.ErrorCode{
		ad.CodeInsufficientRights: v1.ErrorCode_ERROR_CODE_INSUFFICIENT_RIGHTS,
		ad.CodeUnreachable:        v1.ErrorCode_ERROR_CODE_UNREACHABLE_DC,
		ad.CodeBindFailed:         v1.ErrorCode_ERROR_CODE_BIND_FAILED,
	} {
		ce := connectorError(fmt.Errorf("wrapped %s: %w", secretDN, ad.NewError(code)))
		if ce.Code != want || strings.Contains(ce.Message, "Entra") || strings.Contains(ce.Message, "Secret") {
			t.Errorf("%s: %v %q", code, ce.Code, ce.Message)
		}
	}
}

func TestVerifyMalformedVerificationID(t *testing.T) {
	w := newWorld(t)
	fx := newEpochFix(t)
	for _, vid := range []*v1.Guid{nil, {Value: []byte{1, 2, 3}}} {
		req := &v1.VerifyConnectionRequest{VerificationId: vid}
		st := &fakeStream{}
		err := w.handler(t, fx.state(), nil).VerifyConnection(context.Background(), req, st)
		if status.Code(err) != grpccodes.InvalidArgument || connErr(t, err).Code != v1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT {
			t.Fatalf("err %v", err)
		}
		if len(st.sent) != 0 {
			t.Fatal("events sent")
		}
	}
	for _, p := range []string{fx.store.Path, fx.sink.Path} {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s written: %v", filepath.Base(p), err)
		}
	}
}

func TestVerifyLocalRecordFailedMapsToLOCAL_RECORD_FAILED(t *testing.T) {
	w := newWorld(t)
	d := t.TempDir()
	// The records sink cannot be written: the missing-baseline record fails.
	ep := NewEpochState(FileBaselineStore{filepath.Join(d, "baseline.json")}, FileRecordSink{filepath.Join(d, "no-such-dir", "records.log")}, nil)
	h := w.handler(t, ep, nil)
	closed := false
	h.onLRF = func(string) { closed = true }
	st := &fakeStream{}
	err := h.VerifyConnection(context.Background(), request(w), st)
	if ce := connErr(t, err); ce.Code != v1.ErrorCode_ERROR_CODE_LOCAL_RECORD_FAILED || ce.Retry != v1.RetryAdvice_RETRY_ADVICE_NEVER {
		t.Fatalf("%v", ce)
	}
	if !closed {
		t.Fatal("gate hook not called")
	}
	for _, m := range st.sent {
		if m.GetCompleted() != nil {
			t.Fatal("completed sent")
		}
	}
}

func TestVerifyHappyPath(t *testing.T) {
	w := newWorld(t)
	st := &fakeStream{}
	if err := w.handler(t, nil, nil).VerifyConnection(context.Background(), request(w), st); err != nil {
		t.Fatal(err)
	}
	if len(st.sent) == 0 || st.sent[len(st.sent)-1].GetCompleted() == nil {
		t.Fatal("no completed")
	}
}

func TestNewVerifyHandlerFailsClosedWithoutHook(t *testing.T) {
	w := newWorld(t)
	h := w.handler(t, nil, nil)
	gate, _ := write.NewGateBook(nopBaseline{}, nil)
	base := VerifyConfig{Dir: h.dir, Epoch: h.epoch, Identity: h.identity, Directory: h.directory, Gate: gate,
		OnLocalRecordFailed: gate.CloseLocalRecordFailed}
	for name, mut := range map[string]func(*VerifyConfig){
		"hook":  func(c *VerifyConfig) { c.OnLocalRecordFailed = nil },
		"gate":  func(c *VerifyConfig) { c.Gate = nil },
		"dir":   func(c *VerifyConfig) { c.Dir = nil },
		"epoch": func(c *VerifyConfig) { c.Epoch = nil },
	} {
		c := base
		mut(&c)
		if got, err := NewVerifyHandler(c); err == nil || got != nil {
			t.Fatalf("%s nil: constructed", name)
		}
	}
	// A zero-value handler refuses calls instead of streaming without a gate feed.
	err := (&VerifyHandler{}).VerifyConnection(context.Background(), request(w), &fakeStream{})
	if ce := connErr(t, err); ce.Code != v1.ErrorCode_ERROR_CODE_PROVIDER_FAILURE {
		t.Fatalf("%v", ce)
	}
}

func TestVerifyFeedsGateBookAndLRFClosesIt(t *testing.T) {
	w := newWorld(t)
	h := w.handler(t, nil, nil)
	st := &fakeStream{}
	if err := h.VerifyConnection(context.Background(), request(w), st); err != nil {
		t.Fatal(err)
	}
	if d := h.gate.Check("conn-1", true, nil); !d.Open || len(d.VerificationID) == 0 {
		t.Fatalf("Complete was not fed or gate not open on PASS: %+v", d)
	}
	if d := h.gate.Check("other", true, nil); len(d.VerificationID) != 0 {
		t.Fatal("another connection got the run")
	}
	// A later LOCAL_RECORD_FAILED closes the prior epoch's gate through the mandatory hook.
	d := t.TempDir()
	h.epoch = NewEpochState(FileBaselineStore{filepath.Join(d, "baseline.json")}, FileRecordSink{filepath.Join(d, "no-dir", "records.log")}, nil)
	err := h.VerifyConnection(context.Background(), request(w), &fakeStream{})
	if ce := connErr(t, err); ce.Code != v1.ErrorCode_ERROR_CODE_LOCAL_RECORD_FAILED {
		t.Fatalf("%v", ce)
	}
	after := h.gate.Check("conn-1", true, nil)
	if after.Open || after.State != v1.WriteGateState_WRITE_GATE_STATE_LOCAL_RECORD_FAILED {
		t.Fatalf("gate still open after LOCAL_RECORD_FAILED: %+v", after)
	}
}

func TestVerifyRequiresConnectionID(t *testing.T) {
	w := newWorld(t)
	req := request(w)
	req.Connection = nil
	err := w.handler(t, nil, nil).VerifyConnection(context.Background(), req, &fakeStream{})
	if ce := connErr(t, err); ce.Code != v1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT {
		t.Fatalf("%v", ce)
	}
}

func TestVerifyLogsCodeOnly(t *testing.T) {
	w := newWorld(t)
	raw := fmt.Errorf("LDAP Result Code 50: %s: %w", secretDN, ad.NewError(ad.CodeInsufficientRights))
	h := w.handler(t, nil, failingDir{w.f, raw})
	var buf strings.Builder
	h.log = slog.New(slog.NewTextHandler(&buf, nil))
	if err := h.VerifyConnection(context.Background(), request(w), &fakeStream{}); err == nil {
		t.Fatal("expected an error")
	}
	out := buf.String()
	if !strings.Contains(out, string(ad.CodeInsufficientRights)) {
		t.Fatalf("code not logged: %q", out)
	}
	for _, bad := range []string{secretDN, "Secret Admin", "LDAP Result", "00002098"} {
		if strings.Contains(out, bad) {
			t.Fatalf("log leaks %q: %q", bad, out)
		}
	}
}
