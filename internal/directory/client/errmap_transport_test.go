package client_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/authz/authztest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// leakDesc is the free text a connector (or Go's net package on the connector host) puts in a status
// description: a DC name, an IP and a DN.
const leakDesc = "dial tcp 10.20.30.40:636: dc1.corp.example unreachable bind CN=Admin,OU=Tier0,DC=corp,DC=example"

var leaks = []string{"dc1", "corp.example", "10.20.30.40", "CN=Admin", "OU=Tier0", "dial tcp"}

func noLeak(t *testing.T, err error) {
	t.Helper()
	for _, form := range []string{err.Error(), fmt.Sprintf("%v", err), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err), fmt.Sprintf("%s", err)} {
		for _, l := range leaks {
			if strings.Contains(form, l) {
				t.Fatalf("error text %q contains %q", form, l)
			}
		}
	}
	for u := errors.Unwrap(err); u != nil; u = errors.Unwrap(u) {
		noLeak(t, u)
	}
}

// T-1261 acceptance 1: a status error without a ConnectorError detail reaches the caller as a
// TransportError that carries the code and nothing of the description.
func TestFromStatusDropsDescription(t *testing.T) {
	for _, code := range []codes.Code{codes.Unavailable, codes.Internal, codes.Unknown, codes.PermissionDenied} {
		err := client.FromStatus(status.Error(code, leakDesc))
		noLeak(t, err)
		var te *client.TransportError
		if !errors.As(err, &te) || te.Code != code {
			t.Fatalf("code %v: got %#v, want a TransportError with the code", code, err)
		}
		wrapped := fmt.Errorf("client: read: %w", err)
		noLeak(t, wrapped)
		if !errors.As(wrapped, &te) || te.Code != code {
			t.Fatalf("code %v lost through wrapping", code)
		}
	}
}

func TestTransportErrorRetryable(t *testing.T) {
	for code, want := range map[codes.Code]bool{
		codes.Unavailable: true, codes.ResourceExhausted: true, codes.Aborted: true,
		codes.Internal: false, codes.PermissionDenied: false, codes.InvalidArgument: false, codes.Unknown: false,
	} {
		if got := (&client.TransportError{Code: code}).Retryable(); got != want {
			t.Errorf("%v: Retryable = %v, want %v", code, got, want)
		}
	}
}

// A ConnectorError detail still wins, and an already typed error passes through.
func TestFromStatusKeepsTypedErrors(t *testing.T) {
	st, err := status.New(codes.Unavailable, leakDesc).WithDetails(&connectorv1.ConnectorError{Code: connectorv1.ErrorCode_ERROR_CODE_UNREACHABLE_DC})
	if err != nil {
		t.Fatal(err)
	}
	var re *client.RemoteError
	if !errors.As(client.FromStatus(st.Err()), &re) || re.Err.GetCode() != connectorv1.ErrorCode_ERROR_CODE_UNREACHABLE_DC {
		t.Fatal("ConnectorError detail not extracted")
	}
	in := &client.RemoteError{Err: &connectorv1.ConnectorError{}}
	if got := client.FromStatus(fmt.Errorf("w: %w", in)); !errors.As(got, &re) || re != in {
		t.Fatal("RemoteError not passed through")
	}
	te := &client.TransportError{Code: codes.Internal}
	if got := client.FromStatus(te); got != error(te) {
		t.Fatal("TransportError not passed through")
	}
	if client.FromStatus(nil) != nil {
		t.Fatal("nil must stay nil")
	}
}

// T-1261 acceptance 2: cancellation and deadline stay recognisable, as context errors or as gRPC
// Canceled/DeadlineExceeded statuses, and the wrapping text goes away.
func TestFromStatusKeepsContextErrors(t *testing.T) {
	cases := map[string]struct {
		err  error
		want error
	}{
		"canceled":         {context.Canceled, context.Canceled},
		"deadline":         {context.DeadlineExceeded, context.DeadlineExceeded},
		"wrapped canceled": {fmt.Errorf("dc1.corp.example: %w", context.Canceled), context.Canceled},
		"wrapped deadline": {fmt.Errorf("10.20.30.40: %w", context.DeadlineExceeded), context.DeadlineExceeded},
		"status canceled":  {status.Error(codes.Canceled, leakDesc), context.Canceled},
		"status deadline":  {status.Error(codes.DeadlineExceeded, leakDesc), context.DeadlineExceeded},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			got := client.FromStatus(c.err)
			if !errors.Is(got, c.want) {
				t.Fatalf("errors.Is(%v, %v) = false", got, c.want)
			}
			noLeak(t, got)
		})
	}
	if errors.Is(client.FromStatus(status.Error(codes.Internal, "x")), context.Canceled) {
		t.Fatal("an Internal status must not match context.Canceled")
	}
}

func searchWith(t *testing.T, open, stream error, ctx context.Context) error {
	t.Helper()
	d := domain()
	d.SearchOpenErr, d.SearchStreamErr = open, stream
	us, err := client.NewUserSearch(conns{}, d, d)
	if err != nil {
		t.Fatal(err)
	}
	scope := authztest.ReadScope(grant([]authz.ScopeTerm{termOf(t, authz.TermSubtree, gA)}))
	_, err = us.Users(ctx, tenant.ID{}, connUUID, "pat", 25, scope)
	if err == nil {
		t.Fatal("search succeeded, want an error")
	}
	return err
}

func TestUserSearchTransportErrorsCarryNoDescription(t *testing.T) {
	bare := status.Error(codes.Unavailable, leakDesc)
	for name, c := range map[string]struct{ open, stream error }{
		"open":       {open: bare},
		"mid-stream": {stream: bare},
	} {
		t.Run(name, func(t *testing.T) {
			err := searchWith(t, c.open, c.stream, context.Background())
			noLeak(t, err)
			var te *client.TransportError
			if !errors.As(err, &te) || te.Code != codes.Unavailable || !te.Retryable() {
				t.Fatalf("got %#v, want a retryable Unavailable TransportError", err)
			}
		})
	}
}

func TestUserSearchContextErrorsSurvive(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for name, c := range map[string]struct {
		open, stream error
		want         error
	}{
		"open canceled":   {open: status.Error(codes.Canceled, leakDesc), want: context.Canceled},
		"stream canceled": {stream: status.Error(codes.Canceled, leakDesc), want: context.Canceled},
		"open deadline":   {open: fmt.Errorf("x: %w", context.DeadlineExceeded), want: context.DeadlineExceeded},
		"stream deadline": {stream: status.Error(codes.DeadlineExceeded, leakDesc), want: context.DeadlineExceeded},
		"stream ctx.Err":  {stream: canceled.Err(), want: context.Canceled},
	} {
		t.Run(name, func(t *testing.T) {
			err := searchWith(t, c.open, c.stream, context.Background())
			if !errors.Is(err, c.want) {
				t.Fatalf("errors.Is(%v, %v) = false", err, c.want)
			}
			noLeak(t, err)
		})
	}
}
