package connector_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/skenzeriq/activediq/internal/compose/config"
	"github.com/skenzeriq/activediq/internal/compose/connector"
	"github.com/skenzeriq/activediq/internal/connector/rights"
	"github.com/skenzeriq/activediq/internal/connector/write"
	"github.com/skenzeriq/activediq/internal/platform/fleet"
	"github.com/skenzeriq/activediq/internal/platform/fleet/dial"
	"github.com/skenzeriq/activediq/internal/platform/fleet/tunnelclient"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	v1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

const goodLocal = `{"connection_id":"conn-1","enrollment_dir":"/var/lib/diq/enroll","data_dir":"/var/lib/diq/data",
"servers":["dc1.lab.test"],"ca_file":"/etc/diq/ca.pem","kerberos":{"principal":"svc-diq$","realm":"LAB.TEST","keytab_file":"/etc/diq/svc.keytab"}}`

func boundBackend(t *testing.T, connID string, closed *bool) *connector.Backend {
	t.Helper()
	gate, _ := write.NewGateBook(nopBase{}, nil)
	vh, err := rights.NewVerifyHandler(rights.VerifyConfig{Dir: stubDir{}, Epoch: rights.NewEpochState(nil, nil, nil),
		Directory: dirIdent, Gate: gate, OnLocalRecordFailed: gate.CloseLocalRecordFailed, ConnectionID: connID})
	if err != nil {
		t.Fatal(err)
	}
	return connector.NewBackend(vh, readHandler(t), writeHandler(t), func() { *closed = true })
}

// leafState fabricates an enrolled state: a self-signed leaf carrying a component identity.
func leafState(t *testing.T, kind string) *dial.State {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), URIs: fleet.URIs(tenant.New(), kind, "11111111-2222-4333-8444-555555555555"),
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, k.Public(), k)
	if err != nil {
		t.Fatal(err)
	}
	return &dial.State{Leaf: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}}
}

func cfgFile(t *testing.T) config.Config {
	t.Helper()
	p := filepath.Join(t.TempDir(), "connector.json")
	if err := os.WriteFile(p, []byte(goodLocal), 0o600); err != nil {
		t.Fatal(err)
	}
	return config.Config{ConnectorConfigPath: p}
}

type regs struct{ impls []any }

func (r *regs) RegisterService(_ *grpc.ServiceDesc, impl any) { r.impls = append(r.impls, impl) }

// Run dials out with the enrolled state and the leaf's identity and serves ONE composite
// ConnectorServer for the tunnel; a request for another connection_id is refused INVALID_ARGUMENT.
func TestRunServesOneCompositeServerBoundToTheConfiguredConnection(t *testing.T) {
	st := leafState(t, fleet.KindConnector)
	var closed, served bool
	var got tunnelclient.Config
	err := connector.RunWith(context.Background(), cfgFile(t),
		func(dir string) (*dial.State, error) {
			if dir != "/var/lib/diq/enroll" {
				t.Errorf("enrollment dir %q", dir)
			}
			return st, nil
		},
		func(_ context.Context, loc connector.Local, _ *slog.Logger) (*connector.Backend, error) {
			return boundBackend(t, loc.ConnectionID, &closed), nil
		},
		func(_ context.Context, c tunnelclient.Config) { got, served = c, true })
	if err != nil {
		t.Fatal(err)
	}
	if !served || got.State != st || got.Identity.Kind != fleet.KindConnector || got.Open == nil {
		t.Fatalf("tunnel not served with the enrolled state and leaf identity: %+v", got)
	}
	if !closed {
		t.Fatal("the AD session was not released when the tunnel ended")
	}
	var r regs
	got.Binding.Register(got.Identity, &r)
	if len(r.impls) != 1 {
		t.Fatalf("%d registrations, want exactly one composite ConnectorServer", len(r.impls))
	}
	srv := r.impls[0].(v1.ConnectorServer)
	_, perr := srv.Plan(context.Background(), &v1.PlanRequest{})
	if status.Code(perr) == codes.Unimplemented {
		t.Fatalf("Plan not served by the composite: %v", perr)
	}
}

func TestRunRefusesWithoutConfigOrEnrolment(t *testing.T) {
	loadNever := func(string) (*dial.State, error) { t.Fatal("loaded"); return nil, nil }
	openNever := func(context.Context, connector.Local, *slog.Logger) (*connector.Backend, error) {
		t.Fatal("AD session opened")
		return nil, nil
	}
	serveNever := func(context.Context, tunnelclient.Config) { t.Fatal("tunnel dialled") }
	if err := connector.RunWith(context.Background(), config.Config{}, loadNever, openNever, serveNever); !errors.Is(err, connector.ErrNoConfig) {
		t.Fatalf("no config: %v", err)
	}
	for name, load := range map[string]func(string) (*dial.State, error){
		"not enrolled": func(string) (*dial.State, error) { return nil, dial.ErrState },
		"wrong kind":   func(string) (*dial.State, error) { return leafState(t, fleet.KindADDC), nil },
	} {
		if err := connector.RunWith(context.Background(), cfgFile(t), load, openNever, serveNever); !errors.Is(err, connector.ErrNotEnrolled) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A directory failure stops Run before the tunnel is dialled.
	err := connector.RunWith(context.Background(), cfgFile(t),
		func(string) (*dial.State, error) { return leafState(t, fleet.KindConnector), nil },
		func(context.Context, connector.Local, *slog.Logger) (*connector.Backend, error) {
			return nil, errors.New("bind refused")
		},
		serveNever)
	if err == nil {
		t.Fatal("Run succeeded without a directory session")
	}
}
