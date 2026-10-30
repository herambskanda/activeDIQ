package ad

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/secret"
)

// TestOpenGCReadsSecretSchemaFromDCPort pins T-0619: a Windows GC answers the searchFlags schema
// search on 3269 with no entries (searchFlags is not in the partial attribute set), so OpenGC must
// read the schema from the same host's 636 and still end up with every schema-flagged secret.
func TestOpenGCReadsSecretSchemaFromDCPort(t *testing.T) {
	gcUp := startFakeUpstream(t, 0)
	gcUp.noSchema = true
	dcUp := startFakeUpstream(t, 0)
	var port atomic.Value
	port.Store("")
	p, pool := startFaultProxy(t, func() (net.Conn, error) {
		if port.Load() == "3269" {
			return gcUp.dial()
		}
		return dcUp.dial()
	}, injectPlan{})
	_, proxyPort, _ := net.SplitHostPort(p.Addr())
	var dialed []string
	cfg := Config{
		Servers:    []string{"dc1:3269"},
		Credential: Credential{BindName: "svc", Password: secret.FromBytes([]byte("pw"))},
		RootCAs:    pool,
		ServerName: "127.0.0.1",
		Timeout:    5 * time.Second,
		Dialer: dialerFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, pt, _ := net.SplitHostPort(addr)
			dialed = append(dialed, pt)
			port.Store(pt)
			return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort("127.0.0.1", proxyPort))
		}),
	}
	g, err := OpenGC(context.Background(), cfg)
	if err != nil {
		t.Fatalf("OpenGC: %v", err)
	}
	defer g.Close()
	if !g.s.schema.IsSecret("unicodePwd") {
		t.Error("unicodePwd not secret on the GC session")
	}
	if got := strings.Join(dialed, ","); got != "3269,636" {
		t.Errorf("dialed ports %q, want 3269,636", got)
	}
}

type dialerFunc func(ctx context.Context, network, addr string) (net.Conn, error)

func (f dialerFunc) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return f(ctx, network, addr)
}
