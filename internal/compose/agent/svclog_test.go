package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log/slog"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/compose/tunnelbind"
	"github.com/skenzeriq/activediq/internal/platform/fleet"
	"github.com/skenzeriq/activediq/internal/platform/fleet/dial"
	"github.com/skenzeriq/activediq/internal/platform/fleet/tunnelclient"
)

type capture struct {
	mu  sync.Mutex
	ids []uint32
	txt []string
}

func (c *capture) Report(_ slog.Level, id uint32, msg string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ids, c.txt = append(c.ids, id), append(c.txt, msg)
}

func (c *capture) snapshot() ([]uint32, []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]uint32(nil), c.ids...), append([]string(nil), c.txt...)
}

// T-1277 AC1 end to end on the real tunnel client: the server is unreachable after a successful
// Load; the retry loop runs several times; exactly one event 110 reaches the reporter and it carries
// no address and no key material.
func TestUnreachableServerWritesOneClassedEvent(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "t"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := x509.ParseCertificate(der)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()

	st := &dial.State{Roots: []*x509.Certificate{root}, Leaf: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key},
		Endpoints: []dial.Endpoint{{Host: "127.0.0.1", Port: uint16(port)}}}
	rep := &capture{}
	log := newLogger(slog.LevelInfo, rep)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second) // several 1 s, 2 s backoffs
	defer cancel()
	tunnelclient.Run(ctx, tunnelclient.Config{State: st, Log: log, Open: tunnelbind.Open, Binding: fleet.Binding{}})

	ids, txt := rep.snapshot()
	if len(ids) != 1 || ids[0] != 110 {
		t.Fatalf("events %v %q, want exactly one 110", ids, txt)
	}
	for _, s := range txt {
		if strings.Contains(s, strconv.Itoa(port)) || strings.Contains(s, "127.0.0.1") || strings.Contains(strings.ToLower(s), "key") {
			t.Fatalf("event text leaks detail: %q", s)
		}
	}
}
