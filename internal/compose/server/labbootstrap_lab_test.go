//go:build lab

package server

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/connector/labadmin"
	"github.com/skenzeriq/activediq/internal/connector/write"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant/provision"
	"github.com/skenzeriq/activediq/internal/testlab"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

func envOf(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

// T-0684 acceptance 3 (config half): no lab variables, no lab.
func TestLabSpecsNoEnvSeedsNothing(t *testing.T) {
	sp, err := labSpecs(envOf(nil))
	if err != nil || len(sp) != 0 {
		t.Fatalf("labSpecs(empty) = %v, %v; want none", sp, err)
	}
}

// T-0684 acceptance 1 and 2 (config half): both labs are read from their variables.
func TestLabSpecsReadBothLabs(t *testing.T) {
	sp, err := labSpecs(envOf(map[string]string{
		"WIN_LAB_DC_ADDR": "10.0.0.5", "WIN_LAB_SVC_PASSWORD": "pw1", "WIN_LAB_CA": "/ca1",
		"LAB_LDAPS_PORT": "6361", "LAB_SVC_PASSWORD": "pw2", "LAB_CA": "/ca2"}))
	if err != nil || len(sp) != 2 {
		t.Fatalf("labSpecs = %v, %v", sp, err)
	}
	if sp[0].Name != "win" || sp[0].Server != "10.0.0.5:636" || sp[0].ServerName != winLabTLS {
		t.Errorf("windows spec = %+v", sp[0])
	}
	if sp[1].Name != "samba" || sp[1].Server != "localhost:6361" {
		t.Errorf("samba spec = %+v", sp[1])
	}
}

// A partly configured lab fails closed and the error names the variable, never a value.
func TestLabSpecsPartialConfigFailsWithoutLeaking(t *testing.T) {
	_, err := labSpecs(envOf(map[string]string{"WIN_LAB_DC_ADDR": "10.0.0.5", "WIN_LAB_CA": "/ca"}))
	if err == nil || !strings.Contains(err.Error(), "WIN_LAB_SVC_PASSWORD") {
		t.Fatalf("err = %v, want one naming WIN_LAB_SVC_PASSWORD", err)
	}
	_, err = labSpecs(envOf(map[string]string{"LAB_LDAPS_PORT": "6361", "LAB_SVC_PASSWORD": "hunter2"}))
	if err == nil || !strings.Contains(err.Error(), "LAB_CA") || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("err = %v, want one naming LAB_CA and not the password", err)
	}
}

// T-0684 acceptance 3 with no environment: the bootstrap returns the tunnel source untouched and
// touches neither database nor registry (both nil).
func TestLabBootstrapWithoutEnvIsInert(t *testing.T) {
	var next client.ConnectorSource = &client.TunnelSource{}
	got, closeFn, err := labBootstrap(context.Background(), nil, nil, envOf(nil), next)
	if err != nil || got != next {
		t.Fatalf("labBootstrap(no env) = (%v, %v)", got, err)
	}
	closeFn()
}

// The source routes a seeded connection in process and anything else to the tunnel source.
func TestLabSourceFallsThrough(t *testing.T) {
	s := &labSource{by: map[string]connectorv1.ConnectorClient{}}
	if _, err := s.Connector(context.Background(), "x"); err == nil {
		t.Fatal("an unknown connection with no tunnel source must be refused")
	}
}


// syncBuf is a goroutine-safe log sink.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string               { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// T-0684 acceptance 1, 2 and 4 against the Samba lab: the bootstrap seeds one active AD connection in the
// install's tenant, the returned source resolves it to a working in-process connector (a real Read of the
// domain head, by GUID, through the product's read adapter), a second boot reuses the connection, and
// nothing it logged contains the service password. The Windows lab (VM 119) takes the same path with
// WIN_LAB_* and is a Windows-lab case (see the ticket note).
func TestLabBootstrapSeedsActiveConnectionAndServesReads(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		le := testlab.Load(t)
		d := s.NewDatabase(t)
		d.Migrate(t)
		db, err := store.Open(context.Background(), store.Config{DSN: d.AppDSN()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(db.Close)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		var logs syncBuf
		old := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
		t.Cleanup(func() { slog.SetDefault(old) })

		pw := le.Values["LAB_SVC_PASSWORD"]
		env := envOf(map[string]string{"LAB_LDAPS_PORT": le.Port, "LAB_SVC_PASSWORD": pw, "LAB_CA": le.CAPath})
		conns := connection.NewRegistry(db)
		var next client.ConnectorSource
		src, closeFn, err := labBootstrap(ctx, db, conns, env, next)
		if err != nil {
			t.Fatalf("labBootstrap: %v", err)
		}
		defer closeFn()

		res, err := provision.FirstRun(ctx, db, "lab")
		if err != nil {
			t.Fatal(err)
		}
		all, err := conns.List(ctx, res.Tenant, false)
		if err != nil || len(all) != 1 || all[0].State != connection.StateActive || all[0].Kind != connection.KindADForest || all[0].DirectoryIdentity == "" {
			t.Fatalf("connections = %+v, %v; want exactly one active AD forest connection with an identity", all, err)
		}
		conn := all[0]

		// A real read through the product's adapter and the in-process connector.
		admin := labadmin.Dial(t, le.Port, le.Pool, "Administrator@lab.activediq.test", le.Values["LAB_ADMIN_PASSWORD"])
		g, err := guid.FromBytes(admin.ObjectGUID(labDom))
		if err != nil {
			t.Fatal(err)
		}
		head := uuidText(write.GUIDToWire(g).GetValue())
		if string(conn.DirectoryIdentity) != head {
			t.Fatalf("connection identity %s != domain head %s", conn.DirectoryIdentity, head)
		}
		tr, err := client.NewGRPCReadTransport(src)
		if err != nil {
			t.Fatal(err)
		}
		reads, err := client.NewConnectorReads(conns, tr)
		if err != nil {
			t.Fatal(err)
		}
		rctx := authority.WithTenant(ctx, res.Tenant.String())
		got, err := reads.Object(rctx, nil, authority.TargetRef{Connection: string(conn.ID), GUID: head, Class: "domainDNS", NC: authority.NamingContextID(head)}, head, false)
		if err != nil {
			t.Fatalf("read of the domain head through the lab source: %v", err)
		}
		if !got.Exists || got.Parent != "" {
			t.Errorf("domain head read = %+v, want an existing naming-context head", got)
		}

		// A second boot reuses the connection rather than adding another.
		_, close2, err := labBootstrap(ctx, db, conns, env, next)
		if err != nil {
			t.Fatalf("second labBootstrap: %v", err)
		}
		close2()
		if again, _ := conns.List(ctx, res.Tenant, false); len(again) != 1 {
			t.Errorf("second boot left %d connections, want 1", len(again))
		}

		if pw == "" || strings.Contains(logs.String(), pw) {
			t.Errorf("service password empty or present in the bootstrap's logs")
		}
		if !strings.Contains(logs.String(), "lab connection active") {
			t.Errorf("bootstrap logged nothing: %q", logs.String())
		}
	})
}
