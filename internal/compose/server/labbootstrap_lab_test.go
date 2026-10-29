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

	"github.com/skenzeriq/activediq/internal/compose/config"
	"github.com/skenzeriq/activediq/internal/connector/labadmin"
	"github.com/skenzeriq/activediq/internal/connector/write"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/keys"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/testlab"
	"github.com/skenzeriq/activediq/tools/labserver/labboot"
)

func envOf(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

// syncBuf is a goroutine-safe log sink.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

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
		src, seed, closeFn, err := labboot.Bootstrap(ctx, env, next)
		if err != nil {
			t.Fatalf("labBootstrap: %v", err)
		}
		defer closeFn()

		// What Run does around the bootstrap: the tenant with its keys and audit genesis, the verify
		// transport over the lab source, the connection service.
		kek, err := keys.NewLocalProvider("test-kek", secret.FromBytes(bytes.Repeat([]byte{7}, 32)))
		if err != nil {
			t.Fatal(err)
		}
		ch := audit.NewChainer(db)
		tid, err := bootstrapTenant(ctx, config.Config{InstanceID: "node-1"}, db, ch, kek, jobs.NewRegistry())
		if err != nil {
			t.Fatal(err)
		}
		vopts, err := verifyOptions(src)
		if err != nil {
			t.Fatal(err)
		}
		svc, err := connection.NewService(conns, client.New(vopts...), ch)
		if err != nil {
			t.Fatal(err)
		}
		if err := seed(ctx, conns, svc, tid); err != nil {
			t.Fatalf("seed: %v", err)
		}
		res := struct{ Tenant tenant.ID }{tid}
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
		src2, seed2, close2, err := labboot.Bootstrap(ctx, env, next)
		if err != nil {
			t.Fatalf("second labBootstrap: %v", err)
		}
		defer close2()
		if err := seed2(ctx, conns, svc, tid); err != nil {
			t.Fatalf("second seed: %v", err)
		}
		if _, err := src2.Connector(ctx, string(conn.ID)); err != nil {
			t.Errorf("second boot does not serve the existing connection: %v", err)
		}
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
