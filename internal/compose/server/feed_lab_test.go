//go:build lab

package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/compose/config"
	"github.com/skenzeriq/activediq/internal/connector/labadmin"
	"github.com/skenzeriq/activediq/internal/connector/write"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/keys"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
	"github.com/skenzeriq/activediq/internal/testlab"
)

func feedCall(t *testing.T, c connectorv1.ConnectorClient, r *connectorv1.ChangeFeedRequest) []*connectorv1.ChangeBatch {
	t.Helper()
	st, err := c.ChangeFeed(context.Background(), r)
	if err != nil {
		t.Fatalf("ChangeFeed: %v", err)
	}
	var out []*connectorv1.ChangeBatch
	for {
		m, err := st.Recv()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatalf("ChangeFeed recv: %v", err)
		}
		out = append(out, m.GetBatch())
	}
}

// T-1194 acceptance 5: the lab server serves ChangeFeed, so a -tags lab server reaches the Samba lab's
// feed through the same ConnectorSource the product reads use. Prime returns one empty complete batch and
// a cookie; resume from it is complete, and a change made between the two arrives in it.
func TestLabServerServesChangeFeed(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		le := testlab.Load(t)
		d := s.NewDatabase(t)
		d.Migrate(t)
		db, err := store.Open(context.Background(), store.Config{DSN: d.AppDSN()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(db.Close)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()

		env := envOf(map[string]string{"LAB_LDAPS_PORT": le.Port, "LAB_SVC_PASSWORD": le.Values["LAB_SVC_PASSWORD"], "LAB_CA": le.CAPath})
		conns := connection.NewRegistry(db)
		var next client.ConnectorSource
		src, seed, closeFn, err := labBootstrap(ctx, env, next)
		if err != nil {
			t.Fatalf("labBootstrap: %v", err)
		}
		defer closeFn()
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
		all, err := conns.List(ctx, tid, false)
		if err != nil || len(all) != 1 {
			t.Fatalf("connections = %+v, %v", all, err)
		}
		conn := all[0]

		admin := labadmin.Dial(t, le.Port, le.Pool, "Administrator@lab.activediq.test", le.Values["LAB_ADMIN_PASSWORD"])
		g, err := guid.FromBytes(admin.ObjectGUID(labDom))
		if err != nil {
			t.Fatal(err)
		}
		wire := write.GUIDToWire(g)
		cc, err := src.Connector(ctx, string(conn.ID))
		if err != nil {
			t.Fatal(err)
		}
		req := func(start func(*connectorv1.ChangeFeedRequest)) *connectorv1.ChangeFeedRequest {
			r := &connectorv1.ChangeFeedRequest{
				Connection: &connectorv1.ConnectionRef{ConnectionId: string(conn.ID), DirectoryIdentity: &connectorv1.DirectoryIdentity{
					Identity: &connectorv1.DirectoryIdentity_AdForest{AdForest: &connectorv1.AdForestIdentity{ForestRootNcGuid: wire}}}},
				Partition:  &connectorv1.FeedPartition{Partition: &connectorv1.FeedPartition_AdNcGuid{AdNcGuid: wire}},
				Attributes: []string{"cn", "sAMAccountName"},
			}
			start(r)
			return r
		}

		bs := feedCall(t, cc, req(func(r *connectorv1.ChangeFeedRequest) {
			r.Start = &connectorv1.ChangeFeedRequest_Prime{Prime: &connectorv1.FeedPrime{}}
		}))
		if len(bs) != 1 || !bs[0].GetCycleComplete() || len(bs[0].GetChanges()) != 0 || bs[0].GetCookieAfter() == nil {
			t.Fatalf("prime = %v; want one complete batch, no changes, a cookie", bs)
		}

		admin.CreateUser("t1194-feed-user", "CN=Users,"+labDom) // deleted by the helper's cleanup

		cookie := bs[0].GetCookieAfter()
		bs = feedCall(t, cc, req(func(r *connectorv1.ChangeFeedRequest) {
			r.Start = &connectorv1.ChangeFeedRequest_Resume{Resume: &connectorv1.FeedResume{Cookie: cookie}}
		}))
		if len(bs) == 0 || !bs[len(bs)-1].GetCycleComplete() {
			t.Fatalf("resume did not end with cycle_complete: %v", bs)
		}
		found := false
		for _, b := range bs {
			for _, c := range b.GetChanges() {
				for _, a := range c.GetAttributes() {
					if a.GetName() == "samaccountname" {
						found = true
					}
				}
			}
		}
		if !found {
			t.Errorf("resume did not deliver the user created after the prime")
		}
	})
}
