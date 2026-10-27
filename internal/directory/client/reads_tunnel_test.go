package client

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

const (
	tsTenant = "11111111-1111-4111-8111-111111111111"
	tsConn   = "22222222-2222-4222-8222-222222222222"
	tsComp   = "33333333-3333-4333-8333-333333333333"
)

type tsConns struct {
	c   connection.Connection
	err error
}

func (f tsConns) Get(_ context.Context, _ tenant.ID, _ connection.ID) (connection.Connection, error) {
	return f.c, f.err
}

type tsBindings struct {
	bs  []connection.Binding
	err error
}

func (f tsBindings) Bindings(context.Context, tenant.ID, connection.ID) ([]connection.Binding, error) {
	return f.bs, f.err
}

type tsTunnels struct {
	gotTenant, gotComp string
	calls              int
}

func (f *tsTunnels) Conn(tid tenant.ID, comp string) grpc.ClientConnInterface {
	f.calls++
	f.gotTenant, f.gotComp = tid.String(), comp
	return nil
}

func TestTunnelSource(t *testing.T) {
	ok := connection.Connection{ID: tsConn}
	retired := time.Now()
	active := connection.Binding{ConnectionID: tsConn, Target: connection.TargetComponent, ComponentID: tsComp, State: "active"}
	cases := []struct {
		name string
		ctx  context.Context
		conn tsConns
		bs   tsBindings
		id   string
		want error
	}{
		{"component binding", authority.WithTenant(context.Background(), tsTenant), tsConns{c: ok}, tsBindings{bs: []connection.Binding{active}}, tsConn, nil},
		{"no tenant", context.Background(), tsConns{c: ok}, tsBindings{bs: []connection.Binding{active}}, tsConn, ErrReadTenant},
		{"bad id", authority.WithTenant(context.Background(), tsTenant), tsConns{c: ok}, tsBindings{bs: []connection.Binding{active}}, "x", ErrReadConnection},
		{"other tenant / unknown", authority.WithTenant(context.Background(), tsTenant), tsConns{err: connection.ErrNotFound}, tsBindings{bs: []connection.Binding{active}}, tsConn, ErrReadConnection},
		{"retired", authority.WithTenant(context.Background(), tsTenant), tsConns{c: connection.Connection{ID: tsConn, RetiredAt: &retired}}, tsBindings{bs: []connection.Binding{active}}, tsConn, ErrReadConnection},
		{"embedded only", authority.WithTenant(context.Background(), tsTenant), tsConns{c: ok}, tsBindings{bs: []connection.Binding{{ConnectionID: tsConn, Target: connection.TargetEmbedded, State: "active"}}}, tsConn, ErrNoEndpoint},
		{"disabled component", authority.WithTenant(context.Background(), tsTenant), tsConns{c: ok}, tsBindings{bs: []connection.Binding{{ConnectionID: tsConn, Target: connection.TargetComponent, ComponentID: tsComp, State: "disabled"}}}, tsConn, ErrNoEndpoint},
		{"binding read fails", authority.WithTenant(context.Background(), tsTenant), tsConns{c: ok}, tsBindings{err: errors.New("db")}, tsConn, ErrNoEndpoint},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tn := &tsTunnels{}
			s, err := NewTunnelSource(tc.conn, tc.bs, tn)
			if err != nil {
				t.Fatal(err)
			}
			cc, err := s.Connector(tc.ctx, tc.id)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if tc.want != nil && (cc != nil || tn.calls != 0) {
				t.Fatal("a tunnel was opened on a refused call")
			}
			if tc.want == nil && (cc == nil || tn.gotTenant != tsTenant || tn.gotComp != tsComp) {
				t.Fatalf("tunnel for %q/%q, client %v", tn.gotTenant, tn.gotComp, cc)
			}
		})
	}
	if _, err := NewTunnelSource(tsConns{}, tsBindings{}, nil); !errors.Is(err, ErrNoConnectorTunnels) {
		t.Fatal("nil tunnels accepted")
	}
}
