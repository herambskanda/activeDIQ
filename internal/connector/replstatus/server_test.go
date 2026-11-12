package replstatus

// The gRPC hop (the remote transport): the Server streams results then the summary over a real
// connection, and a handler refusal reaches the caller as a status error.

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

func TestServerStreamsOverGRPC(t *testing.T) {
	src := &fakeSrc{dcs: []DC{{Identity: dcID(1)}, {Identity: dcID(2)}}, readers: map[byte]reader{
		1: func([]ad.ReplAttr) (ad.ReplRead, error) { return ad.ReplRead{}, nil },
	}}
	h, err := New(src)
	if err != nil {
		t.Fatal(err)
	}
	lis := bufconn.Listen(1 << 20)
	g := grpc.NewServer()
	connectorv1.RegisterConnectorServer(g, NewServer(h))
	go g.Serve(lis)
	t.Cleanup(g.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	st, err := connectorv1.NewConnectorClient(conn).ReadReplicationStatus(context.Background(), newReq(nil))
	if err != nil {
		t.Fatal(err)
	}
	var results int
	var sum *connectorv1.ReplicationSummary
	for {
		m, err := st.Recv()
		if err != nil {
			break
		}
		if m.GetResult() != nil {
			results++
		}
		if m.GetSummary() != nil {
			sum = m.GetSummary()
		}
	}
	if results != 2 || sum == nil || sum.Coverage != connectorv1.Coverage_COVERAGE_PARTIAL {
		t.Fatalf("results=%d summary=%v", results, sum)
	}
}
