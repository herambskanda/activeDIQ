package server

import (
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/status"

	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

const (
	nsForest = "aaaaaaaa-0000-0000-0000-0000000000f1"
	nsDomain = "aaaaaaaa-0000-0000-0000-0000000000a1"
	opTenant = "6f1c2a40-0000-4000-8000-0000000000aa"
)

func guidBytes(t *testing.T, s string) *connectorv1.Guid {
	t.Helper()
	b, err := hexUUID(s)
	if err != nil {
		t.Fatal(err)
	}
	return &connectorv1.Guid{Value: b}
}

func hexUUID(s string) ([]byte, error) {
	h := strings.ReplaceAll(s, "-", "")
	out := make([]byte, 16)
	for i := range out {
		var v byte
		for _, c := range []byte(h[2*i : 2*i+2]) {
			v <<= 4
			switch {
			case c >= '0' && c <= '9':
				v |= c - '0'
			case c >= 'a' && c <= 'f':
				v |= c - 'a' + 10
			default:
				return nil, errors.New("bad hex")
			}
		}
		out[i] = v
	}
	return out, nil
}

type descConnector struct {
	connectorv1.ConnectorClient
	resp *connectorv1.DescribeResponse
	err  error
}

func (d *descConnector) Describe(context.Context, *connectorv1.DescribeRequest, ...grpc.CallOption) (*connectorv1.DescribeResponse, error) {
	return d.resp, d.err
}

type descSource struct{ c *descConnector }

func (s descSource) Connector(context.Context, string) (connectorv1.ConnectorClient, error) {
	return s.c, nil
}

type recConns struct{ got tenant.ID }

func (c *recConns) Get(_ context.Context, tid tenant.ID, id connection.ID) (connection.Connection, error) {
	c.got = tid
	return connection.Connection{ID: id, Kind: connection.KindADForest, DirectoryIdentity: connection.DirectoryIdentity(nsForest)}, nil
}

func realPinner(t *testing.T, c *descConnector) (dcPinner, *recConns) {
	t.Helper()
	conns := &recConns{}
	dcs, err := client.NewDCDirectory(conns, descSource{c})
	if err != nil {
		t.Fatal(err)
	}
	p, err := newDCPinner(dcs)
	if err != nil {
		t.Fatal(err)
	}
	return p, conns
}

func describeWith(t *testing.T, host, dsa string) *connectorv1.DescribeResponse {
	return &connectorv1.DescribeResponse{
		NamingContexts: []*connectorv1.NamingContextInfo{{NcGuid: guidBytes(t, nsDomain), Kind: connectorv1.NamingContextKind_NAMING_CONTEXT_KIND_DOMAIN}},
		DomainControllers: []*connectorv1.DomainControllerInfo{{
			Identity: &connectorv1.DcIdentity{DsaGuid: guidBytes(t, dsa), DnsHostname: host}, DomainNcGuid: guidBytes(t, nsDomain),
			IsRodc: connectorv1.TriState_TRI_STATE_FALSE, Reachable: true}},
	}
}

// The composed product path: the real dcPinner over the real client.DCDirectory resolves the connection
// under the tenant the caller put on ctx, and pins the Describe DC's host and DSA GUID.
func TestRealPinnerOverDCDirectoryPinsDescribedDC(t *testing.T) {
	p, conns := realPinner(t, &descConnector{resp: describeWith(t, "dc1.example.test", dsaA)})
	ctx := authority.WithTenant(context.Background(), opTenant)
	pin, err := p.Pin(ctx, "c1", nsDomain, "")
	if err != nil || pin.Host != "dc1.example.test" || pin.DSAGUID != dsaA {
		t.Fatalf("pin = %+v, %v", pin, err)
	}
	if conns.got.String() != opTenant {
		t.Fatalf("connection resolved under tenant %q, want %q", conns.got, opTenant)
	}
	// Without a tenant on ctx the pin fails closed (the runner always supplies it).
	if pin, err := p.Pin(context.Background(), "c1", nsDomain, ""); err == nil || pin.Host != "" || pin.DSAGUID != "" {
		t.Fatalf("pin without tenant = %+v, %v", pin, err)
	}
}

// A Describe failure's free-text status message never reaches the pin error.
func TestPinErrorCarriesNoConnectorMessage(t *testing.T) {
	const leak = "LDAP bind CN=svc,DC=corp: secret-detail"
	p, _ := realPinner(t, &descConnector{err: status.Error(13, leak)})
	pin, err := p.Pin(authority.WithTenant(context.Background(), opTenant), "c1", nsDomain, "")
	if err == nil || pin.Host != "" || pin.DSAGUID != "" {
		t.Fatalf("pin = %+v, %v", pin, err)
	}
	if strings.Contains(err.Error(), "secret-detail") || strings.Contains(err.Error(), "CN=svc") {
		t.Fatalf("connector message leaked: %v", err)
	}
	if !errors.Is(err, client.ErrDescribeFailed) {
		t.Fatalf("err = %v, want ErrDescribeFailed", err)
	}
}
