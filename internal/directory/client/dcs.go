package client

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// Errors of the DC directory. None carries a connector message or a DC list.
var (
	ErrNoDescribe     = errors.New("client: no connector source wired for DC discovery")
	ErrDescribeFailed = errors.New("client: connector describe failed")
	ErrDCNC           = errors.New("client: naming context is not one the connection describes")
	ErrDCIdentity     = errors.New("client: connector returned a DC without a usable identity")
)

// WritableDC is one reachable, writable DC: the host and the DSA GUID the connector read from that same
// DC in one Describe answer (rootDSE dnsHostName and the NTDS Settings objectGUID), the GUID in
// canonical text after the attr/guid codec has validated it.
type WritableDC struct {
	Host    string
	DSAGUID string
	// Site is the AD site the DC reported (DcIdentity.site); empty when it reported none.
	Site string
}

// DCDirectory lists a connection's writable DCs, live (Describe with refresh), so a DC rebuilt under
// the same name shows its new DSA GUID.
type DCDirectory struct {
	conns ConnectionSource
	src   ConnectorSource
}

// NewDCDirectory returns the directory. Both arguments are required.
func NewDCDirectory(conns ConnectionSource, src ConnectorSource) (*DCDirectory, error) {
	switch {
	case conns == nil:
		return nil, errors.New("client: DC directory needs a connection source")
	case src == nil:
		return nil, ErrNoDescribe
	}
	return &DCDirectory{conns: conns, src: src}, nil
}

// WritableDCs returns the reachable writable DCs that serve nc, sorted by host. The connection is
// resolved under the tenant of ctx. A DC with a nil or malformed identity is an error, never skipped
// into a partial answer. An nc the connection does not describe is ErrDCNC.
func (d *DCDirectory) WritableDCs(ctx context.Context, connectionID string, nc authority.NamingContextID) ([]WritableDC, error) {
	tid, err := readTenant(ctx)
	if err != nil {
		return nil, err
	}
	conn, err := d.conns.Get(ctx, tid, connection.ID(connectionID))
	if err != nil || string(conn.ID) != connectionID || conn.RetiredAt != nil {
		return nil, ErrReadConnection
	}
	ident := directoryOf(conn)
	if ident == nil {
		return nil, ErrReadDirectory
	}
	want, err := parseUUID(string(nc))
	if err != nil {
		return nil, fmt.Errorf("%w: naming context", ErrInvalidOp)
	}
	resp, err := describeDCs(ctx, d.src, connectionID, ident, "DC discovery")
	if err != nil {
		return nil, err
	}
	return writableDCsOf(resp, want)
}

// describeDCs is the one live Describe (refresh) path of DC discovery and DC counting. A status without a
// ConnectorError detail carries a free-text message: it is never passed on.
func describeDCs(ctx context.Context, src ConnectorSource, connectionID string, ident *connectorv1.DirectoryIdentity, why string) (*connectorv1.DescribeResponse, error) {
	cc, err := src.Connector(ctx, connectionID)
	if err != nil {
		return nil, fmt.Errorf("client: connector for %s: %w", why, err)
	}
	resp, err := cc.Describe(ctx, &connectorv1.DescribeRequest{
		Connection: &connectorv1.ConnectionRef{ConnectionId: connectionID, DirectoryIdentity: ident},
		Refresh:    true,
	})
	if err != nil {
		if re := (&RemoteError{}); errors.As(FromStatus(err), &re) {
			return nil, fmt.Errorf("client: connector describe: %w", re)
		}
		return nil, ErrDescribeFailed
	}
	return resp, nil
}

// dcsOfNC returns the DCs that serve nc: a domain NC lives on the DCs of that domain, a forest-wide
// partition on every DC. An nc the response does not describe is ErrDCNC.
func dcsOfNC(resp *connectorv1.DescribeResponse, nc []byte) ([]*connectorv1.DomainControllerInfo, error) {
	var kind connectorv1.NamingContextKind
	for _, n := range resp.GetNamingContexts() {
		if string(n.GetNcGuid().GetValue()) == string(nc) {
			kind = n.GetKind()
		}
	}
	if kind == connectorv1.NamingContextKind_NAMING_CONTEXT_KIND_UNSPECIFIED {
		return nil, ErrDCNC
	}
	var out []*connectorv1.DomainControllerInfo
	for _, dc := range resp.GetDomainControllers() {
		if kind == connectorv1.NamingContextKind_NAMING_CONTEXT_KIND_DOMAIN && string(dc.GetDomainNcGuid().GetValue()) != string(nc) {
			continue
		}
		out = append(out, dc)
	}
	return out, nil
}

func writableDCsOf(resp *connectorv1.DescribeResponse, nc []byte) ([]WritableDC, error) {
	dcs, err := dcsOfNC(resp, nc)
	if err != nil {
		return nil, err
	}
	var out []WritableDC
	for _, dc := range dcs {
		// Only a DC proven writable and reachable is a candidate: UNKNOWN is not writable.
		if !dc.GetReachable() || dc.GetIsRodc() != connectorv1.TriState_TRI_STATE_FALSE {
			continue
		}
		host := dc.GetIdentity().GetDnsHostname()
		g, err := guid.Parse(formatUUID(dc.GetIdentity().GetDsaGuid().GetValue()))
		if host == "" || len(dc.GetIdentity().GetDsaGuid().GetValue()) != guid.Size || err != nil {
			return nil, ErrDCIdentity
		}
		out = append(out, WritableDC{Host: host, DSAGUID: g.String(), Site: dc.GetIdentity().GetSite()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out, nil
}
