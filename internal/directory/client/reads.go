package client

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// Errors of the connector read adapter. None carries an object identifier or a connector message.
var (
	ErrNoReadTransport = errors.New("client: no read transport wired")
	ErrNoTier0Verdict  = errors.New("client: read returned no tier0 verdict")
	ErrReadTenant      = errors.New("client: read has no tenant in its context")
	ErrReadConnection  = errors.New("client: connection not readable for this tenant")
	ErrReadPin         = errors.New("client: pinned read without a usable DSA pin")
	ErrReadProtocol    = errors.New("client: read stream violates the contract")
	ErrReadIdentity    = errors.New("client: read returned a different object than asked")
)

// ReadStream is the receiving side of the Read RPC. The generated grpc.ServerStreamingClient
// satisfies it.
type ReadStream interface {
	Recv() (*connectorv1.ReadResponse, error)
}

// ReadTransport opens the Read stream of the connector serving req.Connection. The gRPC transport
// implements it; the generated client is referenced there and nowhere else.
type ReadTransport interface {
	Read(ctx context.Context, req *connectorv1.ReadRequest) (ReadStream, error)
}

// ConnectorReads is the Reads implementation over the connector's Read RPC.
type ConnectorReads struct {
	conns ConnectionSource
	tr    ReadTransport
}

var _ Reads = (*ConnectorReads)(nil)

// NewConnectorReads returns the adapter. Every argument is required; a missing one is an error here
// rather than a silent unpinned read later. The Tier-0 verdict is not a port: it rides on the Read
// header (ReadHeader.tier0), computed by the connector on the DC that served the read.
func NewConnectorReads(conns ConnectionSource, tr ReadTransport) (*ConnectorReads, error) {
	switch {
	case conns == nil:
		return nil, errors.New("client: connector reads need a connection source")
	case tr == nil:
		return nil, ErrNoReadTransport
	}
	return &ConnectorReads{conns: conns, tr: tr}, nil
}

// Object implements Reads. The connection is resolved under the tenant of ctx (authority.WithTenant),
// so a connection ID of another tenant is not found and the read fails. With pins, the read goes to
// the DC pinned for the target's naming context, by DSA GUID (authority.DSAPinsFrom), and a pin
// without a DSA GUID is an error, never an unpinned read (rule 5). With no pins at all (a read of a
// container for scope-root ancestry) the DcSelection is left unset and the connector picks one DC for
// the call. Every failure returns an error, which the caller treats as "refuse".
func (r *ConnectorReads) Object(ctx context.Context, pins authority.Pins, target authority.TargetRef, guid string, needTier0 bool) (ObjectRead, error) {
	tidText, ok := authority.TenantFrom(ctx)
	if !ok {
		return ObjectRead{}, ErrReadTenant
	}
	tid, err := tenant.Parse(tidText)
	if err != nil {
		return ObjectRead{}, ErrReadTenant
	}
	id, err := parseUUID(guid)
	if err != nil {
		return ObjectRead{}, fmt.Errorf("%w: object GUID", ErrInvalidOp)
	}
	conn, err := r.conns.Get(ctx, tid, connection.ID(target.Connection))
	if err != nil || string(conn.ID) != target.Connection || conn.RetiredAt != nil {
		return ObjectRead{}, ErrReadConnection
	}

	req := &connectorv1.ReadRequest{
		Connection:   &connectorv1.ConnectionRef{ConnectionId: target.Connection},
		Guid:         &connectorv1.Guid{Value: id},
		Attributes:   []string{"objectClass"},
		IncludeTier0: needTier0,
	}
	var dsa []byte
	if nc := string(target.NC); nc != "" {
		ncb, err := parseUUID(nc)
		if err != nil {
			return ObjectRead{}, fmt.Errorf("%w: naming context", ErrInvalidOp)
		}
		req.NcGuid = &connectorv1.Guid{Value: ncb}
	}
	if len(pins) > 0 {
		if target.NC == "" || pins[target.NC] == "" {
			return ObjectRead{}, ErrReadPin
		}
		dsa, err = parseUUID(authority.DSAPinsFrom(ctx)[target.NC])
		if err != nil || allZero(dsa) {
			return ObjectRead{}, ErrReadPin
		}
		req.Dc = &connectorv1.DcSelection{PinnedDsaGuid: &connectorv1.Guid{Value: dsa}}
	}

	return r.read(ctx, req, id, needTier0, dsa)
}

// read folds the Read stream: exactly one header, then chunks, then one completed; anything else is
// a protocol error. OBJECT_NOT_FOUND is an answer (Exists false); every other error is an error.
func (r *ConnectorReads) read(ctx context.Context, req *connectorv1.ReadRequest, want []byte, needTier0 bool, pin []byte) (ObjectRead, error) {
	st, err := r.tr.Read(ctx, req)
	if err != nil {
		return notFoundOr(err)
	}
	var (
		out       ObjectRead
		header    bool
		completed bool
	)
	for {
		m, err := st.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return notFoundOr(err)
		}
		if completed {
			return ObjectRead{}, ErrReadProtocol
		}
		switch ev := m.GetEvent().(type) {
		case *connectorv1.ReadResponse_Header:
			if header || ev.Header.GetEntry() == nil {
				return ObjectRead{}, ErrReadProtocol
			}
			e := ev.Header.GetEntry()
			if string(e.GetObjectGuid().GetValue()) != string(want) {
				return ObjectRead{}, ErrReadIdentity
			}
			// A pinned read is served by the pinned DC or fails: a header that names another DC
			// (or none) is refused, never accepted as an answer from the wrong replica.
			if len(pin) != 0 {
				dsa := ev.Header.GetObserved().GetDc().GetDsaGuid().GetValue()
				if string(dsa) != string(pin) {
					return ObjectRead{}, ErrReadPin
				}
			}
			// The verdict is present exactly when asked for; a missing one is an error, never false.
			if needTier0 {
				if ev.Header.GetTier0() == nil {
					return ObjectRead{}, ErrNoTier0Verdict
				}
				out.Tier0 = ev.Header.GetTier0().GetTier0()
			} else if ev.Header.GetTier0() != nil {
				return ObjectRead{}, ErrReadProtocol
			}
			header = true
			out.Exists = true
			if p := e.GetParentGuid().GetValue(); len(p) != 0 {
				if len(p) != 16 || allZero(p) {
					return ObjectRead{}, ErrReadProtocol
				}
				out.Parent = formatUUID(p)
			}
		case *connectorv1.ReadResponse_Chunk:
			if !header {
				return ObjectRead{}, ErrReadProtocol
			}
		case *connectorv1.ReadResponse_Completed:
			if !header {
				return ObjectRead{}, ErrReadProtocol
			}
			completed = true
		default:
			return ObjectRead{}, ErrReadProtocol
		}
	}
	if !header || !completed {
		return ObjectRead{}, ErrReadProtocol // a stream that ends early is an incomplete read
	}
	return out, nil
}

func notFoundOr(err error) (ObjectRead, error) {
	var re *RemoteError
	if errors.As(FromStatus(err), &re) && re.Err.GetCode() == connectorv1.ErrorCode_ERROR_CODE_OBJECT_NOT_FOUND {
		return ObjectRead{Exists: false}, nil
	}
	return ObjectRead{}, fmt.Errorf("client: connector read: %w", err)
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func formatUUID(b []byte) string {
	const hexd = "0123456789abcdef"
	out := make([]byte, 0, 36)
	for i, c := range b {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			out = append(out, '-')
		}
		out = append(out, hexd[c>>4], hexd[c&15])
	}
	return string(out)
}
