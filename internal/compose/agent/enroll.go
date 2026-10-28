package agent

import (
	"context"
	"errors"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/skenzeriq/activediq/internal/platform/fleet/dial"
	fleetv1 "github.com/skenzeriq/activediq/internal/proto/activediq/fleet/v1"
)

// Enroll runs the client side of enrolment with the single-use token. The token comes from the
// caller (the CLI reads it from stdin, never argv) and is not retained. The state lands in the
// enrolment directory named by the local configuration.
func Enroll(ctx context.Context, m dial.Material) error {
	path := os.Getenv(ConfigEnv)
	if path == "" {
		return ErrNoConfig
	}
	loc, err := LoadLocal(path)
	if err != nil {
		return err
	}
	if _, err := dial.Enroll(ctx, m, loc.EnrollmentDir, exchange); err != nil {
		return err
	}
	return nil
}

func exchange(ctx context.Context, creds credentials.TransportCredentials, addr, token string, csr []byte) (dial.Response, error) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return dial.Response{}, err
	}
	defer conn.Close()
	r, err := fleetv1.NewFleetClient(conn).Enroll(ctx, &fleetv1.EnrollRequest{EnrollmentToken: token, CsrDer: csr})
	if err != nil {
		return dial.Response{}, err
	}
	out := dial.Response{LeafDER: r.GetLeafCertificateDer(), CABundlePEM: r.GetCaBundlePem()}
	for _, e := range r.GetEndpoints() {
		if e.GetPort() == 0 || e.GetPort() > 65535 {
			return dial.Response{}, errors.New("agent: server returned an invalid endpoint")
		}
		out.Endpoints = append(out.Endpoints, dial.Endpoint{Host: e.GetHost(), Port: uint16(e.GetPort())})
	}
	return out, nil
}
