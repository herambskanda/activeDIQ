package dial

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc/credentials"

	"github.com/skenzeriq/activediq/internal/platform/fleet"
)

// Material is what the administrator hands the host: the server address, the single-use token and the
// pin of the installation CA (TM-D24 rule D1). There is no option to skip the pin.
type Material struct {
	Address string // host:port of the Enroll endpoint
	Token   string
	Pin     string // sha256:<hex>
}

// Response is the server's answer to Enroll, translated from the wire message by the role package.
type Response struct {
	LeafDER     []byte
	CABundlePEM []byte
	Endpoints   []Endpoint
}

// Exchange performs the Enroll RPC over creds, which verify the server against the pinned CA. The
// role package implements it with the generated client; this package never sees the proto.
type Exchange func(ctx context.Context, creds credentials.TransportCredentials, addr, token string, csrDER []byte) (Response, error)

// Enroll runs the whole client side of enrollment and persists the result in dir only if all of it
// verified:
//
//  1. a private key is generated here (ECDSA P-256) and stays in this process;
//  2. the server's presented chain must contain the CA with the pinned SPKI, which becomes the only
//     root; the token is sent only over a connection verified against it (no skip option, no retry
//     and no fallback on failure);
//  3. the returned bundle is parsed strictly (rule D3) and must contain the pinned CA;
//  4. the returned leaf must match our key, verify to that bundle and carry a component identity.
//
// Any failure persists nothing. The key and token never appear in an error.
func Enroll(ctx context.Context, m Material, dir string, ex Exchange) (*State, error) {
	pin, err := ParsePin(m.Pin)
	if err != nil {
		return nil, err
	}
	host, _, err := net.SplitHostPort(m.Address)
	if err != nil || host == "" || m.Token == "" || ex == nil {
		return nil, errors.New("dial: enrollment material is incomplete")
	}
	// Fail before the single-use token is spent if this host cannot store the key safely.
	if err := ensureDir(dir); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrState, err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("dial: generating key: %w", err)
	}
	// The subject is empty: the server decides the identity from the token and puts it in the SAN.
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return nil, fmt.Errorf("dial: building certificate request: %w", err)
	}
	root, err := pinnedRoot(ctx, m.Address, host, pin)
	if err != nil {
		return nil, err
	}
	creds := credentials.NewTLS(clientTLS(Pool([]*x509.Certificate{root}), host, nil))
	resp, err := ex(ctx, creds, m.Address, m.Token, csr)
	if err != nil {
		return nil, err
	}
	ca, err := ParseBundle(resp.CABundlePEM, pin)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(resp.LeafDER)
	if err != nil {
		return nil, ErrLeaf
	}
	if err := checkLeaf(leaf, key, ca); err != nil {
		return nil, err
	}
	eps, err := checkEndpoints(resp.Endpoints)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("dial: encoding key: %w", err)
	}
	if err := save(dir, pin, resp.CABundlePEM, resp.LeafDER, keyDER, eps); err != nil {
		return nil, fmt.Errorf("dial: persisting enrollment: %w", err)
	}
	return Load(dir)
}

// ErrLeaf: the returned leaf is not ours, not from the pinned CA, or carries no component identity.
var ErrLeaf = errors.New("dial: server returned an unusable component certificate")

func checkLeaf(leaf *x509.Certificate, key *ecdsa.PrivateKey, ca []*x509.Certificate) error {
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(key.Public()) {
		return ErrLeaf
	}
	if _, err := fleet.IdentityOf(leaf); err != nil {
		return ErrLeaf
	}
	opts := x509.VerifyOptions{Roots: Pool(ca), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: time.Now()}
	if _, err := leaf.Verify(opts); err != nil {
		return ErrLeaf
	}
	return nil
}

const maxEndpoints = 16

func checkEndpoints(in []Endpoint) ([]Endpoint, error) {
	if len(in) == 0 || len(in) > maxEndpoints {
		return nil, errors.New("dial: server returned no usable endpoints")
	}
	for _, e := range in {
		if e.Host == "" || e.Port == 0 || strings.ContainsAny(e.Host, " \t\r\n/") {
			return nil, errors.New("dial: server returned an invalid endpoint")
		}
	}
	return in, nil
}

func parseEndpoints(s string) ([]Endpoint, error) {
	var out []Endpoint
	for _, line := range strings.Split(strings.TrimSpace(s), "\n") {
		h, p, err := net.SplitHostPort(line)
		n, perr := strconv.ParseUint(p, 10, 16)
		if err != nil || perr != nil {
			return nil, ErrState
		}
		out = append(out, Endpoint{Host: h, Port: uint16(n)})
	}
	return checkEndpoints(out)
}
