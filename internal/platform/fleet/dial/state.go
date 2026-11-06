package dial

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/ownerfile"
)

// Files of the component's enrollment state directory.
const (
	CAFile        = "ca-bundle.pem"
	PinFile       = "ca-pin.txt"
	LeafFile      = "leaf.pem"
	KeyFile       = "key.pem"
	EndpointsFile = "endpoints.txt"
)

// ErrState: the state directory is missing, incomplete or unsafe. It names the problem, never content.
var ErrState = errors.New("dial: enrollment state is not usable")

// ErrExpired: the component certificate (or the CA) is outside its validity period. Distinct from
// ErrState so a caller can start renewal instead of reporting corruption.
var ErrExpired = errors.New("dial: component certificate has expired")

// Endpoint is where the component dials the server.
type Endpoint struct {
	Host string
	Port uint16
}

// State is a complete, validated enrollment: the pinned server CA (Roots, the only TLS roots), the
// tenant client CAs (ClientCAs, used only to check our leaf), the component's leaf and key, and the
// server endpoints.
type State struct {
	Pin       Pin
	Roots     []*x509.Certificate
	ClientCAs []*x509.Certificate
	Leaf      tls.Certificate
	Endpoints []Endpoint
}

// save persists a verified enrollment into dir, each file by write-to-temp then rename through the
// held directory handle (ownerfile.Dir.WriteFile): the temp file is created owner-only, never with an
// inherited ACL, so the key is never in a file anyone else can read. The directory's parent is
// verified before anything is written. The leaf is written last, so a crash midway leaves a directory
// Load refuses rather than a half-enrolled component.
func save(dir string, pin Pin, bundlePEM []byte, leafDER []byte, keyDER []byte, eps []Endpoint) error {
	d, err := ownerfile.CreateDir(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	var epText strings.Builder
	for _, e := range eps {
		epText.WriteString(net.JoinHostPort(e.Host, strconv.Itoa(int(e.Port))) + "\n")
	}
	steps := []struct {
		name string
		data []byte
	}{
		{CAFile, bundlePEM},
		{PinFile, []byte(pin.String() + "\n")},
		{EndpointsFile, []byte(epText.String())},
		{KeyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})},
		{LeafFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})},
	}
	for _, s := range steps {
		if err := d.WriteFile(s.name, s.data); err != nil {
			return err
		}
	}
	return nil
}

// Load reads and re-validates the state in dir: unsafe permissions, a bundle that breaks rule D3 or
// lacks the recorded pin, or a leaf that does not match the key or verify against the bundle are all
// ErrState. A missing component is not enrolled.
//
// The directory is opened once, with its parent verified (ownerfile.OpenDir), and every file is read
// through that handle (T-1315): nothing is checked by path and then used by path, so a directory
// swapped for a junction or symlink after the check cannot supply the pin, bundle, key or leaf.
func Load(dir string) (*State, error) {
	d, err := ownerfile.OpenDir(dir)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrState, err)
	}
	defer d.Close()
	return load(d)
}

func load(d *ownerfile.Dir) (*State, error) {
	read := func(name string) ([]byte, error) {
		b, err := d.ReadFile(name)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrState, err)
		}
		return b, nil
	}
	pinB, err := read(PinFile)
	if err != nil {
		return nil, err
	}
	pin, err := ParsePin(strings.TrimSpace(string(pinB)))
	if err != nil {
		return nil, ErrState
	}
	bundle, err := read(CAFile)
	if err != nil {
		return nil, err
	}
	bun, err := ParseBundle(bundle, pin)
	if err != nil {
		return nil, ErrState
	}
	keyPEM, err := read(KeyFile)
	if err != nil {
		return nil, err
	}
	leafPEM, err := read(LeafFile)
	if err != nil {
		return nil, err
	}
	pair, err := tls.X509KeyPair(leafPEM, keyPEM)
	if err != nil {
		return nil, ErrState
	}
	pair.Leaf, err = x509.ParseCertificate(pair.Certificate[0])
	if err != nil || len(pair.Certificate) != 1 {
		return nil, ErrState
	}
	if _, err := pair.Leaf.Verify(x509.VerifyOptions{Roots: Pool(bun.ClientCAs), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: time.Now()}); err != nil {
		var ci x509.CertificateInvalidError
		if errors.As(err, &ci) && ci.Reason == x509.Expired {
			return nil, ErrExpired // the renewal flow re-enrols; never dial with it
		}
		return nil, ErrState
	}
	epB, err := read(EndpointsFile)
	if err != nil {
		return nil, err
	}
	eps, err := parseEndpoints(string(epB))
	if err != nil {
		return nil, ErrState
	}
	return &State{Pin: pin, Roots: bun.Roots, ClientCAs: bun.ClientCAs, Leaf: pair, Endpoints: eps}, nil
}
