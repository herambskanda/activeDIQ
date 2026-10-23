package dial

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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

// Endpoint is where the component dials the server.
type Endpoint struct {
	Host string
	Port uint16
}

// State is a complete, validated enrollment: the pinned CA bundle, the component's leaf and key, and
// the server endpoints.
type State struct {
	Pin       Pin
	CA        []*x509.Certificate
	Leaf      tls.Certificate
	Endpoints []Endpoint
}

// Save persists a verified enrollment into dir (created 0700), each file by write-to-temp then rename.
// The key is written first-class with mode 0600; the leaf is written last, so a crash midway leaves a
// directory Load refuses rather than a half-enrolled component.
func save(dir string, pin Pin, bundlePEM []byte, leafDER []byte, keyDER []byte, eps []Endpoint) error {
	if err := ensureDir(dir); err != nil {
		return err
	}
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
		if err := writeFile(filepath.Join(dir, s.name), s.data); err != nil {
			return err
		}
	}
	return nil
}

// Load reads and re-validates the state in dir: unsafe permissions, a bundle that breaks rule D3 or
// lacks the recorded pin, or a leaf that does not match the key or verify against the bundle are all
// ErrState. A missing component is not enrolled.
func Load(dir string) (*State, error) {
	if err := checkDir(dir); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrState, err)
	}
	read := func(name string, secret bool) ([]byte, error) {
		p := filepath.Join(dir, name)
		if err := checkFile(p, secret); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrState, err)
		}
		return os.ReadFile(p)
	}
	pinB, err := read(PinFile, false)
	if err != nil {
		return nil, err
	}
	pin, err := ParsePin(strings.TrimSpace(string(pinB)))
	if err != nil {
		return nil, ErrState
	}
	bundle, err := read(CAFile, false)
	if err != nil {
		return nil, err
	}
	ca, err := ParseBundle(bundle, pin)
	if err != nil {
		return nil, ErrState
	}
	keyPEM, err := read(KeyFile, true)
	if err != nil {
		return nil, err
	}
	leafPEM, err := read(LeafFile, false)
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
	if _, err := pair.Leaf.Verify(x509.VerifyOptions{Roots: Pool(ca), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: pair.Leaf.NotBefore}); err != nil {
		return nil, ErrState
	}
	epB, err := read(EndpointsFile, false)
	if err != nil {
		return nil, err
	}
	eps, err := parseEndpoints(string(epB))
	if err != nil {
		return nil, ErrState
	}
	return &State{Pin: pin, CA: ca, Leaf: pair, Endpoints: eps}, nil
}
