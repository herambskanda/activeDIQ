package dial

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
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

// ErrAbsent: there is no enrolment yet (the directory, or one of its files, does not exist). It is the
// only Load failure that means "not enrolled"; every other failure is state that exists and cannot be
// used, which an operator has to hear about (T-1249). An ErrAbsent is also an ErrState.
var ErrAbsent = errors.New("dial: not enrolled")

// ErrIncomplete: some of the state files exist and others do not, which is what a reader sees while
// `enroll` is still writing (the leaf is written last) or after a crash midway. It is also an
// ErrAbsent (not enrolled yet) and an ErrState; a caller that polls can re-check soon instead of
// waiting a full interval.
var ErrIncomplete = errors.New("dial: enrollment is incomplete")

// ErrUnsafe: the state exists but its owner, DACL/mode or file type is not one this component accepts
// (squatted, widened, planted, or written for another identity). An ErrUnsafe is also an ErrState.
var ErrUnsafe = errors.New("dial: enrollment state has unsafe ownership or permissions")

// stateErr classifies a failure of the ownerfile checks: a missing path is ErrAbsent, anything else is
// ErrUnsafe. Both also match ErrState. The underlying text names a path component, never content.
func stateErr(err error) error {
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w (%w): %v", ErrAbsent, ErrState, err)
	}
	return fmt.Errorf("%w (%w): %v", ErrUnsafe, ErrState, err)
}

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
func save(dir string, pin Pin, bundlePEM []byte, leafDER []byte, keyDER []byte, eps []Endpoint, opts ...ownerfile.DirOption) error {
	d, err := ownerfile.CreateDir(dir, opts...)
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
//
// Failures are classified (T-1249): ErrAbsent (nothing there; ErrIncomplete if enrolment is partly
// written), ErrUnsafe (present but owned or permissioned wrongly, for example written for another
// identity), ErrExpired, and plain ErrState (present but unparsable or inconsistent). Only ErrAbsent
// means "not enrolled". State an administrator wrote for the service (ForAccount) is accepted: the
// directory may be owned by BUILTIN\Administrators and name them.
func Load(dir string) (*State, error) {
	d, err := ownerfile.OpenDir(dir, ownerfile.TrustAdministrators())
	if err != nil {
		return nil, stateErr(err)
	}
	defer d.Close()
	return load(d)
}

var stateFiles = []string{CAFile, PinFile, EndpointsFile, KeyFile, LeafFile}

func load(d *ownerfile.Dir) (*State, error) {
	read := func(name string) ([]byte, error) {
		b, err := d.ReadFile(name)
		if err == nil {
			return b, nil
		}
		if errors.Is(err, fs.ErrNotExist) {
			// A missing file while others exist is `enroll` mid-write (or a crash): say so.
			for _, other := range stateFiles {
				if other == name {
					continue
				}
				if _, oerr := d.ReadFile(other); oerr == nil || !errors.Is(oerr, fs.ErrNotExist) {
					return nil, fmt.Errorf("%w (%w): %v", ErrIncomplete, errors.Join(ErrAbsent, ErrState), err)
				}
			}
		}
		return nil, stateErr(err)
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
