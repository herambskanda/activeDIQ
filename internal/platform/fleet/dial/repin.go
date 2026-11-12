package dial

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/skenzeriq/activediq/internal/platform/ownerfile"
)

// ErrRepin: the new pin could not be adopted. Nothing the component trusts has changed unless the
// error says otherwise; the existing identity (key and leaf) is never touched.
var ErrRepin = errors.New("dial: cannot adopt the new pin")

// RepinEvent is the audit record of one use of Repin. It is delivered exactly once per call that got
// past argument parsing, on success and on failure. It holds pins (public values), never key material.
type RepinEvent struct {
	OldPin Pin
	NewPin Pin
	Err    error // nil on success
}

// Repin moves an enrolled component to a new server-CA pin received out of band (ADR-0008
// obligation 5), keeping its identity: the key and leaf are not regenerated, no token is spent.
//
// The new root is obtained exactly as at enrolment: from the chain a configured endpoint presents,
// accepting only the certificate whose SPKI matches newPin and has the server-root shape, and then
// proving the endpoint fully verifies against it (name, validity, ServerAuth). The state is rewritten
// so that every intermediate on-disk state loads (old pin + bundle holding both roots, then new pin,
// then the bundle without the old root): a crash leaves a working component, never a half-pinned one.
// The old root is left in the bundle only as a non-root until the last step removes it. audit is
// called once with the outcome.
//
// ForAccount must be passed when the state was written for the service by an administrator (Enroll with
// ForAccount): the caller is then not the identity the state names.
func Repin(ctx context.Context, dir string, newPin string, audit func(RepinEvent), opts ...Option) error {
	var o enrollOptions
	for _, f := range opts {
		f(&o)
	}
	if audit == nil {
		return errors.New("dial: repin requires an audit sink")
	}
	np, err := ParsePin(newPin)
	if err != nil {
		return err
	}
	// One verified, held handle for the whole operation: the state read here is the state rewritten
	// below, and the directory cannot be swapped between the two (T-1315).
	d, err := ownerfile.OpenDir(dir, o.dirOpts()...)
	if err != nil {
		return stateErr(err)
	}
	defer d.Close()
	st, err := load(d)
	if err != nil {
		return err // not enrolled or unusable: nothing to repin, and no pin to audit against
	}
	ev := RepinEvent{OldPin: st.Pin, NewPin: np}
	ev.Err = repin(ctx, d, st, np)
	audit(ev)
	return ev.Err
}

func repin(ctx context.Context, d *ownerfile.Dir, st *State, np Pin) error {
	if np == st.Pin {
		return fmt.Errorf("%w: it is already the current pin", ErrRepin)
	}
	root, err := findRoot(ctx, st.Endpoints, np)
	if err != nil {
		return err
	}
	// New bundle: the new root, then every certificate that is not a root today. The old roots are
	// kept for the transition bundle only.
	toPEM := func(cs ...*x509.Certificate) []byte {
		var b bytes.Buffer
		for _, c := range cs {
			_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
		}
		return b.Bytes()
	}
	final := append([]*x509.Certificate{root}, st.ClientCAs...)
	transition := append(append([]*x509.Certificate{}, st.Roots...), final...)
	if len(transition) > MaxBundleCerts {
		return fmt.Errorf("%w: bundle would exceed %d certificates", ErrRepin, MaxBundleCerts)
	}
	steps := []struct {
		name string
		data []byte
	}{
		{CAFile, toPEM(transition...)},
		{PinFile, []byte(np.String() + "\n")},
		{CAFile, toPEM(final...)},
	}
	// Every intermediate state must load: prove each bundle parses under the pin in force when it is
	// written (the transition under the old pin, the last under the new one) before anything is written.
	if _, err := ParseBundle(steps[0].data, st.Pin); err != nil {
		return fmt.Errorf("%w: transition bundle would not load: %v", ErrRepin, err)
	}
	if _, err := ParseBundle(steps[2].data, np); err != nil {
		return fmt.Errorf("%w: final bundle would not load: %v", ErrRepin, err)
	}
	for _, s := range steps {
		if err := d.WriteFile(s.name, s.data); err != nil {
			return fmt.Errorf("%w: persisting: %v", ErrRepin, err)
		}
	}
	if _, err := load(d); err != nil {
		return fmt.Errorf("%w: state does not reload: %v", ErrRepin, err)
	}
	return nil
}

// findRoot returns the pinned root presented by the first configured endpoint that both presents it
// and verifies against it as a ServerAuth server for the endpoint's host.
func findRoot(ctx context.Context, eps []Endpoint, pin Pin) (*x509.Certificate, error) {
	var last error = ErrUntrustedServer
	for _, e := range eps {
		addr := net.JoinHostPort(e.Host, strconv.Itoa(int(e.Port)))
		root, err := pinnedRoot(ctx, addr, e.Host, pin)
		if err != nil {
			last = err
			continue
		}
		d := tls.Dialer{Config: clientTLS(Pool([]*x509.Certificate{root}), e.Host, nil)}
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			last = ErrUntrustedServer
			continue
		}
		conn.Close()
		return root, nil
	}
	return nil, fmt.Errorf("%w: %v", ErrRepin, last)
}
