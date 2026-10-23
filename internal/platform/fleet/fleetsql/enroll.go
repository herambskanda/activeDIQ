package fleetsql

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/audit/chain"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/fleet"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

const (
	// DefaultLeafTTL is how long a component certificate lives before the component must rotate.
	DefaultLeafTTL = 90 * 24 * time.Hour
	clockSkew      = 5 * time.Minute
)

// Errors of Enroll and Rotate beyond those of Redeem.
var (
	// ErrCSR: the certificate request is malformed, badly signed or asks for a key we do not accept.
	// It says nothing about the token, so it is no oracle for one.
	ErrCSR = errors.New("fleetsql: certificate request is not acceptable")
	// ErrRotateRefused: the presented certificate is not the component's current one (superseded, or
	// the component is not enrolled or active). One answer for every cause.
	ErrRotateRefused = errors.New("fleetsql: certificate cannot be renewed")
)

// Endpoint is where a component dials its tunnel.
type Endpoint struct {
	Host string
	Port uint16
}

// Enroller serves the server side of the Enroll RPC (TM-TB6-T1, TM-A11): it redeems a token, signs a
// leaf certificate whose SAN names the token's tenant and component and nothing else, and returns the
// CA bundle. It owns no transport: the gateway passes the transport peer address and the bytes.
type Enroller struct {
	Enrollment *Enrollment
	Keys       KeySource  // the tenant DEK that seals the CA key
	Alerts     Alerter    // installation alerts (TM-D24 D2)
	Audit      audit.Sink // enrolment is recorded in the same transaction that makes it
	Endpoints  []Endpoint // returned to the component, in preference order
	LeafTTL    time.Duration
	Clock      func() time.Time // tests only
}

// Enrolled is what the component receives.
type Enrolled struct {
	LeafDER     []byte
	CABundlePEM []byte
	Endpoints   []Endpoint
	NotAfter    time.Time
	Identity    fleet.Identity // what the leaf says, for the caller's own records; not sent
}

func (e *Enroller) now() time.Time {
	if e.Clock != nil {
		return e.Clock()
	}
	return time.Now()
}

func (e *Enroller) ready() error {
	if e == nil || e.Keys == nil || e.Alerts == nil || e.Audit == nil {
		return ErrNotConfigured
	}
	return e.Enrollment.ready()
}

// Enroll redeems tokenText for source (the transport peer address, never a header) and enrols the
// component the token was issued for. The tenant, the component and its kind come from the token's
// own row; the request names none of them (TM-TB6-T3). Redemption, the certificate, the Component's
// pending to enrolled write and the audit event are one transaction: if the CA cannot sign, the token
// is not burned. An unknown, expired, used or revoked token, and a CA whose stored material fails
// validation, all return ErrTokenInvalid.
func (e *Enroller) Enroll(ctx context.Context, source, tokenText string, csrDER []byte) (Enrolled, error) {
	if err := e.ready(); err != nil {
		return Enrolled{}, err
	}
	pub, err := ParseCSR(csrDER)
	if err != nil {
		return Enrolled{}, ErrCSR
	}
	var out Enrolled
	_, err = e.Enrollment.redeemWith(ctx, source, ParseToken(tokenText), func(ctx context.Context, tx store.Tx, r Redeemed) error {
		iss, err := e.issue(ctx, tx, r.TenantID, string(r.Kind), r.ComponentID, pub)
		if err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE public.components SET state = 'enrolled', cert_serial = $2, updated_at = now()
			WHERE id = $1::uuid AND state = 'pending'`, r.ComponentID, iss.Identity.Serial)
		if err != nil {
			return fmt.Errorf("fleetsql: enrol component: %w", err)
		}
		if tag.RowsAffected() != 1 {
			return ErrTokenInvalid
		}
		out = iss
		return e.audit(ctx, tx, "fleet.component.enrolled", iss.Identity)
	})
	if err != nil {
		return Enrolled{}, publicErr(err)
	}
	return out, nil
}

// Rotate renews the certificate of an enrolled component that presents its current one. peer is the
// leaf is the client certificate the gateway has already verified. A chain that verifies only proves
// that some tenant's CA signed it, so Rotate reads the identity from the leaf itself and requires that
// one of the named tenant's own CAs (active or retired) signed it; otherwise one tenant's CA key
// could mint an identity in another tenant. Rotate trusts nothing else about the caller. The Component row, and so its
// identity, is kept (DM-12.I3); only cert_serial changes. A certificate that is not the current one
// (an earlier generation, a revoked or removed component) is refused.
func (e *Enroller) Rotate(ctx context.Context, leaf *x509.Certificate, csrDER []byte) (Enrolled, error) {
	if err := e.ready(); err != nil {
		return Enrolled{}, err
	}
	pub, err := ParseCSR(csrDER)
	if err != nil {
		return Enrolled{}, ErrCSR
	}
	peer, err := fleet.IdentityOf(leaf)
	if err != nil || peer.Tenant.IsZero() || peer.ComponentID == "" || peer.Serial == "" {
		return Enrolled{}, ErrRotateRefused
	}
	var out Enrolled
	err = e.Enrollment.DB.WithTenant(ctx, peer.Tenant, func(ctx context.Context, tx store.Tx) error {
		cas, err := e.ensureCA(ctx, tx, peer.Tenant)
		if err != nil {
			return err
		}
		signedByTenant := false
		for _, c := range cas {
			if leaf.CheckSignatureFrom(c.cert) == nil {
				signedByTenant = true
				break
			}
		}
		if !signedByTenant {
			return ErrRotateRefused
		}
		var kind, state string
		var serial *string
		err = tx.QueryRow(ctx, `SELECT kind, state, cert_serial FROM public.components WHERE id = $1::uuid FOR UPDATE`,
			peer.ComponentID).Scan(&kind, &state, &serial)
		if store.IsNoRows(err) {
			return ErrRotateRefused
		}
		if err != nil {
			return fmt.Errorf("fleetsql: rotate: %w", err)
		}
		if kind != peer.Kind || (state != "enrolled" && state != "active") || serial == nil || *serial != peer.Serial {
			return ErrRotateRefused
		}
		iss, err := e.issue(ctx, tx, peer.Tenant, kind, peer.ComponentID, pub)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE public.components SET cert_serial = $2, updated_at = now() WHERE id = $1::uuid`,
			peer.ComponentID, iss.Identity.Serial); err != nil {
			return fmt.Errorf("fleetsql: rotate: %w", err)
		}
		out = iss
		return e.audit(ctx, tx, "fleet.component.certificate_rotated", iss.Identity)
	})
	if err != nil {
		return Enrolled{}, publicErr(err)
	}
	return out, nil
}

// publicErr maps stored-CA validation failures to the one generic answer, so a caller learns nothing
// about the installation; other errors pass through.
func publicErr(err error) error {
	if errors.Is(err, errCAIntegrity) {
		return ErrTokenInvalid
	}
	return err
}

// CAPin returns the "sha256:<hex>" pin of the tenant's CA public key for the enrolment material
// (TM-D24 D1), creating the CA the first time. Call it inside the issuing flow's tenant transaction.
func (e *Enroller) CAPin(ctx context.Context, tx store.Tx, tid tenant.ID) (string, error) {
	if err := e.ready(); err != nil {
		return "", err
	}
	cas, err := e.ensureCA(ctx, tx, tid)
	if err != nil {
		return "", err
	}
	if len(cas) == 0 || !cas[0].active {
		return "", errCAIntegrity
	}
	return PinOf(cas[0].cert), nil
}

// InitTenant is a tenant initialiser (provision.Initialiser): it creates the tenant's CA so the first
// Enroll does not.
func (e *Enroller) InitTenant(ctx context.Context, tx store.Tx, tid tenant.ID) error {
	_, err := e.CAPin(ctx, tx, tid)
	return err
}

// issue signs the leaf and builds the bundle inside tx.
func (e *Enroller) issue(ctx context.Context, tx store.Tx, tid tenant.ID, kind, componentID string, pub crypto.PublicKey) (Enrolled, error) {
	cas, err := e.ensureCA(ctx, tx, tid)
	if err != nil {
		return Enrolled{}, err
	}
	if len(cas) == 0 || !cas[0].active {
		e.Alerts.Raise(ctx, Alert{Kind: AlertCAMaterial, Tenant: tid})
		return Enrolled{}, errCAIntegrity
	}
	bundle, err := bundlePEM(cas)
	if err != nil {
		e.Alerts.Raise(ctx, Alert{Kind: AlertCAMaterial, Tenant: tid})
		return Enrolled{}, err
	}
	signer, err := e.signer(ctx, tx, tid, cas[0])
	if err != nil {
		if errors.Is(err, errCAIntegrity) {
			e.Alerts.Raise(ctx, Alert{Kind: AlertCAMaterial, Tenant: tid})
		}
		return Enrolled{}, err
	}
	serial, err := newSerial()
	if err != nil {
		return Enrolled{}, err
	}
	ttl := e.LeafTTL
	if ttl <= 0 {
		ttl = DefaultLeafTTL
	}
	now := e.now()
	notAfter := now.Add(ttl)
	if notAfter.After(cas[0].cert.NotAfter) {
		notAfter = cas[0].cert.NotAfter
	}
	// Subject and SAN come from the token's row, never from the request. The SAN holds the tenant and
	// the component and nothing else.
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  fleet.URIs(tid, kind, componentID),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, cas[0].cert, pub, signer)
	if err != nil {
		return Enrolled{}, fmt.Errorf("fleetsql: sign leaf: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return Enrolled{}, fmt.Errorf("fleetsql: sign leaf: %w", err)
	}
	id, err := fleet.IdentityOf(leaf)
	if err != nil {
		return Enrolled{}, fmt.Errorf("fleetsql: sign leaf: %w", err)
	}
	return Enrolled{LeafDER: der, CABundlePEM: bundle, Endpoints: append([]Endpoint(nil), e.Endpoints...), NotAfter: leaf.NotAfter, Identity: id}, nil
}

var componentActor = func(id string) authority.Chain {
	return authority.Chain{Requester: authority.Principal{ID: authority.PrincipalID("component:" + id), Kind: authority.System}}
}

func (e *Enroller) audit(ctx context.Context, tx store.Tx, kind audit.Kind, id fleet.Identity) error {
	return e.Audit.Append(ctx, tx, audit.Event{
		ID:        string(kind) + "." + id.ComponentID + "." + id.Serial,
		Kind:      kind,
		At:        e.now(),
		Actor:     componentActor(id.ComponentID),
		Target:    authority.TargetRef{GUID: id.ComponentID, Class: "component"},
		Component: "fleet",
		Outcome:   audit.Success,
		Details:   []chain.Detail{{Key: "cert_serial", Value: id.Serial}, {Key: "component_kind", Value: id.Kind}},
	})
}
