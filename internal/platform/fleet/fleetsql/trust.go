package fleetsql

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Anchor is one tenant's CA certificate as the gateway's client-CA pool holds it.
type Anchor struct {
	Tenant tenant.ID
	Cert   *x509.Certificate
}

// TrustAnchors reads every tenant's active and retired, unexpired CA certificates in one platform-scope
// call to fleet_ca_trust_anchors() (migration 0054; fleet-contract 'Gateway client-CA pool'). That
// SECURITY DEFINER function is the only path to those rows and its owner role cannot read sealed_key, so
// no key material is reachable from here. This is the one WithPlatform site of that function.
type TrustAnchors struct {
	DB     *store.DB
	Alerts Alerter // optional: raised once per tenant whose stored certificate fails validation
}

// Load returns the anchors that validate. A row that does not parse as a CA certificate (strict DER, no
// PEM, no private-key marker) or whose pin does not match its stored SPKI hash is left out and raises
// AlertCAMaterial for its tenant: one bad tenant must not take the rest of the fleet out of the pool.
func (t *TrustAnchors) Load(ctx context.Context) ([]Anchor, error) {
	if t == nil || t.DB == nil {
		return nil, errors.New("fleetsql: trust anchors are not configured")
	}
	var out []Anchor
	err := t.DB.WithPlatform(ctx, "fleet: load every tenant's CA certificates for the gateway client-CA pool", func(ctx context.Context, tx store.Tx) error {
		rows, err := tx.Query(ctx, `SELECT tenant_id::text, spki_sha256, cert_der FROM public.fleet_ca_trust_anchors()`)
		if err != nil {
			return fmt.Errorf("fleetsql: read trust anchors: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var (
				tid      string
				pin, der []byte
			)
			if err := rows.Scan(&tid, &pin, &der); err != nil {
				return fmt.Errorf("fleetsql: read trust anchors: %w", err)
			}
			id, perr := tenant.Parse(tid)
			if perr != nil {
				return fmt.Errorf("fleetsql: read trust anchors: %w", perr)
			}
			cert, exposure, perr := parseStoredCert(der)
			if exposure {
				t.raise(ctx, AlertCAKeyExposure, id)
			}
			if perr == nil {
				if sum := pinBytes(cert); len(pin) != len(sum) || string(pin) != string(sum[:]) {
					perr = errCAIntegrity
				}
			}
			if perr != nil {
				t.raise(ctx, AlertCAMaterial, id)
				continue
			}
			out = append(out, Anchor{Tenant: id, Cert: cert})
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (t *TrustAnchors) raise(ctx context.Context, k AlertKind, id tenant.ID) {
	if t.Alerts != nil {
		t.Alerts.Raise(ctx, Alert{Kind: k, Tenant: id})
	}
}
