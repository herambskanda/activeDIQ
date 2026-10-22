package graph

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"time"
)

// Credential is the customer's app-registration certificate and its private key. The key is held as a
// crypto.Signer so it can live in a KMS or TPM; it must be an RSA key (RS256 assertions).
type Credential struct {
	Cert *x509.Certificate
	Key  crypto.Signer
}

// String and GoString keep the credential out of logs and %v dumps.
func (Credential) String() string   { return "graph.Credential{redacted}" }
func (Credential) GoString() string { return "graph.Credential{redacted}" }

const assertionTTL = 5 * time.Minute

var b64 = base64.RawURLEncoding

// buildAssertion makes the RFC 7523 client assertion: a JWT signed RS256 with the registered
// certificate, x5t#S256 identifying it, iss = sub = client id, aud = the tenant's token endpoint.
func buildAssertion(c Credential, clientID, audience string, now time.Time, jti string) (string, error) {
	if c.Cert == nil || c.Key == nil {
		return "", newErr(CodeInvalidArgument, 0, "certificate credential is incomplete", nil)
	}
	if _, ok := c.Key.Public().(*rsa.PublicKey); !ok {
		return "", newErr(CodeInvalidArgument, 0, "certificate key must be RSA", nil)
	}
	thumb := sha256.Sum256(c.Cert.Raw)
	hdr, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "x5t#S256": b64.EncodeToString(thumb[:])})
	claims, _ := json.Marshal(map[string]any{
		"aud": audience, "iss": clientID, "sub": clientID, "jti": jti,
		"nbf": now.Unix() - 30, "iat": now.Unix(), "exp": now.Add(assertionTTL).Unix(),
	})
	signing := b64.EncodeToString(hdr) + "." + b64.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signing))
	sig, err := c.Key.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return "", newErr(CodeBindFailed, 0, "signing the client assertion failed", err)
	}
	return signing + "." + b64.EncodeToString(sig), nil
}
