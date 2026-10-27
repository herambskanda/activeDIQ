package oidc

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json/v2"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/authn/sso"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

const (
	issuer   = "https://idp.example.test"
	clientID = "adq-console"
	kid      = "k1"
)

var (
	keyOnce  sync.Once
	idpKey   *rsa.PrivateKey // the IdP's signing key
	evilKey  *rsa.PrivateKey // an attacker's key
	weakKey  *rsa.PrivateKey // RSA-1024
	baseTime = time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
)

func keys(t *testing.T) {
	t.Helper()
	keyOnce.Do(func() {
		var err error
		if idpKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
		if evilKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
		if weakKey, err = rsa.GenerateKey(rand.Reader, 1024); err != nil {
			panic(err)
		}
	})
}

func jwk(pub *rsa.PublicKey, kid string) map[string]any {
	return map[string]any{
		"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
		"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

// harness is a stub IdP behind the HTTPClient seam. No sockets.
type harness struct {
	t     *testing.T
	now   time.Time
	v     *Verifier
	mu    sync.Mutex
	calls map[string]int
	forms []url.Values
	auths []string

	jwksKeys  []map[string]any
	tokenBody func(h *harness) (int, []byte) // the token endpoint
	idToken   string                         // raw id_token the token endpoint returns
	cfg       sso.OIDCConfig
}

func newHarness(t *testing.T) *harness {
	keys(t)
	h := &harness{t: t, now: baseTime, calls: map[string]int{}}
	h.jwksKeys = []map[string]any{jwk(&idpKey.PublicKey, kid)}
	h.tokenBody = func(h *harness) (int, []byte) {
		b, _ := json.Marshal(map[string]any{"id_token": h.idToken, "access_token": "at", "token_type": "Bearer"})
		return 200, b
	}
	h.v = New(h, func() time.Time { return h.now })
	h.cfg = sso.OIDCConfig{
		Issuer: issuer, ClientID: clientID, RedirectURI: "https://console.example.test/auth/sso/idp1/callback",
		Alg: "RS256", ClientSecret: secret.FromBytes([]byte("s3cr3t/+ &")),
		Discovery: sso.Discovery{
			Issuer: issuer, AuthorizationEndpoint: issuer + "/authorize", TokenEndpoint: issuer + "/token", JWKSURI: issuer + "/jwks",
			CodeChallengeMethods: []string{"S256"},
		},
	}
	return h
}

func (h *harness) Do(req *http.Request) (*http.Response, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls[req.URL.Path]++
	status, body := 404, []byte("{}")
	switch req.URL.Path {
	case "/jwks":
		status = 200
		body, _ = json.Marshal(map[string]any{"keys": h.jwksKeys})
	case "/token":
		b, _ := io.ReadAll(req.Body)
		f, _ := url.ParseQuery(string(b))
		h.forms = append(h.forms, f)
		h.auths = append(h.auths, req.Header.Get("Authorization"))
		status, body = h.tokenBody(h)
	}
	return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(body)), Header: http.Header{}}, nil
}

func (h *harness) idp() sso.IdP {
	c := h.cfg
	return sso.IdP{ID: "idp1", Protocol: sso.ProtocolOIDC, Enabled: true, OIDC: &c}
}

// claims returns valid claims for tx with edits applied; a nil edit value deletes the claim.
func (h *harness) claims(tx sso.Transaction, edit map[string]any) map[string]any {
	c := map[string]any{
		"iss": issuer, "aud": clientID, "sub": "user-1", "nonce": tx.Nonce,
		"iat": h.now.Unix(), "exp": h.now.Add(5 * time.Minute).Unix(),
	}
	for k, v := range edit {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	return c
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// mint builds a compact JWS signed by key with RS256 (hash chosen from the header alg).
func mint(t *testing.T, hdr, claims map[string]any, key *rsa.PrivateKey) string {
	t.Helper()
	hj, _ := json.Marshal(hdr)
	cj, _ := json.Marshal(claims)
	in := b64(hj) + "." + b64(cj)
	var sig []byte
	switch hdr["alg"] {
	case "RS384":
		d := sha512.Sum384([]byte(in))
		sig, _ = rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA384, d[:])
	default:
		d := sha256.Sum256([]byte(in))
		sig, _ = rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, d[:])
	}
	return in + "." + b64(sig)
}

func std() map[string]any { return map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid} }

// flow runs Start, lets the stub IdP answer the exchange with token(tx), and returns Complete's result.
func (h *harness) flow(intent sso.Intent, token func(tx sso.Transaction) string, mod func(q url.Values, tx *sso.Transaction, cb *sso.Callback)) (sso.Verified, error) {
	h.t.Helper()
	idp := h.idp()
	u, tx, err := h.v.Start(h.t.Context(), tenant.New(), idp, intent)
	if err != nil {
		h.t.Fatalf("Start: %v", err)
	}
	_ = u
	h.idToken = token(tx)
	q := url.Values{"code": {"auth-code"}, "state": {tx.State}}
	cb := sso.Callback{IdPID: idp.ID, Query: q}
	if mod != nil {
		mod(q, &tx, &cb)
	}
	return h.v.Complete(h.t.Context(), tenant.ID{}, idp, tx, cb)
}

func (h *harness) goodToken(edit map[string]any) func(sso.Transaction) string {
	return func(tx sso.Transaction) string { return mint(h.t, std(), h.claims(tx, edit), idpKey) }
}

func wantReason(t *testing.T, err error, reason string) {
	t.Helper()
	if got := sso.ReasonOf(err); got != reason {
		t.Fatalf("reason = %q (err %v), want %q", got, err, reason)
	}
}

// discoClient answers every request with body and remembers the URL.
type discoClient struct {
	body string
	url  string
}

func (d *discoClient) Do(req *http.Request) (*http.Response, error) {
	d.url = req.URL.String()
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(d.body))}, nil
}
