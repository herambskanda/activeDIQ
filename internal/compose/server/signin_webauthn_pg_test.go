package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/compose/config"
	"github.com/skenzeriq/activediq/internal/modules/directory"
	"github.com/skenzeriq/activediq/internal/platform/authn"
	"github.com/skenzeriq/activediq/internal/platform/keys"
	"github.com/skenzeriq/activediq/internal/platform/keys/keystest"
	"github.com/skenzeriq/activediq/internal/platform/rbac"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

const (
	waChallengePath = "/api/v1/auth/second-factor/webauthn/challenge"
	waVerifyPath    = "/api/v1/auth/second-factor/webauthn/verify"
	waPasswordPath  = "/api/v1/auth/break-glass/password"
)

// softAuthenticator is a software authenticator: an ES256 credential that signs assertions the way a
// platform authenticator does (WebAuthn §6.3.3), so the real library verifies real signatures.
type softAuthenticator struct {
	priv           *ecdsa.PrivateKey
	credID, handle []byte
}

func newSoftAuthenticator(t *testing.T) *softAuthenticator {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a := &softAuthenticator{priv: k, credID: make([]byte, 32), handle: make([]byte, 64)}
	rand.Read(a.credID)
	rand.Read(a.handle)
	return a
}

// credential is the registered form: the COSE_Key (RFC 9052) {1:2, 3:-7, -1:1, -2:x, -3:y}, hand-encoded.
func (a *softAuthenticator) credential() authn.WebAuthnCredential {
	x, y := a.priv.PublicKey.X.FillBytes(make([]byte, 32)), a.priv.PublicKey.Y.FillBytes(make([]byte, 32))
	cose := append([]byte{0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20}, x...)
	cose = append(append(cose, 0x22, 0x58, 0x20), y...)
	return authn.WebAuthnCredential{CredentialID: a.credID, PublicKey: cose, UserHandle: a.handle, Label: "test key"}
}

// assert answers a challenge for the relying party rpID; origin is what the browser would put in clientDataJSON.
func (a *softAuthenticator) assert(t *testing.T, rpID, challenge, origin string, counter uint32) map[string]string {
	t.Helper()
	cd, _ := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": challenge, "origin": origin, "crossOrigin": false})
	rp := sha256.Sum256([]byte(rpID))
	ad := append(append([]byte{}, rp[:]...), 0x05) // UP | UV
	ad = binary.BigEndian.AppendUint32(ad, counter)
	cdh := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), cdh[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	e := base64.RawURLEncoding.EncodeToString
	return map[string]string{"credentialId": e(a.credID), "authenticatorData": e(ad), "clientDataJson": e(cd), "signature": e(sig), "userHandle": e(a.handle)}
}

type waServer struct {
	h       http.Handler
	console *consoleStack
	key     *softAuthenticator
	logs    *bytes.Buffer
}

// waBoot composes the console as Run composes it, over a real database holding one active local account
// with a WebAuthn credential (and TOTP, which activates the account). publicURL is ACTIVEDIQ_PUBLIC_URL.
func waBoot(t *testing.T, s *storetest.Server, publicURL string) *waServer {
	t.Helper()
	ctx := context.Background()
	d := s.NewDatabase(t)
	d.Migrate(t)
	db, err := store.Open(ctx, store.Config{DSN: d.AppDSN()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	ks := keys.NewStore(keystest.New("kek-1"))
	ten := tenanttest.Seed(t, d.ExecOwner, firstRunTenantName)
	if err := db.WithTenant(ctx, ten, func(ctx context.Context, tx store.Tx) error { return ks.Provision(ctx, tx, ten) }); err != nil {
		t.Fatal(err)
	}
	deps := localAccountDeps{DB: db, Sink: nopSink{}, Keys: ks.KeySource()}
	la, err := createLocalAccount(ctx, deps, LocalAccountSpec{Username: "Break.Glass", Password: secret.FromBytes([]byte(signInPassword))})
	if err != nil {
		t.Fatal(err)
	}
	var seedText string
	la.Seed.Expose(func(b []byte) { seedText = string(b) })
	seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(seedText))
	if err != nil {
		t.Fatal(err)
	}
	if err := confirmTOTP(ctx, deps, la, totpCode(seed, time.Now())); err != nil {
		t.Fatal(err)
	}

	logs := &bytes.Buffer{}
	console, err := buildConsole(db, nopSink{}, ks.KeySource(), slog.New(slog.NewTextHandler(logs, nil)), withPublicURL(publicURL))
	if err != nil {
		t.Fatal(err)
	}
	console.SetTenant(ten)
	key := newSoftAuthenticator(t)
	if console.WebAuthn != nil {
		if _, err := console.WebAuthn.AddCredential(ctx, ten, la.ID, key.credential()); err != nil {
			t.Fatal(err)
		}
	}
	src, err := rbac.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	az, err := rbac.New(src)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{APIBodyBudget: config.DefaultAPIBodyBudget, PublicURL: publicURL}
	h, err := buildAPIPorts(cfg, bootedCatalogue(), console.ports(testLimiter(t), az, bootedCatalogue()), console.Tags(), directory.Handlers{Connections: activeConns{}, Search: &oneUser{}, Scopes: consoleScopes{}}.Bind())
	if err != nil {
		t.Fatal(err)
	}
	return &waServer{h: h, console: console, key: key, logs: logs}
}

// pendingCookie runs the password step and returns the pending cookie.
func (w *waServer) pendingCookie(t *testing.T) *http.Cookie {
	t.Helper()
	rec := postJSON(w.h, waPasswordPath, `{"username":"break.glass","password":"`+signInPassword+`"}`)
	if rec.Code != http.StatusNoContent || len(rec.Result().Cookies()) != 1 || rec.Result().Cookies()[0].Name != authn.PendingCookieName {
		t.Fatalf("password step: %d %s %v", rec.Code, rec.Body, rec.Result().Cookies())
	}
	return rec.Result().Cookies()[0]
}

type waOptions struct {
	Challenge        string `json:"challenge"`
	RPID             string `json:"rpId"`
	UserVerification string `json:"userVerification"`
	AllowCredentials []struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	} `json:"allowCredentials"`
}

func (w *waServer) challenge(t *testing.T, pending *http.Cookie) waOptions {
	t.Helper()
	rec := postJSON(w.h, waChallengePath, ``, pending)
	if rec.Code != http.StatusOK {
		t.Fatalf("challenge: %d %s", rec.Code, rec.Body)
	}
	var o waOptions
	if err := json.Unmarshal(rec.Body.Bytes(), &o); err != nil {
		t.Fatal(err)
	}
	return o
}

func jsonBody(t *testing.T, m map[string]string) string {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// T-0853 acceptance 1: with the public URL set the mounted challenge route answers the relying party and
// the enrolled credential.
func TestWebAuthnChallengeThroughTheMountedRoutes(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		w := waBoot(t, s, "https://diq.example.com")
		o := w.challenge(t, w.pendingCookie(t))
		if o.RPID != "diq.example.com" || o.UserVerification != "required" || o.Challenge == "" {
			t.Fatalf("options = %+v", o)
		}
		if len(o.AllowCredentials) != 1 || o.AllowCredentials[0].Type != "public-key" ||
			o.AllowCredentials[0].ID != base64.RawURLEncoding.EncodeToString(w.key.credID) {
			t.Fatalf("allowCredentials = %+v", o.AllowCredentials)
		}
		if strings.Contains(w.logs.String(), "WebAuthn sign-in is off") {
			t.Errorf("logged that WebAuthn is off while configured: %s", w.logs)
		}
	})
}

// T-0853 acceptance 2: password then a valid assertion makes the session, clears the pending cookie, and
// the session records both methods.
func TestWebAuthnSignInThroughTheMountedRoutes(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		w := waBoot(t, s, "https://diq.example.com")
		pending := w.pendingCookie(t)
		o := w.challenge(t, pending)
		rec := postJSON(w.h, waVerifyPath, jsonBody(t, w.key.assert(t, o.RPID, o.Challenge, "https://diq.example.com", 1)), pending)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("verify: %d %s", rec.Code, rec.Body)
		}
		var session, cleared *http.Cookie
		for _, c := range rec.Result().Cookies() {
			switch c.Name {
			case "__Host-adiq_session":
				session = c
			case authn.PendingCookieName:
				cleared = c
			}
		}
		if session == nil || session.Value == "" || !session.HttpOnly || !session.Secure || session.SameSite != http.SameSiteStrictMode {
			t.Fatalf("session cookie = %+v", session)
		}
		if cleared == nil || cleared.Value != "" || cleared.MaxAge >= 0 {
			t.Fatalf("pending cookie not cleared: %+v", cleared)
		}
		tok, err := authn.ParseToken(session.Value)
		if err != nil {
			t.Fatal(err)
		}
		sess, err := w.console.Sessions.Lookup(context.Background(), tok)
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Join(sess.Methods, ","); got != "password,webauthn" {
			t.Errorf("session methods = %s, want password,webauthn", got)
		}
	})
}

// T-0853 acceptance 3: a tampered signature, an assertion for another origin, a replayed challenge and no
// pending cookie are all the one 401 sign-in-failed, with no session cookie.
func TestWebAuthnSignInRefusalsAreUniform(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		w := waBoot(t, s, "https://diq.example.com")
		refused := func(t *testing.T, name string, rec interface {
			Result() *http.Response
		}, code int, body string) string {
			t.Helper()
			if code != http.StatusUnauthorized || !strings.Contains(body, "/problems/sign-in-failed") {
				t.Fatalf("%s: %d %s", name, code, body)
			}
			for _, c := range rec.Result().Cookies() {
				if c.Name == "__Host-adiq_session" {
					t.Fatalf("%s: set a session cookie", name)
				}
			}
			return traceID.ReplaceAllString(body, "")
		}
		var bodies []string
		try := func(name string, mutate func(o waOptions, a map[string]string), usePending bool) {
			pending := w.pendingCookie(t)
			o := w.challenge(t, pending)
			a := w.key.assert(t, o.RPID, o.Challenge, "https://diq.example.com", 1)
			mutate(o, a)
			if !usePending {
				pending = &http.Cookie{Name: "unrelated", Value: "x"}
			}
			rec := postJSON(w.h, waVerifyPath, jsonBody(t, a), pending)
			bodies = append(bodies, refused(t, name, rec, rec.Code, rec.Body.String()))
		}
		try("tampered signature", func(_ waOptions, a map[string]string) {
			sig, _ := base64.RawURLEncoding.DecodeString(a["signature"])
			sig[len(sig)-1] ^= 0xff
			a["signature"] = base64.RawURLEncoding.EncodeToString(sig)
		}, true)
		try("another origin", func(o waOptions, a map[string]string) {
			for k, v := range w.key.assert(t, o.RPID, o.Challenge, "https://evil.example.com", 1) {
				a[k] = v
			}
		}, true)
		try("no pending cookie", func(waOptions, map[string]string) {}, false)

		// A replay: the accepted assertion, sent again with the same pending cookie.
		pending := w.pendingCookie(t)
		o := w.challenge(t, pending)
		body := jsonBody(t, w.key.assert(t, o.RPID, o.Challenge, "https://diq.example.com", 1))
		if rec := postJSON(w.h, waVerifyPath, body, pending); rec.Code != http.StatusNoContent {
			t.Fatalf("first use: %d %s", rec.Code, rec.Body)
		}
		rec := postJSON(w.h, waVerifyPath, body, pending)
		bodies = append(bodies, refused(t, "replay", rec, rec.Code, rec.Body.String()))

		for i, b := range bodies[1:] {
			if b != bodies[0] {
				t.Errorf("refusal %d differs from the first:\n%s\n%s", i+1, bodies[0], b)
			}
		}
	})
}

// T-0853 acceptance 4: without a public URL there is no relying party, so the routes answer 501 and the
// start-up log says so; TOTP sign-in is unchanged.
func TestWebAuthnOffWithoutPublicURL(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		w := waBoot(t, s, "")
		if w.console.WebAuthn != nil {
			t.Fatal("a WebAuthn factor without a public URL")
		}
		if n := strings.Count(w.logs.String(), "WebAuthn sign-in is off"); n != 1 {
			t.Errorf("start-up log says WebAuthn is off %d times, want once: %s", n, w.logs)
		}
		pending := w.pendingCookie(t)
		for _, path := range []string{waChallengePath, waVerifyPath} {
			body := ""
			if path == waVerifyPath {
				body = `{"credentialId":"a","authenticatorData":"a","clientDataJson":"a","signature":"a"}`
			}
			rec := postJSON(w.h, path, body, pending)
			if rec.Code != http.StatusNotImplemented {
				t.Errorf("%s: %d %s, want 501", path, rec.Code, rec.Body)
			}
		}
		rec := postJSON(w.h, "/api/v1/auth/second-factor/totp/verify", `{"code":"000000"}`, pending)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("TOTP route: %d %s, want the uniform 401 (mounted, not 501)", rec.Code, rec.Body)
		}
	})
}
