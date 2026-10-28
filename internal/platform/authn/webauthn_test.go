package authn

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
	"github.com/skenzeriq/activediq/internal/platform/authn/api"
	"github.com/skenzeriq/activediq/internal/platform/store"
)

const (
	waRPID   = "console.example.test"
	waOrigin = "https://console.example.test"
)

// softKey is a software authenticator: an ES256 credential that signs assertions the way a platform
// authenticator does (WebAuthn §6.3.3), so the real library verifies real signatures.
type softKey struct {
	priv   *ecdsa.PrivateKey
	credID []byte
	handle []byte
}

func newSoftKey(t *testing.T) *softKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k2 := &softKey{priv: k, credID: make([]byte, 32), handle: make([]byte, 64)}
	rand.Read(k2.credID)
	rand.Read(k2.handle)
	return k2
}

// cose is the COSE_Key (RFC 9052) of an ES256 public key, hand-encoded: {1:2, 3:-7, -1:1, -2:x, -3:y}.
func (k *softKey) cose() []byte {
	x, y := k.priv.PublicKey.X.FillBytes(make([]byte, 32)), k.priv.PublicKey.Y.FillBytes(make([]byte, 32))
	b := []byte{0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20}
	b = append(b, x...)
	b = append(b, 0x22, 0x58, 0x20)
	return append(b, y...)
}

func (k *softKey) credential() WebAuthnCredential {
	return WebAuthnCredential{CredentialID: k.credID, PublicKey: k.cose(), UserHandle: k.handle, Label: "test key"}
}

// assert answers a challenge. counter is the signature counter in the authenticator data; origin is what
// the browser would put in clientDataJSON.
func (k *softKey) assert(t *testing.T, challenge, origin string, counter uint32) WebAuthnAssertion {
	t.Helper()
	cd, _ := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": challenge, "origin": origin, "crossOrigin": false})
	rp := sha256.Sum256([]byte(waRPID))
	ad := append([]byte{}, rp[:]...)
	ad = append(ad, 0x05) // UP | UV
	ad = binary.BigEndian.AppendUint32(ad, counter)
	cdh := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), cdh[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, k.priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	e := base64.RawURLEncoding.EncodeToString
	return WebAuthnAssertion{CredentialID: e(k.credID), AuthenticatorData: e(ad), ClientDataJSON: e(cd), Signature: e(sig), UserHandle: e(k.handle)}
}

type waEnv struct {
	*pendEnv
	wf  *WebAuthnFactor
	key *softKey
}

func eachWebAuthn(t *testing.T, fn func(t *testing.T, e *waEnv)) {
	eachPending(t, func(t *testing.T, p *pendEnv) {
		wf, err := NewWebAuthnFactor(WebAuthnConfig{RPID: waRPID, RPDisplayName: "activeDIQ", Origins: []string{waOrigin}}, p.db, p.pending, p.sess, p.sink)
		if err != nil {
			t.Fatal(err)
		}
		e := &waEnv{pendEnv: p, wf: wf, key: newSoftKey(t)}
		if _, err := wf.AddCredential(context.Background(), p.ten, p.account, e.key.credential()); err != nil {
			t.Fatal(err)
		}
		fn(t, e)
	})
}

func (e *waEnv) challenge(t *testing.T, h PendingHandle) string {
	t.Helper()
	o, err := e.wf.Begin(context.Background(), h)
	if err != nil {
		t.Fatal(err)
	}
	if o.RPID != waRPID || o.UserVerification != "required" || len(o.AllowCredentials) != 1 {
		t.Fatalf("options: %+v", o)
	}
	return o.Challenge
}

func (e *waEnv) signCount(t *testing.T) string {
	return e.query(t, `SELECT sign_count FROM public.authn_webauthn_credentials`)[0]
}

func TestWebAuthnSignInCreatesSessionWithNewID(t *testing.T) {
	eachWebAuthn(t, func(t *testing.T, e *waEnv) {
		h := e.begin(t)
		res, err := e.wf.Verify(context.Background(), h, e.key.assert(t, e.challenge(t, h), waOrigin, 1), netip.Addr{})
		if err != nil {
			t.Fatalf("a valid assertion: %v", err)
		}
		if got := strings.Join(res.Session.Methods, ","); got != "password,webauthn" {
			t.Fatalf("methods = %s", got)
		}
		if e.sessions(t) != 1 || e.row(t, "state") != "consumed" || e.signCount(t) != "1" {
			t.Fatalf("sessions=%d state=%s count=%s", e.sessions(t), e.row(t, "state"), e.signCount(t))
		}
	})
}

// webauthn_replay (T-0207 acceptance 1): an assertion that was accepted, or that was captured, cannot be
// submitted again.
func Test_webauthn_replay(t *testing.T) {
	eachWebAuthn(t, func(t *testing.T, e *waEnv) {
		ctx := context.Background()
		h1 := e.begin(t)
		a := e.key.assert(t, e.challenge(t, h1), waOrigin, 1)
		if _, err := e.wf.Verify(ctx, h1, a, netip.Addr{}); err != nil {
			t.Fatal(err)
		}
		// 1. The same assertion, the same pending sign-in: it is consumed.
		if _, err := e.wf.Verify(ctx, h1, a, netip.Addr{}); !errors.Is(err, ErrPendingInvalid) {
			t.Fatalf("replay on the consumed pending sign-in: got %v", err)
		}
		// 2. The same assertion against a fresh pending sign-in with a fresh challenge: it signs the old one.
		h2 := e.begin(t)
		e.challenge(t, h2)
		if _, err := e.wf.Verify(ctx, h2, a, netip.Addr{}); !errors.Is(err, ErrSecondFactorRefused) {
			t.Fatalf("replay against a new challenge: got %v", err)
		}
		if e.sessions(t) != 1 {
			t.Fatalf("%d sessions, want exactly the first", e.sessions(t))
		}
	})
}

// A challenge is spent by the first submission, right or wrong: a captured valid assertion cannot be tried
// after a failed attempt used the challenge up.
func TestWebauthnChallengeSingleUse(t *testing.T) {
	eachWebAuthn(t, func(t *testing.T, e *waEnv) {
		ctx := context.Background()
		h := e.begin(t)
		ch := e.challenge(t, h)
		good := e.key.assert(t, ch, waOrigin, 1)
		bad := good
		bad.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, 70))
		if _, err := e.wf.Verify(ctx, h, bad, netip.Addr{}); !errors.Is(err, ErrSecondFactorRefused) {
			t.Fatalf("bad signature: %v", err)
		}
		if _, err := e.wf.Verify(ctx, h, good, netip.Addr{}); !errors.Is(err, ErrSecondFactorRefused) {
			t.Fatalf("valid assertion after the challenge was spent: got %v", err)
		}
		if e.sessions(t) != 0 {
			t.Fatal("a session exists")
		}
		// A new challenge works again, within the five attempts.
		if _, err := e.wf.Verify(ctx, h, e.key.assert(t, e.challenge(t, h), waOrigin, 1), netip.Addr{}); err != nil {
			t.Fatalf("fresh challenge: %v", err)
		}
	})
}

func TestWebAuthnNoChallengeIssued(t *testing.T) {
	eachWebAuthn(t, func(t *testing.T, e *waEnv) {
		h := e.begin(t)
		if _, err := e.wf.Verify(context.Background(), h, e.key.assert(t, "AAAA", waOrigin, 1), netip.Addr{}); !errors.Is(err, ErrSecondFactorRefused) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestWebAuthnSignCountMustAdvance(t *testing.T) {
	eachWebAuthn(t, func(t *testing.T, e *waEnv) {
		ctx := context.Background()
		h := e.begin(t)
		if _, err := e.wf.Verify(ctx, h, e.key.assert(t, e.challenge(t, h), waOrigin, 5), netip.Addr{}); err != nil {
			t.Fatal(err)
		}
		h2 := e.begin(t)
		if _, err := e.wf.Verify(ctx, h2, e.key.assert(t, e.challenge(t, h2), waOrigin, 5), netip.Addr{}); !errors.Is(err, ErrSecondFactorRefused) {
			t.Fatalf("a counter that did not advance: got %v", err)
		}
		if e.signCount(t) != "5" {
			t.Fatalf("count = %s", e.signCount(t))
		}
		if _, err := e.wf.Verify(ctx, h2, e.key.assert(t, e.challenge(t, h2), waOrigin, 6), netip.Addr{}); err != nil {
			t.Fatalf("an advanced counter: %v", err)
		}
	})
}

func TestWebAuthnZeroCounterAuthenticator(t *testing.T) {
	eachWebAuthn(t, func(t *testing.T, e *waEnv) {
		for i := 0; i < 2; i++ { // synced passkeys report 0 forever; that is not a regression
			h := e.begin(t)
			if _, err := e.wf.Verify(context.Background(), h, e.key.assert(t, e.challenge(t, h), waOrigin, 0), netip.Addr{}); err != nil {
				t.Fatalf("round %d: %v", i, err)
			}
		}
	})
}

func TestWebAuthnWrongOriginAndWrongKeyRefused(t *testing.T) {
	eachWebAuthn(t, func(t *testing.T, e *waEnv) {
		ctx := context.Background()
		h := e.begin(t)
		if _, err := e.wf.Verify(ctx, h, e.key.assert(t, e.challenge(t, h), "https://evil.example.test", 1), netip.Addr{}); !errors.Is(err, ErrSecondFactorRefused) {
			t.Fatalf("phishing origin: %v", err)
		}
		other := newSoftKey(t)
		other.credID, other.handle = e.key.credID, e.key.handle // same credential ID, different private key
		if _, err := e.wf.Verify(ctx, h, other.assert(t, e.challenge(t, h), waOrigin, 1), netip.Addr{}); !errors.Is(err, ErrSecondFactorRefused) {
			t.Fatalf("signature by another key: %v", err)
		}
		if e.sessions(t) != 0 {
			t.Fatal("a session exists")
		}
	})
}

func TestWebAuthnRefusalsAreAudited(t *testing.T) {
	eachWebAuthn(t, func(t *testing.T, e *waEnv) {
		h := e.begin(t)
		_, _ = e.wf.Verify(context.Background(), h, e.key.assert(t, "AAAA", waOrigin, 1), netip.Addr{})
		found := false
		for _, ev := range e.sink.evs {
			if ev.Kind == KindSecondFactorRefused && ev.Reason == RefusedNoChallenge {
				found = true
			}
		}
		if !found {
			t.Fatal("no authn.secondfactor.refused event with reason no_challenge")
		}
	})
}

func TestWebAuthnBeginNeedsLivePendingAndCredential(t *testing.T) {
	eachWebAuthn(t, func(t *testing.T, e *waEnv) {
		ctx := context.Background()
		stale := e.begin(t)
		e.now = e.now.Add(PendingSignInTTL)
		if _, err := e.wf.Begin(ctx, stale); !errors.Is(err, ErrPendingInvalid) {
			t.Fatalf("expired pending sign-in: %v", err)
		}
		e.now = e.now.Add(-PendingSignInTTL)
		if err := e.tx(t, e.ten, func(ctx context.Context, tx store.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE public.authn_webauthn_credentials SET state = 'revoked'`)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := e.wf.Begin(ctx, e.begin(t)); !errors.Is(err, ErrSecondFactorRefused) {
			t.Fatalf("no active credential: %v", err)
		}
	})
}

type waCookieAdapter struct{ f *WebAuthnFactor }

func (a waCookieAdapter) BeginWebAuthnCookie(ctx context.Context, pending string) (WebAuthnOptions, error) {
	h, err := ParsePendingHandle(pending)
	if err != nil {
		return WebAuthnOptions{}, ErrPendingInvalid
	}
	return a.f.Begin(ctx, h)
}

func (a waCookieAdapter) VerifyWebAuthnCookie(ctx context.Context, pending string, in WebAuthnAssertion, from netip.Addr) (CreateResult, []string, error) {
	h, err := ParsePendingHandle(pending)
	if err != nil {
		return CreateResult{}, nil, ErrPendingInvalid
	}
	res, err := a.f.Verify(ctx, h, in, from)
	return res, []string{"__Host-adiq_session=x", "__Host-adiq_pending=; Max-Age=0"}, err
}

// The handlers answer the contract's shapes, and every refusal is the one uniform 401.
func TestWebAuthnHandlers(t *testing.T) {
	eachWebAuthn(t, func(t *testing.T, e *waEnv) {
		ctx := context.Background()
		hd := Handlers{WebAuthn: waCookieAdapter{e.wf}}
		h := e.begin(t)
		in := api.CreateWebAuthnSignInChallengeInput{HostAdiqPending: apitypes.NewCookieValue(h.Reveal()), PeerIP: "192.0.2.7"}
		out, err := hd.CreateWebAuthnSignInChallenge(ctx, in)
		if err != nil {
			t.Fatal(err)
		}
		ch := out.(api.CreateWebAuthnSignInChallenge200).Body
		if ch.RpID != waRPID || ch.UserVerification != api.WebAuthnUserVerificationRequired || len(ch.AllowCredentials) != 1 ||
			ch.AllowCredentials[0].Type != api.WebAuthnCredentialTypePublicKey || ch.TimeoutMs < 1000 || ch.TimeoutMs > 300000 {
			t.Fatalf("challenge = %+v", ch)
		}
		a := e.key.assert(t, ch.Challenge, waOrigin, 1)
		body := api.WebAuthnAssertion{CredentialID: a.CredentialID, AuthenticatorData: a.AuthenticatorData, ClientDataJSON: a.ClientDataJSON, Signature: a.Signature, UserHandle: &a.UserHandle}
		vin := api.VerifyWebAuthnSignInInput{HostAdiqPending: apitypes.NewCookieValue(h.Reveal()), PeerIP: "192.0.2.7", Body: body}
		vout, err := hd.VerifyWebAuthnSignIn(ctx, vin)
		if err != nil {
			t.Fatal(err)
		}
		if o, ok := vout.(api.VerifyWebAuthnSignIn204); !ok || len(o.SetCookie) != 2 {
			t.Fatalf("out = %#v", vout)
		}
		// Replayed: the same uniform 401 as any other sign-in failure.
		_, err = hd.VerifyWebAuthnSignIn(ctx, vin)
		var want *apitypes.Problem
		if err == nil || !errors.As(err, &want) || want.Status != 401 {
			t.Fatalf("replay: got %v", err)
		}
		if _, err := hd.CreateWebAuthnSignInChallenge(ctx, in); err == nil {
			t.Fatal("a challenge for a consumed pending sign-in")
		}
	})
}
