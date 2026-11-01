package oidc

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/authn/sso"
	"github.com/skenzeriq/activediq/internal/platform/authn/sso/signin"
	"github.com/skenzeriq/activediq/internal/platform/authn/sso/signin/signintest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// The TM-F-SSO OIDC corpus (console-sso.md §10.1 and §10.3, T-0911). One JSON record per case under
// testdata/corpus/oidc, named after its id; every record runs as its own subtest of TestCorpus and must be
// refused with exactly the reason code it names. FIT-SSO-2 (tools/fitness/sso) reads the same records, checks
// that every OIDC-n is cited and every class is present, and requires a passing subtest per id.
//
// A record's "build" names a builder below. A builder drives the case end to end (Start, the stub IdP,
// Complete) once per variant the spec row lists, and every variant must be refused with the record's reason.

type corpusRecord struct {
	ID     string   `json:"id"`
	Class  string   `json:"class"`
	Cites  []string `json:"cites"`
	Build  string   `json:"build"`
	Expect string   `json:"expect"`
	Reason string   `json:"reason"`
}

const corpusDir = "../testdata/corpus/oidc"

func loadCorpus(t testing.TB) []corpusRecord {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(corpusDir, "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no corpus records in %s: %v", corpusDir, err)
	}
	sort.Strings(files)
	var out []corpusRecord
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var r corpusRecord
		if err := json.Unmarshal(b, &r); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		out = append(out, r)
	}
	return out
}

// outcome is what Complete (or Start) returned for one variant of a case.
type outcome struct {
	variant string
	v       sso.Verified
	err     error
}

// A builder returns one outcome per variant. It may fail the test itself for side-effect assertions (the
// code was not exchanged, the JWKS was fetched once).
type builder func(t *testing.T) []outcome

// TestCorpus runs every record end to end: a case that is accepted, or refused with another reason, fails.
func TestCorpus(t *testing.T) {
	used := map[string]bool{}
	for _, rec := range loadCorpus(t) {
		t.Run(rec.ID, func(t *testing.T) {
			if rec.Expect != "refuse" || rec.Reason == "" {
				t.Fatalf("record %s must expect a refusal with a reason", rec.ID)
			}
			b, ok := builders[rec.Build]
			if !ok {
				t.Fatalf("record %s names builder %q, which does not exist", rec.ID, rec.Build)
			}
			used[rec.Build] = true
			outs := b(t)
			if len(outs) == 0 {
				t.Fatalf("builder %q produced no variant", rec.Build)
			}
			for _, o := range outs {
				if o.err == nil {
					t.Errorf("%s: ACCEPTED: %+v", o.variant, o.v)
					continue
				}
				if got := sso.ReasonOf(o.err); got != rec.Reason {
					t.Errorf("%s: reason %q, want %q (%v)", o.variant, got, rec.Reason, o.err)
				}
				if o.v.Subject != "" || o.v.ResponseID != "" || o.v.Anchor != nil {
					t.Errorf("%s: partial claims returned with a refusal: %+v", o.variant, o.v)
				}
			}
		})
	}
	// A builder no record uses is dead test code (or a record that was deleted); say so.
	t.Run("builders_all_used", func(t *testing.T) {
		var orphan []string
		for name := range builders {
			if !used[name] {
				orphan = append(orphan, name)
			}
		}
		slices.Sort(orphan)
		if len(orphan) > 0 {
			t.Errorf("builders without a corpus record: %v", orphan)
		}
	})
}

// variant is one run of the flow on a fresh harness.
type variant struct {
	name   string
	intent sso.Intent
	setup  func(h *harness)
	token  func(h *harness) func(sso.Transaction) string
	mod    func(q url.Values, tx *sso.Transaction, cb *sso.Callback)
	// config marks a case refused when the IdP is saved or started, before any callback exists.
	config bool
}

func (c variant) run(t *testing.T) (*harness, outcome) {
	t.Helper()
	h := newHarness(t)
	if c.setup != nil {
		c.setup(h)
	}
	if c.config {
		_, _, err := h.v.Start(t.Context(), tenant.New(), h.idp(), sso.IntentSignin)
		return h, outcome{variant: c.name, err: err}
	}
	tok := h.goodToken(nil)
	if c.token != nil {
		tok = c.token(h)
	}
	intent := c.intent
	if intent == "" {
		intent = sso.IntentSignin
	}
	v, err := h.flow(intent, tok, c.mod)
	return h, outcome{c.name, v, err}
}

func runAll(t *testing.T, cases ...variant) []outcome {
	t.Helper()
	var out []outcome
	for _, c := range cases {
		_, o := c.run(t)
		out = append(out, o)
	}
	return out
}

func withHdr(edit func(map[string]any)) map[string]any {
	h := std()
	edit(h)
	return h
}

func idpSigned(t *testing.T, hdr map[string]any, edit map[string]any) func(*harness) func(sso.Transaction) string {
	return func(h *harness) func(sso.Transaction) string {
		return func(tx sso.Transaction) string { return mint(t, hdr, h.claims(tx, edit), idpKey) }
	}
}

func claimsEdit(edit map[string]any) func(*harness) func(sso.Transaction) string {
	return func(h *harness) func(sso.Transaction) string { return h.goodToken(edit) }
}

func noExchange(t *testing.T, h *harness, what string) {
	t.Helper()
	if h.calls["/token"] != 0 {
		t.Fatalf("%s: the code was exchanged", what)
	}
}

func evilX5C(t *testing.T) []string {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "evil"}, NotBefore: baseTime.Add(-time.Hour), NotAfter: baseTime.Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &evilKey.PublicKey, evilKey)
	if err != nil {
		t.Fatal(err)
	}
	return []string{base64.StdEncoding.EncodeToString(der)}
}

func tamper(tok string, f func(parts []string)) string {
	p := strings.Split(tok, ".")
	f(p)
	return strings.Join(p, ".")
}

var builders = map[string]builder{
	// O-F01: alg none with an empty signature.
	"alg_none": func(t *testing.T) []outcome {
		unsigned := func(alg string) func(*harness) func(sso.Transaction) string {
			return func(h *harness) func(sso.Transaction) string {
				return func(tx sso.Transaction) string {
					hj, _ := json.Marshal(map[string]any{"alg": alg, "kid": kid})
					cj, _ := json.Marshal(h.claims(tx, nil))
					return b64(hj) + "." + b64(cj) + "."
				}
			}
		}
		return runAll(t, variant{name: "none", token: unsigned("none")}, variant{name: "None", token: unsigned("None")})
	},

	// O-F02: HS256 keyed with the IdP's RSA public key.
	"alg_hs256_public_key": func(t *testing.T) []outcome {
		der, _ := x509.MarshalPKIXPublicKey(&idpKey.PublicKey)
		pemKey := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
		hs := func(secret []byte) func(*harness) func(sso.Transaction) string {
			return func(h *harness) func(sso.Transaction) string {
				return func(tx sso.Transaction) string {
					hj, _ := json.Marshal(map[string]any{"alg": "HS256", "kid": kid})
					cj, _ := json.Marshal(h.claims(tx, nil))
					in := b64(hj) + "." + b64(cj)
					m := hmac.New(sha256.New, secret)
					m.Write([]byte(in))
					return in + "." + b64(m.Sum(nil))
				}
			}
		}
		return runAll(t,
			variant{name: "HS256, PEM public key as secret", token: hs(pemKey)},
			variant{name: "HS256, DER public key as secret", token: hs(der)},
			variant{name: "HS256 pinned at config time", config: true, setup: func(h *harness) { h.cfg.Alg = "HS256" }, token: hs(pemKey)},
		)
	},

	// O-F03: the trusted key, an algorithm other than the pinned one.
	"alg_not_pinned": func(t *testing.T) []outcome {
		return runAll(t, variant{name: "RS384 against pinned RS256", token: idpSigned(t, withHdr(func(m map[string]any) { m["alg"] = "RS384" }), nil)})
	},

	// O-F04: an attacker key referenced by jku, x5u, an embedded jwk or x5c.
	"key_from_header": func(t *testing.T) []outcome {
		evil := jwk(&evilKey.PublicKey, "evil")
		x5c := evilX5C(t)
		var outs []outcome
		for _, extra := range []string{"jku", "x5u", "jwk", "x5c"} {
			hdr := std()
			hdr["kid"] = "evil" // a kid the cached set does not hold: the header is the only way to a key
			switch extra {
			case "jku", "x5u":
				hdr[extra] = "https://evil.test/keys"
			case "jwk":
				hdr[extra] = evil
			case "x5c":
				hdr[extra] = x5c
			}
			c := variant{name: extra, token: func(h *harness) func(sso.Transaction) string {
				return func(tx sso.Transaction) string { return mint(t, hdr, h.claims(tx, nil), evilKey) }
			}}
			h, o := c.run(t)
			if h.calls["/keys"] != 0 {
				t.Fatalf("%s: the jku/x5u URL was fetched", extra)
			}
			outs = append(outs, o)
		}
		return outs
	},

	// O-F05: an unknown kid: one refresh, then refusal; a second unknown kid within a minute does not refetch.
	"kid_unknown": func(t *testing.T) []outcome {
		h := newHarness(t)
		hdr := std()
		hdr["kid"] = "rotated"
		tok := func(tx sso.Transaction) string { return mint(t, hdr, h.claims(tx, nil), idpKey) }
		var outs []outcome
		for i, name := range []string{"first unknown kid", "second unknown kid within a minute", "third"} {
			v, err := h.flow(sso.IntentSignin, tok, nil)
			outs = append(outs, outcome{name, v, err})
			if h.calls["/jwks"] != 1 {
				t.Fatalf("attempt %d: jwks fetched %d times inside one minute, want 1", i+1, h.calls["/jwks"])
			}
		}
		return outs
	},

	// O-F06: payload changed after signing; signature bit-flipped.
	"signature_broken": func(t *testing.T) []outcome {
		resigned := func(mut func(tx sso.Transaction, p []string)) func(*harness) func(sso.Transaction) string {
			return func(h *harness) func(sso.Transaction) string {
				return func(tx sso.Transaction) string {
					return tamper(mint(t, std(), h.claims(tx, nil), idpKey), func(p []string) { mut(tx, p) })
				}
			}
		}
		return runAll(t,
			variant{name: "payload changed", token: resigned(func(tx sso.Transaction, p []string) {
				c, _ := json.Marshal(map[string]any{"iss": issuer, "aud": clientID, "sub": "admin", "nonce": tx.Nonce, "iat": baseTime.Unix(), "exp": baseTime.Add(time.Hour).Unix()})
				p[1] = b64(c)
			})},
			variant{name: "signature bit flipped", token: resigned(func(_ sso.Transaction, p []string) {
				sig, _ := base64.RawURLEncoding.DecodeString(p[2])
				sig[len(sig)/2] ^= 0x01
				p[2] = b64(sig)
			})},
			variant{name: "signed by another key", token: func(h *harness) func(sso.Transaction) string {
				return func(tx sso.Transaction) string { return mint(t, std(), h.claims(tx, nil), evilKey) }
			}},
		)
	},

	// O-F07: a JWE ID token.
	"jwe": func(t *testing.T) []outcome {
		fixed := func(s string) func(*harness) func(sso.Transaction) string {
			return func(*harness) func(sso.Transaction) string { return func(sso.Transaction) string { return s } }
		}
		return runAll(t,
			variant{name: "five parts", token: fixed(b64([]byte(`{"alg":"RSA-OAEP","enc":"A256GCM"}`)) + ".AAAA.AAAA.AAAA.AAAA")},
			variant{name: "enc header on three parts", token: fixed(b64([]byte(`{"alg":"RS256","enc":"A256GCM","kid":"k1"}`)) + ".AAAA.AAAA")},
		)
	},

	// O-F08: a crit header, on an otherwise valid signature.
	"crit_header": func(t *testing.T) []outcome {
		return runAll(t,
			variant{name: "crit exp", token: idpSigned(t, withHdr(func(m map[string]any) { m["crit"] = []string{"exp"} }), nil)},
			variant{name: "crit unknown extension", token: idpSigned(t, withHdr(func(m map[string]any) { m["crit"] = []string{"x-ext"}; m["x-ext"] = "1" }), nil)},
		)
	},

	// O-F09: an RSA-1024 key in the JWKS.
	"rsa_1024": func(t *testing.T) []outcome {
		hdr := std()
		hdr["kid"] = "weak"
		return runAll(t, variant{
			name:  "RSA-1024 key in the JWKS signs the token",
			setup: func(h *harness) { h.jwksKeys = []map[string]any{jwk(&weakKey.PublicKey, "weak")} },
			token: func(h *harness) func(sso.Transaction) string {
				return func(tx sso.Transaction) string { return mint(t, hdr, h.claims(tx, nil), weakKey) }
			},
		})
	},

	// O-F10: an id_token (implicit or hybrid) or token in the authorization response.
	"implicit_response": func(t *testing.T) []outcome {
		var outs []outcome
		for _, p := range []string{"id_token", "token", "access_token"} {
			h, o := variant{name: p + " beside the code (hybrid)", mod: func(q url.Values, _ *sso.Transaction, _ *sso.Callback) { q.Set(p, "x.y.z") }}.run(t)
			noExchange(t, h, p)
			outs = append(outs, o)
		}
		h, o := variant{name: "id_token without a code (implicit)", mod: func(q url.Values, _ *sso.Transaction, _ *sso.Callback) {
			q.Del("code")
			q.Set("id_token", "x.y.z")
		}}.run(t)
		noExchange(t, h, "implicit")
		return append(outs, o)
	},

	// O-R01: a callback without state; with a state from another browser.
	"state_missing_or_foreign": func(t *testing.T) []outcome {
		var outs []outcome
		for _, c := range []variant{
			{name: "state missing", mod: func(q url.Values, _ *sso.Transaction, _ *sso.Callback) { q.Del("state") }},
			{name: "state empty", mod: func(q url.Values, _ *sso.Transaction, _ *sso.Callback) { q.Set("state", "") }},
			{name: "state of another browser's Transaction", mod: func(q url.Values, _ *sso.Transaction, _ *sso.Callback) {
				other := newHarness(t)
				_, otherTx, err := other.v.Start(t.Context(), tenant.New(), other.idp(), sso.IntentSignin)
				if err != nil {
					t.Fatal(err)
				}
				q.Set("state", otherTx.State)
			}},
		} {
			h, o := c.run(t)
			noExchange(t, h, c.name) // refused before the code is exchanged
			outs = append(outs, o)
		}
		return outs
	},

	// O-R02: the same callback twice. The IdP's code is single use (RFC 6749 §4.1.2) and the Transaction is
	// consumed first (SSO-1).
	"callback_twice": func(t *testing.T) []outcome {
		h := newHarness(t)
		used := false
		h.tokenBody = func(h *harness) (int, []byte) {
			if used {
				return 400, []byte(`{"error":"invalid_grant"}`)
			}
			used = true
			b, _ := json.Marshal(map[string]any{"id_token": h.idToken})
			return 200, b
		}
		idp := h.idp()
		_, tx, err := h.v.Start(t.Context(), tenant.New(), idp, sso.IntentSignin)
		if err != nil {
			t.Fatal(err)
		}
		h.idToken = mint(t, std(), h.claims(tx, nil), idpKey)
		cb := sso.Callback{IdPID: idp.ID, Query: url.Values{"code": {"auth-code"}, "state": {tx.State}}}
		if _, err := h.v.Complete(t.Context(), tenant.ID{}, idp, tx, cb); err != nil {
			t.Fatalf("first callback: %v", err)
		}
		v, err := h.v.Complete(t.Context(), tenant.ID{}, idp, tx, cb)
		outs := []outcome{{"second callback, code already redeemed", v, err}}

		// SSO-1: the Transaction store hands a Transaction out once, so the second callback never reaches
		// the verifier in production.
		txs := &signintest.MemTxs{Now: func() time.Time { return h.now }, M: map[string]sso.Transaction{}}
		handle, err := txs.Put(t.Context(), tenant.ID{}, tx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := txs.Consume(t.Context(), tenant.ID{}, handle); err != nil {
			t.Fatalf("first consume: %v", err)
		}
		if _, err := txs.Consume(t.Context(), tenant.ID{}, handle); err != signin.ErrNoTransaction {
			t.Fatalf("second consume = %v, want ErrNoTransaction", err)
		}
		return outs
	},

	// O-R03: nonce missing; the nonce of another Transaction.
	"nonce_wrong": func(t *testing.T) []outcome {
		return runAll(t,
			variant{name: "nonce missing", token: claimsEdit(map[string]any{"nonce": nil})},
			variant{name: "nonce empty", token: claimsEdit(map[string]any{"nonce": ""})},
			variant{name: "nonce of another Transaction", token: claimsEdit(map[string]any{"nonce": "nonce-of-another-transaction"})},
		)
	},

	// O-R04: exp passed; iat older than 10 minutes; nbf in the future.
	"time_window": func(t *testing.T) []outcome {
		at := func(d time.Duration) int64 { return baseTime.Add(d).Unix() }
		return runAll(t,
			variant{name: "exp passed", token: claimsEdit(map[string]any{"exp": at(-3 * time.Minute), "iat": at(-8 * time.Minute)})},
			variant{name: "iat older than 10 minutes", token: claimsEdit(map[string]any{"iat": at(-11 * time.Minute)})},
			variant{name: "iat in the future", token: claimsEdit(map[string]any{"iat": at(5 * time.Minute)})},
			variant{name: "nbf in the future", token: claimsEdit(map[string]any{"nbf": at(5 * time.Minute)})},
			variant{name: "exp missing", token: claimsEdit(map[string]any{"exp": nil})},
		)
	},

	// O-R05: a step-up with auth_time older than 120 s, or absent.
	"stepup_stale": func(t *testing.T) []outcome {
		at := func(d time.Duration) int64 { return baseTime.Add(d).Unix() }
		return runAll(t,
			variant{name: "auth_time older than 120 s", intent: sso.IntentStepup, token: claimsEdit(map[string]any{"auth_time": at(-121 * time.Second)})},
			variant{name: "auth_time absent", intent: sso.IntentStepup, token: claimsEdit(nil)},
		)
	},

	// O-R06: Start always sends S256 and never plain; an IdP without S256 cannot be saved or used.
	"pkce_s256_only": func(t *testing.T) []outcome {
		for _, intent := range []sso.Intent{sso.IntentSignin, sso.IntentStepup} {
			h := newHarness(t)
			u, tx, err := h.v.Start(t.Context(), tenant.New(), h.idp(), intent)
			if err != nil {
				t.Fatalf("Start(%s): %v", intent, err)
			}
			q := u.Query()
			if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || strings.Contains(u.RawQuery, "plain") {
				t.Fatalf("Start(%s) did not send S256 only: %s", intent, u.RawQuery)
			}
			if q.Get("code_challenge") == tx.Verifier {
				t.Fatalf("Start(%s) sent the verifier as the challenge (plain)", intent)
			}
			if len(tx.Verifier) < 43 { // 32 bytes, base64url without padding
				t.Fatalf("Start(%s): code_verifier of %d characters", intent, len(tx.Verifier))
			}
		}
		var outs []outcome
		for name, methods := range map[string][]string{"discovery lists no methods": nil, "discovery lists plain only": {"plain"}} {
			h := newHarness(t)
			h.cfg.Discovery.CodeChallengeMethods = methods
			if err := ValidateConfig(&h.cfg); sso.ReasonOf(err) != ReasonPKCE {
				t.Fatalf("%s: ValidateConfig = %v (save must be refused)", name, err)
			}
			_, _, err := h.v.Start(t.Context(), tenant.New(), h.idp(), sso.IntentSignin)
			outs = append(outs, outcome{name + ", Start", sso.Verified{}, err})
			v, err := h.flow2()
			outs = append(outs, outcome{name + ", Complete", v, err})
		}
		return outs
	},

	// O-M01: iss of another issuer; the Entra common issuer; a tid mismatch.
	"issuer_wrong": func(t *testing.T) []outcome {
		const tid = "11111111-2222-3333-4444-555555555555"
		entra := func(h *harness) {
			h.cfg.Issuer = "https://login.microsoftonline.com/" + tid + "/v2.0"
			h.cfg.Discovery.Issuer = h.cfg.Issuer
			h.cfg.EntraTenantID = tid
		}
		entraToken := func(edit map[string]any) func(*harness) func(sso.Transaction) string {
			return func(h *harness) func(sso.Transaction) string {
				e := map[string]any{"iss": h.cfg.Issuer, "tid": tid}
				for k, v := range edit {
					e[k] = v
				}
				return h.goodToken(e)
			}
		}
		return runAll(t,
			variant{name: "iss of another issuer", token: claimsEdit(map[string]any{"iss": "https://evil.example.test"})},
			variant{name: "iss differs by a trailing slash", token: claimsEdit(map[string]any{"iss": issuer + "/"})},
			variant{name: "iss missing", token: claimsEdit(map[string]any{"iss": nil})},
			variant{name: "Entra common issuer cannot be configured", config: true, setup: func(h *harness) {
				h.cfg.Issuer = "https://login.microsoftonline.com/common/v2.0"
				h.cfg.Discovery.Issuer = h.cfg.Issuer
				h.cfg.EntraTenantID = tid
			}},
			variant{name: "Entra tid of another tenant", setup: entra, token: entraToken(map[string]any{"tid": "99999999-2222-3333-4444-555555555555"})},
			variant{name: "Entra tid missing", setup: entra, token: entraToken(map[string]any{"tid": nil})},
		)
	},

	// O-M02: a code from IdP B delivered to IdP A's callback; an RFC 9207 iss mismatch.
	"idp_mixup": func(t *testing.T) []outcome {
		var outs []outcome
		for _, c := range []variant{
			{name: "callback path of IdP B", mod: func(_ url.Values, _ *sso.Transaction, cb *sso.Callback) { cb.IdPID = "idp-b" }},
			{name: "Transaction of IdP B", mod: func(_ url.Values, tx *sso.Transaction, _ *sso.Callback) { tx.IdPID = "idp-b" }},
			{name: "RFC 9207 iss of IdP B", setup: func(h *harness) { h.cfg.Discovery.IssParamSupported = true },
				mod: func(q url.Values, _ *sso.Transaction, _ *sso.Callback) { q.Set("iss", "https://idp-b.example.test") }},
			{name: "RFC 9207 iss missing though advertised", setup: func(h *harness) { h.cfg.Discovery.IssParamSupported = true }},
		} {
			h, o := c.run(t)
			noExchange(t, h, c.name)
			outs = append(outs, o)
		}
		return outs
	},

	// O-M03: aud is another client; aud has an extra value; azp mismatch.
	"audience_wrong": func(t *testing.T) []outcome {
		return runAll(t,
			variant{name: "aud is another client", token: claimsEdit(map[string]any{"aud": "another-client"})},
			variant{name: "aud has an extra value", token: claimsEdit(map[string]any{"aud": []string{clientID, "another-client"}})},
			variant{name: "aud missing", token: claimsEdit(map[string]any{"aud": nil})},
			variant{name: "aud empty list", token: claimsEdit(map[string]any{"aud": []string{}})},
			variant{name: "azp mismatch", token: claimsEdit(map[string]any{"aud": []string{clientID}, "azp": "another-client"})},
		)
	},

	// O-M04: a valid token for tenant A on tenant B's hostname. The hostname binds tenant B's IdP (SSO-2),
	// whose pinned issuer and client are not A's, and the key cache is per tenant.
	"tenant_other": func(t *testing.T) []outcome {
		tenantB := func(h *harness) {
			h.cfg.Issuer = "https://idp-b.example.test"
			h.cfg.Discovery = sso.Discovery{
				Issuer: h.cfg.Issuer, AuthorizationEndpoint: h.cfg.Issuer + "/authorize", TokenEndpoint: h.cfg.Issuer + "/token",
				JWKSURI: h.cfg.Issuer + "/jwks", CodeChallengeMethods: []string{"S256"},
			}
			h.cfg.ClientID = "adq-console-b"
		}
		aToken := func(h *harness) func(sso.Transaction) string {
			return func(tx sso.Transaction) string {
				// Exactly what tenant A's IdP issues for tenant A's client.
				return mint(t, std(), map[string]any{"iss": issuer, "aud": clientID, "sub": "user-1", "nonce": tx.Nonce,
					"iat": h.now.Unix(), "exp": h.now.Add(5 * time.Minute).Unix()}, idpKey)
			}
		}
		outs := runAll(t, variant{name: "tenant A's token at tenant B's IdP", setup: tenantB, token: aToken})

		// A's token with only the client changed to B's still carries A's issuer.
		outs = append(outs, runAll(t, variant{name: "tenant A's issuer, tenant B's client", setup: tenantB,
			token: func(h *harness) func(sso.Transaction) string {
				return func(tx sso.Transaction) string {
					return mint(t, std(), map[string]any{"iss": issuer, "aud": "adq-console-b", "sub": "user-1", "nonce": tx.Nonce,
						"iat": h.now.Unix(), "exp": h.now.Add(5 * time.Minute).Unix()}, idpKey)
				}
			}})...)

		return outs
	},

	// O-M05: a discovery issuer that differs from the configured one; an HTTP endpoint.
	"discovery_changed": func(t *testing.T) []outcome {
		var outs []outcome
		for _, c := range []struct {
			name string
			mod  func(*harness)
		}{
			{"discovery issuer differs", func(h *harness) { h.cfg.Discovery.Issuer = "https://evil.example.test" }},
			{"http authorization endpoint", func(h *harness) { h.cfg.Discovery.AuthorizationEndpoint = "http://idp.example.test/authorize" }},
			{"http token endpoint", func(h *harness) { h.cfg.Discovery.TokenEndpoint = "http://idp.example.test/token" }},
			{"http jwks_uri", func(h *harness) { h.cfg.Discovery.JWKSURI = "http://idp.example.test/jwks" }},
			{"http issuer", func(h *harness) { h.cfg.Issuer = "http://idp.example.test"; h.cfg.Discovery.Issuer = h.cfg.Issuer }},
		} {
			h := newHarness(t)
			c.mod(h)
			if err := ValidateConfig(&h.cfg); sso.ReasonOf(err) != ReasonConfig {
				t.Fatalf("%s: ValidateConfig = %v (save must be refused)", c.name, err)
			}
			_, _, err := h.v.Start(t.Context(), tenant.New(), h.idp(), sso.IntentSignin)
			outs = append(outs, outcome{c.name + ", Start", sso.Verified{}, err})
			v, err := h.flow2()
			outs = append(outs, outcome{c.name + ", Complete", v, err})
			noExchange(t, h, c.name)
		}
		return outs
	},

	// O-D01: an ID token over 32 KiB; three or more dots.
	"token_shape": func(t *testing.T) []outcome {
		return runAll(t,
			variant{name: "ID token over 32 KiB", token: func(h *harness) func(sso.Transaction) string {
				return func(tx sso.Transaction) string {
					return mint(t, std(), h.claims(tx, map[string]any{"pad": strings.Repeat("x", 33<<10)}), idpKey)
				}
			}},
			variant{name: "three dots", token: func(h *harness) func(sso.Transaction) string {
				return func(tx sso.Transaction) string { return mint(t, std(), h.claims(tx, nil), idpKey) + ".AAAA" }
			}},
			variant{name: "four dots", token: func(h *harness) func(sso.Transaction) string {
				return func(tx sso.Transaction) string { return mint(t, std(), h.claims(tx, nil), idpKey) + ".AAAA.AAAA" }
			}},
			variant{name: "two parts", token: func(h *harness) func(sso.Transaction) string {
				return func(tx sso.Transaction) string {
					tok := mint(t, std(), h.claims(tx, nil), idpKey)
					return tok[:strings.LastIndex(tok, ".")]
				}
			}},
		)
	},

	// O-D01b: a token endpoint response over 64 KiB.
	"token_response_oversize": func(t *testing.T) []outcome {
		big := func(h *harness) {
			h.tokenBody = func(h *harness) (int, []byte) {
				b, _ := json.Marshal(map[string]any{"id_token": h.idToken, "pad": strings.Repeat("x", 65<<10)})
				return 200, b
			}
		}
		_, o := variant{name: "token response over 64 KiB", setup: big}.run(t)
		_, o2 := variant{name: "token response is not JSON", setup: func(h *harness) {
			h.tokenBody = func(*harness) (int, []byte) { return 200, bytes.Repeat([]byte("<"), 100) }
		}}.run(t)
		_, o3 := variant{name: "token endpoint answers 500", setup: func(h *harness) {
			h.tokenBody = func(*harness) (int, []byte) { return 500, []byte("{}") }
		}}.run(t)
		return []outcome{o, o2, o3}
	},

	// O-D02: sub missing, empty, over 255 bytes.
	"sub_invalid": func(t *testing.T) []outcome {
		return runAll(t,
			variant{name: "sub missing", token: claimsEdit(map[string]any{"sub": nil})},
			variant{name: "sub empty", token: claimsEdit(map[string]any{"sub": ""})},
			variant{name: "sub of 256 bytes", token: claimsEdit(map[string]any{"sub": strings.Repeat("a", 256)})},
			variant{name: "sub is a number", token: claimsEdit(map[string]any{"sub": 42})},
		)
	},

	// O-D03: claims come from the ID token only. A claim the configuration needs that the ID token does not
	// carry is not fetched from UserInfo, the access token or a Graph call: the sign-in is refused.
	"claims_only_from_id_token": func(t *testing.T) []outcome {
		var outs []outcome
		for _, c := range []variant{
			{name: "oid anchor configured, oid absent from the ID token", setup: func(h *harness) { h.cfg.AnchorClaim = "oid" },
				token: claimsEdit(map[string]any{"tid": "11111111-2222-3333-4444-555555555555"})},
			{name: "oid anchor configured, tid absent from the ID token", setup: func(h *harness) { h.cfg.AnchorClaim = "oid" },
				token: claimsEdit(map[string]any{"oid": "22222222-2222-3333-4444-555555555555"})},
			{name: "onprem_sid anchor configured, claim absent from the ID token", setup: func(h *harness) { h.cfg.AnchorClaim = "onprem_sid" }},
		} {
			h, o := c.run(t)
			for path := range h.calls {
				if path != "/jwks" && path != "/token" { // no UserInfo, no Graph, nothing but the two pinned endpoints
					t.Fatalf("%s: unexpected call to %s", c.name, path)
				}
			}
			outs = append(outs, o)
		}
		return outs
	},
}
