package connections

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const (
	tTenant = "11111111-2222-3333-4444-555555555555"
	tOID    = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
)

var tNow = time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)

func fakeJWT(claims map[string]any) string {
	enc := func(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
	return enc(map[string]any{"alg": "RS256", "nonce": "x"}) + "." + enc(claims) + ".c2ln"
}

func goodClaims() map[string]any {
	return map[string]any{"tid": tTenant, "oid": tOID, "iss": "https://login.microsoftonline.com/" + tTenant + "/v2.0",
		"aud": graphAppID, "exp": tNow.Add(time.Hour).Unix(), "scp": AttestScope}
}

type doerFunc func(*http.Request) (*http.Response, error)

func (f doerFunc) Do(r *http.Request) (*http.Response, error) { return f(r) }

func respond(status int, body string) doerFunc {
	return func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}, nil
	}
}

func tokenBody(jwt string) string {
	// refresh_token and id_token are present on purpose: the adapter must drop them.
	b, _ := json.Marshal(map[string]any{"token_type": "Bearer", "access_token": jwt, "scope": "https://graph.microsoft.com/" + AttestScope,
		"refresh_token": "REFRESH-SECRET", "id_token": "ID-SECRET"})
	return string(b)
}

func newIdP(d HTTPDoer) *OIDCIdP {
	return &OIDCIdP{HTTP: d, Authority: "https://login.microsoftonline.com", ClientID: "app-1", Now: func() time.Time { return tNow }}
}

var exReq = ExchangeRequest{TenantID: tTenant, Code: "the-code", CodeVerifier: "the-verifier", RedirectURI: "https://x/cb", Scopes: []string{AttestScope}}

func TestOIDCExchangeSendsPKCEAndReturnsOnlyClaimsAndBearer(t *testing.T) {
	var got *http.Request
	var form url.Values
	idp := newIdP(doerFunc(func(r *http.Request) (*http.Response, error) {
		got = r
		b, _ := io.ReadAll(r.Body)
		form, _ = url.ParseQuery(string(b))
		return respond(200, tokenBody(fakeJWT(goodClaims())))(r)
	}))
	g, err := idp.Exchange(context.Background(), exReq)
	if err != nil {
		t.Fatal(err)
	}
	if got.Method != "POST" || got.URL.String() != "https://login.microsoftonline.com/"+tTenant+"/oauth2/v2.0/token" {
		t.Fatalf("endpoint %s %s", got.Method, got.URL)
	}
	want := map[string]string{"client_id": "app-1", "grant_type": "authorization_code", "code": "the-code",
		"code_verifier": "the-verifier", "redirect_uri": "https://x/cb", "scope": AttestScope}
	for k, v := range want {
		if form.Get(k) != v {
			t.Errorf("form %s = %q", k, form.Get(k))
		}
	}
	if g.TenantID != tTenant || g.ObjectID != tOID || len(g.Scopes) != 1 || g.Scopes[0] != AttestScope {
		t.Fatalf("grant %+v", g)
	}
	if s := fmt.Sprintf("%v %+v %#v", g, g, g); strings.Contains(s, "REFRESH") || strings.Contains(s, "ID-SECRET") || strings.Contains(s, "eyJ") {
		t.Fatalf("grant prints a secret: %s", s)
	}
	_ = g.Token.Use(func(b []byte) error {
		if !strings.HasPrefix(string(b), "eyJ") {
			t.Errorf("bearer not the access token")
		}
		return nil
	})
}

func TestOIDCExchangeRefusals(t *testing.T) {
	mut := func(f func(map[string]any)) string { c := goodClaims(); f(c); return fakeJWT(c) }
	cases := map[string]struct {
		d    doerFunc
		want error
	}{
		"http error":       {respond(400, `{"error":"invalid_grant","error_description":"code the-code expired"}`), ErrIdPExchange},
		"not json":         {respond(200, `<html>`), ErrIdPResponse},
		"not bearer":       {respond(200, `{"token_type":"mac","access_token":"a.b.c"}`), ErrIdPResponse},
		"opaque token":     {respond(200, tokenBody("opaque")), ErrIdPClaims},
		"other tenant":     {respond(200, tokenBody(mut(func(c map[string]any) { c["tid"] = "99999999-2222-3333-4444-555555555555" }))), ErrTenantMismatch},
		"foreign issuer":   {respond(200, tokenBody(mut(func(c map[string]any) { c["iss"] = "https://evil.example/" + tTenant + "/v2.0" }))), ErrIdPClaims},
		"not graph aud":    {respond(200, tokenBody(mut(func(c map[string]any) { c["aud"] = "api://other" }))), ErrIdPClaims},
		"expired":          {respond(200, tokenBody(mut(func(c map[string]any) { c["exp"] = tNow.Add(-time.Second).Unix() }))), ErrIdPClaims},
		"no oid":           {respond(200, tokenBody(mut(func(c map[string]any) { delete(c, "oid") }))), ErrIdPClaims},
		"transport":        {func(*http.Request) (*http.Response, error) { return nil, errors.New("Post https://x/token?code=the-code") }, ErrIdPExchange},
		"oversized answer": {respond(200, strings.Repeat("a", maxIdPBody+10)), ErrIdPResponse},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			g, err := newIdP(c.d).Exchange(context.Background(), exReq)
			if !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
			if strings.Contains(err.Error(), "the-code") || strings.Contains(err.Error(), "eyJ") {
				t.Fatalf("error leaks input: %v", err)
			}
			_ = g.Token.Use(func(b []byte) error {
				if len(b) != 0 {
					t.Errorf("refusal returned a token")
				}
				return nil
			})
		})
	}
}

func TestOIDCScopeFromResponseWhenNoScpClaim(t *testing.T) {
	c := goodClaims()
	delete(c, "scp")
	g, err := newIdP(respond(200, tokenBody(fakeJWT(c)))).Exchange(context.Background(), exReq)
	if err != nil || len(g.Scopes) != 1 || g.Scopes[0] != AttestScope {
		t.Fatalf("%+v %v", g, err)
	}
	// An extra granted scope is passed through so the Attester's exactScope refuses it.
	c["scp"] = AttestScope + " offline_access"
	g, _ = newIdP(respond(200, tokenBody(fakeJWT(c)))).Exchange(context.Background(), exReq)
	if exactScope(g.Scopes) {
		t.Fatal("extra scope accepted")
	}
}

func TestGraphReaderReadsFeaturesWithBearer(t *testing.T) {
	var auth, path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth, path = r.Header.Get("Authorization"), r.URL.Path+"?"+r.URL.RawQuery
		fmt.Fprint(w, `{"value":[{"features":{"blockCloudObjectTakeoverThroughHardMatchEnabled":true,"blockSoftMatchEnabled":false,"other":1}}]}`)
	}))
	defer srv.Close()
	g := &GraphReader{HTTP: srv.Client(), Base: srv.URL + "/v1.0"}
	f, err := g.ReadSyncFeatures(context.Background(), NewBearer([]byte("tok")))
	if err != nil {
		t.Fatal(err)
	}
	if !f.BlockCloudObjectTakeoverThroughHardMatch || f.BlockSoftMatch {
		t.Fatalf("%+v", f)
	}
	if auth != "Bearer tok" || path != "/v1.0/directory/onPremisesSynchronization?$select=features" {
		t.Fatalf("%q %q", auth, path)
	}
}

func TestGraphReaderRefusals(t *testing.T) {
	for name, body := range map[string]string{
		"empty collection": `{"value":[]}`,
		"two items":        `{"value":[{"features":{"blockCloudObjectTakeoverThroughHardMatchEnabled":true,"blockSoftMatchEnabled":true}},{"features":{"blockCloudObjectTakeoverThroughHardMatchEnabled":true,"blockSoftMatchEnabled":true}}]}`,
		"missing soft":     `{"value":[{"features":{"blockCloudObjectTakeoverThroughHardMatchEnabled":true}}]}`,
		"missing hard":     `{"value":[{"features":{"blockSoftMatchEnabled":true}}]}`,
		"not json":         `nope`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := (&GraphReader{HTTP: respond(200, body)}).ReadSyncFeatures(context.Background(), NewBearer([]byte("t")))
			if !errors.Is(err, ErrGraphAnswer) {
				t.Fatalf("err = %v", err)
			}
		})
	}
	_, err := (&GraphReader{HTTP: respond(403, `{"error":{"message":"tok"}}`)}).ReadSyncFeatures(context.Background(), NewBearer([]byte("tok")))
	if !errors.Is(err, ErrGraphRefused) || strings.Contains(err.Error(), "tok") {
		t.Fatalf("err = %v", err)
	}
	_, err = (&GraphReader{HTTP: respond(200, "{}")}).ReadSyncFeatures(context.Background(), Bearer{})
	if !errors.Is(err, ErrGraphRefused) {
		t.Fatalf("empty bearer: %v", err)
	}
}
