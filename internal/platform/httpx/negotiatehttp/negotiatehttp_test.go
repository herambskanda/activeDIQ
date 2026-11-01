package negotiatehttp

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/authn"
	"github.com/skenzeriq/activediq/internal/platform/authn/negotiate"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

var tid = func() tenant.ID {
	id, err := tenant.Parse("22222222-2222-4222-8222-222222222222")
	if err != nil {
		panic(err)
	}
	return id
}()

type none struct{}

func (none) Accept(context.Context, []byte) (negotiate.Principal, error) {
	return negotiate.Principal{}, errors.New("rejected")
}
func (none) ObjectsBySID(context.Context, tenant.ID, string) ([]authn.DirectoryRef, error) {
	return nil, nil
}
func (none) BackedBy(context.Context, tenant.ID, authn.DirectoryRef) ([]string, error) {
	return nil, nil
}
func (none) Get(context.Context, tenant.ID, string) (authn.Account, error) {
	return authn.Account{}, authn.ErrAccountNotFound
}
func (none) Epoch(context.Context, tenant.ID, string) (authn.Epoch, error) {
	return authn.Epoch{}, authn.ErrAccountInactive
}
func (none) Begin(context.Context, authn.BeginInput) (authn.PendingHandle, error) {
	return authn.PendingHandle{}, errors.New("unreachable")
}

func newHandler() *Handler {
	n := none{}
	svc := &negotiate.Service{Acceptor: n, Directory: n, Accounts: n, Epochs: n, Pending: n, Recorder: recorder{}}
	return &Handler{Service: svc, Tenant: func(*http.Request) (tenant.ID, bool) { return tid, true }, NextPath: "/sign-in/second-factor"}
}

func do(hh *Handler, auth ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, Path, nil)
	for _, a := range auth {
		r.Header.Add("Authorization", a)
	}
	w := httptest.NewRecorder()
	hh.HTTPHandler().ServeHTTP(w, r)
	return w
}

func Test_challenge_when_no_token(t *testing.T) {
	w := do(newHandler())
	if w.Code != 401 || w.Header().Get("WWW-Authenticate") != "Negotiate" {
		t.Fatalf("%d %v", w.Code, w.Header())
	}
}

// Every refusal after a token was offered has the same status, headers and body, and does not
// re-challenge.
func Test_an9_http_failures_are_identical(t *testing.T) {
	ntlm := "NTLM " + base64.StdEncoding.EncodeToString([]byte("NTLMSSP\x00\x01\x00\x00\x00"))
	negNTLM := "Negotiate " + base64.StdEncoding.EncodeToString([]byte("NTLMSSP\x00\x01\x00\x00\x00"))
	garbage := "Negotiate " + base64.StdEncoding.EncodeToString([]byte("not a token"))
	var first *httptest.ResponseRecorder
	for name, auth := range map[string][]string{
		"ntlm scheme": {ntlm}, "ntlmssp in negotiate": {negNTLM}, "garbage": {garbage},
		"bad base64": {"Negotiate !!!"}, "two headers": {garbage, garbage}, "basic": {"Basic Zm9vOmJhcg=="},
	} {
		w := do(newHandler(), auth...)
		if w.Code != 401 || w.Header().Get("WWW-Authenticate") == "Negotiate" || w.Header().Get("Set-Cookie") != "" {
			t.Errorf("%s: %d %v", name, w.Code, w.Header())
		}
		if first == nil {
			first = w
			continue
		}
		if w.Body.String() != first.Body.String() || w.Header().Get("Content-Type") != first.Header().Get("Content-Type") {
			t.Errorf("%s: response differs", name)
		}
	}
}

func Test_header_cap_is_431(t *testing.T) {
	big := "Negotiate " + base64.StdEncoding.EncodeToString(make([]byte, negotiate.MaxTokenBytes+1))
	if w := do(newHandler(), big); w.Code != 431 {
		t.Fatalf("got %d", w.Code)
	}
	huge := "Negotiate " + strings.Repeat("A", 200_000)
	if w := do(newHandler(), huge); w.Code != 431 {
		t.Fatalf("got %d", w.Code)
	}
}

func Test_post_is_405(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, Path, nil)
	w := httptest.NewRecorder()
	newHandler().HTTPHandler().ServeHTTP(w, r)
	if w.Code != 405 {
		t.Fatal(w.Code)
	}
}

type recorder struct{}

func (recorder) Refused(context.Context, tenant.ID, string, netip.Addr) error { return nil }

type okAll struct{ none }

func (okAll) Accept(context.Context, []byte) (negotiate.Principal, error) {
	return negotiate.Principal{SID: "S-1-5-21-1-2-3-1001"}, nil
}
func (okAll) ObjectsBySID(context.Context, tenant.ID, string) ([]authn.DirectoryRef, error) {
	return []authn.DirectoryRef{{ConnectionID: "11111111-1111-4111-8111-111111111111", ObjectGUID: "aaaaaaaa-0000-4000-8000-0000000000a1"}}, nil
}
func (okAll) BackedBy(context.Context, tenant.ID, authn.DirectoryRef) ([]string, error) {
	return []string{"bbbbbbbb-0000-4000-8000-0000000000b1"}, nil
}
func (okAll) Get(_ context.Context, _ tenant.ID, id string) (authn.Account, error) {
	return authn.Account{ID: id, State: authn.AccountActive}, nil
}
func (okAll) Epoch(context.Context, tenant.ID, string) (authn.Epoch, error) {
	return authn.Epoch{}, nil
}
func (okAll) Begin(context.Context, authn.BeginInput) (authn.PendingHandle, error) {
	return authn.ParsePendingHandle(tid.String() + ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
}

// A Kerberos-shaped token: SPNEGO NegTokenInit, krb5 OID first, a krb5 AP-REQ shell.
func krbShaped() []byte {
	oidK := []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02}
	apreq := []byte{0x6e, 0x02, 0x30, 0x00}
	krb := append(append([]byte{0x60, byte(len(oidK) + 2 + len(apreq))}, oidK...), append([]byte{0x01, 0x00}, apreq...)...)
	octet := append([]byte{0x04, byte(len(krb))}, krb...)
	tok2 := append([]byte{0xa2, byte(len(octet))}, octet...)
	mtl := append([]byte{0xa0, byte(len(oidK) + 2), 0x30, byte(len(oidK))}, oidK...)
	seqBody := append(mtl, tok2...)
	seq := append([]byte{0x30, byte(len(seqBody))}, seqBody...)
	init := append([]byte{0xa0, byte(len(seq))}, seq...)
	spn := []byte{0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}
	body := append(spn, init...)
	return append([]byte{0x60, byte(len(body))}, body...)
}

func Test_success_sets_pending_cookie_and_redirects(t *testing.T) {
	n := okAll{}
	h := &Handler{Service: &negotiate.Service{Acceptor: n, Directory: n, Accounts: n, Epochs: n, Pending: n, Recorder: recorder{}},
		Tenant: func(*http.Request) (tenant.ID, bool) { return tid, true }, NextPath: "/sign-in/second-factor"}
	w := do(h, "Negotiate "+base64.StdEncoding.EncodeToString(krbShaped()))
	if w.Code != 303 || w.Header().Get("Location") != "/sign-in/second-factor" {
		t.Fatalf("%d %v", w.Code, w.Header())
	}
	c := w.Result().Cookies()
	if len(c) != 1 || c[0].Name != authn.PendingCookieName || !c[0].HttpOnly || !c[0].Secure {
		t.Fatalf("cookies %v", c)
	}
	for _, x := range c {
		if x.Name == "__Host-adiq_session" {
			t.Fatal("a session cookie was set")
		}
	}
}
