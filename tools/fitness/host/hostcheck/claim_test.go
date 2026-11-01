package hostcheck

import (
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/setup"
)

// TestClaimBodyCarriesValidOwner pins T-1161: the claim route validates the owner block before it looks
// at the secret, so a probe body without a valid owner gets a 400 that says nothing about the secret.
// The body is judged by the server's own owner validator, so a tightened contract fails here, not in a
// Docker run on main.
func TestClaimBodyCarriesValidOwner(t *testing.T) {
	var got struct {
		Secret string `json:"secret"`
		Owner  struct {
			DisplayName string `json:"displayName"`
			Email       string `json:"email"`
		} `json:"owner"`
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/setup/claim" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("body is not JSON: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	st, err := claimSetup(srv.Listener.Addr().String(), roots, `s3"cret`)
	if err != nil || st != http.StatusNoContent {
		t.Fatalf("claimSetup = %d, %v", st, err)
	}
	if got.Secret != `s3"cret` {
		t.Errorf("secret not carried verbatim: %q", got.Secret)
	}
	if !(setup.OwnerDetails{DisplayName: got.Owner.DisplayName, Email: got.Owner.Email}).Valid() {
		t.Errorf("owner block %+v is refused by the server's own validator", got.Owner)
	}
}
