package server

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/compose/config"
	"github.com/skenzeriq/activediq/internal/platform/apitls"
)

const testOpsToken = "ops-token-0123456789abcdef0123456789abcdef"

func writeToken(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ops.token")
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	return p
}

// T-0533: the API listener's handler does not serve the metrics at all, whatever the credential.
func TestAPIListenerDoesNotServeMetrics(t *testing.T) {
	h, err := buildAPI(config.Config{APIBodyBudget: config.DefaultAPIBodyBudget}, testLimiter(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, auth := range []string{"", "Bearer " + testOpsToken} {
		r := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		if auth != "" {
			r.Header.Set("Authorization", auth)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		// With a console embedded the listener answers the console shell for any non-API path (T-0686); what
		// must never be served is the exposition.
		if strings.Contains(rec.Body.String(), "activediq_keys_dek_unwraps_total") || strings.HasPrefix(rec.Header().Get("Content-Type"), "text/plain") {
			t.Fatalf("API listener served /metrics: %d %s", rec.Code, rec.Header().Get("Content-Type"))
		}
	}
}

func TestOpsListenerEndToEnd(t *testing.T) {
	id, err := apitls.LoadOrGenerateSealed("", "127.0.0.1:0", time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{OpsAddr: "127.0.0.1:0", OpsTokenFile: writeToken(t, testOpsToken+"\n", 0o600)}
	// Port 0: grab the real address by listening through listenOps' own path.
	o, err := startOps(cfg, id.TLSConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer o.shutdown(context.Background())

	// The client does not verify the self-signed install certificate (pinning is the admin's job);
	// this test is about the credential.
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, Timeout: 5 * time.Second}
	get := func(auth string, hdr ...string) (int, string) {
		req, _ := http.NewRequest(http.MethodGet, "https://"+o.addr+"/metrics", nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if code, _ := get(""); code != http.StatusUnauthorized {
		t.Fatalf("no credential: %d", code)
	}
	if code, _ := get("Bearer diq_tenantkey_0123456789abcdef0123456789"); code != http.StatusUnauthorized {
		t.Fatalf("tenant key: %d", code)
	}
	code, body := get("Bearer " + testOpsToken)
	if code != http.StatusOK || !strings.Contains(body, "# TYPE activediq_keys_dek_unwraps_total counter") {
		t.Fatalf("ops credential: %d %q", code, body)
	}
}

func TestStartOpsOffWhenUnconfigured(t *testing.T) {
	o, err := startOps(config.Config{}, nil)
	if o != nil || err != nil {
		t.Fatalf("got %v, %v", o, err)
	}
	if o.err() != nil || o.shutdown(context.Background()) != nil {
		t.Fatal("nil listener must be inert")
	}
}

func TestReadOpsTokenRefusesUnsafeFiles(t *testing.T) {
	for name, p := range map[string]string{
		"short":      writeToken(t, "short", 0o600),
		"world-read": writeToken(t, testOpsToken, 0o644),
		"missing":    filepath.Join(t.TempDir(), "nope"),
	} {
		if _, err := readOpsToken(p); err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), testOpsToken) {
			t.Errorf("%s: error carries the token", name)
		}
	}
	tok, err := readOpsToken(writeToken(t, testOpsToken+"\r\n", 0o600))
	if err != nil || tok.IsEmpty() {
		t.Fatalf("valid token refused: %v", err)
	}
}
