package hostcheck

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/tools/fitness/pgharness"
)

// A failing health endpoint is a fixture server: the probe must refuse a 503, a 200 with the wrong body and
// a refused connection, and accept the real answer.
func TestCheckReadyRefusesBrokenHealth(t *testing.T) {
	for name, tc := range map[string]struct {
		code int
		body string
		ok   bool
	}{
		"ready":              {200, `{"status":"ok"}`, true},
		"unavailable":        {503, `{"type":"about:blank","title":"Service Unavailable"}`, false},
		"200 but not ok":     {200, `{"status":"degraded"}`, false},
		"200 with a non-API": {200, `<html>proxy</html>`, false},
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.code)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			err := CheckReady(srv.Client(), srv.URL+"/health/ready")
			if (err == nil) != tc.ok {
				t.Fatalf("CheckReady = %v, want ok=%v", err, tc.ok)
			}
		})
	}
	if err := waitReady(nil, "127.0.0.1:1", 600*time.Millisecond); err == nil || !strings.Contains(err.Error(), "not ready") {
		t.Fatalf("a refused connection must fail the health step, got %v", err)
	}
}

func TestStepErrorNamesProfileAndStep(t *testing.T) {
	e := &StepError{Profile: "saas", Arch: "arm64", PG: "18", Step: StepHealth, Err: errors.New("boom")}
	for _, want := range []string{"P2-oci FAIL", "profile=saas", "arch=arm64", "postgres=18", "step=health", "boom"} {
		if !strings.Contains(e.Error(), want) {
			t.Errorf("%q lacks %q", e.Error(), want)
		}
	}
	if !errors.Is(e, e.Err) {
		t.Error("StepError must unwrap")
	}
}

// Each OCI manifest is judged on its capabilities: saas provisions tenants, linux-oci never does.
func TestManifestChecks(t *testing.T) {
	for _, p := range ociProfiles() {
		if err := p.checkManifest(); err != nil {
			t.Errorf("%s: %v", p.Name, err)
		}
		bad := p
		bad.Provisioning = !p.Provisioning
		if err := bad.checkManifest(); err == nil {
			t.Errorf("%s: a manifest whose tenant-provisioning capability disagrees must fail", p.Name)
		}
	}
}

func TestDockerArch(t *testing.T) {
	for in, want := range map[string]string{"x86_64": "amd64", "aarch64": "arm64", "amd64": "amd64"} {
		if got := dockerArch(in); got != want {
			t.Errorf("dockerArch(%q) = %q, want %q", in, got, want)
		}
	}
}

// The binary's ELF machine must match the image's architecture: an amd64 binary labelled arm64 fails.
func TestELFArchMismatchFails(t *testing.T) {
	self, err := os.Executable()
	if err != nil || !strings.HasSuffix(strings.ToLower(filepath.Base(self)), ".test") {
		t.Skip("needs a Linux ELF test binary")
	}
	if err := checkELFArch(self, "arm64"); err == nil && !strings.Contains(runtime.GOARCH, "arm64") {
		t.Error("an ELF of another architecture must fail checkELFArch")
	}
	if err := checkELFArch(self, "sparc"); err == nil {
		t.Error("an unsupported architecture must fail")
	}
}

// A deliberately broken migration fails the migrations step and the error names profile and step. Needs Docker.
func TestBrokenMigrationFailsNamingProfileAndStep(t *testing.T) {
	ctx := context.Background()
	if err := pgharness.DockerAvailable(ctx); err != nil {
		t.Skip(err)
	}
	ms, _, err := pgharness.ListMigrations(filepath.Join("..", "testdata", "p2oci-broken-migrations"))
	if err != nil || len(ms) != 1 {
		t.Fatalf("fixture: %v %v", ms, err)
	}
	pg, err := pgharness.StartServer(ctx, "16", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Stop()
	// bootCase stops at the migrations step, before any image is touched.
	err = bootCase(ctx, ociProfiles()[0], "amd64", "16", "no-such-image", pg, ms, func(string, ...any) {})
	var se *StepError
	if !errors.As(err, &se) {
		t.Fatalf("want a StepError, got %v", err)
	}
	if se.Step != StepMigrations || se.Profile != "linux-oci" || !strings.Contains(se.Error(), "0001_tenant_broken_fixture.sql") {
		t.Fatalf("got %v", se)
	}
}
