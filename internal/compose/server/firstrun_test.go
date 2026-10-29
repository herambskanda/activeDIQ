package server

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/compose/config"
	setupsecret "github.com/skenzeriq/activediq/internal/platform/setup"
)

func TestBuildSetupIssuesOnceAndShowPrintsIt(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Config{APITLSDir: dir, SetupTTL: time.Hour}
	tags, err := buildSetup(cfg, time.Now)
	if err != nil || len(tags) != 1 {
		t.Fatalf("buildSetup: %v %d", err, len(tags))
	}
	env := func(k string) string {
		if k == config.EnvAPITLSDir {
			return dir
		}
		return ""
	}
	var out bytes.Buffer
	if err := SetupShow(env, &out); err != nil || len(strings.TrimSpace(out.String())) < 52 {
		t.Fatalf("show: %v %q", err, out.String())
	}
	first := out.String()
	if _, err := buildSetup(cfg, time.Now); err != nil { // a restart
		t.Fatal(err)
	}
	out.Reset()
	_ = SetupShow(env, &out)
	if out.String() != first {
		t.Fatal("a restart rotated a live secret")
	}
	st, _ := setupStore(cfg, time.Now)
	if err := st.Claim(first); err != nil {
		t.Fatal(err)
	}
	if err := SetupShow(env, &out); err == nil {
		t.Fatal("show works after the secret was consumed")
	}
	if _, err := buildSetup(cfg, time.Now); err != nil { // claimed install still boots
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, setupsecret.DirName, setupsecret.SecretFile)); !os.IsNotExist(err) {
		t.Fatal("secret reissued on a claimed install")
	}
}

func TestBuildSetupWithoutDirIsOff(t *testing.T) {
	tags, err := buildSetup(config.Config{}, time.Now)
	if err != nil || tags != nil {
		t.Fatalf("%v %v", tags, err)
	}
}
