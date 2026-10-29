package server

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/skenzeriq/activediq/internal/compose/config"
	"github.com/skenzeriq/activediq/internal/platform/apihost"
	setupsecret "github.com/skenzeriq/activediq/internal/platform/setup"
)

// setupStore is the first-run setup store under the API TLS directory (a subdirectory inherits the
// directory's 0700 mode and its Windows ACL). It is nil when the install has no durable directory: that
// is loopback development, which has no installing administrator to hand a secret to.
func setupStore(cfg config.Config, now func() time.Time) (*setupsecret.Store, error) {
	if cfg.APITLSDir == "" {
		return nil, nil
	}
	ttl := cfg.SetupTTL
	if ttl == 0 {
		ttl = config.DefaultSetupTTL
	}
	st, err := setupsecret.New(filepath.Join(cfg.APITLSDir, setupsecret.DirName), ttl, setupsecret.WithClock(now))
	if err != nil {
		return nil, fmt.Errorf("server: first-run setup: %w", err)
	}
	return st, nil
}

// buildSetup issues the one-time setup secret on an unclaimed install and returns the claim route. The
// secret is never logged: the log names the file the administrator reads it from and when it expires.
func buildSetup(cfg config.Config, now func() time.Time) ([]apihost.TagHandlers, error) {
	st, err := setupStore(cfg, now)
	if err != nil || st == nil {
		return nil, err
	}
	issued, exp, err := st.Issue()
	switch {
	case errors.Is(err, setupsecret.ErrAlreadyClaimed):
		slog.Info("server: first-run setup was already claimed")
	case err != nil:
		return nil, fmt.Errorf("server: first-run setup: %w", err)
	case issued:
		slog.Info("server: first-run setup secret issued; read it as the installing administrator with `activediq-server setup show`",
			"file", st.SecretPath(), "expires", exp.UTC().Format(time.RFC3339))
	default:
		slog.Info("server: first-run setup secret still valid", "expires", exp.UTC().Format(time.RFC3339))
	}
	// The route is mounted even when claimed: it answers the same refusal as for a wrong secret.
	return []apihost.TagHandlers{setupsecret.Handlers{Store: st}.Bind()}, nil
}

// SetupShow is `activediq-server setup show`: it prints the setup secret to out for the installing
// administrator. It reads the file with the operating system's own access control, so anyone but the
// service account and administrators gets a permission error, not the secret.
func SetupShow(getenv func(string) string, out io.Writer) error {
	dir := getenv(config.EnvAPITLSDir)
	if dir == "" {
		return fmt.Errorf("%s is not set: the setup secret lives under the API TLS directory", config.EnvAPITLSDir)
	}
	b, err := os.ReadFile(filepath.Join(dir, setupsecret.DirName, setupsecret.SecretFile))
	switch {
	case errors.Is(err, os.ErrNotExist):
		return errors.New("there is no setup secret: setup was already claimed, or the server has not started on this install")
	case err != nil:
		return fmt.Errorf("cannot read the setup secret: %w", err)
	}
	_, err = out.Write(b)
	return err
}
