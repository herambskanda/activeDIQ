package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"runtime"

	"github.com/skenzeriq/activediq/internal/compose/config"
	"github.com/skenzeriq/activediq/internal/platform/keys"
	"github.com/skenzeriq/activediq/internal/platform/opsmetrics"
	"github.com/skenzeriq/activediq/internal/platform/secret"
)

// opsListener is the optional operator listener (threat model §8.1 L4). It serves only /metrics, on its
// own address, behind the operator token. A nil *opsListener is "not configured".
type opsListener struct {
	srv     *http.Server
	serving chan error
	addr    string // the bound address (resolves a :0 bind)
}

// startOps opens the ops listener when configured. A configured listener that cannot start (missing or
// unsafe token file, short token, bind failure) is an error: metrics are never silently unauthenticated.
func startOps(cfg config.Config, tlsConfig *tls.Config) (*opsListener, error) {
	if cfg.OpsAddr == "" {
		return nil, nil
	}
	tok, err := readOpsToken(cfg.OpsTokenFile)
	if err != nil {
		return nil, err
	}
	// The ops listener has no tenant authenticator and no API routes: opsmetrics.Handler is the only handler.
	return listenOps(cfg.OpsAddr, opsmetrics.Handler(tok, keys.WriteMetrics), tlsConfig)
}

func listenOps(addr string, h http.Handler, tlsConfig *tls.Config) (*opsListener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("server: ops listen: %w", err)
	}
	o := &opsListener{srv: newAPIServer(addr, h, tlsConfig), serving: make(chan error, 1), addr: ln.Addr().String()}
	go func() { o.serving <- o.srv.ServeTLS(ln, "", "") }()
	slog.Info("server: ops listening (TLS)", "addr", ln.Addr().String())
	return o, nil
}

// err is the channel the serve loop reports on; a nil listener never reports.
func (o *opsListener) err() <-chan error {
	if o == nil {
		return nil
	}
	return o.serving
}

func (o *opsListener) shutdown(ctx context.Context) error {
	if o == nil {
		return nil
	}
	if err := o.srv.Shutdown(ctx); err != nil {
		_ = o.srv.Close()
		return fmt.Errorf("server: ops shutdown: %w", err)
	}
	return nil
}

func readOpsToken(path string) (secret.Secret, error) {
	if err := kekFileSupported(runtime.GOOS); err != nil {
		return secret.Secret{}, fmt.Errorf("ops token file: %w", err)
	}
	f, err := openSecretFile("ops token file", path)
	if err != nil {
		return secret.Secret{}, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 1024))
	if err != nil {
		return secret.Secret{}, fmt.Errorf("ops token file %s: read failed", path)
	}
	defer clear(raw)
	for len(raw) > 0 && (raw[len(raw)-1] == '\n' || raw[len(raw)-1] == '\r' || raw[len(raw)-1] == ' ') {
		raw = raw[:len(raw)-1]
	}
	if len(raw) < opsmetrics.MinTokenBytes {
		return secret.Secret{}, errors.New("ops token file " + path + " must hold a token of at least 32 bytes")
	}
	return secret.FromBytes(raw), nil
}
