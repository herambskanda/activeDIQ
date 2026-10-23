package webhook_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/egress"
	"github.com/skenzeriq/activediq/internal/platform/webhook"
)

func TestUnsignedPathDoesNotExist(t *testing.T) {
	c, err := egress.New(egress.Config{AllowHTTP: true, Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("unsigned request reached the receiver") }))
	defer srv.Close()
	s, _ := webhook.NewSender(c)
	m := webhook.Message{ID: "m1", Body: []byte("{}")}

	if _, err := s.Send(context.Background(), srv.URL, m, &webhook.Signer{}); !errors.Is(err, webhook.ErrBadSecret) {
		t.Fatalf("zero Signer send: %v", err)
	}
	if sig, err := (&webhook.Signer{}).Sign("m1", time.Now(), nil); !errors.Is(err, webhook.ErrBadSecret) || sig != "" {
		t.Fatalf("zero Signer sign: %q %v", sig, err)
	}
	sec, err := webhook.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	g, err := webhook.NewSigner(sec)
	if err != nil {
		t.Fatal(err)
	}
	sec.Destroy()
	if _, err := g.Sign("m1", time.Now(), nil); !errors.Is(err, webhook.ErrBadSecret) {
		t.Fatalf("destroyed sign: %v", err)
	}
	if _, err := s.Send(context.Background(), srv.URL, m, g); !errors.Is(err, webhook.ErrBadSecret) {
		t.Fatalf("destroyed send: %v", err)
	}
}
