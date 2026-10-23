package webhook

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/egress"
)

func mustSecret(t *testing.T) Secret {
	t.Helper()
	s, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func loopbackClient(t *testing.T) *egress.Client {
	t.Helper()
	c, err := egress.New(egress.Config{AllowHTTP: true, Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// The Standard Webhooks reference vector (secret MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw).
func TestKnownVector(t *testing.T) {
	s, err := ParseSecret("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw")
	if err == nil {
		_ = s // base64 of that text is 24 bytes: accepted
	}
	g, err := NewSigner(s)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"test": 2432232314}`)
	sig, err := g.Sign("msg_p5jXN8AQM9LWM0D4loKWxJek", time.Unix(1614265330, 0), body)
	if err != nil {
		t.Fatal(err)
	}
	if sig != "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=" {
		t.Fatalf("signature %q does not match the Standard Webhooks reference vector", sig)
	}
}

func TestSignVerifyRoundTripAndTamper(t *testing.T) {
	sec := mustSecret(t)
	g, _ := NewSigner(sec)
	now := time.Now()
	body := []byte(`{"type":"user.created"}`)
	sig, _ := g.Sign("msg_1", now, body)
	h := http.Header{}
	h.Set(HeaderID, "msg_1")
	h.Set(HeaderTimestamp, strconv.FormatInt(now.Unix(), 10))
	h.Set(HeaderSignature, sig)
	if err := Verify(h, body, now, 0, sec); err != nil {
		t.Fatalf("valid message rejected: %v", err)
	}
	if err := Verify(h, []byte(`{"type":"user.deleted"}`), now, 0, sec); !errors.Is(err, ErrSignature) {
		t.Fatalf("altered body: %v", err)
	}
	if err := Verify(h, body, now, 0, mustSecret(t)); !errors.Is(err, ErrSignature) {
		t.Fatalf("wrong secret: %v", err)
	}
	h2 := h.Clone()
	h2.Set(HeaderID, "msg_2")
	if err := Verify(h2, body, now, 0, sec); !errors.Is(err, ErrSignature) {
		t.Fatalf("altered id: %v", err)
	}
}

func TestReplayOutsideToleranceRejected(t *testing.T) {
	sec := mustSecret(t)
	g, _ := NewSigner(sec)
	sent := time.Now()
	body := []byte(`{}`)
	sig, _ := g.Sign("msg_1", sent, body)
	h := http.Header{}
	h.Set(HeaderID, "msg_1")
	h.Set(HeaderTimestamp, strconv.FormatInt(sent.Unix(), 10))
	h.Set(HeaderSignature, sig)
	if err := Verify(h, body, sent.Add(4*time.Minute), 0, sec); err != nil {
		t.Fatalf("within tolerance: %v", err)
	}
	if err := Verify(h, body, sent.Add(6*time.Minute), 0, sec); !errors.Is(err, ErrTimestamp) {
		t.Fatalf("old message: %v", err)
	}
	if err := Verify(h, body, sent.Add(-6*time.Minute), 0, sec); !errors.Is(err, ErrTimestamp) {
		t.Fatalf("future message: %v", err)
	}
	if err := Verify(h, body, sent.Add(2*time.Minute), time.Minute, sec); !errors.Is(err, ErrTimestamp) {
		t.Fatalf("custom tolerance: %v", err)
	}
}

func TestRotationOverlap(t *testing.T) {
	oldS, newS := mustSecret(t), mustSecret(t)
	g, _ := NewSigner(newS, oldS)
	now := time.Now()
	sig, _ := g.Sign("msg_1", now, []byte("x"))
	if strings.Count(sig, "v1,") != 2 {
		t.Fatalf("want two signatures, got %q", sig)
	}
	h := http.Header{}
	h.Set(HeaderID, "msg_1")
	h.Set(HeaderTimestamp, strconv.FormatInt(now.Unix(), 10))
	h.Set(HeaderSignature, sig)
	for _, s := range []Secret{oldS, newS} {
		if err := Verify(h, []byte("x"), now, 0, s); err != nil {
			t.Fatalf("receiver with one secret: %v", err)
		}
	}
}

func TestMalformedHeaders(t *testing.T) {
	sec := mustSecret(t)
	now := time.Now()
	mk := func(kv ...string) http.Header {
		h := http.Header{}
		for i := 0; i < len(kv); i += 2 {
			h.Set(kv[i], kv[i+1])
		}
		return h
	}
	for name, h := range map[string]http.Header{
		"none":   {},
		"no sig": mk(HeaderID, "a", HeaderTimestamp, "1"),
		"bad ts": mk(HeaderID, "a", HeaderTimestamp, "x", HeaderSignature, "v1,AAAA"),
	} {
		if err := Verify(h, nil, now, 0, sec); !errors.Is(err, ErrMissingHeaders) {
			t.Errorf("%s: %v", name, err)
		}
	}
	h := http.Header{}
	h.Set(HeaderID, "a")
	h.Set(HeaderTimestamp, strconv.FormatInt(now.Unix(), 10))
	h.Set(HeaderSignature, "v2,AAAA garbage v1,!!")
	if err := Verify(h, nil, now, 0, sec); !errors.Is(err, ErrSignature) {
		t.Errorf("garbage signatures: %v", err)
	}
}

func TestSecretNeverPrints(t *testing.T) {
	s := mustSecret(t)
	for _, out := range []string{s.String(), strings.TrimSpace(strings.ReplaceAll(strings.Repeat("%v", 1), "%v", s.String()))} {
		if strings.Contains(out, s.Reveal()[6:]) {
			t.Fatal("secret leaked")
		}
	}
	rt, err := ParseSecret(s.Reveal())
	if err != nil || rt.Reveal() != s.Reveal() {
		t.Fatalf("round trip: %v", err)
	}
	for _, bad := range []string{"", "whsec_", "whsec_!!!", "whsec_QUJD"} {
		if _, err := ParseSecret(bad); !errors.Is(err, ErrBadSecret) {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := NewSigner(); !errors.Is(err, ErrBadSecret) {
		t.Error("signer without secret")
	}
	if _, err := NewSigner(Secret{}); !errors.Is(err, ErrBadSecret) {
		t.Error("signer with zero secret")
	}
}

func TestSendSignsThroughEgress(t *testing.T) {
	sec := mustSecret(t)
	g, _ := NewSigner(sec)
	var gotErr error
	var gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotCT = r.Header.Get("Content-Type")
		gotErr = Verify(r.Header, b, time.Now(), 0, sec)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	s, err := NewSender(loopbackClient(t))
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.Send(context.Background(), srv.URL+"/hook?token=abc", Message{ID: "msg_9", Body: []byte(`{"type":"job.completed"}`)}, g)
	if err != nil || !res.Delivered || res.StatusCode != 204 {
		t.Fatalf("send: %+v %v", res, err)
	}
	if gotErr != nil {
		t.Fatalf("receiver could not verify: %v", gotErr)
	}
	if gotCT != "application/json" {
		t.Errorf("content-type %q", gotCT)
	}
}

func TestSendRefusals(t *testing.T) {
	g, _ := NewSigner(mustSecret(t))
	// The default egress client refuses loopback: delivery cannot bypass the destination vetting.
	strict, _ := egress.New(egress.Config{AllowHTTP: true})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("request reached a refused destination") }))
	defer srv.Close()
	s, _ := NewSender(strict)
	if _, err := s.Send(context.Background(), srv.URL, Message{ID: "m", Body: []byte("{}")}, g); !errors.Is(err, egress.ErrDestinationDenied) {
		t.Fatalf("loopback via egress: %v", err)
	}
	s2, _ := NewSender(loopbackClient(t))
	if _, err := s2.Send(context.Background(), srv.URL, Message{ID: "m", Body: []byte("{}")}, nil); !errors.Is(err, ErrBadSecret) {
		t.Fatalf("nil signer: %v", err)
	}
	if _, err := s2.Send(context.Background(), srv.URL, Message{ID: "a.b", Body: nil}, g); !errors.Is(err, ErrBadMessage) {
		t.Fatalf("bad id: %v", err)
	}
	if _, err := NewSender(nil); err == nil {
		t.Fatal("nil egress client accepted")
	}
}

func TestNon2xxIsNotDelivered(t *testing.T) {
	g, _ := NewSigner(mustSecret(t))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) }))
	defer srv.Close()
	s, _ := NewSender(loopbackClient(t))
	res, err := s.Send(context.Background(), srv.URL, Message{ID: "m", Body: []byte("{}")}, g)
	if err != nil || res.Delivered || res.StatusCode != 500 {
		t.Fatalf("%+v %v", res, err)
	}
}
