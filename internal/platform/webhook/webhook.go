// Package webhook signs and sends outbound webhooks per the Standard Webhooks scheme
// (https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md),
// threat model §5.9 TM-TB9-T9 (receivers spoofed or payloads altered).
//
// Every message carries webhook-id, webhook-timestamp and webhook-signature:
//
//	webhook-signature: v1,<base64 HMAC-SHA256 over "{id}.{timestamp}.{body}">
//
// There is no unsigned send path: the only way to deliver is Sender.Send, which requires a Signer
// and signs every attempt, and Sender delivers exclusively through the egress client (T-0160).
// During secret rotation a Signer holds several secrets and emits one space-delimited signature per
// secret, so a receiver that knows either secret verifies. Verify rejects a timestamp outside the
// tolerance in either direction (replay and clock-skew), compares in constant time, and never
// reports which part failed beyond a typed error.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/egress"
)

// Header names (canonical form is applied by net/http).
const (
	HeaderID        = "webhook-id"
	HeaderTimestamp = "webhook-timestamp"
	HeaderSignature = "webhook-signature"
)

const (
	// DefaultTolerance is the replay window: api-design conventions §6 and the Standard Webhooks
	// recommendation (5 minutes).
	DefaultTolerance = 5 * time.Minute

	secretPrefix  = "whsec_"
	minSecretLen  = 24
	maxSecretLen  = 64
	newSecretLen  = 32
	maxIDLen      = 128
	maxBodyBytes  = 1 << 20
	drainBytes    = 4 << 10
	sigVersion    = "v1"
	contentTypeJS = "application/json"
)

// Typed failures; test with errors.Is.
var (
	ErrBadSecret      = errors.New("webhook: invalid signing secret")
	ErrBadMessage     = errors.New("webhook: invalid message")
	ErrMissingHeaders = errors.New("webhook: missing or malformed signature headers")
	ErrTimestamp      = errors.New("webhook: timestamp outside the tolerance")
	ErrSignature      = errors.New("webhook: no signature matches")
)

// Secret is a signing secret. It never prints: String, GoString and MarshalText are redacted. The
// wire form for the endpoint owner is "whsec_" + base64(key), shown once at creation or rotation.
type Secret struct{ key []byte }

// NewSecret generates a fresh random secret.
func NewSecret() (Secret, error) {
	k := make([]byte, newSecretLen)
	if _, err := rand.Read(k); err != nil {
		return Secret{}, fmt.Errorf("%w: entropy: %v", ErrBadSecret, err)
	}
	return Secret{key: k}, nil
}

// ParseSecret reads the "whsec_<base64>" form (the prefix is optional) of 24 to 64 key bytes.
func ParseSecret(s string) (Secret, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, secretPrefix))
	if err != nil || len(raw) < minSecretLen || len(raw) > maxSecretLen {
		return Secret{}, fmt.Errorf("%w: expected %s<base64> of %d-%d bytes", ErrBadSecret, secretPrefix, minSecretLen, maxSecretLen)
	}
	return Secret{key: raw}, nil
}

// Reveal returns the wire form. Call it only where the owner is shown the secret once.
func (s Secret) Reveal() string { return secretPrefix + base64.StdEncoding.EncodeToString(s.key) }

func (s Secret) String() string               { return "whsec_[redacted]" }
func (s Secret) GoString() string             { return "webhook.Secret{[redacted]}" }
func (s Secret) MarshalText() ([]byte, error) { return []byte("[redacted]"), nil }
func (s Secret) valid() bool                  { return len(s.key) >= minSecretLen }

func (s Secret) mac(id string, ts int64, body []byte) []byte {
	h := hmac.New(sha256.New, s.key)
	h.Write([]byte(id))
	h.Write([]byte("."))
	h.Write([]byte(strconv.FormatInt(ts, 10)))
	h.Write([]byte("."))
	h.Write(body)
	return h.Sum(nil)
}

// Signer produces signature header values. Hold two secrets only while a rotation overlaps.
type Signer struct{ secrets []Secret }

// NewSigner needs at least one valid secret.
func NewSigner(secrets ...Secret) (*Signer, error) {
	if len(secrets) == 0 {
		return nil, fmt.Errorf("%w: no secret", ErrBadSecret)
	}
	for _, s := range secrets {
		if !s.valid() {
			return nil, fmt.Errorf("%w: zero secret", ErrBadSecret)
		}
	}
	return &Signer{secrets: append([]Secret(nil), secrets...)}, nil
}

// Sign returns the webhook-signature value for the message.
func (g *Signer) Sign(id string, ts time.Time, body []byte) (string, error) {
	if err := checkID(id); err != nil {
		return "", err
	}
	parts := make([]string, len(g.secrets))
	for i, s := range g.secrets {
		parts[i] = sigVersion + "," + base64.StdEncoding.EncodeToString(s.mac(id, ts.Unix(), body))
	}
	return strings.Join(parts, " "), nil
}

func checkID(id string) error {
	if id == "" || len(id) > maxIDLen {
		return fmt.Errorf("%w: id must be 1-%d characters", ErrBadMessage, maxIDLen)
	}
	for _, r := range id {
		ok := r == '_' || r == '-' || r == ':' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z'
		if !ok {
			return fmt.Errorf("%w: id may contain letters, digits, '_', '-' and ':' only", ErrBadMessage)
		}
	}
	return nil
}

// Verify checks a received message against the receiver's secrets (any one may match). h are the
// request headers, body the exact raw bytes received, now the receiver's clock. A timestamp more
// than tolerance from now, in either direction, is rejected (tolerance <= 0 means DefaultTolerance).
// The timestamp is checked before the signature so a replay costs no HMAC.
func Verify(h http.Header, body []byte, now time.Time, tolerance time.Duration, secrets ...Secret) error {
	if tolerance <= 0 {
		tolerance = DefaultTolerance
	}
	id, tsRaw, sigs := h.Get(HeaderID), h.Get(HeaderTimestamp), h.Get(HeaderSignature)
	if id == "" || tsRaw == "" || sigs == "" {
		return ErrMissingHeaders
	}
	ts, err := strconv.ParseInt(tsRaw, 10, 64)
	if err != nil {
		return ErrMissingHeaders
	}
	if d := now.Sub(time.Unix(ts, 0)); d > tolerance || d < -tolerance {
		return ErrTimestamp
	}
	matched := false
	for _, s := range secrets {
		if !s.valid() {
			continue
		}
		want := s.mac(id, ts, body)
		for _, cand := range strings.Fields(sigs) {
			v, enc, ok := strings.Cut(cand, ",")
			if !ok || v != sigVersion {
				continue
			}
			got, derr := base64.StdEncoding.DecodeString(enc)
			if derr == nil && hmac.Equal(got, want) {
				matched = true
			}
		}
	}
	if !matched {
		return ErrSignature
	}
	return nil
}

// Message is one webhook delivery. ID is the dedupe key and is stable across retries of the same
// event; the timestamp and signature are produced per attempt by Sender.
type Message struct {
	ID   string
	Body []byte // JSON payload, versioned by its content; carries no secrets
}

// Result is the receiver's answer to one attempt.
type Result struct {
	StatusCode int
	// Delivered is true for any 2xx. Redirects are followed by the egress client under its policy.
	Delivered bool
}

// Sender delivers signed webhooks through the egress client and nothing else.
type Sender struct {
	client *egress.Client
	now    func() time.Time
}

// NewSender requires the egress client; there is no other transport to give it.
func NewSender(c *egress.Client) (*Sender, error) {
	if c == nil {
		return nil, errors.New("webhook: egress client required")
	}
	return &Sender{client: c, now: time.Now}, nil
}

// Send signs and POSTs one attempt. Retries call Send again with the same Message: the id is kept,
// the timestamp and signature are fresh. A transport failure returns an error; a non-2xx answer
// returns a Result with Delivered false and a nil error so the caller can decide to retry.
func (s *Sender) Send(ctx context.Context, url string, m Message, g *Signer) (Result, error) {
	if g == nil {
		return Result{}, fmt.Errorf("%w: signer required", ErrBadSecret)
	}
	if len(m.Body) > maxBodyBytes {
		return Result{}, fmt.Errorf("%w: body over %d bytes", ErrBadMessage, maxBodyBytes)
	}
	ts := s.now()
	sig, err := g.Sign(m.ID, ts, m.Body)
	if err != nil {
		return Result{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(m.Body))
	if err != nil {
		return Result{}, fmt.Errorf("%w: url", ErrBadMessage)
	}
	req.Header.Set("Content-Type", contentTypeJS)
	req.Header.Set(HeaderID, m.ID)
	req.Header.Set(HeaderTimestamp, strconv.FormatInt(ts.Unix(), 10))
	req.Header.Set(HeaderSignature, sig)
	resp, err := s.client.Do(req)
	if err != nil {
		return Result{}, err
	}
	defer resp.Body.Close()
	_, _ = io.CopyN(io.Discard, resp.Body, drainBytes)
	return Result{StatusCode: resp.StatusCode, Delivered: resp.StatusCode >= 200 && resp.StatusCode < 300}, nil
}
