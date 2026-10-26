package authn

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// secretLen is the entropy of a token: 256 bits.
const secretLen = 32

// ErrInvalidToken is returned for text that is not a session token. It says nothing about why.
var ErrInvalidToken = errors.New("authn: invalid session token")

// Token is the plain session ID. It exists in memory at creation, goes to the client once, and is
// never stored or logged. Its text is "<tenant>.<secret>": the tenant prefix only selects the
// row-level-security context for the lookup; the secret and the hash decide everything. String redacts.
type Token struct{ text string }

func newToken(t tenant.ID) (Token, error) {
	var b [secretLen]byte
	if _, err := rand.Read(b[:]); err != nil {
		return Token{}, fmt.Errorf("authn: no entropy: %w", err)
	}
	return Token{text: t.String() + "." + base64.RawURLEncoding.EncodeToString(b[:])}, nil
}

// Reveal returns the token text, for the one response that hands it to the client.
func (t Token) Reveal() string { return t.text }

// String redacts, so a log line or error message cannot leak the token.
func (Token) String() string { return "authn.Token(redacted)" }

// GoString redacts for %#v.
func (Token) GoString() string { return "authn.Token(redacted)" }

// ParseToken reads token text from a client. It validates the shape only; whether a session exists
// is Lookup's answer.
func ParseToken(s string) (Token, error) {
	i := strings.IndexByte(s, '.')
	if i != 36 || len(s) != 36+1+base64.RawURLEncoding.EncodedLen(secretLen) {
		return Token{}, ErrInvalidToken
	}
	if _, err := tenant.Parse(s[:36]); err != nil {
		return Token{}, ErrInvalidToken
	}
	if raw, err := base64.RawURLEncoding.Strict().DecodeString(s[37:]); err != nil || len(raw) != secretLen {
		return Token{}, ErrInvalidToken
	}
	return Token{text: s}, nil
}

// Tenant returns the tenant the token names.
func (t Token) Tenant() (tenant.ID, error) {
	if len(t.text) < 36 {
		return tenant.ID{}, ErrInvalidToken
	}
	id, err := tenant.Parse(t.text[:36])
	if err != nil {
		return tenant.ID{}, ErrInvalidToken
	}
	return id, nil
}

// hash is what the table stores.
func (t Token) hash() []byte {
	sum := sha256.Sum256([]byte(t.text))
	return sum[:]
}
