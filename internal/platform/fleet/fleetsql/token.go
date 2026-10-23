package fleetsql

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// tokenPrefix versions the wire form. A token is "enr1." + tenant UUID + "." + 256 random bits
// (base64url, no padding). The tenant is routing, not a secret: it lets Redeem open the right
// tenant transaction before it can see any row. The proof of possession is the random part.
const (
	tokenPrefix = "enr1."
	secretBytes = 32
)

// Token is a plaintext enrollment token. It exists in memory only: String is the single place it
// becomes text, Issue returns it once, and nothing stores or logs it. fmt prints it redacted.
type Token struct{ s string }

// String returns the secret text to hand to the administrator, once.
func (t Token) String() string { return t.s }

// GoString and Format keep a token out of logs and error text.
func (Token) GoString() string { return "fleetsql.Token{redacted}" }

// Format implements fmt.Formatter so %v, %+v and %s all print a redaction.
func (Token) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte("[redacted enrollment token]")) }

// ParseToken wraps text the administrator typed or pasted. It does not validate the secret; Redeem
// does, and fails the same way for every malformed or unknown token.
func ParseToken(s string) Token { return Token{s: strings.TrimSpace(s)} }

func newToken(tid tenant.ID) (Token, [32]byte, error) {
	var raw [secretBytes]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return Token{}, [32]byte{}, fmt.Errorf("fleetsql: no entropy: %w", err)
	}
	t := Token{s: tokenPrefix + tid.String() + "." + base64.RawURLEncoding.EncodeToString(raw[:])}
	return t, hash(t), nil
}

func hash(t Token) [32]byte { return sha256.Sum256([]byte(t.s)) }

// tenantOf extracts the routing tenant. Any malformed token returns false; the caller treats that
// exactly like an unknown token.
func tenantOf(t Token) (tenant.ID, bool) {
	rest, ok := strings.CutPrefix(t.s, tokenPrefix)
	if !ok {
		return tenant.ID{}, false
	}
	id, secret, ok := strings.Cut(rest, ".")
	if !ok {
		return tenant.ID{}, false
	}
	if b, err := base64.RawURLEncoding.DecodeString(secret); err != nil || len(b) != secretBytes {
		return tenant.ID{}, false
	}
	tid, err := tenant.Parse(id)
	if err != nil {
		return tenant.ID{}, false
	}
	return tid, true
}
