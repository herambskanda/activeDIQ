// Package setup is the one-time first-run setup secret (TM-TB16-T7, AN-4). A fresh install issues a
// random 256-bit secret and writes it to a file only the installing administrator can read; presenting it
// claims setup exactly once, before it expires. There is no default account and no second chance: the
// claim is a single atomic rename, so two concurrent or repeated uses cannot both win, and a claimed
// install never issues another secret.
//
// State is install-local files in the setup directory (a 0700 subdirectory of the API TLS directory, so
// it inherits that directory's ACL on Windows). That is correct for the self-hosted single-node install
// this gate protects; a multi-node or SaaS tenant is provisioned by its control plane and has no
// first-run claim (see the follow-up ticket noted on T-0636).
package setup

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Names inside the setup directory.
const (
	DirName     = "setup"
	SecretFile  = "setup-secret"  // the plaintext secret, mode 0600, for the installing administrator
	StateFile   = "setup.json"    // the hash and expiry; renamed to ClaimedFile by the one successful claim
	ClaimedFile = "setup.claimed" // its presence means setup was claimed; never reissued
)

// DefaultTTL is how long an issued secret works. Restarting an unclaimed install after expiry issues a
// fresh one.
const DefaultTTL = time.Hour

// ErrRefused is the one answer for every way a claim fails: wrong, expired, used, or not in first-run
// state. Callers must not distinguish them to the requester.
var ErrRefused = errors.New("setup: refused")

// ErrAlreadyClaimed is returned by Issue when setup was claimed: no secret exists and none is created.
var ErrAlreadyClaimed = errors.New("setup: already claimed")

type state struct {
	Hash      string    `json:"sha256"` // hex SHA-256 of the normalised secret
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Store is the setup secret life cycle over one directory.
type Store struct {
	dir  string
	ttl  time.Duration
	now  func() time.Time
	rand func([]byte) (int, error)
}

// Option adjusts a Store (tests).
type Option func(*Store)

// WithClock replaces time.Now.
func WithClock(now func() time.Time) Option { return func(s *Store) { s.now = now } }

// New returns a Store rooted at dir, which is the setup directory itself. ttl must be positive.
func New(dir string, ttl time.Duration, opts ...Option) (*Store, error) {
	if dir == "" {
		return nil, errors.New("setup: no directory")
	}
	if ttl <= 0 {
		return nil, errors.New("setup: ttl must be positive")
	}
	s := &Store{dir: dir, ttl: ttl, now: time.Now, rand: rand.Read}
	for _, o := range opts {
		o(s)
	}
	return s, nil
}

// Dir returns the setup directory.
func (s *Store) Dir() string { return s.dir }

// SecretPath returns the file the installing administrator reads the secret from.
func (s *Store) SecretPath() string { return filepath.Join(s.dir, SecretFile) }

var enc = base32.StdEncoding.WithPadding(base32.NoPadding)

// normalise makes the secret case-, dash- and space-insensitive for typing.
func normalise(p string) string {
	return strings.ToUpper(strings.NewReplacer("-", "", " ", "", "\n", "", "\r", "", "\t", "").Replace(p))
}

func hashOf(norm string) string {
	h := sha256.Sum256([]byte(norm))
	return hex.EncodeToString(h[:])
}

// group writes the secret as dash-separated groups of four for the human who types it.
func group(raw string) string {
	var b strings.Builder
	for i := 0; i < len(raw); i += 4 {
		if i > 0 {
			b.WriteByte('-')
		}
		b.WriteString(raw[i:min(i+4, len(raw))])
	}
	return b.String()
}

// Issue makes sure an unclaimed install has a live secret. It returns issued=true only when it created a
// new one; an existing unexpired secret is left alone (a restart does not rotate it under the
// administrator). If setup was claimed it returns ErrAlreadyClaimed. The secret itself is only ever in
// the file; it is not returned.
func (s *Store) Issue() (issued bool, expires time.Time, err error) {
	if err := s.ensureDir(); err != nil {
		return false, time.Time{}, err
	}
	if _, err := os.Lstat(filepath.Join(s.dir, ClaimedFile)); err == nil {
		return false, time.Time{}, ErrAlreadyClaimed
	} else if !errors.Is(err, fs.ErrNotExist) {
		return false, time.Time{}, fmt.Errorf("setup: %w", err)
	}
	if st, err := s.readState(); err == nil && s.now().Before(st.ExpiresAt) {
		if _, err := os.Lstat(s.SecretPath()); err == nil {
			return false, st.ExpiresAt, nil
		}
	}
	// Expired, half-written or missing: start over. The old files are removed first so the new secret
	// file is created exclusively (never through a planted link).
	_ = os.Remove(s.SecretPath())
	_ = os.Remove(filepath.Join(s.dir, StateFile))
	raw := make([]byte, 32)
	if _, err := s.rand(raw); err != nil {
		return false, time.Time{}, fmt.Errorf("setup: random: %w", err)
	}
	secret := enc.EncodeToString(raw) // 52 chars
	now := s.now()
	st := state{Hash: hashOf(secret), IssuedAt: now.UTC(), ExpiresAt: now.Add(s.ttl).UTC()}
	if err := writeExclusive(s.SecretPath(), []byte(group(secret)+"\n")); err != nil {
		return false, time.Time{}, err
	}
	b, _ := json.Marshal(st)
	if err := writeExclusive(filepath.Join(s.dir, StateFile), b); err != nil {
		_ = os.Remove(s.SecretPath())
		return false, time.Time{}, err
	}
	return true, st.ExpiresAt, nil
}

// Claim consumes the secret. It returns nil exactly once per issued secret; every other outcome is
// ErrRefused, except an infrastructure fault, which is returned as-is (and consumes nothing). A wrong
// guess does not consume the secret.
func (s *Store) Claim(presented string) error {
	st, err := s.readState()
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return ErrRefused
		}
		return fmt.Errorf("setup: %w", err)
	}
	want, err := hex.DecodeString(st.Hash)
	if err != nil || len(want) != sha256.Size {
		return ErrRefused
	}
	got := sha256.Sum256([]byte(normalise(presented)))
	right := subtle.ConstantTimeCompare(want, got[:]) == 1
	live := s.now().Before(st.ExpiresAt)
	if !right || !live {
		return ErrRefused
	}
	// The consume: a rename is atomic, and only one caller finds the source still there.
	if err := os.Rename(filepath.Join(s.dir, StateFile), filepath.Join(s.dir, ClaimedFile)); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return ErrRefused // lost the race: someone else just used it
		}
		return fmt.Errorf("setup: %w", err)
	}
	_ = os.Remove(s.SecretPath()) // best effort: the hash is gone, so the file no longer works either way
	return nil
}

func (s *Store) readState() (state, error) {
	var st state
	b, err := os.ReadFile(filepath.Join(s.dir, StateFile))
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return state{}, fmt.Errorf("setup: unreadable state: %w", err)
	}
	return st, nil
}

func (s *Store) ensureDir() error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return fmt.Errorf("setup: %w", err)
	}
	fi, err := os.Lstat(s.dir)
	if err != nil {
		return fmt.Errorf("setup: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("setup: %s is not a directory (links are refused)", s.dir)
	}
	return checkDirMode(fi)
}

func writeExclusive(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("setup: %w", err)
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return fmt.Errorf("setup: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("setup: %w", err)
	}
	return nil
}
