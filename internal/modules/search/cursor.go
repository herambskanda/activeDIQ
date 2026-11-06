package search

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	jsonv2 "encoding/json/v2"
	"errors"
	"slices"
	"strings"

	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/store/reportsql"
)

// ErrCursorInvalid: the cursor is malformed, has a bad MAC, or was made for another query, type or scope
// (ADR-0011 rule 12). It carries nothing of the cursor.
var ErrCursorInvalid = errors.New("search: cursor invalid")

// maxCursorLen is the contract's bound on nextCursor.
const maxCursorLen = 1024

// MaxPagedHits is where paging stops: this many permitted hits ("refine your search", rule 12).
const MaxPagedHits = 1000

// cursorBinding is everything a cursor's MAC covers besides the rank tuple: the normalised query, the class
// set, the type facet and the fingerprint of every scope passed. A cursor presented with another value of any
// of them does not verify.
type cursorBinding struct {
	Query   string
	Classes string
	Type    reportsql.SearchType
	Scopes  SearchScopes
}

// SearchScopes is the set of scopes of one search, in a fixed order, for binding.
type SearchScopes = reportsql.SearchScopes

// cursorBody is the signed position: the rank tuple of the last admitted hit and how many permitted hits
// the earlier pages delivered.
type cursorBody struct {
	V    int                   `json:"v"`
	Rank reportsql.SearchAfter `json:"r"`
	Sent int                   `json:"n"`
}

// Cursors signs and verifies cursors with a server key (HMAC-SHA256).
type Cursors struct{ key []byte }

// NewCursors uses key, which must be at least 32 bytes.
func NewCursors(key []byte) (Cursors, error) {
	if len(key) < 32 {
		return Cursors{}, errors.New("search: cursor key is shorter than 32 bytes")
	}
	return Cursors{key: append([]byte(nil), key...)}, nil
}

// NewEphemeralCursors makes a random per-process key. A cursor then lives until the process restarts and is
// not valid on another node; the verdict is 400 cursor_invalid and the client searches again. A key from the
// key-custody service replaces this when a deployment needs paging across nodes.
func NewEphemeralCursors() (Cursors, error) {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return Cursors{}, err
	}
	return NewCursors(k)
}

func (c Cursors) mac(body []byte, b cursorBinding) []byte {
	h := hmac.New(sha256.New, c.key)
	h.Write([]byte("activediq/search-cursor/v1\x00"))
	put := func(s string) {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(s)))
		h.Write(n[:])
		h.Write([]byte(s))
	}
	put(string(body))
	put(b.Query)
	put(b.Classes)
	put(typeName(b.Type))
	for _, p := range sortedPerms(b.Scopes) {
		fp := b.Scopes[p].Fingerprint()
		put(string(p))
		h.Write(fp[:])
	}
	return h.Sum(nil)
}

func sortedPerms(s SearchScopes) []authz.Permission {
	out := make([]authz.Permission, 0, len(s))
	for p := range s {
		out = append(out, p)
	}
	slices.Sort(out)
	return out
}

// Sign returns the opaque cursor for position.
func (c Cursors) Sign(rank reportsql.SearchAfter, sent int, b cursorBinding) (string, error) {
	body, err := jsonv2.Marshal(cursorBody{V: 1, Rank: rank, Sent: sent})
	if err != nil {
		return "", err
	}
	s := base64.RawURLEncoding.EncodeToString(body) + "." + base64.RawURLEncoding.EncodeToString(c.mac(body, b))
	if len(s) > maxCursorLen {
		return "", errors.New("search: cursor too long")
	}
	return s, nil
}

// Verify checks the MAC before it decodes anything and returns the position.
func (c Cursors) Verify(cursor string, b cursorBinding) (reportsql.SearchAfter, int, error) {
	if len(cursor) == 0 || len(cursor) > maxCursorLen {
		return reportsql.SearchAfter{}, 0, ErrCursorInvalid
	}
	bs, ms, ok := strings.Cut(cursor, ".")
	if !ok {
		return reportsql.SearchAfter{}, 0, ErrCursorInvalid
	}
	body, err1 := base64.RawURLEncoding.DecodeString(bs)
	got, err2 := base64.RawURLEncoding.DecodeString(ms)
	if err1 != nil || err2 != nil || !hmac.Equal(got, c.mac(body, b)) {
		return reportsql.SearchAfter{}, 0, ErrCursorInvalid
	}
	var cb cursorBody
	if err := jsonv2.Unmarshal(body, &cb); err != nil || cb.V != 1 || cb.Sent < 0 || cb.Sent >= MaxPagedHits {
		return reportsql.SearchAfter{}, 0, ErrCursorInvalid
	}
	return cb.Rank, cb.Sent, nil
}
