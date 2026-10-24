// Package step is the step token of ADR-0005 rule 2: the only key to a write. It is a leaf below every
// write API (rule 13): it imports authority, store and tenant, never operation.
//
// A Step is minted by the operation runner alone (TakeMinter hands the one Minter to the first
// caller), is bound to one claimed step and one plan digest, and dies when the runner revokes it after
// Apply or Verify returns. The zero Step is refused everywhere. A write API takes a Step, calls
// Valid, and on the way to the wire calls Recheck for the Clearance that opens the write.
package step

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"sync"
	"sync/atomic"

	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	"github.com/skenzeriq/activediq/internal/platform/store"
)

// OperationID identifies one operation.
type OperationID string

// Key identifies one step of one item of one operation (DM-42.I1). It is the idempotency key.
type Key struct {
	Operation OperationID
	Item      int
	Step      int
}

// Errors returned by the token. None echoes plan content or credentials.
var (
	ErrZeroStep    = errors.New("step: zero step token")
	ErrRevoked     = errors.New("step: step token revoked")
	ErrNoClearance = errors.New("step: clearance does not match this step")
	ErrNotMinter   = errors.New("step: not the issued minter")
	ErrMinterTaken = errors.New("step: minter already taken")
	ErrDenied      = errors.New("step: authorisation re-check refused the write")
)

// RecheckFunc is the runner's authorisation check, installed at mint. It receives facts read live
// immediately before the write and returns nil only when the initiator chain is still allowed.
type RecheckFunc func(ctx context.Context, f authority.Facts) error

type state struct {
	key     Key
	attempt int
	actor   authority.Chain
	pins    authority.Pins
	nc      authority.NamingContextID
	tx      store.Tx
	query   authority.FactsQuery
	digest  Digest
	recheck RecheckFunc
	secret  secret.Secret
	revoked atomic.Bool
}

// Step is the token. Its field is unexported, so only this package can build a non-zero one.
type Step struct{ s *state }

// Valid returns nil for a live token and a typed error for a zero or revoked one. Every write API
// calls it first.
func (s Step) Valid() error {
	switch {
	case s.s == nil:
		return ErrZeroStep
	case s.s.revoked.Load():
		return ErrRevoked
	}
	return nil
}

// Key returns the step's (operation, item, step) key.
func (s Step) Key() Key {
	if s.s == nil {
		return Key{}
	}
	return s.s.key
}

// Operation returns the operation ID.
func (s Step) Operation() OperationID { return s.Key().Operation }

// Attempt returns the fencing number of this claim (rule 6).
func (s Step) Attempt() int {
	if s.s == nil {
		return 0
	}
	return s.s.attempt
}

// Actor returns the initiator chain, never an approver's authority (rule 7).
func (s Step) Actor() authority.Chain {
	if s.s == nil {
		return authority.Chain{}
	}
	return s.s.actor
}

// DC returns the pinned DC host for a naming context, and false for none (Entra has no DC).
func (s Step) DC(nc authority.NamingContextID) (string, bool) {
	if s.Valid() != nil {
		return "", false
	}
	h, ok := s.s.pins[nc]
	return h, ok
}

// NC returns the naming context the runner bound into this Step (the planned target's NC, covered by
// the digest), empty for a step with none. A write API derives AD-ness and the pin key from it, never
// from the operation it is handed.
func (s Step) NC() authority.NamingContextID {
	if s.Valid() != nil {
		return ""
	}
	return s.s.nc
}

// Tx returns the recording transaction of a Store Action. It is nil for a zero or revoked Step and
// for a Directory step.
func (s Step) Tx() store.Tx {
	if s.Valid() != nil {
		return nil
	}
	return s.s.tx
}

// Secret returns the transient secret input of this step (rule 9), unsealed by the runner for this
// claim only. It is the zero Secret for a step with none, and for a zero or revoked Step. The write
// path hands it to the connector inside the Apply RPC and never persists it.
func (s Step) Secret() secret.Secret {
	if s.Valid() != nil {
		return secret.Secret{}
	}
	return s.s.secret
}

// Digest returns the digest of the planned write this Step authorises.
func (s Step) Digest() Digest {
	if s.s == nil {
		return Digest{}
	}
	return s.s.digest
}

// FactsQuery returns what the Apply-time re-check must read live.
func (s Step) FactsQuery() authority.FactsQuery {
	if s.s == nil {
		return authority.FactsQuery{}
	}
	return s.s.query
}

// Clearance is the value that lets one write be sent. It is bound to the step's key and plan digest.
type Clearance struct {
	owner *state
	key   Key
	dig   Digest
}

// Recheck runs the runner's authorisation check on facts read live immediately before the write.
func (s Step) Recheck(ctx context.Context, f authority.Facts) (Clearance, error) {
	if err := s.Valid(); err != nil {
		return Clearance{}, err
	}
	if err := s.s.recheck(ctx, f); err != nil {
		return Clearance{}, fmt.Errorf("%w: %w", ErrDenied, err)
	}
	return Clearance{owner: s.s, key: s.s.key, dig: s.s.digest}, nil
}

// Check is called by the send path when the RPC goes out: the Clearance must be non-zero, issued to
// this key and this digest, and its Step must not have been revoked since. A Clearance replayed for
// another step, operation or write is refused.
func (c Clearance) Check(key Key, d Digest) error {
	switch {
	case c.owner == nil:
		return ErrZeroStep
	case c.owner.revoked.Load():
		return ErrRevoked
	case c.key != key || c.dig != d:
		return ErrNoClearance
	}
	return nil
}

// Spec is everything the runner binds into a Step at mint.
type Spec struct {
	Key     Key
	Attempt int
	Actor   authority.Chain
	Pins    authority.Pins
	// NC is the target naming context; it must equal the NC in the digested TargetRef.
	NC      authority.NamingContextID
	Tx      store.Tx
	Query   authority.FactsQuery
	Digest  Digest
	Recheck RecheckFunc
	// Secret is the step's transient secret input, if any (rule 9).
	Secret secret.Secret
}

// issued is the package-private proof that a Minter came from TakeMinter.
type issued struct{ _ byte }

// theIssued is the one proof value. Code outside this package cannot set Minter.t, so a zero Minter,
// new(step.Minter) or var m step.Minter is refused by Mint.
var theIssued = &issued{}

// Minter is the single issuer of Steps. Only TakeMinter produces a usable one.
type Minter struct{ t *issued }

var (
	mu    sync.Mutex
	taken bool
)

// TakeMinter returns the Minter to the first caller and ErrMinterTaken to every later one. The
// operation runner takes it during package initialisation; fitness-operation O1 refuses any reference
// to it outside internal/platform/operation, and the server boot asserts that operation holds it.
func TakeMinter() (*Minter, error) {
	mu.Lock()
	defer mu.Unlock()
	if taken {
		return nil, ErrMinterTaken
	}
	taken = true
	return &Minter{t: theIssued}, nil
}

// MinterTaken reports whether the minter has been handed out.
func MinterTaken() bool {
	mu.Lock()
	defer mu.Unlock()
	return taken
}

// Mint issues a Step for one claimed step. The returned revoke func kills the Step and every copy of
// it; the runner calls it as soon as Apply or Verify returns.
func (m *Minter) Mint(sp Spec) (Step, func(), error) {
	if m == nil || m.t == nil || m.t != theIssued {
		return Step{}, nil, ErrNotMinter
	}
	if sp.Recheck == nil {
		return Step{}, nil, errors.New("step: a step needs a recheck")
	}
	if err := sp.Actor.Validate(); err != nil {
		return Step{}, nil, err
	}
	if sp.Key.Operation == "" {
		return Step{}, nil, errors.New("step: a step needs an operation")
	}
	// The pin is copied: a caller-held map (e.g. a DC-locator cache) must not re-point a minted Step.
	st := &state{key: sp.Key, attempt: sp.Attempt, actor: sp.Actor, pins: maps.Clone(sp.Pins), nc: sp.NC, tx: sp.Tx,
		query: sp.Query, digest: sp.Digest, recheck: sp.Recheck, secret: sp.Secret}
	return Step{s: st}, func() { st.revoked.Store(true) }, nil
}
