package jobs

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Mode is how a kind's body runs once the wrapper has established the tenant (ADR-0002 Jobs row, as
// amended by ADR-0005 rule 6). The zero value is not a mode, so a Kind must choose.
type Mode int

const (
	// ModeDefault runs the whole body in one wrapper transaction, which also records the outcome.
	ModeDefault Mode = iota + 1
	// ModeManagedTx hands the body a tenant-bound transaction runner; the body opens short transactions
	// and never holds one across a directory call. The claim is renewed while it runs.
	ModeManagedTx
)

func (m Mode) valid() bool { return m == ModeDefault || m == ModeManagedTx }

// ClaimGrace is added to a kind's timeout to make the lease of its claim.
const ClaimGrace = 30 * time.Second

// Registry errors. Each names at most the kind, never arguments.
var (
	// ErrKindRegistered is returned by Register for a name that is already registered.
	ErrKindRegistered = errors.New("jobs: kind already registered")
	// ErrKindUnknown is returned for a kind that is not registered; the job is refused before any SQL.
	ErrKindUnknown = errors.New("jobs: kind not registered")
	// ErrKindScope is returned when a job's tenant does not match its kind's scope: a job without a
	// tenant must be a registered platform kind (ADR-0002), and a platform kind never carries one.
	ErrKindScope = errors.New("jobs: the job's tenant does not match its kind's scope")
)

// Kind is one registered job kind (EP-5).
type Kind struct {
	// Name is the kind, such as "operation.apply": lower case, digits, '_' and '.'.
	Name string
	// Timeout bounds one run of the body and is required. The claim lasts Timeout + ClaimGrace.
	Timeout time.Duration
	// Mode is ModeDefault or ModeManagedTx.
	Mode Mode
	// Platform marks a kind that runs with no tenant. Every other kind is tenant-carrying.
	Platform bool
	// ValidateArgs, when set, checks the args of every job of this kind at Enqueue, after the common
	// rules (a JSON object, at most MaxArgsBytes, tenant_id set from the job). It must accept only typed
	// references and must not echo values in its error.
	ValidateArgs func(args json.RawMessage) error
	// Run is the body of a ModeDefault kind. It runs in the wrapper's one tenant transaction, which
	// also records the outcome, so its writes and the job's completion commit together.
	Run Body
	// RunManaged is the body of a ModeManagedTx kind. It holds no transaction; it opens short ones
	// through the runner it is given.
	RunManaged ManagedBody
}

func (k Kind) validate() error {
	switch {
	case !kindPattern.MatchString(k.Name):
		return invalid("kind %q is not lower-case letters, digits, '_' and '.' starting with a letter (at most 100)", k.Name)
	case k.Timeout <= 0:
		return invalid("kind %q needs a timeout", k.Name)
	case k.Timeout+ClaimGrace > maxLease:
		return invalid("kind %q timeout must be at most %s", k.Name, maxLease-ClaimGrace)
	case !k.Mode.valid():
		return invalid("kind %q has an unknown mode", k.Name)
	case k.Mode == ModeDefault && (k.Run == nil || k.RunManaged != nil):
		return invalid("kind %q is a default-mode kind and needs Run (and no RunManaged)", k.Name)
	case k.Mode == ModeManagedTx && (k.RunManaged == nil || k.Run != nil):
		return invalid("kind %q is a ManagedTx kind and needs RunManaged (and no Run)", k.Name)
	}
	return nil
}

// Registry holds the registered kinds. The zero value is not usable; use NewRegistry.
type Registry struct {
	mu    sync.RWMutex
	kinds map[string]Kind
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{kinds: map[string]Kind{}} }

// Register adds k. A duplicate name or an invalid kind (no timeout, unknown mode) returns an error and
// registers nothing.
func (r *Registry) Register(k Kind) error {
	if err := k.validate(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.kinds[k.Name]; ok {
		return fmt.Errorf("%w: %q", ErrKindRegistered, k.Name)
	}
	r.kinds[k.Name] = k
	return nil
}

// Lookup returns the registered kind with that name.
func (r *Registry) Lookup(name string) (Kind, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	k, ok := r.kinds[name]
	return k, ok
}

// Leases returns every registered kind with its claim lease, ready for Claim, ordered by name.
func (r *Registry) Leases() []KindLease {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]KindLease, 0, len(r.kinds))
	for _, k := range r.kinds {
		out = append(out, KindLease{Kind: k.Name, Lease: k.Timeout + ClaimGrace})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Kind < out[j].Kind })
	return out
}

// check refuses a job whose kind is unregistered or whose tenant does not fit the kind's scope.
// TenantLeases is Leases without the platform kinds: the tenant wrapper refuses a platform job, so the
// worker must never claim one (it would burn an attempt per lapse until discarded).
func (r *Registry) TenantLeases() []KindLease {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]KindLease, 0, len(r.kinds))
	for _, k := range r.kinds {
		if !k.Platform {
			out = append(out, KindLease{Kind: k.Name, Lease: k.Timeout + ClaimGrace})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Kind < out[j].Kind })
	return out
}

func (r *Registry) check(j Job) (Kind, error) {
	k, ok := r.Lookup(j.Kind)
	if !ok {
		name := j.Kind
		if len(name) > 100 {
			name = name[:100]
		}
		return Kind{}, fmt.Errorf("%w: %q", ErrKindUnknown, name)
	}
	if k.Platform != j.Tenant.IsZero() {
		return Kind{}, fmt.Errorf("%w: %q", ErrKindScope, k.Name)
	}
	return k, nil
}
