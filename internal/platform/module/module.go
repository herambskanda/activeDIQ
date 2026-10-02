// Package module is the server module extension point (blueprint §4.1, EP-1; ADR-0003 rule 4).
// A module is the only way a feature enters the server: it declares what it requires and
// contributes everything through the Registrar. Modules never import each other (ADR-0003 rule 2).
//
// The Registrar is a concrete type with unexported fields, so only this package can build one and
// the zero value refuses every call. Boot is the only constructor of live Registrars: it builds one
// per module, calls Register once, closes it and returns the validated Contributions. Only
// internal/compose/server calls Boot. Module unit tests use module/moduletest.
//
// Registrar methods for the other contribution kinds (API, Job, Permission, ScopeEvaluator,
// AuditKind, Dataset, Sink, AuthMethod, ApprovalGate) are added by the ticket that builds the
// extension point they hook into (EP-2 to EP-10), so the Registrar never names a type that does
// not exist yet. Each new method attributes, namespaces and de-duplicates its contribution here.
package module

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/skenzeriq/activediq/internal/platform/capability"
	"github.com/skenzeriq/activediq/internal/platform/operation"
)

// ID is a module's stable identifier. It is also its OpenAPI tag and its web module ID.
type ID string

// idPattern is the module ID rule of ADR-0003 rule 3.
var idPattern = regexp.MustCompile(`^[a-z][a-z0-9]{1,30}$`)

// Module is a server feature module.
type Module interface {
	ID() ID
	// Requires lists the capabilities that must be enabled for the module to load.
	Requires() []capability.ID
	// Register contributes the module's parts. It is called exactly once, at boot, and it is the
	// only way to contribute anything.
	Register(r *Registrar) error
}

// Entry is what the generated module list builds: the ID the list recorded for a module and the
// module itself. Boot rejects an entry whose Module.ID() differs from ID.
type Entry struct {
	ID     ID
	Module Module
}

// Errors returned by Boot and the Registrar. Callers match them with errors.Is.
var (
	// ErrClosed is returned for any Registrar call outside Boot's Register call: after Boot, or on
	// a Registrar that Boot did not build (the zero value).
	ErrClosed = errors.New("module: registrar is closed")
	// ErrNamespace is returned when a contributed ID does not start with "<moduleID>.".
	ErrNamespace = errors.New("module: contribution outside the module's namespace")
	// ErrDuplicate is returned for a duplicate contribution or a duplicate module.
	ErrDuplicate = errors.New("module: duplicate")
	// ErrInvalid is returned for a malformed module entry or contribution.
	ErrInvalid = errors.New("module: invalid")
)

// Registrar receives one module's contributions during Boot. It is append-only and closed once
// Register returns. The zero value refuses every call with ErrClosed.
type Registrar struct {
	mu      sync.Mutex
	owner   ID
	open    bool
	actions []operation.Action
	seen    map[string]struct{}
}

// Action registers an Action (EP-3). Its ID must start with "<moduleID>." and be unique.
func (r *Registrar) Action(a operation.Action) error {
	if a == nil {
		return fmt.Errorf("%w: nil action", ErrInvalid)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	id := string(a.ID())
	if err := r.claim("action", id); err != nil {
		return err
	}
	r.actions = append(r.actions, a)
	return nil
}

// claim checks that the registrar is open, that id is inside the owner's namespace and that the
// (kind, id) pair is new, then records it. The caller holds r.mu.
func (r *Registrar) claim(kind, id string) error {
	if !r.open {
		return fmt.Errorf("%w: %s %q", ErrClosed, kind, id)
	}
	if !strings.HasPrefix(id, string(r.owner)+".") || len(id) == len(r.owner)+1 {
		return fmt.Errorf("%w: module %q registered %s %q; IDs must start with %q",
			ErrNamespace, r.owner, kind, id, string(r.owner)+".")
	}
	key := kind + "\x00" + id
	if _, dup := r.seen[key]; dup {
		return fmt.Errorf("%w: module %q registered %s %q twice", ErrDuplicate, r.owner, kind, id)
	}
	r.seen[key] = struct{}{}
	return nil
}

func (r *Registrar) close() {
	r.mu.Lock()
	r.open = false
	r.mu.Unlock()
}

// Contributions is what Boot returns: everything the loaded modules registered, validated and
// attributed. Its fields are unexported; kernel hosts read it through the accessors.
type Contributions struct {
	loaded  []ID
	skipped []ID
	actions []operation.Action
}

// Loaded lists the modules that were registered, in boot order.
func (c *Contributions) Loaded() []ID { return append([]ID(nil), c.loaded...) }

// Skipped lists the modules not loaded because a required capability is not enabled.
func (c *Contributions) Skipped() []ID { return append([]ID(nil), c.skipped...) }

// Actions lists every registered Action, grouped by module in boot order.
func (c *Contributions) Actions() []operation.Action {
	return append([]operation.Action(nil), c.actions...)
}

// Boot builds one Registrar per module, calls Register on each module whose required capabilities
// are all enabled, closes every Registrar and returns the validated contributions. Any error fails
// start-up: no partial result is returned. Only internal/compose/server calls it (ADR-0003 rule 5).
func Boot(ctx context.Context, mods []Entry, enabled capability.Set) (*Contributions, error) {
	out := &Contributions{}
	ids := make(map[ID]struct{}, len(mods))
	for _, e := range mods {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if e.Module == nil {
			return nil, fmt.Errorf("%w: entry %q has no module", ErrInvalid, e.ID)
		}
		if !idPattern.MatchString(string(e.ID)) {
			return nil, fmt.Errorf("%w: module ID %q must match %s", ErrInvalid, e.ID, idPattern)
		}
		if got := e.Module.ID(); got != e.ID {
			return nil, fmt.Errorf("%w: generated list recorded module %q but it reports ID %q", ErrInvalid, e.ID, got)
		}
		if _, dup := ids[e.ID]; dup {
			return nil, fmt.Errorf("%w: module %q listed twice", ErrDuplicate, e.ID)
		}
		ids[e.ID] = struct{}{}
		if !satisfied(e.Module.Requires(), enabled) {
			out.skipped = append(out.skipped, e.ID)
			continue
		}
		r := &Registrar{owner: e.ID, open: true, seen: map[string]struct{}{}}
		err := e.Module.Register(r)
		r.close()
		if err != nil {
			return nil, fmt.Errorf("module %q: register: %w", e.ID, err)
		}
		out.loaded = append(out.loaded, e.ID)
		out.actions = append(out.actions, r.actions...)
	}
	return out, nil
}

func satisfied(required []capability.ID, enabled capability.Set) bool {
	for _, c := range required {
		if !enabled.Enabled(c) {
			return false
		}
	}
	return true
}
