// Package module is the server module extension point (blueprint §4.1, EP-1; ADR-0003 rule 4).
// A module is the only way a feature enters the server: it declares what it requires and
// contributes everything through the Registrar. Modules never import each other (ADR-0003 rule 2).
//
// The Registrar is a concrete type with unexported fields, so only this package can build one and
// the zero value refuses every call. Boot is the only constructor of live Registrars: it builds one
// per module, calls Register once, closes it and returns the validated Contributions. Only
// internal/compose/server calls Boot. Module unit tests use module/moduletest.
//
// API (EP-2) and Permission (EP-6) are built (ADR-0013). Registrar methods for the other
// contribution kinds (Job, AuditKind, Sink, AuthMethod, ApprovalGate) are added by the ticket that builds the
// extension point they hook into (EP-2 to EP-10), so the Registrar never names a type that does
// not exist yet. Each new method attributes, namespaces and de-duplicates its contribution here.
package module

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/capability"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store/owners"
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
	// ErrUnknownPermission is returned by Boot when a contributed route's x-permission is neither
	// a registered module permission nor one of the kernel's (WithKernelPermissions).
	ErrUnknownPermission = errors.New("module: x-permission not in the permission catalogue")
)

// Registrar receives one module's contributions during Boot. It is append-only and closed once
// Register returns. The zero value refuses every call with ErrClosed.
type Registrar struct {
	mu      sync.Mutex
	owner   ID
	open    bool
	actions []operation.Action
	scopes  []scopeEntry
	sets    []report.Dataset
	tags    []apihost.TagHandlers
	perms   []authz.Permission
	seen    map[string]struct{}
}

// scopeEntry pins the kind read once at registration, so an evaluator cannot answer differently later.
type scopeEntry struct {
	kind string
	ev   authz.ScopeEvaluator
}

// scopeKindPattern is the shape of an assignment root kind ("ou_subtree"). Root kinds belong to
// the product's scope vocabulary, not to a module, so they are not namespaced by the module ID.
var scopeKindPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{1,40}$`)

// ScopeEvaluator registers the evaluator for one assignment root kind (EP-6). At most one module
// may own a kind: a second registration, in this module or another, fails Boot and names the kind.
func (r *Registrar) ScopeEvaluator(e authz.ScopeEvaluator) error {
	if e == nil {
		return fmt.Errorf("%w: nil scope evaluator", ErrInvalid)
	}
	kind := e.RootKind()
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.open {
		return fmt.Errorf("%w: scope evaluator %q", ErrClosed, kind)
	}
	if !scopeKindPattern.MatchString(kind) {
		return fmt.Errorf("%w: module %q registered a scope evaluator with root kind %q; it must match %s",
			ErrInvalid, r.owner, kind, scopeKindPattern)
	}
	key := "scope_evaluator\x00" + kind
	if _, dup := r.seen[key]; dup {
		return fmt.Errorf("%w: module %q registered a scope evaluator for root kind %q twice", ErrDuplicate, r.owner, kind)
	}
	r.seen[key] = struct{}{}
	r.scopes = append(r.scopes, scopeEntry{kind, e})
	return nil
}

// Dataset registers a report dataset (EP-8). Its ID must start with "<moduleID>." and be unique, and
// its structure must validate. Boot then checks that every table it names is owned by this module.
func (r *Registrar) Dataset(d report.Dataset) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.claim("dataset", string(d.ID)); err != nil {
		return err
	}
	if err := d.Validate(); err != nil {
		return fmt.Errorf("%w: module %q dataset %q: %w", ErrInvalid, r.owner, d.ID, err)
	}
	r.sets = append(r.sets, d)
	return nil
}

// API registers the module's route handlers (EP-2). The tag must equal the module ID and a module
// registers its tag once. A module that is not configured for its routes registers nothing.
func (r *Registrar) API(t apihost.TagHandlers) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.open {
		return fmt.Errorf("%w: api tag %q", ErrClosed, t.Tag())
	}
	if t.Tag() != string(r.owner) {
		return fmt.Errorf("%w: module %q registered API tag %q; the tag must equal the module ID",
			ErrNamespace, r.owner, t.Tag())
	}
	key := "api\x00" + t.Tag()
	if _, dup := r.seen[key]; dup {
		return fmt.Errorf("%w: module %q registered API tag %q twice", ErrDuplicate, r.owner, t.Tag())
	}
	r.seen[key] = struct{}{}
	r.tags = append(r.tags, t)
	return nil
}

// Permission registers a permission ID (EP-6) in the catalogue. It must start with "<moduleID>."
// and be unique. Boot checks every mounted route's x-permission against the catalogue.
func (r *Registrar) Permission(p authz.Permission) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.claim("permission", string(p)); err != nil {
		return err
	}
	r.perms = append(r.perms, p)
	return nil
}

// Action registers an Action (EP-3). Its ID must start with "<moduleID>." and be unique.
func (r *Registrar) Action(a operation.Action) error {
	if a == nil {
		return fmt.Errorf("%w: nil action", ErrInvalid)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	id := string(a.Describe().ID)
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
	scopes  map[string]authz.ScopeEvaluator
	scopeBy map[string]ID
	sets    []report.OwnedDatasets
	tags    []apihost.TagHandlers
	perms   []authz.Permission
}

// API lists the route handlers modules registered, in boot order. compose/server mounts them on
// the API host.
func (c *Contributions) API() []apihost.TagHandlers {
	return append([]apihost.TagHandlers(nil), c.tags...)
}

// Permissions lists the permissions modules registered, in boot order. compose/server adds the
// kernel's own to build the catalogue.
func (c *Contributions) Permissions() []authz.Permission {
	return append([]authz.Permission(nil), c.perms...)
}

// Datasets lists the datasets modules registered, grouped by the module that owns them, in boot
// order. compose/server adds them to the report host. Boot has already checked their tables.
func (c *Contributions) Datasets() []report.OwnedDatasets {
	return append([]report.OwnedDatasets(nil), c.sets...)
}

// ScopeEvaluator returns the evaluator registered for an assignment root kind, or false when no
// loaded module owns that kind. A kind with no evaluator has no read scope: callers contribute nothing.
func (c *Contributions) ScopeEvaluator(kind string) (authz.ScopeEvaluator, bool) {
	e, ok := c.scopes[kind]
	return e, ok
}

// ScopeKinds lists the root kinds that have an evaluator, sorted.
func (c *Contributions) ScopeKinds() []string {
	return slices.Sorted(maps.Keys(c.scopes))
}

// Loaded lists the modules that were registered, in boot order.
func (c *Contributions) Loaded() []ID { return append([]ID(nil), c.loaded...) }

// Skipped lists the modules not loaded because a required capability is not enabled.
func (c *Contributions) Skipped() []ID { return append([]ID(nil), c.skipped...) }

// Actions lists every registered Action, grouped by module in boot order.
func (c *Contributions) Actions() []operation.Action {
	return append([]operation.Action(nil), c.actions...)
}

// BootOption configures Boot.
type BootOption func(*bootConfig)

type bootConfig struct {
	tableOwners report.TableOwners
	kernelPerms []string
}

// WithKernelPermissions lists the permissions that exist outside any module (built-in roles,
// platform packages). Boot accepts a route's x-permission that is one of these, "authenticated" or
// "anonymous", or a module-registered permission; anything else fails with ErrUnknownPermission.
func WithKernelPermissions(p []string) BootOption {
	return func(c *bootConfig) { c.kernelPerms = append([]string(nil), p...) }
}

// WithTableOwners replaces the ownership map the dataset table check reads. Tests use it; the
// server uses the default, store/owners.Lookup.
func WithTableOwners(o report.TableOwners) BootOption {
	return func(c *bootConfig) { c.tableOwners = o }
}

// Boot builds one Registrar per module, calls Register on each module whose required capabilities
// are all enabled, closes every Registrar and returns the validated contributions. Any error fails
// start-up: no partial result is returned. Only internal/compose/server calls it (ADR-0003 rule 5).
//
// A dataset that names a table its module does not own fails Boot and names the table.
func Boot(ctx context.Context, mods []Entry, enabled capability.Set, opts ...BootOption) (*Contributions, error) {
	cfg := bootConfig{tableOwners: owners.Lookup}
	for _, o := range opts {
		o(&cfg)
	}
	out := &Contributions{scopes: map[string]authz.ScopeEvaluator{}, scopeBy: map[string]ID{}}
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
		for _, d := range r.sets {
			if err := report.CheckTables(string(e.ID), d, cfg.tableOwners); err != nil {
				return nil, fmt.Errorf("module %q: dataset: %w", e.ID, err)
			}
		}
		out.loaded = append(out.loaded, e.ID)
		out.actions = append(out.actions, r.actions...)
		out.tags = append(out.tags, r.tags...)
		out.perms = append(out.perms, r.perms...)
		if len(r.sets) > 0 {
			out.sets = append(out.sets, report.OwnedDatasets{Owner: string(e.ID), Datasets: slices.Clone(r.sets)})
		}
		for _, se := range r.scopes {
			kind, ev := se.kind, se.ev
			if prev, dup := out.scopeBy[kind]; dup {
				return nil, fmt.Errorf("%w: root kind %q has a scope evaluator from module %q and from module %q; at most one per kind",
					ErrDuplicate, kind, prev, e.ID)
			}
			out.scopes[kind] = ev
			out.scopeBy[kind] = e.ID
		}
	}
	if err := checkRoutePermissions(out, cfg.kernelPerms); err != nil {
		return nil, err
	}
	return out, nil
}

// checkRoutePermissions fails when a contributed route names a permission that is in no catalogue.
func checkRoutePermissions(c *Contributions, kernel []string) error {
	known := map[string]struct{}{"authenticated": {}, "anonymous": {}}
	for _, k := range kernel {
		known[k] = struct{}{}
	}
	for _, p := range c.perms {
		known[string(p)] = struct{}{}
	}
	for _, t := range c.tags {
		for _, rt := range t.Routes() {
			m := rt.Meta()
			if _, ok := known[m.Permission]; !ok {
				return fmt.Errorf("%w: tag %q operation %q names x-permission %q", ErrUnknownPermission, t.Tag(), m.OperationID, m.Permission)
			}
		}
	}
	return nil
}

func satisfied(required []capability.ID, enabled capability.Set) bool {
	for _, c := range required {
		if !enabled.Enabled(c) {
			return false
		}
	}
	return true
}
