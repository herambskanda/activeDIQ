package objects

import (
	"context"
	"errors"
	"fmt"
	"time"

	jsonv2 "encoding/json/v2"

	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tablekind"
)

var (
	_ = tablekind.Declare(tablekind.Table{Name: "public.objects_templates", Entity: "DM-50", Kind: tablekind.Tenant})
	_ = tablekind.Declare(tablekind.Table{Name: "public.objects_naming_formats", Entity: "DM-51", Kind: tablekind.Tenant})
)

// Store errors. None carries a definition's content.
var (
	ErrNoTenant = errors.New("objects: no tenant context")
	ErrNotFound = errors.New("objects: definition or version not found")
	ErrConflict = errors.New("objects: the version is not in a state that allows this change")
	ErrPurpose  = errors.New("objects: a definition's object kind and purpose cannot change between versions")
)

// State is a version's lifecycle state. A template's live state is published; a naming format's is active.
type State string

// Version states.
const (
	StateDraft     State = "draft"
	StatePublished State = "published"
	StateActive    State = "active"
	StateArchived  State = "archived"
)

// Stored is one stored version of a definition.
type Stored[T any] struct {
	ID        string
	Version   int
	State     State
	Def       T
	UpdatedAt time.Time
}

// rowSet is the part of a pgx result set the store reads; the store's transaction hands back pgx rows
// and this package may not name pgx (tenancy T5).
type rowSet interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
	Close()
}

// backend is one entity's SQL. Each method holds its statement as a constant at the call site (FF-SP2),
// which is why the two entities implement it separately and share only the flow below.
type backend[T any] interface {
	// lock reads the newest version of id, locked: its version, state and identity (the columns that may
	// not change between versions).
	lock(ctx context.Context, tx store.Tx, id string) (version int, state State, ident string, err error)
	insert(ctx context.Context, tx store.Tx, id string, version int, def T, body []byte) error
	update(ctx context.Context, tx store.Tx, id string, version int, def T, body []byte) error
	// move changes a version's state from one to another and returns the rows changed.
	move(ctx context.Context, tx store.Tx, id string, version int, from, to State) (int64, error)
	get(ctx context.Context, tx store.Tx, id string, version int) scanner
	latest(ctx context.Context, tx store.Tx, id string) scanner
	// list returns id, version, state, definition, updated_at of the newest version of each definition,
	// optionally of one identity (kind or purpose); empty means all.
	list(ctx context.Context, tx store.Tx, identity string) (rowSet, error)
}

// versioned is the store flow both entities share.
type versioned[T any] struct {
	b     backend[T]
	live  State
	ident func(T) string // matches backend.lock's identity
}

func tenantOK(ctx context.Context, tx store.Tx) error {
	var tid string
	if err := tx.QueryRow(ctx, `SELECT coalesce(current_setting('app.tenant_id', true), '')`).Scan(&tid); err != nil {
		return fmt.Errorf("objects: tenant context: %w", err)
	}
	if tid == "" {
		return ErrNoTenant
	}
	return nil
}

func encode(v any) ([]byte, error) {
	b, err := jsonv2.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("objects: encode: %w", err)
	}
	return b, nil
}

func decode[T any](b []byte) (T, error) {
	var v T
	if err := jsonv2.Unmarshal(b, &v, jsonv2.RejectUnknownMembers(true)); err != nil {
		return v, fmt.Errorf("objects: stored definition does not decode: %w", err)
	}
	return v, nil
}

// saveDraft creates a definition (id empty) or revises it: the draft is replaced, or, when the newest
// version is live, version n+1 is opened as a draft.
func (v versioned[T]) saveDraft(ctx context.Context, st step.Step, id string, def T) (string, int, error) {
	if err := st.Valid(); err != nil {
		return "", 0, err
	}
	return v.saveDraftTx(ctx, st.Tx(), id, def)
}

func (v versioned[T]) saveDraftTx(ctx context.Context, tx store.Tx, id string, def T) (string, int, error) {
	if err := tenantOK(ctx, tx); err != nil {
		return "", 0, err
	}
	body, err := encode(def)
	if err != nil {
		return "", 0, err
	}
	if id == "" {
		if err := tx.QueryRow(ctx, `SELECT gen_random_uuid()::text`).Scan(&id); err != nil {
			return "", 0, fmt.Errorf("objects: new id: %w", err)
		}
		return id, 1, wrap(v.b.insert(ctx, tx, id, 1, def, body))
	}
	if !IsGUID(id) {
		return "", 0, ErrNotFound
	}
	ver, state, ident, err := v.b.lock(ctx, tx, id)
	if store.IsNoRows(err) {
		return "", 0, ErrNotFound
	}
	if err != nil {
		return "", 0, fmt.Errorf("objects: lock: %w", err)
	}
	if ident != v.ident(def) {
		return "", 0, ErrPurpose
	}
	switch state {
	case StateDraft:
		return id, ver, wrap(v.b.update(ctx, tx, id, ver, def, body))
	case v.live:
		return id, ver + 1, wrap(v.b.insert(ctx, tx, id, ver+1, def, body))
	}
	return "", 0, ErrConflict // archived: a retired definition is not revived
}

func wrap(err error) error {
	if err != nil {
		return fmt.Errorf("objects: write: %w", err)
	}
	return nil
}

// transition moves one version between states, only from the expected one.
func (v versioned[T]) transition(ctx context.Context, st step.Step, id string, version int, from, to State) error {
	if err := st.Valid(); err != nil {
		return err
	}
	return v.transitionTx(ctx, st.Tx(), id, version, from, to)
}

func (v versioned[T]) transitionTx(ctx context.Context, tx store.Tx, id string, version int, from, to State) error {
	if err := tenantOK(ctx, tx); err != nil {
		return err
	}
	if !IsGUID(id) {
		return ErrNotFound
	}
	n, err := v.b.move(ctx, tx, id, version, from, to)
	if err != nil {
		return fmt.Errorf("objects: move: %w", err)
	}
	if n == 0 {
		if _, err := v.get(ctx, tx, id, version); err != nil {
			return err
		}
		return ErrConflict
	}
	return nil
}

type scanner interface{ Scan(...any) error }

func (v versioned[T]) scan(id string, row scanner) (Stored[T], error) {
	var s Stored[T]
	var body []byte
	s.ID = id
	if err := row.Scan(&s.Version, &s.State, &body, &s.UpdatedAt); err != nil {
		if store.IsNoRows(err) {
			return s, ErrNotFound
		}
		return s, fmt.Errorf("objects: read: %w", err)
	}
	def, err := decode[T](body)
	s.Def = def
	return s, err
}

func (v versioned[T]) get(ctx context.Context, tx store.Tx, id string, version int) (Stored[T], error) {
	if err := tenantOK(ctx, tx); err != nil {
		return Stored[T]{}, err
	}
	if !IsGUID(id) {
		return Stored[T]{}, ErrNotFound
	}
	return v.scan(id, v.b.get(ctx, tx, id, version))
}

func (v versioned[T]) latest(ctx context.Context, tx store.Tx, id string) (Stored[T], error) {
	if err := tenantOK(ctx, tx); err != nil {
		return Stored[T]{}, err
	}
	if !IsGUID(id) {
		return Stored[T]{}, ErrNotFound
	}
	return v.scan(id, v.b.latest(ctx, tx, id))
}

func (v versioned[T]) list(ctx context.Context, tx store.Tx, identity string) ([]Stored[T], error) {
	if err := tenantOK(ctx, tx); err != nil {
		return nil, err
	}
	rows, err := v.b.list(ctx, tx, identity)
	if err != nil {
		return nil, fmt.Errorf("objects: list: %w", err)
	}
	defer rows.Close()
	var out []Stored[T]
	for rows.Next() {
		var id string
		var s Stored[T]
		var body []byte
		if err := rows.Scan(&id, &s.Version, &s.State, &body, &s.UpdatedAt); err != nil {
			return nil, fmt.Errorf("objects: list: %w", err)
		}
		s.ID = id
		if s.Def, err = decode[T](body); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("objects: list: %w", err)
	}
	return out, nil
}

// templateSQL is the DM-50 backend. Every statement binds its values and scopes by tenant.
type templateSQL struct{}

func (templateSQL) lock(ctx context.Context, tx store.Tx, id string) (int, State, string, error) {
	var ver int
	var state State
	var ident string
	err := tx.QueryRow(ctx, `SELECT version, state, object_kind || '/' || purpose FROM public.objects_templates
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND id = $1
		ORDER BY version DESC LIMIT 1 FOR UPDATE`, id).Scan(&ver, &state, &ident)
	return ver, state, ident, err
}

func (templateSQL) insert(ctx context.Context, tx store.Tx, id string, ver int, t Template, body []byte) error {
	_, err := tx.Exec(ctx, `INSERT INTO public.objects_templates
		(tenant_id, id, version, state, object_kind, provider, purpose, name, definition)
		VALUES (NULLIF(current_setting('app.tenant_id', true), '')::uuid, $1, $2, 'draft', $3, $4, $5, $6, $7)`,
		id, ver, string(t.Kind), string(t.Provider), string(t.Purpose), t.Name, body)
	return err
}

func (templateSQL) update(ctx context.Context, tx store.Tx, id string, ver int, t Template, body []byte) error {
	_, err := tx.Exec(ctx, `UPDATE public.objects_templates SET provider = $3, name = $4, definition = $5, updated_at = now()
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
		AND id = $1 AND version = $2 AND state = 'draft'`,
		id, ver, string(t.Provider), t.Name, body)
	return err
}

func (templateSQL) move(ctx context.Context, tx store.Tx, id string, ver int, from, to State) (int64, error) {
	tag, err := tx.Exec(ctx, `UPDATE public.objects_templates SET state = $4, updated_at = now(),
		published_at = CASE WHEN $4 = 'published' THEN now() ELSE published_at END,
		archived_at = CASE WHEN $4 = 'archived' THEN now() ELSE archived_at END
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
		AND id = $1 AND version = $2 AND state = $3`, id, ver, string(from), string(to))
	return tag.RowsAffected(), err
}

func (templateSQL) get(ctx context.Context, tx store.Tx, id string, ver int) scanner {
	return tx.QueryRow(ctx, `SELECT version, state, definition, updated_at FROM public.objects_templates
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND id = $1 AND version = $2`, id, ver)
}

func (templateSQL) latest(ctx context.Context, tx store.Tx, id string) scanner {
	return tx.QueryRow(ctx, `SELECT version, state, definition, updated_at FROM public.objects_templates
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND id = $1 AND state = 'published'
		ORDER BY version DESC LIMIT 1`, id)
}

func (templateSQL) list(ctx context.Context, tx store.Tx, kind string) (rowSet, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT ON (id) id::text, version, state, definition, updated_at
		FROM public.objects_templates
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND ($1 = '' OR object_kind = $1)
		ORDER BY id, version DESC`, kind)
	if err != nil {
		return nil, err
	}
	return rows, nil
}

// namingSQL is the DM-51 backend.
type namingSQL struct{}

func (namingSQL) lock(ctx context.Context, tx store.Tx, id string) (int, State, string, error) {
	var ver int
	var state State
	var ident string
	err := tx.QueryRow(ctx, `SELECT version, state, purpose FROM public.objects_naming_formats
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND id = $1
		ORDER BY version DESC LIMIT 1 FOR UPDATE`, id).Scan(&ver, &state, &ident)
	return ver, state, ident, err
}

func (namingSQL) insert(ctx context.Context, tx store.Tx, id string, ver int, f NamingFormat, body []byte) error {
	_, err := tx.Exec(ctx, `INSERT INTO public.objects_naming_formats (tenant_id, id, version, state, purpose, name, definition)
		VALUES (NULLIF(current_setting('app.tenant_id', true), '')::uuid, $1, $2, 'draft', $3, $4, $5)`,
		id, ver, string(f.Purpose), f.Name, body)
	return err
}

func (namingSQL) update(ctx context.Context, tx store.Tx, id string, ver int, f NamingFormat, body []byte) error {
	_, err := tx.Exec(ctx, `UPDATE public.objects_naming_formats SET name = $3, definition = $4, updated_at = now()
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
		AND id = $1 AND version = $2 AND state = 'draft'`, id, ver, f.Name, body)
	return err
}

func (namingSQL) move(ctx context.Context, tx store.Tx, id string, ver int, from, to State) (int64, error) {
	tag, err := tx.Exec(ctx, `UPDATE public.objects_naming_formats SET state = $4, updated_at = now(),
		published_at = CASE WHEN $4 = 'active' THEN now() ELSE published_at END,
		archived_at = CASE WHEN $4 = 'archived' THEN now() ELSE archived_at END
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
		AND id = $1 AND version = $2 AND state = $3`, id, ver, string(from), string(to))
	return tag.RowsAffected(), err
}

func (namingSQL) get(ctx context.Context, tx store.Tx, id string, ver int) scanner {
	return tx.QueryRow(ctx, `SELECT version, state, definition, updated_at FROM public.objects_naming_formats
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND id = $1 AND version = $2`, id, ver)
}

func (namingSQL) latest(ctx context.Context, tx store.Tx, id string) scanner {
	return tx.QueryRow(ctx, `SELECT version, state, definition, updated_at FROM public.objects_naming_formats
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND id = $1 AND state = 'active'
		ORDER BY version DESC LIMIT 1`, id)
}

func (namingSQL) list(ctx context.Context, tx store.Tx, purpose string) (rowSet, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT ON (id) id::text, version, state, definition, updated_at
		FROM public.objects_naming_formats
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND ($1 = '' OR purpose = $1)
		ORDER BY id, version DESC`, purpose)
	if err != nil {
		return nil, err
	}
	return rows, nil
}

var (
	templates = versioned[Template]{b: templateSQL{}, live: StatePublished,
		ident: func(t Template) string { return string(t.Kind) + "/" + string(t.Purpose) }}
	namings = versioned[NamingFormat]{b: namingSQL{}, live: StateActive,
		ident: func(f NamingFormat) string { return string(f.Purpose) }}
)
