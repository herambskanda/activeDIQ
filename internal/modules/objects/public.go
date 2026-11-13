package objects

import (
	"context"
	"fmt"

	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/store"
)

// Templates is the DM-50 store. Reads take the caller's transaction (a Plan's read-only one); every
// write takes the Action's step token and runs in the step's transaction, so the change, its audit
// event and its outcome commit together (ADR-0005 rule 2).
type Templates struct{}

// NamingFormats is the DM-51 store, with the same shape as Templates.
type NamingFormats struct{}

// SaveDraft validates t and stores it as the draft of template id, or as version 1 of a new template
// when id is empty. When the newest version is published the draft opens version n+1; a published
// version is never edited (DM-50.I1). It returns the template ID and the draft's version.
func (Templates) SaveDraft(ctx context.Context, st step.Step, id string, t Template) (string, int, error) {
	if err := st.Valid(); err != nil {
		return "", 0, err
	}
	return saveTemplateTx(ctx, st.Tx(), id, t)
}

func saveTemplateTx(ctx context.Context, tx store.Tx, id string, t Template) (string, int, error) {
	t = t.Normalize()
	if err := t.Validate(); err != nil {
		return "", 0, err
	}
	return templates.saveDraftTx(ctx, tx, id, t)
}

// Publish freezes a draft. Every naming format it pins must exist and be out of draft, so a published
// template never points at a format an administrator has not released.
func (Templates) Publish(ctx context.Context, st step.Step, id string, version int) error {
	if err := st.Valid(); err != nil {
		return err
	}
	return publishTemplateTx(ctx, st.Tx(), id, version)
}

func publishTemplateTx(ctx context.Context, tx store.Tx, id string, version int) error {
	cur, err := templates.get(ctx, tx, id, version)
	if err != nil {
		return err
	}
	if cur.State != StateDraft {
		return ErrConflict
	}
	for p, pin := range cur.Def.NamingFormats {
		f, err := namings.get(ctx, tx, pin.ID, pin.Version)
		if err != nil || f.State == StateDraft || f.Def.Purpose != p {
			return violation("namingFormats."+string(p), "pins a naming format version that is not released")
		}
	}
	return templates.transitionTx(ctx, tx, id, version, StateDraft, StatePublished)
}

// Archive retires a published version; it can no longer be chosen for a new Operation.
func (Templates) Archive(ctx context.Context, st step.Step, id string, version int) error {
	return templates.transition(ctx, st, id, version, StatePublished, StateArchived)
}

// Get returns one version, whatever its state.
func (Templates) Get(ctx context.Context, tx store.Tx, id string, version int) (Stored[Template], error) {
	return templates.get(ctx, tx, id, version)
}

// Latest returns the newest published version: the one a new Operation pins.
func (Templates) Latest(ctx context.Context, tx store.Tx, id string) (Stored[Template], error) {
	return templates.latest(ctx, tx, id)
}

// List returns the newest version of every template, of one object kind or (empty) of all.
func (Templates) List(ctx context.Context, tx store.Tx, kind ObjectKind) ([]Stored[Template], error) {
	if kind != "" && !kind.Valid() {
		return nil, fmt.Errorf("%w: %q is not an object kind", ErrNotFound, kind)
	}
	return templates.list(ctx, tx, string(kind))
}

// SaveDraft validates f and stores it as a draft; see Templates.SaveDraft.
func (NamingFormats) SaveDraft(ctx context.Context, st step.Step, id string, f NamingFormat) (string, int, error) {
	if err := f.Validate(); err != nil {
		return "", 0, err
	}
	return namings.saveDraft(ctx, st, id, f)
}

// Activate releases a draft so templates can pin it.
func (NamingFormats) Activate(ctx context.Context, st step.Step, id string, version int) error {
	return namings.transition(ctx, st, id, version, StateDraft, StateActive)
}

// Archive retires an active version. Templates that pinned it keep working.
func (NamingFormats) Archive(ctx context.Context, st step.Step, id string, version int) error {
	return namings.transition(ctx, st, id, version, StateActive, StateArchived)
}

// Get returns one version, whatever its state.
func (NamingFormats) Get(ctx context.Context, tx store.Tx, id string, version int) (Stored[NamingFormat], error) {
	return namings.get(ctx, tx, id, version)
}

// Latest returns the newest active version.
func (NamingFormats) Latest(ctx context.Context, tx store.Tx, id string) (Stored[NamingFormat], error) {
	return namings.latest(ctx, tx, id)
}

// List returns the newest version of every format, of one purpose or (empty) of all.
func (NamingFormats) List(ctx context.Context, tx store.Tx, p NamePurpose) ([]Stored[NamingFormat], error) {
	if p != "" && !p.Valid() {
		return nil, fmt.Errorf("%w: %q is not a naming purpose", ErrNotFound, p)
	}
	return namings.list(ctx, tx, string(p))
}
