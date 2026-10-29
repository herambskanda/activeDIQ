package keys

import (
	"context"

	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tablekind"
)

// Installation scope (ADR-0008, T-0715). One data-encryption key belongs to the installation rather than to
// a tenant. Its first consumer is the fleet SERVER CA's private key, which signs ServerAuth leaves only;
// per-tenant client CAs stay sealed under their tenant's DEK. It differs from a tenant DEK in three ways, each
// of which makes a cross-use fail closed:
//
//   - wrap domain: it is wrapped as a platform secret with purpose InstallationPurpose, so a provider binds
//     "platform:installation-dek" (not a tenant ID) and a tenant's wrapped DEK never unwraps as it, nor it as a
//     tenant's (WrapRequest domain separation);
//   - seal domain: InstallationContext has no tenant and its associated data starts with its own tag, so a
//     blob sealed under it never opens through Open and a tenant blob never opens through OpenInstallation,
//     even if a key were confused;
//   - storage: public.installation_keys, a registered-global table that only this package references.

// Declared for fitness-domain-keys: the installation-scope arm of DM-02.
var _ = tablekind.Declare(tablekind.Table{Name: "public.installation_keys", Entity: "DM-02", Kind: tablekind.Platform, Sealed: []string{"wrapped_dek"}})

// InstallationPurpose is the platform-wrap purpose of the installation DEK.
const InstallationPurpose = "installation-dek"

// AuditFailed is returned when the unseal could not be audited: the DEK is withheld rather than handed out
// unrecorded (ADR-0005; TM-D7).
const AuditFailed = "AuditFailed"

// InstallationContext names where an installation-scope sealed value lives. There is no tenant: the value
// belongs to the installation. Components are bound into the associated data like Context's.
type InstallationContext struct {
	Table   string
	Row     string
	Column  string
	Version uint32
}

func (c InstallationContext) validate() error {
	if c.Version == 0 {
		return newErr(InvalidContext)
	}
	for _, s := range []string{c.Table, c.Row, c.Column} {
		if s == "" || len(s) > maxComponent {
			return newErr(InvalidContext)
		}
	}
	return nil
}

func (c InstallationContext) aad() []byte {
	out := make([]byte, 0, 32+len(c.Table)+len(c.Row)+len(c.Column))
	out = append(out, "diq.seal.installation.v1"...)
	for _, s := range []string{c.Table, c.Row, c.Column} {
		out = append(out, byte(len(s)>>8), byte(len(s)))
		out = append(out, s...)
	}
	return append(out, byte(c.Version>>24), byte(c.Version>>16), byte(c.Version>>8), byte(c.Version))
}

// SealInstallation encrypts plaintext under the installation DEK, bound to ctx.
func SealInstallation(dek DEK, ctx InstallationContext, plaintext []byte) ([]byte, error) {
	if err := ctx.validate(); err != nil {
		return nil, err
	}
	return sealAAD(dek, ctx.Version, ctx.aad(), plaintext)
}

// OpenInstallation authenticates and decrypts a blob sealed by SealInstallation. A different table, row,
// column or version, a tenant-sealed blob and a wrong key all fail with a typed *Error and nil plaintext.
func OpenInstallation(dek DEK, ctx InstallationContext, blob []byte) ([]byte, error) {
	if err := ctx.validate(); err != nil {
		return nil, err
	}
	return openAAD(dek, ctx.Version, ctx.aad(), blob)
}

// Unseal outcomes recorded in InstallationEvent.
const (
	UnsealOK     = "success"
	UnsealFailed = "failure"
)

// InstallationEvent is what an InstallationAuditor records for every access to the installation DEK. It has
// no key material, no wrapped bytes and no plaintext.
type InstallationEvent struct {
	// Action is "keys.installation_dek.unseal" or "keys.installation_dek.create".
	Action string
	// Reason is the caller-declared consumer, e.g. "fleet.server_ca" (a constant, never user input).
	Reason string
	// Version is the DEK version touched (0 when it could not be determined).
	Version uint32
	// Outcome is UnsealOK or UnsealFailed; Code is the failure's keys code, "" on success.
	Outcome string
	Code    string
}

// Audit actions.
const (
	ActionUnseal = "keys.installation_dek.unseal"
	ActionCreate = "keys.installation_dek.create"
)

// InstallationAuditor records installation-key events inside the caller's transaction. keys cannot import
// the audit package (which imports keys), so the composition root adapts its platform audit sink to this
// port. A nil auditor is refused by NewInstallationKeys: there is no unaudited path.
type InstallationAuditor interface {
	RecordInstallationKey(ctx context.Context, tx store.Tx, ev InstallationEvent) error
}

// InstallationKeys creates and reads the installation DEK. It holds no key material: every DEK call asks the
// provider again and nothing unwrapped is cached (a KEK outage is felt at once and a plaintext DEK lives only
// as long as its caller keeps it).
type InstallationKeys struct {
	provider Provider
	audit    InstallationAuditor
}

// NewInstallationKeys returns an InstallationKeys over the boot-unlocked KEK provider p. Both arguments are
// required.
func NewInstallationKeys(p Provider, a InstallationAuditor) (*InstallationKeys, error) {
	if p == nil || a == nil {
		return nil, newErr(InvalidContext)
	}
	return &InstallationKeys{provider: p, audit: a}, nil
}

// DEK returns the installation DEK of version v (0 = active) for reason, which the audit event records. When
// v is 0 and the installation has no key yet, one is created (version 1, wrapped by the provider, active):
// concurrent callers end with exactly one active key, because the loser's INSERT conflicts on the partial
// unique index and it reads the winner's row. Run it in a transaction (store.DB.WithPlatform); the caller
// destroys the returned key. Failures are *Error: ProviderUnavailable, UnwrapFailed, KeyNotFound, InvalidKey,
// StoreFailed, AuditFailed. Every call, success or failure, is audited; if the success cannot be audited the
// key is destroyed and AuditFailed returned.
func (k *InstallationKeys) DEK(ctx context.Context, tx store.Tx, version uint32, reason string) (DEK, error) {
	if reason == "" || len(reason) > maxComponent {
		return DEK{}, newErr(InvalidContext)
	}
	d, created, err := k.load(ctx, tx, version)
	if err != nil {
		// A failed access is audited best-effort: the caller already gets the primary error, and a
		// rolled-back transaction would not keep the row anyway.
		_ = k.audit.RecordInstallationKey(ctx, tx, InstallationEvent{Action: ActionUnseal, Reason: reason,
			Version: version, Outcome: UnsealFailed, Code: Code(err)})
		return DEK{}, err
	}
	if created {
		if aerr := k.audit.RecordInstallationKey(ctx, tx, InstallationEvent{Action: ActionCreate, Reason: reason,
			Version: d.Version, Outcome: UnsealOK}); aerr != nil {
			d.Destroy()
			return DEK{}, &Error{Code: AuditFailed, err: aerr}
		}
	}
	if aerr := k.audit.RecordInstallationKey(ctx, tx, InstallationEvent{Action: ActionUnseal, Reason: reason,
		Version: d.Version, Outcome: UnsealOK}); aerr != nil {
		d.Destroy()
		return DEK{}, &Error{Code: AuditFailed, err: aerr}
	}
	return d, nil
}

func (k *InstallationKeys) load(ctx context.Context, tx store.Tx, version uint32) (DEK, bool, error) {
	d, err := k.read(ctx, tx, version)
	if err == nil {
		return d, false, nil
	}
	if version != 0 || Code(err) != NoActiveKey {
		return DEK{}, false, err
	}
	if err := k.create(ctx, tx); err != nil {
		return DEK{}, false, err
	}
	// Whoever won the race, the active row now exists; read it back through the provider.
	d, err = k.read(ctx, tx, 0)
	if err != nil {
		return DEK{}, false, err
	}
	return d, true, nil
}

func (k *InstallationKeys) create(ctx context.Context, tx store.Tx) error {
	dek, err := NewDEK(1)
	if err != nil {
		return err
	}
	defer dek.Destroy()
	wrapped, ref, err := wrapInstallation(k.provider, dek)
	if err != nil {
		return err
	}
	// Serialise creators: the second waits for the first's commit, then conflicts and does nothing.
	if _, err := tx.Exec(ctx, `INSERT INTO public.installation_keys (version, state, wrapped_dek, kek_provider, kek_key_id)
		VALUES (1, 'active', $1, $2, $3) ON CONFLICT DO NOTHING`, wrapped, ref.Provider, ref.KeyID); err != nil {
		return &Error{Code: StoreFailed, err: err}
	}
	return nil
}

func (k *InstallationKeys) read(ctx context.Context, tx store.Tx, version uint32) (DEK, error) {
	var (
		v    int32
		wrap []byte
		ref  KEKRef
		err  error
	)
	if version == 0 {
		err = tx.QueryRow(ctx, `SELECT version, wrapped_dek, kek_provider, kek_key_id FROM public.installation_keys
			WHERE state = 'active'`).Scan(&v, &wrap, &ref.Provider, &ref.KeyID)
	} else {
		err = tx.QueryRow(ctx, `SELECT version, wrapped_dek, kek_provider, kek_key_id FROM public.installation_keys
			WHERE version = $1`, int64(version)).Scan(&v, &wrap, &ref.Provider, &ref.KeyID)
	}
	if err != nil {
		if store.IsNoRows(err) {
			if version == 0 {
				return DEK{}, newErr(NoActiveKey)
			}
			return DEK{}, newErr(KeyNotFound)
		}
		return DEK{}, &Error{Code: StoreFailed, err: err}
	}
	if v <= 0 || (version != 0 && uint32(v) != version) {
		return DEK{}, newErr(InvalidKey)
	}
	b, err := UnwrapPlatform(k.provider, InstallationPurpose, uint32(v), ref, wrap)
	if err != nil {
		return DEK{}, err
	}
	return DEKFromBytes(uint32(v), b)
}

func wrapInstallation(p Provider, dek DEK) (wrapped []byte, ref KEKRef, err error) {
	dek.key.Expose(func(b []byte) {
		if len(b) != DEKSize || dek.Version == 0 {
			err = newErr(InvalidKey)
			return
		}
		wrapped, ref, err = WrapPlatform(p, InstallationPurpose, dek.Version, b)
	})
	return
}
