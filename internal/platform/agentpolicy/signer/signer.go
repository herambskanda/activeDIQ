// Package signer is the one place the tenant's policy private key is ever opened (ADR-0007 decision 1
// and P8). It generates the Ed25519 key, seals it under the tenant DEK, signs policy and keyset
// documents, rotates the keyset chain and reads the chain back for delivery. The key never leaves the
// package: the exported surface takes and returns signed documents, and the one function that opens
// the sealed bytes (openPrivate) is unexported. The test TestP8_OnlySignerTouchesTheKeyTable fails the
// build if any other package names the key table or the sealed column in SQL or imports this
// package's internals.
//
// Every method runs in the caller's tenant transaction (store.WithTenant), so a document, its audit
// event and its sequence commit together, and the database, not this code, refuses a row of another
// tenant. A per-tenant advisory lock serialises signers, so two nodes cannot both take the next
// sequence or both rotate.
package signer

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/skenzeriq/activediq/internal/platform/agentpolicy"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/audit/chain"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/keys"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tablekind"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

var (
	_ = tablekind.Declare(tablekind.Table{Name: "public.agent_policy_key", Entity: "DM-86", Kind: tablekind.Tenant, Sealed: []string{"sealed_key"}})
	_ = tablekind.Declare(tablekind.Table{Name: "public.agent_policy_keyset", Entity: "DM-87", Kind: tablekind.Tenant, AppendOnly: true})
	_ = tablekind.Declare(tablekind.Table{Name: "public.agent_policy_head", Entity: "DM-88", Kind: tablekind.Tenant})
)

// Place of the sealed key in the AEAD associated data (TM-D7).
const (
	keyTable  = "agent_policy_key"
	keyColumn = "sealed_key"
)

// Defaults of the schedule (ADR-0007 decision 6).
const (
	// RotationInterval is the age of the active key at which the scheduled job rotates it.
	RotationInterval = 180 * 24 * time.Hour
	// DefaultPolicyLifetime is how long a signed policy stays acceptable when the caller names none.
	DefaultPolicyLifetime = agentpolicy.MaxLifetime
)

// Audit kinds. The details carry sequences and key IDs only.
const (
	KindKeysetPublished audit.Kind = "agentfleet.keyset.published"
	KindPolicySigned    audit.Kind = "agentfleet.policy.signed"
)

// Errors. None carries key material, stored bytes or SQL.
var (
	ErrNotConfigured = errors.New("signer: not configured")
	ErrIntegrity     = errors.New("signer: stored policy key material failed validation") // suspected exposure or corruption
	ErrTooManyKeys   = errors.New("signer: the keyset is full; wait for the overlap to end before rotating again")
	ErrNoKeyset      = errors.New("signer: the tenant has no keyset yet")
	ErrInvalid       = errors.New("signer: invalid request")
)

// KeySource gives the tenant's data-encryption key (TM-D7). version 0 asks for the current one. The
// caller destroys the key when done. It is the same port the CA and the audit checkpointer take.
type KeySource interface {
	DEK(ctx context.Context, tx store.Tx, id tenant.ID, version uint32) (keys.DEK, error)
}

// Signer signs policy and keyset documents. Audit is required; Clock is for tests.
type Signer struct {
	Keys  KeySource
	Audit audit.Sink
	Clock func() time.Time
}

func (s *Signer) now() time.Time {
	if s.Clock != nil {
		return s.Clock().UTC().Truncate(time.Second)
	}
	return time.Now().UTC().Truncate(time.Second)
}

func (s *Signer) ready() error {
	if s == nil || s.Keys == nil || s.Audit == nil {
		return ErrNotConfigured
	}
	return nil
}

func lock(ctx context.Context, tx store.Tx, tid tenant.ID) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('agentpolicy/' || $1::text, 0))`, tid.String())
	return err
}

type keyRow struct {
	id          string
	keyID       string
	public      ed25519.PublicKey
	sealed      []byte
	version     uint32
	state       agentpolicy.KeyState
	retireAfter time.Time
	createdAt   time.Time
}

// liveKeys reads the tenant's non-dropped keys, ordered by KeyID (the keyset's order).
func liveKeys(ctx context.Context, tx store.Tx) ([]keyRow, error) {
	rows, err := tx.Query(ctx, `SELECT id::text, key_id, public_key, sealed_key, key_version, state, retire_after, created_at
		FROM public.agent_policy_key WHERE state <> 'dropped' ORDER BY key_id`)
	if err != nil {
		return nil, fmt.Errorf("signer: read keys: %w", err)
	}
	defer rows.Close()
	var out []keyRow
	for rows.Next() {
		var (
			r     keyRow
			ver   int32
			state string
			ra    *time.Time
		)
		if err := rows.Scan(&r.id, &r.keyID, &r.public, &r.sealed, &ver, &state, &ra, &r.createdAt); err != nil {
			return nil, fmt.Errorf("signer: read keys: %w", err)
		}
		r.version = uint32(ver)
		switch state {
		case "active":
			r.state = agentpolicy.KeyActive
		case "retiring":
			r.state = agentpolicy.KeyRetiring
		default:
			return nil, ErrIntegrity
		}
		if ra != nil {
			r.retireAfter = ra.UTC()
		}
		if len(r.public) != ed25519.PublicKeySize || r.keyID != agentpolicy.KeyID(r.public) {
			return nil, ErrIntegrity
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("signer: read keys: %w", err)
	}
	return out, nil
}

func activeOf(ks []keyRow) (keyRow, bool) {
	for _, k := range ks {
		if k.state == agentpolicy.KeyActive {
			return k, true
		}
	}
	return keyRow{}, false
}

func keyContext(tid tenant.ID, rowID string, version uint32) keys.Context {
	return keys.Context{Tenant: tid, Table: keyTable, Row: rowID, Column: keyColumn, Version: version}
}

// openPrivate unseals one key. It is the only function in the product that returns the policy private
// key; the caller signs and clears it. A blob that fails to open, or opens to a key that is not the
// stored public key, is reported as ErrIntegrity.
func (s *Signer) openPrivate(ctx context.Context, tx store.Tx, tid tenant.ID, k keyRow) (ed25519.PrivateKey, error) {
	dek, err := s.Keys.DEK(ctx, tx, tid, k.version)
	if err != nil {
		return nil, fmt.Errorf("signer: tenant data key: %w", err)
	}
	defer dek.Destroy()
	seed, err := keys.Open(dek, keyContext(tid, k.id, k.version), k.sealed)
	if err != nil {
		return nil, ErrIntegrity
	}
	defer clear(seed)
	if len(seed) != ed25519.SeedSize {
		return nil, ErrIntegrity
	}
	priv := ed25519.NewKeyFromSeed(seed)
	if !priv.Public().(ed25519.PublicKey).Equal(k.public) {
		clear(priv)
		return nil, ErrIntegrity
	}
	return priv, nil
}

// newKey generates, seals and inserts a key in the given state. The seed is cleared before return.
func (s *Signer) newKey(ctx context.Context, tx store.Tx, tid tenant.ID, state agentpolicy.KeyState) (keyRow, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return keyRow{}, nil, fmt.Errorf("signer: generate key: %w", err)
	}
	dek, err := s.Keys.DEK(ctx, tx, tid, 0)
	if err != nil {
		clear(priv)
		return keyRow{}, nil, fmt.Errorf("signer: tenant data key: %w", err)
	}
	defer dek.Destroy()
	var rowID string
	if err := tx.QueryRow(ctx, `SELECT gen_random_uuid()::text`).Scan(&rowID); err != nil {
		clear(priv)
		return keyRow{}, nil, fmt.Errorf("signer: create key: %w", err)
	}
	seed := priv.Seed()
	sealed, err := keys.Seal(dek, keyContext(tid, rowID, dek.Version), seed)
	clear(seed)
	if err != nil {
		clear(priv)
		return keyRow{}, nil, fmt.Errorf("signer: seal key: %w", err)
	}
	kr := keyRow{id: rowID, keyID: agentpolicy.KeyID(pub), public: pub, sealed: sealed, version: dek.Version, state: state}
	if _, err := tx.Exec(ctx, `INSERT INTO public.agent_policy_key (tenant_id, id, key_id, public_key, sealed_key, key_version, state)
		VALUES ($1, $2, $3, $4, $5, $6, 'active')`, tid.String(), rowID, kr.keyID, []byte(pub), sealed, int32(dek.Version)); err != nil {
		clear(priv)
		return keyRow{}, nil, fmt.Errorf("signer: insert key: %w", err)
	}
	return kr, priv, nil
}

// keysetOf builds the next keyset document body from key rows.
func keysetOf(tid tenant.ID, seq uint64, now time.Time, signer string, ks []keyRow) agentpolicy.Keyset {
	out := agentpolicy.Keyset{Tenant: tid, Seq: seq, IssuedAt: now, SignerKeyID: signer}
	for _, k := range ks {
		out.Keys = append(out.Keys, agentpolicy.KeysetKey{KeyID: k.keyID, Public: k.public, State: k.state, RetireAfter: k.retireAfter})
	}
	sort.Slice(out.Keys, func(i, j int) bool { return out.Keys[i].KeyID < out.Keys[j].KeyID })
	return out
}

func lastKeysetSeq(ctx context.Context, tx store.Tx) (uint64, error) {
	var seq int64
	err := tx.QueryRow(ctx, `SELECT COALESCE(max(keyset_seq), 0) FROM public.agent_policy_keyset`).Scan(&seq)
	if err != nil {
		return 0, fmt.Errorf("signer: read keyset sequence: %w", err)
	}
	return uint64(seq), nil
}

func insertKeyset(ctx context.Context, tx store.Tx, tid tenant.ID, sk agentpolicy.SignedKeyset) error {
	_, err := tx.Exec(ctx, `INSERT INTO public.agent_policy_keyset (tenant_id, keyset_seq, signed, issued_at) VALUES ($1, $2, $3, $4)`,
		tid.String(), int64(sk.Seq), sk.Marshal(), sk.IssuedAt)
	if err != nil {
		return fmt.Errorf("signer: store keyset: %w", err)
	}
	return nil
}

// EnsureKeyset returns the tenant's current keyset, creating the first key and the self-signed
// keyset 1 when there is none (generation is lazy: a tenant with no addc agent has no key). It is
// what the first authenticated call after enrolment delivers as the anchor (decision 5).
func (s *Signer) EnsureKeyset(ctx context.Context, tx store.Tx, tid tenant.ID, actor authority.Chain) (agentpolicy.SignedKeyset, error) {
	if err := s.ready(); err != nil {
		return agentpolicy.SignedKeyset{}, err
	}
	if err := lock(ctx, tx, tid); err != nil {
		return agentpolicy.SignedKeyset{}, fmt.Errorf("signer: %w", err)
	}
	if sk, ok, err := currentKeyset(ctx, tx); err != nil || ok {
		return sk, err
	}
	now := s.now()
	kr, priv, err := s.newKey(ctx, tx, tid, agentpolicy.KeyActive)
	if err != nil {
		return agentpolicy.SignedKeyset{}, err
	}
	defer clear(priv)
	sk, err := agentpolicy.SignKeyset(keysetOf(tid, 1, now, kr.keyID, []keyRow{kr}), priv)
	if err != nil {
		return agentpolicy.SignedKeyset{}, err
	}
	if err := insertKeyset(ctx, tx, tid, sk); err != nil {
		return agentpolicy.SignedKeyset{}, err
	}
	return sk, s.auditKeyset(ctx, tx, tid, actor, now, "created", sk)
}

// currentKeyset reads the highest stored keyset.
func currentKeyset(ctx context.Context, tx store.Tx) (agentpolicy.SignedKeyset, bool, error) {
	var raw []byte
	err := tx.QueryRow(ctx, `SELECT signed FROM public.agent_policy_keyset ORDER BY keyset_seq DESC LIMIT 1`).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return agentpolicy.SignedKeyset{}, false, nil
	}
	if err != nil {
		return agentpolicy.SignedKeyset{}, false, fmt.Errorf("signer: read keyset: %w", err)
	}
	sk, err := agentpolicy.ParseSignedKeyset(raw)
	if err != nil {
		return agentpolicy.SignedKeyset{}, false, ErrIntegrity
	}
	return sk, true, nil
}

// Chain returns every keyset with a sequence above since, in order: what an agent that was offline
// across several rotations replays link by link (each is signed by a key the previous one carried).
// since 0 returns the whole chain, which begins with the anchor.
func (s *Signer) Chain(ctx context.Context, tx store.Tx, since uint64) ([]agentpolicy.SignedKeyset, error) {
	rows, err := tx.Query(ctx, `SELECT signed FROM public.agent_policy_keyset WHERE keyset_seq > $1 ORDER BY keyset_seq`, int64(since))
	if err != nil {
		return nil, fmt.Errorf("signer: read chain: %w", err)
	}
	defer rows.Close()
	var out []agentpolicy.SignedKeyset
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, fmt.Errorf("signer: read chain: %w", err)
		}
		sk, err := agentpolicy.ParseSignedKeyset(raw)
		if err != nil {
			return nil, ErrIntegrity
		}
		out = append(out, sk)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("signer: read chain: %w", err)
	}
	return out, nil
}

// Rotate introduces a new active key (decision 4). The old active key becomes retiring for the
// overlap window and signs the new keyset, so every agent holding the old keyset can verify the link.
// It refuses when the keyset has no room (ErrTooManyKeys) rather than dropping a key early.
func (s *Signer) Rotate(ctx context.Context, tx store.Tx, tid tenant.ID, actor authority.Chain, reason string) (agentpolicy.SignedKeyset, error) {
	if err := s.ready(); err != nil {
		return agentpolicy.SignedKeyset{}, err
	}
	if err := lock(ctx, tx, tid); err != nil {
		return agentpolicy.SignedKeyset{}, fmt.Errorf("signer: %w", err)
	}
	ks, err := liveKeys(ctx, tx)
	if err != nil {
		return agentpolicy.SignedKeyset{}, err
	}
	old, ok := activeOf(ks)
	if !ok {
		return agentpolicy.SignedKeyset{}, ErrNoKeyset
	}
	if len(ks) >= agentpolicy.MaxKeys {
		return agentpolicy.SignedKeyset{}, ErrTooManyKeys
	}
	now := s.now()
	oldPriv, err := s.openPrivate(ctx, tx, tid, old)
	if err != nil {
		return agentpolicy.SignedKeyset{}, err
	}
	defer clear(oldPriv)
	// The old key moves first: the partial unique index admits one active key.
	retire := now.Add(agentpolicy.OverlapWindow)
	if _, err := tx.Exec(ctx, `UPDATE public.agent_policy_key SET state = 'retiring', retire_after = $2 WHERE id = $1`, old.id, retire); err != nil {
		return agentpolicy.SignedKeyset{}, fmt.Errorf("signer: retire key: %w", err)
	}
	fresh, freshPriv, err := s.newKey(ctx, tx, tid, agentpolicy.KeyActive)
	if err != nil {
		return agentpolicy.SignedKeyset{}, err
	}
	clear(freshPriv) // the new key signs nothing until the next call opens it
	for i := range ks {
		if ks[i].id == old.id {
			ks[i].state, ks[i].retireAfter = agentpolicy.KeyRetiring, retire
		}
	}
	return s.publish(ctx, tx, tid, actor, now, old, oldPriv, append(ks, fresh), "rotated:"+reason)
}

// DropExpired publishes a keyset without the retiring keys whose overlap has ended, and erases their
// sealed material. The new active key signs it, so agents already hold the signer. It returns
// (zero, false) when nothing has expired.
func (s *Signer) DropExpired(ctx context.Context, tx store.Tx, tid tenant.ID, actor authority.Chain) (agentpolicy.SignedKeyset, bool, error) {
	if err := s.ready(); err != nil {
		return agentpolicy.SignedKeyset{}, false, err
	}
	if err := lock(ctx, tx, tid); err != nil {
		return agentpolicy.SignedKeyset{}, false, fmt.Errorf("signer: %w", err)
	}
	ks, err := liveKeys(ctx, tx)
	if err != nil {
		return agentpolicy.SignedKeyset{}, false, err
	}
	now := s.now()
	var keep, drop []keyRow
	for _, k := range ks {
		if k.state == agentpolicy.KeyRetiring && !k.retireAfter.After(now) {
			drop = append(drop, k)
		} else {
			keep = append(keep, k)
		}
	}
	if len(drop) == 0 {
		return agentpolicy.SignedKeyset{}, false, nil
	}
	active, ok := activeOf(keep)
	if !ok {
		return agentpolicy.SignedKeyset{}, false, ErrIntegrity
	}
	priv, err := s.openPrivate(ctx, tx, tid, active)
	if err != nil {
		return agentpolicy.SignedKeyset{}, false, err
	}
	defer clear(priv)
	sk, err := s.publish(ctx, tx, tid, actor, now, active, priv, keep, "dropped")
	if err != nil {
		return agentpolicy.SignedKeyset{}, false, err
	}
	for _, k := range drop {
		if _, err := tx.Exec(ctx, `UPDATE public.agent_policy_key SET state = 'dropped', sealed_key = NULL, key_version = NULL, dropped_at = $2 WHERE id = $1`, k.id, now); err != nil {
			return agentpolicy.SignedKeyset{}, false, fmt.Errorf("signer: drop key: %w", err)
		}
	}
	return sk, true, nil
}

// publish signs the next keyset with signerKey, which is in the previous keyset, stores it and audits.
func (s *Signer) publish(ctx context.Context, tx store.Tx, tid tenant.ID, actor authority.Chain, now time.Time,
	signerKey keyRow, signerPriv ed25519.PrivateKey, ks []keyRow, what string) (agentpolicy.SignedKeyset, error) {
	last, err := lastKeysetSeq(ctx, tx)
	if err != nil {
		return agentpolicy.SignedKeyset{}, err
	}
	sk, err := agentpolicy.SignKeyset(keysetOf(tid, last+1, now, signerKey.keyID, ks), signerPriv)
	if err != nil {
		return agentpolicy.SignedKeyset{}, err
	}
	if err := insertKeyset(ctx, tx, tid, sk); err != nil {
		return agentpolicy.SignedKeyset{}, err
	}
	return sk, s.auditKeyset(ctx, tx, tid, actor, now, what, sk)
}

// PendingMaintenance says what the scheduled job would do now: rotate (the active key is older than
// RotationInterval) or drop (a retiring key's overlap has ended). Both false for a tenant with no
// keyset.
func (s *Signer) PendingMaintenance(ctx context.Context, tx store.Tx) (rotate, drop bool, err error) {
	ks, err := liveKeys(ctx, tx)
	if err != nil {
		return false, false, err
	}
	now := s.now()
	for _, k := range ks {
		switch {
		case k.state == agentpolicy.KeyActive && now.Sub(k.createdAt) >= RotationInterval:
			rotate = true
		case k.state == agentpolicy.KeyRetiring && !k.retireAfter.After(now):
			drop = true
		}
	}
	return rotate, drop, nil
}

// SignPolicy signs body as the next policy of kind for the tenant. The sequence is the head row's
// plus one, taken under the tenant lock, so it is strictly increasing (decision 2). The body is
// validated against the schema bounds first; an out-of-bounds policy is never signed.
func (s *Signer) SignPolicy(ctx context.Context, tx store.Tx, tid tenant.ID, kind string, body agentpolicy.AddcPolicy,
	lifetime time.Duration, actor authority.Chain) (agentpolicy.SignedPolicy, error) {
	if err := s.ready(); err != nil {
		return agentpolicy.SignedPolicy{}, err
	}
	// Only the addc body schema exists in this ticket; the fileserver policy is T-0143's.
	if kind != agentpolicy.KindADDC || actor.Validate() != nil {
		return agentpolicy.SignedPolicy{}, ErrInvalid
	}
	if lifetime == 0 {
		lifetime = DefaultPolicyLifetime
	}
	if lifetime < 0 || lifetime > agentpolicy.MaxLifetime {
		return agentpolicy.SignedPolicy{}, ErrInvalid
	}
	enc, err := body.Encode()
	if err != nil {
		return agentpolicy.SignedPolicy{}, err
	}
	if err := lock(ctx, tx, tid); err != nil {
		return agentpolicy.SignedPolicy{}, fmt.Errorf("signer: %w", err)
	}
	ks, err := liveKeys(ctx, tx)
	if err != nil {
		return agentpolicy.SignedPolicy{}, err
	}
	active, ok := activeOf(ks)
	if !ok {
		return agentpolicy.SignedPolicy{}, ErrNoKeyset
	}
	var floor int64
	err = tx.QueryRow(ctx, `SELECT policy_seq FROM public.agent_policy_head WHERE agent_kind = $1`, kind).Scan(&floor)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return agentpolicy.SignedPolicy{}, fmt.Errorf("signer: read policy sequence: %w", err)
	}
	priv, err := s.openPrivate(ctx, tx, tid, active)
	if err != nil {
		return agentpolicy.SignedPolicy{}, err
	}
	defer clear(priv)
	now := s.now()
	h := agentpolicy.PolicyHeader{Tenant: tid, Kind: kind, Seq: uint64(floor) + 1, IssuedAt: now, NotAfter: now.Add(lifetime), KeyID: active.keyID}
	sp, err := agentpolicy.SignPolicy(h, enc, priv)
	if err != nil {
		return agentpolicy.SignedPolicy{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO public.agent_policy_head (tenant_id, agent_kind, policy_seq, signed, issued_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (tenant_id, agent_kind) DO UPDATE SET policy_seq = EXCLUDED.policy_seq, signed = EXCLUDED.signed, issued_at = EXCLUDED.issued_at`,
		tid.String(), kind, int64(h.Seq), sp.Marshal(), now); err != nil {
		return agentpolicy.SignedPolicy{}, fmt.Errorf("signer: store policy: %w", err)
	}
	err = s.Audit.Append(ctx, tx, audit.Event{
		ID: fmt.Sprintf("%s.%s.%s.%d", KindPolicySigned, tid, kind, h.Seq), Kind: KindPolicySigned, At: now, Actor: actor,
		Target:    authority.TargetRef{GUID: tid.String(), Class: "agent_policy"},
		Component: "agentfleet", Outcome: audit.Success,
		Details: []chain.Detail{{Key: "agent_kind", Value: kind}, {Key: "key_id", Value: h.KeyID}, {Key: "policy_seq", Value: fmt.Sprint(h.Seq)}},
	})
	return sp, err
}

// CurrentPolicy returns the latest signed policy of kind, for delivery to an agent that connects.
func (s *Signer) CurrentPolicy(ctx context.Context, tx store.Tx, kind string) (agentpolicy.SignedPolicy, bool, error) {
	var raw []byte
	err := tx.QueryRow(ctx, `SELECT signed FROM public.agent_policy_head WHERE agent_kind = $1`, kind).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return agentpolicy.SignedPolicy{}, false, nil
	}
	if err != nil {
		return agentpolicy.SignedPolicy{}, false, fmt.Errorf("signer: read policy: %w", err)
	}
	sp, err := agentpolicy.ParseSignedPolicy(raw)
	if err != nil {
		return agentpolicy.SignedPolicy{}, false, ErrIntegrity
	}
	return sp, true, nil
}

func (s *Signer) auditKeyset(ctx context.Context, tx store.Tx, tid tenant.ID, actor authority.Chain, now time.Time, what string, sk agentpolicy.SignedKeyset) error {
	return s.Audit.Append(ctx, tx, audit.Event{
		ID: fmt.Sprintf("%s.%s.%d", KindKeysetPublished, tid, sk.Seq), Kind: KindKeysetPublished, At: now, Actor: actor,
		Target:    authority.TargetRef{GUID: tid.String(), Class: "agent_policy_key"},
		Component: "agentfleet", Outcome: audit.Success, Reason: what,
		Details: []chain.Detail{{Key: "keyset_seq", Value: fmt.Sprint(sk.Seq)}, {Key: "signer_key_id", Value: sk.SignerKeyID}},
	})
}
