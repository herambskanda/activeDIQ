package audit

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit/chain"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/keys"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// KeySource gives the tenant's data-encryption key (TM-D7) under which the checkpoint private key is
// sealed. version 0 asks for the current version. The caller destroys the key when done.
type KeySource interface {
	DEK(ctx context.Context, tx store.Tx, id tenant.ID, version uint32) (keys.DEK, error)
}

// Anchor receives every checkpoint and every key event for external anchoring (a SIEM sink; ADR-0005
// rule 11). Delivery is at least once; seq de-duplicates.
type Anchor interface {
	Anchor(ctx context.Context, c chain.Checkpoint) error
}

// ErrAnchor is returned by Checkpointer.Sign when the checkpoint was recorded but an anchor refused it.
// The checkpoint is durable and the forwarding job re-sends it by seq.
var ErrAnchor = errors.New("audit: the checkpoint is recorded but an anchor did not accept it")

const (
	keyTable  = "audit_checkpoint_key"
	keyColumn = "sealed_private_key"
)

var systemActor = authority.Chain{Requester: authority.Principal{ID: "system:audit", Kind: authority.System}}

func keyContext(id tenant.ID, keyID string, version uint32) keys.Context {
	return keys.Context{Tenant: id, Table: keyTable, Row: keyID, Column: keyColumn, Version: version}
}

// Checkpointer signs the chain head and hands the checkpoint to its anchors.
type Checkpointer struct {
	chainer *Chainer
	ks      KeySource
	anchors []Anchor
}

// NewCheckpointer makes a checkpointer. The chainer is the one the store was opened with.
func NewCheckpointer(c *Chainer, ks KeySource, anchors ...Anchor) *Checkpointer {
	return &Checkpointer{chainer: c, ks: ks, anchors: anchors}
}

// InitTenant is the tenant initialiser of ADR-0005 rule 11 (provision.Initialiser): it creates the
// genesis head, the first checkpoint key, and appends audit.checkpoint_key.created and
// audit.tenant.initialised. It is idempotent: a tenant that has a head is left alone.
func (c *Checkpointer) InitTenant(ctx context.Context, tx store.Tx, id tenant.ID) error {
	g := chain.Genesis(uuidBytes(id))
	tag, err := tx.Exec(ctx, `INSERT INTO audit_head (tenant_id, seq, hash, at) VALUES ($1::uuid, 0, $2, now()) ON CONFLICT (tenant_id) DO NOTHING`, id.String(), g[:])
	if err != nil {
		return fmt.Errorf("audit: create chain head: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return nil
	}
	if err := c.newKey(ctx, tx, id, 1); err != nil {
		return err
	}
	return c.chainer.Append(ctx, tx, Event{ID: "audit.tenant.initialised", Kind: chain.KindTenantInited, At: time.Now(),
		Actor: systemActor, Component: "audit", Outcome: Success})
}

// newKey creates the tenant's ordinal-th checkpoint key, seals its private key and appends the created event.
func (c *Checkpointer) newKey(ctx context.Context, tx store.Tx, id tenant.ID, ordinal int) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("audit: generate checkpoint key: %w", err)
	}
	seed := priv.Seed()
	defer clear(seed)
	dek, err := c.ks.DEK(ctx, tx, id, 0)
	if err != nil {
		return fmt.Errorf("audit: tenant data key: %w", err)
	}
	defer dek.Destroy()
	keyID := chain.Fingerprint(pub)
	sealed, err := keys.Seal(dek, keyContext(id, keyID, dek.Version), seed)
	if err != nil {
		return fmt.Errorf("audit: seal checkpoint key: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO audit_checkpoint_key (tenant_id, key_id, public_key, sealed_private_key, key_version, ordinal)
		VALUES ($1::uuid, $2, $3, $4, $5, $6)`, id.String(), keyID, []byte(pub), sealed, int32(dek.Version), int32(ordinal)); err != nil {
		return fmt.Errorf("audit: store checkpoint key: %w", err)
	}
	return c.chainer.Append(ctx, tx, Event{ID: "audit.key.created." + keyID, Kind: chain.KindKeyCreated, At: time.Now(),
		Actor: systemActor, Component: "audit", Outcome: Success,
		Details: []chain.Detail{{Key: "key_id", Value: keyID}, {Key: "public_key", Value: hex.EncodeToString(pub)}}})
}

// Sign signs the current head if anything was appended since the last checkpoint, records it, and sends
// it to every anchor after the commit. recorded is false when there was nothing new to sign (the latest
// checkpoint is returned). A failing anchor yields ErrAnchor with the recorded checkpoint.
func (c *Checkpointer) Sign(ctx context.Context, db *store.DB, id tenant.ID) (cp chain.Checkpoint, recorded bool, err error) {
	err = db.WithTenant(ctx, id, func(ctx context.Context, tx store.Tx) error {
		var e error
		cp, recorded, e = c.signInTx(ctx, tx, id)
		return e
	})
	if err != nil || !recorded {
		return cp, recorded, err
	}
	for _, a := range c.anchors {
		if aerr := a.Anchor(ctx, cp); aerr != nil {
			err = ErrAnchor
		}
	}
	return cp, true, err
}

func (c *Checkpointer) signInTx(ctx context.Context, tx store.Tx, id tenant.ID) (chain.Checkpoint, bool, error) {
	var head struct {
		seq  uint64
		hash []byte
	}
	if err := tx.QueryRow(ctx, `SELECT seq, hash FROM audit_head WHERE tenant_id = $1::uuid`, id.String()).Scan(&head.seq, &head.hash); err != nil {
		if store.IsNoRows(err) {
			return chain.Checkpoint{}, false, ErrNoHead
		}
		return chain.Checkpoint{}, false, fmt.Errorf("audit: read head: %w", err)
	}
	last, haveLast, err := latestCheckpoint(ctx, tx, id)
	if err != nil {
		return chain.Checkpoint{}, false, err
	}
	if head.seq == 0 || (haveLast && last.Seq == head.seq) {
		return last, false, nil
	}
	// The newest key signs.
	var keyID string
	var sealed []byte
	var version int32
	if err := tx.QueryRow(ctx, `SELECT key_id, sealed_private_key, key_version FROM audit_checkpoint_key WHERE tenant_id = $1::uuid ORDER BY ordinal DESC LIMIT 1`, id.String()).Scan(&keyID, &sealed, &version); err != nil {
		return chain.Checkpoint{}, false, fmt.Errorf("audit: read checkpoint key: %w", err)
	}
	dek, err := c.ks.DEK(ctx, tx, id, uint32(version))
	if err != nil {
		return chain.Checkpoint{}, false, fmt.Errorf("audit: tenant data key: %w", err)
	}
	defer dek.Destroy()
	seed, err := keys.Open(dek, keyContext(id, keyID, uint32(version)), sealed)
	if err != nil {
		return chain.Checkpoint{}, false, fmt.Errorf("audit: open checkpoint key: %w", err)
	}
	defer clear(seed)
	priv := ed25519.NewKeyFromSeed(seed)
	cp := chain.Checkpoint{Tenant: uuidBytes(id), Seq: head.seq, KeyID: keyID}
	copy(cp.Hash[:], head.hash)
	if haveLast {
		cp.PrevSeq, cp.PrevHash = last.Seq, last.Hash
	}
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&cp.SignedAt); err != nil {
		return chain.Checkpoint{}, false, fmt.Errorf("audit: read clock: %w", err)
	}
	cp.SignedAt = cp.SignedAt.UTC().Truncate(time.Microsecond)
	if err := cp.Sign(priv); err != nil {
		return chain.Checkpoint{}, false, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO audit_checkpoint (tenant_id, seq, hash, signed_at, key_id, prev_checkpoint_seq, prev_checkpoint_hash, signature)
		VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8)`, id.String(), cp.Seq, cp.Hash[:], cp.SignedAt, cp.KeyID, cp.PrevSeq, cp.PrevHash[:], cp.Signature); err != nil {
		return chain.Checkpoint{}, false, fmt.Errorf("audit: record checkpoint: %w", err)
	}
	return cp, true, nil
}

func latestCheckpoint(ctx context.Context, tx store.Tx, id tenant.ID) (chain.Checkpoint, bool, error) {
	cps, err := ListCheckpoints(ctx, tx, id, 0, 0, 1, true)
	if err != nil || len(cps) == 0 {
		return chain.Checkpoint{}, false, err
	}
	return cps[0], true, nil
}

const listCheckpoints = `SELECT seq, hash, signed_at, key_id, prev_checkpoint_seq, prev_checkpoint_hash, signature
	FROM audit_checkpoint WHERE tenant_id = $1::uuid AND seq > $2 AND ($3 = 0 OR seq <= $3)
	ORDER BY CASE WHEN $5::boolean THEN -seq ELSE seq END LIMIT $4`

// ListCheckpoints reads checkpoints with after < seq <= upTo (upTo 0: no upper bound), oldest first, at
// most limit; newest first when newestFirst. The forwarding job reads by this seq watermark.
func ListCheckpoints(ctx context.Context, tx store.Tx, id tenant.ID, after, upTo uint64, limit int, newestFirst bool) ([]chain.Checkpoint, error) {
	rows, err := tx.Query(ctx, listCheckpoints, id.String(), after, upTo, limit, newestFirst)
	if err != nil {
		return nil, fmt.Errorf("audit: list checkpoints: %w", err)
	}
	defer rows.Close()
	var out []chain.Checkpoint
	for rows.Next() {
		cp := chain.Checkpoint{Tenant: uuidBytes(id)}
		var h, ph []byte
		if err := rows.Scan(&cp.Seq, &h, &cp.SignedAt, &cp.KeyID, &cp.PrevSeq, &ph, &cp.Signature); err != nil {
			return nil, fmt.Errorf("audit: read checkpoint: %w", err)
		}
		copy(cp.Hash[:], h)
		copy(cp.PrevHash[:], ph)
		cp.SignedAt = cp.SignedAt.UTC()
		out = append(out, cp)
	}
	return out, rows.Err()
}

// Rotate signs a final checkpoint under the current key, then retires it and introduces a new one, both
// as chained events (routine rotation; ADR-0005 rule 11). The first checkpoint under the new key is
// signed by the next Sign.
func (c *Checkpointer) Rotate(ctx context.Context, db *store.DB, id tenant.ID, actor authority.Chain) error {
	if _, _, err := c.Sign(ctx, db, id); err != nil && !errors.Is(err, ErrAnchor) {
		return err
	}
	return db.WithTenant(ctx, id, func(ctx context.Context, tx store.Tx) error {
		var oldID string
		var ordinal int32
		if err := tx.QueryRow(ctx, `SELECT key_id, ordinal FROM audit_checkpoint_key WHERE tenant_id = $1::uuid ORDER BY ordinal DESC LIMIT 1`, id.String()).Scan(&oldID, &ordinal); err != nil {
			return fmt.Errorf("audit: read checkpoint key: %w", err)
		}
		if err := c.chainer.Append(ctx, tx, Event{ID: "audit.key.retired." + oldID, Kind: chain.KindKeyRetired, At: time.Now(),
			Actor: actor, Component: "audit", Outcome: Success, Details: []chain.Detail{{Key: "key_id", Value: oldID}}}); err != nil {
			return err
		}
		return c.newKey(ctx, tx, id, int(ordinal)+1)
	})
}

func uuidBytes(id tenant.ID) [16]byte {
	u, _ := chain.ParseUUID(id.String())
	return u
}
