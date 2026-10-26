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
	parts   Partitions
}

// NewCheckpointer makes a checkpointer. The chainer is the one the store was opened with.
func NewCheckpointer(c *Chainer, ks KeySource, anchors ...Anchor) *Checkpointer {
	return &Checkpointer{chainer: c, ks: ks, anchors: anchors, parts: Monthly}
}

// WithPartitions sets how time is partitioned for boundary checkpoints (default Monthly) and returns c.
// Set it before the checkpointer is shared.
func (c *Checkpointer) WithPartitions(p Partitions) *Checkpointer {
	c.parts = p
	return c
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
	if err := c.newKey(ctx, tx, id, 1, nil); err != nil {
		return err
	}
	return c.chainer.Append(ctx, tx, Event{ID: "audit.tenant.initialised", Kind: chain.KindTenantInited, At: time.Now(),
		Actor: systemActor, Component: "audit", Outcome: Success})
}

// newKey creates the tenant's ordinal-th checkpoint key, seals its private key and appends the created event.
// A non-nil signer is the outgoing key: it cross-signs the new key's introduction.
func (c *Checkpointer) newKey(ctx context.Context, tx store.Tx, id tenant.ID, ordinal int, signer ed25519.PrivateKey) error {
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
	details := []chain.Detail{{Key: "key_id", Value: keyID}, {Key: "public_key", Value: hex.EncodeToString(pub)}}
	if signer != nil {
		signerID, sig, err := chain.CrossSign(uuidBytes(id), signer, pub)
		if err != nil {
			return fmt.Errorf("audit: cross-sign checkpoint key: %w", err)
		}
		// Details must be in key order.
		details = []chain.Detail{{Key: chain.DetailCrossSignature, Value: hex.EncodeToString(sig)}, details[0], details[1],
			{Key: chain.DetailSignedBy, Value: signerID}}
	}
	return c.chainer.Append(ctx, tx, Event{ID: "audit.key.created." + keyID, Kind: chain.KindKeyCreated, At: time.Now(),
		Actor: systemActor, Component: "audit", Outcome: Success, Details: details})
}

// Sign signs, in order, the last event of every time partition that has ended since the last checkpoint
// (see SignBoundaries) and then the current head if anything was appended since, records them, and sends
// each to every anchor after the commit. recorded is false when there was nothing new to sign (the latest
// checkpoint is returned); cp is the newest checkpoint. A failing anchor yields ErrAnchor with the
// recorded checkpoint.
func (c *Checkpointer) Sign(ctx context.Context, db *store.DB, id tenant.ID) (cp chain.Checkpoint, recorded bool, err error) {
	var made []chain.Checkpoint
	err = db.WithTenant(ctx, id, func(ctx context.Context, tx store.Tx) error {
		var e error
		made, e = c.signBoundariesInTx(ctx, tx, id)
		if e != nil {
			return e
		}
		head, ok, e := c.signHeadInTx(ctx, tx, id)
		if e != nil {
			return e
		}
		if ok {
			made = append(made, head)
		}
		if len(made) > 0 {
			cp = made[len(made)-1]
			return nil
		}
		cp = head
		return nil
	})
	if err != nil || len(made) == 0 {
		return cp, false, err
	}
	return cp, true, c.anchor(ctx, made)
}

// SignBoundaries signs the last event of every time partition that has ended and is not yet covered by a
// checkpoint (ADR-0005 rule 11: the partition-boundary checkpoint is what makes a partition purgeable).
// Sign does this first on every call, so a rollover job that calls only this is optional. It returns the
// checkpoints it recorded, oldest first.
func (c *Checkpointer) SignBoundaries(ctx context.Context, db *store.DB, id tenant.ID) ([]chain.Checkpoint, error) {
	var made []chain.Checkpoint
	err := db.WithTenant(ctx, id, func(ctx context.Context, tx store.Tx) error {
		var e error
		made, e = c.signBoundariesInTx(ctx, tx, id)
		return e
	})
	if err != nil || len(made) == 0 {
		return nil, err
	}
	return made, c.anchor(ctx, made)
}

func (c *Checkpointer) anchor(ctx context.Context, cps []chain.Checkpoint) error {
	var err error
	for _, cp := range cps {
		for _, a := range c.anchors {
			if aerr := a.Anchor(ctx, cp); aerr != nil {
				err = ErrAnchor
			}
		}
	}
	return err
}

// signBoundariesInTx walks the partitions that have ended since the latest checkpoint. For each it signs
// the partition's last event, unless a checkpoint already sits there. Checkpoints chain by seq, so the
// boundary must be signed before any later checkpoint: Sign calls this before it signs the head.
func (c *Checkpointer) signBoundariesInTx(ctx context.Context, tx store.Tx, id tenant.ID) ([]chain.Checkpoint, error) {
	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return nil, fmt.Errorf("audit: read clock: %w", err)
	}
	var made []chain.Checkpoint
	for {
		last, haveLast, err := latestCheckpoint(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		var next time.Time
		err = tx.QueryRow(ctx, `SELECT at FROM audit_event WHERE tenant_id = $1::uuid AND seq > $2 ORDER BY seq LIMIT 1`, id.String(), last.Seq).Scan(&next)
		if store.IsNoRows(err) {
			return made, nil
		} else if err != nil {
			return nil, fmt.Errorf("audit: read next event: %w", err)
		}
		end := c.parts.End(next)
		if end.After(now) {
			return made, nil // the partition is still open
		}
		var seq uint64
		var hash []byte
		if err := tx.QueryRow(ctx, `SELECT seq, hash FROM audit_event WHERE tenant_id = $1::uuid AND at < $2 ORDER BY seq DESC LIMIT 1`, id.String(), end).Scan(&seq, &hash); err != nil {
			return nil, fmt.Errorf("audit: read partition boundary: %w", err)
		}
		// A key signs only from the seq that introduces it. A partition that ended across a rotation, with
		// its last event before the current key's introduction, can no longer be signed validly (the old
		// key is retired, and wiped): it stays unpurgeable and the later partitions are signed as usual.
		var created uint64
		if err := tx.QueryRow(ctx, `SELECT e.seq FROM audit_event e WHERE e.tenant_id = $1::uuid AND e.event_id = 'audit.key.created.' || (
			SELECT key_id FROM audit_checkpoint_key WHERE tenant_id = $1::uuid ORDER BY ordinal DESC LIMIT 1)`, id.String()).Scan(&created); err != nil {
			// No introduction event: a retention purge deleted it, so the key was introduced below every
			// retained event (its window lives in the purge event) and any retained seq may be signed.
			if !store.IsNoRows(err) {
				return nil, fmt.Errorf("audit: read key introduction: %w", err)
			}
			created = 0
		}
		if seq < created {
			return made, nil
		}
		cp, err := c.signAt(ctx, tx, id, seq, hash, last, haveLast)
		if err != nil {
			return nil, err
		}
		made = append(made, cp)
	}
}

// signHeadInTx signs the head if anything was appended since the latest checkpoint; otherwise it returns
// that checkpoint with ok false.
func (c *Checkpointer) signHeadInTx(ctx context.Context, tx store.Tx, id tenant.ID) (cp chain.Checkpoint, ok bool, err error) {
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
	cp, err = c.signAt(ctx, tx, id, head.seq, head.hash, last, haveLast)
	return cp, err == nil, err
}

// signAt signs the event (seq, hash), chained to the latest checkpoint, and records it.
func (c *Checkpointer) signAt(ctx context.Context, tx store.Tx, id tenant.ID, seq uint64, hash []byte, last chain.Checkpoint, haveLast bool) (chain.Checkpoint, error) {
	keyID, _, priv, err := c.currentKey(ctx, tx, id)
	if err != nil {
		return chain.Checkpoint{}, err
	}
	defer clear(priv)
	cp := chain.Checkpoint{Tenant: uuidBytes(id), Seq: seq, KeyID: keyID}
	copy(cp.Hash[:], hash)
	if haveLast {
		cp.PrevSeq, cp.PrevHash = last.Seq, last.Hash
	}
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&cp.SignedAt); err != nil {
		return chain.Checkpoint{}, fmt.Errorf("audit: read clock: %w", err)
	}
	cp.SignedAt = cp.SignedAt.UTC().Truncate(time.Microsecond)
	if err := cp.Sign(priv); err != nil {
		return chain.Checkpoint{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO audit_checkpoint (tenant_id, seq, hash, signed_at, key_id, prev_checkpoint_seq, prev_checkpoint_hash, signature)
		VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8)`, id.String(), cp.Seq, cp.Hash[:], cp.SignedAt, cp.KeyID, cp.PrevSeq, cp.PrevHash[:], cp.Signature); err != nil {
		return chain.Checkpoint{}, fmt.Errorf("audit: record checkpoint: %w", err)
	}
	return cp, nil
}

// currentKey opens the tenant's newest checkpoint key. The caller clears the returned private key.
func (c *Checkpointer) currentKey(ctx context.Context, tx store.Tx, id tenant.ID) (keyID string, ordinal int, priv ed25519.PrivateKey, err error) {
	var sealed []byte
	var version, ord int32
	if err := tx.QueryRow(ctx, `SELECT key_id, sealed_private_key, key_version, ordinal FROM audit_checkpoint_key WHERE tenant_id = $1::uuid ORDER BY ordinal DESC LIMIT 1`, id.String()).Scan(&keyID, &sealed, &version, &ord); err != nil {
		return "", 0, nil, fmt.Errorf("audit: read checkpoint key: %w", err)
	}
	dek, err := c.ks.DEK(ctx, tx, id, uint32(version))
	if err != nil {
		return "", 0, nil, fmt.Errorf("audit: tenant data key: %w", err)
	}
	defer dek.Destroy()
	seed, err := keys.Open(dek, keyContext(id, keyID, uint32(version)), sealed)
	if err != nil {
		return "", 0, nil, fmt.Errorf("audit: open checkpoint key: %w", err)
	}
	defer clear(seed)
	return keyID, int(ord), ed25519.NewKeyFromSeed(seed), nil
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
// as chained events (routine rotation; ADR-0005 rule 11), and finally wipes the retired key's private
// material (WipeRetiredKeys). The first checkpoint under the new key is signed by the next Sign.
func (c *Checkpointer) Rotate(ctx context.Context, db *store.DB, id tenant.ID, actor authority.Chain) error {
	if _, _, err := c.Sign(ctx, db, id); err != nil && !errors.Is(err, ErrAnchor) {
		return err
	}
	err := db.WithTenant(ctx, id, func(ctx context.Context, tx store.Tx) error {
		oldID, ordinal, oldPriv, err := c.currentKey(ctx, tx, id)
		if err != nil {
			return err
		}
		defer clear(oldPriv)
		if err := c.chainer.Append(ctx, tx, Event{ID: "audit.key.retired." + oldID, Kind: chain.KindKeyRetired, At: time.Now(),
			Actor: actor, Component: "audit", Outcome: Success, Details: []chain.Detail{{Key: "key_id", Value: oldID}}}); err != nil {
			return err
		}
		return c.newKey(ctx, tx, id, ordinal+1, oldPriv)
	})
	if err != nil {
		return err
	}
	return c.WipeRetiredKeys(ctx, db, id)
}

// WipeRetiredKeys destroys the sealed private key of every retired checkpoint key of the tenant, through
// the SECURITY DEFINER function audit_wipe_retired_key; the runtime role cannot update the key table
// itself (migration 0015, I5). It is idempotent. Rotate calls it once the retirement is committed, and a
// maintenance job can call it again if that call failed after the rotation.
func (c *Checkpointer) WipeRetiredKeys(ctx context.Context, db *store.DB, id tenant.ID) error {
	return db.WithTenant(ctx, id, func(ctx context.Context, tx store.Tx) error {
		rows, err := tx.Query(ctx, `SELECT key_id FROM audit_checkpoint_key WHERE tenant_id = $1::uuid
			AND ordinal < (SELECT max(ordinal) FROM audit_checkpoint_key WHERE tenant_id = $1::uuid)
			AND octet_length(sealed_private_key) > 0 ORDER BY ordinal`, id.String())
		if err != nil {
			return fmt.Errorf("audit: list retired keys: %w", err)
		}
		var ids []string
		for rows.Next() {
			var k string
			if err := rows.Scan(&k); err != nil {
				rows.Close()
				return fmt.Errorf("audit: read retired key: %w", err)
			}
			ids = append(ids, k)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return fmt.Errorf("audit: list retired keys: %w", err)
		}
		for _, k := range ids {
			if _, err := tx.Exec(ctx, `SELECT public.audit_wipe_retired_key($1)`, k); err != nil {
				return fmt.Errorf("audit: wipe retired key %s: %w", k, err)
			}
		}
		return nil
	})
}

func uuidBytes(id tenant.ID) [16]byte {
	u, _ := chain.ParseUUID(id.String())
	return u
}
