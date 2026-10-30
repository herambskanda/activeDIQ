package audit

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit/chain"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// KindExported is the event an export records about itself (AG-8).
const KindExported Kind = "audit.exported"

// ErrNoBoundary is returned when an export that does not start at seq 1 has no checkpoint at seq-1 to
// start verification from.
var ErrNoBoundary = errors.New("audit: no checkpoint just below the requested range: export from seq 1 or from just after a checkpoint")

// Exporter builds adq-audit-export/1 bundles.
type Exporter struct {
	cp *Checkpointer
}

// NewExporter makes an exporter. Every export ends at a fresh checkpoint, signed first (ADR-0005 rule 11).
func NewExporter(cp *Checkpointer) *Exporter { return &Exporter{cp: cp} }

// Export returns the bundle for from <= seq <= to (0, 0 means the whole chain up to the head), with every
// checkpoint in the range and the one just below it, and the manifest of checkpoint keys. It signs the
// head first, anchoring the checkpoint, and records an audit.exported event with the range and row count.
// Step-up (TM-D16) is the caller's gate.
func (x *Exporter) Export(ctx context.Context, db *store.DB, id tenant.ID, actor authority.Chain, from, to uint64) (chain.Bundle, error) {
	if _, _, err := x.cp.Sign(ctx, db, id); err != nil && !errors.Is(err, ErrAnchor) {
		return chain.Bundle{}, err
	}
	var b chain.Bundle
	err := db.WithTenant(ctx, id, func(ctx context.Context, tx store.Tx) error {
		var head uint64
		if err := tx.QueryRow(ctx, `SELECT seq FROM audit_head WHERE tenant_id = $1::uuid`, id.String()).Scan(&head); err != nil {
			if store.IsNoRows(err) {
				return ErrNoHead
			}
			return fmt.Errorf("audit: read head: %w", err)
		}
		if from == 0 {
			from = 1
		}
		if to == 0 || to > head {
			to = head
		}
		if from > to && head > 0 {
			return fmt.Errorf("audit: empty range %d..%d", from, to)
		}
		b = chain.Bundle{Format: chain.BundleFormat, Tenant: id.String(), FromSeq: from, ToSeq: to}
		rows, err := tx.Query(ctx, `SELECT seq, envelope, prev_hash, hash FROM audit_event WHERE tenant_id = $1::uuid AND seq BETWEEN $2 AND $3 ORDER BY seq`, id.String(), from, to)
		if err != nil {
			return fmt.Errorf("audit: read events: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var ev chain.StoredEvent
			var ph, h []byte
			if err := rows.Scan(&ev.Seq, &ev.Envelope, &ph, &h); err != nil {
				return fmt.Errorf("audit: read event: %w", err)
			}
			copy(ev.PrevHash[:], ph)
			copy(ev.Hash[:], h)
			b.Events = append(b.Events, ev)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("audit: read events: %w", err)
		}
		rows.Close()
		lo := from - 1 // the checkpoint just below the range is where verification starts
		after := uint64(0)
		if lo > 0 {
			after = lo - 1
		}
		cps, err := ListCheckpoints(ctx, tx, id, after, to, 1<<20, false)
		if err != nil {
			return err
		}
		b.Checkpoints = cps
		if from > 1 && (len(cps) == 0 || cps[0].Seq != lo) {
			return ErrNoBoundary
		}
		b.Keys, err = keyManifest(ctx, tx, id)
		if err != nil {
			return err
		}
		return x.cp.chainer.Append(ctx, tx, Event{ID: "audit.exported." + strconv.FormatInt(time.Now().UnixNano(), 36), Kind: KindExported, At: time.Now(),
			Actor: actor, Component: "audit", Outcome: Success,
			Details: []chain.Detail{{Key: "from_seq", Value: strconv.FormatUint(from, 10)}, {Key: "rows", Value: strconv.Itoa(len(b.Events))}, {Key: "to_seq", Value: strconv.FormatUint(to, 10)}}})
	})
	// The bundle names the tenant by UUID text; id.String() is that.
	return b, err
}

// keyManifest lists the checkpoint keys with their windows, read from the chain's own key events.
func keyManifest(ctx context.Context, tx store.Tx, id tenant.ID) ([]chain.KeyInfo, error) {
	out, idx, err := purgedKeyWindows(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT seq, envelope FROM audit_event WHERE tenant_id = $1::uuid AND kind IN ($2, $3) ORDER BY seq`, id.String(), chain.KindKeyCreated, chain.KindKeyRetired)
	if err != nil {
		return nil, fmt.Errorf("audit: read key events: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var seq uint64
		var raw []byte
		if err := rows.Scan(&seq, &raw); err != nil {
			return nil, fmt.Errorf("audit: read key event: %w", err)
		}
		env, err := chain.ParseEnvelope(raw)
		if err != nil {
			return nil, fmt.Errorf("audit: key event %d: %w", seq, err)
		}
		keyID, _ := env.Detail("key_id")
		switch env.Kind {
		case chain.KindKeyCreated:
			pub, _ := env.Detail("public_key")
			raw, err := hex.DecodeString(pub)
			if err != nil {
				return nil, fmt.Errorf("audit: key event %d: %w", seq, err)
			}
			idx[keyID] = len(out)
			out = append(out, chain.KeyInfo{KeyID: keyID, PublicKey: raw, CreatedSeq: seq})
		case chain.KindKeyRetired:
			if i, ok := idx[keyID]; ok {
				out[i].RetiredSeq = seq
			}
		}
	}
	return out, rows.Err()
}

// purgedKeyWindows lists the keys whose introduction was purged, from the windows the newest purge event
// carries (retention.go). The key events still in the chain are added after them.
func purgedKeyWindows(ctx context.Context, tx store.Tx, id tenant.ID) ([]chain.KeyInfo, map[string]int, error) {
	idx := map[string]int{}
	var raw []byte
	err := tx.QueryRow(ctx, `SELECT envelope FROM audit_event WHERE tenant_id = $1::uuid AND kind = $2 ORDER BY seq DESC LIMIT 1`, id.String(), string(KindRetentionPurged)).Scan(&raw)
	if store.IsNoRows(err) {
		return nil, idx, nil
	} else if err != nil {
		return nil, nil, fmt.Errorf("audit: read purge event: %w", err)
	}
	env, err := chain.ParseEnvelope(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("audit: purge event: %w", err)
	}
	var out []chain.KeyInfo
	for _, d := range env.Details {
		rest, ok := strings.CutPrefix(d.Key, keyWindowPrefix)
		if !ok {
			continue
		}
		keyID, field, ok := strings.Cut(rest, ".")
		if !ok {
			continue
		}
		i, seen := idx[keyID]
		if !seen {
			i = len(out)
			idx[keyID] = i
			out = append(out, chain.KeyInfo{KeyID: keyID})
		}
		switch field {
		case "pub":
			pub, err := hex.DecodeString(d.Value)
			if err != nil {
				return nil, nil, fmt.Errorf("audit: purge event key %s: %w", keyID, err)
			}
			out[i].PublicKey = pub
		case "created", "retired":
			n, err := strconv.ParseUint(d.Value, 10, 64)
			if err != nil {
				return nil, nil, fmt.Errorf("audit: purge event key %s: %w", keyID, err)
			}
			if field == "created" {
				out[i].CreatedSeq = n
			} else {
				out[i].RetiredSeq = n
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedSeq < out[j].CreatedSeq })
	idx = map[string]int{}
	for i, k := range out {
		idx[k.KeyID] = i
	}
	return out, idx, nil
}
