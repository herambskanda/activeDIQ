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
	"github.com/skenzeriq/activediq/internal/platform/personal"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// KindRetentionPurged is the event a purge records about itself: the range, the boundary checkpoint and
// the archive digest (ADR-0005 rule 11, "every purge is evidence").
const KindRetentionPurged Kind = "audit.retention.purged"

// Errors of the retention purge.
var (
	// ErrNothingToPurge is returned when no whole, checkpointed partition ends at or before the cutoff.
	ErrNothingToPurge = errors.New("audit: no fully checkpointed partition is old enough to purge")
	// ErrPurgeNeedsArchive is returned when a purge names neither an archive digest nor the
	// purge-without-archive setting.
	ErrPurgeNeedsArchive = errors.New("audit: a purge needs a recorded archive digest, or the tenant's purge_without_archive setting")
	// ErrBadPurgeRequest is returned for a cutoff in the future or a malformed archive digest.
	ErrBadPurgeRequest = errors.New("audit: invalid purge request")
)

// PurgeRequest asks to purge the partitions that ended at or before Before (rounded down to a partition
// start).
type PurgeRequest struct {
	Before time.Time
	// ArchiveDigest is the lowercase hex SHA-256 of the archive export covering the range.
	ArchiveDigest string
	// WithoutArchive states that the tenant's purge_without_archive setting is on. The caller (the
	// retention Action, behind step-up) reads the setting; this package does not store it.
	WithoutArchive bool
	Actor          authority.Chain
}

// PurgeResult describes a completed purge.
type PurgeResult struct {
	FromSeq, ToSeq uint64 // the deleted range; ToSeq is the boundary checkpoint's seq
	Events         int64
	Boundary       chain.Checkpoint
	// PersonalValues and PersonalSubjects count the side-store rows (values, salts) the purge deleted.
	PersonalValues, PersonalSubjects int
	// BlockedByHold is set when a legal hold stopped the purge short (ADR-0005 rule 11, T-0515). Nothing
	// from the blocked partition on was deleted. When no earlier partition qualified, Events is 0 and
	// Boundary is the zero value.
	BlockedByHold *HoldBlock
}

// HoldBlock describes where a legal hold stopped a purge. It names no subject.
type HoldBlock struct {
	// PartitionStart is the start of the oldest partition holding an event that references a held subject.
	PartitionStart time.Time
	// OldestRetainedSeq is the first seq the purge kept: the hold UX shows it (data before it is gone).
	OldestRetainedSeq uint64
	// HeldSubjects counts the held subjects referenced by events in the range the purge would have taken.
	HeldSubjects int
}

// KindRetentionHeld is the event a purge records when a legal hold stopped it: the blocking partition and
// the count of held subjects, never a name.
const KindRetentionHeld Kind = "audit.retention.held"

// HoldAlerter tells the tenant-owner accounts that a hold stopped a purge, so the over-retention of other
// subjects' data in the retained partitions is visible. It runs after the purge's transaction commits and
// carries counts and a time, never a subject. An implementation resolves the owners itself.
type HoldAlerter interface {
	RetentionHeld(ctx context.Context, id tenant.ID, b HoldBlock)
}

// purgedValueIDs lists the personal value IDs referenced by the envelopes of events up to seq.
func purgedValueIDs(ctx context.Context, tx store.Tx, id tenant.ID, upTo uint64) ([][16]byte, error) {
	rows, err := tx.Query(ctx, `SELECT seq, envelope FROM audit_event WHERE tenant_id = $1::uuid AND seq <= $2 ORDER BY seq`, id.String(), upTo)
	if err != nil {
		return nil, fmt.Errorf("audit: read events to purge: %w", err)
	}
	defer rows.Close()
	var ids [][16]byte
	for rows.Next() {
		var seq uint64
		var raw []byte
		if err := rows.Scan(&seq, &raw); err != nil {
			return nil, fmt.Errorf("audit: read event to purge: %w", err)
		}
		env, err := chain.ParseEnvelope(raw)
		if err != nil {
			return nil, fmt.Errorf("audit: event %d: %w", seq, err)
		}
		for _, r := range env.Snapshots {
			ids = append(ids, r.ValueID)
		}
		for _, c := range env.Changes {
			for _, r := range c.Before {
				ids = append(ids, r.ValueID)
			}
			for _, r := range c.After {
				ids = append(ids, r.ValueID)
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: read events to purge: %w", err)
	}
	return ids, nil
}

// Purger deletes whole time partitions below a signed checkpoint. It runs on the maintenance path, with a
// store opened with store.OpenMaintenance as the owner role: the runtime role has no DELETE on audit_event (DM-80.I2).
type Purger struct {
	owner   *store.DB
	chainer *Chainer
	parts   Partitions
	alerter HoldAlerter
}

// WithHoldAlerter sets who is told when a legal hold stops a purge (nil: nobody; the audit event remains).
func (p *Purger) WithHoldAlerter(a HoldAlerter) *Purger {
	p.alerter = a
	return p
}

// WithPartitions sets the partitioning (default Monthly); it must match the checkpointer's.
func (p *Purger) WithPartitions(parts Partitions) *Purger {
	p.parts = parts
	return p
}

// NewPurger makes a purger. owner is a store opened with the owner role's DSN; NewPurger installs the
// chain hook on it, so the purge event is chained in the purge's own transaction.
func NewPurger(owner *store.DB) *Purger {
	return &Purger{owner: owner, chainer: NewChainer(owner), parts: Monthly}
}

// Purge deletes every event up to the newest partition-boundary checkpoint that lies in a partition that
// ended at or before req.Before, and chains audit.retention.purged in the same transaction. Checkpoints
// are never deleted (DM-81.I1); verification of the retained chain starts at the boundary checkpoint.
// It is refused when no partition qualifies: a partition whose last event has no checkpoint is not
// purgeable.
func (p *Purger) Purge(ctx context.Context, id tenant.ID, req PurgeRequest) (PurgeResult, error) {
	digest := req.ArchiveDigest
	switch {
	case digest != "":
		if b, err := hex.DecodeString(digest); err != nil || len(b) != 32 || digest != hex.EncodeToString(b) {
			return PurgeResult{}, fmt.Errorf("%w: archive digest is not a lowercase hex SHA-256", ErrBadPurgeRequest)
		}
	case req.WithoutArchive:
		digest = "none"
	default:
		return PurgeResult{}, ErrPurgeNeedsArchive
	}
	if req.Actor.Validate() != nil {
		return PurgeResult{}, fmt.Errorf("%w: no actor", ErrBadPurgeRequest)
	}
	cutoff := p.parts.Start(req.Before)
	var res PurgeResult
	err := p.owner.WithTenant(ctx, id, func(ctx context.Context, tx store.Tx) error {
		var now time.Time
		if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			return fmt.Errorf("audit: read clock: %w", err)
		}
		if req.Before.After(now) {
			return fmt.Errorf("%w: the cutoff is in the future", ErrBadPurgeRequest)
		}
		first, err := p.firstSeq(ctx, tx, id)
		if err != nil {
			return err
		}
		// The newest checkpoint that sits on the last event of a partition ended by the cutoff.
		toSeq, hash, found, err := p.boundary(ctx, tx, id, cutoff)
		if err != nil {
			return err
		}
		// A legal hold (rule 11, T-0515): the hold rows are locked FOR SHARE first, so a hold set during
		// this purge is either seen here or commits after the purge. The purge is a prefix of the chain, so
		// it stops before the oldest partition holding an event that references a held subject.
		var block *HoldBlock
		if found && toSeq >= first {
			held, err := lockHeldSubjects(ctx, tx, id)
			if err != nil {
				return err
			}
			if len(held) > 0 {
				block, err = p.firstHeldPartition(ctx, tx, id, toSeq, held)
				if err != nil {
					return err
				}
			}
		}
		if block != nil {
			toSeq, hash, found, err = p.boundary(ctx, tx, id, block.PartitionStart)
			if err != nil {
				return err
			}
			block.OldestRetainedSeq = first
			if found && toSeq >= first {
				block.OldestRetainedSeq = toSeq + 1
			}
			res.BlockedByHold = block
			if err := p.chainer.Append(ctx, tx, Event{ID: "audit.retention.held." + strconv.FormatUint(first, 10) + "." + strconv.FormatInt(now.UnixNano(), 10),
				Kind: KindRetentionHeld, At: time.Now(), Actor: req.Actor, Component: "audit", Outcome: Success,
				Details: []chain.Detail{
					{Key: "held_subjects", Value: strconv.Itoa(block.HeldSubjects)},
					{Key: "oldest_retained_seq", Value: strconv.FormatUint(block.OldestRetainedSeq, 10)},
					{Key: "partition_start", Value: block.PartitionStart.UTC().Format(time.RFC3339Nano)},
				}}); err != nil {
				return err
			}
		}
		if !found || toSeq < first {
			if block != nil {
				return nil // nothing before the blocked partition: the held event is the whole result
			}
			return ErrNothingToPurge
		}
		res.ToSeq = toSeq
		cps, err := ListCheckpoints(ctx, tx, id, res.ToSeq-1, res.ToSeq, 1, false)
		if err != nil || len(cps) != 1 || cps[0].Seq != res.ToSeq {
			return fmt.Errorf("audit: read boundary checkpoint: %w", errors.Join(err, ErrNothingToPurge))
		}
		res.Boundary, res.FromSeq = cps[0], first
		windows, err := keyWindowDetails(ctx, tx, id, res.ToSeq)
		if err != nil {
			return err
		}
		// The personal values only these events reference go with them, in this transaction (A9).
		valueIDs, err := purgedValueIDs(ctx, tx, id, res.ToSeq)
		if err != nil {
			return err
		}
		pv, err := personal.New().PurgeValues(ctx, tx, id, valueIDs)
		if err != nil {
			return fmt.Errorf("audit: purge personal values: %w", err)
		}
		res.PersonalValues, res.PersonalSubjects = pv.Values, pv.Subjects
		tag, err := tx.Exec(ctx, `DELETE FROM audit_event WHERE tenant_id = $1::uuid AND seq <= $2`, id.String(), res.ToSeq)
		if err != nil {
			return fmt.Errorf("audit: purge events: %w", err)
		}
		res.Events = tag.RowsAffected()
		// Details in key order: archive_digest, boundary_hash, from_seq, then the key windows ("k." sorts
		// after "f"), rows, to_seq. "k." sorts before "r", so the windows sit between from_seq and rows.
		details := []chain.Detail{
			{Key: "archive_digest", Value: digest},
			{Key: "boundary_hash", Value: hex.EncodeToString(hash)},
			{Key: "from_seq", Value: strconv.FormatUint(res.FromSeq, 10)},
		}
		details = append(details, windows...)
		details = append(details,
			chain.Detail{Key: "rows", Value: strconv.FormatInt(res.Events, 10)},
			chain.Detail{Key: "to_seq", Value: strconv.FormatUint(res.ToSeq, 10)})
		return p.chainer.Append(ctx, tx, Event{ID: "audit.retention.purged." + strconv.FormatUint(res.ToSeq, 10), Kind: KindRetentionPurged, At: time.Now(),
			Actor: req.Actor, Component: "audit", Outcome: Success, Details: details})
	})
	if err != nil {
		return PurgeResult{}, err
	}
	if res.BlockedByHold != nil && p.alerter != nil {
		p.alerter.RetentionHeld(ctx, id, *res.BlockedByHold)
	}
	return res, nil
}

// boundary finds the newest checkpoint that sits on the last event of a partition that ended before cutoff.
func (p *Purger) boundary(ctx context.Context, tx store.Tx, id tenant.ID, cutoff time.Time) (seq uint64, hash []byte, found bool, err error) {
	rows, err := tx.Query(ctx, `SELECT c.seq, c.hash, e.at, n.at
		FROM audit_checkpoint c JOIN audit_event e ON e.tenant_id = c.tenant_id AND e.seq = c.seq AND e.hash = c.hash
		LEFT JOIN audit_event n ON n.tenant_id = c.tenant_id AND n.seq = c.seq + 1
		WHERE c.tenant_id = $1::uuid AND e.at < $2 ORDER BY c.seq DESC`, id.String(), cutoff)
	if err != nil {
		return 0, nil, false, fmt.Errorf("audit: find boundary checkpoint: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var s uint64
		var h []byte
		var at time.Time
		var nextAt *time.Time
		if err := rows.Scan(&s, &h, &at, &nextAt); err != nil {
			return 0, nil, false, fmt.Errorf("audit: read boundary candidate: %w", err)
		}
		// The last event of its partition: nothing follows in the same partition.
		if nextAt == nil || !nextAt.Before(p.parts.End(at)) {
			return s, h, true, nil
		}
	}
	if err := rows.Err(); err != nil {
		return 0, nil, false, fmt.Errorf("audit: find boundary checkpoint: %w", err)
	}
	return 0, nil, false, nil
}

// lockHeldSubjects takes the tenant's hold rows FOR SHARE and returns the held subject refs. A writer that
// sets a hold needs the row exclusively, so it waits for this transaction or has committed before it.
func lockHeldSubjects(ctx context.Context, tx store.Tx, id tenant.ID) (map[string]struct{}, error) {
	rows, err := tx.Query(ctx, `SELECT subject_ref FROM public.personal_subject WHERE tenant_id = $1::uuid AND hold FOR SHARE`, id.String())
	if err != nil {
		return nil, fmt.Errorf("audit: read legal holds: %w", err)
	}
	defer rows.Close()
	held := map[string]struct{}{}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, fmt.Errorf("audit: read legal hold: %w", err)
		}
		held[s] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: read legal holds: %w", err)
	}
	return held, nil
}

// referencedSubjects lists the subjects an envelope is about: the subject of every value ref, and the
// directory object it targets.
func referencedSubjects(env chain.Envelope) []string {
	var out []string
	if s, ok := personal.DirSubject(env.Connection, env.TargetGUID); ok {
		out = append(out, s)
	}
	for _, r := range env.Snapshots {
		out = append(out, r.Subject)
	}
	for _, c := range env.Changes {
		for _, r := range c.Before {
			out = append(out, r.Subject)
		}
		for _, r := range c.After {
			out = append(out, r.Subject)
		}
	}
	return out
}

// firstHeldPartition scans the events up to upTo and returns the oldest partition holding one that
// references a held subject (nil if none), with the count of distinct held subjects seen in the range.
func (p *Purger) firstHeldPartition(ctx context.Context, tx store.Tx, id tenant.ID, upTo uint64, held map[string]struct{}) (*HoldBlock, error) {
	rows, err := tx.Query(ctx, `SELECT seq, at, envelope FROM audit_event WHERE tenant_id = $1::uuid AND seq <= $2 ORDER BY seq`, id.String(), upTo)
	if err != nil {
		return nil, fmt.Errorf("audit: read events for hold check: %w", err)
	}
	defer rows.Close()
	var block *HoldBlock
	seen := map[string]struct{}{}
	for rows.Next() {
		var seq uint64
		var at time.Time
		var raw []byte
		if err := rows.Scan(&seq, &at, &raw); err != nil {
			return nil, fmt.Errorf("audit: read event for hold check: %w", err)
		}
		env, err := chain.ParseEnvelope(raw)
		if err != nil {
			return nil, fmt.Errorf("audit: event %d: %w", seq, err)
		}
		for _, s := range referencedSubjects(env) {
			if _, ok := held[s]; ok {
				seen[s] = struct{}{}
				if block == nil {
					block = &HoldBlock{PartitionStart: p.parts.Start(at)}
				}
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: read events for hold check: %w", err)
	}
	if block != nil {
		block.HeldSubjects = len(seen)
	}
	return block, nil
}

func (p *Purger) firstSeq(ctx context.Context, tx store.Tx, id tenant.ID) (uint64, error) {
	var first *uint64
	if err := tx.QueryRow(ctx, `SELECT min(seq) FROM audit_event WHERE tenant_id = $1::uuid`, id.String()).Scan(&first); err != nil {
		return 0, fmt.Errorf("audit: read first event: %w", err)
	}
	if first == nil {
		return 0, ErrNothingToPurge
	}
	return *first, nil
}

// Key windows survive a purge in the purge event. The export manifest lists keys whose introduction lies
// before the retained range, with the seq of their introduction and retirement; those key events are
// deleted with their partition, so the purge event carries them: "k.<key_id>.created" and
// "k.<key_id>.retired" hold a seq, "k.<key_id>.pub" the hex public key. A purge also carries forward the
// windows of an earlier purge event it deletes.
const keyWindowPrefix = "k."

func keyWindowDetails(ctx context.Context, tx store.Tx, id tenant.ID, upTo uint64) ([]chain.Detail, error) {
	rows, err := tx.Query(ctx, `SELECT seq, envelope FROM audit_event WHERE tenant_id = $1::uuid AND seq <= $2 AND kind IN ($3, $4, $5) ORDER BY seq`,
		id.String(), upTo, chain.KindKeyCreated, chain.KindKeyRetired, string(KindRetentionPurged))
	if err != nil {
		return nil, fmt.Errorf("audit: read key events to purge: %w", err)
	}
	defer rows.Close()
	w := map[string]string{}
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
		switch env.Kind {
		case chain.KindKeyCreated, chain.KindKeyRetired:
			keyID, _ := env.Detail("key_id")
			if env.Kind == chain.KindKeyCreated {
				pub, _ := env.Detail("public_key")
				w[keyWindowPrefix+keyID+".created"], w[keyWindowPrefix+keyID+".pub"] = strconv.FormatUint(seq, 10), pub
			} else {
				w[keyWindowPrefix+keyID+".retired"] = strconv.FormatUint(seq, 10)
			}
		default:
			for _, d := range env.Details {
				if strings.HasPrefix(d.Key, keyWindowPrefix) {
					w[d.Key] = d.Value
				}
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: read key events to purge: %w", err)
	}
	out := make([]chain.Detail, 0, len(w))
	for k, v := range w {
		out = append(out, chain.Detail{Key: k, Value: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}
