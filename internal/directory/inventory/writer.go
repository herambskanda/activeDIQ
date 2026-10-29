package inventory

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/store"
)

// Writer errors. None carries a directory value.
var (
	// ErrConflict: the AD or Entra object already has a live correlation to a different peer (DM-20.I2).
	ErrConflict = errors.New("inventory: the object already has a live correlation to another peer")
	// ErrNotFound: no live correlation or designation to change.
	ErrNotFound = errors.New("inventory: not found")
	// ErrUnknownConnection: the connection is not one of this tenant's.
	ErrUnknownConnection = errors.New("inventory: unknown connection")
)

// Writer writes the DM-20 correlations and DM-16.I8 designations. Every method runs in the caller's
// tenant transaction (the sync ingester's, or an Operation's): row-level security scopes it, and
// every statement names the tenant from the transaction's setting as well. It decides nothing about
// who may call it: the permission, the step-up and the audit event belong to the Operation that does.
type Writer struct{}

func requireTenant(ctx context.Context, tx store.Tx) error {
	var ok bool
	if err := tx.QueryRow(ctx, `SELECT NULLIF(current_setting('app.tenant_id', true), '') IS NOT NULL`).Scan(&ok); err != nil {
		return fmt.Errorf("inventory: tenant context: %w", err)
	}
	if !ok {
		return ErrNoTenant
	}
	return nil
}

// Formation is one observed (AD object, Entra object) pair for the gate to judge and the writer to store.
type Formation struct {
	AD, Entra Ref
	Match     Match
	// AnchorAttr and AnchorValue are required when Match is anchor (opaque bytes, never converted).
	AnchorAttr  string
	AnchorValue []byte
	// Gate is the input to Evaluate; the writer fills Gate.Prior from the stored correlation, and
	// Gate.ADSID is stored as the SID evidence.
	Gate GateInput
	// ADBases and EntraBases are the tier0 bases the classifiers computed for each side (empty: not
	// tier0). FactsAsOf is the inventory as-of of those facts and is always required: "not tier0" is
	// a fact with a time too (contract §8.3 F3), and a link without it would force every write that
	// relies on it to refuse or live-refresh.
	ADBases, EntraBases []Basis
	FactsAsOf           time.Time
	Now                 time.Time
}

// Formed is the outcome of Form.
type Formed struct {
	ID      string
	Created bool
	Verdict Verdict
}

type stored struct {
	id       string
	state    State
	live     bool
	since    *time.Time
	class    string
	reconfBy *string
	reconfAt *time.Time
}

// Form evaluates the DM-20.I4 gate for the pair and stores the result: it inserts a new correlation,
// or updates the live one. A removed correlation of the same two objects is not revived; a new row
// inherits its I4(g) markers. The I4(g) markers are set once, in SQL too.
func (Writer) Form(ctx context.Context, tx store.Tx, f Formation) (Formed, error) {
	if !f.AD.Valid() || !f.Entra.Valid() || f.AD.Connection == f.Entra.Connection {
		return Formed{}, ErrInvalid
	}
	switch f.Match {
	case MatchAnchor:
		if f.AnchorAttr == "" || len(f.AnchorAttr) > 100 || len(f.AnchorValue) == 0 || len(f.AnchorValue) > 1024 {
			return Formed{}, ErrInvalid
		}
	case MatchSID:
		if len(f.Gate.ADSID) < 8 {
			return Formed{}, ErrInvalid
		}
		f.AnchorAttr, f.AnchorValue = "", nil
	default:
		return Formed{}, ErrInvalid
	}
	if f.FactsAsOf.IsZero() {
		return Formed{}, fmt.Errorf("%w: tier0 status (true or false) needs an as-of time", ErrInvalid)
	}
	if f.Now.IsZero() {
		return Formed{}, ErrInvalid
	}
	if err := requireTenant(ctx, tx); err != nil {
		return Formed{}, err
	}

	var p stored
	err := tx.QueryRow(ctx, `SELECT id::text, state, state <> 'removed', eligible_since, eligibility_class, reconfirmed_by::text, reconfirmed_at
		FROM public.correlations
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
		AND ad_connection_id = $1::uuid AND ad_object_guid = $2::uuid AND entra_connection_id = $3::uuid AND entra_object_guid = $4::uuid
		ORDER BY (state <> 'removed') DESC, updated_at DESC LIMIT 1 FOR UPDATE`,
		string(f.AD.Connection), string(f.AD.Object), string(f.Entra.Connection), string(f.Entra.Object)).
		Scan(&p.id, &p.state, &p.live, &p.since, &p.class, &p.reconfBy, &p.reconfAt)
	found := err == nil
	if err != nil && !store.IsNoRows(err) {
		return Formed{}, fmt.Errorf("inventory: read correlation: %w", err)
	}
	g := f.Gate
	g.Prior = nil
	if found {
		g.Prior = &Prior{State: p.state, EligibilityClass: p.class, EligibleSince: val(p.since), ReconfirmedAt: val(p.reconfAt)}
	}
	v := Evaluate(g, f.Now)

	var since *time.Time
	if !v.EligibleSince.IsZero() {
		t := v.EligibleSince
		since = &t
	}
	var asOf *time.Time
	if !f.FactsAsOf.IsZero() {
		t := f.FactsAsOf.UTC()
		asOf = &t
	}
	adB, enB := basisStrings(f.ADBases), basisStrings(f.EntraBases)
	var sid []byte
	if len(g.ADSID) > 0 {
		sid = g.ADSID
	}
	var anchor []byte
	if f.Match == MatchAnchor {
		anchor = f.AnchorValue
	}

	if found && p.live {
		_, err = tx.Exec(ctx, `UPDATE public.correlations SET match = $2, anchor_attr = $3, anchor_value = $4, ad_sid = $5,
			state = $6, candidate_reason = $7, gate_checked_at = $8,
			eligible_since = COALESCE(eligible_since, $9::timestamptz), eligibility_class = COALESCE(NULLIF(eligibility_class, ''), $10),
			ad_tier0 = $11, ad_tier0_bases = $12, entra_tier0 = $13, entra_tier0_bases = $14, facts_as_of = $15,
			ad_facts_as_of = NULL, entra_facts_as_of = NULL, updated_at = now()
			WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND id = $1::uuid`,
			p.id, string(f.Match), f.AnchorAttr, anchor, sid, string(v.State), string(v.Reason), f.Now.UTC(),
			since, v.EligibilityClass, len(adB) > 0, adB, len(enB) > 0, enB, asOf)
		if err != nil {
			return Formed{}, writeErr("update correlation", err)
		}
		return Formed{ID: p.id, Verdict: v}, nil
	}
	var id string
	err = tx.QueryRow(ctx, `INSERT INTO public.correlations (tenant_id, ad_connection_id, ad_object_guid, entra_connection_id, entra_object_guid,
			match, anchor_attr, anchor_value, ad_sid, state, candidate_reason, gate_checked_at, eligible_since, eligibility_class,
			reconfirmed_by, reconfirmed_at, ad_tier0, ad_tier0_bases, entra_tier0, entra_tier0_bases, facts_as_of)
		VALUES (NULLIF(current_setting('app.tenant_id', true), '')::uuid, $1::uuid, $2::uuid, $3::uuid, $4::uuid,
			$5, $6, $7, $8, $9, $10, $11, $12::timestamptz, $13, $14::uuid, $15, $16, $17, $18, $19, $20)
		RETURNING id::text`,
		string(f.AD.Connection), string(f.AD.Object), string(f.Entra.Connection), string(f.Entra.Object),
		string(f.Match), f.AnchorAttr, anchor, sid, string(v.State), string(v.Reason), f.Now.UTC(), since, v.EligibilityClass,
		p.reconfBy, p.reconfAt, len(adB) > 0, adB, len(enB) > 0, enB, asOf).Scan(&id)
	if err != nil {
		return Formed{}, writeErr("insert correlation", err)
	}
	return Formed{ID: id, Created: true, Verdict: v}, nil
}

func basisStrings(bs []Basis) []string {
	out := make([]string, len(bs))
	for i, b := range bs {
		out[i] = string(b)
	}
	return out
}

func writeErr(what string, err error) error {
	switch store.SQLState(err) {
	case "23505":
		return ErrConflict
	case "23503":
		return ErrUnknownConnection
	case "23514", "22P02", "23502":
		return fmt.Errorf("%w: %s", ErrInvalid, what)
	}
	return fmt.Errorf("inventory: %s: %w", what, err)
}

// RecordEvaluation records that the correlation job evaluated every object of the connection from
// inventory as of at (contract §8.3 F3). at is the as-of of the OLDEST input the run read, usually
// the start of the run, never its completion time: a completion time overstates freshness by the
// length of the run.
//
// It only moves forward, and it refuses a stale run: if a run with a later as-of has already been
// recorded it returns ErrStale, and the caller must roll back the transaction so this run's Form and
// Remove calls do not land (otherwise an old run could delete a link a newer run formed while the
// newer time stays recorded). at later than the database's now() plus five minutes (F3's clock-skew allowance; the time is forward-only and undeletable, so a future
// value would make every "no peers" answer look fresh for good) is ErrInvalid.
//
// To serialise concurrent runs of one connection, call RecordEvaluation FIRST in the run's
// transaction: the upsert takes the connection's row lock, held until commit, so a competing run
// waits and then sees the newer time. The reader sees the new time and the run's links together
// because both commit in that one transaction.
func (Writer) RecordEvaluation(ctx context.Context, tx store.Tx, connection ConnectionID, at time.Time) error {
	if _, ok := canon(string(connection)); !ok || at.IsZero() {
		return ErrInvalid
	}
	if err := requireTenant(ctx, tx); err != nil {
		return err
	}
	var future bool
	if err := tx.QueryRow(ctx, `SELECT $1::timestamptz > now() + interval '5 minutes'`, at.UTC()).Scan(&future); err != nil {
		return writeErr("record evaluation", err)
	}
	if future {
		return fmt.Errorf("%w: evaluation as-of is in the future", ErrInvalid)
	}
	tag, err := tx.Exec(ctx, `INSERT INTO public.correlation_evaluations (tenant_id, connection_id, evaluated_at)
		VALUES (NULLIF(current_setting('app.tenant_id', true), '')::uuid, $1::uuid, $2)
		ON CONFLICT (tenant_id, connection_id) DO UPDATE SET evaluated_at = EXCLUDED.evaluated_at
		WHERE EXCLUDED.evaluated_at >= public.correlation_evaluations.evaluated_at`,
		string(connection), at.UTC())
	if err != nil {
		return writeErr("record evaluation", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrStale
	}
	return nil
}

// Remove sets the live correlation of the pair to removed. Nothing is deleted: its I4(g) markers are
// inherited if the pair is formed again.
func (Writer) Remove(ctx context.Context, tx store.Tx, ad, entra Ref) error {
	if !ad.Valid() || !entra.Valid() {
		return ErrInvalid
	}
	if err := requireTenant(ctx, tx); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE public.correlations SET state = 'removed', candidate_reason = '', updated_at = now()
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND state <> 'removed'
		AND ad_connection_id = $1::uuid AND ad_object_guid = $2::uuid AND entra_connection_id = $3::uuid AND entra_object_guid = $4::uuid`,
		string(ad.Connection), string(ad.Object), string(entra.Connection), string(entra.Object))
	if err != nil {
		return writeErr("remove correlation", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Designate records object as a customer tier0 designation of the connection (DM-16.I8). It reports
// whether anything changed: designating a live designation is a no-op. A previously removed
// designation is re-activated in place and its removal markers cleared. by is the requesting
// principal's ID.
func (Writer) Designate(ctx context.Context, tx store.Tx, connection ConnectionID, object GUID, by string) (changed bool, err error) {
	if !(Ref{connection, object}).Valid() || by == "" {
		return false, ErrInvalid
	}
	if err := requireTenant(ctx, tx); err != nil {
		return false, err
	}
	tag, err := tx.Exec(ctx, `INSERT INTO public.tier0_designations (tenant_id, connection_id, object_guid, designated_by)
		VALUES (NULLIF(current_setting('app.tenant_id', true), '')::uuid, $1::uuid, $2::uuid, $3)
		ON CONFLICT (tenant_id, connection_id, object_guid) DO UPDATE
		SET designated_by = EXCLUDED.designated_by, designated_at = now(), removed_at = NULL, removed_by = NULL
		WHERE public.tier0_designations.removed_at IS NOT NULL`, string(connection), string(object), by)
	if err != nil {
		return false, writeErr("designate", err)
	}
	return tag.RowsAffected() > 0, nil
}

// Undesignate soft-deletes the live designation (removed_at, removed_by): the row stays, and the
// runtime role cannot DELETE it. ErrNotFound if the object is not designated.
func (Writer) Undesignate(ctx context.Context, tx store.Tx, connection ConnectionID, object GUID, by string) error {
	if !(Ref{connection, object}).Valid() || by == "" {
		return ErrInvalid
	}
	if err := requireTenant(ctx, tx); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE public.tier0_designations SET removed_at = now(), removed_by = $3
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND connection_id = $1::uuid AND object_guid = $2::uuid
		AND removed_at IS NULL`, string(connection), string(object), by)
	if err != nil {
		return writeErr("undesignate", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// IsDesignated reports whether object is a live designation (the Operation's Verify reads it).
func (Writer) IsDesignated(ctx context.Context, tx store.Tx, connection ConnectionID, object GUID) (bool, error) {
	if !(Ref{connection, object}).Valid() {
		return false, ErrInvalid
	}
	if err := requireTenant(ctx, tx); err != nil {
		return false, err
	}
	var ok bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM public.tier0_designations
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND connection_id = $1::uuid AND object_guid = $2::uuid AND removed_at IS NULL)`,
		string(connection), string(object)).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("inventory: designated: %w", err)
	}
	return ok, nil
}

// SetMember records or refreshes the DM-17 member edge group → member as active (the sync ingester's
// write, in the same transaction as the rest of the cycle). RemoveMember marks it removed.
func (Writer) SetMember(ctx context.Context, tx store.Tx, connection ConnectionID, group, member GUID, observed time.Time) error {
	return setEdge(ctx, tx, "member", connection, group, member, observed)
}

// RemoveMember marks the member edge removed.
func (Writer) RemoveMember(ctx context.Context, tx store.Tx, connection ConnectionID, group, member GUID, observed time.Time) error {
	return removeEdge(ctx, tx, "member", connection, group, member, observed)
}

// SetPrimaryGroup records the DM-17.I2 primary-group edge group → user (the user's primaryGroupID
// resolved to the group): a membership that has no member value, which the GroupSource must follow
// or a designated group's primary-group members lose Tier-0 protection. RemovePrimaryGroup marks it removed.
func (Writer) SetPrimaryGroup(ctx context.Context, tx store.Tx, connection ConnectionID, group, user GUID, observed time.Time) error {
	return setEdge(ctx, tx, "primary_group", connection, group, user, observed)
}

// RemovePrimaryGroup marks the primary-group edge removed.
func (Writer) RemovePrimaryGroup(ctx context.Context, tx store.Tx, connection ConnectionID, group, user GUID, observed time.Time) error {
	return removeEdge(ctx, tx, "primary_group", connection, group, user, observed)
}

// setEdge's attr is one of the two constants above, passed as a bind parameter.
func setEdge(ctx context.Context, tx store.Tx, attr string, connection ConnectionID, group, member GUID, observed time.Time) error {
	if !(Ref{connection, group}).Valid() || !(Ref{connection, member}).Valid() || observed.IsZero() {
		return ErrInvalid
	}
	if err := requireTenant(ctx, tx); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `INSERT INTO public.links (tenant_id, connection_id, source_guid, link_attr, target_guid, state, observed_at)
		VALUES (NULLIF(current_setting('app.tenant_id', true), '')::uuid, $1::uuid, $2::uuid, $5, $3::uuid, 'active', $4)
		ON CONFLICT (tenant_id, connection_id, source_guid, link_attr, target_guid) DO UPDATE SET state = 'active', observed_at = EXCLUDED.observed_at`,
		string(connection), string(group), string(member), observed.UTC(), attr)
	if err != nil {
		return writeErr("set "+attr, err)
	}
	return nil
}

func removeEdge(ctx context.Context, tx store.Tx, attr string, connection ConnectionID, group, member GUID, observed time.Time) error {
	if !(Ref{connection, group}).Valid() || !(Ref{connection, member}).Valid() || observed.IsZero() {
		return ErrInvalid
	}
	if err := requireTenant(ctx, tx); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE public.links SET state = 'removed', observed_at = $4
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND connection_id = $1::uuid
		AND source_guid = $2::uuid AND link_attr = $5 AND target_guid = $3::uuid`,
		string(connection), string(group), string(member), observed.UTC(), attr)
	if err != nil {
		return writeErr("remove "+attr, err)
	}
	return nil
}

// ErrBasisUnknown: a live read says the object is tier0 but the stored correlation names no basis for
// it, and a live read yields a verdict, not a basis (the flag and the bases agree exactly). The
// correlation job names the basis; until it has, the fact is not advanced.
var ErrBasisUnknown = errors.New("inventory: live read found the object tier0 with no recorded basis")

// RecordLiveFacts stores the tier0 verdict of a live read of ref, taken at readAt, on every live
// correlation ref is a side of (DM-20.I5; contract §8.3 F3), and moves that side's as-of
// (ad_facts_as_of / entra_facts_as_of) to readAt if that is later. It returns how many correlations it updated (zero is valid: ref has none).
//
// Only ref's own side changes, and only the tier0 fact of it: the peer's fact, the gate verdict, the
// state and gate_checked_at are not touched, because a read of one object cannot vouch for them. The
// as-of of the pair (Link.FactsAsOf) is the older of the two sides' as-ofs, so it moves only once the
// peer's side has been refreshed too. A verdict of not-tier0 clears
// the bases. A verdict of tier0 keeps the stored bases; with none stored it is ErrBasisUnknown and
// nothing is written. The time never moves back, and one later than the database's now() plus five
// minutes is ErrInvalid. Runs in the caller's tenant transaction; the caller rolls back on error.
func (Writer) RecordLiveFacts(ctx context.Context, tx store.Tx, ref Ref, tier0 bool, readAt time.Time) (int, error) {
	if !ref.Valid() || readAt.IsZero() {
		return 0, ErrInvalid
	}
	if err := requireTenant(ctx, tx); err != nil {
		return 0, err
	}
	var future bool
	if err := tx.QueryRow(ctx, `SELECT $1::timestamptz > now() + interval '5 minutes'`, readAt.UTC()).Scan(&future); err != nil {
		return 0, writeErr("record live facts", err)
	}
	if future {
		return 0, fmt.Errorf("%w: read time is in the future", ErrInvalid)
	}
	n := 0
	for _, q := range []struct{ update, missing string }{
		{`UPDATE public.correlations SET ad_tier0 = $3, ad_tier0_bases = CASE WHEN $3 THEN ad_tier0_bases ELSE '{}' END,
			ad_facts_as_of = GREATEST(COALESCE(ad_facts_as_of, facts_as_of, $4), $4), updated_at = now()
			WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
			AND ad_connection_id = $1::uuid AND ad_object_guid = $2::uuid AND state <> 'removed'
			AND (NOT $3 OR cardinality(ad_tier0_bases) > 0)`,
			`SELECT count(*) FROM public.correlations
			WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
			AND ad_connection_id = $1::uuid AND ad_object_guid = $2::uuid AND state <> 'removed' AND cardinality(ad_tier0_bases) = 0`},
		{`UPDATE public.correlations SET entra_tier0 = $3, entra_tier0_bases = CASE WHEN $3 THEN entra_tier0_bases ELSE '{}' END,
			entra_facts_as_of = GREATEST(COALESCE(entra_facts_as_of, facts_as_of, $4), $4), updated_at = now()
			WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
			AND entra_connection_id = $1::uuid AND entra_object_guid = $2::uuid AND state <> 'removed'
			AND (NOT $3 OR cardinality(entra_tier0_bases) > 0)`,
			`SELECT count(*) FROM public.correlations
			WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
			AND entra_connection_id = $1::uuid AND entra_object_guid = $2::uuid AND state <> 'removed' AND cardinality(entra_tier0_bases) = 0`},
	} {
		if tier0 { // checked first so that nothing is written when a basis is missing
			var missing int
			if err := tx.QueryRow(ctx, q.missing, string(ref.Connection), string(ref.Object)).Scan(&missing); err != nil {
				return 0, writeErr("record live facts", err)
			}
			if missing > 0 {
				return 0, ErrBasisUnknown
			}
		}
		tag, err := tx.Exec(ctx, q.update, string(ref.Connection), string(ref.Object), tier0, readAt.UTC())
		if err != nil {
			return 0, writeErr("record live facts", err)
		}
		n += int(tag.RowsAffected())
	}
	return n, nil
}
