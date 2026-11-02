package inventory

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/platform/store"
)

// Opt is a value a patch sets or leaves alone. The zero Opt leaves the stored value alone; Some(zero value)
// sets it to "absent" (a cleared attribute: an empty string, a NULL time, a nil pointer).
type Opt[T any] struct {
	Set   bool
	Value T
}

// Some is an Opt that sets v.
func Some[T any](v T) Opt[T] { return Opt[T]{Set: true, Value: v} }

// ClassKind is an object's most specific structural class and the kind derived from it.
type ClassKind struct {
	Class string
	Kind  Kind
}

// Patch is what one DirSync ObjectChange says about one object, as a patch (contract §6.4, DM-18.I2): only the
// fields it sets are written, and every other column and attribute of the stored row is left as it is. A
// change to displayName changes display_name, observed_at and nothing else.
//
// A time input that is set (LockoutTime, PwdLastSet, AccountExpires, LastLogonTimestamp) also sets its
// InputsRead bit: the feed said what the attribute is now, so a zero value is "absent and read" (not locked,
// must change, never, never logged on), which is told from "not read".
type Patch struct {
	Object GUID
	// NC is the naming context of the feed partition the change came from. It is the row's nc_guid.
	NC GUID
	// Create is the whole observation to store when inventory has no row for Object (the object was created
	// and modified between two polls). It is built only from a change that carries everything a row needs; a
	// patch without it, for an object inventory has never seen, is reported in Patched.NeedsRead and stores
	// nothing: a half object is never stored. Create is ignored when the row exists.
	Create *Observation

	State Opt[ObjectState]
	Class Opt[ClassKind]
	// DN and RDN are display snapshots (DM-16.I2).
	DN, RDN Opt[string]
	// Parent is the parent's GUID, "" for none. The chain (ancestry and ancestry_complete) is derived from the
	// stored parent row, here and again whenever the parent is written, never taken from the producer, so the
	// result does not depend on the order in which a parent and its children arrive.
	Parent Opt[GUID]

	SAMAccountName, UPN, DisplayName Opt[string]
	// SID and ConsistencyGUID: an empty value clears.
	SID, ConsistencyGUID     Opt[[]byte]
	WhenCreated, WhenChanged Opt[time.Time]

	// UserAccountControl nil clears it (and enabled). Enabled follows from the ACCOUNTDISABLE bit.
	UserAccountControl Opt[*int64]
	PrimaryGroupID     Opt[*int64]
	HasSPN             Opt[*bool]
	// GroupType nil clears the stored judge input.
	GroupType Opt[*int32]

	LockoutTime, PwdLastSet, AccountExpires, LastLogonTimestamp Opt[time.Time]

	// Attributes are generic bag keys to set, ClearAttributes keys to remove; every other key is kept. A judge key
	// (GroupType has its own field) or a secret name in either is refused.
	Attributes      map[string]any
	ClearAttributes []string

	// Members are member edges to add, RemovedMembers edges to remove: only those edges change. MembersComplete says
	// Members is the whole current set (a SET of member, or CLEARED with none): edges not named are removed.
	Members, RemovedMembers []GUID
	MembersComplete         bool

	// Reread says the change touched the group's membership in a way the patch cannot carry: a removal (or a
	// whole set) with a value that names no GUID. The patch is applied as far as it goes, then the group's active
	// member edges are ended and the object is reported in Patched.NeedsRead. An edge that should have been
	// removed must never stay active (the edges are an authorization input), so the group grants nothing until a
	// full read names its members again; an unresolved add needs no such care (it under-grants).
	Reread bool
	// Refused says the mapper could not map the change at all. The patch then names only Object and NC, nothing
	// is written to the row, and the object is reported in NeedsRead with the effect of Reread: the change is
	// consumed with its cookie, so what it carried (a removal, a disable) is lost unless the object is read.
	Refused bool
}

// PatchCycle is one batch of patches of one AD connection, as of one instant.
type PatchCycle struct {
	Connection  ConnectionID
	Observed    time.Time
	ObservedDSA string
	Patches     []Patch
	Now         time.Time
	// MoreBatches and PassNCs are as in Cycle.
	MoreBatches bool
	PassNCs     []GUID
}

// Patched is the outcome of ApplyPatches.
type Patched struct {
	Updated, Created int
	// Stale counts patches older than the stored row; they are ignored.
	Stale int
	// Refused counts patches skipped because they carry group fields for an object that is not a group.
	Refused int
	// NeedsRead lists the objects the caller must read by GUID (a ScopedSearch) and ingest in full: those the
	// inventory has never seen whose change did not carry enough to build a row, and those whose change was
	// refused or whose membership change could not be applied in full (Patch.Reread, Patch.Refused). A stored
	// group in the second kind has its member edges ended until that read lands. Sorted, without duplicates.
	NeedsRead []GUID
	// EdgesRemoved counts member and primary-group edges removed because an end of them is no longer live.
	EdgesRemoved int
	Ingested     Ingested
}

// ApplyPatches applies a batch of patches (see Patch) and then runs the closure refresh and, on the last batch,
// the pass records and the hybrid gate, all in the caller's tenant transaction. It is Populate's patch mode, not a
// second writer: it takes the same per-connection lock, stores through Populate when it creates a row, derives
// the chain with the same completeness rule, and keeps the search index, the member edges and the closure in
// step in the same transaction.
//
// The result does not depend on the order of the patches (CC-FEED-16), nor on which of two parents arrives
// first, and applying the same batch again changes nothing (an edge or a column set to what it already is). A
// batch that names an object twice is ErrInvalid: the caller applies the second change after the first.
func (g Ingester) ApplyPatches(ctx context.Context, tx store.Tx, c PatchCycle) (Patched, error) {
	var out Patched
	if g.Classifier == nil {
		return out, ErrNoClassifier
	}
	if !(Ref{c.Connection, "aaaaaaaa-0000-4000-8000-000000000000"}).Valid() || c.Observed.IsZero() || c.Now.IsZero() {
		return out, ErrInvalid
	}
	out, err := g.Populator.applyPatches(ctx, tx, c)
	if err != nil {
		return out, err
	}
	out.Ingested, err = g.Ingest(ctx, tx, Cycle{Connection: c.Connection, Observed: c.Observed, Now: c.Now, MoreBatches: c.MoreBatches, PassNCs: c.PassNCs})
	return out, err
}

type patchRow struct {
	kind     Kind
	state    ObjectState
	observed time.Time
}

func (p Populator) applyPatches(ctx context.Context, tx store.Tx, c PatchCycle) (Patched, error) {
	var out Patched
	if len(c.Patches) > maxObjects {
		return out, ErrTooMany
	}
	if err := requireTenant(ctx, tx); err != nil {
		return out, err
	}
	if err := lockConnection(ctx, tx, c.Connection); err != nil {
		return out, err
	}
	var ck string
	if err := tx.QueryRow(ctx, `SELECT kind FROM public.connections
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND id = $1::uuid`, string(c.Connection)).Scan(&ck); err != nil {
		if store.IsNoRows(err) {
			return out, ErrUnknownConnection
		}
		return out, fmt.Errorf("inventory: connection kind: %w", err)
	}
	if ck != connKindADForest {
		return out, ErrInvalid // the feed patch is DirSync's; Graph delta has its own mapping
	}
	var future bool
	if err := tx.QueryRow(ctx, `SELECT $1::timestamptz > now() + $2::interval`, c.Observed.UTC(), fmt.Sprintf("%d seconds", int(clockSkewAllowance.Seconds()))).Scan(&future); err != nil {
		return out, writeErr("patch as-of", err)
	}
	if future || len(c.ObservedDSA) > 256 || strings.ContainsRune(c.ObservedDSA, 0) {
		return out, fmt.Errorf("%w: patch as-of is in the future or the DSA is malformed", ErrInvalid)
	}
	seen := make(map[GUID]bool, len(c.Patches))
	for i := range c.Patches {
		if err := c.Patches[i].validate(); err != nil {
			return out, err
		}
		if seen[c.Patches[i].Object] {
			return out, fmt.Errorf("%w: patch batch names an object twice", ErrInvalid)
		}
		seen[c.Patches[i].Object] = true
	}
	if len(c.Patches) == 0 {
		return out, nil
	}

	// What inventory holds of these objects now.
	ids := make([]string, len(c.Patches))
	for i := range c.Patches {
		ids[i] = string(c.Patches[i].Object)
	}
	held, err := patchRows(ctx, tx, c.Connection, ids)
	if err != nil {
		return out, err
	}

	var creates []Observation
	var updates []*Patch
	var touched []GUID  // objects whose row this call wrote
	var distrust []GUID // stored groups whose member edges are ended: their membership cannot be trusted
	for i := range c.Patches {
		pt := &c.Patches[i]
		row, ok := held[pt.Object]
		switch {
		case pt.Refused:
			// Nothing of the change is applied. A row newer than the as-of already reflects whatever it said.
			switch {
			case ok && row.observed.After(c.Observed):
				out.Stale++
			default:
				out.Refused++
				out.NeedsRead = append(out.NeedsRead, pt.Object)
				if ok && row.kind == KindGroup {
					distrust = append(distrust, pt.Object)
				}
			}
			continue
		case !ok && pt.Create != nil:
			o := *pt.Create
			o.ObservedDSA = c.ObservedDSA
			creates = append(creates, o)
		case !ok:
			out.NeedsRead = append(out.NeedsRead, pt.Object)
		case row.observed.After(c.Observed):
			out.Stale++
		default:
			kind := row.kind
			if pt.Class.Set {
				kind = pt.Class.Value.Kind
			}
			if kind != KindGroup && (pt.GroupType.Set || len(pt.Members) > 0 || len(pt.RemovedMembers) > 0 || pt.MembersComplete) {
				// A directory that sends member or groupType for a non-group is odd, not fatal to the batch. The
				// change is consumed all the same, so the object is read rather than trusted.
				out.Refused++
				out.NeedsRead = append(out.NeedsRead, pt.Object)
				if row.kind == KindGroup {
					distrust = append(distrust, pt.Object)
				}
				continue
			}
			if pt.Reread {
				out.NeedsRead = append(out.NeedsRead, pt.Object)
				distrust = append(distrust, pt.Object)
			}
			updates = append(updates, pt)
		}
	}
	sort.Slice(out.NeedsRead, func(i, j int) bool { return out.NeedsRead[i] < out.NeedsRead[j] })
	out.NeedsRead = slices.Compact(out.NeedsRead)

	// New rows first, through Populate: it stores the row, its member edges and its search keys.
	if len(creates) > 0 {
		res, err := p.Populate(ctx, tx, c.Connection, c.Observed, creates)
		if err != nil {
			return out, err
		}
		out.Created = res.Inserted
		out.Stale += res.Stale
		for i := range creates {
			touched = append(touched, creates[i].Object)
		}
	}
	for _, pt := range updates {
		n, err := pt.write(ctx, tx, c.Connection, c.Observed, c.ObservedDSA)
		if err != nil {
			return out, err
		}
		if n == 0 {
			out.Stale++ // raced past the as-of check; ignored like any stale observation
			continue
		}
		out.Updated++
		touched = append(touched, pt.Object)
	}

	// The chain of every row written, and of every row below one whose chain changed.
	for _, o := range touched {
		if err := settleChain(ctx, tx, c.Connection, o); err != nil {
			return out, err
		}
	}

	// Edges. The group of an update is marked dirty by the edge writers; a group whose own row changed is a
	// closure root to recompute.
	var counterparts []string
	for _, pt := range updates {
		if len(pt.Members)+len(pt.RemovedMembers) == 0 && !pt.MembersComplete {
			continue
		}
		for _, m := range pt.Members {
			if err := p.SetMember(ctx, tx, c.Connection, pt.Object, m, c.Observed); err != nil {
				return out, err
			}
			counterparts = append(counterparts, string(m))
		}
		for _, m := range pt.RemovedMembers {
			if err := p.RemoveMember(ctx, tx, c.Connection, pt.Object, m, c.Observed); err != nil {
				return out, err
			}
		}
		if pt.MembersComplete {
			if err := p.removeUnseen(ctx, tx, "member", c.Connection, pt.Object, c.Observed); err != nil {
				return out, err
			}
		}
	}
	// A group whose change could not be applied in full grants nothing until it is read (Patch.Reread): its
	// edges go last, so the adds of the same patch are ended too and come back with the read.
	for _, g := range distrust {
		if err := p.endActiveEdges(ctx, tx, "member", c.Connection, g, c.Observed, true); err != nil {
			return out, err
		}
	}
	for _, o := range creates {
		for _, m := range o.Members {
			counterparts = append(counterparts, string(m))
		}
	}
	if len(touched) > 0 {
		if err := markGroupsDirty(ctx, tx, c.Connection, touched); err != nil {
			return out, err
		}
		if err := p.followPrimaryGroups(ctx, tx, c.Connection, touched, c.Observed); err != nil {
			return out, err
		}
		if err := rewriteKeysOf(ctx, tx, c.Connection, touched); err != nil {
			return out, err
		}
	}

	// An edge never stays active at an end that is deleted, recycled or purged, whichever of the two writes came
	// first. The candidates are the objects of this batch and the other ends of the edges it wrote.
	cands := make([]string, 0, len(touched)+len(counterparts))
	for _, o := range touched {
		cands = append(cands, string(o))
	}
	cands = append(cands, counterparts...)
	dead, err := deadAmong(ctx, tx, c.Connection, cands)
	if err != nil {
		return out, err
	}
	for _, ch := range chunks(dead, reconcileChunk) {
		var n int
		if err := tx.QueryRow(ctx, removeEdgesSQL, string(c.Connection), ch, c.Observed.UTC()).Scan(&n); err != nil {
			return out, writeErr("remove edges of dead objects", err)
		}
		out.EdgesRemoved += n
	}
	if _, err := p.RefreshClosure(ctx, tx, c.Connection); err != nil {
		return out, err
	}
	return out, nil
}

func patchRows(ctx context.Context, tx store.Tx, connection ConnectionID, ids []string) (map[GUID]patchRow, error) {
	rows, err := tx.Query(ctx, `SELECT object_guid::text, kind, state, observed_at FROM public.directory_objects
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND connection_id = $1::uuid AND object_guid = ANY($2::uuid[])`,
		string(connection), ids)
	if err != nil {
		return nil, writeErr("read patched objects", err)
	}
	defer rows.Close()
	out := make(map[GUID]patchRow, len(ids))
	for rows.Next() {
		var g, k, s string
		var r patchRow
		if err := rows.Scan(&g, &k, &s, &r.observed); err != nil {
			return nil, writeErr("read patched objects", err)
		}
		r.kind, r.state = Kind(k), ObjectState(s)
		out[GUID(g)] = r
	}
	if err := rows.Err(); err != nil {
		return nil, writeErr("read patched objects", err)
	}
	return out, nil
}

// validate checks the patch before anything is written. The bounds are Populate's.
func (pt *Patch) validate() error {
	bad := func(why string) error { return fmt.Errorf("%w: patch: %s", ErrInvalid, why) }
	if !validGUID(pt.Object) || !validGUID(pt.NC) {
		return bad("object or naming context guid")
	}
	if pt.State.Set && pt.State.Value != ObjLive && pt.State.Value != ObjDeleted && pt.State.Value != ObjRecycled {
		return bad("state")
	}
	if pt.Class.Set && (!validKinds[pt.Class.Value.Kind] || pt.Class.Value.Class == "" || len(pt.Class.Value.Class) > 100) {
		return bad("kind or class")
	}
	if pt.Parent.Set && pt.Parent.Value != "" && (!validGUID(pt.Parent.Value) || pt.Parent.Value == pt.Object) {
		return bad("parent")
	}
	if pt.SID.Set && len(pt.SID.Value) != 0 && (len(pt.SID.Value) < 8 || len(pt.SID.Value) > 68) {
		return bad("sid")
	}
	if pt.ConsistencyGUID.Set && len(pt.ConsistencyGUID.Value) != 0 {
		if _, err := guid.FromBytes(pt.ConsistencyGUID.Value); err != nil {
			return bad("ms-DS-ConsistencyGuid")
		}
	}
	for _, v := range []Opt[*int64]{pt.UserAccountControl, pt.PrimaryGroupID} {
		if v.Set && v.Value != nil && (*v.Value < 0 || *v.Value > 1<<32-1) {
			return bad("account control or primary group out of range")
		}
	}
	for _, c := range []struct {
		o    Opt[string]
		name string
		max  int
	}{{pt.DN, "dn", 4096}, {pt.RDN, "rdn", 1024}, {pt.SAMAccountName, "sAMAccountName", 256}, {pt.UPN, "upn", 1024}, {pt.DisplayName, "displayName", 1024}} {
		if c.o.Set && (len(c.o.Value) > c.max || strings.ContainsRune(c.o.Value, 0)) {
			return bad(c.name + " too long or NUL")
		}
	}
	if pt.Class.Set && strings.ContainsRune(pt.Class.Value.Class, 0) {
		return bad("NUL in class")
	}
	if len(pt.Members) > maxMembersEach || len(pt.RemovedMembers) > maxMembersEach {
		return bad("members")
	}
	for _, m := range append(append([]GUID{}, pt.Members...), pt.RemovedMembers...) {
		if !validGUID(m) || m == pt.Object {
			return bad("member guid")
		}
	}
	if _, _, err := pt.bagUpdate(); err != nil {
		return err
	}
	if pt.Create != nil {
		o := pt.Create
		if o.Object != pt.Object || o.NC != pt.NC || o.State == ObjPurged {
			return bad("created observation names another object or naming context")
		}
		if _, err := validateObservation(o, false); err != nil {
			return err
		}
	}
	return nil
}

// bagUpdate returns the attribute keys to remove and the JSON object of keys to set. GroupType is one of the
// judge's inputs and lives in the same column, set or cleared by its own field.
func (pt *Patch) bagUpdate() (clear []string, set []byte, err error) {
	bad := func(why string) error { return fmt.Errorf("%w: patch: %s", ErrInvalid, why) }
	for k := range pt.Attributes {
		for _, j := range judgeKeys {
			if strings.EqualFold(k, j) {
				return nil, nil, bad("judge key in attributes; use the typed field")
			}
		}
	}
	for _, k := range pt.ClearAttributes {
		for _, j := range judgeKeys {
			if strings.EqualFold(k, j) {
				return nil, nil, bad("judge key in cleared attributes; use the typed field")
			}
		}
		if secretKey(k) || strings.ContainsRune(k, 0) {
			return nil, nil, bad("cleared attribute name")
		}
		clear = append(clear, k)
	}
	m := make(map[string]any, len(pt.Attributes)+1)
	for k, v := range pt.Attributes {
		m[k] = v
	}
	if pt.GroupType.Set {
		if pt.GroupType.Value != nil {
			m[AttrGroupType] = *pt.GroupType.Value
		} else {
			clear = append(clear, AttrGroupType)
		}
	}
	if len(m) == 0 {
		return clear, []byte("{}"), nil
	}
	b, err := json.Marshal(m)
	if err != nil || len(b) > maxAttributesSz {
		return nil, nil, bad("attributes")
	}
	var generic any
	if err := json.Unmarshal(b, &generic); err != nil || hasSecret(generic) {
		return nil, nil, bad("a secret attribute is never stored")
	}
	if strings.Contains(string(b), `\u0000`) {
		return nil, nil, bad("NUL in attributes")
	}
	return clear, b, nil
}

func timeArg(o Opt[time.Time]) (set bool, v any) { return o.Set, nullTime(o.Value) }

func bitIf(o Opt[time.Time], bit InputsRead) InputsRead {
	if o.Set {
		return bit
	}
	return 0
}

// write applies the patch to its stored row and reports the rows affected (0: the row is newer).
func (pt *Patch) write(ctx context.Context, tx store.Tx, connection ConnectionID, observed time.Time, dsa string) (int64, error) {
	clear, set, err := pt.bagUpdate()
	if err != nil {
		return 0, err
	}
	if clear == nil {
		clear = []string{}
	}
	var sid, cg []byte
	if pt.SID.Set {
		sid = nilIfEmpty(pt.SID.Value)
	}
	if pt.ConsistencyGUID.Set {
		cg = nilIfEmpty(pt.ConsistencyGUID.Value)
	}
	var parent any
	if pt.Parent.Set {
		parent = nullGUID(pt.Parent.Value)
	}
	var uac *int64
	var enabled *bool
	if pt.UserAccountControl.Set && pt.UserAccountControl.Value != nil {
		uac = pt.UserAccountControl.Value
		en := *uac&0x2 == 0 // ACCOUNTDISABLE
		enabled = &en
	}
	lockSet, lock := timeArg(pt.LockoutTime)
	pwdSet, pwd := timeArg(pt.PwdLastSet)
	expSet, exp := timeArg(pt.AccountExpires)
	logSet, logon := timeArg(pt.LastLogonTimestamp)
	read := bitIf(pt.LockoutTime, ReadLockoutTime) | bitIf(pt.PwdLastSet, ReadPwdLastSet) | bitIf(pt.AccountExpires, ReadAccountExpires) |
		bitIf(pt.LastLogonTimestamp, ReadLastLogonTimestamp)
	createdSet, created := timeArg(pt.WhenCreated)
	changedSet, changed := timeArg(pt.WhenChanged)

	tag, err := tx.Exec(ctx, patchSQL,
		string(connection), string(pt.Object), string(pt.NC),
		pt.Class.Set, string(pt.Class.Value.Kind), pt.Class.Value.Class,
		pt.State.Set, string(pt.State.Value),
		pt.DN.Set, pt.DN.Value, pt.RDN.Value,
		pt.Parent.Set, parent,
		pt.SAMAccountName.Set, pt.SAMAccountName.Value, pt.UPN.Set, pt.UPN.Value, pt.DisplayName.Set, pt.DisplayName.Value,
		pt.SID.Set, sid, pt.ConsistencyGUID.Set, cg,
		createdSet, created, changedSet, changed,
		pt.UserAccountControl.Set, uac, enabled,
		pt.PrimaryGroupID.Set, pt.PrimaryGroupID.Value,
		lockSet, lock, pwdSet, pwd, expSet, exp, logSet, logon, int16(read),
		pt.HasSPN.Set, pt.HasSPN.Value,
		clear, string(set),
		observed.UTC(), dsa)
	if err != nil {
		return 0, writeErr("patch object", err)
	}
	return tag.RowsAffected(), nil
}

// patchSQL: every column is written only under its own flag, so a patch that names displayName leaves the
// rest of the row as it is. A recycled object never goes back to deleted or live (past the deleted-object
// lifetime it is not restorable), whichever order two reports of it arrive in. The unqualified NC head and the
// chain are not touched here: settleChain derives them from the stored parent.
const patchSQL = `UPDATE public.directory_objects d SET
		nc_guid = $3::uuid,
		kind = CASE WHEN $4::boolean THEN $5 ELSE d.kind END,
		object_class = CASE WHEN $4::boolean THEN $6 ELSE d.object_class END,
		state = CASE WHEN $7::boolean AND NOT (d.state = 'recycled' AND $8::text <> 'recycled') THEN $8::text ELSE d.state END,
		dn = CASE WHEN $9::boolean THEN $10::text ELSE d.dn END,
		rdn = CASE WHEN $9::boolean THEN $11::text ELSE d.rdn END,
		parent_guid = CASE WHEN $12::boolean THEN $13::uuid ELSE d.parent_guid END,
		sam_account_name = CASE WHEN $14::boolean THEN $15::text ELSE d.sam_account_name END,
		upn = CASE WHEN $16::boolean THEN $17::text ELSE d.upn END,
		display_name = CASE WHEN $18::boolean THEN $19::text ELSE d.display_name END,
		sid = CASE WHEN $20::boolean THEN $21::bytea ELSE d.sid END,
		consistency_guid = CASE WHEN $22::boolean THEN $23::bytea ELSE d.consistency_guid END,
		when_created = CASE WHEN $24::boolean THEN $25::timestamptz ELSE d.when_created END,
		when_changed = CASE WHEN $26::boolean THEN $27::timestamptz ELSE d.when_changed END,
		user_account_control = CASE WHEN $28::boolean THEN $29::bigint ELSE d.user_account_control END,
		enabled = CASE WHEN $28::boolean THEN $30::boolean ELSE d.enabled END,
		primary_group_id = CASE WHEN $31::boolean THEN $32::bigint ELSE d.primary_group_id END,
		lockout_time = CASE WHEN $33::boolean THEN $34::timestamptz ELSE d.lockout_time END,
		pwd_last_set = CASE WHEN $35::boolean THEN $36::timestamptz ELSE d.pwd_last_set END,
		account_expires = CASE WHEN $37::boolean THEN $38::timestamptz ELSE d.account_expires END,
		last_logon_timestamp = CASE WHEN $39::boolean THEN $40::timestamptz ELSE d.last_logon_timestamp END,
		inputs_read = d.inputs_read | $41::smallint,
		spn_present = CASE WHEN $42::boolean THEN $43::boolean ELSE d.spn_present END,
		attributes = (d.attributes - $44::text[]) || $45::jsonb,
		observed_at = $46::timestamptz,
		observed_dsa = CASE WHEN $47::text <> '' THEN $47::text ELSE d.observed_dsa END
	WHERE d.tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND d.connection_id = $1::uuid
	AND d.object_guid = $2::uuid AND d.observed_at <= $46::timestamptz`

// chainSQL derives the chain of one row from the stored row of its parent, the rule of upsertObjectSQL:
// the row is complete when it is its naming context's head, or a child of the head with the chain [head], or
// its parent is complete and the chain is the parent plus the parent's chain. A parent that is not stored yet
// leaves the known prefix [parent] and an incomplete row, which settleChain of the parent completes when it
// arrives.
const chainSQL = `WITH r AS (
		SELECT object_guid, nc_guid, parent_guid FROM public.directory_objects
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND connection_id = $1::uuid AND object_guid = $2::uuid),
	calc AS (
		SELECT r.object_guid,
			CASE
				WHEN r.parent_guid IS NULL THEN '{}'::uuid[]
				WHEN r.nc_guid IS NOT NULL AND r.parent_guid = r.nc_guid THEN ARRAY[r.parent_guid]
				ELSE COALESCE((SELECT CASE WHEN cardinality(p.ancestry) < 128 AND NOT r.object_guid = ANY(p.ancestry)
						THEN ARRAY[p.object_guid] || p.ancestry ELSE '{}'::uuid[] END
					FROM public.directory_objects p
					WHERE p.tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND p.connection_id = $1::uuid
					AND p.object_guid = r.parent_guid), ARRAY[r.parent_guid])
			END AS chain,
			CASE
				WHEN r.parent_guid IS NULL THEN r.nc_guid IS NOT NULL AND r.nc_guid = r.object_guid
				WHEN r.nc_guid IS NOT NULL AND r.parent_guid = r.nc_guid THEN true
				ELSE COALESCE((SELECT p.ancestry_complete AND cardinality(p.ancestry) < 128 AND NOT r.object_guid = ANY(p.ancestry)
					FROM public.directory_objects p
					WHERE p.tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND p.connection_id = $1::uuid
					AND p.object_guid = r.parent_guid), false)
			END AS complete
		FROM r)
	UPDATE public.directory_objects d SET ancestry = calc.chain, ancestry_complete = calc.complete
	FROM calc
	WHERE d.tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND d.connection_id = $1::uuid
	AND d.object_guid = calc.object_guid AND (d.ancestry IS DISTINCT FROM calc.chain OR d.ancestry_complete IS DISTINCT FROM calc.complete)
`

// belowSQL re-derives, top down, the chain and completeness of every row below $2 through parent_guid
// (DM-19.I5: the feed does not report the children of a moved parent). A row is never entered twice and a
// cycle in bad data ends: a row already in its own chain gets an empty chain and is incomplete.
const belowSQL = `WITH RECURSIVE sub AS (
		SELECT c.object_guid,
			CASE WHEN cardinality(r.ancestry) < 128 AND NOT c.object_guid = ANY(r.ancestry) THEN ARRAY[r.object_guid] || r.ancestry ELSE '{}'::uuid[] END AS chain,
			r.ancestry_complete AND cardinality(r.ancestry) < 128 AND NOT c.object_guid = ANY(r.ancestry) AS complete,
			1 AS depth
		FROM public.directory_objects r
		JOIN public.directory_objects c ON c.tenant_id = r.tenant_id AND c.connection_id = r.connection_id AND c.parent_guid = r.object_guid
		WHERE r.tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND r.connection_id = $1::uuid AND r.object_guid = $2::uuid
		AND c.object_guid <> r.object_guid
	UNION ALL
		SELECT c.object_guid,
			CASE WHEN cardinality(s.chain) < 128 AND NOT c.object_guid = ANY(s.chain) THEN ARRAY[s.object_guid] || s.chain ELSE '{}'::uuid[] END,
			s.complete AND cardinality(s.chain) < 128 AND NOT c.object_guid = ANY(s.chain),
			s.depth + 1
		FROM sub s
		JOIN public.directory_objects c ON c.tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
			AND c.connection_id = $1::uuid AND c.parent_guid = s.object_guid
		WHERE s.depth <= 128 AND c.object_guid <> $2::uuid
	)
	UPDATE public.directory_objects d SET ancestry = sub.chain, ancestry_complete = sub.complete
	FROM (SELECT DISTINCT ON (object_guid) object_guid, chain, complete FROM sub ORDER BY object_guid, depth) sub
	WHERE d.tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND d.connection_id = $1::uuid
	AND d.object_guid = sub.object_guid AND (d.ancestry IS DISTINCT FROM sub.chain OR d.ancestry_complete IS DISTINCT FROM sub.complete)`

// settleChain derives the chain of object from its stored parent and re-derives everything below it. It runs after every write of a row, so a child that arrived before its parent is completed when the
// parent arrives, and the rows below a moved parent follow it.
func settleChain(ctx context.Context, tx store.Tx, connection ConnectionID, object GUID) error {
	if _, err := tx.Exec(ctx, chainSQL, string(connection), string(object)); err != nil {
		return writeErr("derive ancestry", err)
	}
	// Children are re-derived even when this row's chain did not change: a newly written row may be the parent
	// that rows waiting for it have not yet been completed against. The lookup is the parent index.
	if _, err := tx.Exec(ctx, belowSQL, string(connection), string(object)); err != nil {
		return writeErr("rederive descendants", err)
	}
	return nil
}

// markGroupsDirty marks the groups among objects as closure roots to recompute.
func markGroupsDirty(ctx context.Context, tx store.Tx, connection ConnectionID, objects []GUID) error {
	ids := make([]string, len(objects))
	for i, o := range objects {
		ids[i] = string(o)
	}
	_, err := tx.Exec(ctx, `INSERT INTO public.inventory_group_closure_dirty (tenant_id, connection_id, group_guid)
		SELECT tenant_id, connection_id, object_guid FROM public.directory_objects
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND connection_id = $1::uuid
		AND object_guid = ANY($2::uuid[]) AND kind = 'group' ON CONFLICT DO NOTHING`, string(connection), ids)
	if err != nil {
		return writeErr("mark group dirty", err)
	}
	return nil
}

// deadAmong returns those of objects that are stored as deleted, recycled or purged.
func deadAmong(ctx context.Context, tx store.Tx, connection ConnectionID, objects []string) ([]string, error) {
	if len(objects) == 0 {
		return nil, nil
	}
	rows, err := tx.Query(ctx, `SELECT object_guid::text FROM public.directory_objects
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND connection_id = $1::uuid
		AND object_guid = ANY($2::uuid[]) AND state IN ('deleted', 'recycled', 'purged') ORDER BY object_guid`, string(connection), objects)
	if err != nil {
		return nil, writeErr("find dead objects", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, writeErr("find dead objects", err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// rewriteKeysOf replaces the search keys of objects with keys built from their stored rows.
func rewriteKeysOf(ctx context.Context, tx store.Tx, connection ConnectionID, objects []GUID) error {
	ids := make([]string, len(objects))
	for i, o := range objects {
		ids[i] = string(o)
	}
	rows, err := tx.Query(ctx, `SELECT object_guid::text, kind, state, display_name, rdn, sam_account_name, upn, dn, sid, consistency_guid,
			COALESCE(attributes->>'mail', ''), COALESCE(attributes->>'dNSHostName', '')
		FROM public.directory_objects
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND connection_id = $1::uuid AND object_guid = ANY($2::uuid[])
		ORDER BY object_guid`, string(connection), ids)
	if err != nil {
		return writeErr("read rows for search keys", err)
	}
	var keyed []searchKeyRow
	for rows.Next() {
		var g, k, st string
		var s keySource
		if err := rows.Scan(&g, &k, &st, &s.displayName, &s.rdn, &s.sam, &s.upn, &s.dn, &s.sid, &s.consistencyGUID, &s.mail, &s.dnsHost); err != nil {
			rows.Close()
			return writeErr("read rows for search keys", err)
		}
		s.object, s.kind, s.state = GUID(g), Kind(k), ObjectState(st)
		keyed = append(keyed, searchKeys(s)...)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return writeErr("read rows for search keys", err)
	}
	_, err = writeSearchKeys(ctx, tx, connection, objects, keyed)
	return err
}

// ridBytes is the little-endian 4 bytes of a relative ID, as the last sub-authority of a binary SID.
const ridBytes = `set_byte(set_byte(set_byte(set_byte('\x00000000'::bytea, 0, (%[1]s & 255)::int), 1, ((%[1]s >> 8) & 255)::int),
	2, ((%[1]s >> 16) & 255)::int), 3, ((%[1]s >> 24) & 255)::int)`

// patchPrimaryGroupSQL: $1 connection, $2 the objects a patch wrote, $3 the as-of. The primary group of a principal
// is the group of its domain whose SID is the principal's with the last sub-authority replaced by
// primaryGroupID (DM-17.I2). It is derived from stored rows on both sides, so it is the same whether the user
// or its group was written first: the candidates are the principals written and the principals of the domain
// that name a group written. A principal with no such group keeps no primary-group edge. It returns the edges
// it removed.
var patchPrimaryGroupSQL = fmt.Sprintf(`WITH ob AS (
		SELECT object_guid, nc_guid, kind, sid, primary_group_id, state FROM public.directory_objects
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND connection_id = $1::uuid AND object_guid = ANY($2::uuid[])),
	cand AS (
		SELECT u.object_guid, u.nc_guid, u.sid, u.primary_group_id FROM public.directory_objects u
		WHERE u.tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND u.connection_id = $1::uuid
		AND u.kind IN ('user', 'inetorgperson', 'computer', 'gmsa') AND u.state = 'live' AND u.sid IS NOT NULL AND length(u.sid) >= 12
		AND u.primary_group_id IS NOT NULL
		AND (u.object_guid IN (SELECT object_guid FROM ob)
			OR EXISTS (SELECT 1 FROM ob g WHERE g.kind = 'group' AND g.sid IS NOT NULL AND g.nc_guid = u.nc_guid
				AND g.sid = substring(u.sid from 1 for length(u.sid) - 4) || %s))),
	want AS (
		SELECT c.object_guid AS member, g.object_guid AS grp FROM cand c
		JOIN public.directory_objects g ON g.tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND g.connection_id = $1::uuid
			AND g.kind = 'group' AND g.state = 'live' AND g.nc_guid = c.nc_guid AND g.object_guid <> c.object_guid
			AND g.sid = substring(c.sid from 1 for length(c.sid) - 4) || %s),
	setg AS (
		INSERT INTO public.links (tenant_id, connection_id, source_guid, link_attr, target_guid, state, observed_at)
		SELECT NULLIF(current_setting('app.tenant_id', true), '')::uuid, $1::uuid, w.grp, 'primary_group', w.member, 'active', $3 FROM want w
		ON CONFLICT (tenant_id, connection_id, source_guid, link_attr, target_guid) DO UPDATE SET state = 'active', observed_at = EXCLUDED.observed_at
			WHERE links.state <> 'active' OR links.observed_at < EXCLUDED.observed_at
		RETURNING source_guid),
	drop AS (
		UPDATE public.links l SET state = 'removed', observed_at = GREATEST(l.observed_at, $3)
		WHERE l.tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND l.connection_id = $1::uuid
		AND l.link_attr = 'primary_group' AND l.state = 'active' AND l.target_guid IN (SELECT object_guid FROM cand)
		AND NOT EXISTS (SELECT 1 FROM want w WHERE w.member = l.target_guid AND w.grp = l.source_guid)
		RETURNING l.source_guid)
	INSERT INTO public.inventory_group_closure_dirty (tenant_id, connection_id, group_guid)
	SELECT NULLIF(current_setting('app.tenant_id', true), '')::uuid, $1::uuid, x.source_guid FROM (
		SELECT source_guid FROM setg UNION SELECT source_guid FROM drop) x ON CONFLICT DO NOTHING`,
	fmt.Sprintf(ridBytes, "u.primary_group_id"), fmt.Sprintf(ridBytes, "c.primary_group_id"))

// followPrimaryGroups brings the primary-group edges of the principals among objects, and of the principals that
// name a group among objects, to what the stored rows say (see patchPrimaryGroupSQL).
func (Writer) followPrimaryGroups(ctx context.Context, tx store.Tx, connection ConnectionID, objects []GUID, observed time.Time) error {
	ids := make([]string, len(objects))
	for i, o := range objects {
		ids[i] = string(o)
	}
	if _, err := tx.Exec(ctx, patchPrimaryGroupSQL, string(connection), ids, observed.UTC()); err != nil {
		return writeErr("follow primary groups", err)
	}
	return nil
}
