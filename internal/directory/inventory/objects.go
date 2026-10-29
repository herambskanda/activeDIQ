package inventory

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"strings"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/attr/secretattr"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tablekind"
)

var _ = tablekind.Declare(tablekind.Table{Name: "public.directory_objects", Entity: "DM-16", Kind: tablekind.Directory})

// Kind is DM-16 `kind`.
type Kind string

// The kinds a row can have.
const (
	KindUser          Kind = "user"
	KindInetOrgPerson Kind = "inetorgperson"
	KindGroup         Kind = "group"
	KindComputer      Kind = "computer"
	KindContact       Kind = "contact"
	KindOU            Kind = "ou"
	KindContainer     Kind = "container"
	KindGMSA          Kind = "gmsa"
	KindFSP           Kind = "fsp"
	KindOther         Kind = "other"
)

var validKinds = map[Kind]bool{KindUser: true, KindInetOrgPerson: true, KindGroup: true, KindComputer: true, KindContact: true,
	KindOU: true, KindContainer: true, KindGMSA: true, KindFSP: true, KindOther: true}

// ObjectState is the DM-16 lifecycle state. AD: live, deleted, recycled, purged, out_of_scope.
// Entra: active, soft_deleted, purged.
type ObjectState string

// The states.
const (
	ObjLive        ObjectState = "live"
	ObjDeleted     ObjectState = "deleted"
	ObjRecycled    ObjectState = "recycled"
	ObjPurged      ObjectState = "purged"
	ObjOutOfScope  ObjectState = "out_of_scope"
	ObjActive      ObjectState = "active"
	ObjSoftDeleted ObjectState = "soft_deleted"
)

const (
	maxObjects          = 5000
	maxMembersEach      = 100000
	maxAttributesSz     = 64 * 1024
	maxAncestryHops     = 128
	connKindADForest    = "ad_forest"
	connKindEntraTenant = "entra_tenant"
	clockSkewAllowance  = 5 * time.Minute
)

var adStates = map[ObjectState]bool{ObjLive: true, ObjDeleted: true, ObjRecycled: true, ObjPurged: true, ObjOutOfScope: true}
var entraStates = map[ObjectState]bool{ObjActive: true, ObjSoftDeleted: true, ObjPurged: true}

// secretNames is the refusal set (DM-16.I3, X4, safe-primitives LF-38): the one static list in
// secretattr, lower-cased once, plus Entra and trust names that list does not carry. Matching is
// on the lower-cased name with any ";option" suffix removed.
var secretNames = func() map[string]bool {
	m := map[string]bool{}
	for _, n := range secretattr.Static() {
		m[strings.ToLower(n)] = true
	}
	for _, n := range []string{"currentValue", "priorValue", "initialAuthIncomingPwd", "initialAuthOutgoingPwd",
		"msDS-KeyCredentialLink", "passwordProfile", "pwdHistory", "trustAuthIncoming", "trustAuthOutgoing"} {
		m[strings.ToLower(n)] = true
	}
	return m
}()

// secretKey reports whether an attribute key must be refused: a secret name (options stripped), or
// anything that is not ldapDisplayName syntax (numeric OIDs, empty, NUL), since this package cannot map
// an OID to a name. Producers must also drop the session's schema-flagged SecretAttrs (searchFlags
// 0x80/0x200/0x1000) before building an Observation; the connector-side producer is T-0326's input.
func secretKey(k string) bool {
	if i := strings.IndexByte(k, ';'); i >= 0 {
		k = k[:i]
	}
	if k == "" || !(k[0] >= 'A' && k[0] <= 'Z' || k[0] >= 'a' && k[0] <= 'z') {
		return true
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return true
		}
	}
	return secretNames[strings.ToLower(k)]
}

// hasSecret walks a decoded JSON value and reports a secret key at any depth.
func hasSecret(v any) bool {
	switch t := v.(type) {
	case map[string]any:
		for k, e := range t {
			if secretKey(k) || hasSecret(e) {
				return true
			}
		}
	case []any:
		for _, e := range t {
			if hasSecret(e) {
				return true
			}
		}
	}
	return false
}

// Observation is what one sync cycle saw of one object. The connector (LDAP, DirSync, Graph delta)
// builds it; this package decides nothing about the directory beyond what DM-16 states.
type Observation struct {
	Object GUID
	// NC is the naming context's GUID (AD only; empty for Entra).
	NC       GUID
	Kind     Kind
	Class    string
	Parent   GUID
	Ancestry []GUID
	DN, RDN  string
	// SID is the binary objectSid (security principals; AD).
	SID             []byte
	SAMAccountName  string
	UPN             string
	DisplayName     string
	Enabled         *bool
	LockoutTime     time.Time
	PwdLastSet      time.Time
	AccountExpires  time.Time
	ConsistencyGUID []byte
	// Attributes is the generic attribute bag. It never carries a judge key (judgeKeys): those enter
	// only through Facts, so a fact cannot be stored without its computed-at.
	Attributes map[string]any
	// Facts are the typed group facts the eligibility judge reads (DM-36.I2, TM-D18).
	Facts       GroupFacts
	WhenCreated time.Time
	WhenChanged time.Time
	ObservedDSA string
	State       ObjectState
	// Entra only, users and groups: onPremisesSyncEnabled (nil = absent) and
	// onPremisesSyncBehavior.isCloudManaged. They decide cloud_seen_at (DM-16.I9).
	OnPremisesSyncEnabled *bool
	CloudManaged          bool
	// OnPremisesSyncRead says the sync read onPremisesSyncEnabled on this Entra group. With it set,
	// a nil OnPremisesSyncEnabled is Graph's JSON null (never synced); without it the key is stored
	// absent, which the judge treats as unknown. OnPremisesSyncEnabled set requires it.
	OnPremisesSyncRead bool
	// Entra only, users and groups: the other inputs of the DM-20.I4 gate, kept so that a later AD-side
	// cycle can run the gate again. OnPremisesSID is onPremisesSecurityIdentifier (binary),
	// OnPremisesDomainName is onPremisesDomainName ("" when not populated) and OnPremisesImmutableID is
	// the decoded onPremisesImmutableId (the anchor, 16 bytes for a GUID anchor).
	OnPremisesSID         []byte
	OnPremisesDomainName  string
	OnPremisesImmutableID []byte

	// PrimaryGroup is a user's primaryGroupID resolved to the group (DM-17.I2). Zero: none observed.
	PrimaryGroup GUID
	// Members are the group's member values resolved to GUIDs. They are written through
	// Writer.SetMember. MembersComplete says Members is the whole current set (a full read, or the
	// last range of a ranged read): edges the cycle did not see are then marked removed. A delta
	// leaves it false and only adds.
	Members         []GUID
	MembersComplete bool
	// RemovedMembers are explicit removals (a DirSync delta).
	RemovedMembers []GUID
}

// GroupFacts are the judge's inputs, typed so the producer cannot store one without the others it
// depends on. A nil pointer or nil slice is "not read", which the judge treats as unknown. AD groups
// use GroupType, BroadMembershipWrite(+At) and WrittenBack; Entra groups use SecurityEnabled,
// Visibility and GroupTypes (and Observation.OnPremisesSyncRead).
type GroupFacts struct {
	GroupType *int32 // AD groupType
	// BroadMembershipWrite is the computed fact (TM-D18); BroadMembershipWriteAt is when it was
	// computed and is required with it: a fact without an age cannot grant.
	BroadMembershipWrite   *bool
	BroadMembershipWriteAt time.Time
	WrittenBack            *bool
	SecurityEnabled        *bool
	Visibility             string   // "" is not read / none
	GroupTypes             []string // nil is not read; empty non-nil is read and has no entries
}

func (f GroupFacts) ad() bool {
	return f.GroupType != nil || f.BroadMembershipWrite != nil || !f.BroadMembershipWriteAt.IsZero() || f.WrittenBack != nil
}

func (f GroupFacts) entra() bool {
	return f.SecurityEnabled != nil || f.Visibility != "" || f.GroupTypes != nil
}

// judgeKeys are the attribute keys the judge reads. They are produced only from typed fields.
var judgeKeys = []string{AttrGroupType, AttrSecurityEnabled, AttrVisibility, AttrGroupTypes,
	AttrBroadMembershipWrite, AttrWrittenBack, AttrBroadMembershipWriteAt, AttrOnPremisesSyncEnabled}

// merged returns the attributes to store: the generic bag plus the typed facts. A judge key in the
// bag is refused, whatever its case.
func (o *Observation) merged(entra bool) (map[string]any, error) {
	for k := range o.Attributes {
		for _, j := range judgeKeys {
			if strings.EqualFold(k, j) {
				return nil, fmt.Errorf("judge key %q in attributes; use the typed fields", k)
			}
		}
	}
	f := o.Facts
	if o.Kind != KindGroup {
		if f.ad() || f.entra() || o.OnPremisesSyncRead {
			return nil, fmt.Errorf("group facts on a non-group")
		}
		return o.Attributes, nil
	}
	if entra && f.ad() || !entra && (f.entra() || o.OnPremisesSyncRead) {
		return nil, fmt.Errorf("group facts of the other plane")
	}
	if (f.BroadMembershipWrite == nil) != f.BroadMembershipWriteAt.IsZero() {
		return nil, fmt.Errorf("broadMembershipWrite and its computed-at come together")
	}
	if entra && o.OnPremisesSyncEnabled != nil && !o.OnPremisesSyncRead {
		return nil, fmt.Errorf("onPremisesSyncEnabled set without OnPremisesSyncRead")
	}
	out := make(map[string]any, len(o.Attributes)+8)
	for k, v := range o.Attributes {
		out[k] = v
	}
	if f.GroupType != nil {
		out[AttrGroupType] = *f.GroupType
	}
	if f.BroadMembershipWrite != nil {
		out[AttrBroadMembershipWrite] = *f.BroadMembershipWrite
		out[AttrBroadMembershipWriteAt] = f.BroadMembershipWriteAt.UTC().Format(time.RFC3339)
	}
	if f.WrittenBack != nil {
		out[AttrWrittenBack] = *f.WrittenBack
	}
	if f.SecurityEnabled != nil {
		out[AttrSecurityEnabled] = *f.SecurityEnabled
	}
	if f.Visibility != "" {
		out[AttrVisibility] = f.Visibility
	}
	if f.GroupTypes != nil {
		out[AttrGroupTypes] = f.GroupTypes
	}
	if o.OnPremisesSyncRead {
		if o.OnPremisesSyncEnabled != nil {
			out[AttrOnPremisesSyncEnabled] = *o.OnPremisesSyncEnabled
		} else {
			out[AttrOnPremisesSyncEnabled] = nil
		}
	}
	return out, nil
}

// Populated is the outcome of Populate.
type Populated struct {
	Inserted, Updated int
	// Stale counts observations older than the stored row; they are ignored, not errors.
	Stale int
	// CloudSeen counts Entra rows whose cloud_seen_at moved in this call.
	CloudSeen              int
	Members, PrimaryGroups int
}

// Populator writes DM-16 rows and the DM-17 member and primary-group edges for one connection from a
// sync cycle's observations. Like Writer it runs in the caller's tenant transaction and decides
// nothing about who may call it.
type Populator struct{ Writer }

func nullGUID(g GUID) any {
	if g == "" {
		return nil
	}
	return string(g)
}

func nilIfEmpty(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return b
}

func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC()
}

func validGUID(g GUID) bool { c, ok := canon(string(g)); return ok && c == string(g) }

// Populate upserts the observations of connection observed at the given time (the cycle's as-of) and
// writes their edges. All or nothing: any invalid observation fails the call before the first write, so a
// caller's transaction never holds half a batch. An observation older than the stored row is counted
// Stale and ignored (a late delta must not overwrite newer state).
func (p Populator) Populate(ctx context.Context, tx store.Tx, connection ConnectionID, observed time.Time, obs []Observation) (Populated, error) {
	var out Populated
	if _, ok := canon(string(connection)); !ok || string(connection) != lower(string(connection)) || observed.IsZero() {
		return out, ErrInvalid
	}
	if len(obs) > maxObjects {
		return out, ErrTooMany
	}
	if err := requireTenant(ctx, tx); err != nil {
		return out, err
	}
	var ck string
	if err := tx.QueryRow(ctx, `SELECT kind FROM public.connections
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND id = $1::uuid`, string(connection)).Scan(&ck); err != nil {
		if store.IsNoRows(err) {
			return out, ErrUnknownConnection
		}
		return out, fmt.Errorf("inventory: connection kind: %w", err)
	}
	var future bool
	if err := tx.QueryRow(ctx, `SELECT $1::timestamptz > now() + $2::interval`, observed.UTC(), fmt.Sprintf("%d seconds", int(clockSkewAllowance.Seconds()))).Scan(&future); err != nil {
		return out, writeErr("observed as-of", err)
	}
	if future {
		return out, fmt.Errorf("%w: observation as-of is in the future", ErrInvalid)
	}
	entra := ck == connKindEntraTenant
	if !entra && ck != connKindADForest {
		return out, ErrCorrupt
	}
	attrs := make([][]byte, len(obs))
	for i := range obs {
		b, err := validateObservation(&obs[i], entra)
		if err != nil {
			return out, err
		}
		attrs[i] = b
	}

	for i := range obs {
		o := &obs[i]
		var cloud any
		if entra && (o.Kind == KindUser || o.Kind == KindGroup) &&
			((o.OnPremisesSyncEnabled == nil || !*o.OnPremisesSyncEnabled) || o.CloudManaged) {
			cloud = observed.UTC()
		}
		// The gate inputs are stored for Entra users and groups only; for anything else they stay NULL.
		var onPremSync, onPremCloud any
		if entra && (o.Kind == KindUser || o.Kind == KindGroup) {
			if o.OnPremisesSyncEnabled != nil {
				onPremSync = *o.OnPremisesSyncEnabled
			}
			onPremCloud = o.CloudManaged
		}
		anc := make([]string, len(o.Ancestry))
		for j, a := range o.Ancestry {
			anc[j] = string(a)
		}
		var sid, cg []byte
		if len(o.SID) > 0 {
			sid = o.SID
		}
		if len(o.ConsistencyGUID) > 0 {
			cg = o.ConsistencyGUID
		}
		var inserted bool
		err := tx.QueryRow(ctx, `INSERT INTO public.directory_objects AS d (tenant_id, connection_id, object_guid, nc_guid, kind, object_class,
				parent_guid, ancestry, dn, rdn, sid, sam_account_name, upn, display_name, enabled, lockout_time, pwd_last_set, account_expires,
				consistency_guid, attributes, when_created, when_changed, observed_at, observed_dsa, cloud_seen_at, state,
				on_prem_sync_enabled, on_prem_cloud_managed, on_prem_sid, on_prem_domain_name, on_prem_immutable_id)
			VALUES (NULLIF(current_setting('app.tenant_id', true), '')::uuid, $1::uuid, $2::uuid, $3::uuid, $4, $5,
				$6::uuid, $7::uuid[], $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19::jsonb, $20, $21, $22, $23, $24, $25,
				$26, $27, $28, $29, $30)
			ON CONFLICT (tenant_id, connection_id, object_guid) DO UPDATE SET
				nc_guid = EXCLUDED.nc_guid, kind = EXCLUDED.kind, object_class = EXCLUDED.object_class, parent_guid = EXCLUDED.parent_guid,
				ancestry = EXCLUDED.ancestry, dn = EXCLUDED.dn, rdn = EXCLUDED.rdn, sid = EXCLUDED.sid,
				sam_account_name = EXCLUDED.sam_account_name, upn = EXCLUDED.upn, display_name = EXCLUDED.display_name,
				enabled = EXCLUDED.enabled, lockout_time = EXCLUDED.lockout_time, pwd_last_set = EXCLUDED.pwd_last_set,
				account_expires = EXCLUDED.account_expires, consistency_guid = EXCLUDED.consistency_guid, attributes = EXCLUDED.attributes,
				when_created = EXCLUDED.when_created, when_changed = EXCLUDED.when_changed, observed_at = EXCLUDED.observed_at,
				observed_dsa = EXCLUDED.observed_dsa, state = EXCLUDED.state,
				on_prem_sync_enabled = EXCLUDED.on_prem_sync_enabled, on_prem_cloud_managed = EXCLUDED.on_prem_cloud_managed,
				on_prem_sid = EXCLUDED.on_prem_sid, on_prem_domain_name = EXCLUDED.on_prem_domain_name,
				on_prem_immutable_id = EXCLUDED.on_prem_immutable_id,
				cloud_seen_at = GREATEST(d.cloud_seen_at, EXCLUDED.cloud_seen_at)
			WHERE d.observed_at <= EXCLUDED.observed_at
			RETURNING (xmax = 0)`,
			string(connection), string(o.Object), nullGUID(o.NC), string(o.Kind), o.Class,
			nullGUID(o.Parent), anc, o.DN, o.RDN, sid, o.SAMAccountName, o.UPN, o.DisplayName, o.Enabled,
			nullTime(o.LockoutTime), nullTime(o.PwdLastSet), nullTime(o.AccountExpires),
			cg, string(attrs[i]), nullTime(o.WhenCreated), nullTime(o.WhenChanged), observed.UTC(), o.ObservedDSA, cloud, string(o.State),
			onPremSync, onPremCloud, nilIfEmpty(o.OnPremisesSID), o.OnPremisesDomainName, nilIfEmpty(o.OnPremisesImmutableID)).Scan(&inserted)
		if store.IsNoRows(err) {
			out.Stale++
			continue
		}
		if err != nil {
			return out, writeErr("upsert object", err)
		}
		if inserted {
			out.Inserted++
		} else {
			out.Updated++
		}
		if cloud != nil {
			out.CloudSeen++
		}

		if o.Kind == KindGroup {
			for _, m := range o.Members {
				if err := p.SetMember(ctx, tx, connection, o.Object, m, observed); err != nil {
					return out, err
				}
				out.Members++
			}
			for _, m := range o.RemovedMembers {
				if err := p.RemoveMember(ctx, tx, connection, o.Object, m, observed); err != nil {
					return out, err
				}
			}
			if o.MembersComplete {
				if err := p.removeUnseen(ctx, tx, "member", connection, o.Object, observed); err != nil {
					return out, err
				}
			}
		}
		if o.PrimaryGroup != "" {
			if err := p.SetPrimaryGroup(ctx, tx, connection, o.PrimaryGroup, o.Object, observed); err != nil {
				return out, err
			}
			out.PrimaryGroups++
			if err := p.removeOtherPrimaryGroups(ctx, tx, connection, o.PrimaryGroup, o.Object, observed); err != nil {
				return out, err
			}
		}
	}
	return out, nil
}

func validateObservation(o *Observation, entra bool) ([]byte, error) {
	bad := func(why string) ([]byte, error) { return nil, fmt.Errorf("%w: observation: %s", ErrInvalid, why) }
	if !validGUID(o.Object) {
		return bad("object guid")
	}
	if !validKinds[o.Kind] || o.Class == "" || len(o.Class) > 100 {
		return bad("kind or class")
	}
	if entra {
		if len(o.OnPremisesSID) != 0 && (len(o.OnPremisesSID) < 8 || len(o.OnPremisesSID) > 68) {
			return bad("onPremisesSecurityIdentifier")
		}
		if len(o.OnPremisesImmutableID) > 64 || len(o.OnPremisesDomainName) > 255 || strings.ContainsRune(o.OnPremisesDomainName, 0) {
			return bad("onPremises anchor or domain")
		}
		if o.NC != "" || len(o.SID) > 0 || len(o.ConsistencyGUID) > 0 || !entraStates[o.State] {
			return bad("entra object with AD-only fields or state")
		}
	} else {
		if !validGUID(o.NC) || !adStates[o.State] || o.OnPremisesSyncEnabled != nil || o.CloudManaged ||
			len(o.OnPremisesSID) > 0 || o.OnPremisesDomainName != "" || len(o.OnPremisesImmutableID) > 0 {
			return bad("AD object nc, state or cloud fields")
		}
		if len(o.ConsistencyGUID) != 0 {
			if _, err := guid.FromBytes(o.ConsistencyGUID); err != nil {
				return bad("ms-DS-ConsistencyGuid")
			}
		}
	}
	if len(o.SID) != 0 && (len(o.SID) < 8 || len(o.SID) > 68) {
		return bad("sid")
	}
	if o.Parent != "" && (!validGUID(o.Parent) || o.Parent == o.Object) {
		return bad("parent")
	}
	if len(o.Ancestry) > maxAncestryHops {
		return bad("ancestry")
	}
	for _, a := range o.Ancestry {
		if !validGUID(a) {
			return bad("ancestry")
		}
	}
	if o.PrimaryGroup != "" && (!validGUID(o.PrimaryGroup) || o.PrimaryGroup == o.Object || o.Kind == KindGroup) {
		return bad("primary group")
	}
	if len(o.Members) > maxMembersEach || len(o.RemovedMembers) > maxMembersEach {
		return bad("members")
	}
	if len(o.Members) > 0 || len(o.RemovedMembers) > 0 || o.MembersComplete {
		if o.Kind != KindGroup {
			return bad("members on a non-group")
		}
		for _, m := range append(append([]GUID{}, o.Members...), o.RemovedMembers...) {
			if !validGUID(m) {
				return bad("member guid")
			}
		}
	}
	b := []byte("{}")
	attrs, err := o.merged(entra)
	if err != nil {
		return bad(err.Error())
	}
	if len(attrs) > 0 {
		if b, err = json.Marshal(attrs); err != nil || len(b) > maxAttributesSz {
			return bad("attributes")
		}
		var generic any
		if err := json.Unmarshal(b, &generic); err != nil || hasSecret(generic) {
			return bad("a secret attribute is never stored")
		}
	}
	if len(o.DN) > 4096 || len(o.RDN) > 1024 || len(o.SAMAccountName) > 256 || len(o.UPN) > 1024 || len(o.DisplayName) > 1024 || len(o.ObservedDSA) > 256 {
		return bad("value too long")
	}
	// PostgreSQL text cannot hold NUL; refuse rather than let the database error carry the value.
	for _, s := range []string{o.DN, o.RDN, o.SAMAccountName, o.UPN, o.DisplayName, o.ObservedDSA, o.Class} {
		if strings.ContainsRune(s, 0) {
			return bad("NUL in text")
		}
	}
	if strings.Contains(string(b), `\u0000`) {
		return bad("NUL in attributes")
	}
	return b, nil
}

// removeUnseen marks the active attr edges of group that this cycle did not refresh (observed_at older
// than the cycle) removed: the cycle read the whole membership.
func (Writer) removeUnseen(ctx context.Context, tx store.Tx, attr string, connection ConnectionID, group GUID, observed time.Time) error {
	_, err := tx.Exec(ctx, `UPDATE public.links SET state = 'removed', observed_at = $3
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND connection_id = $1::uuid
		AND source_guid = $2::uuid AND link_attr = $4 AND state = 'active' AND observed_at < $3`,
		string(connection), string(group), observed.UTC(), attr)
	if err != nil {
		return writeErr("remove unseen "+attr, err)
	}
	return nil
}

// removeOtherPrimaryGroups: a user has one primary group, so any other active primary_group edge to the
// user is stale once the new one is observed.
func (Writer) removeOtherPrimaryGroups(ctx context.Context, tx store.Tx, connection ConnectionID, group, user GUID, observed time.Time) error {
	_, err := tx.Exec(ctx, `UPDATE public.links SET state = 'removed', observed_at = $4
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND connection_id = $1::uuid
		AND link_attr = 'primary_group' AND target_guid = $3::uuid AND source_guid <> $2::uuid AND state = 'active' AND observed_at <= $4`,
		string(connection), string(group), string(user), observed.UTC())
	if err != nil {
		return writeErr("remove stale primary group", err)
	}
	return nil
}

// AnchorMatches resolves an anchor value across the given AD connections (DM-20.I1a): the number of AD
// objects whose ms-DS-ConsistencyGuid or objectGUID equals the 16-byte value (LDAP wire order, the
// decoded onPremisesImmutableId). Objects purged from the directory are not counted. The caller
// supplies the AD connections that have a HybridLink to the Entra tenant (the connection module's
// port, ADR-0003 F1); a connection that is not one of the tenant's AD forests is ErrUnknownConnection,
// so a wrong list is an error, never a silent undercount. A value that is not 16 bytes cannot be a
// GUID anchor and matches nothing here (string anchors are a separate lookup).
//
// Only user and inetOrgPerson rows count (DM-20.I1a is user-to-user); computers, gMSAs, groups and
// contacts sharing the GUID are not matches.
//
// The count, not a bool: more than one is DM-20 `ambiguous_anchor`.
func (Writer) AnchorMatches(ctx context.Context, tx store.Tx, adConnections []ConnectionID, anchor []byte) (int, error) {
	if len(adConnections) == 0 || len(adConnections) > 1000 {
		return 0, ErrInvalid
	}
	ids := make([]string, len(adConnections))
	for i, c := range adConnections {
		if !(Ref{c, "aaaaaaaa-0000-4000-8000-000000000000"}).Valid() {
			return 0, ErrInvalid
		}
		ids[i] = string(c)
	}
	if err := requireTenant(ctx, tx); err != nil {
		return 0, err
	}
	var ok int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM public.connections
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND kind = 'ad_forest' AND id = ANY($1::uuid[])`, ids).Scan(&ok); err != nil {
		return 0, fmt.Errorf("inventory: anchor connections: %w", err)
	}
	if ok != len(uniq(ids)) {
		return 0, ErrUnknownConnection
	}
	g, err := guid.FromBytes(anchor)
	if err != nil {
		return 0, nil
	}
	var n int
	err = tx.QueryRow(ctx, `SELECT count(*) FROM public.directory_objects
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND connection_id = ANY($1::uuid[])
		AND nc_guid IS NOT NULL AND state <> 'purged' AND kind IN ('user','inetorgperson') AND (consistency_guid = $2 OR object_guid = $3::uuid)`,
		ids, g.Bytes(), g.String()).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("inventory: anchor matches: %w", err)
	}
	return n, nil
}

func uniq(s []string) map[string]bool {
	m := make(map[string]bool, len(s))
	for _, x := range s {
		m[x] = true
	}
	return m
}
