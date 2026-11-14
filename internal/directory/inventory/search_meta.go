package inventory

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/reportsql"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// MaxSearchMetaRefs bounds one metadata read: four groups of at most MaxSearchGroupLimit admitted hits.
const MaxSearchMetaRefs = 4 * reportsql.MaxSearchGroupLimit

// SearchRef names one admitted hit by its identity.
type SearchRef struct{ Connection, Object string }

// SearchMeta is what a hit row shows beyond the statement's own columns: display snapshots of the stored
// row (DM-16.I2), never keys. Mail, Title, Office and Department are string attributes of the stored row; an
// attribute the sync never read is "" (T-1129 syncs title, office and department).
type SearchMeta struct {
	DN, SAMAccountName, UserPrincipalName, Mail string
	Title, Office, Department                   string
	Status                                      SearchStatus
}

// SearchStatus is the stored facts behind a hit's status chips. Every field is positive-only: false, nil and
// the zero time mean "not shown", which covers both "no" and "the inputs were not read". The two are never
// told apart here, so a hit with unknown inputs gets no chip and nothing that says "not locked".
type SearchStatus struct {
	// Locked is the users dataset's locked_out state (locked); LockedAt is lockoutTime, zero when not stored.
	Locked   bool
	LockedAt time.Time
	// PasswordExpired is password_state expired. PasswordExpiresInDays is the whole days left when the state
	// is expires and the policy gives a limit; nil otherwise (never expires, must change, unknown).
	PasswordExpired       bool
	PasswordExpiresInDays *int64
	// AccountExpires is accountExpires when the account has an expiry (past or future); zero for never or unread.
	AccountExpires time.Time
	// Tier0 is a stored tier0 fact: an active designation, or a correlation whose own side is tier0 with an
	// as-of. An object with no stored fact is not marked; the live classifier is the authority at write time.
	Tier0 bool
	// CloudOnly: an Entra user or group the sync read as not synced from on-premises (ad-expert, T-1097).
	CloudOnly bool
}

// The columns of the users dataset the chips are derived from. Their rules live in datasets_sql.go and are
// evaluated by the report compiler; this file never restates them.
const (
	colConn       report.ColumnID = "connection_id"
	colLocked     report.ColumnID = "locked_out"
	colLockTime   report.ColumnID = "lockout_time"
	colPwdState   report.ColumnID = "password_state"
	colPwdDays    report.ColumnID = "days_to_password_expiry"
	colAcctState  report.ColumnID = "account_expired"
	colAcctExpire report.ColumnID = "account_expires"
	colGUID       report.ColumnID = "object_guid"
)

var statusCols = []report.ColumnID{colGUID, colConn, colLocked, colLockTime, colPwdState, colPwdDays, colAcctState, colAcctExpire}

func (s *Searcher) registerUsers(sch reportsql.Schema) error {
	src := usersDataset()
	reg, err := reportsql.NewRegistry(reportsql.Options{Schema: sch, SecretKey: SecretKey}, src)
	if err != nil {
		return fmt.Errorf("inventory: search status dataset: %w", err)
	}
	ds, ok := reg.Dataset(DatasetUsers)
	if !ok {
		return fmt.Errorf("inventory: search status dataset missing")
	}
	s.users, s.usersSrc = ds, src
	return nil
}

// SearchMetadata is the one batched read of rule 13: the display fields and status facts of the hits the
// statement already admitted, keyed by their GUIDs. It is not the scope check and must be given only the hits
// of Search; scope is the caller's directory.read scope and is applied again to the derived-state read, so the
// read can only narrow. now is the instant the derived states are evaluated at. A ref the table does not hold
// is absent from the answer.
func (s *Searcher) SearchMetadata(ctx context.Context, tx store.Tx, tid tenant.ID, scope authz.ReadScope, now time.Time, hits []reportsql.SearchHit) (map[SearchRef]SearchMeta, error) {
	if s == nil {
		return nil, ErrNotConfigured
	}
	if tid.IsZero() {
		return nil, ErrNoTenant
	}
	out := make(map[SearchRef]SearchMeta, len(hits))
	if len(hits) == 0 {
		return out, nil
	}
	if len(hits) > MaxSearchMetaRefs {
		return nil, ErrTooMany
	}
	conns, objs := make([]string, 0, len(hits)), make([]string, 0, len(hits))
	var userGUIDs []authz.ObjectID
	for _, h := range hits {
		c, okc := canon(h.Connection)
		o, oko := canon(h.Object)
		if !okc || !oko {
			return nil, ErrInvalid
		}
		conns, objs = append(conns, c), append(objs, o)
		if h.Group == reportsql.TypeUser {
			id, err := authz.ParseObjectID(o)
			if err != nil {
				return nil, ErrInvalid
			}
			userGUIDs = append(userGUIDs, id)
		}
	}
	rows, err := tx.Query(ctx, `SELECT o.connection_id::text, o.object_guid::text, o.dn, o.sam_account_name, o.upn,
			CASE WHEN jsonb_typeof(o.attributes -> 'mail') = 'string' THEN o.attributes ->> 'mail' ELSE '' END,
			CASE WHEN jsonb_typeof(o.attributes -> 'title') = 'string' THEN o.attributes ->> 'title' ELSE '' END,
			CASE WHEN jsonb_typeof(o.attributes -> 'physicalDeliveryOfficeName') = 'string' THEN o.attributes ->> 'physicalDeliveryOfficeName' ELSE '' END,
			CASE WHEN jsonb_typeof(o.attributes -> 'department') = 'string' THEN o.attributes ->> 'department' ELSE '' END,
			(EXISTS (SELECT 1 FROM public.tier0_designations d
				WHERE d.tenant_id = o.tenant_id AND d.connection_id = o.connection_id AND d.object_guid = o.object_guid AND d.removed_at IS NULL)
			 OR EXISTS (SELECT 1 FROM public.correlations c
				WHERE c.tenant_id = o.tenant_id AND c.state <> 'removed' AND c.facts_as_of IS NOT NULL
				AND ((c.ad_connection_id = o.connection_id AND c.ad_object_guid = o.object_guid AND c.ad_tier0)
				  OR (c.entra_connection_id = o.connection_id AND c.entra_object_guid = o.object_guid AND c.entra_tier0)))) AS tier0,
			(o.nc_guid IS NULL AND o.kind IN ('user', 'group') AND o.state = 'active'
			 AND o.on_prem_sync_enabled IS NOT TRUE AND o.on_prem_cloud_managed IS NOT TRUE
			 AND (o.kind = 'user' OR o.attributes ? 'onPremisesSyncEnabled')) AS cloud_only
		FROM public.directory_objects o
		JOIN unnest($2::uuid[], $3::uuid[]) AS k (connection_id, object_guid)
		  ON o.connection_id = k.connection_id AND o.object_guid = k.object_guid
		WHERE o.tenant_id = $1::uuid`, tid.String(), conns, objs)
	if err != nil {
		return nil, fmt.Errorf("inventory: search metadata: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var r SearchRef
		var m SearchMeta
		if err := rows.Scan(&r.Connection, &r.Object, &m.DN, &m.SAMAccountName, &m.UserPrincipalName, &m.Mail,
			&m.Title, &m.Office, &m.Department, &m.Status.Tier0, &m.Status.CloudOnly); err != nil {
			return nil, fmt.Errorf("inventory: search metadata: %w", err)
		}
		out[r] = m
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("inventory: search metadata: %w", err)
	}
	rows.Close()
	if len(userGUIDs) == 0 {
		return out, nil
	}
	return out, s.userStates(ctx, tx, scope, now, userGUIDs, out)
}

// userStates reads the locked-out, password and account-expiry states of the user hits through the
// inventory.users report dataset: the same compiled derivation the user and password reports run, with the
// caller's scope and the same now. An input the sync did not read comes back Unknown and leaves the status empty.
func (s *Searcher) userStates(ctx context.Context, tx store.Tx, scope authz.ReadScope, now time.Time, guids []authz.ObjectID, out map[SearchRef]SearchMeta) error {
	vals := make([]report.Value, len(guids))
	for i, g := range guids {
		vals[i] = report.GUIDV(g)
	}
	def := report.Definition{ID: "search-status", Version: 1, Category: report.CategoryUsers, Title: "Search status", Dataset: DatasetUsers,
		Columns: statusCols, Presets: []report.Preset{{ID: "all", Where: report.Cmp{Column: colGUID, Op: report.OpIn, Values: vals}}}}
	rq, err := report.Resolve(def, "all", report.RunParams{}, s.usersSrc)
	if err != nil {
		return fmt.Errorf("inventory: search status: %w", err)
	}
	cq, err := reportsql.Compile(rq, s.users, scope, reportsql.Inputs{Now: now, Limit: len(guids)})
	if err != nil {
		return fmt.Errorf("inventory: search status: %w", err)
	}
	rows, err := reportsql.ExecAll(ctx, tx, cq, len(guids))
	if err != nil {
		return fmt.Errorf("inventory: search status: %w", err)
	}
	type idPair struct{ conn, obj authz.ObjectID }
	byID := make(map[idPair]SearchRef, len(out))
	for r := range out {
		c, errC := authz.ParseObjectID(r.Connection)
		o, errO := authz.ParseObjectID(r.Object)
		if errC == nil && errO == nil {
			byID[idPair{c, o}] = r
		}
	}
	for _, row := range rows {
		cell := func(c report.ColumnID) report.Cell { return row.Cells[slices.Index(statusCols, c)] }
		ref, ok := byID[idPair{cell(colConn).GUID(), cell(colGUID).GUID()}]
		if !ok {
			continue
		}
		m, ok := out[ref]
		if !ok {
			continue
		}
		st := &m.Status
		if c := cell(colLocked); c.Kind() == report.CellEnum && c.Text() == "locked" {
			st.Locked = true
			if t := cell(colLockTime); t.Kind() == report.CellTime {
				st.LockedAt = t.Time()
			}
		}
		if c := cell(colPwdState); c.Kind() == report.CellEnum {
			switch c.Text() {
			case "expired":
				st.PasswordExpired = true
			case "expires":
				if d := cell(colPwdDays); d.Kind() == report.CellInt {
					n := d.Int()
					st.PasswordExpiresInDays = &n
				}
			}
		}
		if c := cell(colAcctState); c.Kind() == report.CellEnum && (c.Text() == "expired" || c.Text() == "not_expired") {
			if t := cell(colAcctExpire); t.Kind() == report.CellTime {
				st.AccountExpires = t.Time()
			}
		}
		out[ref] = m
	}
	return nil
}
