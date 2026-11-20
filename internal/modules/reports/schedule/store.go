package schedule

import (
	"context"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/store"
)

// ErrNotFound: no such schedule in the tenant (RLS makes another tenant's the same answer).
var ErrNotFound = errors.New("schedule: not found")

// ErrStale: the schedule is not at the version the write was planned against.
var ErrStale = errors.New("schedule: changed since the plan")

// Store reads and writes DM-73. It holds no state; every method runs in the caller's tenant transaction
// (RLS scopes it), and the writes are called only by the Actions and the fire job.
type Store struct{}

const cols = `id::text, name, definition_id, definition_version, COALESCE(preset, ''), params, recurrence, time_zone,
  owner_account::text, notify_only_if_data, confirmed_external, state, COALESCE(pause_reason, ''), version, next_run_at,
  last_fire_at, created_by::text, created_at, updated_at`

const selectSchedule = `SELECT ` + cols + ` FROM public.report_schedules WHERE id = $1::uuid`
const selectScheduleForUpdate = selectSchedule + ` FOR UPDATE`

func scan(row interface{ Scan(...any) error }) (Schedule, error) {
	var s Schedule
	var params, rec []byte
	var state string
	if err := row.Scan(&s.ID, &s.Name, &s.DefinitionID, &s.DefinitionVersion, &s.Preset, &params, &rec, &s.TimeZone, &s.Owner,
		&s.NotifyOnlyIfData, &s.ConfirmedExternal, &state, &s.PauseReason, &s.Version, &s.NextRunAt, &s.LastFireAt, &s.CreatedBy,
		&s.CreatedAt, &s.UpdatedAt); err != nil {
		return Schedule{}, err
	}
	s.State, s.Params = State(state), jsontext.Value(params)
	if err := jsonv2.Unmarshal(rec, &s.Recurrence); err != nil {
		return Schedule{}, fmt.Errorf("schedule: corrupt recurrence: %w", err)
	}
	return s, nil
}

func (Store) recipients(ctx context.Context, tx store.Tx, id string) ([]Recipient, error) {
	rows, err := tx.Query(ctx, `SELECT kind, COALESCE(account::text, ''), COALESCE(address, ''), formats, delivery
		FROM public.report_schedule_recipients WHERE schedule_id = $1::uuid ORDER BY ordinal`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Recipient{}
	for rows.Next() {
		var r Recipient
		var kind, del string
		if err := rows.Scan(&kind, &r.AccountID, &r.Address, &r.Formats, &del); err != nil {
			return nil, err
		}
		r.Kind, r.AsLink = recipientKindEmail, del == "link"
		if kind == "account" {
			r.Kind = recipientKindAccount
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Get reads one schedule with its recipients. forUpdate locks the row for a write.
func (st Store) Get(ctx context.Context, tx store.Tx, id string, forUpdate bool) (Schedule, error) {
	if !uuidRe.MatchString(id) {
		return Schedule{}, ErrNotFound
	}
	var row interface{ Scan(...any) error }
	if forUpdate {
		row = tx.QueryRow(ctx, selectScheduleForUpdate, id)
	} else {
		row = tx.QueryRow(ctx, selectSchedule, id)
	}
	s, err := scan(row)
	if store.IsNoRows(err) {
		return Schedule{}, ErrNotFound
	}
	if err != nil {
		return Schedule{}, err
	}
	s.Recipients, err = st.recipients(ctx, tx, id)
	return s, err
}

// Exists reports whether the id is taken, whatever its state.
func (Store) Exists(ctx context.Context, tx store.Tx, id string) (bool, error) {
	var ok bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM public.report_schedules WHERE id = $1::uuid)`, id).Scan(&ok)
	return ok, err
}

// Page is one page of the list. After is the keyset cursor (created_at, id) of the last item.
type Page struct {
	Items []Schedule
	Next  *Cursor
}

// Cursor is the keyset position in the list order (newest first).
type Cursor struct {
	At time.Time
	ID string
}

// List returns up to limit non-archived schedules, newest first. owner "" lists every owner's (the
// manage_all view); the caller has already decided whether that is allowed.
func (st Store) List(ctx context.Context, tx store.Tx, owner string, after *Cursor, limit int) (Page, error) {
	var ownerArg, idArg *string
	var atArg *time.Time
	if owner != "" {
		ownerArg = &owner
	}
	if after != nil {
		atArg, idArg = &after.At, &after.ID
	}
	rows, err := tx.Query(ctx, `SELECT `+cols+` FROM public.report_schedules
		WHERE state <> 'archived' AND ($1::uuid IS NULL OR owner_account = $1::uuid)
		  AND ($2::timestamptz IS NULL OR (created_at, id) < ($2::timestamptz, $3::uuid))
		ORDER BY created_at DESC, id DESC LIMIT $4`, ownerArg, atArg, idArg, limit+1)
	if err != nil {
		return Page{}, err
	}
	var out []Schedule
	for rows.Next() {
		s, err := scan(rows)
		if err != nil {
			rows.Close()
			return Page{}, err
		}
		out = append(out, s)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return Page{}, err
	}
	var p Page
	if len(out) > limit {
		out = out[:limit]
		last := out[len(out)-1]
		p.Next = &Cursor{At: last.CreatedAt, ID: last.ID}
	}
	for i := range out {
		if out[i].Recipients, err = st.recipients(ctx, tx, out[i].ID); err != nil {
			return Page{}, err
		}
	}
	p.Items = out
	return p, nil
}

// next is the next_run_at an active schedule holds after a write at now; a paused or archived one has none.
func next(c Content, now time.Time) (*time.Time, error) {
	if c.State != Active {
		return nil, nil
	}
	t, err := c.Recurrence.NextAfter(c.TimeZone, now)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (Store) writeRecipients(ctx context.Context, tx store.Tx, id string, rs []Recipient) error {
	if _, err := tx.Exec(ctx, `DELETE FROM public.report_schedule_recipients WHERE schedule_id = $1::uuid`, id); err != nil {
		return err
	}
	for i, r := range rs {
		var account, address *string
		kind, del := "address", "attachment"
		if r.Kind == recipientKindAccount {
			kind, account = "account", &r.AccountID
		} else {
			a, err := CanonicalAddress(r.Address)
			if err != nil {
				return err
			}
			address = &a
		}
		if r.AsLink {
			del = "link"
		}
		if _, err := tx.Exec(ctx, `INSERT INTO public.report_schedule_recipients
			(tenant_id, schedule_id, ordinal, kind, account, address, formats, delivery)
			VALUES (NULLIF(current_setting('app.tenant_id', true), '')::uuid, $1::uuid, $2, $3, $4::uuid, $5, $6, $7)`,
			id, i, kind, account, address, r.Formats, del); err != nil {
			return err
		}
	}
	return nil
}

func (Store) appendVersion(ctx context.Context, tx store.Tx, id string, version int, c Content, by string) error {
	b, err := jsonv2.Marshal(c)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO public.report_schedule_versions (tenant_id, schedule_id, version, content, written_by)
		VALUES (NULLIF(current_setting('app.tenant_id', true), '')::uuid, $1::uuid, $2, $3::jsonb, $4::uuid)`, id, version, string(b), by)
	return err
}

// Version reads the content a version wrote.
func (Store) Version(ctx context.Context, tx store.Tx, id string, version int) (Content, error) {
	var b []byte
	err := tx.QueryRow(ctx, `SELECT content FROM public.report_schedule_versions WHERE schedule_id = $1::uuid AND version = $2`, id, version).Scan(&b)
	if store.IsNoRows(err) {
		return Content{}, ErrNotFound
	}
	if err != nil {
		return Content{}, err
	}
	var c Content
	return c, jsonv2.Unmarshal(b, &c)
}

// Create inserts version 1.
func (st Store) Create(ctx context.Context, tx store.Tx, id string, c Content, by string, now time.Time) error {
	nx, err := next(c, now)
	if err != nil {
		return err
	}
	rec, _ := jsonv2.Marshal(c.Recurrence)
	var preset *string
	if c.Preset != "" {
		preset = &c.Preset
	}
	if _, err := tx.Exec(ctx, `INSERT INTO public.report_schedules
		(tenant_id, id, name, definition_id, definition_version, preset, params, recurrence, time_zone, owner_account,
		 notify_only_if_data, confirmed_external, state, pause_reason, version, next_run_at, created_by)
		VALUES (NULLIF(current_setting('app.tenant_id', true), '')::uuid, $1::uuid, $2, $3, $4, $5, $6::jsonb, $7::jsonb, $8, $9::uuid,
		 $10, $11, $12, $13, 1, $14, $15::uuid)`,
		id, c.Name, c.DefinitionID, c.DefinitionVersion, preset, string(c.Params), string(rec), c.TimeZone, c.Owner,
		c.NotifyOnlyIfData, nz(c.ConfirmedExternal), string(c.State), pauseArg(c), nx, by); err != nil {
		return err
	}
	if err := st.writeRecipients(ctx, tx, id, c.Recipients); err != nil {
		return err
	}
	return st.appendVersion(ctx, tx, id, 1, c, by)
}

// Replace writes c as the schedule's next version. from is the version the write was planned against: a
// different stored version is ErrStale, and nothing changes.
func (st Store) Replace(ctx context.Context, tx store.Tx, id string, from int, c Content, by string, now time.Time) (int, error) {
	nx, err := next(c, now)
	if err != nil {
		return 0, err
	}
	rec, _ := jsonv2.Marshal(c.Recurrence)
	var preset *string
	if c.Preset != "" {
		preset = &c.Preset
	}
	tag, err := tx.Exec(ctx, `UPDATE public.report_schedules SET name = $3, definition_id = $4, definition_version = $5, preset = $6,
		params = $7::jsonb, recurrence = $8::jsonb, time_zone = $9, owner_account = $10::uuid, notify_only_if_data = $11,
		confirmed_external = $12, state = $13, pause_reason = $14, version = version + 1, next_run_at = $15, updated_at = $16
		WHERE id = $1::uuid AND version = $2`,
		id, from, c.Name, c.DefinitionID, c.DefinitionVersion, preset, string(c.Params), string(rec), c.TimeZone, c.Owner,
		c.NotifyOnlyIfData, nz(c.ConfirmedExternal), string(c.State), pauseArg(c), nx, now)
	if err != nil {
		return 0, err
	}
	if tag.RowsAffected() != 1 {
		return 0, ErrStale
	}
	if err := st.writeRecipients(ctx, tx, id, c.Recipients); err != nil {
		return 0, err
	}
	if err := st.appendVersion(ctx, tx, id, from+1, c, by); err != nil {
		return 0, err
	}
	return from + 1, nil
}

func nz(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func pauseArg(c Content) *string {
	if c.State != Paused {
		return nil
	}
	r := c.PauseReason
	if r == "" {
		r = PauseByUser
	}
	return &r
}
