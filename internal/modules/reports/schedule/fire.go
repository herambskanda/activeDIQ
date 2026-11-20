package schedule

import (
	"context"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/skenzeriq/activediq/internal/modules/reports/export"
	"github.com/skenzeriq/activediq/internal/modules/reports/run"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/audit/chain"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/notify/delivery"
	"github.com/skenzeriq/activediq/internal/platform/notify/settings"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/rbac"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Job kinds (EP-5). The tick turns due schedules into fires; a fire is one occurrence, staged across job
// invocations because the run and the exports it needs are jobs themselves.
const (
	TickKind = "reports.schedule.tick"
	FireKind = "reports.schedule.fire"
)

// Purposes of the DM-84 deliveries a fire makes; the Renderer of each is in render.go.
const (
	PurposeDelivery = "reports.schedule.delivery"
	PurposePaused   = "reports.schedule.paused"
	// SourceSchedule is the DM-84 source kind of a delivery about a schedule.
	SourceSchedule = "report_schedule"
)

// Stable reason codes of a fire and of a recipient that failed alone (reports.md 8, AC-31..33, AC-46).
const (
	ReasonNotActive         = "schedule_not_active"
	ReasonRunTimeout        = "run_timeout"
	ReasonRunFailed         = "run_failed"
	ReasonAllFailed         = "all_recipients_failed"
	ReasonNoAddress         = "no_address"
	ReasonRecipientInactive = "recipient_not_active"
	ReasonAccountExternal   = "account_address_external"
	ReasonBecameExternal    = "address_became_external"
	ReasonOwnerExternal     = "owner_external_not_permitted"
	ReasonFormatUnavailable = "format_unavailable"
	ReasonNotAttachable     = "format_not_attachable"
	ReasonTooLarge          = "attachment_too_large"
	ReasonExportFailed      = "export_failed"
)

const (
	fireDeadline = 30 * time.Minute
	pollEvery    = 10 * time.Second
	tickEvery    = time.Minute
	dueBatch     = 200
	// MaxAttachmentBytes is the most a message carries as attachments (10 MB): an account gets links instead
	// beyond it, an external address fails alone.
	MaxAttachmentBytes = 10 << 20
	nilUUID            = "00000000-0000-0000-0000-000000000000"
)

// Fire runs the schedules: the tick and the fire job. Every field is required.
type Fire struct {
	*Env
	DB         *store.DB
	Jobs       *jobs.Registry
	Runs       *run.Service
	Exports    *export.Service
	Deliveries *delivery.Deliveries
	Audit      audit.Sink
	Log        *slog.Logger
}

var systemActor = authority.Chain{Requester: authority.Principal{ID: "reports-scheduler", Kind: authority.System}}

func ownerChain(owner string) authority.Chain {
	return authority.Chain{Requester: authority.Principal{ID: authority.PrincipalID(owner), Kind: authority.Human}}
}

func (f *Fire) log() *slog.Logger {
	if f.Log != nil {
		return f.Log
	}
	return slog.Default()
}

type fireArgs struct {
	FireID string `json:"fireId"`
	Tick   bool   `json:"tick,omitempty"`
}

// Kinds returns the two job kinds, each with its seed (the tick is seeded per tenant on every boot).
func (f *Fire) Kinds() []jobs.Kind {
	return []jobs.Kind{
		{Name: TickKind, Timeout: 5 * time.Minute, Mode: jobs.ModeManagedTx, RunManaged: f.tickJob},
		{Name: FireKind, Timeout: 10 * time.Minute, Mode: jobs.ModeManagedTx, RunManaged: f.fireJob,
			ValidateArgs: func(args jsontext.Value) error {
				var a fireArgs
				if err := jsonv2.Unmarshal(args, &a); err != nil || !uuidRe.MatchString(a.FireID) {
					return errors.New("reports.schedule.fire: bad args")
				}
				return nil
			}},
	}
}

// SeedTick schedules the tenant's tick; it is safe on every boot and on several nodes (keyed by minute).
func (f *Fire) SeedTick(ctx context.Context, tx store.Tx, tid tenant.ID) error {
	return f.enqueueTick(ctx, tx, tid, f.now())
}

func (f *Fire) enqueueTick(ctx context.Context, tx store.Tx, tid tenant.ID, at time.Time) error {
	_, err := f.Jobs.Enqueue(ctx, tx, jobs.Job{Kind: TickKind, Tenant: tid, Args: struct{}{},
		UniqueKey: "t:" + at.UTC().Truncate(time.Minute).Format("200601021504"), RunAt: at})
	return err
}

// tickJob enqueues one fire per due schedule and moves next_run_at to the first occurrence after now. A
// schedule that was due several times while the system was down fires once, for the oldest occurrence it
// missed (the missed-run policy: coalesce, never a burst of reports); the unique (schedule, due_at) makes a
// repeated tick enqueue nothing.
func (f *Fire) tickJob(ctx context.Context, jt jobs.TenantTx, c jobs.Claimed) error {
	return jt.Run(ctx, func(ctx context.Context, tx store.Tx) error {
		now := f.now()
		rows, err := tx.Query(ctx, `SELECT id::text FROM public.report_schedules
			WHERE state = 'active' AND next_run_at <= $1 ORDER BY next_run_at LIMIT $2 FOR UPDATE SKIP LOCKED`, now, dueBatch)
		if err != nil {
			return err
		}
		var ids []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, id := range ids {
			s, err := f.Store.Get(ctx, tx, id, true)
			if errors.Is(err, ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			if s.State != Active || s.NextRunAt == nil || s.NextRunAt.After(now) {
				continue
			}
			if _, err := f.queueFire(ctx, tx, c.Tenant, s.ID, *s.NextRunAt); err != nil {
				return err
			}
			nx, err := s.Recurrence.NextAfter(s.TimeZone, now)
			var nxp *time.Time
			if err != nil {
				f.log().Error("reports.schedule: no next occurrence; the schedule is not due again until it is rewritten", "schedule", s.ID, "err", err)
			} else {
				nxp = &nx
			}
			if _, err := tx.Exec(ctx, `UPDATE public.report_schedules SET next_run_at = $2, last_fire_at = $3 WHERE id = $1::uuid`, s.ID, nxp, now); err != nil {
				return err
			}
		}
		return f.enqueueTick(ctx, tx, c.Tenant, now.Add(tickEvery))
	})
}

// QueueNow records a fire due now for the schedule (run now) and enqueues its job. It returns the fire id.
func (f *Fire) QueueNow(ctx context.Context, tx store.Tx, tid tenant.ID, scheduleID string) (string, error) {
	return f.queueFire(ctx, tx, tid, scheduleID, f.now())
}

func (f *Fire) queueFire(ctx context.Context, tx store.Tx, tid tenant.ID, scheduleID string, due time.Time) (string, error) {
	id := run.NewID().String()
	tag, err := tx.Exec(ctx, `INSERT INTO public.report_schedule_fires (tenant_id, schedule_id, due_at, id, state)
		VALUES (NULLIF(current_setting('app.tenant_id', true), '')::uuid, $1::uuid, $2, $3::uuid, 'queued') ON CONFLICT DO NOTHING`, scheduleID, due.UTC().Truncate(time.Microsecond), id)
	if err != nil {
		return "", err
	}
	if tag.RowsAffected() == 0 {
		return "", nil // this occurrence is already recorded
	}
	return id, f.enqueueFire(ctx, tx, tid, id, f.now())
}

func (f *Fire) enqueueFire(ctx context.Context, tx store.Tx, tid tenant.ID, id string, at time.Time) error {
	_, err := f.Jobs.Enqueue(ctx, tx, jobs.Job{Kind: FireKind, Tenant: tid, Args: fireArgs{FireID: id}, RunAt: at,
		UniqueKey: "fire:" + id + ":" + strconv.FormatInt(at.Unix(), 10)})
	return err
}

type fireRow struct {
	ID         string
	ScheduleID string
	State      string
	Reason     string
	RunID      string
	Exports    map[string]string
	Created    time.Time
}

func (r fireRow) terminal() bool {
	return r.State != "queued" && r.State != "running"
}

func loadFire(ctx context.Context, tx store.Tx, id string) (fireRow, error) {
	var r fireRow
	var ex []byte
	err := tx.QueryRow(ctx, `SELECT id::text, schedule_id::text, state, COALESCE(reason, ''), COALESCE(run_id::text, ''), exports, created_at
		FROM public.report_schedule_fires WHERE id = $1::uuid FOR UPDATE`, id).Scan(&r.ID, &r.ScheduleID, &r.State, &r.Reason, &r.RunID, &ex, &r.Created)
	if store.IsNoRows(err) {
		return r, ErrNotFound
	}
	if err != nil {
		return r, err
	}
	r.Exports = map[string]string{}
	return r, jsonv2.Unmarshal(ex, &r.Exports)
}

type action int

const (
	actDone action = iota
	actWait
	actRun
	actExports
)

type decision struct {
	act      action
	fire     fireRow
	sched    Schedule
	formats  []string // actExports: the formats still to make
	deadline bool
}

// fireJob advances one fire as far as it can without waiting, then (when it must wait for the run or an
// export) enqueues itself again ten seconds on. Each step re-reads the world, so a crash anywhere repeats a
// step and never a send: the delivery rows are keyed by (fire, recipient).
func (f *Fire) fireJob(ctx context.Context, jt jobs.TenantTx, c jobs.Claimed) error {
	var a fireArgs
	if err := jsonv2.Unmarshal(c.Args, &a); err != nil {
		return &jobs.Failure{Code: "bad_args", Permanent: true}
	}
	for range 6 {
		var d decision
		if err := jt.Run(ctx, func(ctx context.Context, tx store.Tx) (err error) {
			d, err = f.decide(ctx, tx, c.Tenant, a.FireID)
			return err
		}); err != nil {
			if errors.Is(err, ErrNotFound) {
				return nil
			}
			return err
		}
		switch d.act {
		case actDone:
			return nil
		case actWait:
			return jt.Run(ctx, func(ctx context.Context, tx store.Tx) error {
				return f.enqueueFire(ctx, tx, c.Tenant, a.FireID, f.now().Add(pollEvery))
			})
		case actRun:
			if err := f.startRun(ctx, jt, c.Tenant, d); err != nil {
				return err
			}
		case actExports:
			if err := f.startExports(ctx, jt, c.Tenant, d); err != nil {
				return err
			}
		}
	}
	return jt.Run(ctx, func(ctx context.Context, tx store.Tx) error {
		return f.enqueueFire(ctx, tx, c.Tenant, a.FireID, f.now().Add(pollEvery))
	})
}

// decide reads the fire and decides its next step; the terminal steps (pause, fail, deliver) are done here,
// in the same transaction as the read, under the fire's row lock.
func (f *Fire) decide(ctx context.Context, tx store.Tx, tid tenant.ID, fireID string) (decision, error) {
	fr, err := loadFire(ctx, tx, fireID)
	if err != nil {
		return decision{}, err
	}
	if fr.terminal() {
		return decision{act: actDone}, nil
	}
	s, err := f.Store.Get(ctx, tx, fr.ScheduleID, true)
	if err != nil {
		return decision{}, err
	}
	d := decision{fire: fr, sched: s}
	now := f.now()
	if fr.RunID == "" {
		if s.State != Active {
			return d, f.finishFire(ctx, tx, fr, "paused", ReasonNotActive, nil, nil, nil)
		}
		reason, err := f.ownerReason(ctx, tx, tid, s)
		if err != nil {
			return d, err
		}
		if reason != "" {
			return d, f.systemPause(ctx, tx, tid, s, fr, reason)
		}
		d.act = actRun
		return d, nil
	}
	rid, err := run.ParseID(fr.RunID)
	if err != nil {
		return d, err
	}
	r, err := f.Runs.Peek(ctx, tx, rid)
	if err != nil {
		return d, err
	}
	late := now.After(fr.Created.Add(fireDeadline))
	switch r.State {
	case run.StateQueued, run.StateRunning:
		if late {
			return d, f.finishFire(ctx, tx, fr, "failed", ReasonRunTimeout, &r, nil, nil)
		}
		d.act = actWait
		return d, nil
	case run.StateSucceeded:
	default:
		return d, f.finishFire(ctx, tx, fr, "failed", ReasonRunFailed, &r, nil, nil)
	}
	if rows := deref(r.RowCount); rows == 0 && s.NotifyOnlyIfData {
		return d, f.finishFire(ctx, tx, fr, "nothing_to_send", "", &r, nil, nil)
	}
	var missing []string
	for _, fm := range needFormats(s.Recipients) {
		if _, ok := fr.Exports[fm]; !ok {
			missing = append(missing, fm)
		}
	}
	if len(missing) > 0 {
		d.act, d.formats = actExports, missing
		return d, nil
	}
	pending := false
	for _, id := range fr.Exports {
		eid, err := export.ParseID(id)
		if err != nil {
			continue // a marker, not an export
		}
		e, err := export.Peek(ctx, tx, eid)
		if err != nil {
			return d, err
		}
		if e.State == export.StateQueued || e.State == export.StateRunning {
			pending = true
		}
	}
	if pending {
		if late {
			return d, f.finishFire(ctx, tx, fr, "failed", ReasonRunTimeout, &r, nil, nil)
		}
		d.act = actWait
		return d, nil
	}
	return d, f.deliver(ctx, tx, tid, s, fr, r)
}

func deref(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

func needFormats(rs []Recipient) []string {
	var out []string
	for _, r := range rs {
		for _, fm := range r.Formats {
			if !slices.Contains(out, fm) {
				out = append(out, fm)
			}
		}
	}
	slices.Sort(out)
	return out
}

// ownerReason checks, at every fire, that the owner can still run the report (AC-31, AC-32): the account is
// active, still holds reports.run and still has a non-empty read scope. "" means yes.
func (f *Fire) ownerReason(ctx context.Context, tx store.Tx, tid tenant.ID, s Schedule) (string, error) {
	if ok, err := f.Owners.Active(ctx, tx, tid, s.Owner); err != nil {
		return "", err
	} else if !ok {
		return PauseOwnerDisabled, nil
	}
	err := f.CanWriteActive(ctx, tx, tid, ownerChain(s.Owner))
	var pr *operation.PlanRefusal
	if errors.As(err, &pr) {
		return PauseOwnerLostPerm, nil
	}
	return "", err
}

// startRun creates the fire's run as the owner. A run already made for this schedule since the fire began
// (a crash between the two commits) is adopted rather than made twice.
func (f *Fire) startRun(ctx context.Context, jt jobs.TenantTx, tid tenant.ID, d decision) error {
	s := d.sched
	var rid string
	err := f.DB.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) error {
		err := tx.QueryRow(ctx, `SELECT id::text FROM public.report_runs WHERE schedule_id = $1::uuid AND created_at >= $2
			ORDER BY created_at LIMIT 1`, s.ID, d.fire.Created).Scan(&rid)
		if store.IsNoRows(err) {
			return nil
		}
		return err
	})
	if err != nil {
		return err
	}
	if rid == "" {
		sid := s.ID
		r, _, err := f.Runs.Create(ctx, run.CreateInput{Tenant: tid, Chain: ownerChain(s.Owner), DefinitionID: s.DefinitionID,
			Version: s.DefinitionVersion, Preset: s.Preset, Params: s.Params, ScheduleID: &sid, Zone: s.TimeZone})
		if errors.Is(err, run.ErrDefinitionUnknown) {
			return jt.Run(ctx, func(ctx context.Context, tx store.Tx) error {
				return f.finishFire(ctx, tx, d.fire, "failed", ReasonRunFailed, nil, nil, nil)
			})
		}
		if err != nil {
			return err
		}
		rid = r.ID.String()
	}
	return jt.Run(ctx, func(ctx context.Context, tx store.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE public.report_schedule_fires SET run_id = $2::uuid, state = 'running' WHERE id = $1::uuid AND run_id IS NULL`, d.fire.ID, rid)
		return err
	})
}

// startExports makes one export per format the recipients need, as the owner. A format that cannot be made
// (the table is too wide for it, the result is over its cap) is recorded as a marker; the recipients that
// asked for it fail alone with format_unavailable.
func (f *Fire) startExports(ctx context.Context, jt jobs.TenantTx, tid tenant.ID, d decision) error {
	rid, err := run.ParseID(d.fire.RunID)
	if err != nil {
		return err
	}
	made := map[string]string{}
	for _, fm := range d.formats {
		e, err := f.Exports.Create(ctx, tid, ownerChain(d.sched.Owner), rid, export.Format(fm))
		var capErr *export.CapError
		switch {
		case errors.Is(err, export.ErrFormatUnavailable), errors.As(err, &capErr):
			made[fm] = "unavailable"
		case err != nil:
			return err
		default:
			made[fm] = e.ID.String()
		}
	}
	b, _ := jsonv2.Marshal(made)
	return jt.Run(ctx, func(ctx context.Context, tx store.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE public.report_schedule_fires SET exports = exports || $2::jsonb WHERE id = $1::uuid`, d.fire.ID, string(b))
		return err
	})
}

// RecipientResult is one recipient's outcome of a fire (report_schedule_fires.recipients).
type RecipientResult struct {
	Ordinal int    `json:"ordinal"`
	Outcome string `json:"outcome"` // queued | failed
	Reason  string `json:"reason,omitempty"`
}

func (f *Fire) finishFire(ctx context.Context, tx store.Tx, fr fireRow, state, reason string, r *run.Run, rows *int64, rec []RecipientResult) error {
	var scope []byte
	var rc *int64 = rows
	if r != nil {
		scope, _ = jsonv2.Marshal(r.ScopeApplied)
		if rc == nil {
			rc = r.RowCount
		}
	}
	var scopeArg *string
	if scope != nil {
		x := string(scope)
		scopeArg = &x
	}
	var reasonArg *string
	if reason != "" {
		reasonArg = &reason
	}
	if rec == nil {
		rec = []RecipientResult{}
	}
	rb, _ := jsonv2.Marshal(rec)
	if _, err := tx.Exec(ctx, `UPDATE public.report_schedule_fires SET state = $2, reason = $3, scope_applied = $4::jsonb, row_count = $5,
		recipients = $6::jsonb, finished_at = $7 WHERE id = $1::uuid`, fr.ID, state, reasonArg, scopeArg, rc, string(rb), f.now()); err != nil {
		return err
	}
	queued, failed := 0, 0
	for _, x := range rec {
		if x.Outcome == "queued" {
			queued++
		} else {
			failed++
		}
	}
	out := audit.Success
	if state == "failed" || state == "paused" {
		out = audit.Failure
	}
	runID := ""
	rowsText := ""
	if r != nil {
		runID = r.ID.String()
	}
	if rc != nil {
		rowsText = strconv.FormatInt(*rc, 10)
	}
	return f.Audit.Append(ctx, tx, audit.Event{ID: "reports.schedule.fire:" + fr.ID + ":finished", Kind: AuditFired, At: f.now(), Actor: systemActor,
		Target: target(fr.ScheduleID), Component: "reports", Outcome: out, Reason: reason,
		Details: []chain.Detail{{Key: "fire_id", Value: fr.ID}, {Key: "recipients_failed", Value: strconv.Itoa(failed)},
			{Key: "recipients_queued", Value: strconv.Itoa(queued)}, {Key: "row_count", Value: rowsText}, {Key: "run_id", Value: runID},
			{Key: "state", Value: state}}})
}

// systemPause pauses the schedule because its owner can no longer run it, records why, tells the tenant's
// owners and sends nothing (AC-31, AC-32). The pause is a new version written as the system.
func (f *Fire) systemPause(ctx context.Context, tx store.Tx, tid tenant.ID, s Schedule, fr fireRow, reason string) error {
	c := s.Content()
	c.State, c.PauseReason = Paused, reason
	ver, err := f.Store.Replace(ctx, tx, s.ID, s.Version, c, nilUUID, f.now())
	if err != nil {
		return err
	}
	if err := f.Audit.Append(ctx, tx, audit.Event{ID: "reports.schedule:" + s.ID + ":system_paused:" + strconv.Itoa(ver), Kind: AuditSystemPaused,
		At: f.now(), Actor: systemActor, Target: target(s.ID), Component: "reports", Outcome: audit.Success, Reason: reason,
		Details: []chain.Detail{{Key: "fire_id", Value: fr.ID}, {Key: "version", Value: strconv.Itoa(ver)}}}); err != nil {
		return err
	}
	owners, err := (rbac.Owners{}).TenantOwners(ctx, tx, tid)
	if err != nil {
		return err
	}
	for _, o := range owners {
		if _, err := f.Deliveries.Enqueue(ctx, tx, delivery.NewDelivery{DedupKey: "paused:" + s.ID + ":" + strconv.Itoa(ver) + ":" + o,
			Purpose: PurposePaused, TemplateVersion: 1, Variables: map[string]string{"schedule": s.ID, "reason": reason},
			Recipient: delivery.Recipient{Account: o}, Source: delivery.SourceRef{Kind: SourceSchedule, ID: s.ID}}, systemActor); err != nil {
			return err
		}
	}
	return f.finishFire(ctx, tx, fr, "paused", reason, nil, nil, nil)
}

// deliver evaluates every recipient again now and queues one delivery per recipient that passes. Each fails
// alone with a stable reason (AC-33, AC-46): the classification is the one in force now, never the one at
// write time, and the owner's authority to send outside the organisation is checked again.
func (f *Fire) deliver(ctx context.Context, tx store.Tx, tid tenant.ID, s Schedule, fr fireRow, r run.Run) error {
	cfg, err := (settings.Store{}).Get(ctx, tx)
	if err != nil {
		return err
	}
	ownerExt, err := f.allow(ctx, tid, ownerChain(s.Owner), f.Perm.DeliverExternal)
	if err != nil {
		return err
	}
	type file struct {
		fmt  string
		id   string
		size int64
	}
	files := map[string]file{}
	exportFailed := map[string]bool{}
	for fm, id := range fr.Exports {
		eid, err := export.ParseID(id)
		if err != nil {
			continue
		}
		e, err := export.Peek(ctx, tx, eid)
		if err != nil {
			return err
		}
		if e.State != export.StateSucceeded {
			exportFailed[fm] = true
			continue
		}
		files[fm] = file{fm, id, deref(e.ByteSize)}
	}
	var res []RecipientResult
	for i, rc := range s.Recipients {
		fail := func(reason string) error {
			res = append(res, RecipientResult{Ordinal: i, Outcome: "failed", Reason: reason})
			return f.Audit.Append(ctx, tx, audit.Event{ID: "reports.schedule.fire:" + fr.ID + ":" + strconv.Itoa(i) + ":failed", Kind: AuditDeliveryFailed,
				At: f.now(), Actor: systemActor, Target: target(s.ID), Component: "reports", Outcome: audit.Failure, Reason: reason,
				Details: []chain.Detail{{Key: "fire_id", Value: fr.ID}, {Key: "ordinal", Value: strconv.Itoa(i)}}})
		}
		var rcpt delivery.Recipient
		var addr string
		if rc.Kind == recipientKindAccount {
			if ok, err := f.Owners.Active(ctx, tx, tid, rc.AccountID); err != nil {
				return err
			} else if !ok {
				if err := fail(ReasonRecipientInactive); err != nil {
					return err
				}
				continue
			}
			addr, err = f.Accounts.MailAddress(ctx, tx, rc.AccountID)
			if errors.Is(err, delivery.ErrNoAddress) {
				if err := fail(ReasonNoAddress); err != nil {
					return err
				}
				continue
			} else if err != nil {
				return err
			}
			rcpt = delivery.Recipient{Account: rc.AccountID}
		} else {
			addr, rcpt = rc.Address, delivery.Recipient{Address: rc.Address}
		}
		a, class, perr := cfg.ClassifyString(addr)
		if perr != nil {
			if err := fail(ReasonNoAddress); err != nil {
				return err
			}
			continue
		}
		link := rc.AsLink
		if class == settings.External {
			switch {
			case rc.Kind == recipientKindAccount && !link:
				if err := fail(ReasonAccountExternal); err != nil {
					return err
				}
				continue
			case !slices.Contains(s.ConfirmedExternal, a.String()):
				if err := fail(ReasonBecameExternal); err != nil {
					return err
				}
				continue
			case !ownerExt:
				if err := fail(ReasonOwnerExternal); err != nil {
					return err
				}
				continue
			}
		}
		var use []file
		reason := ""
		for _, fm := range rc.Formats {
			x, ok := files[fm]
			switch {
			case !ok && exportFailed[fm]:
				reason = ReasonExportFailed
			case !ok:
				reason = ReasonFormatUnavailable
			case fm == "html" && !link:
				reason = ReasonNotAttachable
			default:
				use = append(use, x)
			}
		}
		if len(use) == 0 {
			if err := fail(reason); err != nil {
				return err
			}
			continue
		}
		if !link {
			var total int64
			for _, x := range use {
				total += x.size
			}
			if total > MaxAttachmentBytes {
				if rc.Kind != recipientKindAccount {
					if err := fail(ReasonTooLarge); err != nil {
						return err
					}
					continue
				}
				link = true // an account gets links beyond the limit
			}
		}
		if link {
			for _, x := range use {
				if _, err := f.Deliveries.Enqueue(ctx, tx, delivery.NewDelivery{DedupKey: fr.ID + ":" + strconv.Itoa(i) + ":" + x.fmt,
					Purpose: PurposeDelivery, TemplateVersion: 1, Recipient: rcpt,
					Variables: map[string]string{"fire": fr.ID, "mode": "link", "exports": x.id, "schedule": s.ID},
					Source:    delivery.SourceRef{Kind: export.SourceKind, ID: x.id}}, ownerChain(s.Owner)); err != nil {
					return err
				}
			}
		} else {
			ids := make([]string, len(use))
			for j, x := range use {
				ids[j] = x.id
			}
			if _, err := f.Deliveries.Enqueue(ctx, tx, delivery.NewDelivery{DedupKey: fr.ID + ":" + strconv.Itoa(i),
				Purpose: PurposeDelivery, TemplateVersion: 1, Recipient: rcpt, RequireInternal: true,
				Variables: map[string]string{"fire": fr.ID, "mode": "attachment", "exports": strings.Join(ids, ","), "schedule": s.ID},
				Source:    delivery.SourceRef{Kind: export.SourceKind, ID: use[0].id}}, ownerChain(s.Owner)); err != nil {
				return err
			}
		}
		res = append(res, RecipientResult{Ordinal: i, Outcome: "queued"})
	}
	state, reason := "sent", ""
	if !slices.ContainsFunc(res, func(x RecipientResult) bool { return x.Outcome == "queued" }) {
		state, reason = "failed", ReasonAllFailed
	}
	return f.finishFire(ctx, tx, fr, state, reason, &r, nil, res)
}

// Last is the latest fire of a schedule: what the schedule view shows as lastRun and as each recipient's
// delivery.
type Last struct {
	ID         string
	State      string
	Reason     string
	RunID      string
	Exports    map[string]string
	Recipients []RecipientResult
	StartedAt  time.Time
	UpdatedAt  time.Time
}

// LastFire reads the latest finished or running fire of the schedule; nil when it never fired.
func (Store) LastFire(ctx context.Context, tx store.Tx, scheduleID string) (*Last, error) {
	var l Last
	var ex, rc []byte
	var fin *time.Time
	err := tx.QueryRow(ctx, `SELECT id::text, state, COALESCE(reason, ''), COALESCE(run_id::text, ''), exports, recipients, created_at, finished_at
		FROM public.report_schedule_fires WHERE schedule_id = $1::uuid ORDER BY due_at DESC LIMIT 1`, scheduleID).Scan(&l.ID, &l.State, &l.Reason, &l.RunID, &ex, &rc, &l.StartedAt, &fin)
	if store.IsNoRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	l.UpdatedAt = l.StartedAt
	if fin != nil {
		l.UpdatedAt = *fin
	}
	if err := jsonv2.Unmarshal(ex, &l.Exports); err != nil {
		return nil, err
	}
	return &l, jsonv2.Unmarshal(rc, &l.Recipients)
}

// ExportFor is the export a recipient's delivery is about (the first of its formats that was made), which is
// the source of its DM-84 row.
func (l Last) ExportFor(r Recipient) string {
	for _, fm := range r.Formats {
		if id, ok := l.Exports[fm]; ok && uuidRe.MatchString(id) {
			return id
		}
	}
	return ""
}
