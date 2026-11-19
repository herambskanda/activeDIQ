package schedule

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/skenzeriq/activediq/internal/modules/reports/run"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/notify/delivery"
	"github.com/skenzeriq/activediq/internal/platform/notify/settings"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/rbac"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Permissions the schedule rules read. They are the reports module's (doc.go there); the module hands them in
// so this package does not import it.
type Permissions struct {
	Run, Schedule, ManageAll, DeliverExternal authz.Permission
}

// Authorizer answers whether a chain holds a permission at tenant scope (a failure refuses).
type Authorizer interface {
	Allow(ctx context.Context, tid tenant.ID, c authority.Chain, p authz.Permission) (bool, error)
}

// Env is everything the Actions and the fire job read. Every field is required except Now.
type Env struct {
	Store    Store
	Catalog  run.Catalog
	Codec    run.ParamsCodec
	Authz    Authorizer
	Owners   rbac.OwnerStatus
	Accounts delivery.Accounts
	Scopes   run.ReadScopes
	Perm     Permissions
	Now      func() time.Time
}

func (e *Env) now() time.Time {
	if e.Now != nil {
		return e.Now().UTC()
	}
	return time.Now().UTC()
}

// Audit kinds of the schedule Actions and of the system pause (TM-D30 SX-8).
const (
	AuditCreated  audit.Kind = "reports.schedule.created"
	AuditUpdated  audit.Kind = "reports.schedule.updated"
	AuditPaused   audit.Kind = "reports.schedule.paused"
	AuditResumed  audit.Kind = "reports.schedule.resumed"
	AuditReassign audit.Kind = "reports.schedule.reassigned"
	AuditDeleted  audit.Kind = "reports.schedule.deleted"
	AuditRestored audit.Kind = "reports.schedule.restored"
	// AuditSystemPaused is written by the fire job when an owner-authority check fails; it carries the reason.
	AuditSystemPaused audit.Kind = "reports.schedule.system_paused"
	// AuditFired records one fire: the run, the scope applied and the outcome.
	AuditFired audit.Kind = "reports.schedule.fired"
	// AuditDeliveryFailed records a recipient that failed alone, with its reason code (SX-8, AC-56).
	AuditDeliveryFailed audit.Kind = "reports.schedule.delivery_failed"
)

// Refusal codes of Plan (blocked[].code of a preview, errors[].code of a write).
const (
	CodeNotOwner           = "not_owner"
	CodeManageAllRequired  = "manage_all_required"
	CodeExternalNotAllowed = "external_not_permitted"
	CodeExternalUnconfirm  = "external_not_confirmed"
	CodeScopeEmpty         = "report_scope_empty"
	CodePerDCDaily         = "per_dc_no_more_than_daily"
	CodeOwnerNotActive     = "owner_not_active"
	CodeRunNotPermitted    = "report_run_not_permitted"
	CodeSuperseded         = "superseded"
	CodeNotActive          = "schedule_not_active"
	CodeAlreadyPaused      = "already_paused"
	CodeAlreadyActive      = "already_active"
	CodeUnknownDefinition  = "definition_unknown"
	CodeInvalidParameters  = "invalid_parameters"
)

func refuse(code string) error { return &operation.PlanRefusal{Code: code} }

// ConfirmExternal is the confirmation kind of external recipients (ADR-0004 rule 14).
const ConfirmExternal = "external_recipients"

// External classifies the recipients now (SX-5): an address outside the allowed domains is external, and so
// is an account whose own mail address is. The result is sorted, canonical and unique: the set a write
// confirms and the fire job re-evaluates. An account with no address is not external (the delivery fails with
// no_address instead).
func (e *Env) External(ctx context.Context, tx store.Tx, rs []Recipient) ([]string, error) {
	cfg, err := (settings.Store{}).Get(ctx, tx)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, r := range rs {
		addr := r.Address
		if r.Kind == recipientKindAccount {
			if addr, err = e.Accounts.MailAddress(ctx, tx, r.AccountID); errors.Is(err, delivery.ErrNoAddress) {
				continue
			} else if err != nil {
				return nil, err
			}
		}
		a, class, err := cfg.ClassifyString(addr)
		if err != nil {
			if r.Kind == recipientKindEmail {
				return nil, invalid("not a valid e-mail address")
			}
			continue
		}
		if class == settings.External && !slices.Contains(out, a.String()) {
			out = append(out, a.String())
		}
	}
	slices.Sort(out)
	return out, nil
}

// perDC reports whether the definition's columns include a per-DC attribute (USR-04, PWD-03).
func perDC(def run.Definition, q report.Query) bool {
	for _, c := range q.Columns {
		if col, ok := def.Dataset.Column(c); ok && col.IsPerDC() {
			return true
		}
	}
	return false
}

// Checked is a validated write: the definition pinned, the preset chosen, the parameters stored.
type Checked struct {
	Version int
	Preset  string
	Params  []byte
}

// CheckDefinition validates what the schedule runs: the definition and its pinned version, the preset, the
// parameters (typed, through the report codec and Resolve) and the per-DC floor (AC-38).
func (e *Env) CheckDefinition(in WriteInput) (Checked, error) {
	def, ok := e.Catalog.Definition(in.DefinitionID, in.DefinitionVersion)
	if !ok {
		return Checked{}, refuse(CodeUnknownDefinition)
	}
	preset := in.PresetID
	if preset == "" && len(def.Def.Presets) > 0 {
		preset = def.Def.Presets[0].ID
	}
	raw := in.Parameters
	if len(raw) == 0 {
		raw = []byte(`{}`)
	}
	rp, err := e.Codec.Decode(raw, def.Def)
	if err != nil {
		return Checked{}, refuse(CodeInvalidParameters)
	}
	q, err := report.Resolve(def.Def, preset, rp, def.Dataset)
	if err != nil {
		return Checked{}, refuse(CodeInvalidParameters)
	}
	if perDC(def, q) && in.Recurrence.MoreOftenThanDaily() {
		return Checked{}, refuse(CodePerDCDaily)
	}
	return Checked{Version: def.Def.Version, Preset: preset, Params: raw}, nil
}

func (e *Env) allow(ctx context.Context, tid tenant.ID, c authority.Chain, p authz.Permission) (bool, error) {
	if e.Authz == nil {
		return false, nil
	}
	return e.Authz.Allow(ctx, tid, c, p)
}

// CanWriteActive checks what an active schedule needs of its owner now: reports.run and a non-empty read scope
// (AC-31, AC-32 at write time; the fire job checks again at every fire).
func (e *Env) CanWriteActive(ctx context.Context, tx store.Tx, tid tenant.ID, owner authority.Chain) error {
	if ok, err := e.allow(ctx, tid, owner, e.Perm.Run); err != nil {
		return err
	} else if !ok {
		return refuse(CodeRunNotPermitted)
	}
	sc, err := e.Scopes.For(ctx, tx, tid, owner, run.Perm)
	if err != nil {
		return err
	}
	if sc.Empty() {
		return refuse(CodeScopeEmpty)
	}
	return nil
}

// SameSet reports whether two address lists hold the same addresses.
func SameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(x, y)
}

func subset(a, of []string) bool {
	for _, s := range a {
		if !slices.Contains(of, s) {
			return false
		}
	}
	return true
}
