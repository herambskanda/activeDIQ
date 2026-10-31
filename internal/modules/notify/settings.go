package notify

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/notify/settings"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
)

// The Action, its permission and its audit kind. The permission is in the control-plane family
// ("notify.", authz.NeverCrosses): it is personal to an account and no group, token or automation
// policy ever exercises it. No built-in role holds it; the tenant owner does by DM-34.I1.
const (
	UpdateSettingsActionID operation.ActionID = "notify.settings.update"
	PermUpdateSettings     authz.Permission   = "notify.settings.update"
	AuditSettingsUpdated   audit.Kind         = "notify.settings.updated"

	// TargetClassSettings is the class of the target the permission is checked at: the tenant's mail settings.
	TargetClassSettings = "notify_settings"
)

// SettingsInput replaces the tenant's mail settings whole: a domain not listed is removed, and an absent
// relay clears the relay.
type SettingsInput struct {
	AllowedDomains []string    `json:"allowedDomains"`
	Relay          *RelayInput `json:"relay,omitempty"`
}

// RelayInput is the SMTP relay. Security is starttls, tls or none; none needs PlaintextOptIn.
type RelayInput struct {
	Host           string `json:"host"`
	Port           int    `json:"port,omitempty"`
	Security       string `json:"security"`
	From           string `json:"from"`
	PlaintextOptIn bool   `json:"plaintextOptIn,omitempty"`
}

// settingsView is the stored shape, carried in the step payload as the before-image and the target.
type settingsView struct {
	AllowedDomains []string    `json:"allowedDomains"`
	Relay          *RelayInput `json:"relay,omitempty"`
}

type settingsPayload struct {
	Before      settingsView `json:"before"`
	After       settingsView `json:"after"`
	FromVersion int          `json:"fromVersion"`
	Tenant      string       `json:"tenant"`
}

// SettingsOutcome is the version written.
type SettingsOutcome struct {
	Version int `json:"version"`
}

func viewOf(s settings.Settings) settingsView {
	v := settingsView{AllowedDomains: slices.Clone(s.AllowedDomains)}
	if v.AllowedDomains == nil {
		v.AllowedDomains = []string{}
	}
	if r := s.Relay; r != nil {
		v.Relay = &RelayInput{Host: r.Host, Port: r.Port, Security: string(r.Security), From: r.From, PlaintextOptIn: r.PlaintextOptIn}
	}
	return v
}

func (v settingsView) update() settings.Update {
	u := settings.Update{AllowedDomains: v.AllowedDomains}
	if r := v.Relay; r != nil {
		u.Relay = &settings.Relay{Host: r.Host, Port: r.Port, Security: settings.Security(r.Security), From: r.From, PlaintextOptIn: r.PlaintextOptIn}
	}
	return u
}

func (v settingsView) input() SettingsInput { return SettingsInput(v) }

// diff lists the attributes that change, before and after. The relay carries no credential, so nothing
// here is secret.
func diff(before, after settingsView) []operation.Change {
	var out []operation.Change
	if !slices.Equal(before.AllowedDomains, after.AllowedDomains) {
		out = append(out, operation.Change{Attribute: "allowed_domains", Before: before.AllowedDomains, After: after.AllowedDomains})
	}
	field := func(name string, get func(*RelayInput) string) {
		var b, a []string
		if before.Relay != nil {
			b = []string{get(before.Relay)}
		}
		if after.Relay != nil {
			a = []string{get(after.Relay)}
		}
		if !slices.Equal(b, a) {
			out = append(out, operation.Change{Attribute: name, Before: b, After: a})
		}
	}
	field("smtp_host", func(r *RelayInput) string { return r.Host })
	field("smtp_port", func(r *RelayInput) string { return strconv.Itoa(r.Port) })
	field("smtp_security", func(r *RelayInput) string { return r.Security })
	field("smtp_from", func(r *RelayInput) string { return r.From })
	field("smtp_plaintext_opt_in", func(r *RelayInput) string { return strconv.FormatBool(r.PlaintextOptIn) })
	return out
}

// UpdateSettings builds the notify.settings.update Action.
func UpdateSettings() (operation.Action, error) {
	var st settings.Store
	return operation.Define(operation.Typed[SettingsInput, settingsPayload, SettingsOutcome]{
		Descriptor: operation.Descriptor{
			ID: UpdateSettingsActionID, Version: 1, Permission: PermUpdateSettings,
			Input:  "#/components/schemas/NotifySettingsUpdate",
			Target: operation.TargetStore, Reversibility: operation.Reversible, AuditKind: AuditSettingsUpdated,
			StepUp: true, ControlPlane: true,
		},
		Plan: func(ctx context.Context, pc operation.PlanContext, in SettingsInput) ([]operation.TypedStep[settingsPayload], error) {
			want := settings.Update{AllowedDomains: in.AllowedDomains}
			if r := in.Relay; r != nil {
				want.Relay = &settings.Relay{Host: r.Host, Port: r.Port, Security: settings.Security(r.Security), From: r.From, PlaintextOptIn: r.PlaintextOptIn}
			}
			n, err := want.Normalize()
			if err != nil {
				return nil, fmt.Errorf("%w: %s", operation.ErrInvalid, err.Error())
			}
			cur, err := st.Get(ctx, pc.Tx)
			if err != nil {
				return nil, err
			}
			var tid string
			if err := pc.Tx.QueryRow(ctx, `SELECT coalesce(current_setting('app.tenant_id', true), '')`).Scan(&tid); err != nil || tid == "" {
				return nil, errors.New("notify: no tenant context")
			}
			after := viewOf(settings.Settings{AllowedDomains: n.AllowedDomains, Relay: n.Relay})
			before := viewOf(cur)
			return []operation.TypedStep[settingsPayload]{{
				Plan: operation.StepPlan{
					Target:              authority.TargetRef{GUID: tid, Class: TargetClassSettings},
					Kind:                string(UpdateSettingsActionID),
					Diff:                diff(before, after),
					Preconditions:       []string{"settings_version=" + strconv.Itoa(cur.Version)},
					Reversibility:       operation.Reversible,
					ReversibilityReason: "the previous settings are restored by the same Action; mail already sent under the new settings is not recalled",
				},
				Payload: settingsPayload{Before: before, After: after, FromVersion: cur.Version, Tenant: tid},
			}}, nil
		},
		Apply: func(ctx context.Context, s step.Step, p operation.TypedStep[settingsPayload]) (SettingsOutcome, error) {
			got, err := st.Set(ctx, s, p.Payload.After.update(), p.Payload.FromVersion)
			switch {
			case errors.Is(err, settings.ErrStale):
				return SettingsOutcome{}, fmt.Errorf("%w: mail settings", operation.ErrStaleState)
			case errors.Is(err, settings.ErrInvalid):
				return SettingsOutcome{}, fmt.Errorf("%w: %s", operation.ErrInvalid, err.Error())
			case err != nil:
				return SettingsOutcome{}, err
			}
			return SettingsOutcome{Version: got.Version}, nil
		},
		Verify: func(ctx context.Context, s step.Step, p operation.TypedStep[settingsPayload], o SettingsOutcome) (operation.Verdict, error) {
			now, err := st.Get(ctx, s.Tx())
			if err != nil {
				return operation.Verdict{}, err
			}
			if got := viewOf(now); !equalView(got, p.Payload.After) || now.Version != p.Payload.FromVersion+1 {
				return operation.Verdict{Reason: "settings_not_as_applied"}, nil
			}
			return operation.Verdict{OK: true}, nil
		},
		Inverse: func(p operation.TypedStep[settingsPayload], _ SettingsOutcome) (SettingsInput, error) {
			return p.Payload.Before.input(), nil
		},
	})
}

func equalView(a, b settingsView) bool {
	if !slices.Equal(a.AllowedDomains, b.AllowedDomains) {
		return false
	}
	if (a.Relay == nil) != (b.Relay == nil) {
		return false
	}
	return a.Relay == nil || *a.Relay == *b.Relay
}
