package agentfleet

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/agentpolicy"
	"github.com/skenzeriq/activediq/internal/platform/agentpolicy/signer"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authn/tenantref"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// The two operator writes of the module (T-0599): edit the addc password and event policy, and rotate
// the policy signing key ahead of schedule. Both sign through the signer, the only code that opens the
// key (ADR-0007, P8); neither builds SQL, a filter or a DN. Both are human-only, need a fresh step-up
// and a permission in the never-crosses family (a hybrid correlation never carries them), because
// policy is what every DC agent in the tenant enforces.
const (
	PolicyEditActionID operation.ActionID = "agentfleet.policy.edit"
	KeyRotateActionID  operation.ActionID = "agentfleet.keyset.rotate"

	PolicyEditPermission authz.Permission = "agentfleet.policy.edit"
	KeyRotatePermission  authz.Permission = "agentfleet.keyset.rotate"

	AuditPolicyEdit audit.Kind = "agentfleet.policy.edit"
	AuditKeyRotate  audit.Kind = "agentfleet.keyset.rotate"

	// TargetClassAgentPolicy is the class of both Actions' target: the tenant's agent policy, not a
	// directory object.
	TargetClassAgentPolicy = "agent_policy"
	// ReasonHumanRequired is the stable reason for refusing a non-human requester.
	ReasonHumanRequired = "human_required"
)

// Rotation reasons (ADR-0007 decision 6: the immediate triggers). A closed set, so the audit reason
// is never free text. The stolen-key anchor reset (decision 7) is a different procedure.
const (
	ReasonSuspectedExposure = "suspected_exposure"
	ReasonBackupRestore     = "backup_restored_to_new_host"
	ReasonEarlyScheduled    = "early_scheduled"
)

// PolicySigner is the part of the signer the Actions use (*signer.Signer implements it).
type PolicySigner interface {
	SignPolicy(ctx context.Context, tx store.Tx, tid tenant.ID, kind string, body agentpolicy.AddcPolicy, lifetime time.Duration, actor authority.Chain) (agentpolicy.SignedPolicy, error)
	CurrentPolicy(ctx context.Context, tx store.Tx, kind string) (agentpolicy.SignedPolicy, bool, error)
	Rotate(ctx context.Context, tx store.Tx, tid tenant.ID, actor authority.Chain, reason string) (agentpolicy.SignedKeyset, error)
	Chain(ctx context.Context, tx store.Tx, since uint64) ([]agentpolicy.SignedKeyset, error)
}

var _ PolicySigner = (*signer.Signer)(nil)

// PasswordInput mirrors agentpolicy.PasswordRules with names an API client can read.
type PasswordInput struct {
	MinLength              uint32   `json:"min_length"`
	MaxLength              uint32   `json:"max_length"`
	ClassesRequired        []string `json:"classes_required"` // lower, upper, digit, symbol
	MinClasses             uint8    `json:"min_classes"`
	BannedTerms            []string `json:"banned_terms"`
	RejectSAMInPassword    bool     `json:"reject_sam_in_password"`
	RejectDisplayNameParts bool     `json:"reject_display_name_parts"`
}

// EventsInput mirrors agentpolicy.EventRules.
type EventsInput struct {
	CollectionEnabled  bool     `json:"collection_enabled"`
	Channels           []string `json:"channels"` // security, directory_service
	EventIDs           []uint32 `json:"event_ids"`
	MaxEventsPerSecond uint32   `json:"max_events_per_second"`
	BatchMaxBytes      uint32   `json:"batch_max_bytes"`
	OutboxMaxBytes     uint32   `json:"outbox_max_bytes"`
}

// PolicyEditInput is the whole next addc policy (an edit replaces the policy; the diff shows what
// changed). LifetimeSeconds 0 takes the signer's default.
type PolicyEditInput struct {
	Password        PasswordInput `json:"password"`
	Events          EventsInput   `json:"events"`
	LifetimeSeconds uint32        `json:"lifetime_seconds"`
}

var (
	classNames   = map[string]agentpolicy.Class{"lower": agentpolicy.ClassLower, "upper": agentpolicy.ClassUpper, "digit": agentpolicy.ClassDigit, "symbol": agentpolicy.ClassSymbol}
	channelNames = map[string]agentpolicy.Channel{"security": agentpolicy.ChannelSecurity, "directory_service": agentpolicy.ChannelDirectoryService}
)

func (in PolicyEditInput) policy() (agentpolicy.AddcPolicy, error) {
	p := agentpolicy.AddcPolicy{Password: agentpolicy.PasswordRules{
		MinLength: in.Password.MinLength, MaxLength: in.Password.MaxLength, MinClasses: in.Password.MinClasses,
		BannedTerms: in.Password.BannedTerms, RejectSAMInPassword: in.Password.RejectSAMInPassword, RejectDisplayNameParts: in.Password.RejectDisplayNameParts,
	}, Events: agentpolicy.EventRules{
		CollectionEnabled: in.Events.CollectionEnabled, EventIDs: in.Events.EventIDs, MaxEventsPerSecond: in.Events.MaxEventsPerSecond,
		BatchMaxBytes: in.Events.BatchMaxBytes, OutboxMaxBytes: in.Events.OutboxMaxBytes,
	}}
	for _, c := range in.Password.ClassesRequired {
		v, ok := classNames[c]
		if !ok {
			return p, fmt.Errorf("%w: unknown character class", operation.ErrInvalid)
		}
		p.Password.ClassesRequired = append(p.Password.ClassesRequired, v)
	}
	for _, c := range in.Events.Channels {
		v, ok := channelNames[c]
		if !ok {
			return p, fmt.Errorf("%w: unknown event channel", operation.ErrInvalid)
		}
		p.Events.Channels = append(p.Events.Channels, v)
	}
	// Sets are strictly increasing on the wire; the operator's order is irrelevant, so normalise.
	slices.Sort(p.Password.ClassesRequired)
	slices.Sort(p.Events.Channels)
	slices.Sort(p.Events.EventIDs)
	if err := p.Validate(); err != nil {
		return p, fmt.Errorf("%w: %v", operation.ErrInvalid, err)
	}
	return p, nil
}

type policyPayload struct {
	Tenant  string          `json:"tenant"`
	Policy  PolicyEditInput `json:"policy"`
	NextSeq uint64          `json:"next_seq"`
}

// PolicyEditOutcome is what Apply did.
type PolicyEditOutcome struct {
	Seq   uint64 `json:"policy_seq"`
	KeyID string `json:"key_id"`
}

func requireHuman(s step.Step) error {
	if s.Actor().Requester.Kind != authority.Human {
		return fmt.Errorf("%w: %s", operation.ErrDenied, ReasonHumanRequired)
	}
	return nil
}

func signerErr(err error) error {
	switch {
	case errors.Is(err, signer.ErrInvalid), errors.Is(err, agentpolicy.ErrOutOfBounds):
		return fmt.Errorf("%w: the policy was refused by the signer", operation.ErrInvalid)
	case errors.Is(err, signer.ErrTooManyKeys):
		return fmt.Errorf("%w: a rotation is already within its overlap window; wait for it to end", operation.ErrInvalid)
	case errors.Is(err, signer.ErrNoKeyset):
		return fmt.Errorf("%w: the tenant has no policy key yet", operation.ErrInvalid)
	}
	return err
}

func policyDiff(before *agentpolicy.AddcPolicy, after agentpolicy.AddcPolicy) []operation.Change {
	var b agentpolicy.AddcPolicy
	if before != nil {
		b = *before
	}
	one := func(attr string, bv, av any) operation.Change {
		bs := []string{"none"}
		if before != nil {
			bs = []string{fmt.Sprint(bv)}
		}
		return operation.Change{Attribute: attr, Before: bs, After: []string{fmt.Sprint(av)}}
	}
	// Banned terms are summarised by count: the list is up to 1 MiB and not a diff line.
	return []operation.Change{
		one("password_min_length", b.Password.MinLength, after.Password.MinLength),
		one("password_max_length", b.Password.MaxLength, after.Password.MaxLength),
		one("password_classes_required", b.Password.ClassesRequired, after.Password.ClassesRequired),
		one("password_min_classes", b.Password.MinClasses, after.Password.MinClasses),
		one("password_banned_terms_count", len(b.Password.BannedTerms), len(after.Password.BannedTerms)),
		one("password_reject_sam_in_password", b.Password.RejectSAMInPassword, after.Password.RejectSAMInPassword),
		one("password_reject_display_name_parts", b.Password.RejectDisplayNameParts, after.Password.RejectDisplayNameParts),
		one("events_collection_enabled", b.Events.CollectionEnabled, after.Events.CollectionEnabled),
		one("events_channels", b.Events.Channels, after.Events.Channels),
		one("events_event_ids", b.Events.EventIDs, after.Events.EventIDs),
		one("events_max_events_per_second", b.Events.MaxEventsPerSecond, after.Events.MaxEventsPerSecond),
		one("events_batch_max_bytes", b.Events.BatchMaxBytes, after.Events.BatchMaxBytes),
		one("events_outbox_max_bytes", b.Events.OutboxMaxBytes, after.Events.OutboxMaxBytes),
	}
}

// PolicyEdit builds the policy-edit Action. The module passes a possibly unconfigured *signer.Signer
// (compose wires the production one with the tenant DEK source, T-0598); every run then fails with
// signer.ErrNotConfigured and changes nothing.
func PolicyEdit(sg PolicySigner) (operation.Action, error) {
	if sg == nil {
		return nil, errors.New("agentfleet: policy edit needs the signer")
	}
	return operation.Define(operation.Typed[PolicyEditInput, policyPayload, PolicyEditOutcome]{
		Descriptor: operation.Descriptor{
			ID: PolicyEditActionID, Version: 1, Permission: PolicyEditPermission,
			Input:  "#/components/schemas/AgentfleetPolicyEdit",
			Target: operation.TargetStore, Reversibility: operation.Irreversible, AuditKind: AuditPolicyEdit, StepUp: true, ControlPlane: true,
		},
		Plan: func(ctx context.Context, pc operation.PlanContext, in PolicyEditInput) ([]operation.TypedStep[policyPayload], error) {
			next, err := in.policy()
			if err != nil {
				return nil, err
			}
			if in.LifetimeSeconds > uint32(agentpolicy.MaxLifetime/time.Second) {
				return nil, fmt.Errorf("%w: lifetime_seconds is above the maximum", operation.ErrInvalid)
			}
			tid, err := tenantFrom(ctx, pc.Tx)
			if err != nil {
				return nil, err
			}
			var cur *agentpolicy.AddcPolicy
			var seq uint64
			sp, ok, err := sg.CurrentPolicy(ctx, pc.Tx, agentpolicy.KindADDC)
			if err != nil {
				return nil, signerErr(err)
			}
			if ok {
				seq = sp.Header.Seq
				if p, err := agentpolicy.DecodeAddcPolicy(sp.Body); err == nil {
					cur = &p
				}
			}
			return []operation.TypedStep[policyPayload]{{
				Plan: operation.StepPlan{
					Target:        authority.TargetRef{GUID: tid, Class: TargetClassAgentPolicy},
					Kind:          "agentfleet.policy.edit",
					Diff:          policyDiff(cur, next),
					Reversibility: operation.Irreversible, ReversibilityReason: "a signed policy is replaced by the next sequence number, never withdrawn; edit again to change it",
				},
				Payload: policyPayload{Tenant: tid, Policy: in, NextSeq: seq + 1},
			}}, nil
		},
		Apply: func(ctx context.Context, s step.Step, p operation.TypedStep[policyPayload]) (PolicyEditOutcome, error) {
			if err := requireHuman(s); err != nil {
				return PolicyEditOutcome{}, err
			}
			tx := s.Tx()
			if tx == nil {
				return PolicyEditOutcome{}, errors.New("agentfleet: a policy edit needs the runner's transaction")
			}
			tid, err := tenantref.TenantFromText(p.Payload.Tenant)
			if err != nil {
				return PolicyEditOutcome{}, fmt.Errorf("%w: tenant", operation.ErrInvalid)
			}
			body, err := p.Payload.Policy.policy()
			if err != nil {
				return PolicyEditOutcome{}, err
			}
			sp, err := sg.SignPolicy(ctx, tx, tid, agentpolicy.KindADDC, body, time.Duration(p.Payload.Policy.LifetimeSeconds)*time.Second, s.Actor())
			if err != nil {
				return PolicyEditOutcome{}, signerErr(err)
			}
			return PolicyEditOutcome{Seq: sp.Header.Seq, KeyID: sp.Header.KeyID}, nil
		},
		Verify: func(ctx context.Context, s step.Step, p operation.TypedStep[policyPayload], o PolicyEditOutcome) (operation.Verdict, error) {
			sp, ok, err := sg.CurrentPolicy(ctx, s.Tx(), agentpolicy.KindADDC)
			if err != nil {
				return operation.Verdict{}, signerErr(err)
			}
			if !ok || sp.Header.Seq != o.Seq {
				return operation.Verdict{Reason: "policy_head_not_updated"}, nil
			}
			return operation.Verdict{OK: true}, nil
		},
		Inverse: func(operation.TypedStep[policyPayload], PolicyEditOutcome) (PolicyEditInput, error) {
			return PolicyEditInput{}, operation.ErrIrreversible
		},
	})
}

// KeyRotateInput names why the key is rotated now.
type KeyRotateInput struct {
	Reason string `json:"reason"` // suspected_exposure, backup_restored_to_new_host, early_scheduled
}

type rotatePayload struct {
	Tenant string `json:"tenant"`
	Reason string `json:"reason"`
}

// KeyRotateOutcome is what Apply did.
type KeyRotateOutcome struct {
	KeysetSeq   uint64 `json:"keyset_seq"`
	SignerKeyID string `json:"signer_key_id"`
}

// KeyRotate builds the key-rotation Action: a new active key, the old one retiring for the overlap
// window, and a keyset signed by the old key that agents holding the previous keyset accept (P1-P8).
// It does not recover from a stolen key: that is the anchor reset of ADR-0007 decision 7.
func KeyRotate(sg PolicySigner) (operation.Action, error) {
	if sg == nil {
		return nil, errors.New("agentfleet: key rotation needs the signer")
	}
	return operation.Define(operation.Typed[KeyRotateInput, rotatePayload, KeyRotateOutcome]{
		Descriptor: operation.Descriptor{
			ID: KeyRotateActionID, Version: 1, Permission: KeyRotatePermission,
			Input:  "#/components/schemas/AgentfleetKeyRotate",
			Target: operation.TargetStore, Reversibility: operation.Irreversible, AuditKind: AuditKeyRotate, StepUp: true, ControlPlane: true,
		},
		Plan: func(ctx context.Context, pc operation.PlanContext, in KeyRotateInput) ([]operation.TypedStep[rotatePayload], error) {
			if !slices.Contains([]string{ReasonSuspectedExposure, ReasonBackupRestore, ReasonEarlyScheduled}, in.Reason) {
				return nil, fmt.Errorf("%w: reason must be one of %s, %s, %s", operation.ErrInvalid, ReasonSuspectedExposure, ReasonBackupRestore, ReasonEarlyScheduled)
			}
			tid, err := tenantFrom(ctx, pc.Tx)
			if err != nil {
				return nil, err
			}
			return []operation.TypedStep[rotatePayload]{{
				Plan: operation.StepPlan{
					Target: authority.TargetRef{GUID: tid, Class: TargetClassAgentPolicy},
					Kind:   "agentfleet.keyset.rotate",
					Diff: []operation.Change{
						{Attribute: "policy_key_active", Before: []string{"current"}, After: []string{"new"}},
						{Attribute: "policy_key_previous", Before: []string{"active"}, After: []string{"retiring"}},
						{Attribute: "reason", Before: []string{"none"}, After: []string{in.Reason}},
					},
					Reversibility: operation.Irreversible, ReversibilityReason: "a published keyset is part of the chain agents replay; it is never withdrawn",
				},
				Payload: rotatePayload{Tenant: tid, Reason: in.Reason},
			}}, nil
		},
		Apply: func(ctx context.Context, s step.Step, p operation.TypedStep[rotatePayload]) (KeyRotateOutcome, error) {
			if err := requireHuman(s); err != nil {
				return KeyRotateOutcome{}, err
			}
			tx := s.Tx()
			if tx == nil {
				return KeyRotateOutcome{}, errors.New("agentfleet: a rotation needs the runner's transaction")
			}
			tid, err := tenantref.TenantFromText(p.Payload.Tenant)
			if err != nil {
				return KeyRotateOutcome{}, fmt.Errorf("%w: tenant", operation.ErrInvalid)
			}
			sk, err := sg.Rotate(ctx, tx, tid, s.Actor(), p.Payload.Reason)
			if err != nil {
				return KeyRotateOutcome{}, signerErr(err)
			}
			return KeyRotateOutcome{KeysetSeq: sk.Seq, SignerKeyID: sk.SignerKeyID}, nil
		},
		Verify: func(ctx context.Context, s step.Step, p operation.TypedStep[rotatePayload], o KeyRotateOutcome) (operation.Verdict, error) {
			chain, err := sg.Chain(ctx, s.Tx(), o.KeysetSeq-1)
			if err != nil {
				return operation.Verdict{}, signerErr(err)
			}
			if len(chain) == 0 || chain[len(chain)-1].Seq != o.KeysetSeq {
				return operation.Verdict{Reason: "keyset_not_published"}, nil
			}
			return operation.Verdict{OK: true}, nil
		},
		Inverse: func(operation.TypedStep[rotatePayload], KeyRotateOutcome) (KeyRotateInput, error) {
			return KeyRotateInput{}, operation.ErrIrreversible
		},
	})
}

func tenantFrom(ctx context.Context, tx store.Tx) (string, error) {
	var tid string
	if err := tx.QueryRow(ctx, `SELECT current_setting('app.tenant_id', true)`).Scan(&tid); err != nil || tid == "" {
		return "", errors.New("agentfleet: no tenant context")
	}
	return tid, nil
}
