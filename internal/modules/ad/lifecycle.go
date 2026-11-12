package ad

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/skenzeriq/activediq/internal/directory/accountkind"
	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/directory/writechange"
	"github.com/skenzeriq/activediq/internal/modules/objects"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/store"
)

// The user lifecycle Actions (T-1585): ADM-008 create, ADM-033 modify, ADM-038 restore, plus delete,
// move and rename. One generic builder (build below) and one spec row per verb, like the account kinds.
const (
	CreateID  operation.ActionID = "ad.user.create"
	UpdateID  operation.ActionID = "ad.user.update"
	DeleteID  operation.ActionID = "ad.user.delete"
	MoveID    operation.ActionID = "ad.user.move"
	RenameID  operation.ActionID = "ad.user.rename"
	RestoreID operation.ActionID = "ad.user.restore"

	PermCreate  authz.Permission = "objects.user.create"
	PermUpdate  authz.Permission = "objects.user.update"
	PermDelete  authz.Permission = "objects.user.delete"
	PermMove    authz.Permission = "objects.user.move" // a rename is a modifyDN: the same permission (TM-D19)
	PermRestore authz.Permission = "objects.user.restore"

	AuditCreated  audit.Kind = "ad.user.created"
	AuditUpdated  audit.Kind = "ad.user.updated"
	AuditDeleted  audit.Kind = "ad.user.deleted"
	AuditMoved    audit.Kind = "ad.user.moved"
	AuditRenamed  audit.Kind = "ad.user.renamed"
	AuditRestored audit.Kind = "ad.user.restored"
)

// More stable refusal reasons.
const (
	ReasonParentInvalid   = "parent_not_a_container"
	ReasonParentNotFound  = "parent_not_found"
	ReasonNoRecycleBin    = "recycle_bin_disabled"
	ReasonNotDeleted      = "target_not_deleted"
	ReasonAttributeDenied = "attribute_not_allowed"
	ReasonTemplate        = "template_refused"
	ReasonName            = "name_invalid"
)

// profileAttrs are the attributes create and update may set: plain profile text. Everything that
// grants sign-in or changes who the account is (sAMAccountName and userPrincipalName on update,
// userAccountControl, pwdLastSet, unicodePwd, memberOf, primaryGroupID, sIDHistory, adminCount,
// nTSecurityDescriptor, ...) has its own Action and permission, so it is not on this list.
var profileAttrs = []string{
	"givenName", "sn", "initials", "displayName", "description", "mail", "telephoneNumber", "mobile",
	"homePhone", "title", "department", "company", "physicalDeliveryOfficeName", "streetAddress", "l", "st",
	"postalCode", "co", "c", "employeeID", "employeeNumber", "info", "wWWHomePage",
}

// createOnlyAttrs are the logon names: set when the account is created, renamed by a later Action.
var createOnlyAttrs = []string{"sAMAccountName", "userPrincipalName"}

const maxValueLen = 1024

func allowedAttr(name string, create bool) bool {
	for _, a := range profileAttrs {
		if strings.EqualFold(a, name) {
			return true
		}
	}
	if create {
		for _, a := range createOnlyAttrs {
			if strings.EqualFold(a, name) {
				return true
			}
		}
	}
	return false
}

// canonicalAttr returns the list spelling of an allowed attribute.
func canonicalAttr(name string, create bool) (string, bool) {
	for _, a := range append(slices.Clone(profileAttrs), createOnlyAttrs...) {
		if strings.EqualFold(a, name) && allowedAttr(a, create) {
			return a, true
		}
	}
	return "", false
}

// TemplateRef pins the Template a create uses. Version 0 means the newest published version.
type TemplateRef struct {
	ID      string `json:"id"`
	Version int    `json:"version,omitempty"`
}

// CreateInput is the input of create. The initial password is a transient secret input of the
// submission (rule 9), not a member. Attributes are plain profile text (profileAttrs) plus the logon
// names; with a Template, the Template's naming formats derive sAMAccountName, userPrincipalName, cn
// and displayName from them.
type CreateInput struct {
	ConnectionID  string            `json:"connectionId"`
	NamingContext string            `json:"namingContext"`
	ParentGuid    string            `json:"parentGuid"`
	Template      *TemplateRef      `json:"template,omitempty"`
	Attributes    map[string]string `json:"attributes"`
	UPNSuffix     string            `json:"upnSuffix,omitempty"`
	Enabled       bool              `json:"enabled"`
}

// UpdateInput changes profile attributes (profileAttrs) of one user: Set replaces the value, Clear
// removes the attribute.
type UpdateInput struct {
	Target
	Set   map[string]string `json:"set,omitempty"`
	Clear []string          `json:"clear,omitempty"`
}

// MoveInput moves a user to another container of the same naming context.
type MoveInput struct {
	Target
	NewParentGuid string `json:"newParentGuid"`
}

// RenameInput changes the user's RDN value (cn); it is a value, never a DN.
type RenameInput struct {
	Target
	NewName string `json:"newName"`
}

// DeleteInput deletes a user.
type DeleteInput struct{ Target }

// RestoreInput restores a deleted user. NewParentGuid and Name default to the last known parent and
// RDN the directory kept.
type RestoreInput struct {
	Target
	NewParentGuid string `json:"newParentGuid,omitempty"`
	Name          string `json:"name,omitempty"`
}

// LifeOutcome is what a lifecycle Apply did.
type LifeOutcome struct {
	NoOp bool `json:"noOp,omitempty"`
	// Object is the GUID the write acted on; for a create, the new account.
	Object string              `json:"object,omitempty"`
	Tier0  []step.Tier0Finding `json:"tier0,omitempty"`
}

// lifePayload is what Plan read, carried to Apply, Verify, Observe and Inverse.
type lifePayload struct {
	Target    Target   `json:"target"`
	Parent    string   `json:"parent,omitempty"`    // planned (create), new (move, restore) parent
	OldParent string   `json:"oldParent,omitempty"` // move
	RDN       string   `json:"rdn,omitempty"`       // planned (create), new (rename, restore) name
	OldRDN    string   `json:"oldRdn,omitempty"`    // rename
	Keys      []string `json:"keys,omitempty"`      // the attributes an update changes
}

// LifecyclePorts are the directory ports of the lifecycle Actions. Any nil port makes every Plan and
// Apply refuse.
type LifecyclePorts struct {
	Reader client.ObjectReader
	Writer client.AccountWriter
	// Definitions reads Templates and NamingFormats (OBJ4); nil reads the objects store.
	Definitions Definitions
}

// Definitions is the read half of the objects store a create consumes at Plan.
type Definitions interface {
	Template(ctx context.Context, tx store.Tx, ref TemplateRef) (objects.Stored[objects.Template], error)
	NamingFormat(ctx context.Context, tx store.Tx, pin objects.Pin) (objects.Stored[objects.NamingFormat], error)
}

type storeDefs struct{}

func (storeDefs) Template(ctx context.Context, tx store.Tx, ref TemplateRef) (objects.Stored[objects.Template], error) {
	if ref.Version == 0 {
		return objects.Templates{}.Latest(ctx, tx, ref.ID)
	}
	return objects.Templates{}.Get(ctx, tx, ref.ID, ref.Version)
}

func (storeDefs) NamingFormat(ctx context.Context, tx store.Tx, pin objects.Pin) (objects.Stored[objects.NamingFormat], error) {
	return objects.NamingFormats{}.Get(ctx, tx, pin.ID, pin.Version)
}

func (p LifecyclePorts) defs() Definitions {
	if p.Definitions == nil {
		return storeDefs{}
	}
	return p.Definitions
}

type lifeSpec[In any] struct {
	id            operation.ActionID
	perm          authz.Permission
	schema        operation.SchemaRef
	audit         audit.Kind
	reversibility operation.Reversibility // the Descriptor's worst case
	secret        bool
	plan          func(ctx context.Context, p LifecyclePorts, pc operation.PlanContext, in In) (*lifePlan, error)
	// satisfied reports whether the live read shows the verb's after-state.
	satisfied func(pl lifePayload, st client.ObjectState) bool
	// before reports whether it still shows the before-state.
	before  func(pl lifePayload, st client.ObjectState) bool
	inverse func(pl lifePayload, o LifeOutcome) (In, error)
	// showDeleted reads the object as a deleted one (restore's before-state).
	showDeleted bool
	// readBack: Verify reads the created object, by the GUID Apply returned.
	create bool
	// gone: Verify expects the object to be absent (delete).
	gone bool
}

// lifePlan is one planned step (nil step list = nothing to do).
type lifePlan struct {
	sp      operation.StepPlan
	pl      lifePayload
	also    []authority.TargetRef
	touched []authority.TargetRef
}

// LifecycleActions builds the six user lifecycle Actions.
func LifecycleActions(p LifecyclePorts) ([]operation.Action, error) {
	var out []operation.Action
	for _, f := range []func(LifecyclePorts) (operation.Action, error){
		func(p LifecyclePorts) (operation.Action, error) { return buildLife(p, createSpec) },
		func(p LifecyclePorts) (operation.Action, error) { return buildLife(p, updateSpec) },
		func(p LifecyclePorts) (operation.Action, error) { return buildLife(p, deleteSpec) },
		func(p LifecyclePorts) (operation.Action, error) { return buildLife(p, moveSpec) },
		func(p LifecyclePorts) (operation.Action, error) { return buildLife(p, renameSpec) },
		func(p LifecyclePorts) (operation.Action, error) { return buildLife(p, restoreSpec) },
	} {
		a, err := f(p)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

func buildLife[In any](p LifecyclePorts, sp lifeSpec[In]) (operation.Action, error) {
	return operation.Define(operation.Typed[In, lifePayload, LifeOutcome]{
		Descriptor: operation.Descriptor{
			ID: sp.id, Version: 1, Permission: sp.perm, Input: sp.schema, Target: operation.TargetAD,
			Reversibility: sp.reversibility, AuditKind: sp.audit, SecretInput: sp.secret,
		},
		Plan: func(ctx context.Context, pc operation.PlanContext, in In) ([]operation.TypedStep[lifePayload], error) {
			if p.Reader == nil {
				return nil, errUnavailable
			}
			lp, err := sp.plan(ctx, p, pc, in)
			if err != nil || lp == nil {
				return nil, err
			}
			lp.sp.Payload = nil
			return []operation.TypedStep[lifePayload]{{Plan: lp.sp, Payload: lp.pl}}, nil
		},
		Apply: func(ctx context.Context, s step.Step, tp operation.TypedStep[lifePayload]) (LifeOutcome, error) {
			if p.Writer == nil {
				return LifeOutcome{}, errUnavailable
			}
			op := client.WriteOp{DigestKind: tp.Plan.Kind, Target: tp.Plan.Target, Attrs: attrsOfDiff(tp.Plan.Diff)}
			if sp.secret {
				op.SecretInput = s.Secret()
			}
			res, err := p.Writer.Write(ctx, s, op)
			if err != nil {
				return LifeOutcome{}, writeError(err, false)
			}
			out := LifeOutcome{NoOp: res.NoOp}
			if res.Apply != nil {
				out.Tier0 = res.Tier0AfterWrite()
				out.Object = res.ObjectGUID()
			}
			return out, nil
		},
		Verify: func(ctx context.Context, s step.Step, tp operation.TypedStep[lifePayload], o LifeOutcome) (operation.Verdict, error) {
			if p.Reader == nil {
				return operation.Verdict{}, errUnavailable
			}
			pl := tp.Payload
			ref := tp.Plan.Target
			if sp.create {
				if o.Object == "" {
					return operation.Verdict{Reason: "created_object_unknown"}, nil
				}
				ref.GUID = o.Object
			}
			st, err := p.Reader.Object(pinnedFor(ctx, s, ref.NC), stepPinsFor(s, ref.NC), ref, nil, false)
			if err != nil {
				return operation.Verdict{}, readError(err)
			}
			if sp.gone {
				if st.Exists {
					return operation.Verdict{Reason: "object_still_present"}, nil
				}
				return operation.Verdict{OK: true}, nil
			}
			if !st.Exists {
				return operation.Verdict{Reason: "target_gone"}, nil
			}
			// Rule 7: the Tier-0 guard runs again on the read-back and outranks every other reason.
			if st.Tier0 {
				return operation.Verdict{Reason: "tier0_after_write", Tier0: []step.Tier0Finding{{Object: ref.GUID}}}, nil
			}
			if !sp.satisfied(pl, st) {
				return operation.Verdict{Reason: "object_not_as_planned"}, nil
			}
			return operation.Verdict{OK: true}, nil
		},
		Inverse: func(tp operation.TypedStep[lifePayload], o LifeOutcome) (In, error) {
			var zero In
			if sp.inverse == nil {
				return zero, operation.ErrIrreversible
			}
			if o.NoOp {
				return zero, ErrNothingToUndo
			}
			return sp.inverse(tp.Payload, o)
		},
		Observe: func(ctx context.Context, pins authority.Pins, tp operation.TypedStep[lifePayload], _ time.Time) (operation.Observation, error) {
			if p.Reader == nil {
				return "", errUnavailable
			}
			ref := tp.Plan.Target
			if sp.create {
				// The created object's GUID is the connector's; before it is known, look for the planned
				// name. Reconciliation of a create is by the parent's child of that RDN, which the reader
				// cannot answer by GUID: report other and let the operator look.
				return operation.ObservedOther, nil
			}
			st, err := p.Reader.Object(ctx, pins, ref, nil, sp.showDeleted)
			if err != nil {
				return "", readError(err)
			}
			if sp.gone {
				if !st.Exists {
					return operation.ObservedAfter, nil
				}
				return operation.ObservedBefore, nil
			}
			if !st.Exists {
				return operation.ObservedOther, nil
			}
			switch {
			case sp.satisfied(tp.Payload, st):
				return operation.ObservedAfter, nil
			case sp.before(tp.Payload, st):
				return operation.ObservedBefore, nil
			}
			return operation.ObservedOther, nil
		},
		Touched:       func(tp operation.TypedStep[lifePayload]) []authority.TargetRef { return touchedOf(tp) },
		AlsoAuthorize: func(tp operation.TypedStep[lifePayload]) []authority.TargetRef { return alsoOf(tp) },
		Tier0:         func(o LifeOutcome) []step.Tier0Finding { return o.Tier0 },
	})
}

// parentRef names a container of the target's naming context.
func parentRef(conn, guid string, nc authority.NamingContextID) authority.TargetRef {
	return authority.TargetRef{Connection: conn, GUID: guid, NC: nc}
}

func alsoOf(tp operation.TypedStep[lifePayload]) []authority.TargetRef {
	pl := tp.Payload
	t := tp.Plan.Target
	switch tp.Plan.Kind {
	case client.DigestObjectMove, client.DigestObjectRestore:
		if pl.Parent != "" {
			return []authority.TargetRef{parentRef(t.Connection, pl.Parent, t.NC)}
		}
	}
	return nil
}

func touchedOf(tp operation.TypedStep[lifePayload]) []authority.TargetRef {
	pl := tp.Payload
	t := tp.Plan.Target
	var out []authority.TargetRef
	for _, g := range []string{pl.Parent, pl.OldParent} {
		if g != "" {
			out = append(out, parentRef(t.Connection, g, t.NC))
		}
	}
	return out
}

func attrsOfDiff(cs []operation.Change) []step.Attr {
	var out []step.Attr
	for _, c := range cs {
		out = append(out, step.Attr{Name: c.Attribute, Values: c.After, Secret: c.Secret})
	}
	return out
}

func diffOfAttrs(attrs []step.Attr, before map[string][]string) []operation.Change {
	var out []operation.Change
	for _, a := range attrs {
		out = append(out, operation.Change{Attribute: a.Name, Before: before[a.Name], After: a.Values, Secret: a.Secret})
	}
	return out
}

func pinnedFor(ctx context.Context, s step.Step, nc authority.NamingContextID) context.Context {
	dsa, _ := s.DSA(nc)
	return authority.WithDSAPins(ctx, authority.DSAPins{nc: dsa})
}

func stepPinsFor(s step.Step, nc authority.NamingContextID) authority.Pins {
	host, _ := s.DC(nc)
	return authority.Pins{nc: host}
}

// objTarget is the digest target of a write on an existing object: GUID and naming context only,
// because the connector reads the class (and, for kinds 4-6, the parent and RDN) live.
func (t Target) objTarget() authority.TargetRef {
	return authority.TargetRef{Connection: t.ConnectionID, GUID: t.ObjectGUID, NC: authority.NamingContextID(t.NamingContext)}
}

// readUser reads the target live and refuses what no lifecycle Action may touch.
func readUser(ctx context.Context, p LifecyclePorts, pc operation.PlanContext, t Target, attrs []string, deleted bool) (client.ObjectState, error) {
	if err := t.validate(); err != nil {
		return client.ObjectState{}, err
	}
	st, err := p.Reader.Object(ctx, pc.Pins, t.objTarget(), attrs, deleted)
	if err != nil {
		return st, readError(err)
	}
	switch {
	case !st.Exists:
		return st, fmt.Errorf("%w: %s", operation.ErrInvalid, ReasonNotFound)
	case st.Class != ClassUser:
		return st, fmt.Errorf("%w: %s", operation.ErrInvalid, ReasonNotUser)
	case st.Tier0:
		return st, fmt.Errorf("%w: %s", operation.ErrDenied, ReasonTier0)
	case st.Deleted != deleted:
		if deleted {
			return st, fmt.Errorf("%w: %s", operation.ErrInvalid, ReasonNotDeleted)
		}
		return st, fmt.Errorf("%w: %s", operation.ErrInvalid, ReasonNotFound)
	}
	return st, nil
}

// readParent reads a destination or planned parent: it must exist, be a container and not be Tier-0.
func readParent(ctx context.Context, p LifecyclePorts, pc operation.PlanContext, conn, guid string, nc authority.NamingContextID) error {
	if !accountkind.Canonical(guid) {
		return fmt.Errorf("%w: the parent GUID must be canonical lower-case UUID text", operation.ErrInvalid)
	}
	st, err := p.Reader.Object(ctx, pc.Pins, parentRef(conn, guid, nc), nil, false)
	if err != nil {
		return readError(err)
	}
	switch {
	case !st.Exists:
		return fmt.Errorf("%w: %s", operation.ErrInvalid, ReasonParentNotFound)
	case st.Tier0:
		return fmt.Errorf("%w: %s", operation.ErrDenied, ReasonTier0)
	}
	switch st.Class {
	case "organizationalUnit", "container", "domainDNS":
		return nil
	}
	return fmt.Errorf("%w: %s", operation.ErrInvalid, ReasonParentInvalid)
}

// validName checks an RDN value: it is a value to the connector (which escapes it), so only length
// and control characters are refused here.
func validName(n string) error {
	if n == "" || n != strings.TrimSpace(n) || utf8.RuneCountInString(n) > 64 || !utf8.ValidString(n) {
		return fmt.Errorf("%w: %s", operation.ErrInvalid, ReasonName)
	}
	for _, r := range n {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: %s", operation.ErrInvalid, ReasonName)
		}
	}
	return nil
}

func validValue(v string) bool {
	if utf8.RuneCountInString(v) > maxValueLen || !utf8.ValidString(v) {
		return false
	}
	for _, r := range v {
		if r < 0x20 && r != '\n' && r != '\r' && r != '\t' || r == 0x7f {
			return false
		}
	}
	return true
}

// ---- create ----

var createSpec = lifeSpec[CreateInput]{
	id: CreateID, perm: PermCreate, schema: "#/components/schemas/AdUserCreate", audit: AuditCreated,
	// A create is Reversible while it has no link values; once the account is in groups its delete is
	// Lossy, which the Descriptor's worst case states.
	reversibility: operation.Lossy, secret: true, create: true,
	plan: planCreate,
	satisfied: func(pl lifePayload, st client.ObjectState) bool {
		return st.Class == ClassUser && st.Parent == pl.Parent && strings.EqualFold(st.RDN, pl.RDN)
	},
	before: func(lifePayload, client.ObjectState) bool { return false },
}

func planCreate(ctx context.Context, p LifecyclePorts, pc operation.PlanContext, in CreateInput) (*lifePlan, error) {
	t := Target{ConnectionID: in.ConnectionID, ObjectGUID: in.ParentGuid, NamingContext: in.NamingContext}
	if err := t.validate(); err != nil {
		return nil, err
	}
	attrs := objects.Input{}
	for k, v := range in.Attributes {
		c, ok := canonicalAttr(k, true)
		if !ok {
			if strings.EqualFold(k, "cn") {
				attrs["cn"] = v
				continue
			}
			return nil, fmt.Errorf("%w: %s: %s", operation.ErrInvalid, ReasonAttributeDenied, k)
		}
		if !validValue(v) {
			return nil, fmt.Errorf("%w: %s: %s", operation.ErrInvalid, ReasonAttributeDenied, c)
		}
		attrs[c] = v
	}
	var tpl *objects.Stored[objects.Template]
	if in.Template != nil {
		var err error
		if tpl, err = loadTemplate(ctx, p.defs(), pc, *in.Template, in.ParentGuid); err != nil {
			return nil, err
		}
		if vs := tpl.Def.CheckInput(attrs); len(vs) > 0 {
			return nil, templateViolation(vs[0])
		}
		attrs = tpl.Def.Effective(attrs)
		if err := deriveNames(ctx, p.defs(), pc, tpl.Def, attrs, in.UPNSuffix); err != nil {
			return nil, err
		}
	}
	rdn := attrs["cn"]
	delete(attrs, "cn")
	if err := validName(rdn); err != nil {
		return nil, err
	}
	if attrs["sAMAccountName"] == "" {
		return nil, fmt.Errorf("%w: sAMAccountName is required (give it, or a Template whose naming format derives it)", operation.ErrInvalid)
	}
	if err := readParent(ctx, p, pc, in.ConnectionID, in.ParentGuid, authority.NamingContextID(in.NamingContext)); err != nil {
		return nil, err
	}
	var set []writechange.Edit
	for _, k := range sortedKeys(attrs) {
		if v := attrs[k]; v != "" {
			set = append(set, writechange.Edit{Op: "set", Attribute: k, Values: []string{v}})
		}
	}
	wa, err := writechange.CreateAttrs(writechange.CreateSpec{RDN: rdn, Enabled: in.Enabled, HasSecret: true, Set: set})
	if err != nil {
		return nil, fmt.Errorf("%w: the create does not encode", operation.ErrInvalid)
	}
	target := authority.TargetRef{
		Connection: in.ConnectionID, Class: ClassUser, Parent: in.ParentGuid, RDN: rdn,
		NC: authority.NamingContextID(in.NamingContext),
	}
	pre := []string{"creates a user in the planned container; the new object does not exist yet"}
	if tpl != nil {
		pre = append(pre, fmt.Sprintf("Template %s version %d applied", tpl.ID, tpl.Version))
	}
	if !in.Enabled {
		pre = append(pre, "the account is created disabled")
	}
	return &lifePlan{
		sp: operation.StepPlan{
			Target: target, Kind: writechange.KeyObjectCreate, Diff: diffOfAttrs(wa, nil), Preconditions: pre,
			Reversibility:       operation.Reversible,
			ReversibilityReason: "the new account has no link values; deleting it undoes the create until it joins a group",
			Credential:          true,
		},
		pl:      lifePayload{Target: t, Parent: in.ParentGuid, RDN: rdn},
		touched: nil,
	}, nil
}

func loadTemplate(ctx context.Context, defs Definitions, pc operation.PlanContext, ref TemplateRef, parent string) (*objects.Stored[objects.Template], error) {
	if pc.Tx == nil {
		return nil, fmt.Errorf("%w: %s", operation.ErrInvalid, ReasonTemplate)
	}
	tpl, err := defs.Template(ctx, pc.Tx, ref)
	if err != nil {
		if errors.Is(err, objects.ErrNotFound) {
			return nil, fmt.Errorf("%w: %s: not found", operation.ErrInvalid, ReasonTemplate)
		}
		return nil, fmt.Errorf("%w: reading the template failed", operation.ErrTransient)
	}
	d := tpl.Def
	switch {
	case tpl.State != objects.StatePublished:
		return nil, fmt.Errorf("%w: %s: the version is not published", operation.ErrInvalid, ReasonTemplate)
	case d.Kind != objects.KindUser || d.Purpose != objects.PurposeCreate || d.Provider == objects.ProviderEntra:
		return nil, fmt.Errorf("%w: %s: not a user create template for AD", operation.ErrInvalid, ReasonTemplate)
	case !d.ContainerAllowed(parent):
		return nil, fmt.Errorf("%w: %s: the container is not allowed by the template", operation.ErrInvalid, ReasonTemplate)
	}
	return &tpl, nil
}

func templateViolation(v *objects.ViolationError) error {
	return fmt.Errorf("%w: %s: %s", operation.ErrInvalid, ReasonTemplate, v.Error())
}

// deriveNames renders the Template's pinned naming formats into attrs. A format that cannot render
// blocks the plan and names the field.
func deriveNames(ctx context.Context, defs Definitions, pc operation.PlanContext, d objects.Template, attrs objects.Input, upnSuffix string) error {
	for _, purpose := range objects.Purposes() {
		pin, ok := d.NamingFormats[purpose]
		if !ok {
			continue
		}
		f, err := defs.NamingFormat(ctx, pc.Tx, pin)
		if err != nil {
			return fmt.Errorf("%w: %s: naming format %s not readable", operation.ErrInvalid, ReasonTemplate, purpose)
		}
		name, err := f.Def.Render(attrs, objects.DefaultLimits)
		if err != nil {
			var v *objects.ViolationError
			if errors.As(err, &v) {
				return templateViolation(v)
			}
			return fmt.Errorf("%w: %s: %s", operation.ErrInvalid, ReasonTemplate, purpose)
		}
		switch purpose {
		case objects.PurposeSAMAccountName:
			attrs["sAMAccountName"] = name
		case objects.PurposeCN:
			attrs["cn"] = name
		case objects.PurposeDisplayName:
			attrs["displayName"] = name
		case objects.PurposeUPNPrefix:
			if upnSuffix == "" || strings.ContainsAny(upnSuffix, "@ \\") {
				return fmt.Errorf("%w: %s: upnSuffix is required by the template's UPN format", operation.ErrInvalid, ReasonTemplate)
			}
			attrs["userPrincipalName"] = name + "@" + upnSuffix
		}
	}
	return nil
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// ---- update ----

var updateSpec = lifeSpec[UpdateInput]{
	id: UpdateID, perm: PermUpdate, schema: "#/components/schemas/AdUserUpdate", audit: AuditUpdated,
	reversibility: operation.Reversible,
	plan:          planUpdate,
	satisfied:     func(lifePayload, client.ObjectState) bool { return true }, // refined by updateVerify below
	before:        func(lifePayload, client.ObjectState) bool { return false },
}

func planUpdate(ctx context.Context, p LifecyclePorts, pc operation.PlanContext, in UpdateInput) (*lifePlan, error) {
	if len(in.Set)+len(in.Clear) == 0 {
		return nil, fmt.Errorf("%w: nothing to change", operation.ErrInvalid)
	}
	var edits []writechange.Edit
	var names []string
	seen := map[string]bool{}
	for _, k := range sortedKeys(in.Set) {
		c, ok := canonicalAttr(k, false)
		if !ok || !allowedAttr(c, false) || seen[c] || !validValue(in.Set[k]) || in.Set[k] == "" {
			return nil, fmt.Errorf("%w: %s: %s", operation.ErrInvalid, ReasonAttributeDenied, k)
		}
		seen[c] = true
		names = append(names, c)
		edits = append(edits, writechange.Edit{Op: "set", Attribute: c, Values: []string{in.Set[k]}})
	}
	for _, k := range in.Clear {
		c, ok := canonicalAttr(k, false)
		if !ok || !allowedAttr(c, false) || seen[c] {
			return nil, fmt.Errorf("%w: %s: %s", operation.ErrInvalid, ReasonAttributeDenied, k)
		}
		seen[c] = true
		names = append(names, c)
		edits = append(edits, writechange.Edit{Op: "clear", Attribute: c})
	}
	st, err := readUser(ctx, p, pc, in.Target, names, false)
	if err != nil {
		return nil, err
	}
	// Only attributes whose value really changes are planned: an update that changes nothing is no step.
	var real []writechange.Edit
	before := map[string][]string{}
	var keys []string
	for _, e := range edits {
		cur := st.Attrs[e.Attribute]
		if e.Op == "set" && slices.Equal(cur, e.Values) || e.Op == "clear" && len(cur) == 0 {
			continue
		}
		real = append(real, e)
		keys = append(keys, e.Attribute)
		before[e.Op+":"+e.Attribute] = cur
	}
	if len(real) == 0 {
		return nil, nil
	}
	wa, err := writechange.UpdateAttrs(real)
	if err != nil {
		return nil, fmt.Errorf("%w: the update does not encode", operation.ErrInvalid)
	}
	return &lifePlan{
		sp: operation.StepPlan{
			Target: in.Target.objTarget(), Kind: writechange.KeyObjectUpdate, Diff: diffOfAttrs(wa, before),
			Reversibility:       operation.Reversible,
			ReversibilityReason: "the previous values are recorded in the diff; setting them again undoes the update",
		},
		pl: lifePayload{Target: in.Target, Keys: keys},
	}, nil
}

// ---- delete ----

var deleteSpec = lifeSpec[DeleteInput]{
	id: DeleteID, perm: PermDelete, schema: "#/components/schemas/AdUserAccount", audit: AuditDeleted,
	reversibility: operation.Irreversible, gone: true,
	plan:      planDelete,
	satisfied: func(lifePayload, client.ObjectState) bool { return false },
	before:    func(lifePayload, client.ObjectState) bool { return true },
}

func planDelete(ctx context.Context, p LifecyclePorts, pc operation.PlanContext, in DeleteInput) (*lifePlan, error) {
	st, err := readUser(ctx, p, pc, in.Target, []string{"memberOf"}, false)
	if err != nil {
		return nil, err
	}
	bin, err := p.Reader.RecycleBin(ctx, pc.Pins, authority.NamingContextID(in.NamingContext))
	if err != nil {
		return nil, readError(err)
	}
	groups := len(st.Attrs["memberOf"])
	sp := operation.StepPlan{Target: in.Target.objTarget(), Kind: writechange.KeyObjectDelete}
	if bin {
		sp.Reversibility = operation.Lossy
		sp.ReversibilityReason = "the AD Recycle Bin keeps the object until its deleted-object lifetime ends; restore is Lossy (see ad.user.restore)"
		sp.Preconditions = []string{"the AD Recycle Bin is enabled: the object moves to Deleted Objects and can be restored until its lifetime ends"}
	} else {
		sp.Reversibility = operation.Irreversible
		sp.ReversibilityReason = "the AD Recycle Bin is not enabled: the object becomes a tombstone, its link values and most attributes are gone, and this product does not restore it"
		sp.Preconditions = []string{"the AD Recycle Bin is not enabled: the delete cannot be undone"}
	}
	if groups > 0 {
		sp.Preconditions = append(sp.Preconditions, fmt.Sprintf("the account is a member of %d group(s); the memberships end with the delete", groups))
	}
	return &lifePlan{sp: sp, pl: lifePayload{Target: in.Target}}, nil
}

// ---- move ----

var moveSpec = lifeSpec[MoveInput]{
	id: MoveID, perm: PermMove, schema: "#/components/schemas/AdUserMove", audit: AuditMoved,
	reversibility: operation.Reversible,
	plan:          planMove,
	satisfied:     func(pl lifePayload, st client.ObjectState) bool { return st.Parent == pl.Parent },
	before:        func(pl lifePayload, st client.ObjectState) bool { return st.Parent == pl.OldParent },
	inverse: func(pl lifePayload, _ LifeOutcome) (MoveInput, error) {
		return MoveInput{Target: pl.Target, NewParentGuid: pl.OldParent}, nil
	},
}

func planMove(ctx context.Context, p LifecyclePorts, pc operation.PlanContext, in MoveInput) (*lifePlan, error) {
	st, err := readUser(ctx, p, pc, in.Target, nil, false)
	if err != nil {
		return nil, err
	}
	if err := readParent(ctx, p, pc, in.ConnectionID, in.NewParentGuid, authority.NamingContextID(in.NamingContext)); err != nil {
		return nil, err
	}
	if st.Parent == in.NewParentGuid {
		return nil, nil
	}
	attrs := []step.Attr{
		{Name: client.AttrNewParent, Values: []string{in.NewParentGuid}},
		{Name: client.AttrNewParentNC, Values: []string{in.NamingContext}},
	}
	return &lifePlan{
		sp: operation.StepPlan{
			Target: in.Target.objTarget(), Kind: client.DigestObjectMove,
			Diff: diffOfAttrs(attrs, map[string][]string{client.AttrNewParent: {st.Parent}, client.AttrNewParentNC: {in.NamingContext}}),
			Preconditions: []string{
				"source and destination container are re-checked live against the actor's scope immediately before the write",
				"a move can change which GPOs and delegated permissions apply to the account",
			},
			Reversibility:       operation.Reversible,
			ReversibilityReason: "moving the account back to its previous container undoes the move",
		},
		pl: lifePayload{Target: in.Target, Parent: in.NewParentGuid, OldParent: st.Parent},
	}, nil
}

// ---- rename ----

var renameSpec = lifeSpec[RenameInput]{
	id: RenameID, perm: PermMove, schema: "#/components/schemas/AdUserRename", audit: AuditRenamed,
	reversibility: operation.Reversible,
	plan:          planRename,
	satisfied:     func(pl lifePayload, st client.ObjectState) bool { return strings.EqualFold(st.RDN, pl.RDN) },
	before:        func(pl lifePayload, st client.ObjectState) bool { return strings.EqualFold(st.RDN, pl.OldRDN) },
	inverse: func(pl lifePayload, _ LifeOutcome) (RenameInput, error) {
		return RenameInput{Target: pl.Target, NewName: pl.OldRDN}, nil
	},
}

func planRename(ctx context.Context, p LifecyclePorts, pc operation.PlanContext, in RenameInput) (*lifePlan, error) {
	if err := validName(in.NewName); err != nil {
		return nil, err
	}
	st, err := readUser(ctx, p, pc, in.Target, nil, false)
	if err != nil {
		return nil, err
	}
	if st.RDN == in.NewName {
		return nil, nil
	}
	attrs := []step.Attr{{Name: client.AttrNewRDN, Values: []string{in.NewName}}}
	return &lifePlan{
		sp: operation.StepPlan{
			Target: in.Target.objTarget(), Kind: client.DigestObjectRename,
			Diff:                diffOfAttrs(attrs, map[string][]string{client.AttrNewRDN: {st.RDN}}),
			Preconditions:       []string{"the common name changes; sAMAccountName and userPrincipalName do not"},
			Reversibility:       operation.Reversible,
			ReversibilityReason: "renaming the account back to its previous name undoes the rename",
		},
		pl: lifePayload{Target: in.Target, RDN: in.NewName, OldRDN: st.RDN},
	}, nil
}

// ---- restore ----

var restoreSpec = lifeSpec[RestoreInput]{
	id: RestoreID, perm: PermRestore, schema: "#/components/schemas/AdUserRestore", audit: AuditRestored,
	reversibility: operation.Lossy, showDeleted: true,
	plan:      planRestore,
	satisfied: func(pl lifePayload, st client.ObjectState) bool { return !st.Deleted && st.Parent == pl.Parent },
	before:    func(_ lifePayload, st client.ObjectState) bool { return st.Deleted },
}

func planRestore(ctx context.Context, p LifecyclePorts, pc operation.PlanContext, in RestoreInput) (*lifePlan, error) {
	bin, err := p.Reader.RecycleBin(ctx, pc.Pins, authority.NamingContextID(in.NamingContext))
	if err != nil {
		return nil, readError(err)
	}
	if !bin {
		return nil, fmt.Errorf("%w: %s", operation.ErrInvalid, ReasonNoRecycleBin)
	}
	st, err := readUser(ctx, p, pc, in.Target, nil, true)
	if err != nil {
		return nil, err
	}
	parent, name := in.NewParentGuid, in.Name
	if parent == "" {
		parent = st.LastKnownParent
	}
	if name == "" {
		name = st.LastKnownRDN
	}
	if parent == "" || name == "" {
		return nil, fmt.Errorf("%w: the directory kept no last known parent or name; give newParentGuid and name", operation.ErrInvalid)
	}
	if err := validName(name); err != nil {
		return nil, err
	}
	if err := readParent(ctx, p, pc, in.ConnectionID, parent, authority.NamingContextID(in.NamingContext)); err != nil {
		return nil, err
	}
	attrs := []step.Attr{
		{Name: client.AttrNewParent, Values: []string{parent}},
		{Name: client.AttrNewParentNC, Values: []string{in.NamingContext}},
		{Name: client.AttrRDN, Values: []string{name}},
	}
	pre, reason, class := lossNotes(st.Links)
	return &lifePlan{
		sp: operation.StepPlan{
			Target: in.Target.objTarget(), Kind: client.DigestObjectRestore,
			Diff:                diffOfAttrs(attrs, nil),
			Preconditions:       pre,
			Reversibility:       class,
			ReversibilityReason: reason,
		},
		pl: lifePayload{Target: in.Target, Parent: parent, RDN: name},
	}, nil
}

// lossNotes lists what a restore re-grants and what stays dormant. The class is Lossy exactly when a
// retained link value cannot return now (its other end is still deleted); with the Recycle Bin on
// every other retained link is re-granted (connector contract §8.10.3 kind 6, ad-expert T-1585).
func lossNotes(links []client.LinkValue) ([]string, string, operation.Reversibility) {
	pre := []string{"restores the deleted account into the planned container under the planned name"}
	dormant := 0
	for _, l := range links {
		if l.Dormant {
			dormant++
			pre = append(pre, fmt.Sprintf("link value will not return: %s -> %s (deleted; restore it too)", l.Attribute, l.Object))
		} else {
			pre = append(pre, fmt.Sprintf("link value re-granted: %s -> %s", l.Attribute, l.Object))
		}
	}
	if dormant == 0 {
		return pre, "every retained link value is re-granted; links already lost to recycling cannot be read and are not listed", operation.Reversible
	}
	return pre, fmt.Sprintf("%d link value(s) will not return until the object at the other end is restored", dormant), operation.Lossy
}
