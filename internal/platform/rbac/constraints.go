package rbac

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Additive constraints on an assignment (T-1600). Neither is a scope root kind: they ride on the
// assignment DEL1 already stores.
//
//   - Templates (ADM-132) restrict which Templates the holder may create or modify with. No rows means
//     every Template. The check is TemplateGate.Check, called from an Action's Plan before any read.
//   - Sites (ADM-133) order the AD sites whose DCs the holder's operations try first. It is a hint:
//     ADR-0005 rule 5 still pins one DC per naming context, and an unhealthy preferred DC just loses.

const (
	// MaxTemplatesPerAssignment and MaxSitesPerAssignment bound the lists (the table allows 8 sites).
	MaxTemplatesPerAssignment = 64
	MaxSitesPerAssignment     = 8

	// ReasonTemplateNotPermitted is the stable, log-safe reason a Plan records when a technician uses a
	// Template none of their assignments allows.
	ReasonTemplateNotPermitted authz.Reason = "template_not_permitted"
)

// siteRe is an AD site name: letters, digits, space, dot, hyphen, underscore, 1 to 64 characters, not
// starting or ending with a space. AD allows more, but a name that is not plain is refused rather
// than escaped, because it is later compared with what a DC reports.
var siteRe = regexp.MustCompile(`^[A-Za-z0-9_.-](?:[A-Za-z0-9_. -]{0,62}[A-Za-z0-9_.-])?$`)

// ErrNoConstraintSource is returned by the gate when the assignment source cannot read constraints. The
// gate fails closed.
var ErrNoConstraintSource = errors.New("rbac: assignment source cannot read constraints")

// Constraint is the additive constraints of one assignment. Nil Templates: unrestricted. Sites are in
// preference order.
type Constraint struct {
	Templates []string
	Sites     []string
}

// ConstraintSource reads constraints by assignment ID, committed state only. Store implements it.
type ConstraintSource interface {
	Constraints(ctx context.Context, t tenant.ID, assignmentIDs []string) (map[string]Constraint, error)
}

// TemplateError is the typed refusal of the gate. It names the reason and the Template, never a grant.
type TemplateError struct {
	Template string
	Reason   authz.Reason
}

func (e *TemplateError) Error() string {
	return fmt.Sprintf("rbac: denied: %s (template %s)", e.Reason, e.Template)
}

// Unwrap makes every refusal match ErrDenied.
func (e *TemplateError) Unwrap() error { return ErrDenied }

func validConstraint(templates, sites []string) bool {
	if len(templates) > MaxTemplatesPerAssignment || len(sites) > MaxSitesPerAssignment {
		return false
	}
	seen := map[string]bool{}
	for _, t := range templates {
		k := strings.ToLower(t)
		if !accountIDRe.MatchString(t) || t == "00000000-0000-0000-0000-000000000000" || seen[k] {
			return false
		}
		seen[k] = true
	}
	seen = map[string]bool{}
	for _, s := range sites {
		k := strings.ToLower(s)
		if !siteRe.MatchString(s) || seen[k] {
			return false
		}
		seen[k] = true
	}
	return true
}

// insertConstraints writes the constraint rows of a new assignment.
func insertConstraints(ctx context.Context, tx store.Tx, tn tenant.ID, id string, templates, sites []string) error {
	for _, t := range templates {
		if _, err := tx.Exec(ctx, `INSERT INTO public.authz_assignment_templates (tenant_id, assignment_id, template_id) VALUES ($1::uuid, $2::uuid, $3::uuid)`,
			tn.String(), id, t); err != nil {
			return fmt.Errorf("rbac: creating assignment template: %w", err)
		}
	}
	for i, s := range sites {
		if _, err := tx.Exec(ctx, `INSERT INTO public.authz_assignment_sites (tenant_id, assignment_id, ordinal, site) VALUES ($1::uuid, $2::uuid, $3, $4)`,
			tn.String(), id, i, s); err != nil {
			return fmt.Errorf("rbac: creating assignment site: %w", err)
		}
	}
	return nil
}

// readTemplates reads the template lists of the given assignments inside tx.
func readTemplates(ctx context.Context, tx store.Tx, tn tenant.ID, ids []string) (map[string][]string, error) {
	out := map[string][]string{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := tx.Query(ctx, `SELECT assignment_id::text, template_id::text FROM public.authz_assignment_templates
WHERE tenant_id = $1::uuid AND assignment_id = ANY($2::uuid[]) ORDER BY assignment_id, template_id`, tn.String(), ids)
	if err != nil {
		return nil, fmt.Errorf("rbac: reading assignment templates: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, t string
		if err := rows.Scan(&id, &t); err != nil {
			return nil, fmt.Errorf("rbac: reading assignment templates: %w", err)
		}
		out[id] = append(out[id], t)
	}
	return out, rows.Err()
}

// templateEscalation is DM-36.I1 for the template constraint. A grantor whose own assignments for the
// role's permissions are template-restricted holds those permissions only for the intersection of their
// lists (the gate is deny-wins), so a grant must carry a non-empty list inside that intersection.
// Otherwise a restricted technician could hand out the same role unrestricted. A personal
// tenant-owner is exempt, like everywhere else in mustHold.
func templateEscalation(ctx context.Context, tx store.Tx, tn tenant.ID, actor []Assignment, perms []authz.Permission, templates []string) error {
	if slices.ContainsFunc(actor, func(a Assignment) bool { return a.TenantOwner && a.Via == nil && a.Subject == SubjectAccount }) {
		return nil
	}
	var ids []string
	for _, a := range actor {
		if slices.ContainsFunc(a.Permissions, func(p authz.Permission) bool { return slices.Contains(perms, p) }) {
			ids = append(ids, a.ID)
		}
	}
	lists, err := readTemplates(ctx, tx, tn, ids)
	if err != nil {
		return err
	}
	var allowed map[string]bool
	for _, id := range ids {
		l, restricted := lists[id]
		if !restricted {
			continue
		}
		m := map[string]bool{}
		for _, t := range l {
			if allowed == nil || allowed[t] {
				m[t] = true
			}
		}
		allowed = m
	}
	if allowed == nil {
		return nil // the grantor is unrestricted for these permissions
	}
	if len(templates) == 0 {
		return ErrEscalation
	}
	for _, t := range templates {
		if !allowed[strings.ToLower(t)] {
			return ErrEscalation
		}
	}
	return nil
}

// Constraints is ConstraintSource over the store: one short tenant transaction, committed state.
func (s *Store) Constraints(_ context.Context, t tenant.ID, ids []string) (map[string]Constraint, error) {
	out := map[string]Constraint{}
	var valid []string
	for _, id := range ids {
		if accountIDRe.MatchString(id) {
			valid = append(valid, id)
		}
	}
	if len(valid) == 0 {
		return out, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), readTimeout)
	defer cancel()
	err := s.db.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		ts, err := readTemplates(ctx, tx, t, valid)
		if err != nil {
			return err
		}
		for id, l := range ts {
			c := out[id]
			c.Templates = l
			out[id] = c
		}
		rows, err := tx.Query(ctx, `SELECT assignment_id::text, site FROM public.authz_assignment_sites
WHERE tenant_id = $1::uuid AND assignment_id = ANY($2::uuid[]) ORDER BY assignment_id, ordinal`, t.String(), valid)
		if err != nil {
			return fmt.Errorf("rbac: reading assignment sites: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var id, site string
			if err := rows.Scan(&id, &site); err != nil {
				return fmt.Errorf("rbac: reading assignment sites: %w", err)
			}
			c := out[id]
			c.Sites = append(c.Sites, site)
			out[id] = c
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// requesterAssignments are the assignments a chain's authority is made of: the requester's own and
// group-derived ones and, when an automation policy acts for them, the policy's.
func (a *Authorizer) requesterAssignments(ctx context.Context, tn tenant.ID, chain authority.Chain) ([]Assignment, error) {
	if chain.Validate() != nil || chain.Requester.Kind != authority.Human {
		return nil, denied(ReasonUnsupportedChain)
	}
	as, err := a.effective(ctx, tn, string(chain.Requester.ID), false)
	if err != nil {
		return nil, err
	}
	for _, v := range chain.Via {
		if v.Kind == authority.Automation {
			pas, err := a.automation(ctx, tn, string(v.ID))
			if err != nil {
				return nil, err
			}
			as = append(as, pas...)
		}
	}
	return as, nil
}

// CheckTemplate is the ADM-132 gate. An Action that creates or modifies from a Template calls it in
// Plan, before any directory read, and blocks the item with the returned error. The gate is deny-wins:
// every assignment of the chain's authority that grants perm must allow the Template (no list, or the
// list names it), and at least one must grant perm. It does not decide scope: the authoriser does. Being
// stricter than a per-scope match, it never lets a restriction on one assignment be bypassed through an
// unrestricted assignment elsewhere. An error that is not a *TemplateError means the check could not be
// made, and the caller treats it as a refusal.
func (a *Authorizer) CheckTemplate(ctx context.Context, chain authority.Chain, perm authz.Permission, template string) error {
	tid, ok := authority.TenantFrom(ctx)
	if !ok {
		return denied(ReasonNoTenant)
	}
	tn, err := tenant.Parse(tid)
	if err != nil {
		return denied(ReasonNoTenant)
	}
	refuse := &TemplateError{Template: template, Reason: ReasonTemplateNotPermitted}
	if !accountIDRe.MatchString(template) {
		return refuse
	}
	cs, ok := a.src.(ConstraintSource)
	if !ok {
		return ErrNoConstraintSource
	}
	as, err := a.requesterAssignments(ctx, tn, chain)
	if err != nil {
		return err
	}
	var holding []string
	for _, x := range as {
		if slices.Contains(x.Permissions, perm) {
			holding = append(holding, x.ID)
		}
	}
	if len(holding) == 0 {
		return refuse
	}
	cons, err := cs.Constraints(ctx, tn, holding)
	if err != nil {
		return fmt.Errorf("rbac: reading template constraints: %w", err)
	}
	for _, id := range holding {
		c := cons[id]
		if len(c.Templates) > 0 && !slices.ContainsFunc(c.Templates, func(t string) bool { return strings.EqualFold(t, template) }) {
			return refuse
		}
	}
	return nil
}

// PreferredSites returns the AD sites to try first for the chain's operations (ADM-133): the sites of
// every assignment of the chain's authority, in assignment order then ordinal, first occurrence wins.
// It returns none when the source cannot read constraints: a site preference is a hint, so its absence
// is not a refusal.
func (a *Authorizer) PreferredSites(ctx context.Context, chain authority.Chain) ([]string, error) {
	tid, ok := authority.TenantFrom(ctx)
	if !ok {
		return nil, denied(ReasonNoTenant)
	}
	tn, err := tenant.Parse(tid)
	if err != nil {
		return nil, denied(ReasonNoTenant)
	}
	cs, ok := a.src.(ConstraintSource)
	if !ok {
		return nil, nil
	}
	as, err := a.requesterAssignments(ctx, tn, chain)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(as))
	for _, x := range as {
		ids = append(ids, x.ID)
	}
	slices.Sort(ids)
	cons, err := cs.Constraints(ctx, tn, ids)
	if err != nil {
		return nil, fmt.Errorf("rbac: reading site preferences: %w", err)
	}
	var out []string
	for _, id := range ids {
		for _, s := range cons[id].Sites {
			if !slices.ContainsFunc(out, func(o string) bool { return strings.EqualFold(o, s) }) {
				out = append(out, s)
			}
		}
	}
	return out, nil
}
