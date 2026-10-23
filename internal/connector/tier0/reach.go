package tier0

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/skenzeriq/activediq/internal/connector/graph"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
)

// walk is the TM-D25 rule 1 closure: from each seed group, its members (direct for role-assignable
// groups, transitive otherwise), its owners and the principals of its PIM-for-Groups schedules; a
// group found on the way joins the walk. It runs to a fixpoint over a visited set keyed by group
// and basis, so a cycle ends and both bases apply when both do.
type walk struct {
	c         *Classifier
	ctx       context.Context
	s         *Set
	holdingSP map[string]bool
	seen      map[string]bool
	queue     []walkItem
	// pimEmpty: the schedule reads were answered "not licensed" and corroborated (rule 5).
	pimEmpty bool
}

type walkItem struct {
	id     string
	basis  Basis
	direct bool // direct members only (a role-assignable seed cannot nest)
}

func (w *walk) enqueue(id string, b Basis, direct bool) {
	key := fmt.Sprintf("%s|%d", strings.ToLower(id), b)
	if w.seen[key] {
		return
	}
	w.seen[key] = true
	w.queue = append(w.queue, walkItem{id: id, basis: b, direct: direct})
}

func (w *walk) run() error {
	for len(w.queue) > 0 {
		it := w.queue[0]
		w.queue = w.queue[1:]
		if err := w.group(it); err != nil {
			return err
		}
	}
	return nil
}

func (w *walk) group(it walkItem) error {
	gid, err := objectID(it.id)
	if err != nil {
		return fmt.Errorf("tier0: group in the reach closure: %w", err)
	}
	lid := strings.ToLower(it.id)
	w.s.add(it.id, it.basis)
	if w.s.reach[lid] == nil {
		w.s.reach[lid] = map[Basis]bool{}
	}
	w.s.reach[lid][it.basis] = true

	var mem []graph.DirectoryObject
	if it.direct {
		mem, err = w.c.r.GroupMembers(w.ctx, gid)
	} else {
		mem, err = w.c.r.GroupTransitiveMembers(w.ctx, gid)
	}
	if err != nil {
		return fmt.Errorf("tier0: members of a group in the reach closure: %w", err)
	}
	own, err := w.c.r.GroupOwners(w.ctx, gid)
	if err != nil {
		return fmt.Errorf("tier0: owners of a group in the reach closure: %w", err)
	}
	for _, o := range append(mem, own...) {
		if err := w.principal(o.ID, o.Type(), it.basis, !it.direct); err != nil {
			return err
		}
	}
	scheds, err := w.schedules(gid)
	if err != nil {
		return err
	}
	for _, sc := range scheds {
		if err := w.principal(sc.PrincipalID, sc.PrincipalType, it.basis, false); err != nil {
			return err
		}
	}
	return nil
}

// principal adds one member, owner or schedule principal. A service principal there is a privileged
// SP (its owners are E3); a group joins the walk. An empty or unknown type could be an app, so refuse.
func (w *walk) principal(id, typ string, b Basis, devices bool) error {
	if _, err := objectID(id); err != nil {
		return fmt.Errorf("tier0: group in the reach closure has a principal: %w", err)
	}
	switch typ {
	case "user":
	case "device", "orgContact":
		// Only groups that can hold them (not a role-assignable group's own members).
		if !devices {
			return fmt.Errorf("tier0: group in the reach closure has a principal of unexpected type %q", typ)
		}
	case "servicePrincipal":
		w.holdingSP[strings.ToLower(id)] = true
	case "group":
		w.enqueue(id, b, false)
	default:
		return fmt.Errorf("tier0: group in the reach closure has a principal of unknown type %q", typ)
	}
	w.s.add(id, b)
	return nil
}

// schedules reads the counting schedules of one group. It is where rule 4 (any failure fails the
// snapshot) and rule 5 (a corroborated "not licensed" is an empty set) are decided.
func (w *walk) schedules(gid guid.GUID) ([]graph.GroupSchedule, error) {
	if w.pimEmpty {
		return nil, nil
	}
	raw, err := w.c.r.GroupSchedules(w.ctx, gid)
	if err != nil {
		ok, cerr := w.c.corroborateUnlicensed(w.ctx, err)
		if cerr != nil {
			return nil, cerr
		}
		if !ok {
			return nil, fmt.Errorf("tier0: PIM for Groups schedules: %w", err)
		}
		w.pimEmpty = true
		return nil, nil
	}
	return counted(raw, gid.String(), w.s.computedAt)
}

// counted applies TM-D25 rule 2 to schedules read for the group want (want "" for a read by
// principal): every schedule counts, whatever its status, unless it ended before at. Future-dated
// and pending-approval schedules count. An accessId, empty status or principal type the classifier
// does not know fails the snapshot.
func counted(in []graph.GroupSchedule, want string, at time.Time) ([]graph.GroupSchedule, error) {
	var out []graph.GroupSchedule
	for _, sc := range in {
		switch sc.AccessID {
		case "member", "owner":
		default:
			return nil, fmt.Errorf("tier0: PIM for Groups schedule has unknown accessId %q", sc.AccessID)
		}
		if sc.Status == "" {
			return nil, errors.New("tier0: PIM for Groups schedule has no status")
		}
		switch sc.PrincipalType {
		case "user", "group", "servicePrincipal":
		default:
			return nil, fmt.Errorf("tier0: PIM for Groups schedule has principal of unknown type %q", sc.PrincipalType)
		}
		if _, err := objectID(sc.PrincipalID); err != nil {
			return nil, fmt.Errorf("tier0: PIM for Groups schedule principal: %w", err)
		}
		if want != "" && !strings.EqualFold(sc.GroupID, want) {
			return nil, errors.New("tier0: PIM for Groups schedule belongs to another group than the one asked for")
		}
		if sc.End != nil && sc.End.Before(at) {
			continue
		}
		out = append(out, sc)
	}
	return out, nil
}

// corroborateUnlicensed decides whether err is the lab-G11-pinned "tenant has no PIM licence"
// answer AND subscribedSkus shows no enabled PIM service plan (rule 5). false with a nil error means
// "not unlicensed": the caller fails the snapshot with err. A failed subscribedSkus read is an error.
func (c *Classifier) corroborateUnlicensed(ctx context.Context, err error) (bool, error) {
	u := c.unlicensed
	var ge *graph.Error
	if !u.pinned() || !errors.As(err, &ge) || ge.HTTPStatus != u.HTTPStatus || ge.GraphCode != u.GraphCode {
		return false, nil
	}
	skus, serr := c.r.SubscribedSKUs(ctx)
	if serr != nil {
		return false, fmt.Errorf("tier0: PIM for Groups schedules: %w (subscribedSkus unreadable: %v)", err, serr)
	}
	plans := map[string]bool{}
	for _, p := range u.PlanIDs {
		plans[strings.ToLower(p)] = true
	}
	for _, sku := range skus {
		for _, sp := range sku.ServicePlans {
			// Anything but an explicit Disabled counts as licensed: the assumption only helps the attacker.
			if plans[strings.ToLower(sp.ServicePlanID)] && !strings.EqualFold(sp.ProvisioningStatus, "Disabled") {
				return false, nil
			}
		}
	}
	return true, nil
}
