package sync

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"
	"time"

	"google.golang.org/grpc/status"

	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// The limits of one ScopedSearch request (connector contract §5.1, internal/connector/read), so the engine
// never sends a request the connector would refuse for its size.
const (
	maxRootsPerRequest      = 64
	maxAttributesPerRequest = 64
	maxPageSize             = 1000
	maxChainHops            = 128 // the store's bound on a stored chain
)

// FullCycle reads, in full, every managed domain naming context of one active AD connection and hands it to
// the inventory ingester (blueprint §5.2 and §14 flow 1; the AD initial state is a ScopedSearch, contract
// §6.1). Per domain it
//
//  1. claims the domain's cursor under its lease (a lease behind the stored fencing token is ErrFenced, and
//     nothing has been read from the connector yet);
//  2. skips a domain whose cursor is already incremental (its full read is done; a resync moves the cursor
//     to resync_required first);
//  3. pre-scans the domain with the two attributes it needs (objectClass, objectSid): the parent link of
//     every object, so a stored chain is whole whatever order the directory returns entries in, and the
//     groups' SIDs, so primaryGroupID resolves to a group that may arrive after its member. The pre-scan
//     keeps 32 bytes per object and a map entry per group, never an object;
//  4. streams the domain again on the same DC, maps each entry (a malformed one is counted and skipped),
//     and ingests bounded batches, one tenant transaction each: MoreBatches on all but the last, and on the
//     last PassNCs and the cursor move to incremental, in that same transaction.
//
// A domain that fails (a cut-off stream, a connector error) keeps the rows its earlier batches committed,
// records no pass and leaves its cursor alone; the other domains are still read, and the error is a joined
// *DomainError per failed domain. A rerun re-reads the domain and its upserts are idempotent. A fenced
// lease, a cancelled context or a port failure aborts the whole cycle.
//
// Only domain NCs are read: a configuration, schema or application NC, or one the connector does not report
// as a domain, is ErrNotDomainNC before any search is sent.
func (e *Engine) FullCycle(ctx context.Context, tid tenant.ID, id connection.ID, lease LeaseFunc) (Report, error) {
	rep := Report{Connection: inventory.ConnectionID(id)}
	if err := e.ready(); err != nil {
		return rep, err
	}
	if lease == nil || tid.IsZero() {
		return rep, fmt.Errorf("%w: lease or tenant", ErrNotConfigured)
	}
	conn, err := e.Conns.Get(ctx, tid, id)
	if err != nil {
		return rep, fmt.Errorf("%w: connection: %w", ErrSource, err)
	}
	ref, err := e.refuse(conn, id)
	if err != nil {
		return rep, err
	}
	managed, err := e.Domains.ManagedDomains(ctx, tid, id)
	if err != nil {
		return rep, fmt.Errorf("%w: managed domains: %w", ErrSource, err)
	}
	domains, err := checkDomains(managed)
	if err != nil {
		return rep, err
	}

	// Claim every cursor before the first connector call, so a deposed holder reads nothing.
	claims, err := e.claimAll(ctx, tid, id, domains, lease)
	if err != nil {
		return rep, err
	}
	type target struct {
		claim
		skip bool
	}
	targets := make([]target, len(claims))
	for i, c := range claims {
		targets[i] = target{claim: c, skip: c.state == StateIncremental}
		rep.Domains = append(rep.Domains, DomainReport{NC: c.d.NC, Skipped: targets[i].skip})
	}
	todo := false
	for _, t := range targets {
		todo = todo || !t.skip
	}
	if !todo {
		return rep, nil
	}

	cc, pageSize, err := e.connect(ctx, id, ref, domains)
	if err != nil {
		return rep, err
	}

	var failed []error
	for i, t := range targets {
		if t.skip {
			continue
		}
		r := &readJob{e: e, tid: tid, conn: id, ref: ref, cc: cc, key: t.key, lease: t.lease, nc: t.d.NC, pageSize: pageSize, rep: &rep.Domains[i]}
		err := r.run(ctx)
		e.logDomain(rep.Domains[i], err)
		if err == nil {
			continue
		}
		var de *DomainError
		if errors.As(err, &de) && !errors.Is(err, ErrFenced) && ctx.Err() == nil {
			failed = append(failed, err)
			continue
		}
		return rep, err
	}
	return rep, errors.Join(failed...)
}

// connect resolves the connection's connector, checks that every domain to read is a domain NC of this
// directory, and returns the page size to ask for.
func (e *Engine) connect(ctx context.Context, id connection.ID, ref *connectorv1.ConnectionRef, domains []Domain) (client.Reader, uint32, error) {
	cc, err := e.Source.Reader(ctx, string(id))
	if err != nil {
		return nil, 0, fmt.Errorf("%w: connector: %w", ErrSource, err)
	}
	desc, err := cc.Describe(ctx, &connectorv1.DescribeRequest{Connection: ref})
	if err != nil {
		if ctx.Err() != nil {
			return nil, 0, ctx.Err()
		}
		return nil, 0, &ConnectorError{Code: status.Code(err)}
	}
	if err := confirmDomains(desc, domains); err != nil {
		return nil, 0, err
	}
	return cc, min(desc.GetLimits().GetMaxPageSize(), maxPageSize), nil
}

// claim is a managed domain whose partition cursor this holder has claimed under its lease.
type claim struct {
	d     Domain
	key   Key
	lease jobs.Lease
	state State
}

// claimAll claims the cursor of every domain under its lease, in order, before anything is read from the
// connector: a lease behind the stored fencing token is ErrFenced, and a paused partition is ErrPaused.
func (e *Engine) claimAll(ctx context.Context, tid tenant.ID, id connection.ID, domains []Domain, lease LeaseFunc) ([]claim, error) {
	out := make([]claim, 0, len(domains))
	for _, d := range domains {
		part, err := NCPartition(string(d.NC))
		if err != nil {
			return nil, fmt.Errorf("%w: naming context", ErrNotDomainNC)
		}
		key := Key{Connection: inventory.ConnectionID(id), Partition: part}
		name, err := LeaseName(key)
		if err != nil {
			return nil, err
		}
		l, err := lease(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("%w: lease: %w", ErrSource, err)
		}
		var cur Cursor
		if err := e.Tenants.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) error {
			var err error
			cur, err = e.Cursors.Claim(ctx, tx, key, l)
			return err
		}); err != nil {
			return nil, err
		}
		if cur.State == StatePaused {
			return nil, fmt.Errorf("%w", ErrPaused)
		}
		out = append(out, claim{d: d, key: key, lease: l, state: cur.State})
	}
	return out, nil
}

// refuse is the gate before anything is read: an active, unretired AD forest connection with a verified
// directory identity. It returns the ConnectionRef the connector expects.
func (e *Engine) refuse(c connection.Connection, id connection.ID) (*connectorv1.ConnectionRef, error) {
	switch {
	case c.ID != id || c.Kind != connection.KindADForest:
		return nil, &Refusal{Reason: RefusedNotAD}
	case c.RetiredAt != nil:
		return nil, &Refusal{Reason: RefusedRetired}
	case c.State != connection.StateActive:
		return nil, &Refusal{Reason: RefusedNotActive}
	}
	g, err := wireOf(string(c.DirectoryIdentity))
	if err != nil {
		return nil, &Refusal{Reason: RefusedNoIdentity}
	}
	return &connectorv1.ConnectionRef{ConnectionId: string(id), DirectoryIdentity: &connectorv1.DirectoryIdentity{
		Identity: &connectorv1.DirectoryIdentity_AdForest{AdForest: &connectorv1.AdForestIdentity{ForestRootNcGuid: g}}}}, nil
}

// checkDomains validates the managed set: domain NCs only, canonical GUIDs, each once.
func checkDomains(in []Domain) ([]Domain, error) {
	if len(in) == 0 {
		return nil, ErrNoManagedDomains
	}
	seen := map[inventory.GUID]bool{}
	out := make([]Domain, 0, len(in))
	for _, d := range in {
		if d.Kind != NCDomain {
			return nil, ErrNotDomainNC
		}
		if _, err := NCPartition(string(d.NC)); err != nil {
			return nil, ErrNotDomainNC
		}
		if seen[d.NC] {
			continue
		}
		seen[d.NC] = true
		out = append(out, d)
	}
	return out, nil
}

// confirmDomains checks the managed set against what the connector reports: each must be a domain NC of
// this directory. A configuration or schema NC GUID that reached the set by any route stops here.
func confirmDomains(desc *connectorv1.DescribeResponse, want []Domain) error {
	kinds := map[string]connectorv1.NamingContextKind{}
	for _, nc := range desc.GetNamingContexts() {
		if v := nc.GetNcGuid().GetValue(); len(v) == 16 {
			kinds[textOf(v)] = nc.GetKind()
		}
	}
	for _, d := range want {
		if kinds[string(d.NC)] != connectorv1.NamingContextKind_NAMING_CONTEXT_KIND_DOMAIN {
			return ErrNotDomainNC
		}
	}
	return nil
}

func (e *Engine) logDomain(r DomainReport, err error) {
	lvl := slog.LevelInfo
	if err != nil {
		lvl = slog.LevelWarn
	}
	attrs := []any{"nc", string(r.NC), "completed", r.Completed, "skipped", r.Skipped, "entries", r.Entries, "mapped", r.Mapped,
		"refused", r.Refused, "batches", r.Batches, "ancestry_unresolved", r.AncestryUnresolved,
		"groups_partial", r.GroupsPartial, "members_unresolved", r.MembersUnresolved}
	keys := make([]RefusalKey, 0, len(r.RefusedBy))
	for k := range r.RefusedBy {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Attr+string(keys[i].Code) < keys[j].Attr+string(keys[j].Code) })
	for _, k := range keys {
		attrs = append(attrs, "refused."+k.Attr+"."+string(k.Code), r.RefusedBy[k])
	}
	// The first few refused objects by GUID (an identifier, not a directory value); the report has up to
	// MaxRefusedEntries.
	for i, re := range r.RefusedEntries {
		if i == 20 {
			break
		}
		attrs = append(attrs, fmt.Sprintf("refused_object.%d", i), string(re.Object)+" "+re.Attr+"."+string(re.Code))
	}
	if err != nil {
		// Never err.Error(): a store error can carry a database message that repeats a bound value. Log the
		// phase and a class from a fixed vocabulary.
		phase, class := errClass(err)
		attrs = append(attrs, "error_phase", phase, "error_class", class)
	}
	e.log().Log(context.Background(), lvl, "sync: full read of a domain", attrs...)
}

// textOf is the canonical text of a connector Guid (16 bytes in the order of the text).
func textOf(b []byte) string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// wireOf is the connector Guid of a canonical text GUID.
func wireOf(s string) (*connectorv1.Guid, error) {
	k, ok := keyOf(s)
	if !ok {
		return nil, ErrNotDomainNC
	}
	return &connectorv1.Guid{Value: k[:]}, nil
}

// keyOf is the 16 bytes (in the order of the text) of a canonical text GUID.
func keyOf(s string) (k [16]byte, ok bool) {
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return k, false
	}
	b, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if err != nil || len(b) != 16 {
		return k, false
	}
	copy(k[:], b)
	return k, k != [16]byte{}
}

// searchSpec is one full-domain ScopedSearch.
type searchSpec struct {
	attrs    []string
	pageSize uint32
	pin      *connectorv1.Guid
}

// stream runs one ScopedSearch of the whole domain (a subtree search rooted at the NC head) and calls onEntry
// for every entry as it arrives, never buffering. It returns the completion marker's observation; a stream
// that ends without the marker is ErrIncomplete, and a connector failure is a *ConnectorError, so no
// directory text reaches an error.
func (r *readJob) stream(ctx context.Context, spec searchSpec, onEntry func(*connectorv1.DirectoryEntry) error) (*connectorv1.Observation, error) {
	if len(spec.attrs) == 0 || len(spec.attrs) > maxAttributesPerRequest {
		return nil, fmt.Errorf("%w: attribute count", ErrNotConfigured)
	}
	root, err := wireOf(string(r.nc))
	if err != nil {
		return nil, err
	}
	roots := []*connectorv1.SearchRoot{{Guid: root, NcGuid: root}}
	if len(roots) > maxRootsPerRequest {
		return nil, fmt.Errorf("%w: root count", ErrNotConfigured)
	}
	req := &connectorv1.ScopedSearchRequest{
		Connection: r.ref,
		Roots:      roots,
		Depth:      connectorv1.SearchDepth_SEARCH_DEPTH_SUBTREE,
		Filter:     &connectorv1.Filter{Node: &connectorv1.Filter_Present{Present: "objectClass"}},
		Attributes: spec.attrs,
		PageSize:   min(spec.pageSize, maxPageSize),
	}
	if spec.pin != nil {
		req.Dc = &connectorv1.DcSelection{PinnedDsaGuid: spec.pin}
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel() // abandons the LDAP search on every early return
	st, err := r.cc.ScopedSearch(ctx, req)
	if err != nil {
		return nil, r.connErr(ctx, err)
	}
	var done *connectorv1.Observation
	completed := false
	for {
		m, err := st.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, r.connErr(ctx, err)
		}
		if completed {
			return nil, ErrProtocol
		}
		switch ev := m.GetEvent().(type) {
		case *connectorv1.ScopedSearchResponse_Batch:
			for _, en := range ev.Batch.GetEntries() {
				if err := onEntry(en); err != nil {
					return nil, err
				}
			}
		case *connectorv1.ScopedSearchResponse_RootCompleted:
			if g := ev.RootCompleted.GetRoot().GetValue(); len(g) != 16 || textOf(g) != string(r.nc) {
				return nil, ErrProtocol
			}
		case *connectorv1.ScopedSearchResponse_Completed:
			completed, done = true, ev.Completed.GetObserved()
		default:
			return nil, ErrProtocol
		}
	}
	if !completed {
		return nil, ErrIncomplete
	}
	return done, nil
}

func (r *readJob) connErr(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return &ConnectorError{Code: status.Code(err)}
}

// errClass is the phase and the class of a failure of a domain read, both from a fixed vocabulary: the
// phase of a *DomainError, and the sentinel (with the gRPC code of a connector failure or the reason of a
// refusal) that matches. Anything else is "other", whatever its text.
func errClass(err error) (phase, class string) {
	phase = "cycle"
	var de *DomainError
	if errors.As(err, &de) {
		phase = de.Phase
	}
	var ce *ConnectorError
	var rf *Refusal
	switch {
	case errors.As(err, &ce):
		return phase, "connector:" + ce.Code.String()
	case errors.As(err, &rf):
		return phase, "refused:" + string(rf.Reason)
	case errors.Is(err, inventory.ErrMassDelete):
		return phase, "mass_delete_refused"
	case errors.Is(err, ErrFenced):
		return phase, "fenced"
	case errors.Is(err, ErrPaused):
		return phase, "paused"
	case errors.Is(err, ErrIncomplete):
		return phase, "incomplete"
	case errors.Is(err, ErrProtocol):
		return phase, "protocol"
	case errors.Is(err, ErrNotDomainNC):
		return phase, "not_domain_nc"
	case errors.Is(err, ErrSource):
		return phase, "source"
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return phase, "context"
	}
	return phase, "other"
}

// utc is the engine clock, UTC.
func (e *Engine) utc() time.Time { return e.now().UTC() }
