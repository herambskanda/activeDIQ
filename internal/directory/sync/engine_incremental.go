package sync

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// Ports of IncrementalCycle, each satisfied structurally by the production type named with it.
type (
	// Feed is the connector's change feed (client.ChangeFeedReader).
	Feed interface {
		Read(ctx context.Context, tid tenant.ID, req client.FeedRequest, fn func(context.Context, *connectorv1.ChangeBatch) error) (client.FeedResult, error)
	}
	// FeedCursors is the cursor store's feed side (Store): the fenced position, advance and lifecycle moves.
	FeedCursors interface {
		Claim(ctx context.Context, tx store.Tx, k Key, l jobs.Lease) (Cursor, error)
		Position(ctx context.Context, tx store.Tx, k Key, l jobs.Lease) (Cursor, Cookie, error)
		Advance(ctx context.Context, tx store.Tx, k Key, l jobs.Lease, m Move) (Cursor, error)
		CompleteFull(ctx context.Context, tx store.Tx, k Key, l jobs.Lease, f FullSync) (Cursor, error)
		RequireResync(ctx context.Context, tx store.Tx, k Key, l jobs.Lease) (Cursor, error)
		PauseConnection(ctx context.Context, tx store.Tx, c inventory.ConnectionID) (int64, error)
		ResumeConnection(ctx context.Context, tx store.Tx, c inventory.ConnectionID) (int64, error)
	}
)

// ErrRetryable is the class of a cycle failure that leaves the cursor as it was and may simply be run again:
// the DC that issued the cookie is unreachable or throttling, or the stream was cut off. The detail is
// *RetryableError. A retry goes to the same DC; it never re-primes (DM-19.I4).
var ErrRetryable = errors.New("sync: the cycle failed and may be retried")

// RetryableError carries the connector's back-off advice (zero when it gave none) and the typed cause.
type RetryableError struct {
	After time.Duration
	Err   error
}

func (e *RetryableError) Error() string { return ErrRetryable.Error() + ": " + e.Err.Error() }

// Is makes errors.Is(err, ErrRetryable) true.
func (e *RetryableError) Is(target error) bool { return target == ErrRetryable }

// Unwrap returns the cause (client.ErrUnreachableDC, ErrThrottled or ErrFeedIncomplete).
func (e *RetryableError) Unwrap() error { return e.Err }

// ResyncReason is a fixed vocabulary for why a cycle resynced.
type ResyncReason string

// The reasons a cycle ran a full resync.
const (
	ResyncRequested ResyncReason = "cursor_resync_required" // the cursor already said so
	ResyncNoCookie  ResyncReason = "no_feed_position"       // incremental after a scan: nothing to resume from
	ResyncResumed   ResyncReason = "resumed_from_pause"     // the connection was suspended and is active again
	ResyncStale     ResyncReason = "stale_cookie"           // the connector refused the cookie (see StaleReason)
	ResyncBadCookie ResyncReason = "unusable_cookie"        // the stored cookie could not be decoded or was refused as malformed
	ResyncNeedsRead ResyncReason = "needs_read"             // a change could not be applied in full (see ApplyReport.NeedsRead)
)

// IncrementalReport is what IncrementalCycle did for one naming context.
type IncrementalReport struct {
	NC inventory.GUID
	// Primed says the cycle established a position (prime, full read, finish) before resuming.
	Primed bool
	// Resyncs lists why the cycle resynced, in order; empty for a plain resume. StaleReason is the connector's
	// reason for a stale cookie.
	Resyncs     []ResyncReason
	StaleReason connectorv1.ResyncReason
	// Paused says the cycle found the connection suspended, paused the cursors and read nothing.
	Paused bool
	// Full is the full read of a prime or resync, nil for a plain resume.
	Full *DomainReport
	// Reconciled says the deletions a feed cannot see were inferred by a reconcile; Reconcile holds its counts.
	Reconciled bool
	Reconcile  inventory.Reconciled
	// Batches and Changes are the feed batches applied and the object changes they carried.
	Batches, Changes int
	// Applied sums what the batches did.
	Created, Updated, Stale, Refused, EdgesRemoved int
	// Completed says a feed cycle ran to its cycle_complete batch, so the pass watermark moved.
	Completed bool
}

// feedAttrs are the attributes the feed is asked for beyond its mandatory set: the closed list.
func feedAttrs() []string { return Attributes() }

// IncrementalCycle runs one change-feed cycle of one managed domain naming context (connector contract §6.1,
// DM-19). The lease is as in FullCycle's LeaseFunc: it names the partition's own lease, and a reconcile needs
// the other domains' too.
//
//   - A cursor with a stored position resumes from it. Each batch is applied (Applier) and its cookie_after is
//     stored in the SAME tenant transaction, through the fenced store, so a crash replays at most one batch
//     (DM-19.I1). The pass watermark moves on the cycle_complete batch, quiet domain or not.
//   - A cursor with no position (initial_sync; an incremental one left by a scan; resync_required) runs the
//     contract order: prime the feed, read the whole domain (FullCycle's read), then resume from the prime's
//     cookie, so what changed during the read is replayed. A resync (anything but initial_sync) also reconciles,
//     so a deletion missed while the position was lost is found, and only then does the cursor become
//     incremental with the new cookie.
//   - STALE_COOKIE of any reason, a stored cookie that cannot be decoded or is refused as malformed, and a
//     change the apply could not complete (it names objects to read) set resync_required in the transaction that
//     holds the batch and continue as a resync in the same call.
//   - UNREACHABLE_DC and THROTTLED are an ErrRetryable (*RetryableError): the cursor, the cookie and the state
//     are untouched and nothing is re-primed, because the cookie is valid on its DC only (DM-19.I4).
//   - A suspended connection pauses the partition's cursors and the naming context's pass, reads nothing and
//     returns the *Refusal. A paused cursor on an active connection is resumed as resync_required.
//
// The children of a moved or renamed parent are not in the feed: inventory re-derives their ancestry (and dn)
// from the parent's new position when it writes the parent (DM-19.I5).
func (e *Engine) IncrementalCycle(ctx context.Context, tid tenant.ID, id connection.ID, nc inventory.GUID, lease LeaseFunc) (IncrementalReport, error) {
	rep := IncrementalReport{NC: nc}
	err := e.incremental(ctx, tid, id, nc, lease, &rep)
	if errors.Is(err, ErrRefused) {
		if perr := e.pauseIfSuspended(ctx, tid, id, nc, &rep); perr != nil {
			err = errors.Join(err, perr)
		}
	}
	e.logIncremental(rep, err)
	return rep, err
}

func (e *Engine) incrementalReady() error {
	if err := e.ready(); err != nil {
		return err
	}
	if e.Feed == nil || e.Applier == nil || e.FeedCursors == nil || e.Passes == nil {
		return fmt.Errorf("%w: feed, applier, feed cursors or pass marker", ErrNotConfigured)
	}
	return nil
}

func (e *Engine) incremental(ctx context.Context, tid tenant.ID, id connection.ID, nc inventory.GUID, lease LeaseFunc, rep *IncrementalReport) error {
	if err := e.incrementalReady(); err != nil {
		return err
	}
	if lease == nil || tid.IsZero() {
		return fmt.Errorf("%w: lease or tenant", ErrNotConfigured)
	}
	conn, err := e.Conns.Get(ctx, tid, id)
	if err != nil {
		return fmt.Errorf("%w: connection: %w", ErrSource, err)
	}
	ref, err := e.refuse(conn, id)
	if err != nil {
		return err
	}
	managed, err := e.Domains.ManagedDomains(ctx, tid, id)
	if err != nil {
		return fmt.Errorf("%w: managed domains: %w", ErrSource, err)
	}
	domains, err := checkDomains(managed)
	if err != nil {
		return err
	}
	var dom *Domain
	for i := range domains {
		if domains[i].NC == nc {
			dom = &domains[i]
		}
	}
	if dom == nil {
		return ErrNotDomainNC
	}
	part, err := NCPartition(string(nc))
	if err != nil {
		return ErrNotDomainNC
	}
	key := Key{Connection: inventory.ConnectionID(id), Partition: part}
	name, err := LeaseName(key)
	if err != nil {
		return err
	}
	l, err := lease(ctx, name)
	if err != nil {
		return fmt.Errorf("%w: lease: %w", ErrSource, err)
	}
	cy := &incCycle{e: e, tid: tid, conn: id, ref: ref, nc: nc, key: key, lease: l, leaseFn: lease, rep: rep, observed: e.utc()}
	return cy.run(ctx)
}

// incCycle is one IncrementalCycle.
type incCycle struct {
	e       *Engine
	tid     tenant.ID
	conn    connection.ID
	ref     *connectorv1.ConnectionRef
	nc      inventory.GUID
	key     Key
	lease   jobs.Lease
	leaseFn LeaseFunc
	rep     *IncrementalReport

	// observed is the cycle's as-of: the pass watermark and the row as-of of every batch.
	observed time.Time
	mapper   *ChangeMapper
}

// errStopForResync ends a feed read whose batch was committed with RequireResync: the feed is not resumed
// again from the position it left.
var errStopForResync = errors.New("sync: the feed stopped for a resync")

func (c *incCycle) run(ctx context.Context) error {
	m, err := NewChangeMapper(Config{NC: c.nc})
	if err != nil {
		return err
	}
	c.mapper = m

	// Decide the path from the stored position, in the transaction that claims (fences) the cursor.
	var cookie *connectorv1.FeedCookie
	var cur Cursor
	var raw Cookie
	err = c.e.Tenants.WithTenant(ctx, c.tid, func(ctx context.Context, tx store.Tx) error {
		var err error
		if cur, err = c.e.FeedCursors.Claim(ctx, tx, c.key, c.lease); err != nil {
			return err
		}
		if cur.State == StatePaused {
			// The connection is active again (the gate passed): resumption always resyncs.
			if _, err = c.e.FeedCursors.ResumeConnection(ctx, tx, c.key.Connection); err != nil {
				return err
			}
			if err = c.e.Passes.MarkNC(ctx, tx, c.key.Connection, c.nc, inventory.PassResyncRequired); err != nil {
				return err
			}
			c.noteResync(ResyncResumed)
			cur.State = StateResyncRequired
			return nil
		}
		if cur, raw, err = c.e.FeedCursors.Position(ctx, tx, c.key, c.lease); err != nil {
			return err
		}
		if cur.State == StateIncremental && raw.IsZero() {
			// A scan left no position: nothing says what changed since, deletions included.
			if _, err = c.e.FeedCursors.RequireResync(ctx, tx, c.key, c.lease); err != nil {
				return err
			}
			if err = c.e.Passes.MarkNC(ctx, tx, c.key.Connection, c.nc, inventory.PassResyncRequired); err != nil {
				return err
			}
			c.noteResync(ResyncNoCookie)
			cur.State = StateResyncRequired
		}
		return nil
	})
	if err != nil {
		return err
	}
	switch cur.State {
	case StateResyncRequired:
		if len(c.rep.Resyncs) == 0 {
			c.noteResync(ResyncRequested)
		}
	case StateInitialSync:
	case StateIncremental:
		cookie = &connectorv1.FeedCookie{}
		if err := proto.Unmarshal(raw.Bytes(), cookie); err != nil || len(cookie.GetProviderState()) == 0 {
			if err := c.demand(ctx, ResyncBadCookie); err != nil {
				return err
			}
			cookie = nil
		}
	default:
		return fmt.Errorf("%w: cursor state", ErrIllegalTransition)
	}

	for {
		if cookie == nil {
			if cookie, err = c.establish(ctx); err != nil {
				return err
			}
		}
		err := c.resume(ctx, cookie)
		switch {
		case err == nil:
			c.rep.Completed = true
			return nil
		case errors.Is(err, errStopForResync):
			cookie = nil // RequireResync was committed with the batch that named the unread objects
		case client.ResyncRequired(err):
			var se *client.StaleCookieError
			if errors.As(err, &se) {
				c.rep.StaleReason = se.Reason
			}
			if err := c.demand(ctx, ResyncStale); err != nil {
				return err
			}
			cookie = nil
		case errors.Is(err, client.ErrFeedRequest):
			// The stored cookie is not one the reader will send: it is unusable, not a transport failure.
			if err := c.demand(ctx, ResyncBadCookie); err != nil {
				return err
			}
			cookie = nil
		default:
			return c.classify(err)
		}
	}
}

func (c *incCycle) noteResync(r ResyncReason) { c.rep.Resyncs = append(c.rep.Resyncs, r) }

// demand records that the cookie is unusable: the cursor goes to resync_required, dropping the cookie, and
// the naming context's pass is marked, in one transaction.
func (c *incCycle) demand(ctx context.Context, r ResyncReason) error {
	err := c.e.Tenants.WithTenant(ctx, c.tid, func(ctx context.Context, tx store.Tx) error {
		return c.requireResync(ctx, tx)
	})
	if err != nil {
		return err
	}
	c.noteResync(r)
	return nil
}

func (c *incCycle) requireResync(ctx context.Context, tx store.Tx) error {
	if _, err := c.e.FeedCursors.RequireResync(ctx, tx, c.key, c.lease); err != nil {
		return err
	}
	return c.e.Passes.MarkNC(ctx, tx, c.key.Connection, c.nc, inventory.PassResyncRequired)
}

// classify turns a feed failure into the cycle's typed error. An unreachable or throttled DC and a cut-off
// stream are retryable and leave everything as it was.
func (c *incCycle) classify(err error) error {
	var th *client.ThrottledError
	var un *client.UnreachableDCError
	switch {
	case errors.As(err, &th):
		return &RetryableError{After: th.RetryAfter, Err: err}
	case errors.As(err, &un), errors.Is(err, client.ErrFeedIncomplete):
		return &RetryableError{Err: err}
	case errors.Is(err, client.ErrFeedHandler):
		return err // the handler's own error (fenced, paused, refused, store, cancelled) is in the chain
	}
	return &FeedError{Err: err}
}

// FeedError is a feed failure with no further class: only its sentinel is kept, never a message.
type FeedError struct{ Err error }

func (e *FeedError) Error() string { return ErrConnector.Error() }

// Is makes errors.Is(err, ErrConnector) true.
func (e *FeedError) Is(target error) bool { return target == ErrConnector }

// Unwrap returns the sentinel-bearing cause.
func (e *FeedError) Unwrap() error { return e.Err }

// establish runs the contract order for a partition with no position: prime the feed (no object data, a
// cookie), read the whole domain with the cursor left as it is, reconcile after a resync, and in one transaction
// record the pass and move the cursor to incremental with the prime's cookie. It returns that cookie, so the
// feed replays what changed during the read.
func (c *incCycle) establish(ctx context.Context) (*connectorv1.FeedCookie, error) {
	var primed *connectorv1.FeedCookie
	_, err := c.e.Feed.Read(ctx, c.tid, client.FeedRequest{Connection: c.conn, NC: string(c.nc), Attributes: feedAttrs()},
		func(ctx context.Context, b *connectorv1.ChangeBatch) error {
			if len(b.GetChanges()) != 0 {
				return ErrProtocol // a prime returns no object data
			}
			primed = b.GetCookieAfter()
			return nil
		})
	if err != nil {
		return nil, c.classify(err)
	}
	if primed == nil {
		return nil, ErrProtocol
	}
	issuer, err := issuerOf(primed)
	if err != nil {
		return nil, err
	}

	conn, err := c.e.Conns.Get(ctx, c.tid, c.conn)
	if err != nil {
		return nil, fmt.Errorf("%w: connection: %w", ErrSource, err)
	}
	if _, err := c.e.refuse(conn, c.conn); err != nil {
		return nil, err
	}
	dom := &DomainReport{NC: c.nc}
	c.rep.Full = dom
	cc, pageSize, err := c.e.connect(ctx, c.conn, c.ref, []Domain{{NC: c.nc, Kind: NCDomain}})
	if err != nil {
		return nil, err
	}
	r := &readJob{e: c.e, tid: c.tid, conn: c.conn, ref: c.ref, cc: cc, key: c.key, lease: c.lease, nc: c.nc, pageSize: pageSize, rep: dom, deferFinish: true}
	if err := r.run(ctx); err != nil {
		return nil, err
	}
	if c.reconcileNeeded() {
		rr, err := c.e.Reconcile(ctx, c.tid, c.conn, c.leaseFn, ReconcileOptions{})
		if err != nil {
			return nil, err
		}
		c.rep.Reconciled, c.rep.Reconcile = true, rr.Reconciled
		// The reconcile claimed every partition under a lease of its own (this one's too), which moves the stored
		// fencing token: take this holder's lease again, so the finish below is judged against the current one.
		name, err := LeaseName(c.key)
		if err != nil {
			return nil, err
		}
		if c.lease, err = c.leaseFn(ctx, name); err != nil {
			return nil, fmt.Errorf("%w: lease: %w", ErrSource, err)
		}
		r.lease = c.lease
	}

	body, err := proto.Marshal(primed)
	if err != nil {
		return nil, ErrProtocol
	}
	stored, err := NewCookie(body)
	if err != nil {
		return nil, err
	}
	err = c.e.Tenants.WithTenant(ctx, c.tid, func(ctx context.Context, tx store.Tx) error {
		cur, err := c.e.FeedCursors.Claim(ctx, tx, c.key, c.lease)
		if err != nil {
			return err
		}
		if cur.State == StatePaused {
			return ErrPaused
		}
		if _, err := c.e.Ingester.Ingest(ctx, tx, inventory.Cycle{Connection: c.key.Connection, Observed: r.observed, Now: c.e.utc(),
			PassNCs: []inventory.GUID{c.nc}}); err != nil {
			return err
		}
		_, err = c.e.FeedCursors.CompleteFull(ctx, tx, c.key, c.lease, FullSync{At: r.observed, Cookie: stored, IssuingDSA: issuer})
		return err
	})
	if err != nil {
		return nil, r.wrap(err, "store")
	}
	dom.Completed = true
	c.rep.Primed = true
	return primed, nil
}

// reconcileNeeded: a first sync has nothing to infer deletions against; every resync does.
func (c *incCycle) reconcileNeeded() bool {
	return len(c.rep.Resyncs) > 0
}

// issuerOf is the text of the DC GUID that issued a cookie, "" when it names none.
func issuerOf(ck *connectorv1.FeedCookie) (string, error) {
	v := ck.GetIssuer().GetDsaGuid().GetValue()
	switch len(v) {
	case 0:
		return "", nil
	case 16:
		return textOf(v), nil
	}
	return "", ErrProtocol
}

// resume reads the feed from a cookie and applies each batch with its cookie in one transaction. A cycle that
// ends without its cycle_complete batch is *client* ErrFeedIncomplete, and the cursor stays at the last committed
// batch.
func (c *incCycle) resume(ctx context.Context, from *connectorv1.FeedCookie) error {
	c.observed = c.e.utc() // the pass as-of is the start of this read, and never behind the full read's
	_, err := c.e.Feed.Read(ctx, c.tid, client.FeedRequest{Connection: c.conn, NC: string(c.nc), Resume: from, Attributes: feedAttrs()},
		c.batch)
	if errors.Is(err, errStopForResync) {
		return errStopForResync
	}
	return err
}

// batch applies one ChangeBatch and stores its cookie in the same transaction.
func (c *incCycle) batch(ctx context.Context, b *connectorv1.ChangeBatch) error {
	// A suspended, retired or decommissioning connection stops the read before every batch.
	conn, err := c.e.Conns.Get(ctx, c.tid, c.conn)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("%w: connection: %w", ErrSource, err)
	}
	if _, err := c.e.refuse(conn, c.conn); err != nil {
		return err
	}
	issuer, err := issuerOf(b.GetCookieAfter())
	if err != nil {
		return err
	}
	body, err := proto.Marshal(b.GetCookieAfter())
	if err != nil {
		return ErrProtocol
	}
	stored, err := NewCookie(body)
	if err != nil {
		return err
	}
	complete := b.GetCycleComplete()
	o := ApplyOptions{Connection: c.key.Connection, Observed: c.observed, Now: c.e.utc(), ObservedDSA: issuer, MoreBatches: !complete}
	if complete {
		o.PassNCs = []inventory.GUID{c.nc}
	}
	var ar ApplyReport
	stop := false
	err = c.e.Tenants.WithTenant(ctx, c.tid, func(ctx context.Context, tx store.Tx) error {
		cur, err := c.e.FeedCursors.Claim(ctx, tx, c.key, c.lease)
		if err != nil {
			return err
		}
		if cur.State == StatePaused {
			return ErrPaused
		}
		if ar, err = c.e.Applier.Apply(ctx, tx, b, o); err != nil {
			return err
		}
		if len(ar.NeedsRead) > 0 {
			// The batch could not be applied in full (a refused change, a membership removal that named no GUID):
			// inventory has failed closed (the group's edges are ended). Rather than lose what the change carried
			// with the cookie, the position is dropped in this transaction and the domain is read again.
			stop = true
			return c.requireResync(ctx, tx)
		}
		mv := Move{Cookie: stored, IssuingDSA: issuer}
		if len(b.GetChanges()) > 0 {
			mv.LastChange = c.e.utc()
		}
		_, err = c.e.FeedCursors.Advance(ctx, tx, c.key, c.lease, mv)
		return err
	})
	if err != nil {
		return err
	}
	c.rep.Batches++
	c.rep.Changes += ar.Changes
	c.rep.Created += ar.Created
	c.rep.Updated += ar.Updated
	c.rep.Stale += ar.Stale
	c.rep.Refused += ar.Refused
	c.rep.EdgesRemoved += ar.EdgesRemoved
	if stop {
		c.noteResync(ResyncNeedsRead)
		return errStopForResync
	}
	return nil
}

// pauseIfSuspended is the suspension marking (DM-10 I10, DM-19): when a connection is found suspended, every
// cursor of it is paused and the naming context's pass is marked paused, in one transaction. Nothing is read.
func (e *Engine) pauseIfSuspended(ctx context.Context, tid tenant.ID, id connection.ID, nc inventory.GUID, rep *IncrementalReport) error {
	conn, err := e.Conns.Get(ctx, tid, id)
	if err != nil || conn.State != connection.StateSuspended || conn.RetiredAt != nil {
		return nil
	}
	err = e.Tenants.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) error {
		if _, err := e.FeedCursors.PauseConnection(ctx, tx, inventory.ConnectionID(id)); err != nil {
			return err
		}
		return e.Passes.MarkNC(ctx, tx, inventory.ConnectionID(id), nc, inventory.PassPaused)
	})
	if err != nil {
		return err
	}
	rep.Paused = true
	return nil
}

func (e *Engine) logIncremental(r IncrementalReport, err error) {
	lvl := slog.LevelInfo
	if err != nil {
		lvl = slog.LevelWarn
	}
	resyncs := make([]string, len(r.Resyncs))
	for i, x := range r.Resyncs {
		resyncs[i] = string(x)
	}
	attrs := []any{"nc", string(r.NC), "completed", r.Completed, "primed", r.Primed, "paused", r.Paused, "resyncs", resyncs,
		"stale_reason", r.StaleReason.String(), "reconciled", r.Reconciled, "batches", r.Batches, "changes", r.Changes,
		"created", r.Created, "updated", r.Updated, "stale", r.Stale, "refused", r.Refused}
	if err != nil {
		phase, class := errClass(err)
		switch {
		case errors.Is(err, ErrRetryable):
			class = "retryable"
		case errors.Is(err, ErrConnector) && class == "other":
			class = "connector"
		}
		attrs = append(attrs, "error_phase", phase, "error_class", class)
	}
	e.log().Log(context.Background(), lvl, "sync: incremental cycle", attrs...)
}
