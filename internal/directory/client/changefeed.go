package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// Errors of the change feed reader. None carries a directory value or a connector message.
var (
	ErrNoFeedSource   = errors.New("client: no connector source wired for the change feed")
	ErrNoManagedSet   = errors.New("client: no managed-partition source wired for the change feed")
	ErrFeedConnection = errors.New("client: connection is not an active AD connection with a verified directory")
	// ErrFeedPartition: the partition is not a naming context in the connection's managed set (DM-14.I1),
	// or the managed set could not be read. The feed is not asked.
	ErrFeedPartition = errors.New("client: partition is not in the managed set of the connection")
	ErrFeedRequest   = errors.New("client: change feed request is invalid")
	// ErrFeedProtocol: the stream broke the contract (a sequence gap, a batch after the last one, a
	// batch without a cookie, an empty event). The batches before it were yielded; none is trusted after.
	ErrFeedProtocol = errors.New("client: change feed stream violates the contract")
	// ErrFeedIncomplete: the stream ended without a batch that has cycle_complete (contract rule 11,
	// CC-FEED-14). The caller keeps its last committed cookie.
	ErrFeedIncomplete = errors.New("client: change feed ended without a completed cycle")
	// ErrFeedHandler wraps what the caller's batch callback returned; the feed was stopped there.
	ErrFeedHandler = errors.New("client: change feed batch handler failed")

	// Sentinels for errors.Is on the mapped connector errors; the typed errors below carry the detail.
	ErrStaleCookie     = errors.New("client: change feed cookie is stale")
	ErrUnreachableDC   = errors.New("client: change feed DC is unreachable")
	ErrThrottled       = errors.New("client: change feed is throttled")
	ErrSecretAttribute = errors.New("client: change feed asked for a secret attribute")
)

// MaxFeedRetryAfter caps the back-off a connector may ask for, so a broken or hostile answer cannot
// park a partition's sync for longer.
const MaxFeedRetryAfter = time.Hour

// maxFeedAttributes bounds the attribute names one feed request carries.
const maxFeedAttributes = 256

// StaleCookieError is STALE_COOKIE: the cookie cannot be resumed, and the caller sets resync_required
// (DM-19.I3), re-primes, searches and diffs. Reason says why; it holds no DC name or GUID.
type StaleCookieError struct{ Reason connectorv1.ResyncReason }

func (e *StaleCookieError) Error() string {
	return ErrStaleCookie.Error() + ": " + e.Reason.String()
}

// Is makes errors.Is(err, ErrStaleCookie) true.
func (e *StaleCookieError) Is(target error) bool { return target == ErrStaleCookie }

// UnreachableDCError is UNREACHABLE_DC: the DC that issued the cookie (or that a prime pinned) could
// not be reached. It is not a stale cookie (DM-19.I4): retry the same DC. The attempts the connector
// lists name DCs, so they are dropped here.
type UnreachableDCError struct{ Retry connectorv1.RetryAdvice }

func (e *UnreachableDCError) Error() string { return ErrUnreachableDC.Error() }

// Is makes errors.Is(err, ErrUnreachableDC) true.
func (e *UnreachableDCError) Is(target error) bool { return target == ErrUnreachableDC }

// ThrottledError is THROTTLED. RetryAfter is the connector's advice, zero when the source gave none,
// never above MaxFeedRetryAfter.
type ThrottledError struct{ RetryAfter time.Duration }

func (e *ThrottledError) Error() string { return ErrThrottled.Error() }

// Is makes errors.Is(err, ErrThrottled) true.
func (e *ThrottledError) Is(target error) bool { return target == ErrThrottled }

// SecretAttributeError is SECRET_ATTRIBUTE: a requested attribute is a secret one. The connector
// refused before any DirSync call; the attribute name is not echoed.
type SecretAttributeError struct{}

func (e *SecretAttributeError) Error() string { return ErrSecretAttribute.Error() }

// Is makes errors.Is(err, ErrSecretAttribute) true.
func (e *SecretAttributeError) Is(target error) bool { return target == ErrSecretAttribute }

// ResyncRequired reports whether err means the caller's cookie is unusable and the partition must
// resync: only a stale cookie does. An unreachable or throttled DC, a cut-off stream or any other
// error leaves the cookie valid.
func ResyncRequired(err error) bool {
	var s *StaleCookieError
	return errors.As(err, &s)
}

// mapFeedError maps the error of the ChangeFeed call or stream. A connector error whose code has no
// typed mapping stays a *RemoteError (its text is the code only); a transport error passes through.
func mapFeedError(err error) error {
	err = FromStatus(err)
	var re *RemoteError
	if !errors.As(err, &re) || re.Err == nil {
		return err
	}
	ce := re.Err
	switch ce.GetCode() {
	case connectorv1.ErrorCode_ERROR_CODE_STALE_COOKIE:
		return &StaleCookieError{Reason: ce.GetStaleCookie().GetReason()}
	case connectorv1.ErrorCode_ERROR_CODE_UNREACHABLE_DC:
		return &UnreachableDCError{Retry: ce.GetRetry()}
	case connectorv1.ErrorCode_ERROR_CODE_THROTTLED:
		d := ce.GetThrottled().GetRetryAfter().AsDuration()
		return &ThrottledError{RetryAfter: min(max(d, 0), MaxFeedRetryAfter)}
	case connectorv1.ErrorCode_ERROR_CODE_SECRET_ATTRIBUTE:
		return &SecretAttributeError{}
	}
	return re
}

// ManagedPartitions answers DM-14: whether a naming context is in the managed set of a connection.
// An error means it could not be read, and the feed is refused.
type ManagedPartitions interface {
	Managed(ctx context.Context, tid tenant.ID, id connection.ID, ncGUID string) (bool, error)
}

// FeedRequest asks for one feed call over one AD naming context.
type FeedRequest struct {
	Connection connection.ID
	// NC is the canonical text of the objectGUID of a domain NC head in the managed set.
	NC string
	// Resume continues from this cookie; nil primes (establishes a cookie, no object data). The
	// sequence for a new partition is prime, ScopedSearch, resume (contract §6.1).
	Resume *connectorv1.FeedCookie
	// Attributes are explicit names; the connector adds the mandatory set. Never "*" or "+".
	Attributes []string
}

// FeedResult is what a successful (completed) call returns.
type FeedResult struct {
	// Batches is how many batches were yielded; Changes how many object changes they carried.
	Batches, Changes int
	// Cookie is the cookie_after of the last batch: where the caller stands now.
	Cookie *connectorv1.FeedCookie
}

// ChangeFeedReader is the server's side of the connector's ChangeFeed RPC.
type ChangeFeedReader struct {
	conns   ConnectionSource
	src     ConnectorSource
	managed ManagedPartitions
}

// NewChangeFeedReader returns the reader. All arguments are required.
func NewChangeFeedReader(conns ConnectionSource, src ConnectorSource, managed ManagedPartitions) (*ChangeFeedReader, error) {
	switch {
	case conns == nil:
		return nil, errors.New("client: change feed reader needs a connection source")
	case src == nil:
		return nil, ErrNoFeedSource
	case managed == nil:
		return nil, ErrNoManagedSet
	}
	return &ChangeFeedReader{conns: conns, src: src, managed: managed}, nil
}

// Read starts a prime or a resume and calls fn with every batch in order. fn is the place to commit
// the batch's rows together with batch.cookie_after (DM-19.I1); a batch is yielded before the stream
// is known to complete, because each cookie_after is a valid resume point on its own.
//
// Read returns nil only when the stream ended with a batch that has cycle_complete (contract rule 11,
// CC-FEED-14). A stream that ends without one is ErrFeedIncomplete; an error from the connector is
// mapped (StaleCookieError, UnreachableDCError, ThrottledError, SecretAttributeError, else
// *RemoteError); a contract violation is ErrFeedProtocol; an error from fn stops the stream and is
// returned wrapped in ErrFeedHandler. Whatever the failure, the caller stays on the cookie of the
// last batch it committed. The connection and partition are checked before any connector call.
func (r *ChangeFeedReader) Read(ctx context.Context, tid tenant.ID, req FeedRequest, fn func(context.Context, *connectorv1.ChangeBatch) error) (FeedResult, error) {
	if fn == nil {
		return FeedResult{}, fmt.Errorf("%w: no batch handler", ErrFeedRequest)
	}
	conn, err := r.conns.Get(ctx, tid, req.Connection)
	if err != nil || conn.ID != req.Connection || conn.RetiredAt != nil || conn.Kind != connection.KindADForest || conn.State != connection.StateActive {
		return FeedResult{}, ErrFeedConnection
	}
	ident := directoryOf(conn)
	if ident == nil {
		return FeedResult{}, ErrFeedConnection
	}
	nc, err := parseUUID(req.NC)
	if err != nil {
		return FeedResult{}, ErrFeedPartition
	}
	if ok, err := r.managed.Managed(ctx, tid, req.Connection, strings.ToLower(req.NC)); err != nil || !ok {
		return FeedResult{}, ErrFeedPartition
	}
	if err := checkFeedRequest(req); err != nil {
		return FeedResult{}, err
	}
	creq := &connectorv1.ChangeFeedRequest{
		Connection: &connectorv1.ConnectionRef{ConnectionId: string(req.Connection), DirectoryIdentity: ident},
		Partition:  &connectorv1.FeedPartition{Partition: &connectorv1.FeedPartition_AdNcGuid{AdNcGuid: &connectorv1.Guid{Value: nc}}},
		Attributes: req.Attributes,
	}
	if req.Resume != nil {
		creq.Start = &connectorv1.ChangeFeedRequest_Resume{Resume: &connectorv1.FeedResume{Cookie: req.Resume}}
	} else {
		creq.Start = &connectorv1.ChangeFeedRequest_Prime{Prime: &connectorv1.FeedPrime{}}
	}
	cc, err := r.src.Connector(ctx, string(req.Connection))
	if err != nil {
		return FeedResult{}, err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel() // stops the stream on any early return
	st, err := cc.ChangeFeed(ctx, creq)
	if err != nil {
		return FeedResult{}, mapFeedError(err)
	}
	var res FeedResult
	var last uint64
	complete := false
	for {
		m, err := st.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return res, mapFeedError(err)
		}
		b := m.GetBatch()
		// A batch after the last one, a gap or repeat in the sequence, a missing cookie and an empty
		// event are all contract violations; none is yielded.
		if complete || b == nil || b.GetSequence() != last+1 || len(b.GetCookieAfter().GetProviderState()) == 0 {
			return res, ErrFeedProtocol
		}
		last = b.GetSequence()
		if err := fn(ctx, b); err != nil {
			return res, fmt.Errorf("%w: %w", ErrFeedHandler, err)
		}
		res.Batches++
		res.Changes += len(b.GetChanges())
		res.Cookie = b.GetCookieAfter()
		complete = b.GetCycleComplete()
	}
	if !complete {
		return res, ErrFeedIncomplete
	}
	return res, nil
}

func checkFeedRequest(req FeedRequest) error {
	if req.Resume != nil {
		c := req.Resume
		if len(c.GetProviderState()) == 0 || c.GetProviderKind() != connectorv1.ProviderKind_PROVIDER_KIND_AD {
			return fmt.Errorf("%w: resume cookie", ErrFeedRequest)
		}
	}
	if len(req.Attributes) > maxFeedAttributes {
		return fmt.Errorf("%w: too many attributes", ErrFeedRequest)
	}
	for _, a := range req.Attributes {
		if a == "" || a == "*" || a == "+" || strings.ContainsRune(a, 0) {
			return fmt.Errorf("%w: attribute name", ErrFeedRequest)
		}
	}
	return nil
}
