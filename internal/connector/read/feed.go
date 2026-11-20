package read

import (
	"context"
	"errors"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/write"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// ChangeFeed (connector-contract §6): prime and resume over DirSync in object-security mode. A
// cookie is checked against the DC it names before any search is sent, and every STALE_COOKIE is
// raised before the first batch. The stream always ends with a batch that has cycle_complete, held
// back until the DC is seen to be the one the cycle started on.

const (
	// feedFormatVersion is the layout of FeedCookie.provider_state this build writes and reads.
	feedFormatVersion = 1
	// maxCookieBytes caps an incoming provider_state before it is passed anywhere. A DirSync cookie
	// is a USN vector and an up-to-dateness vector: kilobytes, even with many DCs.
	maxCookieBytes = 64 << 10
	// defaultFeedPages and defaultFeedDeadline bound one call. Neither is reachable by a healthy DC
	// (a 200,000-object prime is a few hundred responses); a DC that keeps answering "more" with a
	// new cookie and no changes ends at the first bound instead of looping.
	defaultFeedPages    = 100_000
	defaultFeedDeadline = time.Hour
	// minCookieMargin and the 10 % rule below are the provisional safety margin of §6.3.
	minCookieMargin = 24 * time.Hour
	// maxClockAhead is how far a cookie's issued_at may lie in the future (clock correction).
	maxClockAhead = 24 * time.Hour
)

type feedLimits struct {
	maxPages int
	deadline time.Duration
}

// WithFeedLimits bounds one ChangeFeed call by DirSync responses and by wall time. Non-positive
// values keep the defaults.
func WithFeedLimits(maxPages int, deadline time.Duration) Option {
	return func(h *Handler) {
		if maxPages > 0 {
			h.feed.maxPages = maxPages
		}
		if deadline > 0 {
			h.feed.deadline = deadline
		}
	}
}

// FeedSender is the sending side of the ChangeFeed stream.
type FeedSender interface {
	Send(*connectorv1.ChangeFeedResponse) error
}

var (
	errFeedLimit = errors.New("read: feed limit")
	errNoCookie  = errors.New("read: dirsync response without a cookie")
	errBadChange = errors.New("read: undecodable change")
)

// sendError marks a failure of the stream itself, which passes through the DirSync loop untouched.
type sendError struct{ err error }

func (e sendError) Error() string { return "read: send: " + e.err.Error() }
func (e sendError) Unwrap() error { return e.err }

func invalidFeed(field string) error {
	r := write.NewRefusal(connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, connectorv1.RetryAdvice_RETRY_ADVICE_NEVER, "invalid request")
	r.Err.Details = &connectorv1.ConnectorError_RejectedInput{RejectedInput: &connectorv1.RejectedInputDetails{RuleId: "InvalidChangeFeedRequest", Field: field}}
	return r
}

// stale is a STALE_COOKIE: the cookie cannot be continued and the caller resyncs. issuer is what the
// cookie recorded, observed the DC actually reached when one was.
func stale(reason connectorv1.ResyncReason, issuer, observed *connectorv1.DcIdentity) error {
	r := write.NewRefusal(connectorv1.ErrorCode_ERROR_CODE_STALE_COOKIE, connectorv1.RetryAdvice_RETRY_ADVICE_AFTER_RESYNC, "cookie cannot be continued")
	r.Err.Dc = proto.Clone(observed).(*connectorv1.DcIdentity)
	r.Err.Details = &connectorv1.ConnectorError_StaleCookie{StaleCookie: &connectorv1.StaleCookieDetails{
		Reason: reason, Issuer: proto.Clone(issuer).(*connectorv1.DcIdentity), Observed: proto.Clone(observed).(*connectorv1.DcIdentity)}}
	return r
}

func feedLimit(limit string, value uint64) error {
	r := write.NewRefusal(connectorv1.ErrorCode_ERROR_CODE_LIMIT_EXCEEDED, connectorv1.RetryAdvice_RETRY_ADVICE_SAME_DC_AFTER_BACKOFF, "feed cycle limit reached")
	r.Err.Details = &connectorv1.ConnectorError_Limit{Limit: &connectorv1.LimitDetails{Limit: limit, Value: value}}
	return r
}

// ChangeFeed implements the ChangeFeed RPC for AD.
func (h *Handler) ChangeFeed(ctx context.Context, req *connectorv1.ChangeFeedRequest, out FeedSender) error {
	f, ok := h.src.(Feeder)
	if !ok {
		return refuse(connectorv1.ErrorCode_ERROR_CODE_CAPABILITY_UNSUPPORTED, connectorv1.RetryAdvice_RETRY_ADVICE_NEVER, "change feed not supported")
	}
	if req.GetConnection().GetConnectionId() == "" || req.GetConnection().GetDirectoryIdentity() == nil {
		return invalidFeed("connection")
	}
	if !proto.Equal(req.GetConnection().GetDirectoryIdentity(), h.src.Identity()) {
		return refuse(connectorv1.ErrorCode_ERROR_CODE_DIRECTORY_IDENTITY_MISMATCH, connectorv1.RetryAdvice_RETRY_ADVICE_NEVER, "directory identity mismatch")
	}
	ncWire := req.GetPartition().GetAdNcGuid()
	nc, err := write.GUIDFromWire(ncWire)
	if err != nil {
		return invalidFeed("partition") // unset, an Entra resource, or not a GUID
	}
	attrs, err := h.feedAttrs(f, req.GetAttributes())
	if err != nil {
		return err
	}
	var (
		prime  *connectorv1.FeedPrime
		resume *connectorv1.FeedResume
	)
	switch s := req.GetStart().(type) {
	case *connectorv1.ChangeFeedRequest_Prime:
		prime = s.Prime
	case *connectorv1.ChangeFeedRequest_Resume:
		resume = s.Resume
	case *connectorv1.ChangeFeedRequest_Full:
		// The initial state of an AD partition is a ScopedSearch of the NC head (contract §6.1).
		return refuse(connectorv1.ErrorCode_ERROR_CODE_CAPABILITY_UNSUPPORTED, connectorv1.RetryAdvice_RETRY_ADVICE_NEVER, "full start not supported")
	default:
		return invalidFeed("start")
	}
	// The cookie's shape is checked before anything touches the directory.
	var ck *cookieIn
	if resume != nil {
		if ck, err = checkCookie(resume.GetCookie()); err != nil {
			return err
		}
	}
	var pin *connectorv1.Guid
	if prime != nil {
		if sel := prime.GetDc(); sel != nil && sel.PinnedDsaGuid != nil {
			pin = sel.PinnedDsaGuid
			if _, err := write.GUIDFromWire(pin); err != nil {
				return invalidFeed("start.prime.dc.pinned_dsa_guid")
			}
		}
	}
	// The partition must be a naming context this connection manages: a DirSync base accepts any NC
	// head, Configuration and Schema included.
	managed, err := f.ManagesNC(ctx, nc)
	if err != nil {
		return h.feedFailure(ctx, err, nil, nil, resume != nil)
	}
	if !managed {
		return invalidFeed("partition")
	}
	run := &feedRun{h: h, f: f, out: out, nc: dn.GUIDRef(nc), attrs: attrs}
	if prime != nil {
		return run.prime(ctx, pin)
	}
	return run.resume(ctx, ck)
}

// feedAttrs validates the requested names: explicit, known to the schema, not held, and no secret.
// Nothing reaches the DC before this passes.
func (h *Handler) feedAttrs(f Feeder, in []string) ([]string, error) {
	if len(in) > maxAttributes {
		return nil, invalidFeed("attributes")
	}
	canon := make([]string, 0, len(in))
	for _, a := range in {
		if a == "" || strings.ContainsAny(a, "*+") {
			return nil, invalidFeed("attributes") // "*" and "+" are not names
		}
		c, err := h.src.CanonicalAttr(a)
		if err != nil {
			return nil, mapAD(err, nil)
		}
		if strings.EqualFold(c, "nTSecurityDescriptor") { // held for T-0118
			return nil, refuse(connectorv1.ErrorCode_ERROR_CODE_ATTRIBUTE_NOT_ALLOWED, connectorv1.RetryAdvice_RETRY_ADVICE_NEVER, "attribute not allowed")
		}
		canon = append(canon, c)
	}
	if err := f.CheckFeedAttributes(canon); err != nil {
		return nil, mapAD(err, nil)
	}
	return canon, nil
}

// cookieIn is a resume cookie whose shape has been checked.
type cookieIn struct {
	state    []byte
	issuer   *connectorv1.DcIdentity
	usn      uint64
	issuedAt time.Time
}

func checkCookie(c *connectorv1.FeedCookie) (*cookieIn, error) {
	if c == nil {
		return nil, invalidFeed("start.resume.cookie")
	}
	// Size first, version second, before the bytes go anywhere (the cap is not the layout's).
	if len(c.GetProviderState()) > maxCookieBytes {
		return nil, invalidFeed("start.resume.cookie.provider_state")
	}
	if c.GetFormatVersion() != feedFormatVersion {
		return nil, stale(connectorv1.ResyncReason_RESYNC_REASON_COOKIE_FORMAT_UNKNOWN, c.GetIssuer(), nil)
	}
	if c.GetProviderKind() != connectorv1.ProviderKind_PROVIDER_KIND_AD || len(c.GetProviderState()) == 0 {
		return nil, invalidFeed("start.resume.cookie")
	}
	iss := c.GetIssuer()
	if _, err := write.GUIDFromWire(iss.GetDsaGuid()); err != nil {
		return nil, invalidFeed("start.resume.cookie.issuer")
	}
	if _, err := write.GUIDFromWire(iss.GetInvocationId()); err != nil {
		return nil, invalidFeed("start.resume.cookie.issuer")
	}
	if c.HighestCommittedUsnBefore == nil {
		return nil, invalidFeed("start.resume.cookie.highest_committed_usn_before")
	}
	if c.GetIssuedAt() == nil || c.GetIssuedAt().CheckValid() != nil {
		return nil, invalidFeed("start.resume.cookie.issued_at")
	}
	return &cookieIn{state: append([]byte(nil), c.GetProviderState()...), issuer: iss,
		usn: c.GetHighestCommittedUsnBefore(), issuedAt: c.GetIssuedAt().AsTime()}, nil
}

type feedRun struct {
	h     *Handler
	f     Feeder
	out   FeedSender
	nc    dn.ObjectRef
	attrs []string

	seq uint64
	dc  *connectorv1.DcIdentity // the DC the cycle runs on, as read before the first search
	usn uint64                  // its highestCommittedUSN, read before the first search
}

func sameDC(a, b *connectorv1.DcIdentity) bool {
	return proto.Equal(a.GetDsaGuid(), b.GetDsaGuid()) && proto.Equal(a.GetInvocationId(), b.GetInvocationId())
}

// prime drains the first DirSync cycle on the bound DC and returns only the cookie.
func (r *feedRun) prime(ctx context.Context, pin *connectorv1.Guid) error {
	h := r.h
	var err error
	if r.dc, err = h.bound(ctx, pin); err != nil {
		return err
	}
	if err := r.readUSN(ctx, false); err != nil {
		return err
	}
	var dropped uint32
	last, err := r.cycle(ctx, nil, false, func(p ad.DirSyncPage) error {
		dropped += uint32(p.SecretAttributesDropped)
		return nil
	})
	if err != nil {
		return err
	}
	if err := r.sameDCAfter(ctx, false); err != nil {
		return err
	}
	return r.send(&connectorv1.ChangeBatch{CookieAfter: r.cookie(last.Cookie, h.now()), CycleComplete: true, SecretAttributesDropped: dropped})
}

// resume checks the cookie against the DC it names, then streams the changes after it.
func (r *feedRun) resume(ctx context.Context, ck *cookieIn) error {
	h := r.h
	// The cookie names its DC and nothing else may serve it. This connector is bound to one DC; if
	// that DC cannot be read the answer is UNREACHABLE_DC for the same DC, never a stale cookie.
	dc, err := h.src.BoundDC(ctx)
	if err != nil || dc == nil {
		return unreachableIssuer()
	}
	r.dc = dc
	if !proto.Equal(dc.GetDsaGuid(), ck.issuer.GetDsaGuid()) {
		return stale(connectorv1.ResyncReason_RESYNC_REASON_ISSUER_MISMATCH, ck.issuer, dc)
	}
	if !proto.Equal(dc.GetInvocationId(), ck.issuer.GetInvocationId()) {
		return stale(connectorv1.ResyncReason_RESYNC_REASON_INVOCATION_ID_CHANGED, ck.issuer, dc)
	}
	if err := r.readUSN(ctx, true); err != nil {
		return err
	}
	if r.usn < ck.usn {
		return stale(connectorv1.ResyncReason_RESYNC_REASON_USN_ROLLBACK, ck.issuer, dc)
	}
	life, err := h.feedFailureOr(ctx, r.f.DeletionLifetime)
	if err != nil {
		return err
	}
	now := h.now()
	if age := now.Sub(ck.issuedAt); age >= life-cookieMargin(life) {
		return stale(connectorv1.ResyncReason_RESYNC_REASON_COOKIE_TOO_OLD, ck.issuer, dc)
	} else if age < -maxClockAhead {
		return invalidFeed("start.resume.cookie.issued_at")
	}

	started := now
	var held *ad.DirSyncPage
	_, err = r.cycle(ctx, ck.state, true, func(p ad.DirSyncPage) error {
		if !p.More {
			held = &p // the last page goes out after the DC has been seen to be the same one
			return nil
		}
		b, err := r.batch(p, started, false)
		if err != nil {
			return err
		}
		return r.send(b)
	})
	if err != nil {
		return err
	}
	if held == nil { // DirSyncCycle hands every page, the last included, to the callback
		return refuse(connectorv1.ErrorCode_ERROR_CODE_PROVIDER_FAILURE, connectorv1.RetryAdvice_RETRY_ADVICE_NEVER, "feed ended without a final response")
	}
	if err := r.sameDCAfter(ctx, true); err != nil {
		return err
	}
	b, err := r.batch(*held, h.now(), true)
	if err != nil {
		return r.fail(ctx, err, true)
	}
	return r.send(b)
}

// cookieMargin is the safety margin below the deletion lifetime (contract §6.3, provisional: the
// larger of one day and 10 % of the lifetime).
func cookieMargin(life time.Duration) time.Duration { return max(minCookieMargin, life/10) }

func unreachableIssuer() error {
	return refuse(connectorv1.ErrorCode_ERROR_CODE_UNREACHABLE_DC, connectorv1.RetryAdvice_RETRY_ADVICE_SAME_DC_AFTER_BACKOFF, "issuing domain controller unreachable")
}

// readUSN reads highestCommittedUSN on the bound DC. It runs before the first search: the cookie
// records a USN no later than the state it covers.
func (r *feedRun) readUSN(ctx context.Context, resuming bool) error {
	n, err := r.f.HighestCommittedUSN(ctx)
	if err != nil {
		return r.h.feedFailure(ctx, err, r.dc, nil, resuming)
	}
	r.usn = uint64(n)
	return nil
}

// cycle runs the DirSync cycle from cookie under the call's page and time bounds.
func (r *feedRun) cycle(ctx context.Context, cookie []byte, resuming bool, fn func(ad.DirSyncPage) error) (ad.DirSyncPage, error) {
	cctx, cancel := context.WithTimeout(ctx, r.h.feed.deadline)
	defer cancel()
	pages := 0
	last, err := r.f.DirSyncCycle(cctx, ad.DirSyncRequest{NC: r.nc, Cookie: cookie, Attributes: r.attrs}, func(p ad.DirSyncPage) error {
		if pages++; pages > r.h.feed.maxPages {
			return errFeedLimit
		}
		if len(p.Cookie) == 0 {
			return errNoCookie // resuming from nothing would restart the enumeration
		}
		return fn(p)
	})
	if err != nil {
		if ctx.Err() == nil && cctx.Err() != nil {
			return ad.DirSyncPage{}, feedLimit("deadline_seconds", uint64(r.h.feed.deadline/time.Second))
		}
		return ad.DirSyncPage{}, r.fail(ctx, err, resuming)
	}
	return last, nil
}

func (r *feedRun) fail(ctx context.Context, err error, resuming bool) error {
	return r.h.feedFailure(ctx, err, r.dc, r.dc, resuming)
}

// sameDCAfter fails unless the DC the cycle ran on is still the same one, invocation id included.
func (r *feedRun) sameDCAfter(ctx context.Context, resuming bool) error {
	after, err := r.h.src.BoundDC(ctx)
	if err != nil || after == nil {
		if resuming {
			return unreachableIssuer()
		}
		return refuse(connectorv1.ErrorCode_ERROR_CODE_UNREACHABLE_DC, connectorv1.RetryAdvice_RETRY_ADVICE_AFTER_REPLAN, "domain controller identity unavailable")
	}
	if sameDC(r.dc, after) {
		return nil
	}
	if !resuming {
		return pinRefusal()
	}
	if !proto.Equal(r.dc.GetDsaGuid(), after.GetDsaGuid()) {
		return stale(connectorv1.ResyncReason_RESYNC_REASON_ISSUER_MISMATCH, r.dc, after)
	}
	return stale(connectorv1.ResyncReason_RESYNC_REASON_INVOCATION_ID_CHANGED, r.dc, after)
}

// feedFailure maps an error of the DirSync cycle or of a read it needs to the contract. dc is the
// DC the call runs on.
func (h *Handler) feedFailure(ctx context.Context, err error, dc, issuer *connectorv1.DcIdentity, resuming bool) error {
	var se sendError
	switch {
	case errors.As(err, &se):
		return se.err
	case errors.Is(err, errFeedLimit):
		return feedLimit("responses", uint64(h.feed.maxPages))
	case errors.Is(err, errNoCookie):
		return refuse(connectorv1.ErrorCode_ERROR_CODE_PROVIDER_FAILURE, connectorv1.RetryAdvice_RETRY_ADVICE_NEVER, "directory returned no cookie")
	case errors.Is(err, errBadChange):
		return refuse(connectorv1.ErrorCode_ERROR_CODE_PROVIDER_FAILURE, connectorv1.RetryAdvice_RETRY_ADVICE_NEVER, "attribute could not be decoded")
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if resuming && ad.CodeOf(err) == ad.CodeCookieRejected {
		return stale(connectorv1.ResyncReason_RESYNC_REASON_SERVER_REJECTED, issuer, dc)
	}
	mapped := mapAD(err, dc)
	if resuming {
		// The cookie's DC is the one to retry, not another.
		var rf *write.Refusal
		if errors.As(mapped, &rf) && rf.Err.GetCode() == connectorv1.ErrorCode_ERROR_CODE_UNREACHABLE_DC {
			rf.Err.Retry = connectorv1.RetryAdvice_RETRY_ADVICE_SAME_DC_AFTER_BACKOFF
		}
	}
	return mapped
}

// feedFailureOr runs a read the pre-checks need and maps its failure for a resume.
func (h *Handler) feedFailureOr(ctx context.Context, read func(context.Context) (time.Duration, error)) (time.Duration, error) {
	d, err := read(ctx)
	if err != nil {
		return 0, h.feedFailure(ctx, err, nil, nil, true)
	}
	return d, nil
}

func (r *feedRun) cookie(state []byte, issued time.Time) *connectorv1.FeedCookie {
	usn := r.usn
	return &connectorv1.FeedCookie{
		ProviderState:             append([]byte(nil), state...),
		ProviderKind:              connectorv1.ProviderKind_PROVIDER_KIND_AD,
		FormatVersion:             feedFormatVersion,
		Issuer:                    r.dc,
		HighestCommittedUsnBefore: &usn,
		IssuedAt:                  timestamppb.New(issued),
	}
}

// batch turns one DirSync page into a ChangeBatch. issued is the cookie's issued_at.
func (r *feedRun) batch(p ad.DirSyncPage, issued time.Time, complete bool) (*connectorv1.ChangeBatch, error) {
	b := &connectorv1.ChangeBatch{CookieAfter: r.cookie(p.Cookie, issued), CycleComplete: complete,
		SecretAttributesDropped: uint32(p.SecretAttributesDropped)}
	for _, c := range p.Changes {
		oc, err := r.h.objectChange(c)
		if err != nil {
			return nil, errBadChange
		}
		b.Changes = append(b.Changes, oc)
	}
	return b, nil
}

func (r *feedRun) send(b *connectorv1.ChangeBatch) error {
	r.seq++
	b.Sequence = r.seq
	b.Observed = &connectorv1.Observation{Dc: r.dc, ReceivedAt: timestamppb.New(r.h.now())}
	if err := r.out.Send(&connectorv1.ChangeFeedResponse{Event: &connectorv1.ChangeFeedResponse_Batch{Batch: b}}); err != nil {
		return sendError{err}
	}
	return nil
}

func (h *Handler) objectChange(c ad.ObjectChange) (*connectorv1.ObjectChange, error) {
	out := &connectorv1.ObjectChange{ObjectGuid: write.GUIDToWire(c.GUID), Dn: &connectorv1.DnValue{DisplayDn: c.DN}}
	switch c.State {
	case ad.StateLive:
		out.State = connectorv1.ObjectState_OBJECT_STATE_LIVE
	case ad.StateDeleted:
		out.State = connectorv1.ObjectState_OBJECT_STATE_DELETED
	case ad.StateRecycled:
		out.State = connectorv1.ObjectState_OBJECT_STATE_RECYCLED
	default:
		return nil, errBadChange
	}
	if c.HasParent {
		out.ParentGuid = write.GUIDToWire(c.Parent)
	}
	for _, a := range c.Attributes {
		name := strings.ToLower(a.Name)
		ac := &connectorv1.AttributeChange{Name: name}
		switch a.Op {
		case ad.OpSet:
			ac.Op = connectorv1.ChangeOp_CHANGE_OP_SET
		case ad.OpCleared:
			ac.Op = connectorv1.ChangeOp_CHANGE_OP_CLEARED
		case ad.OpValuesAdded:
			ac.Op = connectorv1.ChangeOp_CHANGE_OP_VALUES_ADDED
		case ad.OpValuesRemoved:
			ac.Op = connectorv1.ChangeOp_CHANGE_OP_VALUES_REMOVED
		default:
			return nil, errBadChange
		}
		for _, raw := range a.Values {
			v, err := h.value(name, raw)
			if err != nil {
				return nil, err
			}
			ac.Values = append(ac.Values, v)
		}
		out.Attributes = append(out.Attributes, ac)
	}
	return out, nil
}
