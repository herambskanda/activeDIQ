package rights

import (
	"context"
	"errors"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/skenzeriq/activediq/internal/connector/tier0"
	adguid "github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	v1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// InvalidArgumentError is a malformed request (ERROR_CODE_INVALID_ARGUMENT), found before any
// directory call: no run starts and the connector's gate keeps its previous run.
type InvalidArgumentError struct{ Reason string }

func (e *InvalidArgumentError) Error() string { return "invalid argument: " + e.Reason }

// ADInputFromRequest decodes and validates the request. identity is the connector's own account.
func ADInputFromRequest(req *v1.VerifyConnectionRequest, identity dn.ObjectRef) (ADInput, error) {
	in := ADInput{Identity: identity, EnabledFamilies: req.GetEnabledFamilies()}
	conv := func(what string, gs []*v1.Guid) ([]adguid.GUID, error) {
		var out []adguid.GUID
		for _, g := range gs {
			v, err := ParseGUID(g)
			if err != nil {
				return nil, &InvalidArgumentError{what + ": not a GUID"}
			}
			out = append(out, v)
		}
		return out, nil
	}
	// A verification_id that is not a GUID would write "" into the baseline and the shrink record.
	if _, err := ParseGUID(req.GetVerificationId()); err != nil {
		return in, &InvalidArgumentError{"verification_id: not a GUID"}
	}
	var err error
	if in.ManagedDomains, err = conv("managed_domains", req.GetManagedDomains()); err != nil {
		return in, err
	}
	if in.ManagedRoots, err = conv("managed_roots", req.GetManagedRoots()); err != nil {
		return in, err
	}
	if in.Designated, err = conv("designated_tier0", req.GetDesignatedTier0()); err != nil {
		return in, err
	}
	for _, m := range req.GetCorrelatedTier0() {
		g, gerr := ParseGUID(m.GetObject())
		if gerr != nil {
			return in, &InvalidArgumentError{"correlated_tier0: object unset or not a GUID"}
		}
		if len(m.GetBasis()) != 1 || m.GetBasis()[0] != tier0.C16 {
			return in, &InvalidArgumentError{"correlated_tier0: basis must be exactly C16 on an AD connection"}
		}
		in.Correlated = append(in.Correlated, g)
	}
	return in, nil
}

var errNoDirectoryIdentity = errors.New("rights: connector has no bound directory identity")

const (
	findingsPerChunk = 200
	membersPerChunk  = 1000
)

// StreamAD is the body of the AD VerifyConnection server stream: header, findings, tier0_set, then
// completed (contract §8.4). It is read-only. send is the transport's Send.
//
// directory is the directory the connector is bound to (the forest root NC); it is returned in
// `completed.directory_identity` (V5, contract v1.3). A nil directory is a wiring defect: the run
// is refused before any directory call rather than streamed without the identity the server needs.
//
// A directory failure that prevents naming the identity returns an error before `completed` (the
// caller records FAILED). ErrLocalRecordFailed means the shrink record or the baseline could not be
// made durable: the stream carries no `completed`, no epoch starts and the caller closes the gate.
func StreamAD(ctx context.Context, d ADDirectory, epoch *EpochState, req *v1.VerifyConnectionRequest, identity dn.ObjectRef, directory *v1.DirectoryIdentity,
	send func(*v1.VerifyConnectionResponse) error, now func() time.Time) error {
	if now == nil {
		now = time.Now
	}
	if directory.GetAdForest().GetForestRootNcGuid() == nil {
		return errNoDirectoryIdentity
	}
	in, err := ADInputFromRequest(req, identity)
	if err != nil {
		return err
	}
	root, err := ParseGUID(directory.GetAdForest().GetForestRootNcGuid())
	if err != nil {
		return errNoDirectoryIdentity
	}
	in.RootNC = &root
	started := now()
	res, err := VerifyAD(ctx, d, in)
	if err != nil {
		return err
	}
	vid := req.GetVerificationId()
	if err := send(&v1.VerifyConnectionResponse{Event: &v1.VerifyConnectionResponse_Header{Header: &v1.VerificationHeader{
		VerificationId: vid, CheckListVersion: CheckListVersionAD, StartedAt: timestamppb.New(started),
		Identity: &v1.ObservedIdentity{Identity: &v1.ObservedIdentity_Ad{Ad: res.Identity}}}}}); err != nil {
		return err
	}
	for i := 0; i < len(res.Findings); i += findingsPerChunk {
		end := min(i+findingsPerChunk, len(res.Findings))
		ch := &v1.FindingsChunk{}
		for _, f := range res.Findings[i:end] {
			ch.Findings = append(ch.Findings, f.RightsFinding)
		}
		if err := send(&v1.VerifyConnectionResponse{Event: &v1.VerifyConnectionResponse_Findings{Findings: ch}}); err != nil {
			return err
		}
	}
	for i := 0; i < len(res.Tier0Set); i += membersPerChunk {
		end := min(i+membersPerChunk, len(res.Tier0Set))
		if err := send(&v1.VerifyConnectionResponse{Event: &v1.VerifyConnectionResponse_Tier0Set{
			Tier0Set: &v1.Tier0SetChunk{Members: res.Tier0Set[i:end]}}}); err != nil {
			return err
		}
	}
	dropped := uint32(0)
	if epoch != nil {
		var inputs []ReportedEntry
		for _, g := range in.Designated {
			inputs = append(inputs, ReportedEntry{GUID: g.String(), Basis: tier0.Designated})
		}
		for _, g := range in.Correlated {
			inputs = append(inputs, ReportedEntry{GUID: g.String(), Basis: tier0.C16})
		}
		n, err := epoch.Complete(ctx, guidText(vid), inputs)
		if err != nil {
			return err
		}
		dropped = uint32(n)
	}
	// V5 (identity) is answered by reaching this point: VerifyAD refuses the run when the connector's
	// own account cannot be read, so a completed stream means the identity was read. The server needs
	// the outcome to accept a pass (a pass that does not answer V5 is an incomplete answer).
	checks := append([]*v1.CheckResult{{Check: v1.VerificationCheck_VERIFICATION_CHECK_V5_IDENTITY,
		Outcome: v1.CheckOutcome_CHECK_OUTCOME_PASS}}, res.Checks...)
	return send(&v1.VerifyConnectionResponse{Event: &v1.VerifyConnectionResponse_Completed{Completed: &v1.VerificationCompleted{
		Verdict: res.Verdict, Checks: checks, CompletedAt: timestamppb.New(now()),
		FindingCount: uint32(len(res.Findings)), Tier0MemberCount: uint32(len(res.Tier0Set)),
		WriteGateOpenable: res.WriteGateOpenable, Tier0InputsDropped: dropped,
		DirectoryIdentity: proto.Clone(directory).(*v1.DirectoryIdentity)}}})
}

func guidText(g *v1.Guid) string {
	if v, err := ParseGUID(g); err == nil {
		return v.String()
	}
	return ""
}

// IsInvalidArgument reports whether err is a malformed request.
func IsInvalidArgument(err error) bool {
	var e *InvalidArgumentError
	return errors.As(err, &e)
}
