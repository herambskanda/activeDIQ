package sync

import (
	"context"
	"errors"
	"io"

	"google.golang.org/grpc/status"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/directory/sd"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// Outcome keys of DomainReport.PasswordChange: a fixed vocabulary, never directory text. The state
// names are sd.PasswordChange.String(); the not-confirmed causes are below, suffixed with the
// connector's error code name when it gave one.
const (
	pwOutcomeMismatch  = "not_confirmed.guid_mismatch"
	pwOutcomeNoVerdict = "not_confirmed.no_verdict"
	pwOutcomeProtocol  = "not_confirmed.protocol"
	pwOutcomeCallPre   = "not_confirmed.call."
	pwOutcomeCodePre   = "not_confirmed.code."
)

// readPasswordChange sets o.PasswordChange and o.PasswordChangeAt from the connector's DACL read
// (Read with include_password_change; the connector classifies, no descriptor byte reaches this
// package). It fails closed (T-1551, security review of T-1472):
//
//   - every outcome stamps PasswordChangeAt, so the stored state is "Not confirmed as of <time>" and
//     never the previous value and never a state read for another object;
//   - a failed, malformed, withheld or missing verdict is PasswordChangeNotConfirmed, counted by a fixed
//     code in the report; the pass goes on with the next object;
//   - a verdict naming another objectGUID is refused;
//   - only a cancelled context is returned, because the whole read is then over.
func (r *readJob) readPasswordChange(ctx context.Context, o *inventory.Observation, pin *connectorv1.Guid) error {
	at := r.e.utc()
	state, outcome := r.askPasswordChange(ctx, o, pin)
	if err := ctx.Err(); err != nil {
		return err
	}
	o.PasswordChange, o.PasswordChangeAt = state, at
	if r.rep.PasswordChange == nil {
		r.rep.PasswordChange = map[string]int{}
	}
	r.rep.PasswordChange[outcome]++
	return nil
}

func (r *readJob) askPasswordChange(ctx context.Context, o *inventory.Observation, pin *connectorv1.Guid) (sd.PasswordChange, string) {
	notConfirmed := func(outcome string) (sd.PasswordChange, string) { return sd.PasswordChangeNotConfirmed, outcome }
	obj, err := wireOf(string(o.Object))
	if err != nil {
		return notConfirmed(pwOutcomeProtocol)
	}
	nc, err := wireOf(string(r.nc))
	if err != nil {
		return notConfirmed(pwOutcomeProtocol)
	}
	req := &connectorv1.ReadRequest{
		Connection: r.ref, Guid: obj, NcGuid: nc,
		Attributes:            []string{"objectClass"}, // the contract wants one; the verdict is what is read
		IncludePasswordChange: true,
	}
	if pin != nil {
		req.Dc = &connectorv1.DcSelection{PinnedDsaGuid: pin}
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	st, err := r.cc.Read(ctx, req)
	if err != nil {
		return notConfirmed(pwOutcomeCallPre + status.Code(err).String())
	}
	var verdict *connectorv1.PasswordChangeVerdict
	seen := false
	for {
		m, err := st.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return notConfirmed(pwOutcomeCallPre + status.Code(err).String())
		}
		if h := m.GetHeader(); h != nil {
			if seen {
				return notConfirmed(pwOutcomeProtocol)
			}
			seen, verdict = true, h.GetPasswordChange()
		}
	}
	if verdict == nil {
		return notConfirmed(pwOutcomeNoVerdict)
	}
	// A verdict names the object it was read from. A GUID that is not the observed object's is refused
	// whatever the state, and a definite state with no GUID cannot be tied to the object.
	g := verdict.GetObjectGuid().GetValue()
	definite := verdict.GetState() != connectorv1.PasswordChangeState_PASSWORD_CHANGE_STATE_NOT_CONFIRMED &&
		verdict.GetState() != connectorv1.PasswordChangeState_PASSWORD_CHANGE_STATE_UNSPECIFIED
	if (len(g) == 16 && textOf(g) != string(o.Object)) || (definite && len(g) != 16) {
		return notConfirmed(pwOutcomeMismatch)
	}
	switch verdict.GetState() {
	case connectorv1.PasswordChangeState_PASSWORD_CHANGE_STATE_BLOCKED:
		return sd.PasswordChangeBlocked, sd.PasswordChangeBlocked.String()
	case connectorv1.PasswordChangeState_PASSWORD_CHANGE_STATE_BLOCKED_ONE_ACE:
		return sd.PasswordChangeBlockedOneACE, sd.PasswordChangeBlockedOneACE.String()
	case connectorv1.PasswordChangeState_PASSWORD_CHANGE_STATE_NO_DENY_ACE:
		return sd.PasswordChangeNoDenyACE, sd.PasswordChangeNoDenyACE.String()
	}
	if c := verdict.GetErrorCode(); c != connectorv1.ErrorCode_ERROR_CODE_UNSPECIFIED {
		return notConfirmed(pwOutcomeCodePre + c.String())
	}
	return notConfirmed(sd.PasswordChangeNotConfirmed.String())
}
