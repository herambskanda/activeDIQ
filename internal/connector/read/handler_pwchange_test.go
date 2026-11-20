package read_test

import (
	"errors"
	"github.com/skenzeriq/activediq/internal/connector/read"
	"strings"
	"testing"

	"context"
	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/sd"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// pcSrc is a Source that also reads the Cannot Change Password state (read.PasswordChanger).
type pcSrc struct {
	*src
	got   guid.GUID
	state sd.PasswordChange
	err   error
	asked int
}

func (p *pcSrc) ReadPasswordChange(context.Context, guid.GUID) (guid.GUID, sd.PasswordChange, error) {
	p.asked++
	return p.got, p.state, p.err
}

func pcReq() *connectorv1.ReadRequest {
	r := req(dsaA, false)
	r.IncludePasswordChange = true
	return r
}

func newPC() *pcSrc {
	return &pcSrc{src: &src{dsa: dsaA, entry: entry(map[string][][]byte{"cn": {[]byte("x")}})}, got: g(objGUID)}
}

func verdictOf(t *testing.T, s read.Source) *connectorv1.PasswordChangeVerdict {
	t.Helper()
	ms, err := collect(t, start(t, s), pcReq())
	if err != nil || len(ms) < 2 {
		t.Fatalf("read failed even though only the descriptor was bad: %v %d", err, len(ms))
	}
	return ms[0].GetHeader().GetPasswordChange()
}

func TestPasswordChangeVerdictStates(t *testing.T) {
	for st, want := range map[sd.PasswordChange]connectorv1.PasswordChangeState{
		sd.PasswordChangeBlocked:       connectorv1.PasswordChangeState_PASSWORD_CHANGE_STATE_BLOCKED,
		sd.PasswordChangeBlockedOneACE: connectorv1.PasswordChangeState_PASSWORD_CHANGE_STATE_BLOCKED_ONE_ACE,
		sd.PasswordChangeNoDenyACE:     connectorv1.PasswordChangeState_PASSWORD_CHANGE_STATE_NO_DENY_ACE,
	} {
		p := newPC()
		p.state = st
		v := verdictOf(t, p)
		if v.GetState() != want || !proto3Eq(v.GetObjectGuid(), reqGUID()) {
			t.Errorf("%v -> %v", st, v)
		}
	}
}

func reqGUID() *connectorv1.Guid { return pcReq().GetGuid() }

func TestPasswordChangeFailureIsNotConfirmedNotAnError(t *testing.T) {
	p := newPC()
	p.err = ad.NewError(ad.CodeInsufficientRights)
	v := verdictOf(t, p)
	if v.GetState() != connectorv1.PasswordChangeState_PASSWORD_CHANGE_STATE_NOT_CONFIRMED || v.GetErrorCode() != connectorv1.ErrorCode_ERROR_CODE_INSUFFICIENT_RIGHTS {
		t.Fatalf("%v", v)
	}
	p = newPC()
	p.err = errors.New("SENTINEL-descriptor-bytes")
	v = verdictOf(t, p)
	if v.GetState() != connectorv1.PasswordChangeState_PASSWORD_CHANGE_STATE_NOT_CONFIRMED || strings.Contains(v.String(), "SENTINEL") {
		t.Fatalf("%v", v)
	}
}

func TestPasswordChangeForAnotherObjectIsRefused(t *testing.T) {
	p := newPC()
	p.state, p.got = sd.PasswordChangeBlocked, g(parGUID)
	v := verdictOf(t, p)
	if v.GetState() != connectorv1.PasswordChangeState_PASSWORD_CHANGE_STATE_NOT_CONFIRMED || v.GetObjectGuid() != nil {
		t.Fatalf("%v", v)
	}
}

func TestPasswordChangeOnlyWhenAsked(t *testing.T) {
	p := newPC()
	p.state = sd.PasswordChangeBlocked
	ms, err := collect(t, start(t, p), req(dsaA, false))
	if err != nil || ms[0].GetHeader().GetPasswordChange() != nil || p.asked != 0 {
		t.Fatalf("%v asked %d", err, p.asked)
	}
}

func TestPasswordChangeWithoutCapabilityIsNotConfirmed(t *testing.T) {
	s := &src{dsa: dsaA, entry: entry(map[string][][]byte{"cn": {[]byte("x")}})}
	v := verdictOf(t, s)
	if v.GetState() != connectorv1.PasswordChangeState_PASSWORD_CHANGE_STATE_NOT_CONFIRMED || v.GetErrorCode() != connectorv1.ErrorCode_ERROR_CODE_CAPABILITY_UNSUPPORTED {
		t.Fatalf("%v", v)
	}
}
