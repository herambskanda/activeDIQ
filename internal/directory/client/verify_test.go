package client

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/skenzeriq/activediq/internal/directory/connection"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

const (
	vConn = "11111111-2222-4333-8444-555555555555"
	vRun  = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	vDom  = "01020304-0506-4708-890a-0b0c0d0e0f10"
)

type fakeStream struct {
	msgs []*connectorv1.VerifyConnectionResponse
	err  error
}

func (s *fakeStream) Recv() (*connectorv1.VerifyConnectionResponse, error) {
	if len(s.msgs) == 0 {
		if s.err != nil {
			return nil, s.err
		}
		return nil, io.EOF
	}
	m := s.msgs[0]
	s.msgs = s.msgs[1:]
	return m, nil
}

type fakeVerify struct {
	got *connectorv1.VerifyConnectionRequest
	st  *fakeStream
	err error
}

func (f *fakeVerify) VerifyConnection(_ context.Context, r *connectorv1.VerifyConnectionRequest) (VerifyStream, error) {
	f.got = r
	return f.st, f.err
}

type fixedScope struct {
	sc  VerifyScope
	err error
}

func (f fixedScope) VerifyScope(context.Context, connection.Connection) (VerifyScope, error) {
	return f.sc, f.err
}

func g16(last byte) *connectorv1.Guid {
	b := make([]byte, 16)
	for i := range b {
		b[i] = byte(i + 1)
	}
	b[15] = last
	return &connectorv1.Guid{Value: b}
}

func runGuid() *connectorv1.Guid {
	return &connectorv1.Guid{Value: []byte{0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0x4c, 0xcc, 0x8d, 0xdd, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee}}
}

func header() *connectorv1.VerifyConnectionResponse {
	return &connectorv1.VerifyConnectionResponse{Event: &connectorv1.VerifyConnectionResponse_Header{
		Header: &connectorv1.VerificationHeader{VerificationId: runGuid(), CheckListVersion: "1"}}}
}

func findings(fs ...*connectorv1.RightsFinding) *connectorv1.VerifyConnectionResponse {
	return &connectorv1.VerifyConnectionResponse{Event: &connectorv1.VerifyConnectionResponse_Findings{
		Findings: &connectorv1.FindingsChunk{Findings: fs}}}
}

func completed(v connectorv1.VerificationVerdict, nf, nt uint32, cs ...*connectorv1.CheckResult) *connectorv1.VerifyConnectionResponse {
	return &connectorv1.VerifyConnectionResponse{Event: &connectorv1.VerifyConnectionResponse_Completed{
		Completed: &connectorv1.VerificationCompleted{Verdict: v, Checks: cs, FindingCount: nf, Tier0MemberCount: nt}}}
}

func tier0(n int) *connectorv1.VerifyConnectionResponse {
	ms := make([]*connectorv1.Tier0Member, n)
	for i := range ms {
		ms[i] = &connectorv1.Tier0Member{}
	}
	return &connectorv1.VerifyConnectionResponse{Event: &connectorv1.VerifyConnectionResponse_Tier0Set{
		Tier0Set: &connectorv1.Tier0SetChunk{Members: ms}}}
}

func chk(c connectorv1.VerificationCheck, o connectorv1.CheckOutcome) *connectorv1.CheckResult {
	return &connectorv1.CheckResult{Check: c, Outcome: o}
}

func fp(b byte) []byte {
	out := make([]byte, 32)
	out[0] = b
	return out
}

func tier0Finding() *connectorv1.RightsFinding {
	return &connectorv1.RightsFinding{
		Check: connectorv1.VerificationCheck_VERIFICATION_CHECK_V7_OVER_PRIVILEGE,
		Kind:  connectorv1.FindingKind_FINDING_KIND_TIER0_GROUP_MEMBERSHIP, Severity: connectorv1.FindingSeverity_FINDING_SEVERITY_BLOCK,
		Code: "over.tier0_group", Object: g16(9), ObjectDomainSid: &connectorv1.Sid{Value: []byte{1, 4, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0}},
		Source: &connectorv1.RightSource{Source: &connectorv1.RightSource_Membership{Membership: &connectorv1.MembershipPath{
			Hops: []*connectorv1.MembershipHop{{Group: g16(7)}}}}},
		Fingerprint: fp(1),
	}
}

func newVerifyClient(st *fakeStream, sc fixedScope) (*Client, *fakeVerify) {
	fv := &fakeVerify{st: st}
	return New(WithVerifyTransport(fv), WithVerifyScope(sc)), fv
}

func vreq() connection.VerifyRequest {
	return connection.VerifyRequest{Connection: connection.Connection{ID: vConn, Kind: connection.KindADForest},
		Kind: connection.KindManual, VerificationID: vRun}
}

func TestVerifyConnectionFoldsStreamAndSendsScope(t *testing.T) {
	st := &fakeStream{msgs: []*connectorv1.VerifyConnectionResponse{
		header(), findings(tier0Finding()), tier0(2),
		completed(connectorv1.VerificationVerdict_VERIFICATION_VERDICT_REFUSED, 1, 2,
			chk(connectorv1.VerificationCheck_VERIFICATION_CHECK_V5_IDENTITY, connectorv1.CheckOutcome_CHECK_OUTCOME_PASS),
			chk(connectorv1.VerificationCheck_VERIFICATION_CHECK_V7_OVER_PRIVILEGE, connectorv1.CheckOutcome_CHECK_OUTCOME_FAIL)),
	}}
	cl, fv := newVerifyClient(st, fixedScope{sc: VerifyScope{
		EnabledFamilies: []connectorv1.RightsFamily{connectorv1.RightsFamily_RIGHTS_FAMILY_AD_R1_INVENTORY, connectorv1.RightsFamily_RIGHTS_FAMILY_AD_R6_GROUPS},
		ManagedDomains:  []string{vDom},
	}})
	res, err := cl.VerifyConnection(context.Background(), vreq())
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != connection.VerdictRefused || res.CheckListVersion != 1 {
		t.Fatalf("verdict/version: %+v", res)
	}
	if res.Outcomes[connection.CheckV7OverPrivilege] != connection.OutcomeFail || res.Outcomes["V5"] != connection.OutcomePass {
		t.Fatalf("outcomes: %v", res.Outcomes)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("findings: %v", res.Findings)
	}
	f := res.Findings[0]
	if f.Check != "V7" || f.Kind != "tier0_group_membership" || f.Severity != connection.SeverityBlock ||
		f.ObjectGUID != "01020304-0506-0708-090a-0b0c0d0e0f09" || f.Qualifier != "01020304-0506-0708-090a-0b0c0d0e0f07" ||
		f.ObjectDomainSID != "S-1-5-21-1-2-3" || !strings.HasPrefix(f.Fingerprint, "01") || len(f.Fingerprint) != 64 {
		t.Fatalf("finding: %+v", f)
	}
	r := fv.got
	if r.GetConnection().GetConnectionId() != vConn || r.GetRunKind() != connectorv1.VerificationRunKind_VERIFICATION_RUN_KIND_MANUAL {
		t.Fatalf("request: %v", r)
	}
	if len(r.EnabledFamilies) != 2 || len(r.ManagedDomains) != 1 || r.ManagedDomains[0].Value[0] != 1 || r.ManagedDomains[0].Value[15] != 0x10 {
		t.Fatalf("scope not sent: %v", r)
	}
}

func TestVerifyConnectionIncompleteStreamsAreNotResults(t *testing.T) {
	pass := connectorv1.VerificationVerdict_VERIFICATION_VERDICT_PASS
	f := func() *connectorv1.VerifyConnectionResponse { return findings(tier0Finding()) }
	cases := map[string][]*connectorv1.VerifyConnectionResponse{
		"empty":               {},
		"no completion":       {header(), f()},
		"no header":           {completed(pass, 0, 0)},
		"findings no header":  {f(), completed(pass, 1, 0)},
		"second header":       {header(), header(), completed(pass, 0, 0)},
		"after completion":    {header(), completed(pass, 0, 0), f()},
		"finding count":       {header(), f(), completed(pass, 2, 0)},
		"tier0 count":         {header(), tier0(1), completed(pass, 0, 0)},
		"duplicate finding":   {header(), f(), f(), completed(pass, 2, 0)},
		"unspecified verdict": {header(), completed(0, 0, 0)},
		"wrong run id": {&connectorv1.VerifyConnectionResponse{Event: &connectorv1.VerifyConnectionResponse_Header{
			Header: &connectorv1.VerificationHeader{VerificationId: g16(1), CheckListVersion: "1"}}}, completed(pass, 0, 0)},
		"bad version": {&connectorv1.VerifyConnectionResponse{Event: &connectorv1.VerifyConnectionResponse_Header{
			Header: &connectorv1.VerificationHeader{VerificationId: runGuid(), CheckListVersion: "x"}}}, completed(pass, 0, 0)},
		"bad fingerprint": {header(), findings(&connectorv1.RightsFinding{Check: 1, Kind: 1, Severity: 1, Code: "x", Fingerprint: []byte{1}}), completed(pass, 1, 0)},
	}
	for name, msgs := range cases {
		cl, _ := newVerifyClient(&fakeStream{msgs: msgs}, fixedScope{})
		res, err := cl.VerifyConnection(context.Background(), vreq())
		if !errors.Is(err, ErrStreamProtocol) {
			t.Errorf("%s: err = %v", name, err)
		}
		if res.Verdict != "" || res.Findings != nil {
			t.Errorf("%s: a result came back with the error: %+v", name, res)
		}
	}
}

func TestVerifyConnectionStreamErrorKeepsOnlyTheCode(t *testing.T) {
	ce := &connectorv1.ConnectorError{Code: connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT}
	stt, err := status.New(codes.InvalidArgument, "secret host dc01.corp").WithDetails(ce)
	if err != nil {
		t.Fatal(err)
	}
	cl, _ := newVerifyClient(&fakeStream{msgs: []*connectorv1.VerifyConnectionResponse{header()}, err: stt.Err()}, fixedScope{})
	_, err = cl.VerifyConnection(context.Background(), vreq())
	var re *RemoteError
	if !errors.As(err, &re) || strings.Contains(err.Error(), "dc01") {
		t.Fatalf("err = %v", err)
	}
	cl, _ = newVerifyClient(&fakeStream{err: errors.New("dial dc01.corp: refused")}, fixedScope{})
	_, err = cl.VerifyConnection(context.Background(), vreq())
	if !errors.Is(err, ErrTransport) || strings.Contains(err.Error(), "dc01") {
		t.Fatalf("err = %v", err)
	}
}

func TestVerifyConnectionRefusesBadInputBeforeTheWire(t *testing.T) {
	cl := New()
	if _, err := cl.VerifyConnection(context.Background(), vreq()); !errors.Is(err, ErrNoVerifier) {
		t.Fatal(err)
	}
	cl, fv := newVerifyClient(&fakeStream{}, fixedScope{sc: VerifyScope{ManagedDomains: []string{"not-a-guid"}}})
	if _, err := cl.VerifyConnection(context.Background(), vreq()); !errors.Is(err, ErrVerifyInput) || fv.got != nil {
		t.Fatalf("bad domain: %v", err)
	}
	cl, fv = newVerifyClient(&fakeStream{}, fixedScope{err: errors.New("db down")})
	if _, err := cl.VerifyConnection(context.Background(), vreq()); !errors.Is(err, ErrVerifyInput) || fv.got != nil {
		t.Fatalf("scope error: %v", err)
	}
	cl, fv = newVerifyClient(&fakeStream{}, fixedScope{})
	bad := vreq()
	bad.Kind = "bogus"
	if _, err := cl.VerifyConnection(context.Background(), bad); !errors.Is(err, ErrVerifyInput) || fv.got != nil {
		t.Fatalf("bad kind: %v", err)
	}
}

// The folded findings must pass the registry's own validation shape: Entra credential findings
// qualify by key id; a could-not-verify finding has no qualifier.
func TestVerifyQualifiers(t *testing.T) {
	ent := &connectorv1.RightsFinding{
		Check: connectorv1.VerificationCheck_VERIFICATION_CHECK_EV3_OVER_PRIVILEGE, Kind: connectorv1.FindingKind_FINDING_KIND_ENTRA_PASSWORD_CREDENTIAL,
		Severity: connectorv1.FindingSeverity_FINDING_SEVERITY_BLOCK, Code: "over.entra_secret", Object: g16(3), Fingerprint: fp(2),
		Right: &connectorv1.RightRef{Right: &connectorv1.RightRef_Entra{Entra: &connectorv1.EntraRight{Right: &connectorv1.EntraRight_PasswordCredential{
			PasswordCredential: &connectorv1.EntraPasswordCredential{KeyId: g16(4)}}}}},
	}
	cnv := &connectorv1.RightsFinding{
		Check: connectorv1.VerificationCheck_VERIFICATION_CHECK_V7_OVER_PRIVILEGE, Kind: connectorv1.FindingKind_FINDING_KIND_COULD_NOT_VERIFY,
		Severity: connectorv1.FindingSeverity_FINDING_SEVERITY_BLOCK, Code: "cnv.acl", Fingerprint: fp(3),
	}
	ace := &connectorv1.RightsFinding{
		Check: connectorv1.VerificationCheck_VERIFICATION_CHECK_V7_OVER_PRIVILEGE, Kind: connectorv1.FindingKind_FINDING_KIND_EXCESSIVE_RIGHT,
		Severity: connectorv1.FindingSeverity_FINDING_SEVERITY_BLOCK, Code: "over.tier0_write", Object: g16(3), Fingerprint: fp(4),
		Right:  &connectorv1.RightRef{Right: &connectorv1.RightRef_Ad{Ad: &connectorv1.AdRight{Kind: connectorv1.AdRightKind_AD_RIGHT_KIND_WRITE_DAC}}},
		Source: &connectorv1.RightSource{Source: &connectorv1.RightSource_Ace{Ace: &connectorv1.AceSource{Trustee: &connectorv1.Sid{Value: []byte{1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0}}}}},
	}
	for _, c := range []struct {
		f    *connectorv1.RightsFinding
		want string
	}{
		{ent, "01020304-0506-0708-090a-0b0c0d0e0f04"},
		{cnv, ""},
		{ace, "S-1-5-18"},
	} {
		got, err := mapFinding(c.f)
		if err != nil || got.Qualifier != c.want {
			t.Errorf("%v: qualifier %q err %v, want %q", c.f.Kind, got.Qualifier, err, c.want)
		}
	}
}
