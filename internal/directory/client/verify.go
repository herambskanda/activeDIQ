package client

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
	"github.com/skenzeriq/activediq/internal/directory/connection"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// Errors of the VerifyConnection path. None carries a finding, an object identifier or a connector
// message (DM-24.I5).
var (
	ErrNoVerifier  = errors.New("client: no verify transport wired")
	ErrNoVerifyIn  = errors.New("client: no verify inputs wired")
	ErrVerifyInput = errors.New("client: invalid verify input")
	// ErrStreamProtocol: the stream broke contract §2 rule 11 or §8.4 (no header, a second header,
	// a message after completion, no completion, counts that do not add up, a mismatched run id).
	ErrStreamProtocol = errors.New("client: verify stream violates the contract")
)

// VerifyScope is what a run is told it manages (contract §8.4): the families the connection has
// enabled and, for AD, the domain NCs it manages (V8). The server's registry is the only source.
type VerifyScope struct {
	EnabledFamilies []connectorv1.RightsFamily
	ManagedDomains  []string // canonical UUID text of each domain NC head
}

// VerifyScopeSource answers a connection's VerifyScope. A read error stops the run before any call.
type VerifyScopeSource interface {
	VerifyScope(ctx context.Context, conn connection.Connection) (VerifyScope, error)
}

// VerifyStream is the receiving side of the VerifyConnection RPC. The generated
// grpc.ServerStreamingClient satisfies it.
type VerifyStream interface {
	Recv() (*connectorv1.VerifyConnectionResponse, error)
}

// VerifyTransport opens the VerifyConnection stream. The gRPC transport implements it.
type VerifyTransport interface {
	VerifyConnection(ctx context.Context, req *connectorv1.VerifyConnectionRequest) (VerifyStream, error)
}

// WithVerifyTransport wires the VerifyConnection transport.
func WithVerifyTransport(t VerifyTransport) Option { return func(c *Client) { c.verify = t } }

// WithVerifyScope wires the source of enabled families and managed domains.
func WithVerifyScope(s VerifyScopeSource) Option { return func(c *Client) { c.scope = s } }

var _ connection.ConnectorClient = (*Client)(nil)

// maxVerifyFindings bounds what the fold keeps; the registry enforces the same bound on record.
const maxVerifyFindings = 50000

// VerifyConnection implements connection.ConnectorClient: it sends the run request with the
// connection's enabled families and managed domains, and folds the stream into a VerifyResult. A
// stream that does not end in exactly one `completed` is an error and no result (contract §2 rule 11).
// The run is read-only and is not gated.
func (c *Client) VerifyConnection(ctx context.Context, req connection.VerifyRequest) (connection.VerifyResult, error) {
	switch {
	case c.verify == nil:
		return connection.VerifyResult{}, ErrNoVerifier
	case c.scope == nil:
		return connection.VerifyResult{}, ErrNoVerifyIn
	}
	scope, err := c.scope.VerifyScope(ctx, req.Connection)
	if err != nil {
		return connection.VerifyResult{}, fmt.Errorf("%w: scope unavailable", ErrVerifyInput)
	}
	wreq, err := buildVerifyRequest(req, scope)
	if err != nil {
		return connection.VerifyResult{}, err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel() // abandoning the fold early must not leak the stream
	st, err := c.verify.VerifyConnection(ctx, wreq)
	if err != nil {
		return connection.VerifyResult{}, sanitize(err)
	}
	return foldVerify(st, req)
}

func buildVerifyRequest(req connection.VerifyRequest, sc VerifyScope) (*connectorv1.VerifyConnectionRequest, error) {
	rk, ok := runKinds[req.Kind]
	vid, verr := parseUUID(string(req.VerificationID))
	cid := string(req.Connection.ID)
	if !ok || verr != nil || cid == "" {
		return nil, fmt.Errorf("%w: run kind, verification id or connection", ErrVerifyInput)
	}
	out := &connectorv1.VerifyConnectionRequest{
		Connection:     &connectorv1.ConnectionRef{ConnectionId: cid},
		RunKind:        rk,
		VerificationId: &connectorv1.Guid{Value: vid},
	}
	for _, f := range sc.EnabledFamilies {
		if f == connectorv1.RightsFamily_RIGHTS_FAMILY_UNSPECIFIED {
			return nil, fmt.Errorf("%w: rights family", ErrVerifyInput)
		}
		out.EnabledFamilies = append(out.EnabledFamilies, f)
	}
	for _, d := range sc.ManagedDomains {
		b, err := parseUUID(d)
		if err != nil {
			return nil, fmt.Errorf("%w: managed domain", ErrVerifyInput)
		}
		out.ManagedDomains = append(out.ManagedDomains, &connectorv1.Guid{Value: b})
	}
	return out, nil
}

var runKinds = map[connection.VerificationKind]connectorv1.VerificationRunKind{
	connection.KindOnboarding:       connectorv1.VerificationRunKind_VERIFICATION_RUN_KIND_ONBOARDING,
	connection.KindActivation:       connectorv1.VerificationRunKind_VERIFICATION_RUN_KIND_ACTIVATION,
	connection.KindResume:           connectorv1.VerificationRunKind_VERIFICATION_RUN_KIND_RESUME,
	connection.KindCredentialChange: connectorv1.VerificationRunKind_VERIFICATION_RUN_KIND_CREDENTIAL_CHANGE,
	connection.KindScheduled:        connectorv1.VerificationRunKind_VERIFICATION_RUN_KIND_SCHEDULED,
	connection.KindManual:           connectorv1.VerificationRunKind_VERIFICATION_RUN_KIND_MANUAL,
}

func protocolErr(why string) error { return fmt.Errorf("%w: %s", ErrStreamProtocol, why) }

func foldVerify(st VerifyStream, req connection.VerifyRequest) (connection.VerifyResult, error) {
	var (
		res       connection.VerifyResult
		haveHead  bool
		done      bool
		seenFP    = map[string]struct{}{}
		tier0Seen uint32
	)
	for {
		m, err := st.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return connection.VerifyResult{}, sanitize(err)
		}
		if done {
			return connection.VerifyResult{}, protocolErr("message after completion")
		}
		switch ev := m.GetEvent().(type) {
		case *connectorv1.VerifyConnectionResponse_Header:
			if haveHead {
				return connection.VerifyResult{}, protocolErr("second header")
			}
			haveHead = true
			h := ev.Header
			if g, err := guidText(h.GetVerificationId().GetValue()); err != nil || g != string(req.VerificationID) {
				return connection.VerifyResult{}, protocolErr("run id mismatch")
			}
			v, err := strconv.Atoi(h.GetCheckListVersion())
			if err != nil || v < 1 {
				return connection.VerifyResult{}, protocolErr("check list version")
			}
			res.CheckListVersion = v
		case *connectorv1.VerifyConnectionResponse_Findings:
			if !haveHead {
				return connection.VerifyResult{}, protocolErr("findings before header")
			}
			for _, f := range ev.Findings.GetFindings() {
				if len(res.Findings) >= maxVerifyFindings {
					return connection.VerifyResult{}, protocolErr("too many findings")
				}
				fd, err := mapFinding(f)
				if err != nil {
					return connection.VerifyResult{}, err
				}
				if _, dup := seenFP[fd.Fingerprint]; dup {
					return connection.VerifyResult{}, protocolErr("duplicate fingerprint")
				}
				seenFP[fd.Fingerprint] = struct{}{}
				res.Findings = append(res.Findings, fd)
			}
		case *connectorv1.VerifyConnectionResponse_Tier0Set:
			if !haveHead {
				return connection.VerifyResult{}, protocolErr("tier0 set before header")
			}
			// The server compares the set with its inventory elsewhere; here it is only counted.
			tier0Seen += uint32(len(ev.Tier0Set.GetMembers()))
		case *connectorv1.VerifyConnectionResponse_Completed:
			if !haveHead {
				return connection.VerifyResult{}, protocolErr("completion before header")
			}
			done = true
			cm := ev.Completed
			if cm.GetFindingCount() != uint32(len(res.Findings)) || cm.GetTier0MemberCount() != tier0Seen {
				return connection.VerifyResult{}, protocolErr("counts do not match")
			}
			if res.Verdict, err = mapVerdict(cm.GetVerdict()); err != nil {
				return connection.VerifyResult{}, err
			}
			if res.Outcomes, err = mapChecks(cm.GetChecks()); err != nil {
				return connection.VerifyResult{}, err
			}
		default:
			return connection.VerifyResult{}, protocolErr("unknown message")
		}
	}
	if !done {
		return connection.VerifyResult{}, protocolErr("no completion")
	}
	return res, nil
}

func mapVerdict(v connectorv1.VerificationVerdict) (connection.Verdict, error) {
	switch v {
	case connectorv1.VerificationVerdict_VERIFICATION_VERDICT_PASS:
		return connection.VerdictPass, nil
	case connectorv1.VerificationVerdict_VERIFICATION_VERDICT_REFUSED:
		return connection.VerdictRefused, nil
	case connectorv1.VerificationVerdict_VERIFICATION_VERDICT_COULD_NOT_VERIFY:
		return connection.VerdictCouldNotVerify, nil
	case connectorv1.VerificationVerdict_VERIFICATION_VERDICT_FAILED:
		return connection.VerdictFailed, nil
	}
	return "", protocolErr("verdict")
}

var outcomes = map[connectorv1.CheckOutcome]connection.Outcome{
	connectorv1.CheckOutcome_CHECK_OUTCOME_PASS:             connection.OutcomePass,
	connectorv1.CheckOutcome_CHECK_OUTCOME_WARN:             connection.OutcomeWarn,
	connectorv1.CheckOutcome_CHECK_OUTCOME_FAIL:             connection.OutcomeFail,
	connectorv1.CheckOutcome_CHECK_OUTCOME_COULD_NOT_VERIFY: connection.OutcomeCouldNotVerify,
	connectorv1.CheckOutcome_CHECK_OUTCOME_NOT_RUN:          connection.OutcomeNotRun,
}

// checkNames maps the wire enum to the registry's names. A check outside the table is a protocol
// error: the registry only stores names it knows.
var checkNames = map[connectorv1.VerificationCheck]connection.Check{
	connectorv1.VerificationCheck_VERIFICATION_CHECK_V1_LOCATE:                "V1",
	connectorv1.VerificationCheck_VERIFICATION_CHECK_V2_CLOCK:                 "V2",
	connectorv1.VerificationCheck_VERIFICATION_CHECK_V3_TRANSPORT:             "V3",
	connectorv1.VerificationCheck_VERIFICATION_CHECK_V4_AUTHENTICATE:          "V4",
	connectorv1.VerificationCheck_VERIFICATION_CHECK_V5_IDENTITY:              "V5",
	connectorv1.VerificationCheck_VERIFICATION_CHECK_V6_TOPOLOGY:              "V6",
	connectorv1.VerificationCheck_VERIFICATION_CHECK_V7_OVER_PRIVILEGE:        connection.CheckV7OverPrivilege,
	connectorv1.VerificationCheck_VERIFICATION_CHECK_V8_READ_SUFFICIENCY:      connection.CheckV8ReadSufficient,
	connectorv1.VerificationCheck_VERIFICATION_CHECK_V9_EXCESS_IN_MANAGED_OUS: "V9",
	connectorv1.VerificationCheck_VERIFICATION_CHECK_EV1_TOKEN:                "EV1",
	connectorv1.VerificationCheck_VERIFICATION_CHECK_EV2_TENANT_IDENTITY:      "EV2",
	connectorv1.VerificationCheck_VERIFICATION_CHECK_EV3_OVER_PRIVILEGE:       connection.CheckEV3OverPrivilege,
	connectorv1.VerificationCheck_VERIFICATION_CHECK_EV4_SUFFICIENCY:          connection.CheckEV4Sufficiency,
	connectorv1.VerificationCheck_VERIFICATION_CHECK_EV5_EXCESS:               "EV5",
}

func mapChecks(cs []*connectorv1.CheckResult) (map[connection.Check]connection.Outcome, error) {
	out := make(map[connection.Check]connection.Outcome, len(cs))
	for _, c := range cs {
		name, ok := checkNames[c.GetCheck()]
		o, ok2 := outcomes[c.GetOutcome()]
		if !ok || !ok2 {
			return nil, protocolErr("check or outcome")
		}
		if _, dup := out[name]; dup {
			return nil, protocolErr("duplicate check")
		}
		out[name] = o // the ConnectorError of a check is not kept: it may name a host
	}
	return out, nil
}

var severities = map[connectorv1.FindingSeverity]connection.Severity{
	connectorv1.FindingSeverity_FINDING_SEVERITY_BLOCK: connection.SeverityBlock,
	connectorv1.FindingSeverity_FINDING_SEVERITY_WARN:  connection.SeverityWarn,
	connectorv1.FindingSeverity_FINDING_SEVERITY_INFO:  connection.SeverityInfo,
}

// mapFinding maps one RightsFinding to a DM-24 Finding (contract §8.4 "Mapping to a DM-24 Finding").
// The fingerprint is the connector's; the server never recomputes it.
func mapFinding(f *connectorv1.RightsFinding) (connection.Finding, error) {
	chk, ok := checkNames[f.GetCheck()]
	sev, ok2 := severities[f.GetSeverity()]
	kind := findingKind(f.GetKind())
	if !ok || !ok2 || kind == "" || f.GetCode() == "" || len(f.GetFingerprint()) != 32 {
		return connection.Finding{}, protocolErr("finding")
	}
	out := connection.Finding{Check: chk, Code: f.GetCode(), Kind: kind, Severity: sev, Fingerprint: hex.EncodeToString(f.GetFingerprint())}
	var err error
	if o := f.GetObject(); o != nil {
		if out.ObjectGUID, err = guidText(o.GetValue()); err != nil {
			return connection.Finding{}, protocolErr("finding object")
		}
	}
	if d := f.GetObjectDomainSid(); d != nil {
		if out.ObjectDomainSID, err = sidTextOf(d.GetValue()); err != nil {
			return connection.Finding{}, protocolErr("finding domain sid")
		}
	}
	if out.Qualifier, err = qualifier(f); err != nil {
		return connection.Finding{}, protocolErr("finding qualifier")
	}
	return out, nil
}

var kindNames = map[connectorv1.FindingKind]connection.FindingKind{
	connectorv1.FindingKind_FINDING_KIND_EXCESSIVE_RIGHT:            connection.FindingExcessiveRight,
	connectorv1.FindingKind_FINDING_KIND_MISSING_RIGHT:              connection.FindingMissingRight,
	connectorv1.FindingKind_FINDING_KIND_TIER0_GROUP_MEMBERSHIP:     "tier0_group_membership",
	connectorv1.FindingKind_FINDING_KIND_DELEGATION_CONFIGURED:      "delegation_configured",
	connectorv1.FindingKind_FINDING_KIND_ENTRA_DENY_LIST_PERMISSION: "entra_deny_list_permission",
	connectorv1.FindingKind_FINDING_KIND_ENTRA_DIRECTORY_ROLE:       "entra_directory_role",
	connectorv1.FindingKind_FINDING_KIND_ENTRA_EXTRA_KEY_CREDENTIAL: "entra_extra_key_credential",
	connectorv1.FindingKind_FINDING_KIND_ENTRA_OWNER:                "entra_owner",
	connectorv1.FindingKind_FINDING_KIND_COULD_NOT_VERIFY:           "could_not_verify",
	connectorv1.FindingKind_FINDING_KIND_ENTRA_PASSWORD_CREDENTIAL:  "entra_password_credential",
}

func findingKind(k connectorv1.FindingKind) connection.FindingKind { return kindNames[k] }

// qualifier derives the DM-24 qualifier per kind (contract §8.4). An empty result is legal.
func qualifier(f *connectorv1.RightsFinding) (string, error) {
	switch f.GetKind() {
	case connectorv1.FindingKind_FINDING_KIND_TIER0_GROUP_MEMBERSHIP:
		hops := f.GetSource().GetMembership().GetHops()
		if len(hops) == 0 {
			return "", nil
		}
		if g := hops[0].GetGroup(); g != nil {
			return guidText(g.GetValue())
		}
		return sidTextOf(hops[0].GetSid().GetValue())
	case connectorv1.FindingKind_FINDING_KIND_EXCESSIVE_RIGHT, connectorv1.FindingKind_FINDING_KIND_MISSING_RIGHT:
		if ad := f.GetRight().GetAd(); ad != nil {
			if ot := ad.GetObjectType(); ot != nil {
				return guidText(ot.GetValue())
			}
			if ace := f.GetSource().GetAce(); ace != nil {
				if g := ace.GetTrusteeGroup(); g != nil {
					return guidText(g.GetValue())
				}
				if t := ace.GetTrustee(); t != nil {
					return sidTextOf(t.GetValue())
				}
			}
			return "", nil
		}
		return entraQualifier(f.GetRight().GetEntra())
	case connectorv1.FindingKind_FINDING_KIND_ENTRA_DENY_LIST_PERMISSION, connectorv1.FindingKind_FINDING_KIND_ENTRA_DIRECTORY_ROLE,
		connectorv1.FindingKind_FINDING_KIND_ENTRA_EXTRA_KEY_CREDENTIAL, connectorv1.FindingKind_FINDING_KIND_ENTRA_OWNER,
		connectorv1.FindingKind_FINDING_KIND_ENTRA_PASSWORD_CREDENTIAL:
		return entraQualifier(f.GetRight().GetEntra())
	}
	return "", nil // delegation, could-not-verify
}

func entraQualifier(e *connectorv1.EntraRight) (string, error) {
	var g *connectorv1.Guid
	switch r := e.GetRight().(type) {
	case *connectorv1.EntraRight_AppPermission:
		g = r.AppPermission.GetAppRoleId()
	case *connectorv1.EntraRight_DirectoryRole:
		g = r.DirectoryRole.GetRoleDefinitionId()
	case *connectorv1.EntraRight_KeyCredential:
		g = r.KeyCredential.GetKeyId()
	case *connectorv1.EntraRight_PasswordCredential:
		g = r.PasswordCredential.GetKeyId()
	case *connectorv1.EntraRight_Owner:
		g = r.Owner
	default:
		return "", nil
	}
	if g == nil {
		return "", nil
	}
	return guidText(g.GetValue())
}

// guidText renders the 16 network-order bytes of a proto Guid as canonical lower-case text. The
// wire form is not the LDAP mixed-endian order, so the attr codec is not used here.
func guidText(b []byte) (string, error) {
	if len(b) != 16 {
		return "", ErrStreamProtocol
	}
	var zero byte
	for _, x := range b {
		zero |= x
	}
	if zero == 0 {
		return "", ErrStreamProtocol
	}
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32], nil
}

func sidTextOf(b []byte) (string, error) {
	s, err := sid.FromBytes(b)
	if err != nil {
		return "", ErrStreamProtocol
	}
	return s.String(), nil
}
