// Package rights is the connector's rights check (VerifyConnection, threat-model §6.5 and §6.6).
// The Entra half reads the app's own grants through the Graph client and compares them with the
// §6.6 policy in policy_entra.go. It is read-only and holds identifiers only (DM-24.I3): no name,
// no key material, no secret metadata beyond key ids and validity.
package rights

import (
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // a certificate thumbprint is SHA-1 by definition; it identifies, it does not authenticate
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/skenzeriq/activediq/internal/connector/graph"
	dguid "github.com/skenzeriq/activediq/internal/directory/attr/guid"
	v1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// Finding codes (DM X6 registered strings).
const (
	CodeDenyList    = "over.entra_deny_list_permission"
	CodeRole        = "over.entra_directory_role"
	CodeExtraPerm   = "over.entra_extra_permission"
	CodeMissingPerm = "missing.entra_permission"
	CodeExtraKey    = "over.entra_extra_key_credential"
	CodeSecret      = "over.entra_password_credential"
	CodeOwner       = "over.entra_owner"
	CodeUnverified  = "unverified.entra"
)

// EntraReader is what the check reads: the app's own service principal, application, grants, roles
// and owners. *graph.Client implements it.
type EntraReader interface {
	OwnServicePrincipal(ctx context.Context) (graph.ServicePrincipal, error)
	OwnApplication(ctx context.Context) (graph.Application, error)
	ServicePrincipalByID(ctx context.Context, id dguid.GUID) (graph.ServicePrincipal, error)
	AppRoleAssignments(ctx context.Context, spID dguid.GUID) ([]graph.AppRoleAssignment, error)
	DirectoryRoleAssignments(ctx context.Context, principalID dguid.GUID) ([]graph.RoleAssignment, error)
	ServicePrincipalGroups(ctx context.Context, spID dguid.GUID) ([]graph.Group, error)
	ApplicationOwners(ctx context.Context, objectID dguid.GUID) ([]graph.DirectoryObject, error)
	ServicePrincipalOwners(ctx context.Context, objectID dguid.GUID) ([]graph.DirectoryObject, error)
}

var _ EntraReader = (*graph.Client)(nil)

// EntraInput is what the server and the connector's own store supply.
type EntraInput struct {
	// EnabledFamilies are the Entra families the connection has enabled; the baseline families are
	// always added.
	EnabledFamilies []v1.RightsFamily
	// HeldThumbprint is the SHA-1 thumbprint of the one certificate this connector holds. A key
	// credential is that certificate only when the SHA-1 of its public certificate (`key`) equals
	// it: customKeyIdentifier is a caller-chosen label and is never trusted. Every other key
	// credential, on the application or its service principal, is extra.
	HeldThumbprint []byte
	// Now is the connector's clock, used to tell an unexpired password credential from an expired
	// one (contract v1.2, CC-VER-13). Nil means time.Now.
	Now func() time.Time
}

// Finding is a RightsFinding plus the DM-24.I4 qualifier. The fingerprint is computed where
// audit/canon is available (the VerifyConnection stream), over Check, Code, Object and Qualifier;
// RightsFinding.Fingerprint stays unset here.
type Finding struct {
	*v1.RightsFinding
	Qualifier string
}

// Result is the Entra rights check's outcome.
type Result struct {
	Findings []Finding
	// Checks has EV3, EV4 and EV5, in that order.
	Checks  []*v1.CheckResult
	Verdict v1.VerificationVerdict
	// WriteGateOpenable is true only for a PASS verdict.
	WriteGateOpenable bool
	// Identity is the observed app, service principal and application object.
	Identity *v1.EntraObservedIdentity
}

// Blocking reports whether any finding has block severity.
func (r *Result) Blocking() bool {
	for _, f := range r.Findings {
		if f.Severity == v1.FindingSeverity_FINDING_SEVERITY_BLOCK {
			return true
		}
	}
	return false
}

// VerifyEntra runs EV3 (deny list, directory roles), EV4 (missing permissions) and EV5 (extra
// permissions, key and password credentials, owners) as the connector's own app.
//
// A read that fails never yields a pass: the check it feeds is COULD_NOT_VERIFY (FR-11), the error
// is attached to the check and the verdict is COULD_NOT_VERIFY unless a blocking finding already
// refuses.
func VerifyEntra(ctx context.Context, rd EntraReader, in EntraInput) (*Result, error) {
	// The identity read is the precondition of everything else; without it nothing can be named.
	sp, err := rd.OwnServicePrincipal(ctx)
	if err != nil {
		return nil, fmt.Errorf("read own service principal: %w", err)
	}
	app, err := rd.OwnApplication(ctx)
	if err != nil {
		return nil, fmt.Errorf("read own application: %w", err)
	}
	spID, err := guidBytes(sp.ID)
	if err != nil {
		return nil, fmt.Errorf("service principal id: %w", err)
	}
	appObj, err := guidBytes(app.ID)
	if err != nil {
		return nil, fmt.Errorf("application id: %w", err)
	}
	appID, err := guidBytes(sp.AppID)
	if err != nil {
		return nil, fmt.Errorf("app id: %w", err)
	}

	spG, err := dguid.Parse(sp.ID)
	if err != nil {
		return nil, fmt.Errorf("service principal id: %w", err)
	}
	appG, err := dguid.Parse(app.ID)
	if err != nil {
		return nil, fmt.Errorf("application id: %w", err)
	}
	b := &builder{sp: spID, spG: spG, ctx: ctx, rd: rd, errs: map[v1.VerificationCheck]error{}}
	res := &Result{Identity: &v1.EntraObservedIdentity{
		AppId: guid(appID), ServicePrincipalId: guid(spID), ApplicationObjectId: guid(appObj)}}

	b.permissions(in)
	b.roles()
	now := time.Now
	if in.Now != nil {
		now = in.Now
	}
	b.credentials(sp, app, spID, appObj, in.HeldThumbprint, now())
	b.owners(appG, appObj, spG, spID)

	res.Findings = b.out
	sort.SliceStable(res.Findings, func(i, j int) bool {
		a, c := res.Findings[i], res.Findings[j]
		if a.Check != c.Check {
			return a.Check < c.Check
		}
		if a.Code != c.Code {
			return a.Code < c.Code
		}
		return a.Qualifier < c.Qualifier
	})
	res.finish(b.errs)
	return res, nil
}

type builder struct {
	ctx  context.Context
	rd   EntraReader
	sp   []byte
	spG  dguid.GUID
	out  []Finding
	errs map[v1.VerificationCheck]error
}

const (
	ev3 = v1.VerificationCheck_VERIFICATION_CHECK_EV3_OVER_PRIVILEGE
	ev4 = v1.VerificationCheck_VERIFICATION_CHECK_EV4_SUFFICIENCY
	ev5 = v1.VerificationCheck_VERIFICATION_CHECK_EV5_EXCESS
)

func (b *builder) fail(c v1.VerificationCheck, err error) {
	if b.errs[c] == nil {
		b.errs[c] = err
	}
}

func (b *builder) add(check v1.VerificationCheck, kind v1.FindingKind, sev v1.FindingSeverity, code string, object []byte,
	right *v1.EntraRight, source *v1.RightSource, family v1.RightsFamily, qualifier string) {
	f := &v1.RightsFinding{Check: check, Kind: kind, Severity: sev, Code: code, Family: family, Source: source}
	if object != nil {
		f.Object = guid(object)
	}
	if right != nil {
		f.Right = &v1.RightRef{Right: &v1.RightRef_Entra{Entra: right}}
	}
	b.out = append(b.out, Finding{RightsFinding: f, Qualifier: qualifier})
}

func assignment(id string) *v1.RightSource {
	g, err := guidBytes(id)
	if err != nil {
		return nil
	}
	return &v1.RightSource{Source: &v1.RightSource_EntraAssignment{EntraAssignment: guid(g)}}
}

// heldPerm is one application permission granted to the app, resolved to its name.
type heldPerm struct {
	value, assignmentID, roleID, resourceAppID string
}

func (b *builder) permissions(in EntraInput) {
	assigns, err := b.rd.AppRoleAssignments(b.ctx, b.spG)
	if err != nil {
		b.fail(ev3, err)
		b.fail(ev4, err)
		b.fail(ev5, err)
		b.unverified(ev3)
		return
	}
	// Resolve each resource once. A grant that cannot be named cannot be classified: it might be on
	// the deny list, so the check cannot pass (FR-11).
	resources := map[string]*graph.ServicePrincipal{}
	var held []heldPerm
	unresolved := false
	for _, a := range assigns {
		res, ok := resources[a.ResourceID]
		if !ok {
			rid, err := dguid.Parse(a.ResourceID)
			var r graph.ServicePrincipal
			if err == nil {
				r, err = b.rd.ServicePrincipalByID(b.ctx, rid)
			}
			if err != nil {
				b.fail(ev3, err)
				res = nil
			} else {
				res = &r
			}
			resources[a.ResourceID] = res
		}
		var role *graph.AppRole
		if res != nil {
			for i := range res.AppRoles {
				if strings.EqualFold(res.AppRoles[i].ID, a.AppRoleID) {
					role = &res.AppRoles[i]
				}
			}
		}
		if role == nil || role.Value == "" {
			unresolved = true
			b.add(ev3, v1.FindingKind_FINDING_KIND_COULD_NOT_VERIFY, v1.FindingSeverity_FINDING_SEVERITY_BLOCK, CodeUnverified,
				b.sp, nil, assignment(a.ID), 0, a.ID)
			continue
		}
		held = append(held, heldPerm{value: role.Value, assignmentID: a.ID, roleID: a.AppRoleID, resourceAppID: res.AppID})
	}
	if unresolved {
		b.fail(ev3, errors.New("an app role assignment could not be resolved to a permission"))
	}

	enabled := map[v1.RightsFamily]bool{}
	for _, f := range baselineFamilies {
		enabled[f] = true
	}
	for _, f := range in.EnabledFamilies {
		enabled[f] = true
	}
	allowed := map[string]bool{}
	var rows []Row
	for _, r := range allowRows {
		if enabled[r.Family] {
			rows = append(rows, r)
			for _, n := range r.Needs {
				for _, p := range n.Any {
					allowed[strings.ToLower(p)] = true
				}
			}
		}
	}

	grantedGraph := map[string]bool{}
	for _, h := range held {
		right := &v1.EntraRight{Right: &v1.EntraRight_AppPermission{AppPermission: &v1.EntraAppPermission{
			AppRoleId: guidOrNil(h.roleID), Value: h.value, ResourceAppId: guidOrNil(h.resourceAppID)}}}
		onGraph := strings.EqualFold(h.resourceAppID, GraphResourceAppID)
		if onGraph {
			grantedGraph[strings.ToLower(h.value)] = true
		}
		switch {
		case DenyListed(h.value):
			b.add(ev3, v1.FindingKind_FINDING_KIND_ENTRA_DENY_LIST_PERMISSION, v1.FindingSeverity_FINDING_SEVERITY_BLOCK,
				CodeDenyList, b.sp, right, assignment(h.assignmentID), 0, strings.ToLower(h.roleID))
		case !onGraph || !allowed[strings.ToLower(h.value)]:
			b.add(ev5, v1.FindingKind_FINDING_KIND_EXCESSIVE_RIGHT, v1.FindingSeverity_FINDING_SEVERITY_WARN,
				CodeExtraPerm, b.sp, right, assignment(h.assignmentID), 0, strings.ToLower(h.roleID))
		}
	}

	reported := map[string]bool{}
	for _, r := range rows {
		for _, n := range r.Needs {
			met := false
			for _, p := range n.Any {
				if grantedGraph[strings.ToLower(p)] {
					met = true
					break
				}
			}
			if met {
				continue
			}
			want := n.Any[0]
			key := fmt.Sprintf("%d|%s", r.Family, strings.ToLower(want))
			if reported[key] {
				continue
			}
			reported[key] = true
			sev := v1.FindingSeverity_FINDING_SEVERITY_WARN
			if r.MissingBlocks {
				sev = v1.FindingSeverity_FINDING_SEVERITY_BLOCK
			}
			// The resource's role id for the expected permission is unknown to us without a
			// lookup; the value is the stable identifier of the missing permission.
			right := &v1.EntraRight{Right: &v1.EntraRight_AppPermission{AppPermission: &v1.EntraAppPermission{
				Value: want, ResourceAppId: guidOrNil(GraphResourceAppID)}}}
			b.add(ev4, v1.FindingKind_FINDING_KIND_MISSING_RIGHT, sev, CodeMissingPerm, b.sp, right,
				&v1.RightSource{Source: &v1.RightSource_ExpectedBy{ExpectedBy: r.Family}}, r.Family, strings.ToLower(want))
		}
	}
}

func (b *builder) unverified(c v1.VerificationCheck) {
	b.add(c, v1.FindingKind_FINDING_KIND_COULD_NOT_VERIFY, v1.FindingSeverity_FINDING_SEVERITY_BLOCK, CodeUnverified, b.sp, nil, nil, 0, "")
}

func (b *builder) roles() {
	// A role held through a role-assignable group passes to its members, so the service principal's
	// own assignments are read together with those of every group it belongs to. Whether a service
	// principal member actually receives the role is [UNVERIFIED — lab G6]: conservative reading.
	holders := []struct {
		id    dguid.GUID
		group string
	}{{b.spG, ""}}
	groups, err := b.rd.ServicePrincipalGroups(b.ctx, b.spG)
	if err != nil {
		// Continue with the direct read so a direct role is still named, but never pass.
		b.fail(ev3, err)
		b.unverified(ev3)
	}
	for _, g := range groups {
		if g.IsAssignableToRole {
			gid, perr := dguid.Parse(g.ID)
			if perr != nil { // a group that cannot be named cannot be read: never pass
				b.fail(ev3, perr)
				b.unverified(ev3)
				continue
			}
			holders = append(holders, struct {
				id    dguid.GUID
				group string
			}{gid, g.ID})
		}
	}
	for _, h := range holders {
		roles, err := b.rd.DirectoryRoleAssignments(b.ctx, h.id)
		if err != nil {
			b.fail(ev3, err)
			b.unverified(ev3)
			continue
		}
		for _, r := range roles {
			kind := v1.EntraRoleAssignmentKind_ENTRA_ROLE_ASSIGNMENT_KIND_ACTIVE
			if r.Eligible {
				kind = v1.EntraRoleAssignmentKind_ENTRA_ROLE_ASSIGNMENT_KIND_ELIGIBLE
			}
			defID := r.RoleDefinitionID
			if defID == "" {
				defID = r.Role.ID
			}
			right := &v1.EntraRight{Right: &v1.EntraRight_DirectoryRole{DirectoryRole: &v1.EntraDirectoryRole{
				RoleDefinitionId: guidOrNil(defID), Assignment: kind, DirectoryScopeId: r.DirectoryScopeID}}}
			q := strings.ToLower(defID)
			if h.group != "" {
				// The group is part of the qualifier so the same role through two groups, or both
				// directly and through a group, are distinct findings.
				q += "@" + strings.ToLower(h.group)
			}
			b.add(ev3, v1.FindingKind_FINDING_KIND_ENTRA_DIRECTORY_ROLE, v1.FindingSeverity_FINDING_SEVERITY_BLOCK,
				CodeRole, b.sp, right, assignment(r.ID), 0, q)
		}
	}
}

func (b *builder) credentials(sp graph.ServicePrincipal, app graph.Application, spID, appObj, held []byte, now time.Time) {
	for _, h := range []struct {
		holder v1.EntraCredentialHolder
		object []byte
		keys   []graph.KeyCredential
		pwds   []graph.PasswordCredential
	}{
		{v1.EntraCredentialHolder_ENTRA_CREDENTIAL_HOLDER_APPLICATION, appObj, app.KeyCredentials, app.PasswordCredentials},
		{v1.EntraCredentialHolder_ENTRA_CREDENTIAL_HOLDER_SERVICE_PRINCIPAL, spID, sp.KeyCredentials, sp.PasswordCredentials},
	} {
		exempted := false
		for _, k := range h.keys {
			// The held certificate is the one credential allowed, once, and only on the
			// application. The same certificate on the service principal is still extra. Identity is
			// the hash of the public certificate itself: a key without certificate bytes, or whose
			// customKeyIdentifier merely claims our thumbprint, is extra.
			sum := sha1.Sum(k.Key) //nolint:gosec
			thumb := k.CustomKeyIdentifier
			if len(k.Key) > 0 {
				thumb = sum[:]
			}
			if h.holder == v1.EntraCredentialHolder_ENTRA_CREDENTIAL_HOLDER_APPLICATION && !exempted &&
				len(held) > 0 && len(k.Key) > 0 && bytes.Equal(sum[:], held) {
				exempted = true
				continue
			}
			right := &v1.EntraRight{Right: &v1.EntraRight_KeyCredential{KeyCredential: &v1.EntraKeyCredential{
				KeyId: guidOrNil(k.KeyID), Thumbprint: thumb, KeyType: k.Type,
				Start: ts(k.StartDateTime), End: ts(k.EndDateTime), Holder: h.holder}}}
			b.add(ev5, v1.FindingKind_FINDING_KIND_ENTRA_EXTRA_KEY_CREDENTIAL, v1.FindingSeverity_FINDING_SEVERITY_WARN,
				CodeExtraKey, h.object, right, nil, 0, strings.ToLower(k.KeyID))
		}
		for _, p := range h.pwds {
			right := &v1.EntraRight{Right: &v1.EntraRight_PasswordCredential{PasswordCredential: &v1.EntraPasswordCredential{
				KeyId: guidOrNil(p.KeyID), Start: ts(p.StartDateTime), End: ts(p.EndDateTime), Holder: h.holder}}}
			// Contract v1.2 (CC-VER-13): a secret with no end, or one ending after the clock
			// (whether or not it has started), is a spare bearer credential: EV3 block. An expired
			// one is only a warning, with a distinct check and so a distinct fingerprint.
			if p.EndDateTime.IsZero() || p.EndDateTime.After(now) {
				b.add(ev3, v1.FindingKind_FINDING_KIND_ENTRA_PASSWORD_CREDENTIAL, v1.FindingSeverity_FINDING_SEVERITY_BLOCK,
					CodeSecret, h.object, right, nil, 0, strings.ToLower(p.KeyID))
				continue
			}
			b.add(ev5, v1.FindingKind_FINDING_KIND_ENTRA_PASSWORD_CREDENTIAL, v1.FindingSeverity_FINDING_SEVERITY_WARN,
				CodeSecret, h.object, right, nil, 0, strings.ToLower(p.KeyID))
		}
	}
}

func (b *builder) owners(appG dguid.GUID, appObj []byte, spG dguid.GUID, spID []byte) {
	for _, o := range []struct {
		object []byte
		list   func(context.Context, dguid.GUID) ([]graph.DirectoryObject, error)
		id     dguid.GUID
	}{{appObj, b.rd.ApplicationOwners, appG}, {spID, b.rd.ServicePrincipalOwners, spG}} {
		owners, err := o.list(b.ctx, o.id)
		if err != nil {
			b.fail(ev5, err)
			continue
		}
		for _, ow := range owners {
			g := guidOrNil(ow.ID)
			right := &v1.EntraRight{Right: &v1.EntraRight_Owner{Owner: g}}
			b.add(ev5, v1.FindingKind_FINDING_KIND_ENTRA_OWNER, v1.FindingSeverity_FINDING_SEVERITY_WARN,
				CodeOwner, o.object, right, nil, 0, strings.ToLower(ow.ID))
		}
	}
}

// finish derives the check outcomes and the verdict (DM-24.I2 order: could-not-verify, then refused).
func (r *Result) finish(errs map[v1.VerificationCheck]error) {
	has := func(c v1.VerificationCheck, sev v1.FindingSeverity) bool {
		for _, f := range r.Findings {
			if f.Check == c && f.Severity == sev {
				return true
			}
		}
		return false
	}
	block, warn := v1.FindingSeverity_FINDING_SEVERITY_BLOCK, v1.FindingSeverity_FINDING_SEVERITY_WARN
	cnv := false
	for _, c := range []v1.VerificationCheck{ev3, ev4, ev5} {
		cr := &v1.CheckResult{Check: c, Outcome: v1.CheckOutcome_CHECK_OUTCOME_PASS}
		if e := errs[c]; e != nil {
			cr.Error = connectorError(e)
		}
		switch {
		case errs[c] != nil && c != ev5:
			// EV3 and EV4 are the blocking checks: an unanswered question never passes.
			cr.Outcome = v1.CheckOutcome_CHECK_OUTCOME_COULD_NOT_VERIFY
			cnv = true
		case has(c, block):
			cr.Outcome = v1.CheckOutcome_CHECK_OUTCOME_FAIL
		case has(c, warn) || errs[c] != nil:
			cr.Outcome = v1.CheckOutcome_CHECK_OUTCOME_WARN
		}
		r.Checks = append(r.Checks, cr)
	}
	refused := r.Checks[0].Outcome == v1.CheckOutcome_CHECK_OUTCOME_FAIL || r.Checks[1].Outcome == v1.CheckOutcome_CHECK_OUTCOME_FAIL
	switch {
	case cnv:
		r.Verdict = v1.VerificationVerdict_VERIFICATION_VERDICT_COULD_NOT_VERIFY
	case refused:
		r.Verdict = v1.VerificationVerdict_VERIFICATION_VERDICT_REFUSED
	default:
		r.Verdict = v1.VerificationVerdict_VERIFICATION_VERDICT_PASS
	}
	r.WriteGateOpenable = r.Verdict == v1.VerificationVerdict_VERIFICATION_VERDICT_PASS
}

func guid(b []byte) *v1.Guid { return &v1.Guid{Value: b} }

func guidOrNil(text string) *v1.Guid {
	b, err := guidBytes(text)
	if err != nil {
		return nil
	}
	return guid(b)
}

// guidBytes decodes the dashed text form into the 16 bytes in RFC 4122 network order, which is how
// v1.Guid carries an Entra object id (not the AD mixed-endian layout).
func guidBytes(text string) ([]byte, error) {
	if len(text) != 36 || text[8] != '-' || text[13] != '-' || text[18] != '-' || text[23] != '-' {
		return nil, errors.New("not a GUID")
	}
	b, err := hex.DecodeString(text[:8] + text[9:13] + text[14:18] + text[19:23] + text[24:])
	if err != nil || len(b) != 16 {
		return nil, errors.New("not a GUID")
	}
	return b, nil
}

func ts(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

// connectorError maps a failed read to the contract's error. Only the graph error code and the HTTP
// status are carried; response bodies and messages from Graph never are.
func connectorError(err error) *v1.ConnectorError {
	ce := &v1.ConnectorError{Code: v1.ErrorCode_ERROR_CODE_PROVIDER_FAILURE, Retry: v1.RetryAdvice_RETRY_ADVICE_SAME_DC_AFTER_BACKOFF,
		Message: "an Entra read for this check failed"}
	var ge *graph.Error
	if errors.As(err, &ge) {
		switch ge.Code {
		case graph.CodeInsufficient:
			ce.Code, ce.Retry = v1.ErrorCode_ERROR_CODE_INSUFFICIENT_RIGHTS, v1.RetryAdvice_RETRY_ADVICE_AFTER_OPERATOR_ACTION
		case graph.CodeNotFound:
			ce.Code, ce.Retry = v1.ErrorCode_ERROR_CODE_OBJECT_NOT_FOUND, v1.RetryAdvice_RETRY_ADVICE_NEVER
		case graph.CodeThrottled:
			ce.Code = v1.ErrorCode_ERROR_CODE_THROTTLED
		case graph.CodeUnreachable:
			ce.Code = v1.ErrorCode_ERROR_CODE_UNREACHABLE_DC
		case graph.CodeBindFailed:
			ce.Code, ce.Retry = v1.ErrorCode_ERROR_CODE_BIND_FAILED, v1.RetryAdvice_RETRY_ADVICE_AFTER_OPERATOR_ACTION
		case graph.CodeTransportSec:
			ce.Code, ce.Retry = v1.ErrorCode_ERROR_CODE_TRANSPORT_SECURITY, v1.RetryAdvice_RETRY_ADVICE_AFTER_OPERATOR_ACTION
		}
		if ge.HTTPStatus != 0 {
			st := int32(ge.HTTPStatus) //nolint:gosec // HTTP status fits in int32
			ce.ProviderResultCode = &st
		}
	}
	return ce
}
