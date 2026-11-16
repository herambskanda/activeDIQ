package helpdesk

import (
	"crypto/rand"
	"encoding/json/v2"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// stepUpActions are the Actions a verified caller may stand in for (TM-D16, ENH-09 §4.15): the account-state
// Actions whose StepUp the caller, not the technician, answers. Anything else needs the technician's own MFA.
// The IDs are the ad module's; this package cannot import a sibling module (ADR-0003 rule 2).
var stepUpActions = map[string]bool{
	"ad.user.resetPassword": true,
	"ad.user.unlock":        true,
}

// Grant is a spent, verified challenge. Only Authorise builds one, so holding a Grant is the proof that a
// caller was verified for this technician, target, Action and operation.
type Grant struct {
	tenant     tenant.ID
	technician string
	target     Target
	action     string
	operation  step.OperationID
	factor     Factor
	challenge  string
}

// Factor is the factor that verified the caller, for the audit trail.
func (g Grant) Factor() Factor { return g.factor }

// ChallengeID names the challenge the Grant came from.
func (g Grant) ChallengeID() string { return g.challenge }

// Bind returns req with its step-up satisfied by the verified caller. It refuses a request that is not the
// exact one the challenge was spent on: another tenant, requester, Action, operation or target.
func (g Grant) Bind(req operation.Request) (operation.Request, error) {
	if g.challenge == "" {
		return req, ErrRefused
	}
	if req.Tenant != g.tenant || string(req.Actor.Requester.ID) != g.technician || string(req.Action) != g.action || req.Operation != g.operation {
		return req, ErrRefused
	}
	var in struct {
		ConnectionID string `json:"connectionId"`
		ObjectGUID   string `json:"objectGuid"`
	}
	if err := json.Unmarshal(req.Input, &in, json.RejectUnknownMembers(false)); err != nil ||
		lower(in.ConnectionID) != g.target.ConnectionID || lower(in.ObjectGUID) != g.target.ObjectGUID {
		return req, ErrRefused
	}
	req.FreshStepUp = true
	return req, nil
}

var uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func validUUID(s string) bool { return uuidRe.MatchString(s) }
func lower(s string) string   { return strings.ToLower(s) }
func itoa(n int) string       { return strconv.Itoa(n) }

func contains(fs []Factor, f Factor) bool {
	for _, x := range fs {
		if x == f {
			return true
		}
	}
	return false
}

func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("helpdesk: no entropy: %w", err)
	}
	b[6], b[8] = b[6]&0x0f|0x40, b[8]&0x3f|0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}
