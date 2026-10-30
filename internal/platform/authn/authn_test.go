package authn

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
	"github.com/skenzeriq/activediq/internal/platform/authn/api"
)

type doc struct {
	Paths map[string]map[string]struct {
		OperationID string                 `json:"operationId"`
		Permission  string                 `json:"x-permission"`
		Anonymous   string                 `json:"x-activediq-anonymous"`
		Limits      struct{ Class string } `json:"x-activediq-limits"`
		Responses   map[string]struct {
			Ref     string                     `json:"$ref"`
			Headers map[string]json.RawMessage `json:"headers"`
			Content map[string]json.RawMessage `json:"content"`
		} `json:"responses"`
	} `json:"paths"`
}

func load(t *testing.T) doc {
	t.Helper()
	b, err := os.ReadFile("../apihost/spec/openapi.gen.json")
	if err != nil {
		t.Fatal(err)
	}
	var d doc
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	return d
}

// AN-8 and AN-10 are anonymous operations of rate class auth (TM section 7.6).
func TestSignInOperationsAreAnonymousRateClassAuth(t *testing.T) {
	d := load(t)
	want := map[string]string{
		"signInBreakGlassPassword":      "AN-8",
		"createWebAuthnSignInChallenge": "AN-10",
		"verifyWebAuthnSignIn":          "AN-10",
		"verifyTotpSignIn":              "AN-10",
	}
	seen := map[string]bool{}
	for _, item := range d.Paths {
		for _, op := range item {
			if row, ok := want[op.OperationID]; ok {
				seen[op.OperationID] = true
				if op.Permission != "anonymous" || op.Anonymous != row || op.Limits.Class != "auth" {
					t.Errorf("%s: permission %q row %q class %q, want anonymous %s auth", op.OperationID, op.Permission, op.Anonymous, op.Limits.Class, row)
				}
			}
		}
	}
	if len(seen) != len(want) {
		t.Fatalf("operations found %v, want %d", seen, len(want))
	}
}

// Acceptance 2: every failure cause of AN-8 shares one 4xx shape. The declared 4xx set is validation
// of the request itself, size and media type, the one sign-in-failed 401, and the source-IP limiter.
// No 403, 404, 409 or 423 can tell a caller which cause applied.
func TestBreakGlassPasswordHasOneFailureShape(t *testing.T) {
	d := load(t)
	op := d.Paths["/auth/break-glass/password"]["post"]
	var codes []string
	for code, r := range op.Responses {
		if strings.HasPrefix(code, "4") {
			codes = append(codes, code+" "+r.Ref)
		}
	}
	sort.Strings(codes)
	want := []string{
		"400 #/components/responses/Validation",
		"401 #/components/responses/SignInFailed",
		"413 #/components/responses/PayloadTooLarge",
		"415 #/components/responses/UnsupportedMediaType",
		"429 #/components/responses/RateLimited",
	}
	if strings.Join(codes, "\n") != strings.Join(want, "\n") {
		t.Fatalf("4xx responses:\n%s\nwant:\n%s", strings.Join(codes, "\n"), strings.Join(want, "\n"))
	}
}

// Acceptance 3: the AN-8 success carries no body and sets only the pending-sign-in cookie.
func TestBreakGlassPasswordSuccessSetsOnlyTheCookie(t *testing.T) {
	d := load(t)
	r := d.Paths["/auth/break-glass/password"]["post"].Responses["204"]
	if len(r.Content) != 0 {
		t.Errorf("204 declares a body: %v", r.Content)
	}
	if len(r.Headers) != 1 || r.Headers["Set-Cookie"] == nil {
		t.Errorf("204 headers = %v, want only Set-Cookie", r.Headers)
	}
	for code, resp := range d.Paths["/auth/break-glass/password"]["post"].Responses {
		if strings.HasPrefix(code, "2") && code != "204" {
			t.Errorf("unexpected success response %s %v", code, resp)
		}
	}
}

func TestSignInFailedProblemIsConstant(t *testing.T) {
	b, err := os.ReadFile("../../../api/openapi/shared/problems.yaml")
	if err != nil {
		t.Fatal(err)
	}
	i := strings.Index(string(b), "    SignInFailed:")
	if i < 0 {
		t.Fatal("no SignInFailed problem")
	}
	block := string(b)[i:]
	if j := strings.Index(block[1:], "\n    Forbidden:"); j > 0 {
		block = block[:j]
	}
	for _, bad := range []string{"detail:", "errors:"} {
		if strings.Contains(block, bad) {
			t.Errorf("SignInFailed example carries %q", bad)
		}
	}
}

// The stubs answer 501 until the build tickets land.
func TestStubsAnswerNotImplemented(t *testing.T) {
	h := Handlers{}
	ctx := context.Background()
	_, e1 := h.SignInBreakGlassPassword(ctx, api.SignInBreakGlassPasswordInput{})
	_, e2 := h.CreateWebAuthnSignInChallenge(ctx, api.CreateWebAuthnSignInChallengeInput{})
	_, e3 := h.VerifyWebAuthnSignIn(ctx, api.VerifyWebAuthnSignInInput{})
	_, e4 := h.VerifyTOTPSignIn(ctx, api.VerifyTOTPSignInInput{}) // unwired: no SecondFactor
	_, e5 := h.SignOut(ctx, api.SignOutInput{})
	_, e6 := h.GetCSRFToken(ctx, api.GetCSRFTokenInput{})
	for i, err := range []error{e1, e2, e3, e4, e5, e6} {
		var p *apitypes.Problem
		if !errors.As(err, &p) || p.Status != 501 || p.Type != apitypes.ProblemTypeNotImplemented || p.Detail != nil {
			t.Errorf("stub %d: %v", i, err)
		}
	}
	if API(Handlers{}).Tag() == "" {
		t.Error("API() has no tag")
	}
}
