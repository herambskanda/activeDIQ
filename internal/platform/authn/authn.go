// Package authn serves the sign-in plane operations of the console: the break-glass password step
// (AN-8), the second factor (AN-10), sign-out and the CSRF value. Until the build tickets land every
// handler answers 501 /problems/not-implemented, so the contract, the policy rows and the route set are
// real while no behaviour is faked (threat model section 7.6).
package authn

import (
	"context"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
	"github.com/skenzeriq/activediq/internal/platform/authn/api"
)

// Handlers implements api.Handlers with 501 stubs.
type Handlers struct{}

var _ api.Handlers = Handlers{}

// API returns the tag's routes for compose/server to mount.
func API() apihost.TagHandlers { return api.Bind(Handlers{}) }

func (Handlers) SignInBreakGlassPassword(context.Context, api.SignInBreakGlassPasswordInput) (api.SignInBreakGlassPasswordOutput, error) {
	return nil, apitypes.NotImplemented("")
}

func (Handlers) CreateWebAuthnSignInChallenge(context.Context, api.CreateWebAuthnSignInChallengeInput) (api.CreateWebAuthnSignInChallengeOutput, error) {
	return nil, apitypes.NotImplemented("")
}

func (Handlers) VerifyWebAuthnSignIn(context.Context, api.VerifyWebAuthnSignInInput) (api.VerifyWebAuthnSignInOutput, error) {
	return nil, apitypes.NotImplemented("")
}

func (Handlers) VerifyTOTPSignIn(context.Context, api.VerifyTOTPSignInInput) (api.VerifyTOTPSignInOutput, error) {
	return nil, apitypes.NotImplemented("")
}

func (Handlers) SignOut(context.Context, api.SignOutInput) (api.SignOutOutput, error) {
	return nil, apitypes.NotImplemented("")
}

func (Handlers) GetCSRFToken(context.Context, api.GetCSRFTokenInput) (api.GetCSRFTokenOutput, error) {
	return nil, apitypes.NotImplemented("")
}
