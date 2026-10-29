package setup

import (
	"context"
	"errors"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
	"github.com/skenzeriq/activediq/internal/platform/setup/api"
)

// Handlers implements the generated Handlers of the platform.setup tag over a Store.
type Handlers struct{ Store *Store }

var _ api.Handlers = Handlers{}

// Bind returns the tag's routes for apihost.Build.
func (h Handlers) Bind() apihost.TagHandlers { return api.Bind(h) }

// ClaimFirstRunSetup consumes the setup secret. Every refusal is the same 401; the secret never reaches a
// log or a response.
func (h Handlers) ClaimFirstRunSetup(_ context.Context, in api.ClaimFirstRunSetupInput) (api.ClaimFirstRunSetupOutput, error) {
	var presented string
	in.Body.Secret.Expose(func(b []byte) { presented = string(b) })
	err := h.Store.Claim(presented)
	switch {
	case err == nil:
		return api.ClaimFirstRunSetup204{}, nil
	case errors.Is(err, ErrRefused):
		return nil, apitypes.SetupRefused("")
	default:
		return nil, err // an infrastructure fault: the chain answers 500 without detail
	}
}
