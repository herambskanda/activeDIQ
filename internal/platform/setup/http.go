package setup

import (
	"context"
	"errors"
	"log/slog"
	"net/mail"
	"strings"
	"unicode"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
	"github.com/skenzeriq/activediq/internal/platform/setup/api"
)

// OwnerDetails is what the claimant supplies about the first tenant owner.
type OwnerDetails struct{ DisplayName, Email string }

// ErrOwnerExists: the install already has a tenant owner, so a claim cannot create the first one. The
// requester sees the uniform refusal.
var ErrOwnerExists = errors.New("setup: the install already has a tenant owner")

// Valid reports whether the details are acceptable. It depends on nothing but the details, and the
// handler checks it before the secret, so a 400 never reveals whether the secret was right.
func (o OwnerDetails) Valid() bool {
	if strings.TrimSpace(o.DisplayName) == "" || len(o.DisplayName) > 200 || len(o.Email) > 320 {
		return false
	}
	for _, r := range o.DisplayName + o.Email {
		if unicode.IsControl(r) {
			return false
		}
	}
	a, err := mail.ParseAddress(o.Email)
	return err == nil && a.Name == "" && a.Address == o.Email
}

// OwnerCreator creates the first tenant owner of the install and audits the claim and the creation, all
// in one database transaction (so either both the account and its audit exist, or neither). sourceIP is
// the requester's address for the audit event. It is implemented by compose/server over the account and
// owner-assignment stores, which setup does not import.
type OwnerCreator interface {
	CreateFirstOwner(ctx context.Context, owner OwnerDetails, sourceIP string) error
}

// Handlers implements the generated Handlers of the platform.setup tag over a Store.
type Handlers struct {
	Store  *Store
	Owners OwnerCreator
	Log    *slog.Logger // nil means slog.Default
}

var _ api.Handlers = Handlers{}

// Bind returns the tag's routes for apihost.Build.
func (h Handlers) Bind() apihost.TagHandlers { return api.Bind(h) }

func (h Handlers) refuse(ctx context.Context) error {
	l := h.Log
	if l == nil {
		l = slog.Default()
	}
	// The auth-failure record: the source and the trace, never the presented secret.
	l.WarnContext(ctx, "setup: claim refused", "event", "auth_failure", "class", "setup_claim",
		"source_ip", apihost.SourceIPFrom(ctx), "trace_id", apihost.TraceID(ctx))
	return apitypes.SetupRefused("")
}

// ClaimFirstRunSetup consumes the setup secret and creates the first tenant owner as one step: the
// secret is reserved, the owner and the audit commit in one transaction, and only then is the secret
// finally consumed; if the owner cannot be created the reservation is given back. Every refusal is the
// same 401; the secret never reaches a log or a response. Refusals write no per-attempt audit row (the
// auth-class limiter and the log carry them).
func (h Handlers) ClaimFirstRunSetup(ctx context.Context, in api.ClaimFirstRunSetupInput) (api.ClaimFirstRunSetupOutput, error) {
	owner := OwnerDetails{DisplayName: in.Body.Owner.DisplayName, Email: in.Body.Owner.Email}
	if !owner.Valid() {
		return nil, apitypes.MalformedRequest("the owner details are not acceptable")
	}
	var presented string
	in.Body.Secret.Expose(func(b []byte) { presented = string(b) })
	res, err := h.Store.Reserve(presented)
	switch {
	case err == nil:
	case errors.Is(err, ErrRefused):
		return nil, h.refuse(ctx)
	default:
		return nil, err // an infrastructure fault: the chain answers 500 without detail
	}
	err = h.Owners.CreateFirstOwner(ctx, owner, apihost.SourceIPFrom(ctx))
	if err != nil {
		if aerr := res.Abort(); aerr != nil {
			// The reservation stays: the install is closed to everyone until an administrator resets it.
			slog.ErrorContext(ctx, "setup: could not release a failed claim", "error", aerr)
		}
		if errors.Is(err, ErrOwnerExists) {
			return nil, h.refuse(ctx)
		}
		return nil, err
	}
	if err := res.Done(); err != nil {
		// The owner exists and the reservation file blocks every other claim; say so for the operator.
		slog.ErrorContext(ctx, "setup: owner created but the claim could not be finalised", "error", err)
		return nil, err
	}
	return api.ClaimFirstRunSetup204{}, nil
}
