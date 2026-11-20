package helpdesk

import (
	"context"
	"errors"

	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Factor is how a caller is verified (DM-38). Only the one-time-code factors are issued here; totp is
// reserved for the enrolment ticket and refused by Issue until its verifier port exists.
type Factor string

// Factors.
const (
	FactorEmailOTP Factor = "email_otp"
	FactorSMSOTP   Factor = "sms_otp"
)

func (f Factor) valid() bool { return f == FactorEmailOTP || f == FactorSMSOTP }

// Target names the caller being verified: a directory object by connection and objectGUID, never a DN.
type Target struct {
	ConnectionID string // canonical lower-case UUID
	ObjectGUID   string // canonical lower-case UUID
}

// Destination is where a code goes. Address is read live from AD or HR by the Destinations port and is
// never supplied by a technician (DM-38.I1). Masked is the only form the technician sees (4.14).
type Destination struct {
	Address string
	Masked  string
}

// Destinations resolves the held destination for a factor. A target that is unknown, disabled, out of scope,
// a protected account, without a destination, or whose attribute changed in the last 24 hours (4.13) is
// ErrNoDestination: the caller cannot tell which, so enumeration learns nothing (4.18).
type Destinations interface {
	Resolve(ctx context.Context, t tenant.ID, target Target, f Factor) (Destination, error)
	// Offered lists the factors available for the target, SMS only when a gateway is configured (4.12).
	Offered(ctx context.Context, t tenant.ID, target Target) ([]Factor, error)
}

// Authorizer decides whether a technician may verify callers on the target (reset permission scoped by
// OU, P8) and reports the technician's own directory object, if any, so a technician cannot verify
// themselves (4.15). A deny is ErrNotAuthorised.
type Authorizer interface {
	MayVerify(ctx context.Context, t tenant.ID, technician string, target Target) (self *Target, err error)
}

// Sender delivers a message. The text is fixed by this package (C6); an error is a transport rejection (4.17).
type Sender interface {
	Send(ctx context.Context, t tenant.ID, f Factor, to Destination, m Message) error
}

// MACKey gives the tenant-derived key that keys the code MAC (DM-38.I2, 4.10).
type MACKey interface {
	Key(ctx context.Context, t tenant.ID) ([]byte, error)
}

// Errors. Verify and Authorise answer every failure with ErrRefused, whatever the cause, so a caller
// learns neither that the cap nor the code was wrong (acceptance 3).
var (
	ErrInvalid       = errors.New("helpdesk: invalid request")
	ErrRefused       = errors.New("helpdesk: caller verification refused")
	ErrNoDestination = errors.New("helpdesk: cannot verify this caller")
	ErrNotAuthorised = errors.New("helpdesk: technician is not authorised for this target")
	ErrQuota         = errors.New("helpdesk: verification limit reached for this target")
	ErrPaused        = errors.New("helpdesk: technician's verification is paused")
	ErrDelivery      = errors.New("helpdesk: the code could not be delivered")
)
