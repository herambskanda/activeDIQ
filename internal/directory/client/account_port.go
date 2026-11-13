package client

import (
	"context"

	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
)

// AccountState is what one live read of an account shows, on the pinned DC, of the attributes the
// four account kinds (accountkind) change. Values are the raw directory text so that an exact restore
// can be proved; nothing here is a secret.
type AccountState struct {
	Exists bool
	// Class is the live object class label ("user", "computer"), read from objectClass.
	Class string
	// Tier0 is the connector's Tier-0 verdict for the object, read on the same DC.
	Tier0 bool
	// UserAccountControl is the stored userAccountControl as decimal text.
	UserAccountControl string
	// LockoutTime is the stored lockoutTime as decimal text; "0" or "" means not locked.
	LockoutTime string
	// PwdLastSet is the stored pwdLastSet as decimal text; "0" means the user must change the
	// password at next logon.
	PwdLastSet string
}

// AccountReader reads an account's state live on the operation's pins (rule 5). It has the shape of
// Reads: the connector adapter lives here, the consumer is the ad module. A read error is an error,
// never a zero state.
type AccountReader interface {
	Account(ctx context.Context, pins authority.Pins, target authority.TargetRef) (AccountState, error)
}

// AccountWriter is the write half the ad module uses: *Client implements it.
type AccountWriter interface {
	Write(ctx context.Context, s step.Step, op WriteOp) (Result, error)
}

var _ AccountWriter = (*Client)(nil)
