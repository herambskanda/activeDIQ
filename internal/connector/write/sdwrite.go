package write

import (
	"context"
	"errors"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/write/ops"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/sd"
)

// ApplyDACL is the operation body for a DACL write (T-0743): it needs the guard's token and hands the
// session the one Modify implementation the fitness function allows. The session re-reads the base
// from its bound DC, runs VerifyBase and sends nothing on a stale base.
func ApplyDACL(ctx context.Context, a Authorised, s *ad.Session, ref dn.ObjectRef, w sd.DACLWrite) error {
	if !a.Valid() {
		return errors.New("write: DACL write not authorised by the guard")
	}
	return s.WriteDACL(ctx, ref, w, ops.ReplaceSD)
}
