package write

import (
	"context"
	"errors"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/write/ops"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/sd"
)

// SDSession is what ApplyDACL needs from a directory session; *ad.Session is the implementation.
type SDSession interface {
	DCIdentity(ctx context.Context) (ad.DCIdentity, error)
	WriteDACL(ctx context.Context, ref dn.ObjectRef, w sd.DACLWrite, send ad.ReplaceSDFunc) error
}

// ApplyDACL is the operation body for a DACL write (T-0743). Before the session is read or written it
// requires that the guard's token covers exactly this write: the object the plan was made for is the
// token's target (the one the guard classified against Tier-0), and the session is bound to the DC
// the guard re-read it on. The session then re-reads the base from its bound DC, runs VerifyBase and
// sends nothing on a stale base.
func ApplyDACL(ctx context.Context, a Authorised, s SDSession, ref dn.ObjectRef, w sd.DACLWrite) error {
	if !a.Valid() {
		return errors.New("write: DACL write not authorised by the guard")
	}
	if !w.Valid() {
		return errors.New("write: DACL write not from a planner")
	}
	ev := a.Evaluated()
	if len(ev) == 0 || ev[0] != w.ObjectGUID() {
		return errors.New("write: DACL write targets an object the guard did not evaluate")
	}
	if a.DC() == (guid.GUID{}) {
		return errors.New("write: guard token is not bound to a DC")
	}
	id, err := s.DCIdentity(ctx)
	if err != nil {
		return err
	}
	if id.DSAGUID != a.DC() {
		return errors.New("write: session is not bound to the DC the guard evaluated on")
	}
	return s.WriteDACL(ctx, ref, w, ops.ReplaceSD)
}
