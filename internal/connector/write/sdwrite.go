package write

import (
	"context"
	"errors"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/write/ops"
	"github.com/skenzeriq/activediq/internal/directory/attr/codec"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/sd"
)

// SDSession is what ApplyDACL needs from a directory session; *ad.Session is the implementation.
type SDSession interface {
	DCIdentity(ctx context.Context) (ad.DCIdentity, error)
	WriteDACL(ctx context.Context, ref dn.ObjectRef, w sd.DACLWrite, send ad.ReplaceSDFunc) error
	ReadDACL(ctx context.Context, ref dn.ObjectRef) (guid.GUID, sd.SD, error)
}

// DACLDiverged is the audit record of sd.write_diverged (SD-R10): the DC accepted the Modify but the
// DACL it now stores is not the planned one. It carries the actual state as digests and counts, never
// ACE bytes or SDDL.
type DACLDiverged struct {
	Object        guid.GUID
	DC            guid.GUID
	PlannedBase   sd.Digest // digest of the DACL the plan was made on
	Actual        sd.Digest // digest of the DACL read back from the same DC
	ActualACEs    int
	ActualProtect bool
}

// DACLAuditor receives the audit records of a DACL write. It must not block for long.
type DACLAuditor interface {
	WriteDiverged(DACLDiverged)
}

// ErrReadBack is returned when the Modify succeeded but the read-back failed: the stored state is
// unknown and the caller must re-read before doing anything else. No retry is made.
var ErrReadBack = errors.New("write: DACL modify sent but the read-back failed; stored state unknown")

// ApplyDACL is the operation body for a DACL write (T-0743). Before the session is read or written it
// requires that the guard's token covers exactly this write: the object the plan was made for is the
// token's target (the one the guard classified against Tier-0), and the session is bound to the DC
// the guard re-read it on. The session then re-reads the base from its bound DC, runs VerifyBase and
// sends nothing on a stale base.
func ApplyDACL(ctx context.Context, a Authorised, s SDSession, audit DACLAuditor, ref dn.ObjectRef, w sd.DACLWrite) error {
	if !a.Valid() {
		return errors.New("write: DACL write not authorised by the guard")
	}
	if !w.Valid() {
		return errors.New("write: DACL write not from a planner")
	}
	if !a.DeclaresProperty("nTSecurityDescriptor") {
		return errors.New("write: token was not issued for a kind that declares nTSecurityDescriptor")
	}
	if audit == nil {
		return errors.New("write: DACL write needs an auditor for sd.write_diverged")
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
	if err := s.WriteDACL(ctx, ref, w, ops.ReplaceSD); err != nil {
		return err
	}
	// SD-R10: re-read the DACL-only SD from the same DC (the session is bound to it) and verify. A
	// divergence is audited with the actual state and returned; the write is never retried.
	g, stored, err := s.ReadDACL(ctx, ref)
	if err != nil || g != w.ObjectGUID() {
		return ErrReadBack
	}
	if _, err := w.VerifyAfter(stored); err != nil {
		if codec.Code(err) == sd.ErrWriteDiverged {
			audit.WriteDiverged(DACLDiverged{Object: g, DC: a.DC(), PlannedBase: w.BaseDigest(),
				Actual: sd.DigestDACL(stored), ActualACEs: len(stored.DACL.ACEs), ActualProtect: stored.Control.Protected()})
		}
		return err
	}
	return nil
}
