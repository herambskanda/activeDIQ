package ad

import (
	"context"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/sd"
)

// ReadPasswordChange reads one object's DACL (DACL-only critical SD_FLAGS control, never the SACL; a
// response carrying one is refused) and classifies the Cannot Change Password state with the sd
// primitive (reports-2-second-slice §4.2 rule 1). It returns the objectGUID the state belongs to, so
// the inventory sync keys the stored value by GUID, never by DN.
//
// The state is sd.PasswordChangeNotConfirmed exactly when err != nil: an unreadable, withheld or
// malformed descriptor yields a typed error (CodeProtocol for a missing attribute or a SACL, the sd
// package's stable codes for malformed bytes, CodeInsufficientRights/CodeObjectNotFound from the DC)
// and no partial value. The caller records "Not confirmed" for any error and moves on to the next
// object; one unreadable user must not stop a sync.
//
// This is a per-object base read on purpose: nTSecurityDescriptor is Read-only in the schema
// allowlist (constructedReadOnly), so no paged search can carry it.
func (s *Session) ReadPasswordChange(ctx context.Context, ref dn.ObjectRef) (guid.GUID, sd.PasswordChange, error) {
	g, d, err := s.ReadDACL(ctx, ref)
	if err != nil {
		return guid.GUID{}, sd.PasswordChangeNotConfirmed, err
	}
	state, err := d.PasswordChange()
	if err != nil {
		return guid.GUID{}, sd.PasswordChangeNotConfirmed, err
	}
	return g, state, nil
}
