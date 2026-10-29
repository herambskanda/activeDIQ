package ad

import (
	"bytes"
	"context"
	"errors"

	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/sd"
)

// WriteDACL is the only write the connector makes to nTSecurityDescriptor (T-0743). Under one hold of
// the session lock, so on the one DC this session is bound to over LDAPS, it:
//
//  1. refuses a DACLWrite that did not come from a planner (the zero value);
//  2. re-reads the object's DACL (DACL-only SD_FLAGS control, never the SACL) and checks it is the object
//     the plan was made for (objectGUID);
//  3. calls DACLWrite.VerifyBase on that fresh read: a different DACL sends nothing and returns
//     sd.stale_base;
//  4. sends one Modify with a single replace of nTSecurityDescriptor and the critical DACL-only SD_FLAGS
//     control the plan carries, no other attribute.
//
// VerifyBase narrows the lost-update window, it does not close it: LDAP has no compare-and-swap. The
// post-write read-back and sd.write_diverged are DACLWrite.VerifyAfter's, called by the caller (T-0726)
// on this same session, so the read is against the same DC.
//
// Errors are the sd package's stable codes (sd.stale_base, sd.not_editable, ...) or *Error. A returned
// error after the Modify was sent leaves the outcome unknown; the caller must re-read before retrying.
func (s *Session) WriteDACL(ctx context.Context, ref dn.ObjectRef, w sd.DACLWrite) error {
	if !w.Valid() {
		return fail(CodeInvalidArgument, "dacl write not from a planner", nil)
	}
	val := w.Value()
	// The control the plan carries must be exactly the DACL-only critical one this package can encode;
	// anything else is refused rather than forwarded.
	want, err := NewSDFlags(SDDACL)
	if err != nil {
		return err
	}
	if c := w.Control(); c.OID != oidSDFlags || !c.Critical || !bytes.Equal(c.Value, []byte{0x30, 0x03, 0x02, 0x01, byte(want.Value())}) {
		return fail(CodeControlNotAllowed, "", nil)
	}
	base, err := ref.ForRequest()
	if err != nil {
		return fail(CodeInvalidArgument, "object reference", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return fail(CodeUnreachable, "session closed", nil)
	}
	stop := s.watch(ctx, s.conn)
	defer stop()

	res, err := s.searchOnceLocked(ctx, base, ldap.ScopeBaseObject, objectClassPresent,
		[]string{"objectGUID", "nTSecurityDescriptor"}, []ldap.Control{want.control()})
	if err != nil {
		return err
	}
	if len(res.Entries) != 1 {
		return fail(CodeObjectNotFound, "", nil)
	}
	ent := newEntry(res.Entries[0].DN)
	absorbEntry(ent, map[string]int{}, map[string]struct{}{"objectguid": {}, "ntsecuritydescriptor": {}}, res.Entries[0])
	g, err := ent.GUID()
	if err != nil {
		return err
	}
	if g != w.ObjectGUID() {
		return fail(CodeInvalidArgument, "object is not the one the plan was made for", nil)
	}
	raw := ent.Raw("nTSecurityDescriptor")
	if len(raw) != 1 || sdHasSACL(raw[0]) {
		return fail(CodeProtocol, "security descriptor missing or has a SACL", nil)
	}
	cur, err := sd.Decode(sd.Raw(raw[0]))
	if err != nil {
		return err
	}
	if err := w.VerifyBase(cur); err != nil {
		return err // sd.stale_base: nothing was sent
	}

	req := ldap.NewModifyRequest(res.Entries[0].DN, []ldap.Control{want.control()})
	req.Replace("nTSecurityDescriptor", []string{string(val)})
	if err := s.conn.Modify(req); err != nil {
		if ctx.Err() != nil {
			return fail(CodeCanceled, "", ctx.Err())
		}
		var le *ldap.Error
		if errors.As(err, &le) {
			switch le.ResultCode {
			case ldap.LDAPResultInsufficientAccessRights:
				return fail(CodeInsufficientRights, "", nil)
			case ldap.LDAPResultNoSuchObject:
				return fail(CodeObjectNotFound, "", nil)
			case ldap.LDAPResultReferral:
				return fail(CodeUnexpectedReferral, "", nil)
			}
			return fail(CodeProtocol, ldapCode(err), nil)
		}
		return fail(CodeUnreachable, ldapCode(err), nil)
	}
	return nil
}
