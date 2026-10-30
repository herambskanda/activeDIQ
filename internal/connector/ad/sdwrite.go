package ad

import (
	"bytes"
	"context"
	"errors"

	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/sd"
)

// Modifier is the one LDAP method a ReplaceSDFunc may use. The session lends its connection for the
// duration of one WriteDACL call only.
type Modifier interface {
	Modify(*ldap.ModifyRequest) error
}

// ReplaceSDFunc sends the single replace of nTSecurityDescriptor with the given controls. The LDAP
// Modify itself lives in internal/connector/write/ops, the only place the write fitness function
// (TM-F-T0GUARD) allows one; this package holds the read, the checks and the error mapping.
type ReplaceSDFunc func(m Modifier, dn string, value []byte, controls []ldap.Control) error

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
// post-write read-back and sd.write_diverged are DACLWrite.VerifyAfter's, called by the caller
// (write.ApplyDACL, T-0726) through ReadDACL on this same session, so the read is against the same DC.
//
// Errors are the sd package's stable codes (sd.stale_base, sd.not_editable, ...) or *Error. A returned
// error after the Modify was sent leaves the outcome unknown; the caller must re-read before retrying.
func (s *Session) WriteDACL(ctx context.Context, ref dn.ObjectRef, w sd.DACLWrite, send ReplaceSDFunc) error {
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

	g, cur, err := s.readDACLLocked(ctx, base, want)
	if err != nil {
		return err
	}
	if g != w.ObjectGUID() {
		return fail(CodeInvalidArgument, "object is not the one the plan was made for", nil)
	}
	if err := w.VerifyBase(cur); err != nil {
		return err // sd.stale_base: nothing was sent
	}

	if send == nil {
		return fail(CodeInvalidArgument, "no sender", nil)
	}
	// The modify is addressed by the GUID that was just checked, not by the DN the read returned, so a
	// rename or replace by another writer between the read and the modify cannot redirect it.
	target, err := dn.GUIDRef(g).ForRequest()
	if err != nil {
		return fail(CodeInvalidArgument, "object reference", err)
	}
	if err := send(s.conn, target, val, []ldap.Control{want.control()}); err != nil {
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

// readDACLLocked reads the object's objectGUID and DACL-only security descriptor (the SD_FLAGS control
// carries no SACL; a response that has one anyway is refused). The caller holds s.mu.
func (s *Session) readDACLLocked(ctx context.Context, base string, want SDFlags) (guid.GUID, sd.SD, error) {
	res, err := s.searchOnceLocked(ctx, base, ldap.ScopeBaseObject, objectClassPresent,
		[]string{"objectGUID", "nTSecurityDescriptor"}, []ldap.Control{want.control()})
	if err != nil {
		return guid.GUID{}, sd.SD{}, err
	}
	if len(res.Entries) != 1 {
		return guid.GUID{}, sd.SD{}, fail(CodeObjectNotFound, "", nil)
	}
	ent := newEntry(res.Entries[0].DN)
	absorbEntry(ent, map[string]int{}, map[string]struct{}{"objectguid": {}, "ntsecuritydescriptor": {}}, res.Entries[0])
	g, err := ent.GUID()
	if err != nil {
		return guid.GUID{}, sd.SD{}, err
	}
	raw := ent.Raw("nTSecurityDescriptor")
	if len(raw) != 1 || sdHasSACL(raw[0]) {
		return guid.GUID{}, sd.SD{}, fail(CodeProtocol, "security descriptor missing or has a SACL", nil)
	}
	cur, err := sd.Decode(sd.Raw(raw[0]))
	if err != nil {
		return guid.GUID{}, sd.SD{}, err
	}
	return g, cur, nil
}

// ReadDACL re-reads the DACL-only security descriptor of the object and returns it with its objectGUID.
// It is the read-back half of a DACL write: the session is bound to one DC, so the read is against the
// DC the Modify went to.
func (s *Session) ReadDACL(ctx context.Context, ref dn.ObjectRef) (guid.GUID, sd.SD, error) {
	want, err := NewSDFlags(SDDACL)
	if err != nil {
		return guid.GUID{}, sd.SD{}, err
	}
	base, err := ref.ForRequest()
	if err != nil {
		return guid.GUID{}, sd.SD{}, fail(CodeInvalidArgument, "object reference", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return guid.GUID{}, sd.SD{}, fail(CodeUnreachable, "session closed", nil)
	}
	stop := s.watch(ctx, s.conn)
	defer stop()
	return s.readDACLLocked(ctx, base, want)
}
