package ad

import (
	"context"
	"errors"
	"github.com/skenzeriq/activediq/internal/connector/ad/scope"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
)

// oidShowDeactivatedLink is LDAP_SERVER_SHOW_DEACTIVATED_LINK_OID: without it, link values (memberOf)
// stored on a deleted object are not returned (MS-ADTS 3.1.1.3.4.1.25), so a deleted Domain Admin
// would read as a member of nothing.
const oidShowDeactivatedLink = "1.2.840.113556.1.4.2065"

type showDeactivatedLink struct{}

func (showDeactivatedLink) GetControlType() string { return oidShowDeactivatedLink }
func (showDeactivatedLink) Encode() *berPacket     { return encodeValuelessControl(oidShowDeactivatedLink) }
func (showDeactivatedLink) String() string         { return "Show deactivated link control" }

// Additional codes of the object write operations.
const (
	CodeTargetChanged Code = "TARGET_CHANGED" // the object is no longer the one the plan was made on
	CodeNameInUse     Code = "NAME_IN_USE"    // entryAlreadyExists at the destination
)

// ObjectConn is the connection lent to a sender for one object write. The senders live in
// internal/connector/write/ops, the only place that may build an LDAP write (fitness TM-F-T0GUARD).
type ObjectConn interface {
	Modify(*ldap.ModifyRequest) error
	ModifyDN(*ldap.ModifyDNRequest) error
}

// DNChange is one ModifyDN, every part rendered from dn types.
type DNChange struct {
	Entry        string // the target DN read under the same lock hold (Samba rejects a <GUID=> entry in ModifyDN)
	NewRDN       string // one RDN, escaped
	NewSuperior  string // empty: the parent does not change
	DeleteOldRDN bool
}

// ModifyDNFunc sends one ModifyDN.
type ModifyDNFunc func(m ObjectConn, c DNChange) error

// RestoreChange is the single Modify that restores a deleted object.
type RestoreChange struct {
	Entry    string // the deleted object as a GUID reference
	NewDN    string // the full DN to restore to, rendered from dn types
	Controls []ldap.Control
}

// RestoreFunc sends the restore Modify.
type RestoreFunc func(m ObjectConn, c RestoreChange) error

// ObjectState is what the object write operations read about one object, live.
type ObjectState struct {
	GUID    guid.GUID
	DN      dn.DN // the live DN (a deleted object's DN is the mangled tombstone DN and is not set)
	Classes []string
	Deleted bool
	// Parent is the objectGUID of the parent container; zero for a deleted object or an NC head.
	Parent guid.GUID
	// Entry carries the attributes read, for callers that classify further.
	Entry *Entry
}

var stateAttrs = []string{"objectGUID", "objectClass", "distinguishedName", "isDeleted", "instanceType", "uSNChanged"}

// ObjectState reads one live object by GUID. A deleted object is not visible to it (no show-deleted
// control is ever sent here); the deleted-state read is DeletedObjectState and the classification
// read of a deleted target is ReadDeletedTarget. It reads through the session, so it must not be
// called from inside a Search callback.
func (s *Session) ObjectState(ctx context.Context, id guid.GUID) (ObjectState, error) {
	e, err := s.Read(ctx, dn.GUIDRef(id), stateAttrs, ReadOptions{})
	if err != nil {
		return ObjectState{}, err
	}
	return s.stateOf(ctx, id, e)
}

func (s *Session) stateOf(ctx context.Context, id guid.GUID, e *Entry) (ObjectState, error) {
	g, err := e.GUID()
	if err != nil || g != id {
		return ObjectState{}, fail(CodeProtocol, "object GUID", err)
	}
	st := ObjectState{GUID: g, Classes: e.Strings("objectClass"), Entry: e}
	if v := e.Strings("isDeleted"); len(v) > 0 && strings.EqualFold(v[0], "TRUE") {
		st.Deleted = true
	}
	if st.Deleted {
		return st, nil // a deleted object has no usable DN or parent
	}
	d, err := dn.Parse(e.DN, dn.Strict)
	if err != nil {
		return ObjectState{}, fail(CodeProtocol, "object DN does not parse", err)
	}
	st.DN = d
	p, has, err := s.Parent(ctx, e)
	if err != nil {
		return ObjectState{}, err
	}
	if has {
		st.Parent = p
	}
	return st, nil
}

// MoveRequest moves Object under NewParent (same RDN, deleteoldrdn true: Samba refuses false for an unchanged RDN).
type MoveRequest struct {
	Object, ExpectParent, NewParent guid.GUID
}

// MoveObject: under one hold of the session lock, so on the one DC this session is bound to, it
// re-reads the object, requires its parent to still be ExpectParent (else CodeTargetChanged, nothing
// sent), reads the new parent, and sends one ModifyDN addressed by the GUID just checked.
func (s *Session) MoveObject(ctx context.Context, r MoveRequest, send ModifyDNFunc) error {
	if send == nil {
		return fail(CodeInvalidArgument, "no sender", nil)
	}
	return s.withObject(ctx, func(conn *ldap.Conn) error {
		cur, err := s.liveLocked(ctx, dn.GUIDRef(r.Object))
		if err != nil {
			return err
		}
		pd := cur.dn.Parent()
		par, err := s.liveLocked(ctx, dn.DNRef(pd))
		if err != nil {
			return err
		}
		if par.guid != r.ExpectParent {
			return fail(CodeTargetChanged, "", nil)
		}
		np, err := s.liveLocked(ctx, dn.GUIDRef(r.NewParent))
		if err != nil {
			return err
		}
		rdn := cur.dn.RDNs()[0]
		leaf, err := dn.Child(dn.DN{}, rdn.Type(), rdn.Value())
		if err != nil {
			return fail(CodeInvalidArgument, "rdn", err)
		}
		return mapWriteErr(ctx, send(conn, DNChange{Entry: cur.dn.String(), NewRDN: leaf.String(), DeleteOldRDN: true, NewSuperior: np.dn.String()}))
	})
}

// RenameRequest renames Object to the RDN value NewValue, keeping its RDN type (deleteoldrdn true).
type RenameRequest struct {
	Object   guid.GUID
	NewValue string
}

func (s *Session) RenameObject(ctx context.Context, r RenameRequest, send ModifyDNFunc) error {
	if send == nil {
		return fail(CodeInvalidArgument, "no sender", nil)
	}
	return s.withObject(ctx, func(conn *ldap.Conn) error {
		cur, err := s.liveLocked(ctx, dn.GUIDRef(r.Object))
		if err != nil {
			return err
		}
		leaf, err := dn.Child(dn.DN{}, cur.dn.RDNs()[0].Type(), r.NewValue)
		if err != nil {
			return fail(CodeInvalidArgument, "rdn", err)
		}
		return mapWriteErr(ctx, send(conn, DNChange{Entry: cur.dn.String(), NewRDN: leaf.String(), DeleteOldRDN: true}))
	})
}

// RestoreRequest restores the deleted Object under NewParent as RDN value Value, whose type is
// RDNType (ou for an organizationalUnit, else cn).
type RestoreRequest struct {
	Object, NewParent guid.GUID
	RDNType           dn.RDNType
	Value             string
}

func (s *Session) RestoreObject(ctx context.Context, r RestoreRequest, send RestoreFunc) error {
	if send == nil {
		return fail(CodeInvalidArgument, "no sender", nil)
	}
	return s.withObject(ctx, func(conn *ldap.Conn) error {
		del, err := s.readDeletedLocked(ctx, r.Object)
		if err != nil {
			return err
		}
		if !del.deleted {
			return fail(CodeTargetChanged, "", nil) // restored (or never deleted) since Plan
		}
		np, err := s.liveLocked(ctx, dn.GUIDRef(r.NewParent))
		if err != nil {
			return err
		}
		nd, err := dn.Child(np.dn, r.RDNType, r.Value)
		if err != nil {
			return fail(CodeInvalidArgument, "rdn", err)
		}
		return mapWriteErr(ctx, send(conn, RestoreChange{Entry: r.Object.ObjectRef(), NewDN: nd.String(),
			Controls: []ldap.Control{scope.ShowDeleted()}}))
	})
}

func (s *Session) withObject(ctx context.Context, fn func(*ldap.Conn) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return fail(CodeUnreachable, "session closed", nil)
	}
	stop := s.watch(ctx, s.conn)
	defer stop()
	return fn(s.conn)
}

type lockedObject struct {
	guid    guid.GUID
	dn      dn.DN
	deleted bool
}

// liveLocked reads a live object's GUID and DN. Callers hold s.mu.
func (s *Session) liveLocked(ctx context.Context, ref dn.ObjectRef) (lockedObject, error) {
	o, err := s.readLocked(ctx, ref)
	if err != nil {
		return o, err
	}
	if o.deleted {
		return o, fail(CodeObjectNotFound, "", nil)
	}
	return o, nil
}

func (s *Session) readLocked(ctx context.Context, ref dn.ObjectRef) (lockedObject, error) {
	return s.lockedRead(ctx, ref, nil)
}

// lockedRead is the one-object base read under the held session lock, with the given extra controls.
// Callers: readLocked (none) and readDeletedLocked (deletedread.go, show-deleted).
func (s *Session) lockedRead(ctx context.Context, ref dn.ObjectRef, ctrls []ldap.Control) (lockedObject, error) {
	base, err := ref.ForRequest()
	if err != nil {
		return lockedObject{}, fail(CodeInvalidArgument, "object reference", err)
	}
	res, err := s.searchOnceLocked(ctx, base, ldap.ScopeBaseObject, objectClassPresent, []string{"objectGUID", "distinguishedName", "isDeleted"}, ctrls)
	if err != nil {
		return lockedObject{}, err
	}
	if len(res.Entries) != 1 {
		return lockedObject{}, fail(CodeObjectNotFound, "", nil)
	}
	raw := res.Entries[0]
	g, err := guid.FromBytes(raw.GetRawAttributeValue("objectGUID"))
	if err != nil {
		return lockedObject{}, fail(CodeProtocol, "object GUID", err)
	}
	o := lockedObject{guid: g, deleted: strings.EqualFold(raw.GetAttributeValue("isDeleted"), "TRUE")}
	if !o.deleted {
		if o.dn, err = dn.Parse(raw.DN, dn.Strict); err != nil || o.dn.Len() == 0 {
			return lockedObject{}, fail(CodeProtocol, "object DN does not parse", err)
		}
	}
	return o, nil
}

// mapWriteErr maps the outcome of a write to the package's errors. A cancelled context leaves the
// outcome unknown and is reported as such.
func mapWriteErr(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
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
		case ldap.LDAPResultEntryAlreadyExists:
			return fail(CodeNameInUse, "", nil)
		case ldap.LDAPResultNotAllowedOnNonLeaf:
			return fail(CodeNotLeaf, "", nil)
		case ldap.LDAPResultReferral:
			return fail(CodeUnexpectedReferral, "", nil)
		}
		return fail(CodeProtocol, ldapCode(err), nil)
	}
	return fail(CodeUnreachable, ldapCode(err), nil)
}
