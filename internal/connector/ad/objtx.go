package ad

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/connector/ad/scope"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/ldapfilter"
)

// WriteConn is the connection a write sender may use for the duration of one Tx.Send call. Like
// Modifier, it exists so this package holds the lock, the reads and the error mapping while the
// requests themselves are built only in internal/connector/write/ops (fitness TM-F-T0GUARD).
type WriteConn interface {
	Add(*ldap.AddRequest) error
	Modify(*ldap.ModifyRequest) error
	Del(*ldap.DelRequest) error
}

// Tx is the session held for one object write: every call inside Do runs on the one DC this
// session is bound to, under one hold of the session lock, so a read-compare-write sequence cannot
// interleave with another request on the connection. LDAP has no transactions; Tx narrows the
// window, it does not close it.
type Tx struct {
	s   *Session
	ctx context.Context
}

// Do runs fn with the session locked. fn must not call back into the Session.
func (s *Session) Do(ctx context.Context, fn func(*Tx) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return fail(CodeUnreachable, "session closed", nil)
	}
	stop := s.watch(ctx, s.conn)
	defer stop()
	return fn(&Tx{s: s, ctx: ctx})
}

// Read is a base-scope read of one object, optionally with the show-deleted control. Constructed
// attributes are allowed (the connector reads what the bound identity sees). Ranged values are not
// followed: the callers read single attributes they are about to edit, bounded by the edit limits.
func (t *Tx) Read(ref dn.ObjectRef, attrs []string) (*Entry, error) {
	base, err := ref.ForRequest()
	if err != nil {
		return nil, fail(CodeInvalidArgument, "object reference", err)
	}
	names, err := t.s.checkAttrs(append([]string{"objectGUID"}, attrs...), true)
	if err != nil {
		return nil, err
	}
	res, err := t.s.searchOnceLocked(t.ctx, base, ldap.ScopeBaseObject, objectClassPresent, names, nil)
	if err != nil {
		return nil, err
	}
	if len(res.Entries) != 1 {
		return nil, fail(CodeObjectNotFound, "", nil)
	}
	ent := newEntry(res.Entries[0].DN)
	asked := make(map[string]struct{}, len(names))
	for _, n := range names {
		asked[strings.ToLower(n)] = struct{}{}
	}
	absorbEntry(ent, map[string]int{}, asked, res.Entries[0])
	return ent, nil
}

// ReadDeleted is Read with the show-deleted control, so an object that is
// a tombstone or in the Recycle Bin can be found by GUID. A live object is returned as well.
func (t *Tx) ReadDeleted(ref dn.ObjectRef, attrs []string) (*Entry, error) {
	base, err := ref.ForRequest()
	if err != nil {
		return nil, fail(CodeInvalidArgument, "object reference", err)
	}
	names, err := t.s.checkAttrs(append([]string{"objectGUID"}, attrs...), true)
	if err != nil {
		return nil, err
	}
	res, err := t.s.searchRaw(t.ctx, base, ldap.ScopeBaseObject, objectClassPresent, names,
		[]ldap.Control{domainScope{}, scope.ShowDeleted()})
	if err != nil {
		return nil, err
	}
	if len(res.Entries) != 1 {
		return nil, fail(CodeObjectNotFound, "", nil)
	}
	ent := newEntry(res.Entries[0].DN)
	asked := make(map[string]struct{}, len(names))
	for _, n := range names {
		asked[strings.ToLower(n)] = struct{}{}
	}
	absorbEntry(ent, map[string]int{}, asked, res.Entries[0])
	return ent, nil
}

// Exists reports whether an object is at the DN (a base-scope read, live objects only).
func (t *Tx) Exists(d dn.DN) (bool, error) {
	_, err := t.Read(dn.DNRef(d), []string{"objectClass"})
	switch CodeOf(err) {
	case "":
		return true, nil
	case CodeObjectNotFound:
		return false, nil
	}
	return false, err
}

// HasChildren reports whether the object has at least one child, with a one-entry size limit.
func (t *Tx) HasChildren(ref dn.ObjectRef) (bool, error) {
	base, err := ref.ForRequest()
	if err != nil {
		return false, fail(CodeInvalidArgument, "object reference", err)
	}
	req := ldap.NewSearchRequest(base, ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 1, int(t.s.cfg.Timeout.Seconds()), false,
		objectClassPresent, []string{"objectGUID"}, []ldap.Control{domainScope{}})
	res, err := t.s.conn.Search(req)
	var le *ldap.Error
	switch {
	case err == nil:
	case errors.As(err, &le) && le.ResultCode == ldap.LDAPResultSizeLimitExceeded:
		return true, nil
	case errors.As(err, &le) && le.ResultCode == ldap.LDAPResultNoSuchObject:
		return false, fail(CodeObjectNotFound, "", nil)
	case errors.As(err, &le) && le.ResultCode == ldap.LDAPResultInsufficientAccessRights:
		return false, fail(CodeInsufficientRights, "", nil)
	case t.ctx.Err() != nil:
		return false, fail(CodeCanceled, "", t.ctx.Err())
	default:
		return false, fail(CodeProtocol, ldapCode(err), nil)
	}
	return len(res.Entries) > 0, nil
}

// Send lends the connection to one sender (built in ops) and maps its LDAP error to this package's
// codes. A returned error after the request was sent leaves the outcome unknown to the caller.
func (t *Tx) Send(send func(WriteConn) error) error {
	if err := send(t.s.conn); err != nil {
		return t.mapWriteErr(err)
	}
	return nil
}

func (t *Tx) mapWriteErr(err error) error {
	if t.ctx.Err() != nil {
		return fail(CodeCanceled, "", t.ctx.Err())
	}
	var le *ldap.Error
	if !errors.As(err, &le) {
		return fail(CodeUnreachable, ldapCode(err), nil)
	}
	switch le.ResultCode {
	case ldap.LDAPResultInsufficientAccessRights:
		return fail(CodeInsufficientRights, "", nil)
	case ldap.LDAPResultNoSuchObject:
		return fail(CodeObjectNotFound, "", nil)
	case ldap.LDAPResultReferral:
		return fail(CodeUnexpectedReferral, "", nil)
	case ldap.LDAPResultEntryAlreadyExists:
		return fail(CodeEntryExists, "", nil)
	case ldap.LDAPResultNotAllowedOnNonLeaf:
		return fail(CodeNotLeaf, "", nil)
	case ldap.LDAPResultNoSuchAttribute, ldap.LDAPResultAttributeOrValueExists:
		return fail(CodeConflict, "", nil)
	case ldap.LDAPResultConstraintViolation, ldap.LDAPResultUnwillingToPerform, ldap.LDAPResultObjectClassViolation,
		ldap.LDAPResultInvalidAttributeSyntax, ldap.LDAPResultNamingViolation, ldap.LDAPResultUndefinedAttributeType,
		ldap.LDAPResultInvalidDNSyntax:
		return fail(CodeConstraint, ldapCode(err), nil)
	}
	return fail(CodeProtocol, ldapCode(err), nil)
}

// Secure reports whether the session's connection is TLS (always true for a Session built by Open;
// a password value is sent only when it is, contract §8.10.5).
func (t *Tx) Secure() bool {
	st, ok := t.s.conn.TLSConnectionState()
	return ok && st.HandshakeComplete
}

// DCTime is the bound DC's own clock (rootDSE currentTime), read on the session's connection.
func (t *Tx) DCTime() (time.Time, error) {
	res, err := t.s.searchOnceLocked(t.ctx, "", ldap.ScopeBaseObject, objectClassPresent, []string{"currentTime"}, nil)
	if err != nil {
		return time.Time{}, err
	}
	if len(res.Entries) != 1 {
		return time.Time{}, fail(CodeProtocol, "rootDSE not returned", nil)
	}
	return ParseGeneralizedTime(res.Entries[0].GetAttributeValue("currentTime"))
}

// ParseGeneralizedTime parses an LDAP GeneralizedTime in UTC ("20060102150405.0Z").
func ParseGeneralizedTime(s string) (time.Time, error) {
	for _, layout := range []string{"20060102150405.0Z", "20060102150405Z"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fail(CodeProtocol, "generalized time malformed", nil)
}

// FormatGeneralizedTime is the inverse for a write value.
func FormatGeneralizedTime(t time.Time) string { return t.UTC().Format("20060102150405.0Z") }

// AttrOID is the schema's attributeID for a resolved ldapDisplayName ("" when unknown); the write
// deny-list matches on it so a renamed attribute is still refused.
func (s *Session) AttrOID(name string) string { return s.schema.OID(name) }

// EditableAttr resolves a requested attribute name (descr in any case, or numeric OID) to its
// schema ldapDisplayName and value syntax for a write. An unknown attribute, one with options, a
// secret one and a constructed one are refused: a write is never blind about what it edits.
func (s *Session) EditableAttr(name string) (string, ldapfilter.Syntax, error) {
	a, err := ldapfilter.ParseAttrName(name, s.schema)
	if err != nil {
		return "", 0, fail(CodeAttributeNotAllowed, "attribute: "+ldapfilter.Code(err), err)
	}
	switch _, rerr := ldapfilter.Render(ldapfilter.Present(a), s.schema); ldapfilter.Code(rerr) {
	case "":
	case ldapfilter.SecretAttribute:
		return "", 0, fail(CodeSecretAttribute, "", rerr)
	default:
		return "", 0, fail(CodeAttributeNotAllowed, "attribute: "+ldapfilter.Code(rerr), rerr)
	}
	syn, ok := s.schema.Syntax(a.String())
	if !ok {
		return "", 0, fail(CodeAttributeNotAllowed, "", nil)
	}
	return a.String(), syn, nil
}
