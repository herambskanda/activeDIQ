package ad

import (
	"context"
	"crypto/tls"
	"errors"
	ber "github.com/go-asn1-ber/asn1-ber"
	"net"
	"strconv"

	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/attr/unicodepwd"
	"github.com/skenzeriq/activediq/internal/directory/dn"
)

// accountAttrs is the fixed read set of an account write (connector-contract §8.10.3 kinds 7 to 10).
// It is a constant of this package, never caller input, so it does not pass the filter schema.
var accountAttrs = []string{"objectGUID", "objectClass", "objectSid", "userAccountControl", "lockoutTime", "pwdLastSet", "uSNChanged"}

// AccountState is the live state of a user or computer as an account write needs it, read from the
// DC this session is bound to. Absent integer attributes are 0 (lockoutTime and pwdLastSet are
// absent or 0 in AD for "never"); the Has flags tell the two apart where it matters.
type AccountState struct {
	GUID        guid.GUID
	Classes     []string // objectClass values, as the DC returned them
	SID         []byte
	UAC         int32
	HasUAC      bool
	LockoutTime int64
	PwdLastSet  int64
	USN         uint64
}

// AccountCheck runs under the session lock on a fresh read. A non-nil error sends nothing.
type AccountCheck func(AccountState) error

// AccountSender sends the one Modify of an account write. sc is the proof of an encrypted, verified
// connection and is the zero value unless the caller asked for it (a password write). The Modify is
// addressed by the objectGUID just read, so a rename between read and write cannot redirect it.
type AccountSender func(m Modifier, dn string, sc unicodepwd.SecureConn) error

type connLink struct{ c *ldap.Conn }

// Generation is constant: a Session owns exactly one connection and never reconnects, so the
// connection a SecureConn was acquired on is the connection it is verified on.
func (connLink) Generation() uint64 { return 0 }
func (l connLink) ConnectionState() (tls.ConnectionState, bool) {
	return l.c.TLSConnectionState()
}

// ReadAccount reads the account state of the object on the bound DC (the read-back half of a write,
// and Plan's read).
func (s *Session) ReadAccount(ctx context.Context, ref dn.ObjectRef) (AccountState, error) {
	base, err := ref.ForRequest()
	if err != nil {
		return AccountState{}, fail(CodeInvalidArgument, "object reference", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return AccountState{}, fail(CodeUnreachable, "session closed", nil)
	}
	stop := s.watch(ctx, s.conn)
	defer stop()
	return s.readAccountLocked(ctx, base)
}

func (s *Session) readAccountLocked(ctx context.Context, base string) (AccountState, error) {
	res, err := s.searchOnceLocked(ctx, base, ldap.ScopeBaseObject, objectClassPresent, accountAttrs, nil)
	if err != nil {
		return AccountState{}, err
	}
	if len(res.Entries) != 1 {
		return AccountState{}, fail(CodeObjectNotFound, "", nil)
	}
	ent := newEntry(res.Entries[0].DN)
	asked := map[string]struct{}{}
	for _, a := range accountAttrs {
		asked[lower(a)] = struct{}{}
	}
	absorbEntry(ent, map[string]int{}, asked, res.Entries[0])
	g, err := ent.GUID()
	if err != nil {
		return AccountState{}, err
	}
	st := AccountState{GUID: g, Classes: ent.Strings("objectClass")}
	if v := ent.Raw("objectSid"); len(v) == 1 {
		st.SID = append([]byte(nil), v[0]...)
	}
	if st.UAC, st.HasUAC, err = ent.Int32("userAccountControl"); err != nil {
		return AccountState{}, err
	}
	if st.LockoutTime, err = int64Attr(ent, "lockoutTime"); err != nil {
		return AccountState{}, err
	}
	if st.PwdLastSet, err = int64Attr(ent, "pwdLastSet"); err != nil {
		return AccountState{}, err
	}
	usn, err := int64Attr(ent, "uSNChanged")
	if err != nil || usn < 0 {
		return AccountState{}, fail(CodeProtocol, "uSNChanged malformed", err)
	}
	st.USN = uint64(usn)
	return st, nil
}

func int64Attr(e *Entry, name string) (int64, error) {
	raw := e.Raw(name)
	if len(raw) == 0 {
		return 0, nil
	}
	if len(raw) != 1 {
		return 0, fail(CodeProtocol, "integer malformed", nil)
	}
	n, err := strconv.ParseInt(string(raw[0]), 10, 64)
	if err != nil {
		return 0, fail(CodeProtocol, "integer malformed", err)
	}
	return n, nil
}

func lower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

// ModifyAccount is the only path to an account write (T-1583). Under one hold of the session lock, so
// on the one DC the session is bound to, it re-reads the object, runs check on that read (the
// precondition compare: nothing is sent when it fails) and sends one Modify addressed by the objectGUID
// just read. needSecure additionally requires an encrypted, certificate-verified connection before
// anything is built (a password write). The Modify's LDAP request is built by send, which lives in
// internal/connector/write/ops, the only place the write fitness function allows one.
//
// LDAP has no compare-and-swap across attributes; the kinds that need one express it in the Modify
// itself (delete old value + add new) and the others narrow the window with check. A returned error
// after the Modify was sent leaves the outcome unknown; the caller re-reads before deciding.
func (s *Session) ModifyAccount(ctx context.Context, ref dn.ObjectRef, check AccountCheck, send AccountSender, needSecure bool) error {
	if check == nil || send == nil {
		return fail(CodeInvalidArgument, "no check or sender", nil)
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

	var sc unicodepwd.SecureConn
	if needSecure {
		if sc, err = unicodepwd.Acquire(connLink{s.conn}, s.tlsName()); err != nil {
			return fail(CodeInsecure, "connection is not secure", err)
		}
	}
	st, err := s.readAccountLocked(ctx, base)
	if err != nil {
		return err
	}
	if err := check(st); err != nil {
		return err // nothing was sent
	}
	target, err := dn.GUIDRef(st.GUID).ForRequest()
	if err != nil {
		return fail(CodeInvalidArgument, "object reference", err)
	}
	if err := send(s.conn, target, sc); err != nil {
		return s.mapModifyErr(ctx, err)
	}
	return nil
}

// tlsName is the name the server certificate must carry.
func (s *Session) tlsName() string {
	if s.cfg.ServerName != "" {
		return s.cfg.ServerName
	}
	host, _, err := net.SplitHostPort(s.server)
	if err != nil {
		return s.server
	}
	return host
}

func (s *Session) mapModifyErr(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return fail(CodeCanceled, "", ctx.Err())
	}
	var le *ldap.Error
	if errors.As(err, &le) {
		// The DC's diagnostic is classified and dropped; it is never kept (it can name a DN).
		diag := ""
		if le.Err != nil {
			diag = le.Err.Error()
		}
		if unicodepwd.ClassifyResult(int(le.ResultCode), diag) != nil {
			return fail(CodePasswordPolicy, "", nil)
		}
		switch le.ResultCode {
		case ldap.LDAPResultInsufficientAccessRights:
			return fail(CodeInsufficientRights, "", nil)
		case ldap.LDAPResultNoSuchObject:
			return fail(CodeObjectNotFound, "", nil)
		case ldap.LDAPResultReferral:
			return fail(CodeUnexpectedReferral, "", nil)
		case ldap.LDAPResultNoSuchAttribute, ldap.LDAPResultAttributeOrValueExists:
			return fail(CodeStaleValue, "", nil) // the compare of delete-old + add-new failed: a second writer
		}
		return fail(CodeProtocol, ldapCode(err), nil)
	}
	return fail(CodeUnreachable, ldapCode(err), nil)
}

// oidPolicyHints is LDAP_SERVER_POLICY_HINTS_OID: with flag 0x1 the DC applies password history and
// minimum age to an administrative set (connector-contract §8.10.3 kind 7, TM §6.3 R5).
const oidPolicyHints = "1.2.840.113556.1.4.2239"

type policyHints struct{}

func (policyHints) GetControlType() string { return oidPolicyHints }

// Encode sends the control non-critical: a DC that does not know it (Samba, [UNVERIFIED]) still does
// the reset, with its own history rule, which §8.10.7 records.
func (policyHints) Encode() *berPacket {
	p := encodeValuelessControl(oidPolicyHints)
	val := berEncodeValue(0x1)
	p.AppendChild(val)
	return p
}

func (policyHints) String() string { return "Policy hints control" }

// PolicyHintsControl is the control a password reset carries.
func PolicyHintsControl() ldap.Control { return policyHints{} }

func berEncodeValue(flags int64) *ber.Packet {
	val := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "Control Value")
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "PolicyHints")
	seq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, flags, "Flags"))
	val.AppendChild(seq)
	return val
}
