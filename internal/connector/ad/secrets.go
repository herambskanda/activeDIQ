package ad

import (
	"context"
	"errors"
	"strconv"

	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/attr/secretattr"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/ldapfilter"
	"github.com/skenzeriq/activediq/internal/platform/secret"
)

// secretSearchFlags are the searchFlags bits that put an attribute in SecretAttrs (safe-primitives
// §3.7): fCONFIDENTIAL 0x80, fRODCFilteredAttribute 0x200, fPARTITIONSECRET 0x1000.
const secretSearchFlags uint32 = 0x80 | 0x200 | 0x1000

// loadSecretAttrs computes the schema-flagged half of SecretAttrs from the DC's attributeSchema
// objects (the bit test runs on the DC, the result streams paged), unions it with the static list and
// extends s.schema so the filter builder and checkAttrs refuse every member. Absent static names are
// still marked: refusing them as secrets is stricter than ignoring them, never looser.
func (s *Session) loadSecretAttrs(ctx context.Context) error {
	rd, err := s.RootDSE(ctx)
	if err != nil {
		return err
	}
	if rd.SchemaNamingContext == "" {
		return fail(CodeProtocol, "schemaNamingContext missing", nil)
	}
	sc := DefaultSchema()
	flags, err1 := ldapfilter.ParseAttrName("searchFlags", sc)
	oc, err2 := ldapfilter.ParseAttrName("objectClass", sc)
	if err1 != nil || err2 != nil {
		return fail(CodeInvalidArgument, "schema allowlist", nil)
	}
	flt, err := ldapfilter.Render(ldapfilter.And(
		ldapfilter.Eq(oc, ldapfilter.String("attributeSchema")),
		ldapfilter.BitOr(flags, secretSearchFlags),
	), sc)
	if err != nil {
		return fail(CodeFilterRejected, ldapfilter.Code(err), err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return fail(CodeUnreachable, "session closed", nil)
	}
	stop := s.watch(ctx, s.conn)
	defer stop()
	extra, err := collectSecretSchema(func(cookie []byte) (*ldap.SearchResult, error) {
		paging := ldap.NewControlPaging(MaxPageSize)
		paging.SetCookie(cookie)
		return s.searchOnceLocked(ctx, rd.SchemaNamingContext, ldap.ScopeSingleLevel, flt.String(),
			[]string{"lDAPDisplayName", "attributeID"}, []ldap.Control{paging})
	})
	if err != nil {
		return err
	}
	s.schema = s.schema.With(extra...)
	return nil
}

// SecretAttr names one SecretAttrs member. The zero value is invalid; obtain one from
// Session.SecretAttr.
type SecretAttr struct{ name string }

// String returns the attribute's ldapDisplayName.
func (a SecretAttr) String() string { return a.name }

// SecretAttr resolves name (descr or numericoid) to a SecretAttrs member of this session's schema.
// Anything else — unknown or not secret — is refused: ReadSecret is for secrets only, and ordinary
// attributes go through Read.
func (s *Session) SecretAttr(name string) (SecretAttr, error) {
	n, err := ldapfilter.ParseAttrName(name, s.schema)
	if err != nil {
		return SecretAttr{}, fail(CodeInvalidArgument, "attribute: "+ldapfilter.Code(err), err)
	}
	if !s.schema.IsSecret(n.String()) {
		return SecretAttr{}, fail(CodeInvalidArgument, "not a secret attribute", nil)
	}
	return SecretAttr{name: n.String()}, nil
}

// SecretReadGrant authorises one ReadSecret for (actor, target object, attribute). The authorisation
// layer mints it after per-object authorisation and any step-up the owning feature demands. It has
// no exported fields and no serialisation, and ReadSecret checks it against its arguments.
type SecretReadGrant struct {
	actor  string
	target guid.GUID
	attr   string
	reason string
}

// MintSecretReadGrant is for the authorisation layer only. actor and reason are recorded in the audit
// event, so both are required.
func MintSecretReadGrant(actor string, target guid.GUID, attr SecretAttr, reason string) (SecretReadGrant, error) {
	if actor == "" || reason == "" || attr.name == "" {
		return SecretReadGrant{}, fail(CodeInvalidArgument, "grant needs actor, attribute and reason", nil)
	}
	return SecretReadGrant{actor: actor, target: target, attr: attr.name, reason: reason}, nil
}

// SecretReadEvent is the audit record of one ReadSecret call. It never carries a value.
type SecretReadEvent struct {
	Actor     string
	Target    guid.GUID
	Attribute string
	Reason    string
	Outcome   string // "ok" or the error Code
}

// ReadSecret reads one secret attribute of one object by a base-scope read over the session's LDAPS
// connection (the session cannot be anything else). The value comes back as a secret.Secret and
// touches nothing else: it is not cached, logged, or kept in an Entry. Every call is audited with its
// outcome; if the audit sink fails the value is destroyed and the call fails. Single-valued secrets
// only: a multi-valued one is refused rather than silently cut.
func (s *Session) ReadSecret(ctx context.Context, target dn.ObjectRef, attr SecretAttr, grant SecretReadGrant) (sec secret.Secret, err error) {
	if s.cfg.SecretAudit == nil {
		return secret.Secret{}, fail(CodeInvalidArgument, "secret audit sink required", nil)
	}
	g, isGUID := target.GUID()
	audit := func(outcome string) error {
		return s.cfg.SecretAudit(SecretReadEvent{Actor: grant.actor, Target: g, Attribute: attr.name, Reason: grant.reason, Outcome: outcome})
	}
	defer func() {
		out := "ok"
		if err != nil {
			out = string(CodeOf(err))
		}
		aerr := audit(out)
		if aerr == nil {
			return
		}
		auditErr := fail(CodeProtocol, "audit failed", aerr)
		if err == nil {
			sec.Destroy()
			sec, err = secret.Secret{}, auditErr
			return
		}
		// The read failed and so did its audit: the caller sees both, the read's error first so
		// CodeOf still names the read failure, and the call is visibly unaudited (T-0313).
		err = errors.Join(err, fail(CodeProtocol, "audit failed (failed read is unaudited)", aerr))
	}()
	if !isGUID || attr.name == "" || grant.attr == "" || grant.target != g || grant.attr != attr.name {
		return secret.Secret{}, fail(CodeInvalidArgument, "grant does not match request", nil)
	}
	if !s.schema.IsSecret(attr.name) {
		return secret.Secret{}, fail(CodeInvalidArgument, "not a secret attribute", nil)
	}
	base, err := target.ForRequest()
	if err != nil {
		return secret.Secret{}, fail(CodeInvalidArgument, "object reference", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return secret.Secret{}, fail(CodeUnreachable, "session closed", nil)
	}
	stop := s.watch(ctx, s.conn)
	defer stop()
	res, err := s.searchOnceLocked(ctx, base, ldap.ScopeBaseObject, objectClassPresent, []string{"objectGUID", attr.name}, nil)
	if err != nil {
		return secret.Secret{}, err
	}
	if len(res.Entries) != 1 {
		return secret.Secret{}, fail(CodeObjectNotFound, "", nil)
	}
	e := res.Entries[0]
	defer func() { // the library's copy of the value must not outlive this call
		for _, a := range e.Attributes {
			for _, v := range a.ByteValues {
				clear(v)
			}
		}
	}()
	if got, gerr := guid.FromBytes(e.GetRawAttributeValue("objectGUID")); gerr != nil || got != g {
		return secret.Secret{}, fail(CodeProtocol, "object identity mismatch", nil)
	}
	var vals [][]byte
	for _, a := range e.Attributes {
		if equalFoldASCII(a.Name, attr.name) {
			vals = a.ByteValues
		}
	}
	switch len(vals) {
	case 0:
		return secret.Secret{}, fail(CodeSecretNotSet, "", nil)
	case 1:
		return secret.FromBytes(vals[0]), nil
	}
	return secret.Secret{}, fail(CodeProtocol, "multi-valued secret ("+strconv.Itoa(len(vals))+" values)", nil)
}

func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		x, y := a[i], b[i]
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}

// collectSecretSchema pages through the schema-flagged attributeSchema objects (page returns one page
// for a cookie) and returns them unioned with the static list. A real AD always flags some attribute
// (unicodePwd and friends carry fCONFIDENTIAL or fPARTITIONSECRET), so zero flagged objects means the
// schema read was filtered, truncated or answered by something that is not the schema: fail closed
// rather than run on the static list alone (T-0313).
func collectSecretSchema(page func(cookie []byte) (*ldap.SearchResult, error)) ([]ldapfilter.AttrInfo, error) {
	extra := make([]ldapfilter.AttrInfo, 0, 64)
	for _, n := range secretattr.Static() {
		extra = append(extra, ldapfilter.AttrInfo{Name: n, Syntax: ldapfilter.SynOctet, Secret: true})
	}
	flagged := 0
	var cookie []byte
	for {
		res, err := page(cookie)
		if err != nil {
			return nil, err
		}
		for _, e := range res.Entries {
			name := e.GetAttributeValue("lDAPDisplayName")
			if name == "" {
				continue
			}
			flagged++
			extra = append(extra, ldapfilter.AttrInfo{
				Name: name, OID: e.GetAttributeValue("attributeID"), Syntax: ldapfilter.SynOctet, Secret: true,
			})
		}
		if cookie = pagingCookie(res.Controls); len(cookie) == 0 {
			break
		}
	}
	if flagged == 0 {
		return nil, fail(CodeProtocol, "schema returned no secret-flagged attributes", nil)
	}
	return extra, nil
}
