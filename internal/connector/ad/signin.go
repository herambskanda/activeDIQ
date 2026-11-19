package ad

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/skenzeriq/activediq/internal/directory/attr/filetime"
	"github.com/skenzeriq/activediq/internal/directory/attr/flags"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/ldapfilter"
)

// maxSignInName is the longest sign-in name tried (a UPN is at most 1024 in AD; real ones are far shorter).
const maxSignInName = 256

var errSignInDone = errors.New("ad: sign-in resolution complete")

// SignInUser is the one user a sign-in name resolved to, with the three flags an authenticator needs.
type SignInUser struct {
	GUID           guid.GUID
	SAMAccountName string
	UPN            string
	Disabled       bool // userAccountControl ACCOUNTDISABLE
	Expired        bool // accountExpires is a past instant
	MustChange     bool // pwdLastSet is 0
}

// ResolveSignInName finds the user whose sAMAccountName or userPrincipalName equals name exactly
// (AD compares both case-insensitively). A name with a wildcard or control character, one that
// matches no user, and one that matches more than one object (an sAMAccountName equal to another
// user's UPN) all return CodeObjectNotFound: the caller cannot tell them apart, by design.
// The domain naming context of the bound DC is searched; computers and other classes are not users.
func (s *Session) ResolveSignInName(ctx context.Context, name string) (SignInUser, error) {
	if !validSignInName(name) {
		return SignInUser{}, fail(CodeObjectNotFound, "", nil)
	}
	nc, err := s.DomainNCGUID(ctx)
	if err != nil {
		return SignInUser{}, err
	}
	f, err := signInFilter(s, name)
	if err != nil {
		return SignInUser{}, err
	}
	attrs := []string{"objectGUID", "sAMAccountName", "userPrincipalName", "userAccountControl", "accountExpires", "pwdLastSet"}
	return uniqueSignIn(func(fn func(*Entry) error) error {
		return s.Search(ctx, SearchRequest{Base: dn.GUIDRef(nc), Scope: ScopeSubtree, Filter: f, Attributes: attrs, PageSize: 2}, fn)
	}, time.Now())
}

// uniqueSignIn runs the search and accepts exactly one match: the second match aborts the search,
// and zero or two matches are both not-found. run is the seam the unit test fakes.
func uniqueSignIn(run func(fn func(*Entry) error) error, now time.Time) (SignInUser, error) {
	var found []*Entry
	err := run(func(e *Entry) error {
		found = append(found, e)
		if len(found) > 1 {
			return errSignInDone
		}
		return nil
	})
	if err != nil && !errors.Is(err, errSignInDone) {
		return SignInUser{}, err
	}
	if len(found) != 1 {
		return SignInUser{}, fail(CodeObjectNotFound, "", nil)
	}
	return signInUserFrom(found[0], now)
}

func validSignInName(name string) bool {
	if name == "" || len(name) > maxSignInName || !utf8.ValidString(name) {
		return false
	}
	return !strings.ContainsAny(name, "*") && strings.IndexFunc(name, func(r rune) bool { return r < 0x20 || r == 0x7f }) < 0
}

// signInFilter is (&(objectClass=user)(!(objectClass=computer))(|(sAMAccountName=n)(userPrincipalName=n))),
// built only with the filter builder, which escapes the value.
func signInFilter(s *Session, name string) (ldapfilter.Filter, error) {
	attr := func(n string) ldapfilter.AttrName {
		a, err := ldapfilter.ParseAttrName(n, s.schema)
		if err != nil {
			panic(err) // a name of this package's own schema
		}
		return a
	}
	v := ldapfilter.String(name)
	return ldapfilter.And(
		ldapfilter.Eq(attr("objectClass"), ldapfilter.String("user")),
		ldapfilter.Not(ldapfilter.Eq(attr("objectClass"), ldapfilter.String("computer"))),
		ldapfilter.Or(ldapfilter.Eq(attr("sAMAccountName"), v), ldapfilter.Eq(attr("userPrincipalName"), v)),
	), nil
}

// signInUserFrom reads the flags off a found entry. An attribute that is absent or malformed is a
// failed resolution (not-found), never a default: the flags decide who may enrol, so a user whose
// state cannot be read is refused.
func signInUserFrom(e *Entry, now time.Time) (SignInUser, error) {
	bad := func() (SignInUser, error) { return SignInUser{}, fail(CodeObjectNotFound, "", nil) }
	g, err := e.GUID()
	if err != nil {
		return bad()
	}
	u := SignInUser{GUID: g}
	if v := e.Strings("sAMAccountName"); len(v) == 1 {
		u.SAMAccountName = v[0]
	}
	if v := e.Strings("userPrincipalName"); len(v) == 1 {
		u.UPN = v[0]
	}
	raw := e.Strings("userAccountControl")
	if len(raw) != 1 {
		return bad()
	}
	uac, err := flags.DecodeUAC(raw[0])
	if err != nil {
		return bad()
	}
	u.Disabled = uac.Has(flags.UACAccountDisable)
	// An absent accountExpires is "never"; a malformed one is refused.
	if raw := e.Strings("accountExpires"); len(raw) == 1 {
		v, err := filetime.Decode(filetime.AccountExpires, raw[0])
		if err != nil {
			return bad()
		}
		switch v.Kind {
		case filetime.KindInstant:
			t, _ := v.Time()
			u.Expired = !t.After(now)
		case filetime.KindNever:
		default:
			return bad()
		}
	}
	// An absent pwdLastSet means a password never set: the user must change it.
	if raw := e.Strings("pwdLastSet"); len(raw) == 1 {
		v, err := filetime.Decode(filetime.PwdLastSet, raw[0])
		if err != nil {
			return bad()
		}
		switch v.Kind {
		case filetime.KindMustChange:
			u.MustChange = true
		case filetime.KindInstant:
		default:
			return bad()
		}
	} else {
		u.MustChange = true
	}
	return u, nil
}
