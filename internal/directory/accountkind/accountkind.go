// Package accountkind is the one definition of the four account write kinds of connector-contract
// §8.10 (T-1583): reset password, unlock, enable, disable. The server (directory/client) derives the
// typed WriteChange from a planned write's attributes with ChangeFromAttrs; the connector recomputes
// the plan digest from the typed request with AttrsOf and Compute. Both sides use these functions and
// nothing else, so what the digest covers is what the connector acts on (ADR-0005 rule 2).
package accountkind

import (
	"errors"
	"strconv"

	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"

	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/operation/digest"
)

// Digest keys: compile-time constants (contract §8.10.2 rule 4).
const (
	KeyResetPassword = "ad.user.resetPassword"
	KeyUnlock        = "ad.user.unlock"
	KeyEnable        = "ad.account.enable"
	KeyDisable       = "ad.account.disable"
)

// Attribute names in the digest's Attrs.
const (
	AttrMustChange = "mustChangeAtNextLogon" // "true" or "false"; reset only
	AttrSecret     = "secretInput"           // reset only; Secret=true, so only its presence is hashed
)

// Classes of the digest's TargetRef.Class.
const (
	ClassUser     = "user"
	ClassComputer = "computer"
)

// ErrAttrs is returned when a planned write's attributes are not exactly the kind's.
var ErrAttrs = errors.New("accountkind: attributes do not match the kind")

// Spec is one kind's row.
type Spec struct {
	Key     string
	Kind    connectorv1.WriteKind
	Classes []string // TargetRef.Class values the kind allows
	// Families are the §6.3 rights families whose rights the kind needs; VerifyConnection checks them
	// and the write gate rests on that run (acceptance 1 of T-1583).
	Families []connectorv1.RightsFamily
}

var (
	r4 = connectorv1.RightsFamily_RIGHTS_FAMILY_AD_R4_ACCOUNT_STATE
	r5 = connectorv1.RightsFamily_RIGHTS_FAMILY_AD_R5_PASSWORD_RESET
)

var specs = []Spec{
	{KeyResetPassword, connectorv1.WriteKind_WRITE_KIND_USER_PASSWORD_RESET, []string{ClassUser}, []connectorv1.RightsFamily{r5, r4}},
	{KeyUnlock, connectorv1.WriteKind_WRITE_KIND_USER_UNLOCK, []string{ClassUser}, []connectorv1.RightsFamily{r4}},
	{KeyEnable, connectorv1.WriteKind_WRITE_KIND_ACCOUNT_ENABLE, []string{ClassUser, ClassComputer}, []connectorv1.RightsFamily{r4}},
	{KeyDisable, connectorv1.WriteKind_WRITE_KIND_ACCOUNT_DISABLE, []string{ClassUser, ClassComputer}, []connectorv1.RightsFamily{r4}},
}

// Specs returns the four rows.
func Specs() []Spec { return append([]Spec(nil), specs...) }

// ByKey finds a kind by its digest key.
func ByKey(key string) (Spec, bool) {
	for _, s := range specs {
		if s.Key == key {
			return s, true
		}
	}
	return Spec{}, false
}

// ByKind finds a kind by its WriteKind.
func ByKind(k connectorv1.WriteKind) (Spec, bool) {
	for _, s := range specs {
		if s.Kind == k {
			return s, true
		}
	}
	return Spec{}, false
}

// AllowsClass reports whether the digest class label is one of the kind's.
func (s Spec) AllowsClass(c string) bool {
	for _, a := range s.Classes {
		if a == c {
			return true
		}
	}
	return false
}

// ChangeFromAttrs derives the typed change from the planned write's attributes. The attributes must
// be exactly the kind's: a stray one is ErrAttrs, so nothing the digest covers is ignored.
func ChangeFromAttrs(key string, attrs []digest.Attr) (*connectorv1.WriteChange, error) {
	switch key {
	case KeyResetPassword:
		var must, secret *digest.Attr
		for i := range attrs {
			switch attrs[i].Name {
			case AttrMustChange:
				if must != nil {
					return nil, ErrAttrs
				}
				must = &attrs[i]
			case AttrSecret:
				if secret != nil {
					return nil, ErrAttrs
				}
				secret = &attrs[i]
			default:
				return nil, ErrAttrs
			}
		}
		if must == nil || secret == nil || !secret.Secret || len(secret.Values) != 0 || must.Secret || len(must.Values) != 1 {
			return nil, ErrAttrs
		}
		b, err := strconv.ParseBool(must.Values[0])
		if err != nil || strconv.FormatBool(b) != must.Values[0] {
			return nil, ErrAttrs
		}
		return &connectorv1.WriteChange{Change: &connectorv1.WriteChange_UserPasswordReset{
			UserPasswordReset: &connectorv1.UserPasswordReset{MustChangeAtNextLogon: b}}}, nil
	case KeyUnlock:
		if len(attrs) != 0 {
			return nil, ErrAttrs
		}
		return &connectorv1.WriteChange{Change: &connectorv1.WriteChange_UserUnlock{UserUnlock: &connectorv1.UserUnlock{}}}, nil
	case KeyEnable:
		if len(attrs) != 0 {
			return nil, ErrAttrs
		}
		return &connectorv1.WriteChange{Change: &connectorv1.WriteChange_AccountEnable{AccountEnable: &connectorv1.AccountEnable{}}}, nil
	case KeyDisable:
		if len(attrs) != 0 {
			return nil, ErrAttrs
		}
		return &connectorv1.WriteChange{Change: &connectorv1.WriteChange_AccountDisable{AccountDisable: &connectorv1.AccountDisable{}}}, nil
	}
	return nil, ErrAttrs
}

// AttrsOf is the inverse: the digest attributes a typed change stands for. hasSecret is whether the
// request carries secret_input (only its presence is covered, ADR-0005 rule 9). A change that is not
// the kind's arm is ErrAttrs.
func AttrsOf(key string, ch *connectorv1.WriteChange, hasSecret bool) ([]digest.Attr, error) {
	switch key {
	case KeyResetPassword:
		r := ch.GetUserPasswordReset()
		if r == nil || !hasSecret {
			return nil, ErrAttrs
		}
		return []digest.Attr{
			{Name: AttrMustChange, Values: []string{strconv.FormatBool(r.GetMustChangeAtNextLogon())}},
			{Name: AttrSecret, Secret: true},
		}, nil
	case KeyUnlock:
		if ch.GetUserUnlock() == nil || hasSecret {
			return nil, ErrAttrs
		}
	case KeyEnable:
		if ch.GetAccountEnable() == nil || hasSecret {
			return nil, ErrAttrs
		}
	case KeyDisable:
		if ch.GetAccountDisable() == nil || hasSecret {
			return nil, ErrAttrs
		}
	default:
		return nil, ErrAttrs
	}
	return nil, nil
}

// Target is the TargetRef an account write is digested over: the connection, the object and its
// naming context (canonical lower-case 8-4-4-4-12 text) and the class label. No parent or RDN.
func Target(connection, object, class, nc string) authority.TargetRef {
	return authority.TargetRef{Connection: connection, GUID: object, Class: class, NC: authority.NamingContextID(nc)}
}

// Canonical reports whether s is the canonical lower-case 8-4-4-4-12 UUID text the connector renders.
func Canonical(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < 36; i++ {
		c := s[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return false
			}
		}
	}
	return true
}
