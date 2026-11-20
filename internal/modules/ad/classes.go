package ad

import (
	"slices"
	"strings"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/operation"
)

// objClass is one directory object class the lifecycle Actions cover (T-1586). The verbs are written
// once; a class is a row here, so a fifth class is data, not a handler. Action IDs, permissions, audit
// kinds and schema names are derived from Seg, so the four spellings cannot drift apart.
type objClass struct {
	Live  string // the live class label the connector reports ("organizationalUnit")
	Seg   string // ID and permission segment: ad.<Seg>.<verb>, objects.<Seg>.<verb>
	Title string // schema name part: Ad<Title>Create
	Noun  string // words in plan text
	// attrs are the plain-text attributes create and update may set; createOnly are set at create only.
	// Everything that grants access or changes who the object is has its own Action and permission.
	attrs      []string
	createOnly []string
	// container: the class can hold children, so delete previews its child count.
	container bool
}

var (
	userClass = objClass{Live: ClassUser, Seg: "user", Title: "User", Noun: "account", attrs: profileAttrs, createOnly: createOnlyAttrs}

	groupClass = objClass{Live: "group", Seg: "group", Title: "Group", Noun: "group",
		attrs:      []string{"description", "info", "displayName", "mail"},
		createOnly: []string{"sAMAccountName"}}

	computerClass = objClass{Live: "computer", Seg: "computer", Title: "Computer", Noun: "computer account",
		attrs:      []string{"description", "location"},
		createOnly: []string{"sAMAccountName"}}

	contactClass = objClass{Live: "contact", Seg: "contact", Title: "Contact", Noun: "contact",
		attrs: []string{"givenName", "sn", "initials", "displayName", "description", "mail", "telephoneNumber", "mobile",
			"title", "department", "company", "physicalDeliveryOfficeName", "streetAddress", "l", "st", "postalCode", "co", "c",
			"info", "wWWHomePage"}}

	ouClass = objClass{Live: "organizationalUnit", Seg: "ou", Title: "OU", Noun: "organizational unit", container: true,
		attrs: []string{"description", "displayName", "street", "l", "st", "postalCode", "co", "c"}}
)

// lifecycleClasses are the classes the lifecycle Actions are registered for, in registration order.
var lifecycleClasses = []objClass{userClass, groupClass, computerClass, contactClass, ouClass}

// VerbID is the Action ID of a verb on a class segment: VerbID("ou", "delete") = ad.ou.delete.
func VerbID(seg, verb string) operation.ActionID { return operation.ActionID("ad." + seg + "." + verb) }

// VerbPermission is the permission of a verb on a class segment. A rename is a modifyDN: "move" (TM-D19).
func VerbPermission(seg, verb string) authz.Permission {
	return authz.Permission("objects." + seg + "." + verb)
}

func (c objClass) id(verb string) operation.ActionID { return VerbID(c.Seg, verb) }
func (c objClass) perm(verb string) authz.Permission { return VerbPermission(c.Seg, verb) }
func (c objClass) audit(past string) audit.Kind      { return audit.Kind("ad." + c.Seg + "." + past) }
func (c objClass) schema(suffix string) operation.SchemaRef {
	return operation.SchemaRef("#/components/schemas/Ad" + c.Title + suffix)
}

// notReason is the refusal reason for a target of another class.
func (c objClass) notReason() string {
	if c.Seg == "user" {
		return ReasonNotUser
	}
	return "target_not_a_" + strings.ToLower(c.Seg)
}

// canon returns the list spelling of an attribute the class allows; create also admits the create-only names.
func (c objClass) canon(name string, create bool) (string, bool) {
	for _, a := range c.attrs {
		if strings.EqualFold(a, name) {
			return a, true
		}
	}
	if create {
		for _, a := range c.createOnly {
			if strings.EqualFold(a, name) {
				return a, true
			}
		}
	}
	return "", false
}

func (c objClass) allowed(name string, create bool) bool {
	_, ok := c.canon(name, create)
	return ok
}

func init() {
	// A class segment must be unique and every class must list attributes distinct from its create-only ones.
	seen := map[string]bool{}
	for _, c := range lifecycleClasses {
		if seen[c.Seg] {
			panic("ad: duplicate lifecycle class " + c.Seg)
		}
		seen[c.Seg] = true
		for _, a := range c.createOnly {
			if slices.ContainsFunc(c.attrs, func(x string) bool { return strings.EqualFold(x, a) }) {
				panic("ad: attribute both profile and create-only: " + a)
			}
		}
	}
}
