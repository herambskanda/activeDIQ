package apihost

// HostBinding is a named hostname binding a policy.anonymous row may reference (ADR-0004 rule 5,
// chain step 4). The table is fixed in code so tools/fitness/api can read it (A13, A4); the
// hostname each name answers to is configuration, Policy.Hosts.
type HostBinding struct {
	Name string
	Ref  string // the allow-list row (AN-n) that justifies it
	Use  string
}

// HostBindings is the complete table of hostname bindings.
var HostBindings = []HostBinding{
	{Name: "totp-enrolment", Ref: "AN-5", Use: "end-user TOTP enrolment, reachable only on the enrolment hostname"},
	{Name: "sspr", Ref: "AN-7", Use: "self-service password reset served on the console/API listener [M4]"},
}

// LookupHostBinding finds a binding by name.
func LookupHostBinding(name string) (HostBinding, bool) {
	for _, b := range HostBindings {
		if b.Name == name {
			return b, true
		}
	}
	return HostBinding{}, false
}

// AnonymousRow is one policy.anonymous entry for an operation of the document.
type AnonymousRow struct {
	Operation string
	Host      string // a HostBindings name, or empty for any host
	Gate      string
}

// Policy is api/openapi/policy.yaml as apihost enforces it (ADR-0004 rule 9). compose/server loads
// the file; nonApiRoutes and secretResponses are checked by fitness-api, not here.
type Policy struct {
	Anonymous     []AnonymousRow
	Authenticated []string          // operationIds any authenticated principal may call
	StepUp        []string          // permissions that need a fresh multi-factor check
	Hosts         map[string]string // binding name → the hostname it answers to
}

func (p Policy) anonymous(op string) (AnonymousRow, bool) {
	for _, r := range p.Anonymous {
		if r.Operation == op {
			return r, true
		}
	}
	return AnonymousRow{}, false
}

func (p Policy) authenticated(op string) bool {
	for _, o := range p.Authenticated {
		if o == op {
			return true
		}
	}
	return false
}

func (p Policy) stepUp(perm string) bool {
	for _, s := range p.StepUp {
		if s == perm {
			return true
		}
	}
	return false
}
