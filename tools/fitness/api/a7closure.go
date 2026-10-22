package main

import (
	"fmt"
	"reflect"
	"strings"
)

// The A7 type closure (ADR-0004 rule 4): every Go type reachable from an operation's Input, its
// request body target, or a response a handler returned must be a generated type, a built-in,
// slice, map or pointer of allowed types, an apitypes scalar, secret.Secret, or a type of the
// binding table; and none may implement the encoding/json (v1) Marshaler or Unmarshaler.

const (
	pkgAPITypes = modPath + "internal/platform/apihost/apitypes"
	pkgAPIHost  = modPath + "internal/platform/apihost"
	pkgSecret   = modPath + "internal/platform/secret"
)

// boundPackages are the owners of the binding table's safe-primitive wire forms (tools/gen/api).
var boundPackages = map[string]bool{
	modPath + "internal/directory/dn":             true,
	modPath + "internal/directory/ldapfilter":     true,
	modPath + "internal/platform/store/reportsql": true,
}

// extraGeneratedPkgs lets a test stand a package in for a generated api package.
var extraGeneratedPkgs = map[string]bool{}

// closure walks t and returns one message per violation.
func closure(root reflect.Type) []string {
	var out []string
	seen := map[reflect.Type]bool{}
	var walk func(t reflect.Type, path string)
	walk = func(t reflect.Type, path string) {
		if seen[t] {
			return
		}
		seen[t] = true
		bad := func(f string, a ...any) { out = append(out, path+": "+fmt.Sprintf(f, a...)) }

		if t.Name() != "" && t.PkgPath() != "" {
			out = append(out, namedViolations(t, path)...)
		}
		if leafType(t) {
			return // an apitypes scalar, secret.Secret or bound primitive: its internals are its own
		}
		switch t.Kind() {
		case reflect.Pointer, reflect.Slice, reflect.Array:
			walk(t.Elem(), path+"[]")
		case reflect.Map:
			if t.Key().Kind() != reflect.String {
				bad("map key %s is not a string", t.Key())
			}
			walk(t.Elem(), path+"{}")
		case reflect.Struct:
			for i := 0; i < t.NumField(); i++ {
				f := t.Field(i)
				if !f.IsExported() {
					continue // presence bits and other generated bookkeeping carry no JSON
				}
				walk(f.Type, path+"."+f.Name)
			}
		case reflect.String, reflect.Bool, reflect.Int64:
		case reflect.Interface:
			bad("an interface type (%s) is outside the closed set: a decoded value must have a generated type", t)
		default:
			bad("kind %s (%s) is outside the closed set (string, bool, int64, generated, apitypes, secret.Secret, bound)", t.Kind(), t)
		}
	}
	walk(root, root.String())
	return out
}

func namedViolations(t reflect.Type, path string) []string {
	var out []string
	bad := func(f string, a ...any) { out = append(out, path+": "+fmt.Sprintf(f, a...)) }
	pkg := t.PkgPath()
	generated := strings.HasSuffix(pkg, "/api") && strings.HasPrefix(pkg, modPath+"internal/") || extraGeneratedPkgs[pkg]
	switch {
	case generated, pkg == pkgAPITypes, boundPackages[pkg]:
	case pkg == pkgSecret && t.Name() == "Secret":
	case pkg == pkgAPIHost && (t.Name() == "Upload" || t.Name() == "Stream"):
	default:
		if t.Kind() == reflect.Struct || t.Kind() == reflect.Map || t.Kind() == reflect.Slice || t.Kind() == reflect.Interface || isBasic(t.Kind()) {
			bad("type %s.%s is not generated, an apitypes scalar, secret.Secret or a bound primitive (ADR-0004 rule 4)", pkg, t.Name())
		}
		return out
	}
	for _, rt := range []reflect.Type{t, reflect.PointerTo(t)} {
		if hasMethod(rt, "MarshalJSON", 0, 2) || hasMethod(rt, "UnmarshalJSON", 1, 1) {
			bad("type %s implements the encoding/json v1 Marshaler or Unmarshaler: v1 repairs invalid UTF-8 and accepts duplicate names, so no reachable type may have these methods (ADR-0004 rule 7)", t)
			break
		}
	}
	pt := reflect.PointerTo(t)
	hasIn, hasOut := hasMethod(pt, "UnmarshalJSONFrom", 1, 1), hasMethod(t, "MarshalJSONTo", 1, 1) || hasMethod(pt, "MarshalJSONTo", 1, 1)
	isSecret := pkg == pkgSecret
	switch {
	case isSecret: // unmarshals only; its MarshalJSONTo returns Unserializable (safe-primitives §5.6)
	case hasOut && !hasIn:
		bad("type %s has MarshalJSONTo but no UnmarshalJSONFrom: the v2 methods come as a pair (ADR-0004 rule 4)", t)
	case pkg == pkgAPITypes && !hasIn && (t.Kind() == reflect.Struct || t.Kind() == reflect.Array):
		bad("apitypes type %s lacks UnmarshalJSONFrom (ADR-0004 rule 4)", t)
	case boundPackages[pkg] && (!hasIn || !hasOut):
		bad("bound type %s must implement both UnmarshalJSONFrom and MarshalJSONTo (ADR-0004 rule 4)", t)
	}
	return out
}

func isBasic(k reflect.Kind) bool {
	switch k {
	case reflect.String, reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Float32, reflect.Float64:
		return true
	}
	return false
}

// hasMethod reports a method by name and arity, without importing encoding/json.
func hasMethod(t reflect.Type, name string, in, out int) bool {
	m, ok := t.MethodByName(name)
	if !ok {
		return false
	}
	n := m.Type.NumIn()
	if t.Kind() != reflect.Interface {
		n-- // the receiver
	}
	return n == in && m.Type.NumOut() == out
}

// leafType: a named type of apitypes, secret or a bound package is a closed unit; the closure does
// not look inside it (UUID is a byte array, Secret holds a func).
func leafType(t reflect.Type) bool {
	pkg := t.PkgPath()
	return t.Name() != "" && (pkg == pkgAPITypes || boundPackages[pkg] || pkg == pkgSecret || pkg == pkgAPIHost)
}
