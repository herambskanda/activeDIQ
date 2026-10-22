// Package main is the fitness-proto job (T-0064, extended by T-0091). It compiles every .proto file under proto/ with
// a pure-Go compiler (no protoc, no buf, no network) and enforces the connector contract's
// structural rules by reading the compiled descriptors. A contract that does not compile, or that
// grows a free-form query verb, a DN-text field, a tenant field or a secret-typed field, fails
// `make ci`.
//
// Rules (knowledge/development/architecture/connector-contract.md §2):
//
//	P1  every .proto under proto/ compiles, imports resolved from proto/ and the standard imports.
//	P2  no request message, however deeply nested, has a string or bytes field named like a
//	    free-form verb or text-form security value: dn, base, base_dn, filter_text, ldap_filter,
//	    query, script, command, sql, tenant, tenant_id (ADR-0002 rule 3; safe-primitives §2.1).
//	P3  no request message contains google.protobuf.Any.
//	P4  RPCs are unary or server-streaming. Client streaming and bidirectional streaming are
//	    refused.
//	P5  every RPC of a service has an `OPERATION_<NAME>` value in the package's Operation enum, so
//	    every operation has a capability entry in Describe.
//	P6  the reserved operation names ReadSecret and VerifyUser exist in Operation and have no RPC
//	    (their shapes belong to later tickets). Apply was reserved in v1 and shaped in v1.1; its
//	    OPERATION_APPLY value must still exist (the number is part of the contract).
//	P7  no string or bytes field anywhere is named password, unicode_pwd, credential or secret.
//	P8  every write-group RPC (Plan, Apply) takes a request with a top-level, non-repeated field of
//	    the package's Tier0Context message type, and that Tier0Context has a repeated field of the
//	    package's CorrelationStatement type (one statement per touched object). No write can be
//	    expressed without the per-object Tier-0 context the connector evaluates fail-closed
//	    (contract §8.3 F1).
//
// The fleet gateway's contract (package activediq.fleet.v1, T-0152) is not an operation contract: it has
// no Operation enum, one bidirectional stream and no write group, so P4, P5, P6 and P8 do not
// apply to it. It has its own rules instead (threat model TM-TB6-T3, T6, T8, TM-F-FLEET):
//
//	F1  the service set is exactly one `Fleet` service with exactly two RPCs: Enroll (unary) and
//	    Tunnel (bidirectional streaming). Nothing else is mounted on the fleet listener.
//	F2  no field of any message in the package has a name containing "tenant".
//	F3  no field of any message in the package has a secret-shaped name (password, passwd, pwd,
//	    secret, credential, passphrase, token, key) except the allowlist: EnrollRequest.enrollment_token,
//	    the single-use token. (Operation payloads travel as `payload` bytes of CallData, opaque.)
//	F4  EnrollResponse carries the CA bundle the component pins (`ca_bundle_pem`) and the signed
//	    leaf, and no field that could hold a private key.
//	F5  no message in the package uses google.protobuf.Any, and Enroll is not a stream.
//	F6  fleet messages reference only messages of their own package and google.protobuf.Timestamp;
//	    F2 and F3 walk every RPC input and output transitively, so imported types cannot smuggle
//	    a tenant or a secret in. F4 is an exact field allowlist for EnrollResponse.
package main

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bufbuild/protocompile"
	"github.com/bufbuild/protocompile/linker"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// Violation is one broken rule at one place.
type Violation struct {
	Rule string
	Pos  string
	Msg  string
}

func (v Violation) String() string { return fmt.Sprintf("%s: [%s] %s", v.Pos, v.Rule, v.Msg) }

var (
	bannedRequestFields = map[string]bool{
		"dn": true, "base": true, "base_dn": true, "filter_text": true, "ldap_filter": true,
		"query": true, "script": true, "command": true, "sql": true, "tenant": true, "tenant_id": true,
	}
	bannedSecretFields = map[string]bool{
		"password": true, "unicode_pwd": true, "credential": true, "secret": true,
	}
	reservedOperations = []string{"READ_SECRET", "VERIFY_USER"}
	// requiredOperations must exist in Operation even though they now have an RPC.
	requiredOperations = []string{"APPLY"}
	writeGroup         = map[string]bool{"PLAN": true, "APPLY": true}
)

// Compile parses every .proto file below dir. Import paths are relative to dir.
func Compile(dir string) (linker.Files, error) {
	var names []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(p, ".proto") {
			rel, rerr := filepath.Rel(dir, p)
			if rerr != nil {
				return rerr
			}
			names = append(names, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("no .proto files under %s", dir)
	}
	sort.Strings(names)
	c := protocompile.Compiler{
		Resolver: protocompile.WithStandardImports(&protocompile.SourceResolver{ImportPaths: []string{dir}}),
	}
	return c.Compile(context.Background(), names...)
}

// Lint applies P2 to P8 to compiled files.
func Lint(files linker.Files) []Violation {
	var vs []Violation
	requests := map[protoreflect.FullName]protoreflect.MessageDescriptor{}
	vs = append(vs, lintFleet(files)...)
	for _, f := range files {
		svcs := f.Services()
		for i := 0; i < svcs.Len(); i++ {
			svc := svcs.Get(i)
			if isFleet(f.Package()) {
				for j := 0; j < svc.Methods().Len(); j++ {
					requests[svc.Methods().Get(j).Input().FullName()] = svc.Methods().Get(j).Input()
				}
				continue
			}
			ops := operationEnum(files, f.Package())
			for j := 0; j < svc.Methods().Len(); j++ {
				m := svc.Methods().Get(j)
				pos := string(m.FullName())
				if m.IsStreamingClient() {
					vs = append(vs, Violation{"P4", pos, "client streaming is not allowed; use a unary or server-streaming RPC"})
				}
				requests[m.Input().FullName()] = m.Input()
				want := "OPERATION_" + screamingSnake(string(m.Name()))
				if ops == nil {
					vs = append(vs, Violation{"P5", pos, "package has no Operation enum, so " + want + " cannot exist"})
				} else if ops.Values().ByName(protoreflect.Name(want)) == nil {
					vs = append(vs, Violation{"P5", pos, "Operation enum has no value " + want})
				}
				for _, r := range reservedOperations {
					if screamingSnake(string(m.Name())) == r {
						vs = append(vs, Violation{"P6", pos, "operation name " + r + " is reserved and has no shape in this contract version"})
					}
				}
				if writeGroup[screamingSnake(string(m.Name()))] && !hasTier0Context(m.Input()) {
					vs = append(vs, Violation{"P8", pos, "write-group request " + string(m.Input().FullName()) + " has no Tier0Context field carrying repeated CorrelationStatement"})
				}
			}
			if ops != nil {
				for _, r := range append(append([]string{}, reservedOperations...), requiredOperations...) {
					if ops.Values().ByName(protoreflect.Name("OPERATION_"+r)) == nil {
						vs = append(vs, Violation{"P6", string(f.Path()), "Operation enum is missing the reserved name OPERATION_" + r})
					}
				}
			}
		}
	}
	names := make([]string, 0, len(requests))
	for n := range requests {
		names = append(names, string(n))
	}
	sort.Strings(names)
	for _, n := range names {
		seen := map[protoreflect.FullName]bool{}
		walk(requests[protoreflect.FullName(n)], n, seen, func(path string, fd protoreflect.FieldDescriptor) {
			if (fd.Kind() == protoreflect.StringKind || fd.Kind() == protoreflect.BytesKind) && bannedRequestFields[string(fd.Name())] {
				vs = append(vs, Violation{"P2", path, "request field `" + string(fd.Name()) + "` is a free-form or text-form value; use a typed message (Guid, Dn, Filter)"})
			}
			if fd.Message() != nil && fd.Message().FullName() == "google.protobuf.Any" {
				vs = append(vs, Violation{"P3", path, "google.protobuf.Any is not allowed in a request"})
			}
		})
	}
	for _, f := range files {
		msgs := f.Messages()
		for i := 0; i < msgs.Len(); i++ {
			walk(msgs.Get(i), string(msgs.Get(i).FullName()), map[protoreflect.FullName]bool{}, func(path string, fd protoreflect.FieldDescriptor) {
				if (fd.Kind() == protoreflect.StringKind || fd.Kind() == protoreflect.BytesKind) && bannedSecretFields[string(fd.Name())] {
					vs = append(vs, Violation{"P7", path, "field `" + string(fd.Name()) + "` would carry a secret as plain text; secrets use the Secret type, not this contract"})
				}
			})
		}
	}
	sort.SliceStable(vs, func(i, j int) bool { return vs[i].String() < vs[j].String() })
	return dedupe(vs)
}

// hasTier0Context reports whether m has a top-level, non-repeated field whose type is a message
// named Tier0Context in m's own package, and that message has a repeated field of a message named
// CorrelationStatement in the same package (per-object statements, contract §8.3 F1).
func hasTier0Context(m protoreflect.MessageDescriptor) bool {
	fields := m.Fields()
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		if fd.Message() == nil || fd.IsList() || fd.IsMap() {
			continue
		}
		if fd.Message().Name() == "Tier0Context" && fd.Message().ParentFile().Package() == m.ParentFile().Package() &&
			hasRepeatedOf(fd.Message(), "CorrelationStatement") {
			return true
		}
	}
	return false
}

// hasRepeatedOf reports whether m has a repeated (non-map) field whose type is a message named name
// in m's own package.
func hasRepeatedOf(m protoreflect.MessageDescriptor, name protoreflect.Name) bool {
	fields := m.Fields()
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		if fd.Message() != nil && fd.IsList() && fd.Message().Name() == name && fd.Message().ParentFile().Package() == m.ParentFile().Package() {
			return true
		}
	}
	return false
}

func dedupe(vs []Violation) []Violation {
	var out []Violation
	for i, v := range vs {
		if i == 0 || v != vs[i-1] {
			out = append(out, v)
		}
	}
	return out
}

func operationEnum(files linker.Files, pkg protoreflect.FullName) protoreflect.EnumDescriptor {
	for _, f := range files {
		if f.Package() != pkg {
			continue
		}
		if e := f.Enums().ByName("Operation"); e != nil {
			return e
		}
	}
	return nil
}

// walk visits every field of m and of every message reachable from it, once per message type.
func walk(m protoreflect.MessageDescriptor, path string, seen map[protoreflect.FullName]bool, visit func(path string, fd protoreflect.FieldDescriptor)) {
	if seen[m.FullName()] {
		return
	}
	seen[m.FullName()] = true
	fields := m.Fields()
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		p := path + "." + string(fd.Name())
		visit(p, fd)
		if fd.Message() != nil && !fd.IsMap() && !strings.HasPrefix(string(fd.Message().FullName()), "google.protobuf.") {
			walk(fd.Message(), p, seen, visit)
		}
	}
}

// screamingSnake turns ReadPerDC into READ_PER_DC.
func screamingSnake(s string) string {
	var b strings.Builder
	rs := []rune(s)
	for i, r := range rs {
		upper := r >= 'A' && r <= 'Z'
		if i > 0 && upper {
			prev := rs[i-1]
			prevLower := (prev >= 'a' && prev <= 'z') || (prev >= '0' && prev <= '9')
			nextLower := i+1 < len(rs) && rs[i+1] >= 'a' && rs[i+1] <= 'z'
			if prevLower || (nextLower && prev >= 'A' && prev <= 'Z') {
				b.WriteByte('_')
			}
		}
		b.WriteString(strings.ToUpper(string(r)))
	}
	return b.String()
}

func main() {
	dir := "proto"
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}
	files, err := Compile(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fitness-proto: [P1] compile failed:", err)
		os.Exit(1)
	}
	vs := Lint(files)
	if len(vs) == 0 {
		fmt.Printf("fitness-proto: ok (%d files)\n", len(files))
		return
	}
	for _, v := range vs {
		fmt.Fprintln(os.Stderr, v)
	}
	fmt.Fprintf(os.Stderr, "fitness-proto: %d violation(s)\n", len(vs))
	os.Exit(1)
}

// isFleet reports whether pkg is a fleet gateway contract package (exactly activediq.fleet.v1).
func isFleet(pkg protoreflect.FullName) bool {
	return pkg == "activediq.fleet.v1"
}

// secretShaped are the name fragments F3 refuses in the fleet package.
var secretShaped = []string{"password", "passwd", "pwd", "secret", "credential", "passphrase", "token", "key"}

// fleetSecretAllow are the only secret-shaped fields: the single-use enrollment token.
var fleetSecretAllow = map[string]bool{"EnrollRequest.enrollment_token": true}

// enrollResponseAllow is the exact field set of EnrollResponse: public material only (F4).
var enrollResponseAllow = map[string]bool{"leaf_certificate_der": true, "ca_bundle_pem": true, "endpoints": true, "leaf_not_after": true}

// lintFleet applies F1 to F5 to every fleet package among files.
func lintFleet(files linker.Files) []Violation {
	var vs []Violation
	pkgs := map[protoreflect.FullName]bool{}
	for _, f := range files {
		if isFleet(f.Package()) {
			pkgs[f.Package()] = true
		}
	}
	for pkg := range pkgs {
		var services []protoreflect.ServiceDescriptor
		for _, f := range files {
			if f.Package() != pkg {
				continue
			}
			for i := 0; i < f.Services().Len(); i++ {
				services = append(services, f.Services().Get(i))
			}
		}
		if len(services) != 1 {
			vs = append(vs, Violation{"F1", string(pkg), fmt.Sprintf("fleet package must define exactly one service (Fleet), has %d", len(services))})
		}
		for _, svc := range services {
			pos := string(svc.FullName())
			if svc.Name() != "Fleet" {
				vs = append(vs, Violation{"F1", pos, "the fleet service must be named Fleet"})
			}
			got := map[protoreflect.Name]protoreflect.MethodDescriptor{}
			for j := 0; j < svc.Methods().Len(); j++ {
				m := svc.Methods().Get(j)
				got[m.Name()] = m
				if m.Name() != "Enroll" && m.Name() != "Tunnel" {
					vs = append(vs, Violation{"F1", string(m.FullName()), "only Enroll and Tunnel may be mounted on the fleet listener"})
				}
			}
			if m := got["Enroll"]; m == nil {
				vs = append(vs, Violation{"F1", pos, "missing RPC Enroll"})
			} else if m.IsStreamingClient() || m.IsStreamingServer() {
				vs = append(vs, Violation{"F5", string(m.FullName()), "Enroll must be unary"})
			}
			if m := got["Tunnel"]; m == nil {
				vs = append(vs, Violation{"F1", pos, "missing RPC Tunnel"})
			} else if !m.IsStreamingClient() || !m.IsStreamingServer() {
				vs = append(vs, Violation{"F1", string(m.FullName()), "Tunnel must be bidirectional streaming (component-initiated)"})
			}
		}
		// Roots: every message the package declares, plus the input and output of every RPC,
		// walked transitively so a field of an imported type is checked like a local one.
		var roots []protoreflect.MessageDescriptor
		for _, f := range files {
			if f.Package() == pkg {
				collectMessages(f.Messages(), &roots)
			}
		}
		for _, svc := range services {
			for j := 0; j < svc.Methods().Len(); j++ {
				roots = append(roots, svc.Methods().Get(j).Input(), svc.Methods().Get(j).Output())
			}
		}
		seen := map[protoreflect.FullName]bool{}
		for _, m := range roots {
			walk(m, string(m.FullName()), seen, func(_ string, fd protoreflect.FieldDescriptor) {
				parent := fd.ContainingMessage()
				pos := string(parent.FullName()) + "." + string(fd.Name())
				lower := strings.ToLower(string(fd.Name()))
				if strings.Contains(lower, "tenant") {
					vs = append(vs, Violation{"F2", pos, "the tenant comes from the certificate SAN, never from a message (ADR-0002)"})
				}
				if fd.Message() != nil {
					full := fd.Message().FullName()
					if full == "google.protobuf.Any" {
						vs = append(vs, Violation{"F5", pos, "google.protobuf.Any is not allowed in the fleet contract"})
					} else if full != "google.protobuf.Timestamp" && fd.Message().ParentFile().Package() != pkg {
						vs = append(vs, Violation{"F6", pos, "fleet messages may reference only messages of their own package and google.protobuf.Timestamp, not " + string(full)})
					}
				}
				key := string(parent.Name()) + "." + string(fd.Name())
				for _, frag := range secretShaped {
					if strings.Contains(lower, frag) && !fleetSecretAllow[key] {
						vs = append(vs, Violation{"F3", pos, "field name looks secret-bearing (`" + frag + "`); nothing secret is pushed over fleet (TM-TB6-T6). Only the single-use enrollment token is allowed"})
						break
					}
				}
			})
		}
		for _, f := range files {
			if f.Package() != pkg {
				continue
			}
			if resp := f.Messages().ByName("EnrollResponse"); resp != nil {
				ca := resp.Fields().ByName("ca_bundle_pem")
				if ca == nil || ca.Kind() != protoreflect.BytesKind {
					vs = append(vs, Violation{"F4", string(resp.FullName()), "EnrollResponse must carry the CA bundle the component pins as bytes `ca_bundle_pem` (TM-TB6-T2)"})
				}
				for i := 0; i < resp.Fields().Len(); i++ {
					fd := resp.Fields().Get(i)
					if !enrollResponseAllow[string(fd.Name())] {
						vs = append(vs, Violation{"F4", string(resp.FullName()) + "." + string(fd.Name()), "EnrollResponse is an exact allowlist (leaf_certificate_der, ca_bundle_pem, endpoints, leaf_not_after); any other field needs a security review and an edit of this rule"})
					}
				}
				if resp.Fields().ByName("leaf_certificate_der") == nil {
					vs = append(vs, Violation{"F4", string(resp.FullName()), "EnrollResponse must carry the signed leaf as `leaf_certificate_der`"})
				}
			} else if f.Messages().ByName("EnrollRequest") != nil {
				vs = append(vs, Violation{"F4", string(f.Path()), "EnrollResponse message is missing"})
			}
		}
	}
	return vs
}

func collectMessages(ms protoreflect.MessageDescriptors, out *[]protoreflect.MessageDescriptor) {
	for i := 0; i < ms.Len(); i++ {
		if ms.Get(i).IsMapEntry() {
			continue
		}
		*out = append(*out, ms.Get(i))
		collectMessages(ms.Get(i).Messages(), out)
	}
}
