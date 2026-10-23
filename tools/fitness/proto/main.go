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
//	F5  no message in the package uses google.protobuf.Any, and Enroll is not a stream.
//	F6  fleet messages reference only messages of their own package and google.protobuf.Timestamp;
//	    F2 and F3 walk every RPC input and output transitively, so imported types cannot smuggle
//	    a tenant or a secret in.
//	F4  the Enroll RPC's output (resolved from the RPC, not by message name) and every message
//	    reachable from it are an exact allowlist of field names and types: leaf_certificate_der,
//	    ca_bundle_pem (both bytes, required), endpoints (repeated Endpoint{host string, port
//	    uint32}) and leaf_not_after (Timestamp). Anything else, at any depth, fails.
//	F8  fleet files are syntax proto3 (no editions, proto2, extension ranges or groups) and no file
//	    extends a fleet message. F6 also covers RPC input and output types, and the token allowance
//	    is keyed on the full name activediq.fleet.v1.EnrollRequest.enrollment_token on the Enroll input.
//	F9  no message type in the package has a secret-shaped name (same fragments as F3), so a
//	    message such as PasswordPush or SecretEnvelope fails even if its fields are innocuous.
//	    A new RPC fails F1 with a pointer to the ADR and review it needs.
//	F10 (reported as F1) Tunnel's input and output are both activediq.fleet.v1.TunnelFrame, and
//	    EnrollRequest is the input or output of no RPC other than Enroll (T-0185).
//	F11 the repository's proto tree must define package activediq.fleet.v1 (RequireFleet, on by
//	    default in the CLI; `-optional-fleet` is for throw-away trees in the CI proof).
//	F7  no map fields anywhere in the fleet contract or reachable from an Enroll or Tunnel input or
//	    output: a map is an unchecked free-form side channel.
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

// RequireFleet reports F11 when no file declares the fleet package: deleting fleet.proto must not
// leave the gate green because every F rule is vacuous without it.
func RequireFleet(files linker.Files) []Violation {
	for _, f := range files {
		if isFleet(f.Package()) {
			return nil
		}
	}
	return []Violation{{"F11", "proto", "the proto tree has no package activediq.fleet.v1; the fleet contract must exist (its rules F1-F10 would otherwise pass vacuously)"}}
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
	optionalFleet := false
	for _, a := range os.Args[1:] {
		if a == "-optional-fleet" {
			optionalFleet = true
		} else {
			dir = a
		}
	}
	files, err := Compile(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fitness-proto: [P1] compile failed:", err)
		os.Exit(1)
	}
	vs := Lint(files)
	if !optionalFleet {
		vs = append(vs, RequireFleet(files)...)
	}
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
var fleetSecretAllow = map[string]bool{"activediq.fleet.v1.EnrollRequest.enrollment_token": true}

// fieldSpec is one allowed field: its kind and, for messages, the full name of its type.
type fieldSpec struct {
	kind    protoreflect.Kind
	list    bool
	message protoreflect.FullName
}

// enrollResponseAllow is the exact field set of the Enroll output: public material only (F4).
var enrollResponseAllow = map[string]fieldSpec{
	"leaf_certificate_der": {kind: protoreflect.BytesKind},
	"ca_bundle_pem":        {kind: protoreflect.BytesKind},
	"endpoints":            {kind: protoreflect.MessageKind, list: true, message: "activediq.fleet.v1.Endpoint"},
	"leaf_not_after":       {kind: protoreflect.MessageKind, message: "google.protobuf.Timestamp"},
}

// endpointAllow is the exact field set of Endpoint (F4).
var endpointAllow = map[string]fieldSpec{
	"host": {kind: protoreflect.StringKind},
	"port": {kind: protoreflect.Uint32Kind},
}

// lintEnrollResponse checks the Enroll output message resp against the F4 allowlist, recursing
// into the messages it references. Required fields: leaf_certificate_der and ca_bundle_pem.
func lintEnrollResponse(pkg protoreflect.FullName, resp protoreflect.MessageDescriptor, seen map[protoreflect.FullName]bool) []Violation {
	var vs []Violation
	for _, req := range []string{"leaf_certificate_der", "ca_bundle_pem"} {
		fd := resp.Fields().ByName(protoreflect.Name(req))
		if fd == nil || fd.Kind() != protoreflect.BytesKind || fd.IsList() {
			vs = append(vs, Violation{"F4", string(resp.FullName()), "the Enroll response must carry bytes `" + req + "` (the signed leaf and the CA bundle the component pins, TM-TB6-T2)"})
		}
	}
	vs = append(vs, checkAllow(resp, enrollResponseAllow, seen, pkg)...)
	return vs
}

func checkAllow(m protoreflect.MessageDescriptor, allow map[string]fieldSpec, seen map[protoreflect.FullName]bool, pkg protoreflect.FullName) []Violation {
	if seen[m.FullName()] {
		return nil
	}
	seen[m.FullName()] = true
	var vs []Violation
	for i := 0; i < m.Fields().Len(); i++ {
		fd := m.Fields().Get(i)
		pos := string(m.FullName()) + "." + string(fd.Name())
		spec, ok := allow[string(fd.Name())]
		if !ok || fd.IsMap() || fd.Kind() != spec.kind || fd.IsList() != spec.list ||
			(fd.Message() != nil && fd.Message().FullName() != spec.message) {
			vs = append(vs, Violation{"F4", pos, "the Enroll response closure is an exact allowlist of names and types (leaf_certificate_der, ca_bundle_pem, endpoints[Endpoint{host, port}], leaf_not_after); any other field needs a security review and an edit of this rule"})
			continue
		}
		if fd.Message() != nil && fd.Message().FullName() == pkg+".Endpoint" {
			vs = append(vs, checkAllow(fd.Message(), endpointAllow, seen, pkg)...)
		}
	}
	return vs
}

// lintFleet applies F1 to F8 to every fleet package among files.
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
					vs = append(vs, Violation{"F1", string(m.FullName()), "only Enroll and Tunnel may be mounted on the fleet listener; a new fleet RPC needs a new ADR (security-architect review, threat model TM-TB6-T8) and an edit of fitness-proto F1"})
				}
			}
			if m := got["Enroll"]; m == nil {
				vs = append(vs, Violation{"F1", pos, "missing RPC Enroll"})
			} else if m.IsStreamingClient() || m.IsStreamingServer() {
				vs = append(vs, Violation{"F5", string(m.FullName()), "Enroll must be unary"})
			}
			if m := got["Tunnel"]; m == nil {
				vs = append(vs, Violation{"F1", pos, "missing RPC Tunnel"})
			} else {
				if !m.IsStreamingClient() || !m.IsStreamingServer() {
					vs = append(vs, Violation{"F1", string(m.FullName()), "Tunnel must be bidirectional streaming (component-initiated)"})
				}
				// F10: the Tunnel carries TunnelFrame both ways, so the single-use enrollment
				// token (EnrollRequest) cannot ride on the long-lived stream.
				want := pkg + ".TunnelFrame"
				if m.Input().FullName() != want || m.Output().FullName() != want {
					vs = append(vs, Violation{"F1", string(m.FullName()), "Tunnel must take and return " + string(want) + " (input " + string(m.Input().FullName()) + ", output " + string(m.Output().FullName()) + "); the enrollment token must not ride on the tunnel"})
				}
			}
			// EnrollRequest is the input or output of Enroll only.
			for j := 0; j < svc.Methods().Len(); j++ {
				m := svc.Methods().Get(j)
				if m.Name() == "Enroll" {
					continue
				}
				for _, t := range []protoreflect.MessageDescriptor{m.Input(), m.Output()} {
					if t.FullName() == pkg+".EnrollRequest" {
						vs = append(vs, Violation{"F1", string(m.FullName()), string(t.FullName()) + " carries the single-use enrollment token and may be used only by Enroll"})
					}
				}
			}
		}
		var enroll protoreflect.MethodDescriptor
		for _, svc := range services {
			if m := svc.Methods().ByName("Enroll"); m != nil {
				enroll = m
			}
		}
		// F6 for RPC types: the contract is self-contained, so every RPC input and output is a
		// message of the fleet package.
		for _, svc := range services {
			for j := 0; j < svc.Methods().Len(); j++ {
				m := svc.Methods().Get(j)
				for _, t := range []protoreflect.MessageDescriptor{m.Input(), m.Output()} {
					if t.ParentFile().Package() != pkg {
						vs = append(vs, Violation{"F6", string(m.FullName()), "RPC types must be messages of the fleet package, not " + string(t.FullName())})
					}
				}
			}
		}
		// F8: proto3 only (no editions, proto2, extension ranges or groups), and no extension of
		// a fleet message from any file.
		for _, f := range files {
			if f.Package() == pkg && f.Syntax() != protoreflect.Proto3 {
				vs = append(vs, Violation{"F8", f.Path(), "fleet files must be syntax proto3: no editions or proto2, so no extension ranges or groups"})
			}
			var exts []protoreflect.ExtensionDescriptor
			collectExtensions(f, &exts)
			for _, x := range exts {
				if x.ContainingMessage().ParentFile().Package() == pkg {
					vs = append(vs, Violation{"F8", string(x.FullName()), "extending a fleet message is not allowed: it is an unchecked side channel"})
				}
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
		// F9: a secret-bearing message type, whatever its fields are called (TM-TB6-T6).
		for _, m := range roots {
			lower := strings.ToLower(string(m.Name()))
			for _, frag := range secretShaped {
				if strings.Contains(lower, frag) {
					vs = append(vs, Violation{"F9", string(m.FullName()), "message type name looks secret-bearing (`" + frag + "`); nothing secret is pushed over fleet (TM-TB6-T6). Secrets travel only as the opaque operation payload of CallData"})
					break
				}
			}
		}
		for _, m := range roots {
			walk(m, string(m.FullName()), seen, func(_ string, fd protoreflect.FieldDescriptor) {
				parent := fd.ContainingMessage()
				pos := string(parent.FullName()) + "." + string(fd.Name())
				lower := strings.ToLower(string(fd.Name()))
				if strings.Contains(lower, "tenant") {
					vs = append(vs, Violation{"F2", pos, "the tenant comes from the certificate SAN, never from a message (ADR-0002)"})
				}
				if fd.IsMap() {
					vs = append(vs, Violation{"F7", pos, "map fields are a free-form side channel and are not allowed in the fleet contract"})
				}
				if fd.Message() != nil {
					full := fd.Message().FullName()
					if full == "google.protobuf.Any" {
						vs = append(vs, Violation{"F5", pos, "google.protobuf.Any is not allowed in the fleet contract"})
					} else if full != "google.protobuf.Timestamp" && fd.Message().ParentFile().Package() != pkg {
						vs = append(vs, Violation{"F6", pos, "fleet messages may reference only messages of their own package and google.protobuf.Timestamp, not " + string(full)})
					}
				}
				key := pos
				if enroll == nil || parent.FullName() != enroll.Input().FullName() {
					key = "" // the token is allowed only on the Enroll RPC's own input message
				}
				for _, frag := range secretShaped {
					if strings.Contains(lower, frag) && !fleetSecretAllow[key] {
						vs = append(vs, Violation{"F3", pos, "field name looks secret-bearing (`" + frag + "`); nothing secret is pushed over fleet (TM-TB6-T6). Only the single-use enrollment token is allowed"})
						break
					}
				}
			})
		}
		// F4: the Enroll RPC's output (whatever it is named) and everything reachable from it is an
		// exact allowlist of names and types: public material only.
		if enroll != nil {
			vs = append(vs, lintEnrollResponse(pkg, enroll.Output(), map[protoreflect.FullName]bool{})...)
		}
	}
	return vs
}

func collectExtensions(f protoreflect.FileDescriptor, out *[]protoreflect.ExtensionDescriptor) {
	for i := 0; i < f.Extensions().Len(); i++ {
		*out = append(*out, f.Extensions().Get(i))
	}
	var rec func(ms protoreflect.MessageDescriptors)
	rec = func(ms protoreflect.MessageDescriptors) {
		for i := 0; i < ms.Len(); i++ {
			for j := 0; j < ms.Get(i).Extensions().Len(); j++ {
				*out = append(*out, ms.Get(i).Extensions().Get(j))
			}
			rec(ms.Get(i).Messages())
		}
	}
	rec(f.Messages())
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
