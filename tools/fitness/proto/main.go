// Package main is the fitness-proto job (T-0064). It compiles every .proto file under proto/ with
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
//	P6  the reserved operation names Apply, ReadSecret and VerifyUser exist in Operation and have
//	    no RPC (their shapes belong to later tickets).
//	P7  no string or bytes field anywhere is named password, unicode_pwd, credential or secret.
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
	reservedOperations = []string{"APPLY", "READ_SECRET", "VERIFY_USER"}
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

// Lint applies P2 to P7 to compiled files.
func Lint(files linker.Files) []Violation {
	var vs []Violation
	requests := map[protoreflect.FullName]protoreflect.MessageDescriptor{}
	for _, f := range files {
		svcs := f.Services()
		for i := 0; i < svcs.Len(); i++ {
			svc := svcs.Get(i)
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
			}
			if ops != nil {
				for _, r := range reservedOperations {
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
