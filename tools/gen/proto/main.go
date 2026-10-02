// Command proto is the connector contract's code generator (T-0157). It compiles every .proto
// file under proto/ with the pure-Go protocompile (no protoc, no buf, no network), hands the
// result to the pinned protoc-gen-go and protoc-gen-go-grpc plugins as a CodeGeneratorRequest, and
// writes the Go code under internal/proto. The plugins are Go tools pinned in go.mod (`tool`
// directive) and run with `go tool`, so the only toolchain is the Go toolchain.
//
//	go run ./tools/gen/proto           regenerate internal/proto in place
//	go run ./tools/gen/proto -check    regenerate in memory and fail if the tree on disk differs:
//	                                   a stale, hand-edited or orphaned generated file fails `make ci`
//
// Output is reproducible: plugin versions are pinned by go.mod, the request carries no compiler
// version, files are processed in sorted order, and nothing is stamped with a time or a path.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bufbuild/protocompile"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/pluginpb"
)

// generatedSuffixes mark the files this tool owns inside the output tree. Anything else in the
// tree (hand-written tests, doc.go) is left alone.
var generatedSuffixes = []string{".pb.go"}

// plugins are run in this order. Each is a main package pinned in go.mod's tool directive.
var plugins = []struct {
	tool  string
	param string
}{
	{"protoc-gen-go", "paths=source_relative"},
	{"protoc-gen-go-grpc", "paths=source_relative,require_unimplemented_servers=true"},
}

func main() {
	in := flag.String("proto", "proto", "directory holding the .proto sources; import paths are relative to it")
	out := flag.String("out", "internal/proto", "output directory for the generated Go code")
	check := flag.Bool("check", false, "do not write; fail if the generated tree on disk differs from a fresh generation")
	flag.Parse()
	if err := run(*in, *out, *check); err != nil {
		fmt.Fprintln(os.Stderr, "gen-proto:", err)
		os.Exit(1)
	}
}

func run(protoDir, outDir string, check bool) error {
	req, err := buildRequest(protoDir)
	if err != nil {
		return err
	}
	files := map[string][]byte{} // relative to outDir, slash-separated
	for _, p := range plugins {
		r := proto.Clone(req).(*pluginpb.CodeGeneratorRequest)
		r.Parameter = proto.String(p.param)
		got, err := runPlugin(p.tool, r)
		if err != nil {
			return err
		}
		for name, content := range got {
			if _, dup := files[name]; dup {
				return fmt.Errorf("two plugins produced %s", name)
			}
			files[name] = content
		}
	}
	if check {
		return compare(outDir, files)
	}
	return write(outDir, files)
}

// buildRequest compiles every .proto under dir and returns the request for the files to generate,
// carrying their transitive imports first (the order protoc uses).
func buildRequest(dir string) (*pluginpb.CodeGeneratorRequest, error) {
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
		Resolver:       protocompile.WithStandardImports(&protocompile.SourceResolver{ImportPaths: []string{dir}}),
		SourceInfoMode: protocompile.SourceInfoStandard, // comments become Go doc comments
	}
	compiled, err := c.Compile(context.Background(), names...)
	if err != nil {
		return nil, err
	}
	req := &pluginpb.CodeGeneratorRequest{FileToGenerate: names}
	seen := map[string]bool{}
	var add func(fd protoreflect.FileDescriptor)
	add = func(fd protoreflect.FileDescriptor) {
		if seen[fd.Path()] {
			return
		}
		seen[fd.Path()] = true
		imps := fd.Imports()
		for i := 0; i < imps.Len(); i++ {
			add(imps.Get(i).FileDescriptor)
		}
		req.ProtoFile = append(req.ProtoFile, protodesc.ToFileDescriptorProto(fd))
	}
	for _, f := range compiled {
		add(f)
	}
	return req, nil
}

func runPlugin(tool string, req *pluginpb.CodeGeneratorRequest) (map[string][]byte, error) {
	in, err := proto.MarshalOptions{Deterministic: true}.Marshal(req)
	if err != nil {
		return nil, err
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.Command("go", "tool", tool)
	cmd.Stdin = bytes.NewReader(in)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("go tool %s: %w\n%s", tool, err, stderr.String())
	}
	var resp pluginpb.CodeGeneratorResponse
	if err := proto.Unmarshal(stdout.Bytes(), &resp); err != nil {
		return nil, fmt.Errorf("go tool %s: unreadable response: %w", tool, err)
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("go tool %s: %s", tool, resp.GetError())
	}
	files := map[string][]byte{}
	for _, f := range resp.File {
		if !isGenerated(f.GetName()) {
			return nil, fmt.Errorf("go tool %s produced %s, which is not a generated-file name", tool, f.GetName())
		}
		files[f.GetName()] = []byte(f.GetContent())
	}
	return files, nil
}

func isGenerated(name string) bool {
	for _, s := range generatedSuffixes {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	return false
}

// existing lists the generated files already under dir, relative and slash-separated.
func existing(dir string) ([]string, error) {
	var have []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if !d.IsDir() && isGenerated(p) {
			rel, rerr := filepath.Rel(dir, p)
			if rerr != nil {
				return rerr
			}
			have = append(have, filepath.ToSlash(rel))
		}
		return nil
	})
	sort.Strings(have)
	return have, err
}

func write(dir string, files map[string][]byte) error {
	have, err := existing(dir)
	if err != nil {
		return err
	}
	for _, h := range have {
		if _, ok := files[h]; !ok {
			if err := os.Remove(filepath.Join(dir, filepath.FromSlash(h))); err != nil {
				return err
			}
		}
	}
	for name, content := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p, content, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func compare(dir string, files map[string][]byte) error {
	var problems []string
	have, err := existing(dir)
	if err != nil {
		return err
	}
	onDisk := map[string]bool{}
	for _, h := range have {
		onDisk[h] = true
		if _, ok := files[h]; !ok {
			problems = append(problems, h+": orphaned (no .proto produces it any more)")
		}
	}
	var names []string
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if !onDisk[n] {
			problems = append(problems, n+": missing")
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(n)))
		if err != nil {
			return err
		}
		if !bytes.Equal(b, files[n]) {
			problems = append(problems, n+": stale (differs from a fresh generation)")
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("generated code under %s is out of date; run `make gen-proto` and commit the result:\n  %s", dir, strings.Join(problems, "\n  "))
	}
	return nil
}
