package agent

import (
	"context"
	"io"
	"net"
	"os"
	"reflect"
	"sort"
	"testing"
	"time"
)

// capModule records the ModuleDeps the host hands to Start.
type capModule struct {
	fakeModule
	got chan ModuleDeps
}

func (m *capModule) Start(_ context.Context, d ModuleDeps) error { m.got <- d; return nil }

func methodNames(v any) []string {
	t := reflect.TypeOf(v)
	var n []string
	for i := 0; i < t.NumMethod(); i++ {
		n = append(n, t.Method(i).Name)
	}
	sort.Strings(n)
	return n
}

// TestModuleDepsExposeNoFileOrConn pins the security-architect's finding on R3: R3 checks syntax
// only, so a module could type-assert a host-supplied value to a writer/closer and mutate state.
// The host must hand modules wrapper types whose method set is exactly the contract, never a
// concrete *os.File, net.Conn or *Outbox.
func TestModuleDepsExposeNoFileOrConn(t *testing.T) {
	mod := &capModule{got: make(chan ModuleDeps, 1)}
	h := openHost(t, privDir(t), mod)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.Run(ctx) }()
	var d ModuleDeps
	select {
	case d = <-mod.got:
	case <-time.After(5 * time.Second):
		t.Fatal("module never started")
	}
	cancel()
	<-done

	if _, ok := d.Events.(*Outbox); ok {
		t.Fatal("module received the concrete *Outbox")
	}
	if got := methodNames(d.Events); !reflect.DeepEqual(got, []string{"Append", "Flush"}) {
		t.Fatalf("EventSink method set = %v, want [Append Flush]", got)
	}
	// The assertions a hostile module would try.
	if _, ok := d.Events.(io.Writer); ok {
		t.Fatal("EventSink is an io.Writer")
	}
	if _, ok := d.Events.(io.Closer); ok {
		t.Fatal("EventSink is an io.Closer")
	}
	if _, ok := d.Events.(interface{ Truncate(int64) error }); ok {
		t.Fatal("EventSink is truncatable")
	}
	if got := methodNames(d.Blobs); !reflect.DeepEqual(got, []string{"Load", "Save"}) {
		t.Fatalf("Blobs method set = %v, want [Load Save]", got)
	}
	// The dependency struct itself carries no file or conn field. (Unexported fields behind the
	// wrappers are unreachable without unsafe, which the module-import rule R3 bans.)
	fileT, connT := reflect.TypeOf((*os.File)(nil)), reflect.TypeOf((*net.Conn)(nil)).Elem()
	dt := reflect.TypeOf(d)
	for i := 0; i < dt.NumField(); i++ {
		if ft := dt.Field(i).Type; ft == fileT || ft.Implements(connT) {
			t.Fatalf("ModuleDeps.%s is a file or conn", dt.Field(i).Name)
		}
	}
}
