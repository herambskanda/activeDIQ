package client

import (
	"reflect"
	"sort"
	"testing"
)

// TestReaderIsReadOnly fixes the method set of the read-only connector port. Widening it (above all with
// Plan or Apply, the directory write RPCs) must fail CI: the write RPC is reachable only through a function
// that takes a step.Clearance (ADR-0005 rule 2, fitness O2).
func TestReaderIsReadOnly(t *testing.T) {
	typ := reflect.TypeOf((*Reader)(nil)).Elem()
	var got []string
	for i := 0; i < typ.NumMethod(); i++ {
		got = append(got, typ.Method(i).Name)
	}
	sort.Strings(got)
	want := []string{"Describe", "ScopedSearch"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("client.Reader methods = %v, want exactly %v", got, want)
	}
	// The concrete reader must not carry the write RPCs either (no embedding of the generated client).
	ct := reflect.TypeOf(readOnly{})
	for _, m := range []string{"Plan", "Apply"} {
		if _, ok := ct.MethodByName(m); ok {
			t.Fatalf("readOnly has method %s", m)
		}
	}
}
