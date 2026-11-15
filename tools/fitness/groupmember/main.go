// Command groupmember is the fitness-group-member job: connector-contract §8.10.8 fitness GM1-GM4
// (kinds 11-13, T-1899) and the TM-D28 B1 key with target class (`unicodePwd[computer]`).
//
//	GM1  group-member Actions declare only the group permissions, and their authz Target is the group
//	GM2  kindTable has a row (with a class) for every wired kind 11-13; TestKindTableClosed lists the thirteen keys
//	GM3  the guarded-v1 block carries unicodePwd[user] and unicodePwd[computer]; ComputerReset() only under
//	     objects.computer.reset_account (B4); the Go table equals the block once internal/directory/guarded lands
//	GM4  every WriteKind has a WriteChange arm of the same number; reserved_test.go and the generated enum equal §8.10.1
//
// A part whose code has not landed (no group-member Action, no guarded package) is printed as pending: not a
// pass. It turns active by itself when the code appears.
package main

import (
	"fmt"
	"os"
	"sort"

	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

func main() {
	root := "."
	if len(os.Args) > 2 && os.Args[1] == "-root" {
		root = os.Args[2]
	}
	vs, pending, err := Run(root, generatedKinds())
	if err != nil {
		fmt.Fprintln(os.Stderr, "fitness-group-member:", err)
		os.Exit(2)
	}
	sort.Strings(pending)
	for _, p := range pending {
		fmt.Printf("  pending   %s (not yet checked, not a pass)\n", p)
	}
	if len(vs) == 0 {
		fmt.Println("fitness-group-member: ok (GM1-GM4 as listed; pending parts above)")
		return
	}
	for _, v := range vs {
		fmt.Fprintln(os.Stderr, v)
	}
	fmt.Fprintf(os.Stderr, "fitness-group-member: %d violation(s); rules: connector-contract §8.10.8\n", len(vs))
	os.Exit(1)
}

// generatedKinds reads the compiled enum and the WriteChange oneof: name (without WRITE_KIND_) -> number,
// and arm name -> field number.
func generatedKinds() Generated {
	g := Generated{Kinds: map[string]int32{}, Arms: map[string]int32{}}
	for name, n := range connectorv1.WriteKind_value {
		g.Kinds[name] = n
	}
	oneof := (&connectorv1.WriteChange{}).ProtoReflect().Descriptor().Oneofs().ByName("change")
	if oneof != nil {
		for i := 0; i < oneof.Fields().Len(); i++ {
			f := oneof.Fields().Get(i)
			g.Arms[string(f.Name())] = int32(f.Number())
		}
	}
	return g
}
