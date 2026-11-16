package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const docRows = "| 1 | `OBJECT_CREATE` / `object_create` | `ad.object.create` | x |\n" +
	"| 11 | `GROUP_MEMBER_ADD` / `group_member_add` | `ad.group.addMember` | x |\n" +
	"| 12 | `GROUP_MEMBER_REMOVE` / `group_member_remove` | `ad.group.removeMember` | x |\n" +
	"| 13 | `COMPUTER_ACCOUNT_RESET` / `computer_account_reset` | `ad.computer.resetAccount` | x |\n"

const goodTM = "```guarded-v1\nreset_password: unicodePwd[user], userPassword\nreset_computer: unicodePwd[computer]\n```\n"

const goodReserved = `package v1
func TestWriteKindList(t *testing.T) {
	want := map[connectorv1.WriteKind]string{
		connectorv1.WriteKind_WRITE_KIND_OBJECT_CREATE: "object_create",
		connectorv1.WriteKind_WRITE_KIND_GROUP_MEMBER_ADD: "group_member_add",
		connectorv1.WriteKind_WRITE_KIND_GROUP_MEMBER_REMOVE: "group_member_remove",
		connectorv1.WriteKind_WRITE_KIND_COMPUTER_ACCOUNT_RESET: "computer_account_reset",
	}
}
`
const goodClosed = `package client
func TestKindTableClosed(t *testing.T) {
	allowed := map[string]bool{"ad.object.create": true, "ad.group.addMember": true, "ad.group.removeMember": true, "ad.computer.resetAccount": true}
}
`
const goodTable = `package client
var kindTable = map[string]kindRow{
	"a": {Kind: connectorv1.WriteKind_WRITE_KIND_OBJECT_CREATE, Class: "none"},
}
`

func goodGen() Generated {
	return Generated{
		Kinds: map[string]int32{"WRITE_KIND_OBJECT_CREATE": 1, "WRITE_KIND_GROUP_MEMBER_ADD": 11, "WRITE_KIND_GROUP_MEMBER_REMOVE": 12, "WRITE_KIND_COMPUTER_ACCOUNT_RESET": 13, "WRITE_KIND_UNSPECIFIED": 0},
		Arms:  map[string]int32{"object_create": 1, "group_member_add": 11, "group_member_remove": 12, "computer_account_reset": 13},
	}
}

func tree(t *testing.T, over map[string]string) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		docPath:     docRows,
		tmPath:      goodTM,
		reservedT:   goodReserved,
		closedTest:  goodClosed,
		kindTblPath: goodTable,
	}
	for k, v := range over {
		if v == "" {
			delete(files, k)
		} else {
			files[k] = v
		}
	}
	for p, c := range files {
		fp := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(fp), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fp, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func run(t *testing.T, root string, gen Generated) ([]Violation, []string) {
	t.Helper()
	constCache = map[string]map[string]string{}
	vs, p, err := Run(root, gen)
	if err != nil {
		t.Fatal(err)
	}
	return vs, p
}

func wantViolation(t *testing.T, vs []Violation, check, sub string) {
	t.Helper()
	for _, v := range vs {
		if v.Check == check && strings.Contains(v.Msg, sub) {
			return
		}
	}
	t.Fatalf("want a %s violation containing %q, got %v", check, sub, vs)
}

func TestCleanTreePasses(t *testing.T) {
	vs, p := run(t, tree(t, nil), goodGen())
	if len(vs) != 0 {
		t.Fatalf("clean tree failed: %v", vs)
	}
	if len(p) != 2 {
		t.Fatalf("want GM1 and GM3 pending, got %v", p)
	}
}

func TestGM4MissingArm(t *testing.T) {
	g := goodGen()
	delete(g.Arms, "group_member_remove")
	vs, _ := run(t, tree(t, nil), g)
	wantViolation(t, vs, "GM4", "no WriteChange arm \"group_member_remove\"")
}

func TestGM4ArmNumberDiffers(t *testing.T) {
	g := goodGen()
	g.Arms["computer_account_reset"] = 14
	vs, _ := run(t, tree(t, nil), g)
	wantViolation(t, vs, "GM4", "computer_account_reset")
}

func TestGM4ReservedListDiffers(t *testing.T) {
	vs, _ := run(t, tree(t, map[string]string{reservedT: strings.Replace(goodReserved, "\t\tconnectorv1.WriteKind_WRITE_KIND_COMPUTER_ACCOUNT_RESET: \"computer_account_reset\",\n", "", 1)}), goodGen())
	wantViolation(t, vs, "GM4", "TestWriteKindList lacks COMPUTER_ACCOUNT_RESET")
}

func TestGM4EnumValueWithoutDocRow(t *testing.T) {
	g := goodGen()
	g.Kinds["WRITE_KIND_EXTRA"] = 14
	vs, _ := run(t, tree(t, nil), g)
	wantViolation(t, vs, "GM4", "WRITE_KIND_EXTRA")
}

func TestGM2ClosedListMissingAndExtra(t *testing.T) {
	vs, _ := run(t, tree(t, map[string]string{closedTest: strings.Replace(goodClosed, `"ad.computer.resetAccount": true`, `"ad.bogus.kind": true`, 1)}), goodGen())
	wantViolation(t, vs, "GM2", `lacks "ad.computer.resetAccount"`)
	wantViolation(t, vs, "GM2", `accepts "ad.bogus.kind"`)
}

func TestGM2WiredKindWithoutRow(t *testing.T) {
	wired := "package write\nvar _ = connectorv1.WriteKind_WRITE_KIND_GROUP_MEMBER_ADD\n"
	vs, _ := run(t, tree(t, map[string]string{"internal/connector/write/kinds_group.go": wired}), goodGen())
	wantViolation(t, vs, "GM2", "no row for ad.group.addMember")
}

func TestGM2WiredKindWithRowPasses(t *testing.T) {
	wired := "package write\nvar _ = connectorv1.WriteKind_WRITE_KIND_GROUP_MEMBER_ADD\n"
	table := strings.Replace(goodTable, "}\n", "\t\"b\": {Kind: connectorv1.WriteKind_WRITE_KIND_GROUP_MEMBER_ADD, Class: \"none\"},\n}\n", 1)
	vs, _ := run(t, tree(t, map[string]string{"internal/connector/write/kinds_group.go": wired, kindTblPath: table}), goodGen())
	if len(vs) != 0 {
		t.Fatalf("%v", vs)
	}
}

func TestGM2RowWithoutClass(t *testing.T) {
	table := strings.Replace(goodTable, "}\n", "\t\"b\": {Kind: connectorv1.WriteKind_WRITE_KIND_COMPUTER_ACCOUNT_RESET},\n}\n", 1)
	vs, _ := run(t, tree(t, map[string]string{kindTblPath: table}), goodGen())
	wantViolation(t, vs, "GM2", "has no class")
}

func TestGM3BlockWithoutComputerKey(t *testing.T) {
	vs, _ := run(t, tree(t, map[string]string{tmPath: "```guarded-v1\nreset_password: unicodePwd, userPassword\n```\n"}), goodGen())
	wantViolation(t, vs, "GM3", "unicodePwd[user]")
	wantViolation(t, vs, "GM3", "unicodePwd[computer]")
}

func TestGM3BareUnicodePwdUnderAnotherClass(t *testing.T) {
	vs, _ := run(t, tree(t, map[string]string{tmPath: goodTM + "```guarded-v1\nx: y\n```\n"}), goodGen())
	_ = vs // first block wins; the regexp takes the first
	vs, _ = run(t, tree(t, map[string]string{tmPath: "```guarded-v1\nreset_password: unicodePwd[user]\nreset_computer: unicodePwd[computer]\nunlock: unicodePwd\n```\n"}), goodGen())
	wantViolation(t, vs, "GM3", "under class unlock")
}

func TestGM3GoTableLacksKey(t *testing.T) {
	over := map[string]string{"internal/directory/guarded/table.go": "package guarded\nvar t = []string{\"unicodePwd[user]\"}\n"}
	vs, p := run(t, tree(t, over), goodGen())
	wantViolation(t, vs, "GM3", "unicodePwd[computer]")
	for _, x := range p {
		if strings.HasPrefix(x, "GM3") {
			t.Fatalf("GM3 must be active once guarded exists: %v", p)
		}
	}
}

const guardedOK = "package guarded\nvar t = []string{\"unicodePwd[user]\", \"unicodePwd[computer]\"}\n"

func TestGM3ComputerResetUnderWrongPermission(t *testing.T) {
	act := `package ad
const PermUpdate = "objects.computer.update"
var d = operation.Descriptor{Permission: PermUpdate}
func f() { guarded.ComputerReset() }
`
	vs, _ := run(t, tree(t, map[string]string{"internal/directory/guarded/table.go": guardedOK, "internal/modules/ad/c.go": act}), goodGen())
	wantViolation(t, vs, "GM3", "ComputerReset() reached by an Action declaring [objects.computer.update]")
}

func TestGM3ComputerResetUnderItsPermission(t *testing.T) {
	act := `package ad
const PermReset = "objects.computer.reset_account"
var d = operation.Descriptor{Permission: PermReset}
func f() { guarded.ComputerReset() }
`
	vs, _ := run(t, tree(t, map[string]string{"internal/directory/guarded/table.go": guardedOK, "internal/modules/ad/c.go": act}), goodGen())
	if len(vs) != 0 {
		t.Fatalf("%v", vs)
	}
}

const groupAction = `package ad
const PermAdd = "objects.group.add_member"
var d = operation.Descriptor{ID: "ad.group.addMember", Permission: %s}
func plan() {
	_ = step.Plan{Target: %s, Kind: "ad.group.addMember", Reversibility: 1}
	_ = client.WriteOp{DigestKind: "ad.group.addMember", Target: %s}
}
`

func groupTree(t *testing.T, perm, stepT, opT string) []Violation {
	body := strings.Replace(groupAction, "%s", perm, 1)
	body = strings.Replace(body, "%s", stepT, 1)
	body = strings.Replace(body, "%s", opT, 1)
	vs, _ := run(t, tree(t, map[string]string{"internal/modules/ad/g.go": body}), goodGen())
	return vs
}

func TestGM1CleanAction(t *testing.T) {
	if vs := groupTree(t, "PermAdd", "groupRef", "groupRef"); len(vs) != 0 {
		t.Fatalf("%v", vs)
	}
}

func TestGM1WrongPermission(t *testing.T) {
	body := strings.Replace(groupAction, "Permission: %s", `Permission: "objects.user.update"`, 1)
	body = strings.Replace(body, "%s", "groupRef", 3)
	vs, _ := run(t, tree(t, map[string]string{"internal/modules/ad/g.go": body}), goodGen())
	wantViolation(t, vs, "GM1", `"objects.user.update" is outside`)
}

func TestGM1TargetIsTheMember(t *testing.T) {
	vs := groupTree(t, "PermAdd", "memberRef", "memberRef")
	wantViolation(t, vs, "GM1", "names the member")
}

func TestGM1StepAndOpTargetsDiffer(t *testing.T) {
	vs := groupTree(t, "PermAdd", "groupRef", "other")
	wantViolation(t, vs, "GM1", `differs from WriteOp Target "other"`)
}

func TestRealTreeIsClean(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	constCache = map[string]map[string]string{}
	vs, _, err := Run("../../..", generatedKinds())
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 0 {
		t.Fatalf("%v", vs)
	}
}
