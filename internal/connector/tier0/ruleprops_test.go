package tier0

import (
	"bufio"
	"os"
	"strings"
	"testing"
)

// Drift: the table and the pinned Microsoft list name the same properties (T0-DYN-MAP).
func TestRulePropsMatchesMicrosoftList(t *testing.T) {
	f, err := os.Open("testdata/ruleprops-microsoft.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	want := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" && !strings.HasPrefix(l, "#") {
			want[strings.ToLower(l)] = true
		}
	}
	for p := range want {
		if !knownRuleProperty(p) {
			t.Errorf("Microsoft lists %s, ruleprops v1 has no row (a rule using it would be RefuseAll)", p)
		}
	}
	for _, p := range RulePropertyNames() {
		if !want[p] {
			t.Errorf("ruleprops v1 row %s is not in the pinned Microsoft list", p)
		}
	}
}

// Every Graph key and AD attribute of every row is refused when its property is in the rule, and an
// unrelated key is not.
func TestRulePropsEveryMappingRefuses(t *testing.T) {
	for name, row := range rulePropsV1 {
		kind, prefix := WriteUser, "user."
		if strings.HasPrefix(name, "device.") {
			kind, prefix = WriteDevice, "device."
		}
		scope := ScopeOfRule(name + ` -eq "x"`)
		if scope.RefuseAll && !strings.HasSuffix(name, ".memberof") {
			t.Fatalf("%s: row property lexes as RefuseAll", name)
		}
		if scope.MemberOf {
			continue // memberOf is RefuseAll by 7b
		}
		_ = prefix
		for plane, keys := range map[Plane][]string{PlaneEntra: row.Graph, PlaneAD: row.AD} {
			for _, k := range keys {
				if decide(PropertyWrite{Plane: plane, Kind: kind, Op: OpUpdate, Keys: []string{k}}, scope, nil) == nil {
					t.Errorf("%s: key %q on plane %d is not refused", name, k, plane)
				}
			}
			if decide(PropertyWrite{Plane: plane, Kind: kind, Op: OpUpdate, Keys: []string{"someUnrelatedKey"}}, scope, nil) != nil {
				t.Errorf("%s: an unrelated key is refused", name)
			}
		}
	}
}

func TestDirectoryExtensionName(t *testing.T) {
	const app = "0123456789abcdef0123456789abcdef"
	for s, want := range map[string]bool{"extension_" + app + "_x": true, "extension_" + app + "_": false, "extension_" + app[:31] + "_x": false,
		"extension_" + strings.ToUpper(app) + "_x": false, "extension_zz": false, "other": false} {
		if isDirectoryExtension(s) != want {
			t.Errorf("%q", s)
		}
	}
}
