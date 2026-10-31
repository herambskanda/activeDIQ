package boundtest

import (
	"context"
	"strings"
	"testing"
)

func events(lines ...string) []byte {
	return []byte(strings.Join(lines, "\n") + "\n")
}

func ev(action, test string) string {
	return `{"Action":"` + action + `","Package":"p","Test":"` + test + `"}`
}

func runFixed(out []byte) Runner {
	return func(context.Context, string, []string, []string) ([]byte, error) { return out, nil }
}

func kinds(fs []Failure) string {
	var k []string
	for _, f := range fs {
		k = append(k, f.Kind+":"+f.Where)
	}
	return strings.Join(k, ",")
}

func TestJudge(t *testing.T) {
	tt := []struct {
		name string
		test Test
		out  []byte
		want string
	}{
		{"pass", Test{Name: "TestA", Pkgs: []string{"p"}}, events(ev("pass", "TestA")), ""},
		{"fail", Test{Name: "TestA", Pkgs: []string{"p"}}, events(ev("fail", "TestA")), "test-failed:p TestA"},
		{"skip", Test{Name: "TestA", Pkgs: []string{"p"}}, events(ev("skip", "TestA")), "test-skipped:p TestA"},
		{"subtest skipped", Test{Name: "TestA", Pkgs: []string{"p"}}, events(ev("skip", "TestA/x"), ev("pass", "TestA")), "test-skipped:p TestA"},
		{"absent", Test{Name: "TestA", Pkgs: []string{"p"}}, events(`{"Action":"output","Output":"testing: warning: no tests to run\n"}`), "test-missing:p TestA"},
		{"build failure", Test{Name: "TestA", Pkgs: []string{"p"}}, []byte("# p\nx.go:1: syntax error\n"), "test-missing:p TestA"},
		{"required subtest present", Test{Name: "TestA", Pkgs: []string{"p"}, Subtests: []string{"d1"}}, events(ev("pass", "TestA/d1"), ev("pass", "TestA")), ""},
		{"required subtest absent", Test{Name: "TestA", Pkgs: []string{"p"}, Subtests: []string{"d1", "d2"}}, events(ev("pass", "TestA/d1"), ev("pass", "TestA")), "subtest-missing:p TestA/d2"},
		{"required subtest skipped", Test{Name: "TestA", Pkgs: []string{"p"}, Subtests: []string{"d1"}}, events(ev("skip", "TestA/d1"), ev("pass", "TestA")), "subtest-skip:p TestA/d1"},
	}
	for _, c := range tt {
		t.Run(c.name, func(t *testing.T) {
			fs, err := Run(context.Background(), ".", []Test{c.test}, runFixed(c.out))
			if err != nil {
				t.Fatal(err)
			}
			if got := kinds(fs); got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestMissingNamesTheTest(t *testing.T) {
	fs, _ := Run(context.Background(), ".", []Test{{Check: "RP5", Name: "Test_export_digest_equals_run_digest", Pkgs: []string{"./x"}, What: "w"}}, runFixed(nil))
	if len(fs) != 1 || !strings.Contains(fs[0].String(), "Test_export_digest_equals_run_digest") || !strings.Contains(fs[0].String(), "RP5") {
		t.Fatalf("%v", fs)
	}
}
