package agent

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/agentpolicy"
	"github.com/skenzeriq/activediq/internal/platform/fleet"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

func mustTenant(s string) tenant.ID {
	id, err := tenant.Parse(s)
	if err != nil {
		panic(err)
	}
	return id
}

var (
	tidA = mustTenant("11111111-1111-4111-8111-111111111111")
	tidB = mustTenant("22222222-2222-4222-8222-222222222222")
)

func idOf(t tenant.ID, comp string) fleet.Identity {
	return fleet.Identity{Tenant: t, Kind: fleet.KindADDC, ComponentID: comp}
}

const compA = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
const compB = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"

func TestStateRoundTripAndReenrol(t *testing.T) {
	dir := t.TempDir()
	st := NewStateStore(dir)
	v, err := st.Load(idOf(tidA, compA))
	if err != nil || v.PolicySeq() != 0 {
		t.Fatalf("fresh: %v", err)
	}
	if err := st.Save(idOf(tidA, compA), v); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Load(idOf(tidA, compA)); err != nil {
		t.Fatalf("reload: %v", err)
	}
	// Another tenant's state is never used.
	if _, err := st.Load(idOf(tidB, compA)); err != nil {
		t.Fatalf("other tenant: %v", err)
	}
	// A new component ID is a re-enrolment: it must load, with the anchor reset.
	v2, err := st.Load(idOf(tidA, compB))
	if err != nil {
		t.Fatalf("re-enrol: %v", err)
	}
	if v2.KeysetSeq() != 0 {
		t.Fatal("anchor survived re-enrolment")
	}
}

func TestCorruptStateIsSetAsideNotFatal(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, stateFile), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	v, err := NewStateStore(dir).Load(idOf(tidA, compA))
	if !errors.Is(err, ErrStateCorrupt) || v == nil {
		t.Fatalf("got %v, %v", v, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "policy-state.corrupt")); err != nil {
		t.Fatal("bad file not kept for the administrator")
	}
	if _, err := NewStateStore(dir).Load(idOf(tidA, compA)); err != nil {
		t.Fatalf("second load after set-aside: %v", err)
	}
}

func TestBlobNamesCannotBePaths(t *testing.T) {
	b, err := NewBlobs(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"", "../x", "a/b", `a\b`, "A", "x.blob", "a b"} {
		if b.Save(n, []byte("x")) == nil {
			t.Errorf("name %q accepted", n)
		}
	}
	if err := b.Save("bookmark", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if got, _ := b.Load("bookmark"); string(got) != "x" {
		t.Fatalf("got %q", got)
	}
	if err := b.Save("big", make([]byte, MaxBlobBytes+1)); err == nil {
		t.Fatal("oversize blob accepted")
	}
}

func TestCheckPrivileges(t *testing.T) {
	if err := CheckPrivileges([]string{"SeChangeNotifyPrivilege"}); err != nil {
		t.Fatal(err)
	}
	err := CheckPrivileges([]string{"SeChangeNotifyPrivilege", "SeDebugPrivilege", "SeBackupPrivilege", "SeDebugPrivilege"})
	if !errors.Is(err, ErrPrivileges) {
		t.Fatalf("got %v", err)
	}
	if want := "SeBackupPrivilege, SeDebugPrivilege"; !contains(err.Error(), want) {
		t.Fatalf("error %q should name %q once each", err, want)
	}
	_ = agentpolicy.KindADDC
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }
