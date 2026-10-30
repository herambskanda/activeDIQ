package ownerfile

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestOpenAppendCreatesOwnerOnly(t *testing.T) {
	p := filepath.Join(t.TempDir(), "b.jsonl")
	f, corrected, err := OpenAppend(p)
	if err != nil || corrected {
		t.Fatal(corrected, err)
	}
	_, _ = f.WriteString("x\n")
	_ = f.Close()
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v", st.Mode())
		}
	}
}

// AC2: an existing wider file is corrected at open, and the content is preserved.
func TestOpenAppendCorrectsWiderExistingFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("covered by TestWindowsDACL")
	}
	p := filepath.Join(t.TempDir(), "b.jsonl")
	if err := os.WriteFile(p, []byte("old\n"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o666); err != nil {
		t.Fatal(err)
	}
	f, corrected, err := OpenAppend(p)
	if err != nil || !corrected {
		t.Fatal(corrected, err)
	}
	_ = f.Close()
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	if b, _ := os.ReadFile(p); string(b) != "old\n" {
		t.Fatalf("content %q", b)
	}
	if _, c, _ := OpenAppend(p); c {
		t.Fatal("second open must not report a correction")
	}
}
