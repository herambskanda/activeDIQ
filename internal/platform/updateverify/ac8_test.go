package updateverify

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// courierFixtures deliver the same signed release two ways and hand the verifier an Input through the
// one entry point. Real couriers are T-0139's; the fixtures prove the verifier cannot tell them apart.
func onlineInput(t *testing.T, w *world) Input {
	in := w.input()
	files := map[string][]byte{"/ts": in.Timestamp, "/sn": in.Snapshot, "/tg": in.Targets, "/artefact": w.artefact}
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		b, ok := files[r.URL.Path]
		if !ok {
			http.NotFound(rw, r)
			return
		}
		_, _ = rw.Write(b)
	}))
	t.Cleanup(srv.Close)
	get := func(p string) []byte {
		resp, err := http.Get(srv.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return b
	}
	resp, err := http.Get(srv.URL + "/artefact")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return Input{Timestamp: get("/ts"), Snapshot: get("/sn"), Targets: get("/tg"), Artifact: resp.Body}
}

func offlineInput(t *testing.T, w *world) Input {
	in := w.input()
	type bundle struct {
		TS, SN, TG, Art []byte
	}
	raw, err := json.Marshal(bundle{in.Timestamp, in.Snapshot, in.Targets, w.artefact})
	if err != nil {
		t.Fatal(err)
	}
	var b bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	return Input{Timestamp: b.TS, Snapshot: b.SN, Targets: b.TG, Artifact: bytes.NewReader(b.Art)}
}

func TestAC8SameVerifierBothCouriers(t *testing.T) {
	var hashes, versions []string
	for _, mk := range []func(*testing.T, *world) Input{onlineInput, offlineInput} {
		w, fl, q := setup(t)
		v := w.verifier(fl, DirQuarantine{q})
		res, err := v.Verify(context.Background(), mk(t, w))
		if err != nil {
			t.Fatal(err)
		}
		if err := v.Commit(context.Background(), res); err != nil {
			t.Fatal(err)
		}
		hashes = append(hashes, res.Release.SHA256)
		versions = append(versions, fl.F.Committed)
	}
	if hashes[0] != hashes[1] || versions[0] != versions[1] || versions[0] != "1.6" {
		t.Fatalf("couriers diverged: %v %v", hashes, versions)
	}
}

// TestAC8NoSecondVerifier fails if a non-test Go file outside this package verifies TUF-style update
// metadata itself (Ed25519 verification together with the snapshot and targets role names).
func TestAC8NoSecondVerifier(t *testing.T) {
	root := "../../.."
	self, _ := filepath.Abs(".")
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "web", "knowledge", "factory":
				return fs.SkipDir
			}
			if abs, _ := filepath.Abs(p); abs == self {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		s := string(b)
		if strings.Contains(s, "ed25519.Verify") && strings.Contains(s, `"snapshot"`) && strings.Contains(s, `"targets"`) {
			t.Errorf("%s looks like a second update verifier; use updateverify.Verifier", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
