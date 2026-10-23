package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit/chain"
)

// writeExport builds a signed three-event chain and writes it, returning the path and key fingerprint.
func writeExport(t *testing.T, mutate func(*chain.Bundle)) (string, string) {
	t.Helper()
	tenant := [16]byte{15: 9}
	pub, priv, _ := ed25519.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{7}, 64)))
	prev := chain.Genesis(tenant)
	var evs []chain.StoredEvent
	add := func(kind string, d ...chain.Detail) {
		seq := uint64(len(evs) + 1)
		raw, err := chain.Envelope{Tenant: tenant, Seq: seq, At: time.Unix(1e9, 0), Kind: kind, KindVersion: 1,
			Requester: chain.Principal{ID: "p", Kind: "human"}, Outcome: "success", Details: d}.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		h := chain.Link(tenant, seq, prev, chain.BodyHash(raw))
		evs = append(evs, chain.StoredEvent{Seq: seq, Envelope: raw, PrevHash: prev, Hash: h})
		prev = h
	}
	add(chain.KindKeyCreated, chain.Detail{Key: "key_id", Value: chain.Fingerprint(pub)}, chain.Detail{Key: "public_key", Value: hex.EncodeToString(pub)})
	add("a")
	add("b")
	cp := chain.Checkpoint{Tenant: tenant, Seq: 3, Hash: prev, SignedAt: time.Unix(1e9, 0), KeyID: chain.Fingerprint(pub)}
	if err := cp.Sign(priv); err != nil {
		t.Fatal(err)
	}
	b := chain.Bundle{Tenant: chain.FormatUUID(tenant), FromSeq: 1, ToSeq: 3, Events: evs, Checkpoints: []chain.Checkpoint{cp}}
	if mutate != nil {
		mutate(&b)
	}
	p := filepath.Join(t.TempDir(), "export.json")
	f, _ := os.Create(p)
	defer f.Close()
	if err := chain.WriteBundle(f, b); err != nil {
		t.Fatal(err)
	}
	return p, chain.Fingerprint(pub)
}

func exec(args ...string) (int, string) {
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String() + errb.String()
}

func TestExitCodes(t *testing.T) {
	p, fp := writeExport(t, nil)
	if code, out := exec("-bundle", p, "-pin", fp); code != 0 || !strings.HasPrefix(out, "OK") {
		t.Fatalf("pinned = %d %q", code, out)
	}
	if code, out := exec("-bundle", p); code != 2 || !strings.HasPrefix(out, "UNANCHORED") {
		t.Fatalf("unpinned = %d %q", code, out)
	}
	if code, _ := exec("-bundle", p, "-pin", strings.Repeat("0", 64)); code != 1 {
		t.Fatalf("wrong pin = %d; want 1", code)
	}
	if code, _ := exec(); code != 64 {
		t.Fatalf("no args = %d; want 64", code)
	}
	if code, _ := exec("-bundle", filepath.Join(t.TempDir(), "missing")); code != 64 {
		t.Fatalf("missing file = %d; want 64", code)
	}
}

// Acceptance 2: an edited, deleted or reordered event fails verification.
func TestEditedDeletedReorderedEventsFail(t *testing.T) {
	for name, mutate := range map[string]func(*chain.Bundle){
		"edited":    func(b *chain.Bundle) { b.Events[1].Envelope[len(b.Events[1].Envelope)-1] ^= 1 },
		"deleted":   func(b *chain.Bundle) { b.Events = append(b.Events[:1], b.Events[2:]...) },
		"reordered": func(b *chain.Bundle) { b.Events[1], b.Events[2] = b.Events[2], b.Events[1] },
		// The newest event and its checkpoint cut off, the manifest left alone and then rewritten to match.
		"tail deleted":              func(b *chain.Bundle) { b.Events, b.Checkpoints = b.Events[:2], nil },
		"tail deleted, range fixed": func(b *chain.Bundle) { b.Events, b.Checkpoints, b.ToSeq = b.Events[:2], nil, 2 },
		"tail deleted, no events":   func(b *chain.Bundle) { b.Events, b.Checkpoints, b.ToSeq = nil, nil, 0; b.FromSeq = 2 },
	} {
		p, fp := writeExport(t, mutate)
		code, out := exec("-bundle", p, "-pin", fp)
		if code != 1 || !strings.HasPrefix(out, "FAILED at seq") {
			t.Errorf("%s: %d %q; want FAILED", name, code, out)
		}
	}
}
