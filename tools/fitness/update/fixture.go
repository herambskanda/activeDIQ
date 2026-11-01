package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// The fixture signs a release train with throw-away keys generated per run (nothing is committed).
// The JSON shapes are those of the ENH-07 metadata the verifier documents (internal/platform/updateverify
// metadata.go and doc.go); building them here, outside the package, is deliberate: the proof drives
// the verifier only through its exported surface, exactly as a courier does.

type key struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
	id   string
}

func newKey() key {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	h := sha256.Sum256(pub)
	return key{priv, pub, hex.EncodeToString(h[:])}
}

type header struct {
	Type    string    `json:"type"`
	Version uint64    `json:"version"`
	Issued  time.Time `json:"issued"`
	Expires time.Time `json:"expires"`
}

type keyEntry struct {
	KeyType string `json:"keytype"`
	Public  string `json:"public"`
}
type roleEntry struct {
	KeyIDs    []string `json:"keyids"`
	Threshold int      `json:"threshold"`
}
type rootBody struct {
	header
	Keys  map[string]keyEntry  `json:"keys"`
	Roles map[string]roleEntry `json:"roles"`
}
type fileRef struct {
	Version uint64 `json:"version"`
	Length  int64  `json:"length"`
	SHA256  string `json:"sha256"`
}
type timestampBody struct {
	header
	Snapshot fileRef `json:"snapshot"`
}
type snapshotBody struct {
	header
	RootVersion uint64  `json:"root_version"`
	Targets     fileRef `json:"targets"`
}
type release struct {
	Name           string `json:"name"`
	ProductVersion string `json:"product_version"`
	Platform       string `json:"platform"`
	Length         int64  `json:"length"`
	SHA256         string `json:"sha256"`
	Withdrawn      bool   `json:"withdrawn,omitempty"`
}
type targetsBody struct {
	header
	Releases []release `json:"releases"`
}

// signed wraps body in the {"signed","signatures"} envelope; each signer signs the exact bytes of "signed".
func signed(body any, signers ...key) []byte {
	raw, err := json.Marshal(body)
	if err != nil {
		panic(err)
	}
	type sig struct {
		KeyID string `json:"keyid"`
		Sig   string `json:"sig"`
	}
	var sigs []sig
	for _, k := range signers {
		sigs = append(sigs, sig{k.id, base64.StdEncoding.EncodeToString(ed25519.Sign(k.priv, raw))})
	}
	out, err := json.Marshal(struct {
		Signed     json.RawMessage `json:"signed"`
		Signatures []sig           `json:"signatures"`
	}{raw, sigs})
	if err != nil {
		panic(err)
	}
	return out
}

type roleKeys struct {
	keys      []key
	threshold int
}

func rootFile(version uint64, now time.Time, roles map[string]roleKeys, signers ...key) []byte {
	b := rootBody{header: header{"root", version, now.Add(-time.Hour), now.Add(365 * 24 * time.Hour)},
		Keys: map[string]keyEntry{}, Roles: map[string]roleEntry{}}
	for name, rk := range roles {
		var ids []string
		for _, k := range rk.keys {
			b.Keys[k.id] = keyEntry{"ed25519", base64.StdEncoding.EncodeToString(k.pub)}
			ids = append(ids, k.id)
		}
		b.Roles[name] = roleEntry{ids, rk.threshold}
	}
	return signed(b, signers...)
}

func ref(raw []byte, v uint64) fileRef {
	h := sha256.Sum256(raw)
	return fileRef{v, int64(len(raw)), hex.EncodeToString(h[:])}
}

func sum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// train is one release train: the keys the pinned root names and the metadata a release is described by.
type train struct {
	now                  time.Time
	rootKeys             []key // 3 keys, threshold 2
	ts, sn, tg           key
	server               key // the server's own key: never in the root
	pinned               []byte
	artefact             []byte
	version              string
	rootV, tsV, snV, tgV uint64
	tsExp, snExp, tgExp  time.Time
	issued               time.Time
}

func newTrain(now time.Time) *train {
	t := &train{now: now, rootKeys: []key{newKey(), newKey(), newKey()}, ts: newKey(), sn: newKey(), tg: newKey(), server: newKey(),
		artefact: []byte("activediq-server-1.6-windows-artefact-bytes"), version: "1.6",
		rootV: 1, tsV: 5, snV: 5, tgV: 5, issued: now.Add(-time.Hour),
		tsExp: now.Add(72 * time.Hour), snExp: now.Add(7 * 24 * time.Hour), tgExp: now.Add(30 * 24 * time.Hour)}
	t.pinned = rootFile(1, now, t.rolesFor(t.rootKeys, t.ts, t.sn, t.tg), t.rootKeys[0], t.rootKeys[1])
	return t
}

func (t *train) rolesFor(rk []key, ts, sn, tg key) map[string]roleKeys {
	return map[string]roleKeys{"root": {rk, 2}, "timestamp": {[]key{ts}, 1}, "snapshot": {[]key{sn}, 1}, "targets": {[]key{tg}, 1}}
}

func (t *train) release() release {
	return release{Name: "server", ProductVersion: t.version, Platform: "windows", Length: int64(len(t.artefact)), SHA256: sum(t.artefact)}
}

// metadata signs timestamp, snapshot and targets for rel with the given targets signer(s).
func (t *train) metadata(rel release, tgSigners ...key) (ts, sn, tg []byte) {
	if len(tgSigners) == 0 {
		tgSigners = []key{t.tg}
	}
	tg = signed(targetsBody{header{"targets", t.tgV, t.issued, t.tgExp}, []release{rel}}, tgSigners...)
	sn = signed(snapshotBody{header{"snapshot", t.snV, t.issued, t.snExp}, t.rootV, ref(tg, t.tgV)}, t.sn)
	ts = signed(timestampBody{header{"timestamp", t.tsV, t.issued, t.tsExp}, ref(sn, t.snV)}, t.ts)
	return
}

func describe(r release) string { return fmt.Sprintf("%s %s/%s", r.ProductVersion, r.Name, r.Platform) }
