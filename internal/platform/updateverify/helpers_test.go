package updateverify

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

type tkey struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
	id   string
}

func newKey(t *testing.T) tkey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return tkey{priv, pub, keyID(pub)}
}

type roleSpec struct {
	keys      []tkey
	threshold int
}

type rootSpec struct {
	version uint64
	roles   map[string]roleSpec
	expires time.Time
	signers []tkey // keys that sign this root file
}

func marshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func sign(t *testing.T, signed any, signers ...tkey) []byte {
	t.Helper()
	raw := marshal(t, signed)
	var sigs []signature
	for _, k := range signers {
		sigs = append(sigs, signature{KeyID: k.id, Sig: base64.StdEncoding.EncodeToString(ed25519.Sign(k.priv, raw))})
	}
	return marshal(t, struct {
		Signed     jsontext.Value `json:"signed"`
		Signatures []signature    `json:"signatures"`
	}{raw, sigs})
}

func mkRoot(t *testing.T, s rootSpec) []byte {
	t.Helper()
	r := rootSigned{header: header{Type: RoleRoot, Version: s.version, Issued: t0.Add(-time.Hour), Expires: s.expires}, Keys: map[string]keyEntry{}, Roles: map[string]roleEntry{}}
	if s.expires.IsZero() {
		r.Expires = t0.Add(365 * 24 * time.Hour)
	}
	for name, rs := range s.roles {
		var ids []string
		for _, k := range rs.keys {
			r.Keys[k.id] = keyEntry{KeyType: keyTypeEd25519, Public: base64.StdEncoding.EncodeToString(k.pub)}
			ids = append(ids, k.id)
		}
		r.Roles[name] = roleEntry{KeyIDs: ids, Threshold: rs.threshold}
	}
	return sign(t, r, s.signers...)
}

// world is a release train fixture.
type world struct {
	t                    *testing.T
	root, ts, sn, tg     tkey
	rootK                []tkey
	artefact             []byte
	rootRaw              []byte
	issued               time.Time
	tsV, snV, tgV, rootV uint64
	tsExp, snExp, tgExp  time.Time
	rel                  Release
}

func newWorld(t *testing.T) *world {
	w := &world{t: t, root: newKey(t), ts: newKey(t), sn: newKey(t), tg: newKey(t), artefact: []byte("activediq-1.6-binary-bytes"),
		issued: t0.Add(-time.Hour), tsV: 5, snV: 5, tgV: 5, rootV: 1,
		tsExp: t0.Add(72 * time.Hour), snExp: t0.Add(7 * 24 * time.Hour), tgExp: t0.Add(30 * 24 * time.Hour)}
	w.rootK = []tkey{w.root, newKey(t), newKey(t)}
	w.rel = w.release("1.6")
	w.rootRaw = mkRoot(t, rootSpec{version: 1, roles: map[string]roleSpec{
		RoleRoot: {w.rootK, 2}, RoleTimestamp: {[]tkey{w.ts}, 1}, RoleSnapshot: {[]tkey{w.sn}, 1}, RoleTargets: {[]tkey{w.tg}, 1}}, signers: w.rootK[:2]})
	return w
}

func (w *world) release(ver string) Release {
	h := sha256.Sum256(w.artefact)
	return Release{Name: "server", Platform: "windows", ProductVersion: ver, Length: int64(len(w.artefact)), SHA256: hex.EncodeToString(h[:])}
}

func ref(raw []byte, v uint64) fileRef {
	h := sha256.Sum256(raw)
	return fileRef{Version: v, Length: int64(len(raw)), SHA256: hex.EncodeToString(h[:])}
}

// input signs a full metadata set for w's current state.
func (w *world) input() Input {
	t := w.t
	tg := sign(t, targetsSigned{header{RoleTargets, w.tgV, w.issued, w.tgExp}, []Release{w.rel}}, w.tg)
	sn := sign(t, snapshotSigned{header{RoleSnapshot, w.snV, w.issued, w.snExp}, w.rootV, ref(tg, w.tgV)}, w.sn)
	ts := sign(t, timestampSigned{header{RoleTimestamp, w.tsV, w.issued, w.tsExp}, ref(sn, w.snV)}, w.ts)
	return Input{Timestamp: ts, Snapshot: sn, Targets: tg, Artifact: bytesReader(w.artefact)}
}

func (w *world) verifier(floor FloorStore, q Quarantine) *Verifier {
	v, err := New(Config{PinnedRoot: w.rootRaw, Floor: floor, Quarantine: q, Name: "server", Platform: "windows", NoPlatformCheck: true, Now: func() time.Time { return t0 }})
	if err != nil {
		w.t.Fatal(err)
	}
	return v
}
