package main

import (
	"bytes"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/updateverify"
)

var epoch = time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)

// scenarios is the TM-F-UPDATE matrix of threat-model section 10 and ENH-07 AC-1..AC-8: the rejected
// cases (tampered artefact, tampered manifest, revoked key, rollback, freeze, server-signed) and the
// accepted ones (a plain release, a root rotation signed by the old threshold).
func scenarios() []scenario {
	var out []scenario
	add := func(s scenario) { out = append(out, s) }
	base := func(t *train) payload {
		ts, sn, tg := t.metadata(t.release())
		return payload{ts: ts, sn: sn, tg: tg, artefact: t.artefact}
	}
	mk := func(id, ac string, want updateverify.Reason, t *train, p payload) scenario {
		return scenario{id: id, ac: ac, want: want, pinned: t.pinned, payload: p, now: t.now, wantVersion: t.version}
	}

	{ // accepted baseline
		t := newTrain(epoch)
		add(mk("accept-signed-release", "AC-8", "", t, base(t)))
	}
	{ // AC-1: one byte of the artefact changed
		t := newTrain(epoch)
		p := base(t)
		p.artefact = bytes.Clone(t.artefact)
		p.artefact[len(p.artefact)/2] ^= 0x01
		add(mk("tamper-artefact-one-byte", "AC-1", updateverify.ReasonTamper, t, p))
	}
	{ // AC-2: manifest hash modified (the manifest is validly signed, the artefact is not what it names)
		t := newTrain(epoch)
		rel := t.release()
		rel.SHA256 = sum([]byte("some other artefact"))
		p := base(t)
		p.ts, p.sn, p.tg = t.metadata(rel)
		add(mk("tamper-manifest-hash", "AC-2", updateverify.ReasonTamper, t, p))
	}
	{ // AC-2: manifest length modified
		t := newTrain(epoch)
		rel := t.release()
		rel.Length++
		p := base(t)
		p.ts, p.sn, p.tg = t.metadata(rel)
		add(mk("tamper-manifest-length", "AC-2", updateverify.ReasonTamper, t, p))
	}
	{ // AC-2: artefact far longer than its signed length is aborted mid-stream
		t := newTrain(epoch)
		t.artefact = bytes.Repeat([]byte{0xAB}, 8<<20)
		rel := t.release()
		rel.Length, rel.SHA256 = 1024, sum(t.artefact[:1024])
		p := base(t)
		p.ts, p.sn, p.tg = t.metadata(rel)
		s := mk("tamper-overlong-artefact", "AC-2", updateverify.ReasonTamper, t, p)
		s.maxArtefact = 1 << 20
		add(s)
	}
	{ // AC-1/2: the signed manifest edited after signing
		t := newTrain(epoch)
		p := base(t)
		p.tg = bytes.Clone(p.tg)
		i := bytes.Index(p.tg, []byte(`"windows"`))
		p.tg[i+1] = 'W'
		add(mk("tamper-metadata-after-signing", "AC-2", updateverify.ReasonTamper, t, p))
	}
	{ // AC-3: metadata signed by a key a later root removed
		t := newTrain(epoch)
		newTg := newKey()
		root2 := rootFile(2, t.now, t.rolesFor(t.rootKeys, t.ts, t.sn, newTg), t.rootKeys[0], t.rootKeys[1])
		t.rootV = 2
		p := base(t) // targets signed by the old, now revoked, targets key
		p.chain = [][]byte{root2}
		add(mk("revoked-key-signs-targets", "AC-3", updateverify.ReasonRevokedKey, t, p))
	}
	{ // AC-4: an older signed release offered after 1.6 committed
		t := newTrain(epoch)
		t.version = "1.5"
		s := mk("rollback-older-release", "AC-4", updateverify.ReasonRollback, t, base(t))
		s.floor = updateverify.Floor{Committed: "1.6"}
		add(s)
	}
	{ // AC-4: older metadata
		t := newTrain(epoch)
		s := mk("rollback-older-metadata", "AC-4", updateverify.ReasonRollback, t, base(t))
		s.floor = updateverify.Floor{Timestamp: 9}
		add(s)
	}
	{ // AC-4: the database half of the floor restored from a pre-1.6 backup; the host half still holds 1.6
		t := newTrain(epoch)
		t.version = "1.5"
		s := mk("rollback-after-database-restore", "AC-4", updateverify.ReasonRollback, t, base(t))
		s.hostFloor = &updateverify.Floor{Committed: "1.6"}
		add(s)
	}
	for _, role := range []string{"timestamp", "snapshot", "targets"} { // AC-5: freeze
		t := newTrain(epoch)
		switch role {
		case "timestamp":
			t.tsExp = epoch.Add(-time.Minute)
		case "snapshot":
			t.snExp = epoch.Add(-time.Minute)
		default:
			t.tgExp = epoch.Add(-time.Minute)
		}
		s := mk("freeze-expired-"+role, "AC-5", updateverify.ReasonFreeze, t, base(t))
		s.wantExpiry = true
		add(s)
	}
	{ // AC-5: system clock earlier than the newest verified signing time
		t := newTrain(epoch)
		s := mk("freeze-clock-rewound", "AC-5", updateverify.ReasonFreeze, t, base(t))
		s.floor = updateverify.Floor{NewestSigning: epoch.Add(24 * time.Hour)}
		add(s)
	}

	// AC-6: root rotation. The new root has all-new keys.
	rotate := func(t *train, signers func(old, nw []key) []key) (nw []key, nts, nsn, ntg key, root2 []byte) {
		nw = []key{newKey(), newKey(), newKey()}
		nts, nsn, ntg = newKey(), newKey(), newKey()
		root2 = rootFile(2, t.now, t.rolesFor(nw, nts, nsn, ntg), signers(t.rootKeys, nw)...)
		return
	}
	{
		t := newTrain(epoch)
		_, nts, nsn, ntg, root2 := rotate(t, func(o, n []key) []key { return []key{o[0], o[1], n[0], n[1]} })
		t.rootV, t.ts, t.sn, t.tg = 2, nts, nsn, ntg
		p := base(t) // the next release is signed by the new keys
		p.chain = [][]byte{root2}
		add(mk("rotation-signed-by-old-threshold-accepted", "AC-6", "", t, p))
	}
	{
		t := newTrain(epoch)
		_, nts, nsn, ntg, root2 := rotate(t, func(o, n []key) []key { return []key{o[0], n[0], n[1]} }) // 1 of 2 old
		t.rootV, t.ts, t.sn, t.tg = 2, nts, nsn, ntg
		p := base(t)
		p.chain = [][]byte{root2}
		add(mk("rotation-below-old-threshold", "AC-6", updateverify.ReasonUnsignedByRoot, t, p))
	}
	{
		t := newTrain(epoch)
		_, nts, nsn, ntg, root2 := rotate(t, func(o, n []key) []key { return []key{o[0], o[1]} }) // new keys did not sign
		t.rootV, t.ts, t.sn, t.tg = 2, nts, nsn, ntg
		p := base(t)
		p.chain = [][]byte{root2}
		add(mk("rotation-not-signed-by-new-keys", "AC-6", updateverify.ReasonUnsignedByRoot, t, p))
	}
	{ // AC-7: an artefact signed only by the server's own key
		t := newTrain(epoch)
		p := base(t)
		p.ts, p.sn, p.tg = t.metadata(t.release(), t.server)
		add(mk("server-key-signs-targets", "AC-7", updateverify.ReasonUnsignedByRoot, t, p))
	}
	{ // AC-7: the compromised server supplies its own root and signs the whole chain with it
		t := newTrain(epoch)
		sk := []key{t.server, newKey(), newKey()}
		evil := rootFile(2, t.now, t.rolesFor(sk, t.server, t.server, t.server), sk[0], sk[1])
		p := base(t)
		p.chain = [][]byte{evil}
		add(mk("server-supplied-root", "AC-7", updateverify.ReasonUnsignedByRoot, t, p))
	}
	{ // AC-7: a release withdrawn in the signed targets
		t := newTrain(epoch)
		rel := t.release()
		rel.Withdrawn = true
		p := base(t)
		p.ts, p.sn, p.tg = t.metadata(rel)
		add(mk("withdrawn-release", "AC-7", updateverify.ReasonWithdrawn, t, p))
	}
	return out
}
