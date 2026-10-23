package chain

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Status is the verifier's verdict.
type Status string

// Verdicts. UNANCHORED is never OK: without a pinned key fingerprint or an external anchor, anyone
// holding an export could have rebuilt and re-signed the chain (ADR-0005 rule 11).
const (
	OK         Status = "OK"
	Unanchored Status = "UNANCHORED"
	Failed     Status = "FAILED"
)

// Reason codes of a failure.
const (
	ReasonFormat           = "bad_format"
	ReasonNonCanonical     = "non_canonical"
	ReasonWrongTenant      = "wrong_tenant"
	ReasonSeqGap           = "seq_gap"
	ReasonSeqOrder         = "seq_order"
	ReasonPrevHash         = "prev_hash_mismatch"
	ReasonHash             = "hash_mismatch"
	ReasonNoStart          = "no_start_point"
	ReasonKeyEvent         = "key_event_invalid"
	ReasonKeyMismatch      = "key_window_mismatch"
	ReasonUnknownKey       = "unknown_key"
	ReasonKeyWindow        = "key_outside_window"
	ReasonBadSignature     = "bad_signature"
	ReasonCheckpointHash   = "checkpoint_hash_mismatch"
	ReasonCheckpointChain  = "checkpoint_chain_broken"
	ReasonAnchorMismatch   = "anchor_mismatch"
	ReasonPinnedKeyAbsent  = "pinned_key_absent"
	ReasonCheckpointTenant = "checkpoint_wrong_tenant"
	ReasonTruncated        = "truncated"
	ReasonUntrustedKey     = "untrusted_key"
	ReasonPinWindow        = "pin_window"
)

// Options carries the trust root.
type Options struct {
	// Pinned are key fingerprints recorded out of band. At least one must have signed a verified
	// checkpoint.
	Pinned []string
	// PinWindows optionally scopes a pinned fingerprint to the key's window (created and retired seq,
	// retired 0 = open). A bundle whose window for that key differs fails. The manifest of a truncated
	// export is written by the exporter, so only a window the operator recorded can refute it.
	PinWindows map[string]PinWindow
	// Anchors are checkpoints received from outside the host (a SIEM). Each one that falls in the
	// verified range must match the chain.
	Anchors []Checkpoint
}

// PinWindow is the key window an operator recorded with a pin: CreatedSeq must equal the bundle's, and
// RetiredSeq, when non-zero, must equal the seq of the retirement.
type PinWindow struct{ CreatedSeq, RetiredSeq uint64 }

// ParsePin splits "FINGERPRINT" or "FINGERPRINT@created-retired" ("@12-" leaves the retirement open).
func ParsePin(s string) (string, *PinWindow, error) {
	fp, win, has := strings.Cut(strings.ToLower(strings.TrimSpace(s)), "@")
	if fp == "" {
		return "", nil, fmt.Errorf("pin %q has no fingerprint", s)
	}
	if !has {
		return fp, nil, nil
	}
	lo, hi, ok := strings.Cut(win, "-")
	c, err1 := strconv.ParseUint(lo, 10, 64)
	var r uint64
	var err2 error
	if hi != "" {
		r, err2 = strconv.ParseUint(hi, 10, 64)
	}
	if !ok || err1 != nil || err2 != nil || c == 0 || (hi != "" && r <= c) {
		return "", nil, fmt.Errorf("pin %q: window must be @created-retired or @created-, with created >= 1 and retired > created", s)
	}
	return fp, &PinWindow{CreatedSeq: c, RetiredSeq: r}, nil
}

// Result is the verdict with enough to act on.
type Result struct {
	Status Status
	// Seq is the first failing seq when Status is Failed.
	Seq    uint64
	Reason string
	Detail string
	// Events and Checkpoints count what was verified.
	Events      int
	Checkpoints int
	// TailUnsigned counts events after the last verified checkpoint: nothing signed covers them.
	TailUnsigned uint64
}

func fail(seq uint64, reason, format string, a ...any) Result {
	return Result{Status: Failed, Seq: seq, Reason: reason, Detail: fmt.Sprintf(format, a...)}
}

type keyWin struct {
	pub     ed25519.PublicKey
	created uint64
	retired uint64 // 0: current
	vouched bool   // already cross-signed a successor
	// fromManifest: the window came from the manifest. chainRet is the seq of the key.retired event
	// actually seen in the chain (0: none); the rotation-shape check trusts only that.
	fromManifest bool
	chainRet     uint64
	// crossBy is the key whose valid cross-signature introduced this one ("" if none).
	crossBy string
}

// Verify checks a bundle against opts. It reads nothing but its arguments.
func Verify(b Bundle, opts Options) Result {
	if b.Format != BundleFormat {
		return fail(0, ReasonFormat, "format %q is not %s", b.Format, BundleFormat)
	}
	tenant, err := ParseUUID(b.Tenant)
	if err != nil {
		return fail(0, ReasonFormat, "tenant is not a UUID")
	}
	if err := checkPinWindows(opts.PinWindows); err != nil {
		return fail(0, ReasonPinWindow, "%v", err)
	}
	keys := map[string]*keyWin{}
	var prev Hash
	var first, last uint64
	// The manifest's range is part of what is verified: the events must be exactly FromSeq..ToSeq, so
	// that deleting the newest events (or all of them) cannot go unnoticed.
	from := b.FromSeq
	if from == 0 {
		from = 1
	}
	if len(b.Events) == 0 {
		if b.ToSeq != 0 || from > 1 {
			return fail(from, ReasonTruncated, "the export claims seq %d..%d but carries no events", from, b.ToSeq)
		}
	} else {
		first = b.Events[0].Seq
		if first != from {
			return fail(from, ReasonSeqGap, "the export claims to start at seq %d but starts at %d", from, first)
		}
	}

	// Starting point: genesis, or a signed checkpoint just below the first retained event.
	boundary := map[uint64]Checkpoint{}
	for _, c := range b.Checkpoints {
		boundary[c.Seq] = c
	}
	switch {
	case len(b.Events) == 0:
	case first == 1:
		prev = Genesis(tenant)
	default:
		c, ok := boundary[first-1]
		if !ok || first < 2 {
			return fail(first, ReasonNoStart, "the export starts at seq %d with no genesis and no checkpoint at seq %d", first, first-1)
		}
		prev = c.Hash
	}

	// The manifest lists keys whose introduction lies before the retained range.
	for _, k := range b.Keys {
		pub := k.key()
		if pub == nil || Fingerprint(pub) != k.KeyID {
			return fail(0, ReasonKeyMismatch, "manifest key %q is malformed", k.KeyID)
		}
		keys[k.KeyID] = &keyWin{pub: pub, created: k.CreatedSeq, retired: k.RetiredSeq, fromManifest: true}
	}
	chainKeys := map[string]bool{}
	for _, c := range b.Checkpoints {
		if c.Seq > b.ToSeq {
			return fail(c.Seq, ReasonTruncated, "checkpoint at seq %d lies beyond the export's last seq %d", c.Seq, b.ToSeq)
		}
	}

	hashAt := map[uint64]Hash{}
	if first > 1 {
		hashAt[first-1] = prev
	}
	expect := first
	for _, ev := range b.Events {
		env, err := ParseEnvelope(ev.Envelope)
		if err != nil {
			return fail(ev.Seq, ReasonNonCanonical, "%v", err)
		}
		if env.Tenant != tenant {
			return fail(ev.Seq, ReasonWrongTenant, "event belongs to tenant %s", FormatUUID(env.Tenant))
		}
		if env.Seq != expect {
			if env.Seq > expect {
				return fail(expect, ReasonSeqGap, "expected seq %d, found %d", expect, env.Seq)
			}
			return fail(expect, ReasonSeqOrder, "expected seq %d, found %d (duplicate or reordered)", expect, env.Seq)
		}
		if ev.Seq != env.Seq {
			return fail(env.Seq, ReasonSeqOrder, "stored seq %d differs from the envelope's", ev.Seq)
		}
		if ev.PrevHash != prev {
			return fail(env.Seq, ReasonPrevHash, "stored prev_hash does not follow seq %d", env.Seq-1)
		}
		h := Link(tenant, env.Seq, prev, BodyHash(ev.Envelope))
		if h != ev.Hash {
			return fail(env.Seq, ReasonHash, "the event's content does not match its hash")
		}
		if r := applyKeyEvent(env, keys, chainKeys); r != nil {
			return *r
		}
		prev, last = h, env.Seq
		hashAt[env.Seq] = h
		expect++
	}

	if len(b.Events) > 0 && last != b.ToSeq {
		return fail(last, ReasonTruncated, "the export claims to end at seq %d but its last event is %d", b.ToSeq, last)
	}
	// A key the chain does not introduce cannot be trusted: inside the retained range the chain is the
	// only evidence, and the manifest may only describe keys introduced before it.
	for id, k := range keys {
		if (first <= 1 || k.created >= first) && !chainKeys[id] {
			return fail(k.created, ReasonKeyMismatch, "manifest key %s has no introduction in the chain", id)
		}
	}

	// A retirement the manifest claims inside the retained range must be a key.retired event in the chain.
	for id, k := range keys {
		if k.fromManifest && k.retired != 0 && k.retired >= first && len(b.Events) > 0 && k.chainRet != k.retired {
			return fail(k.retired, ReasonKeyMismatch, "manifest says key %s retired at seq %d but the chain does not retire it there", id, k.retired)
		}
	}

	cps := append([]Checkpoint(nil), b.Checkpoints...)
	sort.Slice(cps, func(i, j int) bool { return cps[i].Seq < cps[j].Seq })
	res := Result{Events: len(b.Events)}
	pinned := map[string]bool{}
	for _, p := range opts.Pinned {
		pinned[p] = true
	}

	// Anchors come from outside the host. One beyond the newest event proves the export was cut short.
	anchored := false
	trusted := map[string]bool{}
	for p := range pinned {
		trusted[p] = true
	}
	for _, a := range opts.Anchors {
		if a.Tenant != tenant {
			continue
		}
		if a.Seq > last {
			return fail(a.Seq, ReasonTruncated, "the external anchor at seq %d is newer than the export's last event %d", a.Seq, last)
		}
		h, ok := hashAt[a.Seq]
		if !ok {
			continue
		}
		if h != a.Hash {
			return fail(a.Seq, ReasonAnchorMismatch, "the chain at seq %d differs from the external anchor", a.Seq)
		}
		anchored = true
		// The anchored checkpoint's signer is a trust root, once its signature checks out.
		if k, ok := keys[a.KeyID]; ok && a.VerifySignature(k.pub) == nil {
			trusted[a.KeyID] = true
		}
	}
	// A pinned key the export never mentions would be ignored, so adding a pin could weaken the check.
	for p := range pinned {
		if _, ok := keys[p]; !ok {
			return fail(0, ReasonPinnedKeyAbsent, "pinned key %s appears neither in the manifest nor in the chain", p)
		}
	}
	// A key whose window the bundle only asserts (the manifest of a truncated export) cannot be told from
	// a retired key relabelled as current. The operator's pin window refutes it; without windows, more
	// than one pin leaves the choice of "current" to the exporter (full-range exports too: the forger orders the key events).
	for _, p := range sortedKeys(pinned) {
		k := keys[p]
		if w, ok := opts.PinWindows[p]; ok {
			if k.created != w.CreatedSeq || k.retired != w.RetiredSeq {
				return fail(0, ReasonPinWindow, "pinned key %s was recorded with window %d-%d; the export says %d-%d", p, w.CreatedSeq, w.RetiredSeq, k.created, k.retired)
			}
			continue
		}
		if len(pinned) > 1 {
			return fail(0, ReasonPinWindow, "several keys are pinned and %s has no window: the order of keys cannot be taken from the export, which the exporter writes. Pin only the current key, or give each pin its window (KEY@created-retired)", p)
		}
	}
	rooted := len(pinned) > 0 || anchored
	// Trust spreads only along cross-signatures from an already trusted key; nothing else the chain
	// says about a key (a bare key.created, a covering checkpoint) can vouch for it.
	for changed := true; changed; {
		changed = false
		for id, k := range keys {
			if !trusted[id] && k.crossBy != "" && trusted[k.crossBy] {
				trusted[id], changed = true, true
			}
		}
	}

	pinnedSigned := false
	signedBy := map[string]bool{}
	var lastCP uint64
	for i, c := range cps {
		if c.Tenant != tenant {
			return fail(c.Seq, ReasonCheckpointTenant, "checkpoint belongs to tenant %s", FormatUUID(c.Tenant))
		}
		if i > 0 && cps[i-1].Seq == c.Seq {
			return fail(c.Seq, ReasonCheckpointChain, "two checkpoints at seq %d", c.Seq)
		}
		h, inRange := hashAt[c.Seq]
		if inRange && h != c.Hash {
			return fail(c.Seq, ReasonCheckpointHash, "the checkpoint's hash differs from the chain at seq %d", c.Seq)
		}
		k, ok := keys[c.KeyID]
		if !ok {
			return fail(c.Seq, ReasonUnknownKey, "checkpoint key %s is not introduced in the chain", c.KeyID)
		}
		if c.Seq < k.created || (k.retired != 0 && c.Seq >= k.retired) {
			return fail(c.Seq, ReasonKeyWindow, "key %s is not valid at seq %d", c.KeyID, c.Seq)
		}
		if err := c.VerifySignature(k.pub); err != nil {
			return fail(c.Seq, ReasonBadSignature, "%v", err)
		}
		if i > 0 && (c.PrevSeq != cps[i-1].Seq || c.PrevHash != cps[i-1].Hash) {
			return fail(c.Seq, ReasonCheckpointChain, "prev_checkpoint does not name the checkpoint at seq %d", cps[i-1].Seq)
		}
		if rooted && !trusted[c.KeyID] {
			return fail(c.Seq, ReasonUntrustedKey, "key %s is neither pinned, anchored nor cross-signed by a trusted key", c.KeyID)
		}
		if inRange && (!rooted || trusted[c.KeyID]) {
			signedBy[c.KeyID] = true
			if pinned[c.KeyID] {
				pinnedSigned = true
			}
			if c.Seq > lastCP {
				lastCP = c.Seq
			}
		}
		res.Checkpoints++
	}
	if len(pinned) > 0 && !pinnedSigned {
		return fail(0, ReasonPinnedKeyAbsent, "no verified checkpoint is signed by a pinned key")
	}
	// The newest pinned key (by introduction, the operator's window first) that the export reaches must
	// itself have signed a verified checkpoint, whatever the bundle says about its retirement: a
	// retirement needs no signature, so an attacker can retire the current key inside a forged range.
	if len(pinned) > 1 {
		var newest string
		var newestAt uint64
		for _, p := range sortedKeys(pinned) {
			at := keys[p].created
			if w, ok := opts.PinWindows[p]; ok {
				at = w.CreatedSeq
			}
			if at <= last && (newest == "" || at > newestAt) {
				newest, newestAt = p, at
			}
		}
		if newest != "" && !signedBy[newest] {
			return fail(last, ReasonPinnedKeyAbsent, "the newest pinned key %s has signed no verified checkpoint in this export, so a retired pinned key cannot be told from a fork", newest)
		}
	}
	if last > lastCP {
		res.TailUnsigned = last - lastCP
	}
	if pinnedSigned || anchored {
		res.Status = OK
	} else {
		res.Status = Unanchored
		res.Detail = "no pinned key fingerprint and no external anchor: the export is internally consistent but proves nothing about who built it"
	}
	return res
}

// applyKeyEvent folds a key event into the window table, refusing one that disagrees with the manifest.
func applyKeyEvent(env Envelope, keys map[string]*keyWin, fromChain map[string]bool) *Result {
	switch env.Kind {
	case KindKeyCreated:
		id, _ := env.Detail("key_id")
		pubHex, _ := env.Detail("public_key")
		pub, err := hex.DecodeString(pubHex)
		if err != nil || len(pub) != ed25519.PublicKeySize || Fingerprint(pub) != id {
			r := fail(env.Seq, ReasonKeyEvent, "key introduction does not carry a key matching its id")
			return &r
		}
		if k, ok := keys[id]; ok {
			if k.created != env.Seq || string(k.pub) != string(pub) {
				r := fail(env.Seq, ReasonKeyMismatch, "key %s: the manifest disagrees with the chain", id)
				return &r
			}
		} else {
			keys[id] = &keyWin{pub: pub, created: env.Seq}
		}
		fromChain[id] = true
		// An explicit cross-signature by an earlier key is the only way a chain-introduced key can
		// inherit trust. A bad one is a forgery, not an absence.
		if signer, ok := env.Detail(DetailSignedBy); ok {
			sigHex, _ := env.Detail(DetailCrossSignature)
			sig, derr := hex.DecodeString(sigHex)
			sk := keys[signer]
			var st []byte
			if sk != nil && derr == nil {
				st, derr = CrossSignStatement(env.Tenant, signer, id, pub)
			}
			if sk != nil && sk.retired != 0 && sk.retired == env.Seq-1 && sk.chainRet == 0 {
				r := fail(sk.retired, ReasonKeyMismatch, "the manifest retires key %s at seq %d but the chain does not", signer, sk.retired)
				return &r
			}
			// Only the production rotation shape vouches: the signer was retired by the event just
			// before this one, and it vouches for a single successor. A retired or current key that
			// leaks later cannot introduce more keys.
			if sk == nil || sk.created >= env.Seq || sk.chainRet == 0 || sk.chainRet != env.Seq-1 || sk.vouched || derr != nil || !ed25519.Verify(sk.pub, st, sig) {
				r := fail(env.Seq, ReasonKeyEvent, "key %s: the cross-signature by %s does not verify", id, signer)
				return &r
			}
			sk.vouched = true
			keys[id].crossBy = signer
		}
	case KindKeyRetired:
		id, _ := env.Detail("key_id")
		k, ok := keys[id]
		if !ok || k.chainRet != 0 {
			r := fail(env.Seq, ReasonKeyEvent, "retirement of unknown or already retired key %s", id)
			return &r
		}
		if k.fromManifest && k.retired != env.Seq || k.retired != 0 && k.retired != env.Seq {
			r := fail(env.Seq, ReasonKeyMismatch, "key %s: the manifest's retirement (seq %d) disagrees with the chain", id, k.retired)
			return &r
		}
		k.retired, k.chainRet = env.Seq, env.Seq
	}
	return nil
}

// checkPinWindows refuses windows that contradict each other: only one key can be current, and a key
// cannot be valid in two places at once.
func checkPinWindows(ws map[string]PinWindow) error {
	ids := make([]string, 0, len(ws))
	for id := range ws {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for i, a := range ids {
		for _, b := range ids[i+1:] {
			wa, wb := ws[a], ws[b]
			endA, endB := wa.RetiredSeq, wb.RetiredSeq
			if endA == 0 {
				endA = ^uint64(0)
			}
			if endB == 0 {
				endB = ^uint64(0)
			}
			if wa.CreatedSeq < endB && wb.CreatedSeq < endA {
				return fmt.Errorf("pin windows of %s and %s overlap: only one key can be current at a time", a, b)
			}
		}
	}
	return nil
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
